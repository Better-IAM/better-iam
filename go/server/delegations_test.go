package server

// Ports of tests/delegations.test.ts and tests/delegation-handoffs.test.ts (packages/server/src/delegations.ts and
// api/delegations.ts), plus unit tests of the module's helpers. People are provisioned with auth.CreateIdentity and
// agents are written as agents.create writes them (AgentProfile under the owner as sponsor), because identities.create
// and agents.create belong to other units; agent changes the TypeScript tests make through agents.update, suspend,
// resume and delete are made to the stored agent the same way those methods make them. Steps that reach another
// unit's NOT_IMPLEMENTED stub skip the rest of the test (requirePorted, expectCodeOrSkip).

import (
	"context"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// dlgFixture is the organization fixture with the helpers the delegation tests share.
type dlgFixture struct {
	*orgFixture
}

func newDlgFixture(t *testing.T, mutate func(options *BetterIamOptions)) *dlgFixture {
	t.Helper()
	return &dlgFixture{orgFixture: newOrgFixture(t, mutate)}
}

func (f *dlgFixture) api() *DelegationsAPI { return f.iam.API.Delegations }

// in is a request body for the organization: `{ tenantId, ...members }`.
func (f *dlgFixture) in(members ...any) *core.Object {
	return core.NewObject("tenantId", f.tenantID).Assign(core.NewObject(members...))
}

func (f *dlgFixture) now() float64 { return float64(f.clock.Load()) }

func (f *dlgFixture) advance(ms int64) { f.clock.Add(ms) }

// transact runs fn in a transaction of the fixture's store (fails the test on error).
func (f *dlgFixture) transact(fn func(ctx context.Context, tx core.IamStore) error) {
	f.t.Helper()
	if err := f.store.Transaction(f.ctx, fn); err != nil {
		f.t.Fatal(err)
	}
}

// person provisions a member `{name}@acme.test` with the password organizationFixture members get.
func (f *dlgFixture) person(name string) *core.Object {
	f.t.Helper()
	var created *core.Object
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		identity, err := f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: f.tenantID, Email: name + "@acme.test", Name: name, Password: "a strong " + name + " password",
			HasPassword: true, EmailVerified: true,
		})
		created = identity
		return err
	})
	return created
}

// agent writes an agent sponsored by the owner, as agents.create does (profile members as AgentProfileInput).
func (f *dlgFixture) agent(name string, profile ...any) *core.Object {
	f.t.Helper()
	var created *core.Object
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		validated, err := AgentProfile(ctx, f.iam.Context, tx, f.tenantID, core.NewObject(profile...), core.NewObject("sponsorId", f.ownerID))
		if err != nil {
			return err
		}
		created, err = tx.Insert(ctx, "identities", core.NewObject(
			"id", ID(), "tenantId", f.tenantID, "kind", "agent", "name", name, "status", "active", "emailVerified", false,
			"owner", false, "rootAdmin", false, "createdAt", f.now(), "agent", validated,
		))
		return err
	})
	return created
}

// patchAgent changes a stored agent as agents.update / suspend / resume do: change sets members of the identity, and
// profile members of its agent profile (nil deletes one).
func (f *dlgFixture) patchAgent(agentID any, change []any, profile ...any) {
	f.t.Helper()
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		agent, err := tx.Get(ctx, "identities", jsString(agentID))
		if err != nil {
			return err
		}
		next := agent.Spread()
		for index := 0; index+1 < len(change); index += 2 {
			next.Set(change[index].(string), change[index+1])
		}
		if len(profile) > 0 {
			validated, err := AgentProfile(ctx, f.iam.Context, tx, f.tenantID, core.NewObject(profile...), next.Get("agent").(*core.Object))
			if err != nil {
				return err
			}
			next.Set("agent", validated)
		}
		_, err = tx.Put(ctx, "identities", next)
		return err
	})
}

// key issues an API key for an agent (credentials.create) as a freshly signed-in owner.
func (f *dlgFixture) key(agentID any, members ...any) core.CredentialInput {
	f.t.Helper()
	created := f.object(f.iam.API.Credentials.Create(f.ctx, f.ownerSignIn(), Input[apitypes.CredentialsCreateInput](f.in(append([]any{"identityId", agentID}, members...)...))))
	return core.CredentialInput{Token: jsString(created.Get("token"))}
}

// role creates a role holding document and binds it to a subject.
func (f *dlgFixture) roleFor(subjectID any, name string, document *core.Object) *core.Object {
	f.t.Helper()
	role := f.createRole(f.owner, "name", name, "document", document)
	f.bind(f.owner, role.Get("id"), "identity", subjectID)
	return role
}

func dlgDoc(actions []string, resources ...string) *core.Object {
	if len(resources) == 0 {
		resources = []string{"document/*"}
	}
	return core.NewObject("version", 1.0, "statements", []any{core.NewObject(
		"effect", "allow", "actions", stringsOf(actions), "resources", stringsOf(resources),
	)})
}

// decide is iam.authorize(...).allowed for an action on a document (the error unchanged).
func (f *dlgFixture) decide(token, action, id string) (bool, error) {
	decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{
		Credential: core.CredentialInput{Token: token}, TenantID: f.tenantID, Action: action, Resource: ResourceTarget{Type: "document", ID: id},
	})
	return decision.Allowed, err
}

// allowed is decide that fails the test (or skips it at another unit's stub) on error.
func (f *dlgFixture) allowed(token, action string, id ...string) bool {
	f.t.Helper()
	resource := "a"
	if len(id) > 0 {
		resource = id[0]
	}
	allowed, err := f.decide(token, action, resource)
	requirePorted(f.t, err)
	return allowed
}

// refusedWith expects decide to fail with code.
func (f *dlgFixture) refusedWith(token, action, code string) {
	f.t.Helper()
	_, err := f.decide(token, action, "a")
	expectCodeOrSkip(f.t, err, code)
}

func (f *dlgFixture) grant(credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	return f.object(f.api().Grant(f.ctx, credential, Input[apitypes.DelegationsGrantInput](f.in(members...))))
}

func (f *dlgFixture) assume(credential core.CredentialInput, delegationID any, members ...any) *core.Object {
	f.t.Helper()
	return f.object(f.api().Assume(f.ctx, credential, Input[apitypes.DelegationsAssumeInput](f.in(append([]any{"delegationId", delegationID}, members...)...))))
}

func (f *dlgFixture) token(answer *core.Object) core.CredentialInput {
	return core.CredentialInput{Token: jsString(answer.Get("token"))}
}

func (f *dlgFixture) get(credential core.CredentialInput, delegationID any) *core.Object {
	f.t.Helper()
	return f.object(f.api().Get(f.ctx, credential, Input[apitypes.DelegationsGetInput](f.in("delegationId", delegationID))))
}

func (f *dlgFixture) revoke(credential core.CredentialInput, delegationID any) *core.Object {
	f.t.Helper()
	return f.object(f.api().Revoke(f.ctx, credential, Input[apitypes.DelegationsRevokeInput](f.in("delegationId", delegationID))))
}

func (f *dlgFixture) handoff(credential core.CredentialInput, members ...any) (*core.Object, error) {
	answer, err := f.api().Handoff(f.ctx, credential, Input[apitypes.DelegationsHandoffInput](f.in(members...)))
	if err != nil {
		return nil, err
	}
	return answer.Value.(*core.Object), nil
}

func (f *dlgFixture) dispatch() {
	f.t.Helper()
	if _, err := f.iam.Auth.DispatchOutbox(f.ctx, 0); err != nil {
		f.t.Fatal(err)
	}
}

// sent is the first message of the inbox with a template.
func (f *dlgFixture) sent(template string) *auth.DeliveryMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	for index := range f.inbox {
		if f.inbox[index].Template == template {
			return &f.inbox[index]
		}
	}
	return nil
}

// matches checks that every member of want is in got (toMatchObject), recursively for objects.
func dlgMatches(t *testing.T, got *core.Object, want *core.Object) {
	t.Helper()
	want.Entries(func(key string, value any) bool {
		actual := got.Get(key)
		if nested, ok := value.(*core.Object); ok {
			inner, ok := actual.(*core.Object)
			if !ok {
				t.Fatalf("%s: expected an object, got %s in %s", key, core.MustStringify(actual), core.MustStringify(got))
			}
			dlgMatches(t, inner, nested)
			return true
		}
		if core.MustStringify(actual) != core.MustStringify(value) {
			t.Fatalf("%s: expected %s, got %s in %s", key, core.MustStringify(value), core.MustStringify(actual), core.MustStringify(got))
		}
		return true
	})
}

func dlgIDs(items []*core.Object) []string {
	ids := make([]string, len(items))
	for index, item := range items {
		ids[index] = jsString(item.Get("id"))
	}
	return ids
}

// dlgSetup is tests/delegations.test.ts setup: Acme with alice (documents:read and documents:write on every
// document) and an agent sponsored by the owner with its own key but no grants of its own.
func dlgSetup(t *testing.T, profile ...any) (f *dlgFixture, alice, agent *core.Object, agentKey, aliceSession core.CredentialInput) {
	t.Helper()
	f = newDlgFixture(t, nil)
	alice = f.person("alice")
	f.roleFor(alice.Get("id"), "Editor", dlgDoc([]string{"documents:read", "documents:write"}))
	agent = f.agent("Inbox agent", append([]any{"model", "claude-sonnet-5"}, profile...)...)
	agentKey = f.key(agent.Get("id"))
	aliceSession = f.login("alice")
	return
}

func TestDelegationsLetAPersonDelegatePartOfTheirAccess(t *testing.T) {
	f, alice, agent, agentKey, aliceSession := dlgSetup(t)
	// Without a delegation the agent has nothing.
	if f.allowed(agentKey.Token, "documents:read") {
		t.Fatal("the agent must have nothing of its own")
	}
	delegation := f.grant(aliceSession, "agentId", agent.Get("id"), "scopes", []any{"documents:read"}, "expiresInSeconds", 86_400.0)
	dlgMatches(t, delegation, obj(t, `{"status":"active","requestedBy":"subject","scopes":["documents:read"],
		"agent":{"name":"Inbox agent","model":"claude-sonnet-5"},"subject":{"email":"alice@acme.test"}}`))
	if delegation.Get("expiresAt") != f.now()+86_400_000 || member(delegation.Get("agent"), "id") != agent.Get("id") ||
		member(delegation.Get("subject"), "id") != alice.Get("id") {
		t.Fatalf("unexpected summary %s", core.MustStringify(delegation))
	}

	credential := f.assume(agentKey, delegation.Get("id"), "sessionName", "triage-run")
	if kind, ok := auth.ParseCredentialToken(jsString(credential.Get("token"))); !ok || kind != "dlg" {
		t.Fatalf("expected a dlg token, got %q", kind)
	}
	dlgMatches(t, credential.Get("session").(*core.Object), core.NewObject("kind", "delegated", "identityId", alice.Get("id"),
		"agentId", agent.Get("id"), "delegationId", delegation.Get("id"), "sessionName", "triage-run"))
	if credential.Get("expiresIn") != 900.0 || credential.Get("tokenType") != "Bearer" {
		t.Fatalf("unexpected credential %s", core.MustStringify(credential))
	}
	token := jsString(credential.Get("token"))

	// Alice's access, narrowed to the scope.
	if !f.allowed(token, "documents:read") || f.allowed(token, "documents:write") {
		t.Fatal("the delegated session must have alice's access within the scope")
	}
	caller := f.object(f.iam.API.Sts.GetCallerIdentity(f.ctx, core.CredentialInput{Token: token}, Input[apitypes.StsGetCallerIdentityInput](nil)))
	dlgMatches(t, caller, core.NewObject("identityId", alice.Get("id"), "sessionKind", "delegated", "agentId", agent.Get("id"),
		"delegationId", delegation.Get("id")))

	// The audit trail names the person, the agent and the delegation.
	if _, err := f.decide(token, "documents:write", "b"); err != nil {
		t.Fatal(err)
	}
	denials := f.items(f.iam.API.Audit.List(f.ctx, f.owner, Input[apitypes.AuditListInput](f.in("action", "documents:write"))))
	if len(denials) == 0 {
		t.Fatal("expected the denial in the audit log")
	}
	dlgMatches(t, denials[0], core.NewObject("actorId", alice.Get("id"), "outcome", "deny",
		"sessionContext", core.NewObject("kind", "delegated", "agentId", agent.Get("id"), "delegationId", delegation.Get("id"))))

	mine := f.items(f.api().ListMine(f.ctx, aliceSession, Input[apitypes.DelegationsListMineInput](f.in())))
	if !reflect.DeepEqual(dlgIDs(mine), []string{jsString(delegation.Get("id"))}) {
		t.Fatalf("listMine for alice: %v", dlgIDs(mine))
	}
	forAgent := f.items(f.api().ListMine(f.ctx, agentKey, Input[apitypes.DelegationsListMineInput](f.in())))
	if len(forAgent) != 1 || forAgent[0].Get("id") != delegation.Get("id") {
		t.Fatalf("listMine for the agent: %v", dlgIDs(forAgent))
	}
	if _, ok := forAgent[0].Get("lastUsedAt").(float64); !ok {
		t.Fatalf("lastUsedAt must be set: %s", core.MustStringify(forAgent[0]))
	}
}

func TestDelegationsShowThePersonAndTheSponsorWhatTheAgentDid(t *testing.T) {
	f, alice, agent, agentKey, aliceSession := dlgSetup(t)
	delegation := f.grant(aliceSession, "agentId", agent.Get("id"), "scopes", []any{"documents:read"})
	token := jsString(f.assume(agentKey, delegation.Get("id")).Get("token"))
	// One denied action for alice, one denied action with the agent's own key.
	if f.allowed(token, "documents:write", "secret") || f.allowed(agentKey.Token, "documents:read", "own") {
		t.Fatal("both actions must be denied")
	}
	forAlice := f.items(f.api().Activity(f.ctx, aliceSession, Input[apitypes.DelegationsActivityInput](f.in("delegationId", delegation.Get("id")))))
	actions := []string{}
	for _, event := range forAlice {
		actions = append(actions, jsString(event.Get("action")))
	}
	sort.Strings(actions)
	if !reflect.DeepEqual(actions, []string{"delegation:assume", "delegation:grant", "documents:write"}) {
		t.Fatalf("activity: %v", actions)
	}
	for _, event := range forAlice {
		if event.Get("action") == "documents:write" {
			dlgMatches(t, event, core.NewObject("actorId", alice.Get("id"), "resourceId", "secret", "outcome", "deny"))
		}
	}
	// Another member sees nothing (refused before the activity is read). Checked last: the refusal is itself
	// audited against the delegation, so it would show in the activity above.
	f.person("mallory")
	mallory := f.login("mallory")
	_, err := f.api().Activity(f.ctx, mallory, Input[apitypes.DelegationsActivityInput](f.in("delegationId", delegation.Get("id"))))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
}

func TestDelegationsHoldBackSensitiveActionsUntilThePersonConfirmsEachOne(t *testing.T) {
	f, alice, agent, agentKey, aliceSession := dlgSetup(t)
	delegation := f.grant(aliceSession, "agentId", agent.Get("id"), "scopes", []any{"documents:*"}, "confirm", []any{"documents:write"})
	if core.MustStringify(delegation.Get("confirm")) != `["documents:write"]` {
		t.Fatalf("confirm: %s", core.MustStringify(delegation.Get("confirm")))
	}
	acting := f.token(f.assume(agentKey, delegation.Get("id")))
	if !f.allowed(acting.Token, "documents:read", "report") || f.allowed(acting.Token, "documents:write", "report") {
		t.Fatal("writing must wait for a confirmation")
	}
	request := func(credential core.CredentialInput, members ...any) (*core.Object, error) {
		answer, err := f.api().RequestConfirmation(f.ctx, credential, Input[apitypes.DelegationsRequestConfirmationInput](f.in(members...)))
		if err != nil {
			return nil, err
		}
		return answer.Value.(*core.Object), nil
	}
	report := core.NewObject("type", "document", "id", "report")
	// Reading needs no confirmation, so asking for it is refused.
	_, err := request(acting, "action", "documents:read", "resource", report, "reason", "x")
	expectCodeOrSkip(t, err, "INVALID_INPUT")
	// Only the delegated session may ask.
	_, err = request(agentKey, "action", "documents:write", "resource", report, "reason", "x")
	expectCodeOrSkip(t, err, "ACCESS_DENIED")

	first, err := request(acting, "action", "documents:write", "resource", report, "reason", "Fix the typo in the summary you asked about", "validSeconds", 120.0)
	requirePorted(t, err)
	dlgMatches(t, first, core.NewObject("status", "pending", "action", "documents:write", "resource", report,
		"agent", core.NewObject("id", agent.Get("id"), "name", "Inbox agent"), "subjectId", alice.Get("id")))
	// Asking again returns the same pending request.
	again, err := request(acting, "action", "documents:write", "resource", report, "reason", "again")
	requirePorted(t, err)
	if again.Get("id") != first.Get("id") {
		t.Fatal("an identical pending request must be returned as it is")
	}
	f.dispatch()
	email := f.sent("delegation-confirmation")
	if email == nil || email.To != "alice@acme.test" || email.Payload["confirmationId"] != first.Get("id") ||
		email.Payload["action"] != "documents:write" || email.Payload["resource"] != "document/report" || email.Payload["minutes"] != "30" {
		t.Fatalf("unexpected email %+v", email)
	}
	rendered, err := auth.RenderDeliveryMessage(auth.TemplateMessage{Template: email.Template, To: email.To, Payload: email.Payload, TenantID: email.TenantID}, auth.TemplateOptions{})
	if err != nil || rendered == nil || rendered.Subject != "Inbox agent asks you to confirm an action" {
		t.Fatalf("rendered %+v %v", rendered, err)
	}

	// Alice sees it; the agent polls it; the owner (not involved) cannot decide it.
	listed := f.items(f.api().ListConfirmations(f.ctx, aliceSession, Input[apitypes.DelegationsListConfirmationsInput](f.in())))
	if !reflect.DeepEqual(dlgIDs(listed), []string{jsString(first.Get("id"))}) {
		t.Fatalf("listConfirmations: %v", dlgIDs(listed))
	}
	polled := f.object(f.api().GetConfirmation(f.ctx, acting, Input[apitypes.DelegationsGetConfirmationInput](f.in("confirmationId", first.Get("id")))))
	if polled.Get("status") != "pending" {
		t.Fatalf("polled %s", core.MustStringify(polled))
	}
	decide := func(credential core.CredentialInput, id any, approve bool) (*core.Object, error) {
		answer, err := f.api().DecideConfirmation(f.ctx, credential, Input[apitypes.DelegationsDecideConfirmationInput](f.in("confirmationId", id, "approve", approve)))
		if err != nil {
			return nil, err
		}
		return answer.Value.(*core.Object), nil
	}
	_, err = decide(f.owner, first.Get("id"), true)
	expectCodeOrSkip(t, err, "NOT_FOUND")

	approved, err := decide(aliceSession, first.Get("id"), true)
	requirePorted(t, err)
	if approved.Get("status") != "approved" || approved.Get("expiresAt") != f.now()+120_000 {
		t.Fatalf("approved %s", core.MustStringify(approved))
	}
	// Exactly that action on exactly that resource, for a while.
	if !f.allowed(acting.Token, "documents:write", "report") || f.allowed(acting.Token, "documents:write", "other") {
		t.Fatal("the approval opens exactly that action on that resource")
	}
	f.advance(121_000)
	if f.allowed(acting.Token, "documents:write", "report") {
		t.Fatal("the approval must lapse")
	}

	// A rejection opens nothing, and the trail shows every step.
	second, err := request(acting, "action", "documents:write", "resource", report, "reason", "One more edit")
	requirePorted(t, err)
	rejected, err := decide(aliceSession, second.Get("id"), false)
	requirePorted(t, err)
	if rejected.Get("status") != "rejected" || f.allowed(acting.Token, "documents:write", "report") {
		t.Fatal("a rejection opens nothing")
	}
	trail := f.items(f.api().Activity(f.ctx, aliceSession, Input[apitypes.DelegationsActivityInput](f.in("delegationId", delegation.Get("id")))))
	seen := map[string]bool{}
	for _, event := range trail {
		seen[jsString(event.Get("action"))] = true
	}
	for _, action := range []string{"delegation:confirmation-request", "delegation:confirm", "delegation:reject"} {
		if !seen[action] {
			t.Fatalf("the trail misses %s", action)
		}
	}
}

func TestDelegationsUseUpEachApprovalOnce(t *testing.T) {
	f, _, agent, agentKey, aliceSession := dlgSetup(t)
	delegation := f.grant(aliceSession, "agentId", agent.Get("id"), "scopes", []any{"documents:*"}, "confirm", []any{"documents:write"})
	acting := f.token(f.assume(agentKey, delegation.Get("id")))
	request := f.object(f.api().RequestConfirmation(f.ctx, acting, Input[apitypes.DelegationsRequestConfirmationInput](f.in(
		"action", "documents:write", "resource", core.NewObject("type", "iam", "id", "report"), "reason", "Save it",
	))))
	f.object(f.api().DecideConfirmation(f.ctx, aliceSession, Input[apitypes.DelegationsDecideConfirmationInput](f.in("confirmationId", request.Get("id"), "approve", true))))
	session, err := f.iam.Authenticate(f.ctx, acting)
	requirePorted(t, err)
	// One transaction may check the same call more than once: the approval it used still opens it there.
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		now := f.iam.Context.Now()
		if err := UseConfirmation(ctx, tx, session, "documents:write", "iam", "report", now); err != nil {
			return err
		}
		stored, err := tx.Get(ctx, "delegationConfirmations", jsString(request.Get("id")))
		if err != nil {
			return err
		}
		if stored.Get("status") != "used" || stored.Get("usedAt") != float64(now) {
			t.Fatalf("the approval must be used: %s", core.MustStringify(stored))
		}
		if err := UseConfirmation(ctx, tx, session, "documents:write", "iam", "report", now); err != nil {
			return err
		}
		stored, err = tx.Get(ctx, "delegations", jsString(delegation.Get("id")))
		if err != nil {
			return err
		}
		keys, err := ApprovedConfirmations(ctx, tx, stored, now)
		if err != nil {
			return err
		}
		if !keys[ConfirmationKey("documents:write", "iam", "report")] {
			t.Fatal("a confirmation used in this transaction still opens its call here")
		}
		return nil
	})
	// In the next transaction it opens nothing.
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		stored, err := tx.Get(ctx, "delegations", jsString(delegation.Get("id")))
		if err != nil {
			return err
		}
		keys, err := ApprovedConfirmations(ctx, tx, stored, f.iam.Context.Now())
		if err != nil {
			return err
		}
		if len(keys) != 0 {
			t.Fatalf("a used approval opens nothing later: %v", keys)
		}
		return nil
	})
}

func TestDelegationsKeepTheAgentKeysOwnScopesOnTheSessionsItOpens(t *testing.T) {
	f, _, agent, _, aliceSession := dlgSetup(t)
	// An administrator issued this key for reading only.
	readOnly := f.key(agent.Get("id"), "scopes", []any{"documents:read", "iam:*"})
	delegation := f.grant(aliceSession, "agentId", agent.Get("id"), "scopes", []any{"documents:*"})
	token := jsString(f.assume(readOnly, delegation.Get("id")).Get("token"))
	if !f.allowed(token, "documents:read") {
		t.Fatal("reading must be allowed")
	}
	// Alice may write and delegated writing, but the key never could.
	if f.allowed(token, "documents:write") {
		t.Fatal("the key's scopes must bound the delegated session")
	}
}

func TestDelegationsNeverGiveTheAgentMoreThanThePersonHas(t *testing.T) {
	f, _, agent, agentKey, aliceSession := dlgSetup(t)
	delegation := f.grant(aliceSession, "agentId", agent.Get("id"), "scopes", []any{"*"})
	acting := f.token(f.assume(agentKey, delegation.Get("id")))
	if !f.allowed(acting.Token, "documents:write") {
		t.Fatal("alice's own access is delegated")
	}
	// Alice cannot read the audit log, so neither can her agent.
	_, err := f.iam.API.Audit.List(f.ctx, acting, Input[apitypes.AuditListInput](f.in()))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	// A delegated session is no substitute for a fresh sign-in or the person's own session.
	_, err = f.api().Grant(f.ctx, acting, Input[apitypes.DelegationsGrantInput](f.in("agentId", agent.Get("id"), "scopes", []any{"documents:read"})))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	_, err = f.iam.API.Sts.GetSessionToken(f.ctx, acting, Input[apitypes.StsGetSessionTokenInput](nil))
	expectCodeOrSkip(t, err, "CREDENTIAL_CHAINING_DISABLED")
	// A delegated token cannot open further delegated sessions.
	_, err = f.api().Assume(f.ctx, acting, Input[apitypes.DelegationsAssumeInput](f.in("delegationId", delegation.Get("id"))))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")

	// The agent's own ceiling bounds delegated sessions as well, live (agents.update boundary).
	f.patchAgent(agent.Get("id"), nil, "boundary", dlgDoc([]string{"documents:read"}))
	if f.allowed(acting.Token, "documents:write") || !f.allowed(acting.Token, "documents:read") {
		t.Fatal("the agent's boundary must bound the delegated session")
	}

	// A scope-down at assume time narrows one session further.
	narrow := f.token(f.assume(agentKey, delegation.Get("id"), "policy", dlgDoc([]string{"documents:read"}, "document/only-this")))
	if !f.allowed(narrow.Token, "documents:read", "only-this") || f.allowed(narrow.Token, "documents:read", "other") {
		t.Fatal("the scope-down policy must narrow the session")
	}
}

func TestDelegationsRunTheRequestAndApprovalFlow(t *testing.T) {
	f, alice, _, agentKey, aliceSession := dlgSetup(t)
	request := f.object(f.api().Request(f.ctx, agentKey, Input[apitypes.DelegationsRequestInput](f.in(
		"subjectEmail", "Alice@acme.test", "scopes", []any{"documents:read", "documents:write"},
		"reason", "Draft replies to your inbox", "expiresInSeconds", 7*86_400.0,
	))))
	dlgMatches(t, request, core.NewObject("status", "pending", "requestedBy", "agent", "reason", "Draft replies to your inbox",
		"requestedSeconds", 7*86_400.0, "subject", core.NewObject("id", alice.Get("id"))))
	f.dispatch()
	email := f.sent("delegation-request")
	if email == nil || email.To != "alice@acme.test" || email.Payload["delegationId"] != request.Get("id") ||
		email.Payload["agentName"] != "Inbox agent" || email.Payload["days"] != "7" ||
		email.Payload["scopes"] != "documents:read, documents:write" || email.Payload["model"] != "claude-sonnet-5" {
		t.Fatalf("unexpected email %+v", email)
	}
	rendered, err := auth.RenderDeliveryMessage(auth.TemplateMessage{Template: email.Template, To: email.To, Payload: email.Payload, TenantID: email.TenantID},
		auth.TemplateOptions{Links: &auth.TemplateLinks{Delegation: func(input auth.DelegationLinkInput) string {
			return "https://console.test/delegations/" + input.DelegationID
		}}})
	if err != nil || rendered == nil || rendered.Subject != "Inbox agent asks to act on your behalf" ||
		!strings.Contains(rendered.Text, "(claude-sonnet-5)") || !strings.Contains(rendered.Text, "for 7 days") ||
		!strings.Contains(rendered.Text, "Draft replies to your inbox") ||
		!strings.Contains(rendered.HTML, "https://console.test/delegations/"+jsString(request.Get("id"))) {
		t.Fatalf("rendered %+v %v", rendered, err)
	}

	// Not usable until approved; a second request is refused.
	_, err = f.api().Assume(f.ctx, agentKey, Input[apitypes.DelegationsAssumeInput](f.in("delegationId", request.Get("id"))))
	expectCodeOrSkip(t, err, "DELEGATION_PENDING")
	_, err = f.api().Request(f.ctx, agentKey, Input[apitypes.DelegationsRequestInput](f.in(
		"subjectId", alice.Get("id"), "scopes", []any{"documents:read"}, "reason", "again",
	)))
	expectCodeOrSkip(t, err, "DELEGATION_EXISTS")
	// Only alice decides: not the owner, not the agent.
	_, err = f.api().Approve(f.ctx, f.owner, Input[apitypes.DelegationsApproveInput](f.in("delegationId", request.Get("id"))))
	expectCodeOrSkip(t, err, "NOT_FOUND")

	// The agent polls while it waits.
	if f.get(agentKey, request.Get("id")).Get("status") != "pending" {
		t.Fatal("the agent must see the pending request")
	}

	// Alice approves read only.
	approved := f.object(f.api().Approve(f.ctx, aliceSession, Input[apitypes.DelegationsApproveInput](f.in(
		"delegationId", request.Get("id"), "scopes", []any{"documents:read"},
	))))
	dlgMatches(t, approved, obj(t, `{"status":"active","scopes":["documents:read"]}`))
	if approved.Get("expiresAt") != f.now()+7*86_400_000 || approved.Has("requestedSeconds") {
		t.Fatalf("approved %s", core.MustStringify(approved))
	}
	token := jsString(f.assume(agentKey, request.Get("id")).Get("token"))
	if !f.allowed(token, "documents:read") || f.allowed(token, "documents:write") {
		t.Fatal("the approved scope must bound the session")
	}
}

func TestDelegationsLetPeopleDenyRequestsAndRequestsLapse(t *testing.T) {
	f, alice, _, agentKey, aliceSession := dlgSetup(t)
	request := func(reason string) *core.Object {
		return f.object(f.api().Request(f.ctx, agentKey, Input[apitypes.DelegationsRequestInput](f.in(
			"subjectId", alice.Get("id"), "scopes", []any{"documents:read"}, "reason", reason,
		))))
	}
	first := request("Please")
	denied := f.object(f.api().Deny(f.ctx, aliceSession, Input[apitypes.DelegationsDenyInput](f.in("delegationId", first.Get("id")))))
	if denied.Get("status") != "denied" {
		t.Fatalf("denied %s", core.MustStringify(denied))
	}
	second := request("Please, again")
	f.advance(8 * 86_400_000)
	fresh := f.login("alice")
	_, err := f.api().Approve(f.ctx, fresh, Input[apitypes.DelegationsApproveInput](f.in("delegationId", second.Get("id"))))
	expectCodeOrSkip(t, err, "INVALID_TRANSITION")
	if f.get(fresh, second.Get("id")).Get("expired") != true {
		t.Fatal("a lapsed request reads as expired")
	}
}

func TestDelegationsEndDelegatedSessionsTheMomentAnythingInTheChainGoesAway(t *testing.T) {
	f, alice, agent, agentKey, aliceSession := dlgSetup(t)
	grantAndAssume := func() (*core.Object, string) {
		t.Helper()
		fresh := f.login("alice")
		delegation := f.grant(fresh, "agentId", agent.Get("id"), "scopes", []any{"documents:read"})
		token := jsString(f.assume(agentKey, delegation.Get("id")).Get("token"))
		if !f.allowed(token, "documents:read") {
			t.Fatal("the fresh delegation must work")
		}
		return delegation, token
	}

	// 1. The person revokes.
	delegation, token := grantAndAssume()
	f.revoke(aliceSession, delegation.Get("id"))
	f.refusedWith(token, "documents:read", "UNAUTHENTICATED")

	// 2. The sponsor suspends the agent (agents.suspend), then resumes it.
	delegation, token = grantAndAssume()
	f.patchAgent(agent.Get("id"), []any{"status", "suspended"})
	f.refusedWith(token, "documents:read", "UNAUTHENTICATED")
	f.patchAgent(agent.Get("id"), []any{"status", "active"})
	f.revoke(f.owner, delegation.Get("id"))

	// 3. The agent stops accepting delegation.
	delegation, token = grantAndAssume()
	f.patchAgent(agent.Get("id"), nil, "delegable", false)
	f.refusedWith(token, "documents:read", "UNAUTHENTICATED")
	_, err := f.api().Assume(f.ctx, agentKey, Input[apitypes.DelegationsAssumeInput](f.in("delegationId", delegation.Get("id"))))
	expectCodeOrSkip(t, err, "DELEGATION_NOT_ALLOWED")
	f.patchAgent(agent.Get("id"), nil, "delegable", true)
	if !f.allowed(token, "documents:read") {
		t.Fatal("accepting delegation again restores the session")
	}

	// 4. The agent's key is revoked.
	keys := f.items(f.iam.API.Credentials.List(f.ctx, f.owner, Input[apitypes.CredentialsListInput](f.in("identityId", agent.Get("id")))))
	f.ported(f.iam.API.Credentials.Revoke(f.ctx, f.ownerSignIn(), Input[apitypes.CredentialsRevokeInput](f.in("credentialId", keys[0].Get("id")))))
	f.refusedWith(token, "documents:read", "UNAUTHENTICATED")

	// 5. The person is disabled.
	second := f.key(agent.Get("id"))
	again := jsString(f.assume(second, delegation.Get("id")).Get("token"))
	if !f.allowed(again, "documents:read") {
		t.Fatal("a new key opens sessions again")
	}
	f.ported(f.iam.API.Identities.SetStatus(f.ctx, f.ownerSignIn(), Input[apitypes.IdentitiesSetStatusInput](f.in(
		"identityId", alice.Get("id"), "status", "disabled",
	))))
	f.refusedWith(again, "documents:read", "UNAUTHENTICATED")
}

func TestDelegationsRefuseAgentsThatDoNotAcceptItAndNonAgents(t *testing.T) {
	f, alice, _, _, aliceSession := dlgSetup(t)
	closed := f.agent("Closed", "delegable", false)
	grant := func(agentID any, scopes ...any) error {
		if len(scopes) == 0 {
			scopes = []any{"documents:read"}
		}
		_, err := f.api().Grant(f.ctx, aliceSession, Input[apitypes.DelegationsGrantInput](f.in("agentId", agentID, "scopes", scopes)))
		return err
	}
	expectCodeOrSkip(t, grant(closed.Get("id")), "DELEGATION_NOT_ALLOWED")
	// A service account (as serviceAccounts.create writes it) is no agent.
	service := core.NewObject("id", ID(), "tenantId", f.tenantID, "kind", "service", "name", "ci", "status", "active",
		"emailVerified", false, "owner", false, "rootAdmin", false, "createdAt", f.now())
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, "identities", service)
		return err
	})
	expectCodeOrSkip(t, grant(service.Get("id")), "NOT_FOUND")
	expectCodeOrSkip(t, grant(alice.Get("id")), "NOT_FOUND")
	expectCodeOrSkip(t, grant(closed.Get("id"), "no:such-action"), "DELEGATION_NOT_ALLOWED")
	// A stale sign-in cannot consent.
	f.advance(3_600_000)
	open := f.agent("Open")
	expectCodeOrSkip(t, grant(open.Get("id")), "RECENT_AUTH_REQUIRED")
}

func TestDelegationsLetAdministratorsListAndRevokeAndDeletingAnAgentRevokesThem(t *testing.T) {
	f, _, agent, agentKey, aliceSession := dlgSetup(t)
	delegation := f.grant(aliceSession, "agentId", agent.Get("id"), "scopes", []any{"documents:read"})
	token := jsString(f.assume(agentKey, delegation.Get("id")).Get("token"))
	listed := f.items(f.api().List(f.ctx, f.owner, Input[apitypes.DelegationsListInput](f.in("agentId", agent.Get("id")))))
	if !reflect.DeepEqual(dlgIDs(listed), []string{jsString(delegation.Get("id"))}) {
		t.Fatalf("list: %v", dlgIDs(listed))
	}
	// Members without iam:delegations:read are refused.
	f.person("mallory")
	_, err := f.api().List(f.ctx, f.login("mallory"), Input[apitypes.DelegationsListInput](f.in()))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")

	// agents.delete revokes every delegation to the agent, ends its sessions, and leaves a tombstone.
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		stored, err := tx.Get(ctx, "identities", jsString(agent.Get("id")))
		if err != nil {
			return err
		}
		ended, err := RevokeDelegationsOf(ctx, f.iam.Context, tx, stored, f.ownerID)
		if err != nil {
			return err
		}
		if ended != 1 {
			t.Fatalf("expected one delegation ended, got %v", ended)
		}
		_, err = tx.Put(ctx, "identities", stored.Spread(core.NewObject("status", "deleted")))
		return err
	})
	f.refusedWith(token, "documents:read", "UNAUTHENTICATED")
	revoked := f.get(f.owner, delegation.Get("id"))
	if revoked.Get("status") != "revoked" || revoked.Get("revokedBy") != f.ownerID {
		t.Fatalf("revoked %s", core.MustStringify(revoked))
	}
}

func TestDelegationsValidateTheirInput(t *testing.T) {
	f, _, agent, agentKey, aliceSession := dlgSetup(t)
	grant := func(members ...any) error {
		_, err := f.api().Grant(f.ctx, aliceSession, Input[apitypes.DelegationsGrantInput](f.in(append([]any{"agentId", agent.Get("id")}, members...)...)))
		return err
	}
	expectError(t, grant(), "INVALID_INPUT", "Provide either scopes or a policy")
	expectError(t, grant("scopes", []any{"documents:read"}, "policy", dlgDoc([]string{"documents:read"})), "INVALID_INPUT", "Provide either scopes or a policy")
	expectError(t, grant("scopes", []any{}), "INVALID_INPUT", "scopes must name at least one action")
	expectError(t, grant("scopes", []any{"documents:read"}, "expiresInSeconds", 60.0), "INVALID_INPUT", "Invalid expiresInSeconds")
	expectError(t, grant("scopes", []any{"documents:read"}, "maxSessionSeconds", 30.0), "INVALID_INPUT", "Invalid maxSessionSeconds")
	expectError(t, grant("scopes", []any{"documents:read"}, "confirm", []any{"bad pattern"}), "INVALID_INPUT", "Invalid action pattern bad pattern")
	// The spend validation of tests/delegation-spend.test.ts ('is set, changed or removed by the person, and validated').
	for _, spend := range []string{
		`{"period":"week","maxRequests":1}`, `{"period":"day"}`, `{"period":"day","maxCostUsd":0}`,
		`{"period":"day","maxCostUsd":0.0000001}`, `{"period":"day","maxTokens":1.5}`,
	} {
		expectCodeOrSkip(t, grant("scopes", []any{"documents:read"}, "spend", obj(t, spend)), "INVALID_INPUT")
	}
	_, err := f.api().Request(f.ctx, agentKey, Input[apitypes.DelegationsRequestInput](f.in("scopes", []any{"documents:read"}, "reason", "x")))
	expectError(t, err, "INVALID_INPUT", "Provide either subjectId or subjectEmail")
	// A person is not an agent with its own key.
	_, err = f.api().Request(f.ctx, aliceSession, Input[apitypes.DelegationsRequestInput](f.in("subjectEmail", "alice@acme.test", "scopes", []any{"documents:read"}, "reason", "x")))
	expectError(t, err, "ACCESS_DENIED", "Only an agent using its own API key can do this")
	_, err = f.api().DecideConfirmation(f.ctx, aliceSession, Input[apitypes.DelegationsDecideConfirmationInput](f.in("confirmationId", "c", "approve", "yes")))
	expectError(t, err, "INVALID_INPUT", "approve must be a boolean")
	// Delegations already linking the two are refused.
	f.grant(aliceSession, "agentId", agent.Get("id"), "scopes", []any{"documents:read"})
	expectError(t, grant("scopes", []any{"documents:read"}), "DELEGATION_EXISTS", "You already delegate to this agent; revoke that delegation first")
}

// handoffSetup is tests/delegation-handoffs.test.ts setup: Acme with alice (read and write on every document, but
// never document/secret for the research agent) and three agents with keys and no grants of their own.
type handoffAgent struct {
	id  any
	key core.CredentialInput
}

func handoffSetup(t *testing.T, assistantScopes ...any) (f *dlgFixture, alice *core.Object, assistant, researcher, writer handoffAgent, aliceSession core.CredentialInput) {
	t.Helper()
	f = newDlgFixture(t, nil)
	alice = f.person("alice")
	agent := func(name string) handoffAgent {
		created := f.agent(name)
		var members []any
		if name == "Assistant" && len(assistantScopes) > 0 {
			members = []any{"scopes", assistantScopes}
		}
		return handoffAgent{id: created.Get("id"), key: f.key(created.Get("id"), members...)}
	}
	assistant, researcher, writer = agent("Assistant"), agent("Researcher"), agent("Writer")
	document := core.NewObject("version", 1.0, "statements", []any{
		core.NewObject("effect", "allow", "actions", []any{"documents:read", "documents:write"}, "resources", []any{"document/*"}),
		core.NewObject("effect", "deny", "actions", []any{"documents:read"}, "resources", []any{"document/secret"},
			"conditions", core.NewObject("ArrayContains", core.NewObject("principal.delegationChain", []any{researcher.id}))),
	})
	f.roleFor(alice.Get("id"), "Editor", document)
	aliceSession = f.login("alice")
	return
}

func TestDelegationHandoffsLetAnAgentHandPartOfTheWorkOn(t *testing.T) {
	f, alice, assistant, researcher, _, aliceSession := handoffSetup(t)
	delegation := f.grant(aliceSession, "agentId", assistant.id, "scopes", []any{"documents:*"}, "handoff", core.NewObject("agents", []any{researcher.id}))
	if core.MustStringify(delegation.Get("handoff")) != core.MustStringify(core.NewObject("depth", 1.0, "agents", []any{researcher.id})) {
		t.Fatalf("handoff %s", core.MustStringify(delegation.Get("handoff")))
	}
	acting := f.token(f.assume(assistant.key, delegation.Get("id")))

	handoff, err := f.handoff(acting, "agentId", researcher.id, "scopes", []any{"documents:read"}, "reason", "Find the sources for the report")
	requirePorted(t, err)
	dlgMatches(t, handoff, core.NewObject("status", "active", "requestedBy", "handoff", "parentId", delegation.Get("id"),
		"agent", core.NewObject("id", researcher.id), "subject", core.NewObject("id", alice.Get("id")), "scopes", []any{"documents:read"}))
	if core.MustStringify(handoff.Get("chain")) != core.MustStringify([]any{core.NewObject("id", assistant.id, "name", "Assistant")}) {
		t.Fatalf("chain %s", core.MustStringify(handoff.Get("chain")))
	}
	if handoff.Has("handoff") || handoff.Get("expiresAt") != f.now()+3600_000 {
		t.Fatalf("handoff %s", core.MustStringify(handoff))
	}

	// The researcher opens its own sessions for alice with its own key, within the hand-off.
	research := f.assume(researcher.key, handoff.Get("id"))
	dlgMatches(t, research.Get("session").(*core.Object), core.NewObject("identityId", alice.Get("id"), "agentId", researcher.id))
	researchToken := jsString(research.Get("token"))
	if !f.allowed(researchToken, "documents:read") || f.allowed(researchToken, "documents:write") {
		t.Fatal("the hand-off's scope must bound the researcher")
	}
	// Policies see the whole chain: alice keeps document/secret away from anything the researcher does.
	if f.allowed(researchToken, "documents:read", "secret") || !f.allowed(acting.Token, "documents:read", "secret") {
		t.Fatal("the delegation chain must reach the policies")
	}

	// Alice sees the hand-off.
	mine := dlgIDs(f.items(f.api().ListMine(f.ctx, aliceSession, Input[apitypes.DelegationsListMineInput](f.in()))))
	expected := []string{jsString(delegation.Get("id")), jsString(handoff.Get("id"))}
	sort.Strings(mine)
	sort.Strings(expected)
	if !reflect.DeepEqual(mine, expected) {
		t.Fatalf("listMine %v", mine)
	}

	// The researcher's own direct delegations are unaffected by the hand-off.
	direct := f.grant(aliceSession, "agentId", researcher.id, "scopes", []any{"documents:read"})
	if direct.Get("status") != "active" {
		t.Fatal("a direct delegation must be possible")
	}

	// Revoking alice's delegation ends the hand-off and its sessions with it.
	if f.revoke(aliceSession, delegation.Get("id")).Get("status") != "revoked" {
		t.Fatal("expected revoked")
	}
	if f.get(aliceSession, handoff.Get("id")).Get("status") != "revoked" {
		t.Fatal("the hand-off must be revoked too")
	}
	_, err = f.iam.Authenticate(f.ctx, core.CredentialInput{Token: researchToken})
	if known := iamError(t, err); known.Status != 401 {
		t.Fatalf("expected 401, got %+v", known)
	}
	audit := f.items(f.iam.API.Audit.List(f.ctx, f.owner, Input[apitypes.AuditListInput](f.in("action", "delegation:revoke"))))
	if member(audit[0].Get("metadata"), "handoffsRevoked") != 1.0 {
		t.Fatalf("audit %s", core.MustStringify(audit[0]))
	}

	// The delegation's activity includes the researcher's work.
	activity := f.items(f.api().Activity(f.ctx, aliceSession, Input[apitypes.DelegationsActivityInput](f.in("delegationId", delegation.Get("id")))))
	found := false
	for _, event := range activity {
		if member(event.Get("sessionContext"), "agentId") == researcher.id {
			found = true
		}
	}
	if !found {
		t.Fatal("the activity must include the researcher's work")
	}
}

func TestDelegationHandoffsOnlyHandOnWhatThePersonAllowed(t *testing.T) {
	f, _, assistant, researcher, writer, aliceSession := handoffSetup(t)
	plain := f.grant(aliceSession, "agentId", assistant.id, "scopes", []any{"documents:*"})
	acting := f.token(f.assume(assistant.key, plain.Get("id")))
	handOn := func(credential core.CredentialInput, agentID any, scopes ...any) (*core.Object, error) {
		if len(scopes) == 0 {
			scopes = []any{"documents:read"}
		}
		return f.handoff(credential, "agentId", agentID, "scopes", scopes)
	}
	_, err := handOn(acting, researcher.id)
	expectCodeOrSkip(t, err, "DELEGATION_NOT_ALLOWED")
	// Only delegated sessions hand work on.
	_, err = handOn(assistant.key, researcher.id)
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	_, err = handOn(aliceSession, researcher.id)
	expectCodeOrSkip(t, err, "ACCESS_DENIED")

	f.revoke(aliceSession, plain.Get("id"))
	fresh := f.login("alice")
	deep := f.grant(fresh, "agentId", assistant.id, "scopes", []any{"documents:*"}, "confirm", []any{"documents:write"},
		"handoff", core.NewObject("agents", []any{researcher.id, writer.id}, "depth", 2.0))
	assistantSession := f.token(f.assume(assistant.key, deep.Get("id")))
	first, err := handOn(assistantSession, writer.id, "documents:*")
	requirePorted(t, err)
	// Depth and the person's confirm list travel down the chain.
	dlgMatches(t, first, core.NewObject("handoff", core.NewObject("agents", []any{researcher.id, writer.id}, "depth", 1.0),
		"confirm", []any{"documents:write"}))
	writerSession := f.token(f.assume(writer.key, first.Get("id")))
	if f.allowed(writerSession.Token, "documents:write", "draft") || !f.allowed(writerSession.Token, "documents:read") {
		t.Fatal("the writer must confirm writes")
	}
	// The writer asks alice to confirm, as her own delegate would have to.
	confirmation := f.object(f.api().RequestConfirmation(f.ctx, writerSession, Input[apitypes.DelegationsRequestConfirmationInput](f.in(
		"action", "documents:write", "resource", core.NewObject("type", "document", "id", "draft"), "reason", "Save the draft",
	))))
	f.object(f.api().DecideConfirmation(f.ctx, fresh, Input[apitypes.DelegationsDecideConfirmationInput](f.in(
		"confirmationId", confirmation.Get("id"), "approve", true,
	))))
	if !f.allowed(writerSession.Token, "documents:write", "draft") {
		t.Fatal("the approval opens the write")
	}
	// No agent appears twice in a chain.
	_, err = handOn(writerSession, assistant.id)
	expectCodeOrSkip(t, err, "DELEGATION_NOT_ALLOWED")
	second, err := handOn(writerSession, researcher.id)
	requirePorted(t, err)
	chain := []any{}
	for _, item := range second.Get("chain").([]any) {
		chain = append(chain, member(item, "id"))
	}
	if !reflect.DeepEqual(chain, []any{assistant.id, writer.id}) || second.Has("handoff") {
		t.Fatalf("second %s", core.MustStringify(second))
	}
	researchSession := f.token(f.assume(researcher.key, second.Get("id")))
	if !f.allowed(researchSession.Token, "documents:read") {
		t.Fatal("the researcher reads")
	}
	// The end of the line: no further hand-offs.
	_, err = handOn(researchSession, writer.id)
	expectCodeOrSkip(t, err, "DELEGATION_NOT_ALLOWED")

	// Suspending an agent in the middle of the chain stops everything below it.
	f.patchAgent(writer.id, []any{"status", "suspended"})
	_, err = f.iam.Authenticate(f.ctx, researchSession)
	if known := iamError(t, err); known.Status != 401 {
		t.Fatalf("expected 401, got %+v", known)
	}
	f.patchAgent(writer.id, []any{"status", "active"})
	if !f.allowed(researchSession.Token, "documents:read") {
		t.Fatal("resuming the writer restores the chain")
	}
}

func TestDelegationHandoffsEndWithTheKeyThatMadeThem(t *testing.T) {
	f, alice, assistant, researcher, _, aliceSession := handoffSetup(t)
	delegation := f.grant(aliceSession, "agentId", assistant.id, "scopes", []any{"documents:*"}, "handoff", core.NewObject())
	acting := f.token(f.assume(assistant.key, delegation.Get("id")))
	handOn := func() *core.Object {
		t.Helper()
		handoff, err := f.handoff(acting, "agentId", researcher.id, "scopes", []any{"documents:read"}, "expiresInSeconds", 300*86_400.0)
		requirePorted(t, err)
		return handoff
	}
	first := handOn()
	// Never past the key the assistant acted with (a key lasts 90 days by default).
	keys := f.items(f.iam.API.Credentials.List(f.ctx, f.owner, Input[apitypes.CredentialsListInput](f.in())))
	var assistantKey *core.Object
	for _, key := range keys {
		if key.Get("identityId") == assistant.id {
			assistantKey = key
		}
	}
	if jsNumber(first.Get("expiresAt")) > jsNumber(assistantKey.Get("expiresAt")) {
		t.Fatalf("the hand-off outlives the key: %v > %v", first.Get("expiresAt"), assistantKey.Get("expiresAt"))
	}
	research := f.token(f.assume(researcher.key, first.Get("id")))
	if !f.allowed(research.Token, "documents:read") {
		t.Fatal("the researcher reads")
	}

	// The assistant revokes its own hand-off from its delegated session: the record names the assistant, not alice.
	second := handOn()
	revoked := f.revoke(acting, second.Get("id"))
	if revoked.Get("revokedBy") != assistant.id || revoked.Get("revokedBy") == alice.Get("id") {
		t.Fatalf("revokedBy %v", revoked.Get("revokedBy"))
	}

	// Revoking the assistant's key (a compromised agent) stops what it handed on at once.
	f.ported(f.iam.API.Credentials.Revoke(f.ctx, f.ownerSignIn(), Input[apitypes.CredentialsRevokeInput](f.in("credentialId", assistantKey.Get("id")))))
	_, err := f.iam.Authenticate(f.ctx, research)
	if known := iamError(t, err); known.Status != 401 {
		t.Fatalf("expected 401, got %+v", known)
	}
	_, err = f.api().Assume(f.ctx, researcher.key, Input[apitypes.DelegationsAssumeInput](f.in("delegationId", first.Get("id"))))
	expectCodeOrSkip(t, err, "DELEGATION_INACTIVE")
}

func TestDelegationHandoffsNeverHandOnMoreThanTheHandingSessionCouldDo(t *testing.T) {
	// The assistant's key may only read, even though alice's delegation covers writing.
	f, _, assistant, _, writer, aliceSession := handoffSetup(t, "documents:read")
	delegation := f.grant(aliceSession, "agentId", assistant.id, "scopes", []any{"documents:*"}, "handoff", core.NewObject())
	if core.MustStringify(delegation.Get("handoff")) != `{"depth":1}` {
		t.Fatalf("handoff %s", core.MustStringify(delegation.Get("handoff")))
	}
	acting := f.token(f.assume(assistant.key, delegation.Get("id")))
	if f.allowed(acting.Token, "documents:write") {
		t.Fatal("the key may only read")
	}
	handoff, err := f.handoff(acting, "agentId", writer.id, "scopes", []any{"documents:*"})
	requirePorted(t, err)
	writing := f.token(f.assume(writer.key, handoff.Get("id")))
	if !f.allowed(writing.Token, "documents:read") || f.allowed(writing.Token, "documents:write") {
		t.Fatal("the hand-off keeps the handing key's limits")
	}

	// The approval path: an agent's request may ask for hand-offs, but they count only when the person states them.
	request := f.object(f.api().Request(f.ctx, writer.key, Input[apitypes.DelegationsRequestInput](f.in(
		"subjectEmail", "alice@acme.test", "scopes", []any{"documents:read"}, "reason", "Draft the weekly summary",
		"handoff", core.NewObject("depth", 2.0),
	))))
	if core.MustStringify(request.Get("handoff")) != `{"depth":2}` {
		t.Fatalf("request handoff %s", core.MustStringify(request.Get("handoff")))
	}
	approved := f.object(f.api().Approve(f.ctx, aliceSession, Input[apitypes.DelegationsApproveInput](f.in("delegationId", request.Get("id")))))
	if approved.Has("handoff") {
		t.Fatal("a plain approval leaves hand-offs out")
	}
	other := f.agent("Other")
	for _, setting := range []string{`{"agents":["not-an-agent"]}`, `{"depth":4}`, `{"agents":[]}`} {
		_, err := f.api().Grant(f.ctx, aliceSession, Input[apitypes.DelegationsGrantInput](f.in(
			"agentId", other.Get("id"), "scopes", []any{"documents:read"}, "handoff", obj(t, setting),
		)))
		expectCodeOrSkip(t, err, "INVALID_INPUT")
	}
}

func TestDelegationSpendCapsAreSetChangedOrRemovedByThePerson(t *testing.T) {
	f, _, agent, agentKey, aliceSession := dlgSetup(t)
	request := f.object(f.api().Request(f.ctx, agentKey, Input[apitypes.DelegationsRequestInput](f.in(
		"subjectEmail", "alice@acme.test", "scopes", []any{"documents:read"}, "reason", "Summarize your inbox",
		"spend", obj(t, `{"period":"month","maxCostUsd":50}`),
	))))
	dlgMatches(t, request.Get("spend").(*core.Object), obj(t, `{"period":"month","maxCostUsd":50}`))
	approved := f.object(f.api().Approve(f.ctx, aliceSession, Input[apitypes.DelegationsApproveInput](f.in(
		"delegationId", request.Get("id"), "spend", obj(t, `{"period":"minute","maxRequests":1}`),
	))))
	spend := approved.Get("spend").(*core.Object)
	dlgMatches(t, spend, obj(t, `{"period":"minute","maxRequests":1}`))
	if spend.Has("maxCostUsd") {
		t.Fatal("the new cap replaces the old one")
	}
	_ = agent
}

// Unit tests of the module's helpers.

func TestDelegationSpendSetting(t *testing.T) {
	for _, value := range []any{core.Undefined, nil} {
		if spend, err := SpendSetting(value); spend != nil || err != nil {
			t.Fatalf("nullish: %v %v", spend, err)
		}
	}
	spend := must(SpendSetting(obj(t, `{"period":"day","maxTokens":1000,"maxCostUsd":0.0000015,"maxRequests":5}`)))
	if core.MustStringify(spend) != `{"period":"day","maxTokens":1000,"maxCostMicros":2,"maxRequests":5}` {
		t.Fatalf("spend %s", core.MustStringify(spend))
	}
	cases := map[string]string{
		`{"period":"week","maxRequests":1}`:       "spend.period must be 'minute', 'hour', 'day' or 'month'",
		`{"period":"day"}`:                        "spend needs maxTokens, maxCostUsd or maxRequests",
		`{"period":"day","maxCostUsd":0}`:         "spend.maxCostUsd must be at least 0.000001 and at most 1000000",
		`{"period":"day","maxCostUsd":"1"}`:       "spend.maxCostUsd must be at least 0.000001 and at most 1000000",
		`{"period":"day","maxCostUsd":0.0000001}`: "spend.maxCostUsd must be at least 0.000001 and at most 1000000",
		`{"period":"day","maxTokens":1.5}`:        "Invalid spend.maxTokens",
		`{"period":"day","maxRequests":0}`:        "Invalid spend.maxRequests",
	}
	for input, message := range cases {
		_, err := SpendSetting(obj(t, input))
		expectError(t, err, "INVALID_INPUT", message)
	}
	_, err := SpendSetting([]any{})
	expectError(t, err, "INVALID_INPUT", "Expected an object")
}

func TestDelegationConfirmPatterns(t *testing.T) {
	if patterns, err := ConfirmPatterns(core.Undefined); patterns != nil || err != nil {
		t.Fatal("undefined reads as none")
	}
	if patterns, err := ConfirmPatterns([]any{}); patterns != nil || err != nil {
		t.Fatal("an empty list reads as none")
	}
	patterns := must(ConfirmPatterns([]any{"billing:*", "documents:wri?e", "billing:*"}))
	if !reflect.DeepEqual(patterns, []string{"billing:*", "documents:wri?e"}) {
		t.Fatalf("patterns %v", patterns)
	}
	_, err := ConfirmPatterns([]any{":bad"})
	expectError(t, err, "INVALID_INPUT", "Invalid action pattern :bad")
	_, err = ConfirmPatterns(nil)
	expectError(t, err, "INVALID_INPUT", "Invalid confirm")
	many := []any{}
	for index := 0; index < 51; index++ {
		many = append(many, "action:"+jsString(float64(index)))
	}
	_, err = ConfirmPatterns(many)
	expectError(t, err, "INVALID_INPUT", "confirm may list at most 50 actions")
}

func TestDelegationActionsMayOverlap(t *testing.T) {
	cases := []struct {
		pattern, scope string
		overlap        bool
	}{
		{"documents:write", "documents:write", true},
		{"documents:write", "documents:read", false},
		{"documents:*", "documents:read", true},
		{"documents:wri?e", "documents:write", true},
		{"documents:write", "documents:*", true},
		{"billing:*", "documents:*", false},
		{"*:read", "documents:*", true},
		{"*:read", "*:write", false},
		{"${principal.action}", "documents:read", true},
		{"doc*", "documents:*", true},
	}
	for _, item := range cases {
		if got := must(ActionsMayOverlap(item.pattern, item.scope)); got != item.overlap {
			t.Fatalf("actionsMayOverlap(%q, %q) = %v", item.pattern, item.scope, got)
		}
	}
}

func TestDelegationPolicyAllowsScope(t *testing.T) {
	document := func(text string) *core.Object { return obj(t, text) }
	allowAll := document(`{"version":1,"statements":[{"effect":"allow","actions":["documents:*"],"resources":["*"]}]}`)
	for scope, allowed := range map[string]bool{"documents:read": true, "documents:*": true, "billing:read": false, "*": false} {
		if must(PolicyAllowsScope(allowAll, scope)) != allowed {
			t.Fatalf("documents:* on %s", scope)
		}
	}
	limited := document(`{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["document/team-*"]}]}`)
	if must(PolicyAllowsScope(limited, "documents:read")) {
		t.Fatal("a resource-limited allow does not count")
	}
	conditional := document(`{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"],"conditions":{"Bool":{"principal.mfa":true}}}]}`)
	if must(PolicyAllowsScope(conditional, "documents:read")) {
		t.Fatal("a conditional allow does not count")
	}
	emptyConditions := document(`{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"],"conditions":{}}]}`)
	if !must(PolicyAllowsScope(emptyConditions, "documents:read")) {
		t.Fatal("empty conditions are none")
	}
	question := document(`{"version":1,"statements":[{"effect":"allow","actions":["documents:rea?"],"resources":["*"]}]}`)
	if !must(PolicyAllowsScope(question, "documents:read")) || must(PolicyAllowsScope(question, "documents:*")) {
		t.Fatal("a ? pattern covers an action but never a * scope")
	}
	denied := document(`{"version":1,"statements":[{"effect":"allow","actions":["*"],"resources":["*"]},{"effect":"deny","actions":["documents:write"],"resources":["document/x"]}]}`)
	if !must(PolicyAllowsScope(denied, "documents:read")) || must(PolicyAllowsScope(denied, "documents:write")) || must(PolicyAllowsScope(denied, "documents:*")) {
		t.Fatal("a deny that may touch the scope refuses it")
	}
}

func TestDelegationHandoffSettingAndLifetimes(t *testing.T) {
	f := newDlgFixture(t, nil)
	agent := f.agent("Helper")
	person := f.person("alice")
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		for _, value := range []any{core.Undefined, nil} {
			if setting, err := HandoffSetting(ctx, tx, f.tenantID, value); setting != nil || err != nil {
				t.Fatalf("nullish: %v %v", setting, err)
			}
		}
		setting := must(HandoffSetting(ctx, tx, f.tenantID, core.NewObject()))
		if core.MustStringify(setting) != `{"depth":1}` {
			t.Fatalf("default %s", core.MustStringify(setting))
		}
		setting = must(HandoffSetting(ctx, tx, f.tenantID, core.NewObject("agents", []any{agent.Get("id"), agent.Get("id")}, "depth", 3.0)))
		if core.MustStringify(setting) != core.MustStringify(core.NewObject("agents", []any{agent.Get("id")}, "depth", 3.0)) {
			t.Fatalf("setting %s", core.MustStringify(setting))
		}
		_, err := HandoffSetting(ctx, tx, f.tenantID, core.NewObject("depth", 4.0))
		expectError(t, err, "INVALID_INPUT", "Invalid handoff.depth")
		_, err = HandoffSetting(ctx, tx, f.tenantID, core.NewObject("agents", []any{}))
		expectError(t, err, "INVALID_INPUT", "handoff.agents must name 1 to 20 agents")
		_, err = HandoffSetting(ctx, tx, f.tenantID, core.NewObject("agents", []any{person.Get("id")}))
		expectError(t, err, "INVALID_INPUT", "handoff.agents: "+jsString(person.Get("id"))+" is not an agent of this tenant")
		return nil
	})
	if seconds := must(DelegationSeconds(core.Undefined)); seconds != 30*86_400 {
		t.Fatalf("fallback %v", seconds)
	}
	_, err := DelegationSeconds(299.0)
	expectError(t, err, "INVALID_INPUT", "Invalid expiresInSeconds")
	if !must(DelegationLive(core.NewObject("status", "active", "expiresAt", 10.0), 9)) || must(DelegationLive(core.NewObject("status", "active", "expiresAt", 10.0), 10)) {
		t.Fatal("delegationLive")
	}
	if !must(DelegationPending(core.NewObject("status", "pending", "expiresAt", 10.0), 9)) || must(DelegationPending(core.NewObject("status", "active", "expiresAt", 10.0), 9)) {
		t.Fatal("delegationPending")
	}
}

func TestDelegationRevokeDelegationsOfEndsHandoffsBelow(t *testing.T) {
	f, alice, assistant, researcher, writer, aliceSession := handoffSetup(t)
	delegation := f.grant(aliceSession, "agentId", assistant.id, "scopes", []any{"documents:*"},
		"handoff", core.NewObject("depth", 2.0))
	acting := f.token(f.assume(assistant.key, delegation.Get("id")))
	first, err := f.handoff(acting, "agentId", writer.id, "scopes", []any{"documents:read"})
	requirePorted(t, err)
	writing := f.token(f.assume(writer.key, first.Get("id")))
	second, err := f.handoff(writing, "agentId", researcher.id, "scopes", []any{"documents:read"})
	requirePorted(t, err)
	f.assume(researcher.key, second.Get("id"))
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		stored, err := tx.Get(ctx, "identities", jsString(alice.Get("id")))
		if err != nil {
			return err
		}
		ended, err := RevokeDelegationsOf(ctx, f.iam.Context, tx, stored, "admin")
		if err != nil {
			return err
		}
		// alice's own delegation (as the person), and the two hand-offs (also hers, and below it).
		if ended < 3 {
			t.Fatalf("expected the chain ended, got %v", ended)
		}
		for _, id := range []any{delegation.Get("id"), first.Get("id"), second.Get("id")} {
			record, err := tx.Get(ctx, "delegations", jsString(id))
			if err != nil {
				return err
			}
			if record.Get("status") != "revoked" || record.Get("revokedBy") != "admin" ||
				record.Get("sessionsRevokedBefore") != jsNumber(record.Get("revokedAt"))+1 {
				t.Fatalf("not revoked: %s", core.MustStringify(record))
			}
		}
		sessions, err := tx.Find(ctx, "sessions", core.NewObject("kind", "delegated"), nil)
		if err != nil {
			return err
		}
		if len(sessions) != 0 {
			t.Fatalf("delegated sessions remain: %d", len(sessions))
		}
		return nil
	})
	if !slices.Contains([]string{"revoked"}, jsString(f.get(f.owner, second.Get("id")).Get("status"))) {
		t.Fatal("the hand-off reads as revoked")
	}
}
