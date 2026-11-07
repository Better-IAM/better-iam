package server

// Bindings and authorities API tests, after tests/eligible-bindings.test.ts, tests/activation-approvals.test.ts and
// tests/access-windows.test.ts: eligibility settings, just-in-time activation and its rules, approval-gated requests
// with their emails and audit events, revocation, eligibility turned off, group subjects, and delegated grant
// authorities. Roles, policies, groups and memberships are seeded directly in the store (the API groups that write
// them are ported separately); the bindings themselves go through the bindings API.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

type bindingsFixture struct {
	*decisionFixture
	clock     *atomic.Int64
	rootID    string
	owner     core.CredentialInput
	inboxMu   sync.Mutex
	inbox     []auth.DeliveryMessage
	authority string
}

func newBindingsFixture(t *testing.T) *bindingsFixture {
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

// refreshOwner signs the root administrator in again (after the clock moved past the session).
func (f *bindingsFixture) refreshOwner() {
	f.t.Helper()
	root, err := f.iam.Store.Get(context.Background(), "identities", f.rootID)
	if err != nil || root == nil {
		f.t.Fatalf("root identity: %v", err)
	}
	f.owner = core.CredentialInput{Token: f.signIn(root, true)}
}

func (f *bindingsFixture) signInAgain(identityID string) core.CredentialInput {
	f.t.Helper()
	identity, err := f.iam.Store.Get(context.Background(), "identities", identityID)
	if err != nil || identity == nil {
		f.t.Fatalf("identity %s: %v", identityID, err)
	}
	return core.CredentialInput{Token: f.signIn(identity, false)}
}

func (f *bindingsFixture) now() float64     { return float64(f.clock.Load()) }
func (f *bindingsFixture) advance(ms int64) { f.clock.Add(ms) }

// role seeds a role whose policy allows actions on every resource.
func (f *bindingsFixture) role(id, name string, actions ...string) {
	statements := make([]*core.Object, len(actions))
	for index, action := range actions {
		statements[index] = allowStatement(action, "*")
	}
	f.seed("policies", core.NewObject("id", "policy-"+id, "tenantId", f.tenantID, "name", name+" policy", "document", document(statements...), "version", 1.0, "authorityId", f.authority))
	f.seed("roles", core.NewObject("id", id, "tenantId", f.tenantID, "name", name, "policyIds", []any{"policy-" + id}, "authorityId", f.authority))
}

func (f *bindingsFixture) group(id, name string) {
	f.seed("groups", core.NewObject("id", id, "tenantId", f.tenantID, "name", name, "uniqueKey", name))
}

func (f *bindingsFixture) addMember(groupID, identityID string) {
	f.seed("groupMembers", core.NewObject("id", groupID+":"+identityID, "tenantId", f.tenantID, "uniqueKey", groupID+":"+identityID, "groupId", groupID, "identityId", identityID))
}

func (f *bindingsFixture) removeMember(groupID, identityID string) {
	f.t.Helper()
	if err := f.iam.Store.Transaction(context.Background(), func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "groupMembers", groupID+":"+identityID)
	}); err != nil {
		f.t.Fatal(err)
	}
}

// body is a request body for the fixture's tenant with members.
func (f *bindingsFixture) body(members ...any) *core.Object {
	body := core.NewObject("tenantId", f.tenantID)
	for index := 0; index+1 < len(members); index += 2 {
		body.Set(members[index].(string), members[index+1])
	}
	return body
}

func (f *bindingsFixture) member(email, name string) (string, core.CredentialInput) {
	identity := f.createIdentity(email, name, "a strong "+name+" password")
	return jsString(identity.Get("id")), core.CredentialInput{Token: f.signIn(identity, false)}
}

func (f *bindingsFixture) mustMember(email, name string) string {
	id, _ := f.member(email, name)
	return id
}

func (f *bindingsFixture) create(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := f.iam.API.Bindings.Create(context.Background(), credential, Input[apitypes.BindingsCreateInput](f.body(members...)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *bindingsFixture) mustCreate(members ...any) *core.Object {
	f.t.Helper()
	binding, err := f.create(f.owner, members...)
	if err != nil {
		f.t.Fatalf("create binding: %v", err)
	}
	return binding
}

func (f *bindingsFixture) activate(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := f.iam.API.Bindings.Activate(context.Background(), credential, Input[apitypes.BindingsActivateInput](f.body(members...)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *bindingsFixture) mustActivate(credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	activation, err := f.activate(credential, members...)
	if err != nil {
		f.t.Fatalf("activate: %v", err)
	}
	return activation
}

func (f *bindingsFixture) update(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := f.iam.API.Bindings.Update(context.Background(), credential, Input[apitypes.BindingsUpdateInput](f.body(members...)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *bindingsFixture) mustUpdate(members ...any) *core.Object {
	f.t.Helper()
	binding, err := f.update(f.owner, members...)
	if err != nil {
		f.t.Fatalf("update binding: %v", err)
	}
	return binding
}

func (f *bindingsFixture) list(members ...any) []any {
	f.t.Helper()
	out, err := f.iam.API.Bindings.List(context.Background(), f.owner, Input[apitypes.BindingsListInput](f.body(members...)))
	if err != nil {
		f.t.Fatalf("list bindings: %v", err)
	}
	return out.Value.([]any)
}

func (f *bindingsFixture) activations(members ...any) []any {
	f.t.Helper()
	out, err := f.iam.API.Bindings.ListActivations(context.Background(), f.owner, Input[apitypes.BindingsListActivationsInput](f.body(members...)))
	if err != nil {
		f.t.Fatalf("list activations: %v", err)
	}
	return out.Value.([]any)
}

func (f *bindingsFixture) approvals(credential core.CredentialInput) ([]any, error) {
	out, err := f.iam.API.Bindings.ListApprovals(context.Background(), credential, Input[apitypes.BindingsListApprovalsInput](f.body()))
	if err != nil {
		return nil, err
	}
	return out.Value.([]any), nil
}

func (f *bindingsFixture) approve(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := f.iam.API.Bindings.ApproveActivation(context.Background(), credential, Input[apitypes.BindingsApproveActivationInput](f.body(members...)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *bindingsFixture) deny(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := f.iam.API.Bindings.DenyActivation(context.Background(), credential, Input[apitypes.BindingsDenyActivationInput](f.body(members...)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *bindingsFixture) deactivate(credential core.CredentialInput, activationID string) (*core.Object, error) {
	out, err := f.iam.API.Bindings.Deactivate(context.Background(), credential, Input[apitypes.BindingsDeactivateInput](f.body("activationId", activationID)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *bindingsFixture) mine(credential core.CredentialInput) []any {
	f.t.Helper()
	out, err := f.iam.API.Bindings.ListMine(context.Background(), credential, Input[apitypes.BindingsListMineInput](f.body()))
	if err != nil {
		f.t.Fatalf("listMine: %v", err)
	}
	return out.Value.([]any)
}

// can is whether the credential may perform an iam action on the tenant.
func (f *bindingsFixture) can(credential core.CredentialInput, action string) bool {
	f.t.Helper()
	decision, err := f.iam.Authorize(context.Background(), AuthorizationRequest{Credential: credential, TenantID: f.tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: f.tenantID}})
	if err != nil {
		f.t.Fatalf("authorize %s: %v", action, err)
	}
	return decision.Allowed
}

func (f *bindingsFixture) lastAudit(action string) *core.Object {
	f.t.Helper()
	events := f.audits(action)
	if len(events) == 0 {
		f.t.Fatalf("no %s audit event", action)
	}
	latest := events[0]
	for _, event := range events[1:] {
		if jsNumber(event.Get("timestamp")) >= jsNumber(latest.Get("timestamp")) {
			latest = event
		}
	}
	return latest
}

func (f *bindingsFixture) dispatch() []auth.DeliveryMessage {
	f.t.Helper()
	if _, err := f.iam.Auth.DispatchOutbox(context.Background(), 0); err != nil {
		f.t.Fatal(err)
	}
	f.inboxMu.Lock()
	defer f.inboxMu.Unlock()
	return append([]auth.DeliveryMessage(nil), f.inbox...)
}

func ids(items []any) []string {
	out := make([]string, len(items))
	for index, item := range items {
		out[index] = jsString(member(item, "id"))
	}
	return out
}

func findByID(items []any, id string) *core.Object {
	for _, item := range items {
		if object, ok := item.(*core.Object); ok && object.Get("id") == id {
			return object
		}
	}
	return nil
}

func expectValue(t *testing.T, label string, got, want any) {
	t.Helper()
	if !stsStrictEqual(core.Normalize(got), core.Normalize(want)) {
		t.Errorf("%s: got %v, want %v", label, got, want)
	}
}

func TestBindingsEligibleActivationRulesAndExpiry(t *testing.T) {
	f := newBindingsFixture(t)
	aliceID, asAlice := f.member("alice@acme.test", "alice")
	bobID, asBob := f.member("bob@acme.test", "bob")
	f.role("auditor", "Auditor", "iam:audit:read")
	f.role("member", "Member", "iam:bindings:activate")
	for _, id := range []string{aliceID, bobID} {
		f.mustCreate("roleId", "member", "subjectType", "identity", "subjectId", id)
	}
	// Activation settings belong to eligible bindings only.
	_, err := f.create(f.owner, "roleId", "auditor", "subjectType", "identity", "subjectId", aliceID, "maxActivationMs", 60_000.0)
	expectError(t, err, "INVALID_INPUT", "Activation settings apply to eligible bindings only")
	_, err = f.create(f.owner, "roleId", "auditor", "subjectType", "identity", "subjectId", aliceID, "eligible", "yes")
	expectError(t, err, "INVALID_INPUT", "eligible must be boolean")
	_, err = f.create(f.owner, "roleId", "auditor", "subjectType", "identity", "subjectId", aliceID, "eligible", true, "maxActivationMs", 8*86400_000.0)
	expectError(t, err, "INVALID_INPUT", "Invalid maxActivationMs")
	_, err = f.create(f.owner, "roleId", "auditor", "subjectType", "robot", "subjectId", aliceID)
	expectError(t, err, "INVALID_INPUT", "Invalid subject type")
	// Explicit false flags are harmless on standing bindings.
	standingFlags := f.mustCreate("roleId", "auditor", "subjectType", "identity", "subjectId", bobID, "requireMfa", false, "requireApproval", false)
	if standingFlags.Has("requireMfa") || standingFlags.Has("eligible") {
		t.Errorf("standing binding kept flags: %v", standingFlags)
	}
	f.removeBinding(jsString(standingFlags.Get("id")))
	eligible := f.mustCreate("roleId", "auditor", "subjectType", "identity", "subjectId", aliceID, "eligible", true, "maxActivationMs", 600_000.0, "requireJustification", true)
	eligibleID := jsString(eligible.Get("id"))
	expectValue(t, "eligible", eligible.Get("eligible"), true)
	expectValue(t, "maxActivationMs", eligible.Get("maxActivationMs"), 600_000.0)
	expectValue(t, "uniqueKey", eligible.Get("uniqueKey"), "identity:"+aliceID+":auditor:"+f.authority)
	if got := ids(f.list("eligible", true)); len(got) != 1 || got[0] != eligibleID {
		t.Errorf("eligible list: %v", got)
	}
	if got := f.list("roleId", "member", "eligible", false); len(got) != 2 {
		t.Errorf("standing member bindings: %v", got)
	}
	if got := f.list("roleId", "auditor", "eligible", false); len(got) != 0 {
		t.Errorf("standing auditor bindings: %v", got)
	}
	if f.can(asAlice, "iam:audit:read") {
		t.Fatal("an eligible binding granted before activation")
	}
	// She can see what she may elevate to without holding iam:bindings:read.
	mine := f.mine(asAlice)
	listed := findByID(mine, eligibleID)
	if listed == nil || listed.Get("eligible") != true || !isUndefined(listed.Get("activation")) {
		t.Errorf("listMine eligible: %v", listed)
	}
	activate := func(credential core.CredentialInput, members ...any) (*core.Object, error) {
		return f.activate(credential, append([]any{"bindingId", eligibleID}, members...)...)
	}
	_, err = activate(asAlice)
	expectError(t, err, "INVALID_INPUT", "This activation requires a justification")
	_, err = activate(asAlice, "justification", "quarterly review", "durationMs", 600_001.0)
	expectError(t, err, "INVALID_INPUT", "Invalid durationMs")
	_, err = activate(asBob, "justification", "not mine")
	expectError(t, err, "ACCESS_DENIED", "This binding does not apply to you")
	standing := f.list("subjectId", aliceID, "eligible", false)
	_, err = f.activate(asAlice, "bindingId", jsString(member(standing[0], "id")), "justification", "standing role")
	expectError(t, err, "INVALID_TRANSITION", "This binding is not eligible for activation")
	activation, err := activate(asAlice, "justification", "quarterly review")
	if err != nil {
		t.Fatal(err)
	}
	expectValue(t, "bindingId", activation.Get("bindingId"), eligibleID)
	expectValue(t, "identityId", activation.Get("identityId"), aliceID)
	expectValue(t, "roleId", activation.Get("roleId"), "auditor")
	expectValue(t, "active", activation.Get("active"), true)
	expectValue(t, "status", activation.Get("status"), "active")
	expectValue(t, "justification", activation.Get("justification"), "quarterly review")
	expectValue(t, "expiresAt", activation.Get("expiresAt"), f.now()+600_000)
	if activation.Has("uniqueKey") {
		t.Errorf("the public activation carries its unique key: %v", activation)
	}
	if !f.can(asAlice, "iam:audit:read") {
		t.Fatal("the activation did not grant")
	}
	_, err = activate(asAlice, "justification", "again")
	expectError(t, err, "CONFLICT", "This role is already active for you")
	started := f.lastAudit("binding:activate")
	expectValue(t, "actor", started.Get("actorId"), aliceID)
	expectValue(t, "resource", started.Get("resourceId"), eligibleID)
	expectValue(t, "metadata.activationId", member(started.Get("metadata"), "activationId"), activation.Get("id"))
	expectValue(t, "metadata.roleId", member(started.Get("metadata"), "roleId"), "auditor")
	expectValue(t, "metadata.justification", member(started.Get("metadata"), "justification"), "quarterly review")
	if got := f.activations("roleId", "auditor"); len(got) != 1 {
		t.Errorf("live activations: %v", got)
	}
	listed = findByID(f.mine(asAlice), eligibleID)
	expectValue(t, "listMine activation", member(listed.Get("activation"), "id"), activation.Get("id"))
	f.advance(600_001)
	if f.can(asAlice, "iam:audit:read") {
		t.Fatal("an ended activation still grants")
	}
	if got := f.activations(); len(got) != 0 {
		t.Errorf("ended activation listed: %v", got)
	}
	if got := f.activations("includeExpired", true); len(got) != 1 || member(got[0], "active") != false {
		t.Errorf("includeExpired: %v", got)
	}
	// Re-activation replaces the ended record; the holder may end it early, nobody else.
	second, err := activate(asAlice, "justification", "follow-up", "durationMs", 60_000.0)
	if err != nil {
		t.Fatal(err)
	}
	expectValue(t, "second expiresAt", second.Get("expiresAt"), f.now()+60_000)
	if got := f.activations("includeExpired", true); len(got) != 1 {
		t.Errorf("one record per binding and identity: %v", got)
	}
	_, err = f.deactivate(asBob, jsString(second.Get("id")))
	expectError(t, err, "ACCESS_DENIED", "Only the holder can end this activation")
	if result, err := f.deactivate(asAlice, jsString(second.Get("id"))); err != nil || result.Get("deactivated") != true {
		t.Fatalf("deactivate: %v %v", result, err)
	}
	if f.can(asAlice, "iam:audit:read") {
		t.Fatal("a deactivated role still grants")
	}
	// Requiring MFA refuses password-only sessions.
	f.mustUpdate("bindingId", eligibleID, "requireMfa", true)
	_, err = activate(asAlice, "justification", "mfa")
	expectError(t, err, "MFA_REQUIRED", "Activation requires an MFA-verified session")
	f.mustUpdate("bindingId", eligibleID, "requireMfa", false, "requireJustification", false)
	third, err := activate(asAlice)
	if err != nil {
		t.Fatal(err)
	}
	if third.Has("justification") {
		t.Errorf("justification without one: %v", third)
	}
	// Administrators can end someone's activation, and turning eligibility off ends them all.
	revoked, err := f.iam.API.Bindings.RevokeActivation(context.Background(), f.owner, Input[apitypes.BindingsRevokeActivationInput](f.body("activationId", third.Get("id"))))
	if err != nil || member(revoked.Value, "deactivated") != true {
		t.Fatalf("revokeActivation: %v %v", revoked.Value, err)
	}
	ended := f.lastAudit("binding:deactivate")
	expectValue(t, "revoke actor", ended.Get("actorId"), f.rootID)
	expectValue(t, "revoke identity", member(ended.Get("metadata"), "identityId"), aliceID)
	expectValue(t, "revoke flag", member(ended.Get("metadata"), "revoked"), true)
	f.mustActivate(asAlice, "bindingId", eligibleID)
	_, err = f.update(f.owner, "bindingId", eligibleID)
	expectError(t, err, "INVALID_INPUT", "Nothing to update")
	turnedOff := f.mustUpdate("bindingId", eligibleID, "eligible", false)
	if turnedOff.Has("eligible") || turnedOff.Has("maxActivationMs") {
		t.Errorf("eligibility off kept settings: %v", turnedOff)
	}
	if got := f.activations("includeExpired", true); len(got) != 0 {
		t.Errorf("eligibility off kept activations: %v", got)
	}
	// Now a standing binding: the role applies without activation.
	if !f.can(asAlice, "iam:audit:read") {
		t.Fatal("the standing binding does not grant")
	}
	_, err = activate(asAlice)
	expectError(t, err, "INVALID_TRANSITION", "This binding is not eligible for activation")
}

// removeBinding deletes a binding record directly.
func (f *bindingsFixture) removeBinding(id string) {
	f.t.Helper()
	if err := f.iam.Store.Transaction(context.Background(), func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "bindings", id)
	}); err != nil {
		f.t.Fatal(err)
	}
}

func TestBindingsGroupSubjects(t *testing.T) {
	f := newBindingsFixture(t)
	bobID, asBob := f.member("bob@acme.test", "bob")
	f.group("responders", "Responders")
	f.addMember("responders", bobID)
	f.role("member", "Member", "iam:bindings:activate")
	f.role("responder", "Incident responder", "iam:identities:read")
	f.mustCreate("roleId", "member", "subjectType", "group", "subjectId", "responders")
	eligible := f.mustCreate("roleId", "responder", "subjectType", "group", "subjectId", "responders", "eligible", true)
	eligibleID := jsString(eligible.Get("id"))
	if f.can(asBob, "iam:identities:read") {
		t.Fatal("granted before activation")
	}
	listed := findByID(f.mine(asBob), eligibleID)
	if listed == nil || member(listed.Get("via"), "groupId") != "responders" || listed.Get("eligible") != true {
		t.Errorf("listMine group binding: %v", listed)
	}
	activation := f.mustActivate(asBob, "bindingId", eligibleID)
	// The default activation is one hour.
	expectValue(t, "default expiry", activation.Get("expiresAt"), f.now()+3_600_000)
	if !f.can(asBob, "iam:identities:read") {
		t.Fatal("the group activation does not grant")
	}
	// Someone outside the group cannot activate the group's binding.
	if _, err := f.deactivate(asBob, jsString(activation.Get("id"))); err != nil {
		t.Fatal(err)
	}
	f.removeMember("responders", bobID)
	f.mustCreate("roleId", "member", "subjectType", "identity", "subjectId", bobID)
	_, err := f.activate(asBob, "bindingId", eligibleID)
	expectError(t, err, "ACCESS_DENIED", "This binding does not apply to you")
	// Deleting the binding removes its activations.
	f.addMember("responders", bobID)
	again := f.mustActivate(asBob, "bindingId", eligibleID)
	expectValue(t, "active", again.Get("active"), true)
	deleted, err := f.iam.API.Bindings.Delete(context.Background(), f.owner, Input[apitypes.BindingsDeleteInput](f.body("bindingId", eligibleID)))
	if err != nil || member(deleted.Value, "deleted") != true {
		t.Fatalf("delete: %v %v", deleted.Value, err)
	}
	remaining, err := f.iam.Store.Find(context.Background(), "bindingActivations", core.NewObject("tenantId", f.tenantID), nil)
	if err != nil || len(remaining) != 0 {
		t.Errorf("activations survived the binding: %v %v", remaining, err)
	}
}

func TestBindingsApprovalGatedActivation(t *testing.T) {
	f := newBindingsFixture(t)
	aliceID, asAlice := f.member("alice@acme.test", "alice")
	bobID, asBob := f.member("bob@acme.test", "bob")
	carolID, asCarol := f.member("carol@acme.test", "carol")
	f.role("auditor", "Auditor", "iam:audit:read")
	f.role("member", "Member", "iam:bindings:activate")
	f.role("approver", "Approver", "iam:bindings:approve")
	f.group("approvers", "Approvers")
	for _, id := range []string{aliceID, bobID, carolID} {
		f.mustCreate("roleId", "member", "subjectType", "identity", "subjectId", id)
	}
	f.mustCreate("roleId", "approver", "subjectType", "group", "subjectId", "approvers")
	f.addMember("approvers", bobID)
	// The approver group must exist and only applies to eligible bindings.
	_, err := f.create(f.owner, "roleId", "auditor", "subjectType", "identity", "subjectId", aliceID, "eligible", true, "approverGroupId", "missing")
	if known := iamError(t, err); known.Code != "NOT_FOUND" {
		t.Errorf("missing approver group: %v", err)
	}
	_, err = f.create(f.owner, "roleId", "auditor", "subjectType", "identity", "subjectId", aliceID, "requireApproval", true)
	expectError(t, err, "INVALID_INPUT", "Activation settings apply to eligible bindings only")
	eligible := f.mustCreate("roleId", "auditor", "subjectType", "identity", "subjectId", aliceID, "eligible", true,
		"requireApproval", true, "approverGroupId", "approvers", "maxActivationMs", 2*3_600_000.0)
	eligibleID := jsString(eligible.Get("id"))
	expectValue(t, "requireApproval", eligible.Get("requireApproval"), true)
	expectValue(t, "approverGroupId", eligible.Get("approverGroupId"), "approvers")
	// The request grants nothing yet, shows as pending, and emails the approver group.
	request, err := f.activate(asAlice, "bindingId", eligibleID, "justification", "INC-7", "durationMs", 30*60_000.0)
	if err != nil {
		t.Fatal(err)
	}
	requestID := jsString(request.Get("id"))
	expectValue(t, "status", request.Get("status"), "pending")
	expectValue(t, "active", request.Get("active"), false)
	expectValue(t, "requestedDurationMs", request.Get("requestedDurationMs"), 30*60_000.0)
	expectValue(t, "request lifetime", request.Get("expiresAt"), f.now()+24*3_600_000)
	if f.can(asAlice, "iam:audit:read") {
		t.Fatal("a pending request grants")
	}
	_, err = f.activate(asAlice, "bindingId", eligibleID)
	expectError(t, err, "CONFLICT", "Your request is still awaiting a decision")
	listed := findByID(f.mine(asAlice), eligibleID)
	expectValue(t, "pendingActivation", member(listed.Get("pendingActivation"), "id"), requestID)
	var notices []auth.DeliveryMessage
	for _, message := range f.dispatch() {
		if message.Template == "activation-request" {
			notices = append(notices, message)
		}
	}
	if len(notices) != 1 || notices[0].To != "bob@acme.test" {
		t.Fatalf("activation-request emails: %+v", notices)
	}
	payload := notices[0].Payload
	if payload["activationId"] != requestID || payload["roleName"] != "Auditor" || payload["requesterName"] != "alice" ||
		payload["justification"] != "INC-7" || payload["requesterEmail"] != "alice@acme.test" || payload["requestedDurationMs"] != "1800000" {
		t.Errorf("activation-request payload: %v", payload)
	}
	requested := f.lastAudit("binding:activation-requested")
	expectValue(t, "requested actor", requested.Get("actorId"), aliceID)
	expectValue(t, "requested metadata", member(requested.Get("metadata"), "activationId"), requestID)
	expectValue(t, "requested duration", member(requested.Get("metadata"), "requestedDurationMs"), 30*60_000.0)
	// Who may decide: not the requester, not a holder outside the approver group, not without the permission.
	_, err = f.approve(asAlice, "activationId", requestID)
	if known := iamError(t, err); known.Code != "ACCESS_DENIED" {
		t.Errorf("requester without the permission: %v", err)
	}
	_, err = f.approve(asCarol, "activationId", requestID)
	if known := iamError(t, err); known.Code != "ACCESS_DENIED" {
		t.Errorf("outsider: %v", err)
	}
	f.addMember("approvers", aliceID)
	_, err = f.approve(asAlice, "activationId", requestID)
	expectError(t, err, "INVALID_INPUT", "You cannot decide on your own request")
	if inbox, err := f.approvals(asAlice); err != nil || len(inbox) != 0 {
		t.Errorf("own requests listed: %v %v", inbox, err)
	}
	inbox, err := f.approvals(asBob)
	if err != nil || len(inbox) != 1 {
		t.Fatalf("approver inbox: %v %v", inbox, err)
	}
	entry := inbox[0].(*core.Object)
	expectValue(t, "inbox id", entry.Get("id"), requestID)
	expectValue(t, "inbox status", entry.Get("status"), "pending")
	expectValue(t, "inbox role", member(entry.Get("role"), "name"), "Auditor")
	expectValue(t, "inbox requester", member(entry.Get("requester"), "email"), "alice@acme.test")
	if got := f.activations("status", "pending"); len(got) != 1 {
		t.Errorf("pending list: %v", got)
	}
	if got := f.activations(); len(got) != 0 {
		t.Errorf("live list: %v", got)
	}
	_, err = f.approve(asBob, "activationId", requestID, "durationMs", 31*60_000.0)
	expectError(t, err, "INVALID_INPUT", "Invalid durationMs")
	// Approval with a shorter duration makes the role live from now.
	approved, err := f.approve(asBob, "activationId", requestID, "durationMs", 10*60_000.0, "note", "ok for the incident")
	if err != nil {
		t.Fatal(err)
	}
	expectValue(t, "approved status", approved.Get("status"), "active")
	expectValue(t, "approved active", approved.Get("active"), true)
	expectValue(t, "decidedBy", approved.Get("decidedBy"), bobID)
	expectValue(t, "note", approved.Get("note"), "ok for the incident")
	expectValue(t, "approved expiry", approved.Get("expiresAt"), f.now()+10*60_000)
	if !f.can(asAlice, "iam:audit:read") {
		t.Fatal("the approved activation does not grant")
	}
	var decided []auth.DeliveryMessage
	for _, message := range f.dispatch() {
		if message.Template == "activation-decided" {
			decided = append(decided, message)
		}
	}
	if len(decided) != 1 || decided[0].To != "alice@acme.test" || decided[0].Payload["decision"] != "approved" ||
		decided[0].Payload["deciderName"] != "bob" || decided[0].Payload["note"] != "ok for the incident" {
		t.Errorf("activation-decided emails: %+v", decided)
	}
	if inbox, _ := f.approvals(asBob); len(inbox) != 0 {
		t.Errorf("decided request still listed: %v", inbox)
	}
	_, err = f.approve(asBob, "activationId", requestID)
	expectError(t, err, "INVALID_TRANSITION", "This request is not awaiting a decision")
	f.advance(10*60_000 + 1)
	if f.can(asAlice, "iam:audit:read") {
		t.Fatal("the approved activation outlived its duration")
	}
	// Denial keeps a record; cancelling one's own request is allowed.
	second := f.mustActivate(asAlice, "bindingId", eligibleID)
	denied, err := f.deny(asBob, "activationId", second.Get("id"), "note", "not now")
	if err != nil {
		t.Fatal(err)
	}
	expectValue(t, "denied status", denied.Get("status"), "denied")
	expectValue(t, "denied active", denied.Get("active"), false)
	expectValue(t, "denied note", denied.Get("note"), "not now")
	if got := ids(f.activations("status", "denied")); len(got) != 1 || got[0] != jsString(second.Get("id")) {
		t.Errorf("denied list: %v", got)
	}
	deniedEvent := f.lastAudit("binding:activation-denied")
	expectValue(t, "denied actor", deniedEvent.Get("actorId"), bobID)
	expectValue(t, "denied metadata note", member(deniedEvent.Get("metadata"), "note"), "not now")
	expectValue(t, "denied metadata identity", member(deniedEvent.Get("metadata"), "identityId"), aliceID)
	if member(deniedEvent.Get("metadata"), "expiresAt") != core.Undefined {
		t.Errorf("a denial records an expiry: %v", deniedEvent.Get("metadata"))
	}
	third := f.mustActivate(asAlice, "bindingId", eligibleID)
	expectValue(t, "third status", third.Get("status"), "pending")
	if result, err := f.deactivate(asAlice, jsString(third.Get("id"))); err != nil || result.Get("deactivated") != true {
		t.Fatalf("cancel: %v %v", result, err)
	}
	expectValue(t, "cancelled", member(f.lastAudit("binding:deactivate").Get("metadata"), "cancelled"), true)
	// Requests lapse after a day.
	fourth := f.mustActivate(asAlice, "bindingId", eligibleID)
	f.advance(24*3_600_000 + 1)
	// Sessions idle for a day have ended: sign everyone in again.
	f.refreshOwner()
	asAlice, asCarol = f.signInAgain(aliceID), f.signInAgain(carolID)
	if got := f.activations("status", "pending"); len(got) != 0 {
		t.Errorf("lapsed request listed: %v", got)
	}
	_, err = f.approve(f.owner, "activationId", fourth.Get("id"))
	expectError(t, err, "INVALID_TRANSITION", "This request is not awaiting a decision")
	// Without an approver group, anyone holding the permission on the role may decide (owner included).
	cleared := f.mustUpdate("bindingId", eligibleID, "approverGroupId", nil)
	if cleared.Has("approverGroupId") {
		t.Errorf("approver group not cleared: %v", cleared)
	}
	fifth := f.mustActivate(asAlice, "bindingId", eligibleID)
	_, err = f.approvals(asCarol)
	if known := iamError(t, err); known.Code != "ACCESS_DENIED" {
		t.Errorf("listApprovals without the permission: %v", err)
	}
	if got, err := f.approvals(f.owner); err != nil || len(got) != 1 || ids(got)[0] != jsString(fifth.Get("id")) {
		t.Errorf("owner inbox: %v %v", got, err)
	}
	granted, err := f.approve(f.owner, "activationId", fifth.Get("id"))
	if err != nil {
		t.Fatal(err)
	}
	// No duration was requested, so the binding's maximum (two hours) applies.
	expectValue(t, "granted expiry", granted.Get("expiresAt"), f.now()+2*3_600_000)
}

func TestBindingsApproversMustBeReachable(t *testing.T) {
	f := newBindingsFixture(t)
	aliceID, asAlice := f.member("alice@acme.test", "alice")
	managerID, asManager := f.member("manager@acme.test", "manager")
	f.role("auditor", "Auditor", "iam:audit:read")
	f.role("member", "Member", "iam:bindings:activate")
	f.role("approver", "Approver", "iam:bindings:approve")
	f.group("approvers", "Approvers")
	f.mustCreate("roleId", "member", "subjectType", "identity", "subjectId", aliceID)
	f.mustCreate("roleId", "approver", "subjectType", "identity", "subjectId", managerID)
	eligible := f.mustCreate("roleId", "auditor", "subjectType", "identity", "subjectId", aliceID, "eligible", true,
		"requireApproval", true, "approverGroupId", "approvers", "managerApproval", true)
	eligibleID := jsString(eligible.Get("id"))
	expectValue(t, "managerApproval", eligible.Get("managerApproval"), true)
	// An empty approver group and no manager: nobody could decide.
	_, err := f.activate(asAlice, "bindingId", eligibleID)
	expectError(t, err, "INVALID_TRANSITION", "Nobody can approve this request: the approver group is empty and you have no active manager")
	alice, err := f.iam.Store.Get(context.Background(), "identities", aliceID)
	if err != nil {
		t.Fatal(err)
	}
	f.seed("identities", alice.Spread(core.NewObject("managerId", managerID)))
	request := f.mustActivate(asAlice, "bindingId", eligibleID)
	var notices []string
	for _, message := range f.dispatch() {
		if message.Template == "activation-request" {
			notices = append(notices, message.To)
		}
	}
	if len(notices) != 1 || notices[0] != "manager@acme.test" {
		t.Errorf("manager not emailed: %v", notices)
	}
	inbox, err := f.approvals(asManager)
	if err != nil || len(inbox) != 1 {
		t.Fatalf("manager inbox: %v %v", inbox, err)
	}
	approved, err := f.approve(asManager, "activationId", request.Get("id"))
	if err != nil {
		t.Fatal(err)
	}
	// The binding's default maximum (one hour) applies.
	expectValue(t, "approved expiry", approved.Get("expiresAt"), f.now()+3_600_000)
	approvedEvent := f.lastAudit("binding:activation-approved")
	expectValue(t, "approved metadata expiry", member(approvedEvent.Get("metadata"), "expiresAt"), approved.Get("expiresAt"))
}

func TestBindingsUpdatePeriodsWindowsAndPackageTakeover(t *testing.T) {
	f := newBindingsFixture(t)
	aliceID := f.mustMember("alice@acme.test", "alice")
	f.role("auditor", "Auditor", "iam:audit:read")
	_, err := f.create(f.owner, "roleId", "auditor", "subjectType", "identity", "subjectId", aliceID, "startsAt", f.now()+7_200_000, "expiresAt", f.now()+3_600_000)
	expectError(t, err, "INVALID_INPUT", "startsAt must be before expiresAt")
	binding := f.mustCreate("roleId", "auditor", "subjectType", "identity", "subjectId", aliceID, "expiresAt", f.now()+3_600_000)
	bindingID := jsString(binding.Get("id"))
	expectValue(t, "expiresAt", binding.Get("expiresAt"), f.now()+3_600_000)
	if got := f.list("expiresBefore", f.now()+3_600_000); len(got) != 1 {
		t.Errorf("expiresBefore: %v", got)
	}
	if got := f.list("expiresBefore", f.now()+3_599_999); len(got) != 0 {
		t.Errorf("expiresBefore excludes later expiries: %v", got)
	}
	// A package's binding taken over by hand loses its package link.
	stored, err := f.iam.Store.Get(context.Background(), "bindings", bindingID)
	if err != nil {
		t.Fatal(err)
	}
	f.seed("bindings", stored.Spread(core.NewObject("packageAssignmentId", "assignment-1")))
	updated := f.mustUpdate("bindingId", bindingID, "expiresAt", nil, "startsAt", f.now()+60_000)
	if updated.Has("expiresAt") || updated.Has("packageAssignmentId") {
		t.Errorf("update kept expiry or package: %v", updated)
	}
	expectValue(t, "startsAt", updated.Get("startsAt"), f.now()+60_000)
	_, err = f.update(f.owner, "bindingId", bindingID, "expiresAt", f.now()+30_000)
	expectError(t, err, "INVALID_INPUT", "startsAt must be before expiresAt")
	window := core.NewObject("from", "09:00", "to", "17:00", "timeZone", "UTC", "days", []any{5.0, 1.0, 1.0, 3.0})
	windowed := f.mustUpdate("bindingId", bindingID, "window", window, "startsAt", nil)
	if windowed.Has("startsAt") {
		t.Errorf("window update: %v", windowed)
	}
	if text, _, _ := core.Stringify(windowed.Get("window")); text != `{"from":"09:00","to":"17:00","timeZone":"UTC","days":[1,3,5]}` {
		t.Errorf("window: %s", text)
	}
	cleared := f.mustUpdate("bindingId", bindingID, "window", nil)
	if cleared.Has("window") {
		t.Errorf("window not cleared: %v", cleared)
	}
	// Expired bindings are listed only on request.
	expiring := f.mustUpdate("bindingId", bindingID, "expiresAt", f.now()+60_000)
	f.advance(60_001)
	if got := f.list(); findByID(got, bindingID) != nil {
		t.Errorf("expired binding listed: %v", expiring)
	}
	if got := f.list("includeExpired", true); findByID(got, bindingID) == nil {
		t.Error("includeExpired misses the expired binding")
	}
	_, err = f.iam.API.Bindings.List(context.Background(), f.owner, Input[apitypes.BindingsListInput](f.body("subjectType", "robot")))
	expectError(t, err, "INVALID_INPUT", "Invalid subject type")
	_, err = f.iam.API.Bindings.ListActivations(context.Background(), f.owner, Input[apitypes.BindingsListActivationsInput](f.body("status", "lapsed")))
	expectError(t, err, "INVALID_INPUT", "status must be pending, active, or denied")
}

func TestBindingsHigherAuthorityAndProtectedRoles(t *testing.T) {
	f := newBindingsFixture(t)
	aliceID, asAlice := f.member("alice@acme.test", "alice")
	bobID := f.mustMember("bob@acme.test", "bob")
	f.role("admin", "Binding admin", "iam:bindings:create", "iam:bindings:delete", "iam:bindings:read")
	f.role("auditor", "Auditor", "iam:audit:read")
	f.mustCreate("roleId", "admin", "subjectType", "identity", "subjectId", aliceID)
	// Alice holds the permission but no grant authority of her own until one is delegated.
	issued := f.mustCreate("roleId", "auditor", "subjectType", "identity", "subjectId", bobID)
	_, err := f.iam.API.Bindings.Delete(context.Background(), asAlice, Input[apitypes.BindingsDeleteInput](f.body("bindingId", issued.Get("id"))))
	expectError(t, err, "ACCESS_DENIED", "Cannot mutate a higher authority binding")
	_, err = f.update(asAlice, "bindingId", issued.Get("id"), "expiresAt", f.now()+3_600_000)
	expectError(t, err, "ACCESS_DENIED", "Cannot mutate a higher authority binding")
	// Protected roles move by owner transfer only.
	f.seed("roles", core.NewObject("id", "owner-role", "tenantId", f.tenantID, "name", "Owner", "policyIds", []any{}, "protected", true, "authorityId", f.authority))
	_, err = f.create(f.owner, "roleId", "owner-role", "subjectType", "identity", "subjectId", bobID)
	expectError(t, err, "PROTECTED_RESOURCE", "Use owner transfer for protected roles")
	f.seed("bindings", core.NewObject("id", "owner-binding", "tenantId", f.tenantID, "uniqueKey", "owner-binding", "subjectType", "identity", "subjectId", bobID, "roleId", "owner-role", "authorityId", f.authority))
	_, err = f.update(f.owner, "bindingId", "owner-binding", "expiresAt", f.now()+3_600_000)
	expectError(t, err, "PROTECTED_RESOURCE", "Use owner transfer")
	_, err = f.iam.API.Bindings.Delete(context.Background(), f.owner, Input[apitypes.BindingsDeleteInput](f.body("bindingId", "owner-binding")))
	expectError(t, err, "PROTECTED_RESOURCE", "Use owner transfer")
}

func TestAuthoritiesCreateAndRevoke(t *testing.T) {
	f := newBindingsFixture(t)
	aliceIdentity := f.createIdentity("alice@acme.test", "alice", "a strong alice password")
	aliceID := jsString(aliceIdentity.Get("id"))
	asAlice := core.CredentialInput{Token: f.signIn(aliceIdentity, true)}
	bobID := f.mustMember("bob@acme.test", "bob")
	f.role("delegator", "Delegator", "iam:authorities:create", "iam:authorities:revoke", "iam:bindings:create", "iam:bindings:delete")
	f.role("auditor", "Auditor", "iam:audit:read")
	f.mustCreate("roleId", "delegator", "subjectType", "identity", "subjectId", aliceID)
	ceiling := document(allowStatement("iam:audit:read", "*"))
	createAuthority := func(credential core.CredentialInput, members ...any) (*core.Object, error) {
		out, err := f.iam.API.Authorities.Create(context.Background(), credential, Input[apitypes.AuthoritiesCreateInput](f.body(members...)))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	revokeAuthority := func(credential core.CredentialInput, id any) (*core.Object, error) {
		out, err := f.iam.API.Authorities.Revoke(context.Background(), credential, Input[apitypes.AuthoritiesRevokeInput](f.body("authorityId", id)))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	_, err := createAuthority(asAlice, "identityId", aliceID, "ceiling", ceiling)
	expectError(t, err, "ACCESS_DENIED", "Cannot issue authority to yourself")
	delegated, err := createAuthority(f.owner, "identityId", aliceID, "ceiling", ceiling)
	if err != nil {
		t.Fatal(err)
	}
	expectValue(t, "parent", delegated.Get("parentAuthorityId"), f.authority)
	expectValue(t, "revoked", delegated.Get("revoked"), false)
	// Alice grants under her delegated authority, then delegates further.
	granted := f.mustCreateAs(asAlice, "roleId", "auditor", "subjectType", "identity", "subjectId", bobID)
	expectValue(t, "authority", granted.Get("authorityId"), delegated.Get("id"))
	nested, err := createAuthority(asAlice, "identityId", bobID, "ceiling", ceiling)
	if err != nil {
		t.Fatal(err)
	}
	expectValue(t, "nested parent", nested.Get("parentAuthorityId"), delegated.Get("id"))
	// Only the superior authority revokes: never the holder, never a peer.
	_, err = revokeAuthority(asAlice, delegated.Get("id"))
	expectError(t, err, "ACCESS_DENIED", "Only superior authority can revoke this grant")
	revokedNested, err := revokeAuthority(asAlice, nested.Get("id"))
	if err != nil {
		t.Fatal(err)
	}
	expectValue(t, "nested revoked", revokedNested.Get("revoked"), true)
	revoked, err := revokeAuthority(f.owner, delegated.Get("id"))
	if err != nil {
		t.Fatal(err)
	}
	expectValue(t, "revoked", revoked.Get("revoked"), true)
	// A stale session (no recent sign-in) cannot change authorities.
	f.advance(24 * 3_600_000)
	_, err = createAuthority(f.owner, "identityId", bobID, "ceiling", ceiling)
	if err == nil {
		t.Error("a stale session created an authority")
	}
}

func (f *bindingsFixture) mustCreateAs(credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	binding, err := f.create(credential, members...)
	if err != nil {
		f.t.Fatalf("create binding: %v", err)
	}
	return binding
}
