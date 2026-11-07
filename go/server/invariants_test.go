package server

// Port of tests/invariants.test.ts: access invariants (create, update, run, list, delete), their enforcement around
// access-changing operations, and the scheduled check. The role, group, binding and identity APIs belong to other
// units, so the access changes run through the operation envelope with the same actions and record writes.

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// opsFixture is a composed server with an organization ("Acme", a child of the root tenant), its owner signed in, a
// controllable clock, and helpers that write access records directly.
type opsFixture struct {
	*iamFixture
	ctx          context.Context
	clock        *atomic.Int64
	rootTenantID string
	tenantID     string
	rootID       string
	ownerID      string
	owner        core.CredentialInput
	authorityID  string
}

const opsMemberPassword = "a strong member password"

func newOpsFixture(t *testing.T, mutate func(options *BetterIamOptions)) *opsFixture {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(time.Now().UnixMilli())
	base := newIam(t, "http://localhost:3000", func(options *BetterIamOptions) {
		options.WallClock = func() int64 { return clock.Load() }
		options.Authentication = &auth.Options{Now: func() int64 { return clock.Load() }, SendEmail: func(ctx context.Context, message auth.DeliveryMessage) error { return nil }}
		if mutate != nil {
			mutate(options)
		}
	})
	f := &opsFixture{iamFixture: base, ctx: context.Background(), clock: clock, rootTenantID: base.rootTenantID()}
	f.rootID = jsString(member(base.root.Get("identity"), "id"))
	f.tenantID = "acme-" + ID()
	f.put("tenants", core.NewObject("id", f.tenantID, "tenantId", f.tenantID, "name", "Acme", "type", "organization",
		"parentId", f.rootTenantID, "status", "active", "createdAt", float64(clock.Load())))
	f.authorityID = "authority-" + ID()
	f.put("grantAuthorities", core.NewObject("id", f.authorityID, "tenantId", f.tenantID, "identityId", f.rootID, "ceiling", All(), "revoked", false))
	owner := f.member("owner")
	f.ownerID = jsString(owner.Get("id"))
	f.bind("identity", f.ownerID, jsString(f.role("Administrator", "*").Get("id")))
	f.owner = f.memberCredential("owner")
	return f
}

func (f *opsFixture) now() int64       { return f.clock.Load() }
func (f *opsFixture) advance(ms int64) { f.clock.Add(ms) }

// signInResult signs a person of the organization in (the answer: a session or an MFA challenge).
func (f *opsFixture) signInResult(ctx context.Context, tenantID, email, password string) (*core.Object, error) {
	out, err := f.iam.API.Auth.SignIn(ctx, Input[apitypes.AuthSignInInput](core.NewObject("tenantId", tenantID, "email", email, "password", password)))
	result, _ := out.Value.(*core.Object)
	return result, err
}

func (f *opsFixture) signIn(email, password string) string {
	f.t.Helper()
	result, err := f.signInResult(f.ctx, f.tenantID, email, password)
	if err != nil {
		f.t.Fatalf("signIn %s: %v", email, err)
	}
	token, _ := result.Get("token").(string)
	if token == "" {
		f.t.Fatalf("signIn %s gave no token: %v", email, core.MustStringify(result))
	}
	return token
}

// rootCredential is an MFA session of the root administrator, issued in process.
func (f *opsFixture) rootCredential() core.CredentialInput {
	f.t.Helper()
	issued, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		root, err := tx.Get(ctx, "identities", f.rootID)
		if err != nil {
			return nil, err
		}
		return f.iam.Auth.IssueSession(ctx, tx, root, auth.IssueSessionOptions{Mfa: true})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return core.CredentialInput{Token: jsString(issued.Get("token"))}
}

// from runs fn with the client address ip (auth.withClient).
func (f *opsFixture) from(ip string) context.Context {
	return f.iam.Auth.WithClient(f.ctx, &core.SessionClientInfo{IP: ip, UserAgent: "test"})
}

// put writes a record (insert or replace) in its own transaction.
func (f *opsFixture) put(collection string, record *core.Object) *core.Object {
	f.t.Helper()
	stored, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		existing, err := tx.Get(ctx, collection, jsString(record.Get("id")))
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return tx.Put(ctx, collection, record)
		}
		return tx.Insert(ctx, collection, record)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return stored
}

func (f *opsFixture) get(collection, id string) *core.Object {
	f.t.Helper()
	record, err := f.iam.Store.Get(f.ctx, collection, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return record
}

func (f *opsFixture) find(collection string, filter *core.Object) []*core.Object {
	f.t.Helper()
	records, err := f.iam.Store.Find(f.ctx, collection, filter, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return records
}

// member creates a person `{name}@acme.test` with a password.
func (f *opsFixture) member(name string) *core.Object {
	f.t.Helper()
	identity, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: f.tenantID, Email: name + "@acme.test", Name: name, Password: opsMemberPassword, HasPassword: true, EmailVerified: true,
		})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return identity
}

func (f *opsFixture) memberCredential(name string) core.CredentialInput {
	return core.CredentialInput{Token: f.signIn(name+"@acme.test", opsMemberPassword)}
}

func allowDocument(actions ...string) *core.Object {
	return core.NewObject("version", 1.0, "statements", []any{core.NewObject("effect", "allow", "actions", stringsOf(actions), "resources", []any{"*"})})
}

func (f *opsFixture) role(name string, actions ...string) *core.Object {
	return f.put("roles", core.NewObject("id", "role-"+ID(), "tenantId", f.tenantID, "name", name, "uniqueKey", "name:"+strings.ToLower(name),
		"document", allowDocument(actions...), "authorityId", f.authorityID))
}

func (f *opsFixture) bindingRecord(subjectType, subjectID, roleID string) *core.Object {
	return core.NewObject("id", "binding-"+ID(), "tenantId", f.tenantID, "uniqueKey", subjectType+":"+subjectID+":"+roleID+":"+f.authorityID,
		"subjectType", subjectType, "subjectId", subjectID, "roleId", roleID, "authorityId", f.authorityID)
}

func (f *opsFixture) bind(subjectType, subjectID, roleID string) *core.Object {
	return f.put("bindings", f.bindingRecord(subjectType, subjectID, roleID))
}

func (f *opsFixture) group(name string) *core.Object {
	return f.put("groups", core.NewObject("id", "group-"+ID(), "tenantId", f.tenantID, "name", name, "uniqueKey", "name:"+strings.ToLower(name)))
}

func groupMemberRecord(tenantID, groupID, identityID string) *core.Object {
	return core.NewObject("id", "member-"+ID(), "tenantId", tenantID, "uniqueKey", groupID+":"+identityID, "groupId", groupID, "identityId", identityID)
}

// change runs fn as the operation `action` of the owner (the envelope runs the invariant checks around it).
func (f *opsFixture) change(action string, fn func(ctx context.Context, tx core.IamStore) error) error {
	_, err := f.iam.Context.Operations.Operation(f.ctx, f.owner, f.tenantID, action, f.tenantID, func(ctx context.Context, call MutationContext) (any, error) {
		return nil, fn(ctx, call.Tx)
	}, false)
	return err
}

func (f *opsFixture) insertIn(collection string, record *core.Object) func(ctx context.Context, tx core.IamStore) error {
	return func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, collection, record)
		return err
	}
}

func (f *opsFixture) deleteIn(collection, id string) func(ctx context.Context, tx core.IamStore) error {
	return func(ctx context.Context, tx core.IamStore) error { return tx.Delete(ctx, collection, id) }
}

func (f *opsFixture) setAttributes(identityID string, attributes *core.Object) func(ctx context.Context, tx core.IamStore) error {
	return func(ctx context.Context, tx core.IamStore) error {
		identity, err := tx.Get(ctx, "identities", identityID)
		if err != nil {
			return err
		}
		_, err = tx.Put(ctx, "identities", identity.Spread(core.NewObject("attributes", attributes)))
		return err
	}
}

func expectCode(t *testing.T, err error, code string) *core.IamError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got no error", code)
	}
	known := iamError(t, err)
	if known.Code != code {
		t.Fatalf("expected %s, got %s %q", code, known.Code, known.Message)
	}
	return known
}

func expectJSON(t *testing.T, value any, want string) {
	t.Helper()
	got := core.MustStringify(value)
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

type invariantScenario struct {
	*opsFixture
	alice, bob, carol            *core.Object
	reader, writer, oncall       *core.Object
	oncallWriter                 *core.Object
	aliceID, bobID, carolID, d1  string
	readerID, writerID, oncallID string
}

func newInvariantScenario(t *testing.T) *invariantScenario {
	t.Helper()
	f := newOpsFixture(t, func(options *BetterIamOptions) {
		options.ResolveResource = func(ctx context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			return &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID}, nil
		}
		options.Permissions = &core.PermissionsConfig{
			Actions:            []string{"documents:read", "documents:write"},
			IdentityAttributes: []core.NamedAttribute{{Name: "contractor", Type: "boolean"}},
		}
	})
	s := &invariantScenario{opsFixture: f, alice: f.member("alice"), bob: f.member("bob"), carol: f.member("carol")}
	s.aliceID, s.bobID, s.carolID = jsString(s.alice.Get("id")), jsString(s.bob.Get("id")), jsString(s.carol.Get("id"))
	f.put("identities", f.get("identities", s.aliceID).Spread(core.NewObject("attributes", core.NewObject("contractor", true))))
	s.reader = f.role("Reader", "documents:read")
	s.writer = f.role("Writer", "documents:write")
	s.oncall = f.group("On-call")
	s.readerID, s.writerID, s.oncallID = jsString(s.reader.Get("id")), jsString(s.writer.Get("id")), jsString(s.oncall.Get("id"))
	f.put("groupMembers", groupMemberRecord(f.tenantID, s.oncallID, s.bobID))
	s.oncallWriter = f.bind("group", s.oncallID, s.writerID)
	return s
}

func (s *invariantScenario) create(credential core.CredentialInput, body *core.Object) (*core.Object, error) {
	body = core.NewObject("tenantId", s.tenantID).Assign(body)
	out, err := s.iam.API.Invariants.Create(s.ctx, credential, Input[apitypes.InvariantsCreateInput](body))
	result, _ := out.Value.(*core.Object)
	return result, err
}

func d1Resource() *core.Object { return core.NewObject("type", "document", "id", "d1") }

func TestInvariantsRefuseChangesThatNewlyBreakAnEnforcedInvariant(t *testing.T) {
	s := newInvariantScenario(t)
	created := must(s.create(s.owner, core.NewObject(
		"name", "Contractors never write d1", "subject", core.NewObject("attribute", core.NewObject("name", "contractor", "value", true)),
		"action", "documents:write", "resource", d1Resource(), "expect", "deny", "mode", "enforce",
	)))
	invariant := created.Get("invariant").(*core.Object)
	if invariant.Get("assumeMfa") != true {
		t.Fatalf("assumeMfa: %v", invariant.Get("assumeMfa"))
	}
	result := created.Get("result").(*core.Object)
	if result.Get("passed") != true || result.Get("evaluated") != 1.0 || len(result.Get("violations").([]any)) != 0 {
		t.Fatalf("result: %s", core.MustStringify(result))
	}
	// A direct binding, a group membership, and a role edit would each let Alice write.
	expectCode(t, s.change("iam:bindings:create", s.insertIn("bindings", s.bindingRecord("identity", s.aliceID, s.writerID))), "INVARIANT_VIOLATION")
	expectCode(t, s.change("iam:groups:update", s.insertIn("groupMembers", groupMemberRecord(s.tenantID, s.oncallID, s.aliceID))), "INVARIANT_VIOLATION")
	if err := s.change("iam:bindings:create", s.insertIn("bindings", s.bindingRecord("identity", s.aliceID, s.readerID))); err != nil {
		t.Fatal(err)
	}
	err := s.change("iam:roles:update", func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Put(ctx, "roles", s.reader.Spread(core.NewObject("document", allowDocument("documents:read", "documents:write"))))
		return err
	})
	known := expectCode(t, err, "INVARIANT_VIOLATION")
	if !strings.Contains(known.Message, "Contractors never write d1") {
		t.Fatalf("message: %s", known.Message)
	}
	if want := `Access invariant "Contractors never write d1": alice@acme.test would be allowed documents:write on document/d1`; known.Message != want {
		t.Fatalf("message: %s", known.Message)
	}
	// Nothing was written: the transaction rolled back.
	if bindings := s.find("bindings", core.NewObject("subjectId", s.aliceID)); len(bindings) != 1 {
		t.Fatalf("alice bindings: %d", len(bindings))
	}
	if members := s.find("groupMembers", core.NewObject("groupId", s.oncallID, "identityId", s.aliceID)); len(members) != 0 {
		t.Fatal("alice joined on-call")
	}
	// Unrelated changes still go through, and the same change is fine for a non-contractor.
	if err := s.change("iam:bindings:create", s.insertIn("bindings", s.bindingRecord("identity", s.carolID, s.writerID))); err != nil {
		t.Fatal(err)
	}
	// Changing Alice's attribute so she is no longer a contractor lifts the guard for her.
	if err := s.change("iam:identities:update", s.setAttributes(s.aliceID, core.NewObject("contractor", false))); err != nil {
		t.Fatal(err)
	}
	if err := s.change("iam:groups:update", s.insertIn("groupMembers", groupMemberRecord(s.tenantID, s.oncallID, s.aliceID))); err != nil {
		t.Fatal(err)
	}
	// ...but making her a contractor again now breaks the invariant, so that update is refused.
	expectCode(t, s.change("iam:identities:update", s.setAttributes(s.aliceID, core.NewObject("contractor", true))), "INVARIANT_VIOLATION")
	// Operations outside the access-changing actions are not checked at all.
	if err := s.change("iam:audit:read", s.setAttributes(s.aliceID, core.NewObject("contractor", true))); err != nil {
		t.Fatal(err)
	}
}

func TestInvariantsProtectMustAllowInvariantsAndTolerateEarlierViolations(t *testing.T) {
	s := newInvariantScenario(t)
	must(s.create(s.owner, core.NewObject(
		"name", "On-call can always write d1", "subject", core.NewObject("groupId", s.oncallID),
		"action", "documents:write", "resource", d1Resource(), "expect", "allow", "mode", "enforce",
	)))
	oncallWriterID := jsString(s.oncallWriter.Get("id"))
	expectCode(t, s.change("iam:bindings:delete", s.deleteIn("bindings", oncallWriterID)), "INVARIANT_VIOLATION")
	// Taking access away for cause (narrowsAccessOnly) is never blocked by an invariant that expects it to remain.
	_, err := s.iam.Context.Operations.Operation(s.ctx, s.owner, s.tenantID, "iam:clearances:adjudicate", s.tenantID, func(ctx context.Context, call MutationContext) (any, error) {
		NarrowsAccessOnly(call.Tx)
		return nil, call.Tx.Delete(ctx, "bindings", oncallWriterID)
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	// The mark lives for one operation: the next one is checked again.
	s.put("bindings", s.oncallWriter)
	expectCode(t, s.change("iam:bindings:delete", s.deleteIn("bindings", oncallWriterID)), "INVARIANT_VIOLATION")

	// Carol is not allowed to read yet; an enforced must-allow invariant about her starts out broken.
	broken := must(s.create(s.owner, core.NewObject(
		"name", "Carol reads d1", "subject", core.NewObject("identityId", s.carolID),
		"action", "documents:read", "resource", d1Resource(), "expect", "allow",
	)))
	brokenResult := broken.Get("result").(*core.Object)
	if brokenResult.Get("passed") != false || jsString(member(member(brokenResult.Get("violations").([]any)[0], "identity"), "id")) != s.carolID {
		t.Fatalf("broken: %s", core.MustStringify(brokenResult))
	}
	brokenID := jsString(member(broken.Get("invariant"), "id"))
	enforced, err := s.iam.API.Invariants.Update(s.ctx, s.owner, Input[apitypes.InvariantsUpdateInput](core.NewObject("tenantId", s.tenantID, "invariantId", brokenID, "mode", "enforce")))
	if err != nil {
		t.Fatal(err)
	}
	if mode := member(member(enforced.Value, "invariant"), "mode"); mode != "enforce" {
		t.Fatalf("mode %v", mode)
	}
	// The pre-existing violation does not block unrelated work.
	if err := s.change("iam:bindings:create", s.insertIn("bindings", s.bindingRecord("identity", s.bobID, s.readerID))); err != nil {
		t.Fatal(err)
	}
	run, err := s.iam.API.Invariants.Run(s.ctx, s.owner, Input[apitypes.InvariantsRunInput](core.NewObject("tenantId", s.tenantID)))
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, member(run.Value, "summary"), `{"passed":1,"failed":1,"errors":0}`)
	var names []string
	for _, result := range member(run.Value, "results").([]any) {
		names = append(names, jsString(member(member(result, "invariant"), "name"))+"="+jsString(member(result, "passed")))
	}
	if strings.Join(names, ",") != "Carol reads d1=false,On-call can always write d1=true" {
		t.Fatalf("results: %v", names)
	}
	// Granting Carol read fixes it.
	if err := s.change("iam:bindings:create", s.insertIn("bindings", s.bindingRecord("identity", s.carolID, s.readerID))); err != nil {
		t.Fatal(err)
	}
	single, err := s.iam.API.Invariants.Run(s.ctx, s.owner, Input[apitypes.InvariantsRunInput](core.NewObject("tenantId", s.tenantID, "invariantId", brokenID)))
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, member(single.Value, "summary"), `{"passed":1,"failed":0,"errors":0}`)

	// Deleting the group an enforced invariant is about would switch it off silently, so it is refused.
	err = s.change("iam:groups:delete", s.deleteIn("groups", s.oncallID))
	known := expectCode(t, err, "INVARIANT_VIOLATION")
	if !strings.Contains(known.Message, "could no longer be evaluated") {
		t.Fatalf("message: %s", known.Message)
	}
	// Deleting the invariant lifts enforcement.
	list, err := s.iam.API.Invariants.List(s.ctx, s.owner, Input[apitypes.InvariantsListInput](core.NewObject("tenantId", s.tenantID)))
	if err != nil {
		t.Fatal(err)
	}
	var guardID string
	for _, item := range list.Value.([]any) {
		if member(item, "name") == "On-call can always write d1" {
			guardID = jsString(member(item, "id"))
		}
	}
	deleted, err := s.iam.API.Invariants.Delete(s.ctx, s.owner, Input[apitypes.InvariantsDeleteInput](core.NewObject("tenantId", s.tenantID, "invariantId", guardID)))
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, deleted.Value, `{"deleted":true}`)
	if err := s.change("iam:bindings:delete", s.deleteIn("bindings", oncallWriterID)); err != nil {
		t.Fatal(err)
	}
}

func TestInvariantsMonitorOnAScheduleAndAuditBreaksAndRestorationsOnce(t *testing.T) {
	s := newInvariantScenario(t)
	created := must(s.create(s.owner, core.NewObject(
		"name", "Carol never writes", "subject", core.NewObject("identityId", s.carolID),
		"action", "documents:write", "resource", d1Resource(), "expect", "deny",
	)))
	invariantID := jsString(member(created.Get("invariant"), "id"))
	check := func(input *core.Object) *core.Object {
		t.Helper()
		return must(s.iam.CheckInvariants(s.ctx, input))
	}
	expectJSON(t, check(nil), `{"checked":1,"broken":[],"restored":[]}`)
	// Monitor mode lets the change through; the next check reports it once.
	binding := s.bindingRecord("identity", s.carolID, s.writerID)
	if err := s.change("iam:bindings:create", s.insertIn("bindings", binding)); err != nil {
		t.Fatal(err)
	}
	expectJSON(t, check(core.NewObject("tenantId", s.tenantID)),
		`{"checked":1,"broken":[{"tenantId":"`+s.tenantID+`","invariantId":"`+invariantID+`","name":"Carol never writes","violations":["`+s.carolID+`"]}],"restored":[]}`)
	expectJSON(t, check(nil).Get("broken"), `[]`)
	stored := s.get("accessInvariants", invariantID)
	lastCheck := stored.Get("lastCheck").(*core.Object)
	if lastCheck.Get("passed") != false || core.MustStringify(lastCheck.Get("violations")) != `["`+s.carolID+`"]` {
		t.Fatalf("lastCheck: %s", core.MustStringify(lastCheck))
	}
	if err := s.change("iam:bindings:delete", s.deleteIn("bindings", jsString(binding.Get("id")))); err != nil {
		t.Fatal(err)
	}
	expectJSON(t, check(nil).Get("restored"), `[{"tenantId":"`+s.tenantID+`","invariantId":"`+invariantID+`","name":"Carol never writes"}]`)
	events := core.MustStringify(stringsFromRecords(s.find("audit", core.NewObject("tenantId", s.tenantID))))
	if !strings.Contains(events, "invariant:broken") || !strings.Contains(events, "invariant:restored") {
		t.Fatalf("audit lacks invariant events: %s", events)
	}
}

func stringsFromRecords(records []*core.Object) []any {
	out := make([]any, len(records))
	for index, record := range records {
		out[index] = record
	}
	return out
}

func TestInvariantsValidateInputAndRequirePermissions(t *testing.T) {
	s := newInvariantScenario(t)
	base := func(members ...any) *core.Object {
		body := core.NewObject("name", "x", "subject", core.NewObject("everyone", true), "action", "documents:read", "resource", d1Resource(), "expect", "deny")
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		return body
	}
	must(s.create(s.owner, base()))
	_, err := s.create(s.owner, base("name", "X"))
	expectError(t, err, "CONFLICT", "An invariant with this name exists")
	_, err = s.create(s.owner, base("name", "y", "action", "documents:fly"))
	expectError(t, err, "INVALID_ACTION", "Unknown action documents:fly")
	_, err = s.create(s.owner, base("name", "z", "subject", core.NewObject("everyone", true, "identityId", s.aliceID)))
	expectError(t, err, "INVALID_INPUT", invariantSubjectShape)
	_, err = s.create(s.owner, base("name", "w", "subject", core.NewObject("attribute", core.NewObject("name", "contractor", "value", "yes"))))
	expectError(t, err, "INVALID_INPUT", "subject.attribute.value must be a boolean")
	_, err = s.create(s.owner, base("name", "v", "subject", core.NewObject("attribute", core.NewObject("name", "team", "value", "a"))))
	expectError(t, err, "INVALID_INPUT", "Unknown identity attribute team")
	_, err = s.create(s.owner, base("name", "u", "subject", core.NewObject("everyone", false)))
	expectError(t, err, "INVALID_INPUT", "subject.everyone must be true")
	_, err = s.create(s.owner, base("name", "t", "expect", "maybe"))
	expectError(t, err, "INVALID_INPUT", "expect must be allow or deny")
	_, err = s.create(s.owner, base("name", "s", "mode", "loud"))
	expectError(t, err, "INVALID_INPUT", "mode must be enforce or monitor")
	_, err = s.create(s.owner, base("name", "r", "assumeMfa", "yes"))
	expectError(t, err, "INVALID_INPUT", "assumeMfa must be a boolean")
	_, err = s.create(s.owner, base("name", "  "))
	expectError(t, err, "INVALID_INPUT", "Invalid name")
	_, err = s.create(s.owner, base("name", "q", "subject", core.NewObject("identityId", "nobody")))
	expectError(t, err, "NOT_FOUND", "Resource not found")
	// Descriptions are trimmed away when emptied.
	described := must(s.create(s.owner, base("name", "p", "description", "kept")))
	describedID := jsString(member(described.Get("invariant"), "id"))
	cleared, err := s.iam.API.Invariants.Update(s.ctx, s.owner, Input[apitypes.InvariantsUpdateInput](core.NewObject("tenantId", s.tenantID, "invariantId", describedID, "description", "")))
	if err != nil {
		t.Fatal(err)
	}
	if invariant := member(cleared.Value, "invariant").(*core.Object); invariant.Has("description") || invariant.Get("createdBy") != s.ownerID {
		t.Fatalf("cleared: %s", core.MustStringify(invariant))
	}
	alice := s.memberCredential("alice")
	_, err = s.iam.API.Invariants.List(s.ctx, alice, Input[apitypes.InvariantsListInput](core.NewObject("tenantId", s.tenantID)))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = s.create(alice, base("name", "mine"))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = s.iam.API.Invariants.Delete(s.ctx, s.owner, Input[apitypes.InvariantsDeleteInput](core.NewObject("tenantId", s.tenantID)))
	expectError(t, err, "INVALID_INPUT", "Invalid invariantId")
}

func TestInvariantsEvaluateReportsUnevaluableInvariants(t *testing.T) {
	s := newInvariantScenario(t)
	created := must(s.create(s.owner, core.NewObject(
		"name", "Bob never reads", "subject", core.NewObject("identityId", s.bobID),
		"action", "documents:read", "resource", d1Resource(), "expect", "deny",
	)))
	if err := s.iam.Store.Transaction(s.ctx, func(ctx context.Context, tx core.IamStore) error { return tx.Delete(ctx, "identities", s.bobID) }); err != nil {
		t.Fatal(err)
	}
	run, err := s.iam.API.Invariants.Run(s.ctx, s.owner, Input[apitypes.InvariantsRunInput](core.NewObject("tenantId", s.tenantID, "invariantId", member(created.Get("invariant"), "id"))))
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, member(run.Value, "summary"), `{"passed":0,"failed":0,"errors":1}`)
	result := member(run.Value, "results").([]any)[0]
	expectJSON(t, member(result, "error"), `{"code":"NOT_FOUND","message":"The invariant names an identity that no longer exists"}`)
}
