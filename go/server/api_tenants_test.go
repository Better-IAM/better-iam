package server

// Ports of the tenant parts of tests/server.test.ts, tests/limits.test.ts, tests/tenant-defaults.test.ts,
// tests/tenant-auth-policy.test.ts and tests/access-policy.test.ts that exercise packages/server/src/api/tenants.ts.
// Organizations are created with `activate: true` (and their owners given a password) where the TypeScript tests
// redeem an owner invitation, so these tests do not depend on flows.ts.

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const tenantsTestPassword = "a strong tenant owner password"

// tenantsFixture is a composed server on an in-memory database with a bootstrapped root, a root session that
// completed MFA, a controllable clock, and an email inbox.
type tenantsFixture struct {
	t          *testing.T
	ctx        context.Context
	iam        *BetterIam
	store      core.IamStore
	rootID     string
	credential core.CredentialInput
	clock      *atomic.Int64
	mu         sync.Mutex
	inbox      []auth.DeliveryMessage
}

// organization is a tenant created by the fixture and its owner's credential.
type organization struct {
	tenant     *core.Object
	id         string
	owner      *core.Object
	credential core.CredentialInput
}

func newTenantsFixture(t *testing.T, mutate func(options *BetterIamOptions)) *tenantsFixture {
	t.Helper()
	f := &tenantsFixture{t: t, ctx: context.Background(), store: newStore(t), clock: &atomic.Int64{}}
	f.clock.Store(1_767_225_600_000)
	now := func() int64 { return f.clock.Load() }
	options := &BetterIamOptions{
		Database: f.store, Secret: "tenants-test-secret-with-at-least-32-characters", BaseURL: "http://localhost:3000",
		WallClock: now,
		Authentication: &auth.Options{Now: now, SendEmail: func(_ context.Context, message auth.DeliveryMessage) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.inbox = append(f.inbox, message)
			return nil
		}},
	}
	if mutate != nil {
		mutate(options)
	}
	iam, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iam.Close)
	f.iam = iam
	if err := iam.Initialize(f.ctx); err != nil {
		t.Fatal(err)
	}
	root := must(iam.Bootstrap(f.ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password")))
	f.rootID = jsString(member(root.Get("tenant"), "id"))
	challenge := must(iam.Auth.SignIn(f.ctx, core.NewObject("tenantId", f.rootID, "email", "root@example.test", "password", "a strong root test password")))
	if challenge.Get("mfaRequired") != true {
		t.Fatalf("root must require MFA: %s", core.MustStringify(challenge))
	}
	credential := auth.MfaCredential{TenantID: f.rootID, Challenge: jsString(challenge.Get("challenge"))}
	enrollment := must(iam.Auth.BeginMfa(f.ctx, credential))
	code := must(auth.GenerateTotp(jsString(enrollment.Get("secret")), f.clock.Load()))
	session := must(iam.Auth.ConfirmMfa(f.ctx, auth.ConfirmMfaInput{Credential: credential, Code: code}))
	f.credential = core.CredentialInput{Token: jsString(session.Get("token"))}
	return f
}

func (f *tenantsFixture) tenants() *TenantsAPI { return f.iam.API.Tenants }

// signIn signs a person in with a password and answers the session credential.
func (f *tenantsFixture) signIn(tenantID, email string) core.CredentialInput {
	f.t.Helper()
	result, err := f.iam.Auth.SignIn(f.ctx, core.NewObject("tenantId", tenantID, "email", email, "password", tenantsTestPassword))
	if err != nil {
		f.t.Fatal(err)
	}
	token, ok := result.Get("token").(string)
	if !ok {
		f.t.Fatalf("sign-in did not answer a session: %s", core.MustStringify(result))
	}
	return core.CredentialInput{Token: token}
}

// createTenant creates an active organization (or another type) under parent with its owner, gives the owner a
// password, and signs them in.
func (f *tenantsFixture) createTenant(name, parent, kind string) organization {
	f.t.Helper()
	if parent == "" {
		parent = f.rootID
	}
	if kind == "" {
		kind = "organization"
	}
	email := name + "@example.test"
	created := f.call(f.tenants().Create(f.ctx, f.credential, Input[apitypes.TenantsCreateInput](core.NewObject(
		"parentId", parent, "name", name, "type", kind, "ownerEmail", email, "activate", true, "ownerName", name+" owner",
	)))).(*core.Object)
	tenant := created.Get("tenant").(*core.Object)
	owner := created.Get("owner").(*core.Object)
	tenantID := jsString(tenant.Get("id"))
	err := f.store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		realm, err := tx.Get(ctx, "tenants", tenantID)
		if err != nil {
			return err
		}
		identity, err := tx.Get(ctx, "identities", jsString(owner.Get("id")))
		if err != nil {
			return err
		}
		if err := f.iam.Auth.SetPassword(ctx, tx, realm, identity, tenantsTestPassword); err != nil {
			return err
		}
		_, err = tx.Put(ctx, "identities", identity)
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return organization{tenant: tenant, id: tenantID, owner: owner, credential: f.signIn(tenantID, email)}
}

// call unwraps an API answer, failing the test on an error.
func (f *tenantsFixture) call(value any, err error) any {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
	field := reflect.ValueOf(value).FieldByName("Value")
	if !field.IsValid() {
		f.t.Fatalf("unexpected answer %T", value)
	}
	return field.Interface()
}

// requirePorted fails the test on an error, or skips the rest of it when the error is another unit's
// NOT_IMPLEMENTED stub (the behavior past that point cannot be checked until that module is ported).
func requirePorted(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if known := iamError(t, err); known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
	t.Fatal(err)
}

// errorCodeOf is the IamError code of err ("" for none).
func errorCodeOf(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	return iamError(t, err).Code
}

func (f *tenantsFixture) record(collection, id string) *core.Object {
	f.t.Helper()
	return must(f.store.Get(f.ctx, collection, id))
}

func (f *tenantsFixture) find(collection string, filter *core.Object) []*core.Object {
	f.t.Helper()
	return must(f.store.Find(f.ctx, collection, filter, nil))
}

// auditTrail is a tenant's audit events of one action in chain order.
func (f *tenantsFixture) auditTrail(tenantID any, action string) []*core.Object {
	f.t.Helper()
	events := f.find("audit", core.NewObject("tenantId", tenantID, "action", action))
	sort.SliceStable(events, func(i, j int) bool { return jsNumber(events[i].Get("sequence")) < jsNumber(events[j].Get("sequence")) })
	return events
}

func (f *tenantsFixture) dispatch() {
	f.t.Helper()
	if _, err := f.iam.Auth.DispatchOutbox(f.ctx, 0); err != nil {
		f.t.Fatal(err)
	}
}

func (f *tenantsFixture) messages(tenantID, template string) []auth.DeliveryMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	var found []auth.DeliveryMessage
	for _, message := range f.inbox {
		if message.TenantID == tenantID && message.Template == template {
			found = append(found, message)
		}
	}
	return found
}

func idsOf(value any) []string {
	var ids []string
	for _, item := range value.([]any) {
		ids = append(ids, jsString(item.(*core.Object).Get("id")))
	}
	return ids
}

func TestTenantsCreateInvitesTheOwnerAndAdministersInvitations(t *testing.T) {
	f := newTenantsFixture(t, nil)
	api := f.tenants()
	created := f.call(api.Create(f.ctx, f.credential, Input[apitypes.TenantsCreateInput](core.NewObject(
		"parentId", f.rootID, "type", "organization", "name", "Pendingco", "ownerEmail", " Pending@Example.test ",
	)))).(*core.Object)
	if keys := strings.Join(created.Keys(), ","); keys != "tenant,invitationId,ownerEmail" {
		t.Fatalf("create answered %s", keys)
	}
	tenant := created.Get("tenant").(*core.Object)
	tenantID := jsString(tenant.Get("id"))
	if tenant.Get("status") != "pending" || tenant.Get("parentId") != f.rootID || tenant.Get("tenantId") != tenantID ||
		created.Get("ownerEmail") != "pending@example.test" {
		t.Fatalf("unexpected tenant %s", core.MustStringify(created))
	}
	// The owner's grant authority waits for the owner, under the creator's.
	authorities := f.find("grantAuthorities", core.NewObject("tenantId", tenantID))
	if len(authorities) != 1 || authorities[0].Get("identityId") != "pending" || !truthy(authorities[0].Get("parentAuthorityId")) {
		t.Fatalf("unexpected authorities %v", authorities)
	}
	f.dispatch()
	invitations := f.messages(tenantID, "owner-invitation")
	if len(invitations) != 1 || invitations[0].To != "pending@example.test" || invitations[0].Payload["token"] == "" ||
		invitations[0].Payload["tenantName"] != "Pendingco" || invitations[0].Payload["tenantId"] != tenantID {
		t.Fatalf("unexpected invitation messages %+v", invitations)
	}
	firstToken := invitations[0].Payload["token"]
	listed := f.call(api.ListInvitations(f.ctx, f.credential, Input[apitypes.TenantsListInvitationsInput](core.NewObject("tenantId", tenantID)))).([]any)
	if len(listed) != 1 {
		t.Fatalf("listed %d invitations", len(listed))
	}
	invitation := listed[0].(*core.Object)
	if invitation.Has("tokenHash") || invitation.Has("uniqueKey") || invitation.Get("email") != "pending@example.test" ||
		typeOf(invitation.Get("createdAt")) != "number" || truthy(invitation.Get("revoked")) {
		t.Fatalf("unexpected invitation %s", core.MustStringify(invitation))
	}
	stored := f.record("ownerInvitations", jsString(invitation.Get("id")))
	if stored.Get("tokenHash") != Hash(firstToken) {
		t.Fatal("the invitation stores the hash of the token it sent")
	}
	// A re-sent invitation has a new token and lifetime; the earlier one stops working.
	f.clock.Add(60_000)
	resent := f.call(api.ResendInvitation(f.ctx, f.credential, Input[apitypes.TenantsResendInvitationInput](core.NewObject(
		"tenantId", tenantID, "invitationId", invitation.Get("id"),
	)))).(*core.Object)
	if strings.Join(resent.Keys(), ",") != "invitationId,email,expiresAt" || resent.Get("email") != "pending@example.test" ||
		jsNumber(resent.Get("expiresAt")) != float64(f.clock.Load())+f.iam.Context.Config.InvitationLifetimeMs {
		t.Fatalf("unexpected resend %s", core.MustStringify(resent))
	}
	f.dispatch()
	again := f.messages(tenantID, "owner-invitation")
	if len(again) != 2 || again[1].Payload["token"] == firstToken {
		t.Fatalf("expected a second invitation with a new token: %+v", again)
	}
	if renewed := f.record("ownerInvitations", jsString(invitation.Get("id"))); renewed.Get("tokenHash") != Hash(again[1].Payload["token"]) {
		t.Fatal("the renewed invitation stores the new token's hash")
	}
	revoked := f.call(api.RevokeInvitation(f.ctx, f.credential, Input[apitypes.TenantsRevokeInvitationInput](core.NewObject(
		"tenantId", tenantID, "invitationId", invitation.Get("id"),
	)))).(*core.Object)
	if revoked.Get("revoked") != true || revoked.Has("tokenHash") || revoked.Has("uniqueKey") {
		t.Fatalf("unexpected revoked invitation %s", core.MustStringify(revoked))
	}
	_, err := api.RevokeInvitation(f.ctx, f.credential, Input[apitypes.TenantsRevokeInvitationInput](core.NewObject(
		"tenantId", tenantID, "invitationId", invitation.Get("id"),
	)))
	expectError(t, err, "CONFLICT", "Invitation is already consumed or revoked")
	_, err = api.ResendInvitation(f.ctx, f.credential, Input[apitypes.TenantsResendInvitationInput](core.NewObject(
		"tenantId", tenantID, "invitationId", invitation.Get("id"),
	)))
	expectError(t, err, "CONFLICT", "Invitation is already consumed or revoked")
	_, err = api.RevokeInvitation(f.ctx, f.credential, Input[apitypes.TenantsRevokeInvitationInput](core.NewObject(
		"tenantId", f.rootID, "invitationId", invitation.Get("id"),
	)))
	expectError(t, err, "NOT_FOUND", "Resource not found")
	// A pending tenant can only be deleted.
	for _, status := range []string{"active", "suspended"} {
		_, err := api.SetStatus(f.ctx, f.credential, Input[apitypes.TenantsSetStatusInput](core.NewObject("tenantId", tenantID, "status", status)))
		expectError(t, err, "INVALID_TRANSITION", "Tenant cannot make this transition")
	}
}

func TestTenantsCreateValidatesItsInput(t *testing.T) {
	f := newTenantsFixture(t, nil)
	api := f.tenants()
	create := func(members ...any) error {
		body := core.NewObject("parentId", f.rootID, "type", "organization", "name", "Acme", "ownerEmail", "owner@acme.test")
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		_, err := api.Create(f.ctx, f.credential, Input[apitypes.TenantsCreateInput](body))
		return err
	}
	expectError(t, create("name", "  "), "INVALID_INPUT", "Invalid name")
	expectError(t, create("ownerEmail", "nobody"), "INVALID_INPUT", "Invalid email")
	expectError(t, create("activate", "yes"), "INVALID_INPUT", "activate must be a boolean")
	expectError(t, create("ownerEmailVerified", 1.0), "INVALID_INPUT", "ownerEmailVerified must be a boolean")
	expectError(t, create("ownerName", "Owner"), "INVALID_INPUT", "ownerName and ownerEmailVerified need activate: true")
	expectError(t, create("type", "project"), "INVALID_HIERARCHY", "Child type is not permitted")
	expectError(t, create("type", "toString"), "INVALID_HIERARCHY", "Child type is not permitted")
	expectError(t, create("boundary", core.NewObject("version", 1.0, "statements", "nope")), "INVALID_POLICY", "Expected policy version 1 and at most 128 statements")
	if len(f.find("tenants", core.NewObject("name", "Acme"))) != 0 {
		t.Fatal("refused creations leave nothing behind")
	}
	// Invitations need a delivery callback; activation does not.
	quiet := newTenantsFixture(t, func(options *BetterIamOptions) { options.Authentication.SendEmail = nil })
	_, err := quiet.tenants().Create(quiet.ctx, quiet.credential, Input[apitypes.TenantsCreateInput](core.NewObject(
		"parentId", quiet.rootID, "type", "organization", "name", "Acme", "ownerEmail", "owner@acme.test",
	)))
	expectError(t, err, "DELIVERY_REQUIRED", "Organization invitations require an email delivery callback")
	activated := quiet.call(quiet.tenants().Create(quiet.ctx, quiet.credential, Input[apitypes.TenantsCreateInput](core.NewObject(
		"parentId", quiet.rootID, "type", "organization", "name", "Acme", "ownerEmail", "owner@acme.test", "activate", true,
	)))).(*core.Object)
	if member(activated.Get("tenant"), "status") != "active" || member(activated.Get("owner"), "name") != "owner@acme.test" {
		t.Fatalf("unexpected activation %s", core.MustStringify(activated))
	}
}

func TestTenantsCreateActivatesForRootOnly(t *testing.T) {
	f := newTenantsFixture(t, nil)
	org := f.createTenant("acme", "", "")
	if org.tenant.Get("status") != "active" || org.owner.Has("passwordHash") || org.owner.Get("owner") != true ||
		org.owner.Get("name") != "acme owner" || org.owner.Get("emailVerified") != false {
		t.Fatalf("unexpected activation %s / %s", core.MustStringify(org.tenant), core.MustStringify(org.owner))
	}
	if len(f.find("ownerInvitations", core.NewObject("tenantId", org.id))) != 0 {
		t.Fatal("an activated tenant has no owner invitation")
	}
	// The owner holds the protected Owner role under the tenant's authority.
	authority := f.find("grantAuthorities", core.NewObject("tenantId", org.id))[0]
	if authority.Get("identityId") != org.owner.Get("id") {
		t.Fatal("the owner holds the tenant's grant authority")
	}
	if len(f.find("bindings", core.NewObject("tenantId", org.id, "subjectId", org.owner.Get("id")))) != 1 {
		t.Fatal("the owner is bound to the Owner role")
	}
	events := f.auditTrail(org.id, "tenant:activate")
	if len(events) != 1 || member(events[0].Get("metadata"), "invitation") != false ||
		member(events[0].Get("metadata"), "ownerId") != org.owner.Get("id") {
		t.Fatalf("unexpected activation audit %v", events)
	}
	// Owners create projects by invitation, never active ones.
	_, err := f.tenants().Create(f.ctx, org.credential, Input[apitypes.TenantsCreateInput](core.NewObject(
		"parentId", org.id, "type", "project", "name", "Web", "ownerEmail", "web@acme.test", "activate", true,
	)))
	expectError(t, err, "ACCESS_DENIED", "Only a root principal can create an active tenant without an owner invitation")
	project := f.call(f.tenants().Create(f.ctx, org.credential, Input[apitypes.TenantsCreateInput](core.NewObject(
		"parentId", org.id, "type", "project", "name", "Web", "ownerEmail", "web@acme.test",
	)))).(*core.Object)
	if member(project.Get("tenant"), "status") != "pending" {
		t.Fatal("an owner's project waits for its owner")
	}
}

func TestTenantsRenameAndReparentEnforcingHierarchyRules(t *testing.T) {
	f := newTenantsFixture(t, nil)
	api := f.tenants()
	a, b := f.createTenant("move-a", "", ""), f.createTenant("move-b", "", "")
	p := f.createTenant("p", a.id, "project")
	renamed := f.call(api.Update(f.ctx, f.credential, Input[apitypes.TenantsUpdateInput](core.NewObject("tenantId", a.id, "name", "Moved A")))).(*core.Object)
	if renamed.Get("name") != "Moved A" {
		t.Fatal("update renames the tenant")
	}
	if got := f.call(api.Get(f.ctx, f.credential, Input[apitypes.TenantsGetInput](core.NewObject("tenantId", a.id)))).(*core.Object); got.Get("name") != "Moved A" {
		t.Fatal("get reads the renamed tenant")
	}
	_, err := api.Update(f.ctx, f.credential, Input[apitypes.TenantsUpdateInput](core.NewObject("tenantId", a.id, "name", "  ")))
	expectError(t, err, "INVALID_INPUT", "Invalid name")
	_, err = api.Reparent(f.ctx, f.credential, Input[apitypes.TenantsReparentInput](core.NewObject("tenantId", p.id, "parentId", f.rootID)))
	expectError(t, err, "INVALID_HIERARCHY", "Child type is not permitted under the new parent")
	_, err = api.Reparent(f.ctx, f.credential, Input[apitypes.TenantsReparentInput](core.NewObject("tenantId", f.rootID, "parentId", b.id)))
	expectError(t, err, "INVALID_TRANSITION", "Tenant cannot be moved")
	_, err = api.Reparent(f.ctx, f.credential, Input[apitypes.TenantsReparentInput](core.NewObject("tenantId", p.id, "parentId", 7.0)))
	expectError(t, err, "INVALID_INPUT", "Invalid parentId")
	out, err := api.Reparent(f.ctx, f.credential, Input[apitypes.TenantsReparentInput](core.NewObject("tenantId", p.id, "parentId", b.id)))
	requirePorted(t, err)
	if out.Value.(*core.Object).Get("parentId") != b.id {
		t.Fatal("reparent moves the tenant")
	}
	underB := idsOf(f.call(api.ListChildren(f.ctx, f.credential, Input[apitypes.TenantsListChildrenInput](core.NewObject("tenantId", b.id)))))
	underA := idsOf(f.call(api.ListChildren(f.ctx, f.credential, Input[apitypes.TenantsListChildrenInput](core.NewObject("tenantId", a.id)))))
	if !containsString(underB, p.id) || containsString(underA, p.id) {
		t.Fatalf("children: under b %v, under a %v", underB, underA)
	}
	_, err = api.Reparent(f.ctx, f.credential, Input[apitypes.TenantsReparentInput](core.NewObject("tenantId", p.id, "parentId", b.id)))
	expectError(t, err, "INVALID_INPUT", "Tenant is already under this parent")
	found := false
	for _, event := range f.auditTrail(p.id, "tenant:reparent") {
		metadata := event.Get("metadata")
		if member(metadata, "from") == a.id && member(metadata, "to") == b.id {
			found = true
		}
	}
	if !found {
		t.Fatal("the move is audited with where it came from and went")
	}
}

func TestTenantsReparentRejectsCyclesAndDepthViolations(t *testing.T) {
	maxDepth := 4
	f := newTenantsFixture(t, func(options *BetterIamOptions) {
		options.Hierarchy = &core.HierarchyConfig{Types: []core.NamedTenantType{
			{Name: "root", Type: core.TenantType{AllowedChildren: []string{"organization"}}},
			{Name: "organization", Type: core.TenantType{AllowedChildren: []string{"folder"}}},
			{Name: "folder", Type: core.TenantType{AllowedChildren: []string{"folder", "project"}}},
			{Name: "project", Type: core.TenantType{AllowedChildren: []string{}}},
		}, MaxDepth: &maxDepth}
	})
	api := f.tenants()
	a := f.createTenant("deep-a", "", "")
	f1 := f.createTenant("f1", a.id, "folder")
	f2 := f.createTenant("f2", f1.id, "folder")
	g := f.createTenant("g", a.id, "folder")
	reparent := func(tenantID, parentID string) (*core.Object, error) {
		out, err := api.Reparent(f.ctx, f.credential, Input[apitypes.TenantsReparentInput](core.NewObject("tenantId", tenantID, "parentId", parentID)))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	_, err := reparent(f1.id, f2.id)
	expectError(t, err, "INVALID_HIERARCHY", "Cannot move a tenant under its own subtree")
	_, err = reparent(f1.id, g.id)
	expectError(t, err, "MAX_DEPTH", "Maximum tenant depth reached")
	project := f.createTenant("project", g.id, "project")
	_, err = reparent(project.id, a.id)
	expectError(t, err, "INVALID_HIERARCHY", "Child type is not permitted under the new parent")
	// Creating below the depth limit is refused too.
	_, err = api.Create(f.ctx, f.credential, Input[apitypes.TenantsCreateInput](core.NewObject(
		"parentId", f2.id, "type", "folder", "name", "f3", "ownerEmail", "f3@example.test", "activate", true,
	)))
	expectError(t, err, "MAX_DEPTH", "Maximum tenant depth reached")
	moved, err := reparent(f2.id, g.id)
	requirePorted(t, err)
	if moved.Get("parentId") != g.id {
		t.Fatal("f2 moves under g")
	}
	if moved := must(reparent(f1.id, g.id)); moved.Get("parentId") != g.id {
		t.Fatal("f1 moves under g once f2 left it")
	}
	_, err = reparent(f1.id, g.id)
	expectError(t, err, "INVALID_INPUT", "Tenant is already under this parent")
}

func TestTenantsReparentRequiresUpdatePermissionAndAuthorityInTheNewParent(t *testing.T) {
	f := newTenantsFixture(t, nil)
	api := f.tenants()
	a, b := f.createTenant("authz-a", "", ""), f.createTenant("authz-b", "", "")
	p := f.createTenant("proj", a.id, "project")
	attempt := func(credential core.CredentialInput) error {
		_, err := api.Reparent(f.ctx, credential, Input[apitypes.TenantsReparentInput](core.NewObject("tenantId", p.id, "parentId", b.id)))
		return err
	}
	if code := errorCodeOf(t, attempt(p.credential)); code != "GRANT_AUTHORITY_REQUIRED" {
		t.Fatalf("project owner: %s", code)
	}
	if code := errorCodeOf(t, attempt(a.credential)); code != "ACCESS_DENIED" {
		t.Fatalf("old parent owner: %s", code)
	}
	if code := errorCodeOf(t, attempt(b.credential)); code != "ACCESS_DENIED" {
		t.Fatalf("new parent owner: %s", code)
	}
	requirePorted(t, attempt(f.credential))
	if f.record("tenants", p.id).Get("parentId") != b.id {
		t.Fatal("root moved the project")
	}
}

func TestTenantsSlugsResolveForSignIn(t *testing.T) {
	f := newTenantsFixture(t, nil)
	api := f.tenants()
	org := f.createTenant("acme", "", "")
	set := func(slug any) (*core.Object, error) {
		out, err := api.SetSlug(f.ctx, org.credential, Input[apitypes.TenantsSetSlugInput](core.NewObject("tenantId", org.id, "slug", slug)))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	lookup := func(body *core.Object) (*core.Object, error) {
		out, err := api.Lookup(f.ctx, Input[apitypes.TenantsLookupInput](body))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	if updated := must(set("Acme")); updated.Get("slug") != "acme" {
		t.Fatalf("slugs are lowercased: %v", updated.Get("slug"))
	}
	found := must(lookup(core.NewObject("slug", "ACME")))
	if core.MustStringify(found) != `{"tenantId":"`+org.id+`","name":"acme","type":"organization","slug":"acme"}` {
		t.Fatalf("unexpected discovery %s", core.MustStringify(found))
	}
	_, err := lookup(core.NewObject("slug", "nobody"))
	expectError(t, err, "NOT_FOUND", "Organization not found")
	_, err = lookup(core.NewObject("slug", "not a slug"))
	expectError(t, err, "INVALID_INPUT", "Slug must use 1-63 lowercase letters, digits, or hyphens")
	_, err = lookup(core.NewObject("host", "acme.example.test"))
	expectError(t, err, "NOT_FOUND", "Organization not found")
	// Renaming releases the old alias; another tenant cannot take one in use.
	must(set("acme-inc"))
	_, err = lookup(core.NewObject("slug", "acme"))
	expectError(t, err, "NOT_FOUND", "Organization not found")
	other := f.createTenant("other", "", "")
	_, err = api.SetSlug(f.ctx, other.credential, Input[apitypes.TenantsSetSlugInput](core.NewObject("tenantId", other.id, "slug", "acme-inc")))
	expectError(t, err, "SLUG_TAKEN", "This slug is already in use")
	f.call(api.SetSlug(f.ctx, other.credential, Input[apitypes.TenantsSetSlugInput](core.NewObject("tenantId", other.id, "slug", "acme"))))
	// A suspended organization is not found by its alias.
	f.call(api.SetStatus(f.ctx, f.credential, Input[apitypes.TenantsSetStatusInput](core.NewObject("tenantId", org.id, "status", "suspended"))))
	_, err = lookup(core.NewObject("slug", "acme-inc"))
	expectError(t, err, "NOT_FOUND", "Organization not found")
	// null removes the alias.
	cleared := must(api.SetSlug(f.ctx, other.credential, Input[apitypes.TenantsSetSlugInput](core.NewObject("tenantId", other.id, "slug", nil)))).Value.(*core.Object)
	if cleared.Has("slug") || must(f.store.Get(f.ctx, "tenantAliases", "acme")) != nil {
		t.Fatal("a null slug removes the alias")
	}
}

func TestTenantsSuspensionRevokesSessionsAndReactivationNeedsAnActiveParent(t *testing.T) {
	f := newTenantsFixture(t, nil)
	api := f.tenants()
	org := f.createTenant("acme", "", "")
	project := f.createTenant("web", org.id, "project")
	setStatus := func(tenantID, status string) error {
		_, err := api.SetStatus(f.ctx, f.credential, Input[apitypes.TenantsSetStatusInput](core.NewObject("tenantId", tenantID, "status", status)))
		return err
	}
	expectError(t, setStatus(f.rootID, "suspended"), "INVALID_TRANSITION", "Tenant cannot make this transition")
	expectError(t, setStatus(org.id, "archived"), "INVALID_TRANSITION", "Tenant cannot make this transition")
	if err := setStatus(org.id, "suspended"); err != nil {
		t.Fatal(err)
	}
	for _, tenantID := range []string{org.id, project.id} {
		if sessions := f.find("sessions", core.NewObject("tenantId", tenantID)); len(sessions) != 0 {
			t.Fatalf("sessions of %s survive suspension: %d", tenantID, len(sessions))
		}
	}
	if f.record("tenants", project.id).Get("status") != "active" {
		t.Fatal("suspension leaves descendants' own status alone")
	}
	expectError(t, setStatus(project.id, "active"), "TENANT_INACTIVE", "Parent must be active")
	if err := setStatus(org.id, "active"); err != nil {
		t.Fatal(err)
	}
	if f.record("tenants", org.id).Get("status") != "active" {
		t.Fatal("reactivated")
	}
}

func TestTenantsLimitsAreRootControlledAndTightenDescendants(t *testing.T) {
	f := newTenantsFixture(t, func(options *BetterIamOptions) {
		options.TenantDefaults = &TenantDefaults{Limits: core.NewObject("identities", 50.0, "groups", 10.0)}
	})
	api := f.tenants()
	org := f.createTenant("acme", "", "")
	if core.MustStringify(org.tenant.Get("limits")) != `{"identities":50,"groups":10}` {
		t.Fatalf("new organizations get the default limits: %s", core.MustStringify(org.tenant.Get("limits")))
	}
	project := f.createTenant("web", org.id, "project")
	setLimits := func(credential core.CredentialInput, tenantID string, limits any) (*core.Object, error) {
		out, err := api.SetLimits(f.ctx, credential, Input[apitypes.TenantsSetLimitsInput](core.NewObject("tenantId", tenantID, "limits", limits)))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	_, err := setLimits(org.credential, org.id, core.NewObject("identities", 1000.0))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	updated := must(setLimits(f.credential, org.id, core.NewObject("identities", 5.0, "roles", 3.0)))
	if core.MustStringify(updated.Get("limits")) != `{"identities":5,"roles":3}` {
		t.Fatalf("unexpected limits %s", core.MustStringify(updated.Get("limits")))
	}
	// The project is tightened per key, keeping its own stricter or extra keys.
	if got := core.MustStringify(f.record("tenants", project.id).Get("limits")); got != `{"identities":5,"groups":10,"roles":3}` {
		t.Fatalf("descendant limits %s", got)
	}
	// A project created now starts from the defaults, never looser than its parent.
	later := f.createTenant("api", org.id, "project")
	if got := core.MustStringify(later.tenant.Get("limits")); got != `{"identities":5,"groups":10,"roles":3}` {
		t.Fatalf("new descendant limits %s", got)
	}
	// Loosening or clearing leaves descendants alone.
	cleared := must(setLimits(f.credential, org.id, nil))
	if cleared.Has("limits") {
		t.Fatal("null clears the limits")
	}
	if got := core.MustStringify(f.record("tenants", project.id).Get("limits")); got != `{"identities":5,"groups":10,"roles":3}` {
		t.Fatalf("descendant limits after clearing %s", got)
	}
	_, err = setLimits(f.credential, org.id, core.NewObject("identities", -1.0))
	if code := errorCodeOf(t, err); code != "INVALID_INPUT" {
		t.Fatalf("negative limit: %s", code)
	}
	events := f.auditTrail(org.id, "tenant:limits")
	if len(events) != 2 || member(events[1].Get("metadata"), "limits") != nil {
		t.Fatalf("limits changes are audited: %v", events)
	}
	usage := f.call(api.Usage(f.ctx, org.credential, Input[apitypes.TenantsUsageInput](core.NewObject("tenantId", org.id)))).(*core.Object)
	if strings.Join(usage.Keys(), ",") != "tenantId,identities,mfaEnrolled,serviceAccounts,groups,roles,policies,resources,relationships,webhooks,activeSessions,limits" {
		t.Fatalf("usage members %v", usage.Keys())
	}
	if usage.Get("identities") != 1.0 || usage.Get("mfaEnrolled") != 0.0 || usage.Get("roles") != 1.0 ||
		usage.Get("policies") != 1.0 || usage.Get("activeSessions") != 1.0 || core.MustStringify(usage.Get("limits")) != "{}" {
		t.Fatalf("unexpected usage %s", core.MustStringify(usage))
	}
}

func TestStricterLimitsTakesTheStricterValuePerKey(t *testing.T) {
	if stricterLimits(nil, nil) != nil || stricterLimits(core.NewObject(), core.NewObject()) != nil {
		t.Fatal("no limits on either side is none")
	}
	merged := stricterLimits(core.NewObject("identities", 10.0, "groups", 3.0), core.NewObject("identities", 4.0, "groups", 9.0, "roles", 2.0))
	if core.MustStringify(merged) != `{"identities":4,"groups":3,"roles":2}` {
		t.Fatalf("unexpected merge %s", core.MustStringify(merged))
	}
}

func TestTenantsAuthPolicyGuardsTheCallersOwnAddress(t *testing.T) {
	f := newTenantsFixture(t, nil)
	api := f.tenants()
	org := f.createTenant("acme", "", "")
	set := func(ctx context.Context, credential core.CredentialInput, tenantID string, policy any) (*core.Object, error) {
		out, err := api.SetAuthPolicy(ctx, credential, Input[apitypes.TenantsSetAuthPolicyInput](core.NewObject("tenantId", tenantID, "authPolicy", policy)))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	updated := must(set(f.ctx, org.credential, org.id, core.NewObject("requireMfa", false, "minPasswordLength", 16.0)))
	if core.MustStringify(updated.Get("authPolicy")) != `{"requireMfa":false,"minPasswordLength":16}` {
		t.Fatalf("unexpected policy %s", core.MustStringify(updated.Get("authPolicy")))
	}
	_, err := set(f.ctx, org.credential, org.id, core.NewObject("minPasswordLength", 2.0))
	expectError(t, err, "INVALID_INPUT", "Invalid minPasswordLength")
	// An allowlist that leaves out the address the request comes from would lock the caller out.
	from := f.iam.Auth.WithClient(f.ctx, &core.SessionClientInfo{IP: "203.0.113.7"})
	_, err = set(from, org.credential, org.id, core.NewObject("allowedIpRanges", []any{"10.0.0.0/8"}))
	expectError(t, err, "INVALID_INPUT", "allowedIpRanges must include your own address")
	must(set(from, org.credential, org.id, core.NewObject("allowedIpRanges", []any{"203.0.113.0/24"})))
	// Root judges another organization's allowlist by nobody's address.
	must(set(from, f.credential, org.id, core.NewObject("allowedIpRanges", []any{"10.0.0.0/8"})))
	cleared := must(set(f.ctx, f.credential, org.id, nil))
	if cleared.Has("authPolicy") {
		t.Fatal("null clears the policy")
	}
	events := f.auditTrail(org.id, "tenant:auth-policy")
	if len(events) != 4 || member(events[3].Get("metadata"), "authPolicy") != nil {
		t.Fatalf("policy changes are audited: %d", len(events))
	}
	// The root tenant's policy is root's to set (root may).
	must(set(f.ctx, f.credential, f.rootID, core.NewObject("requireMfa", true)))
}

func TestTenantsAccessPolicySetsActivationFloors(t *testing.T) {
	f := newTenantsFixture(t, nil)
	api := f.tenants()
	org := f.createTenant("acme", "", "")
	set := func(policy any) (*core.Object, error) {
		out, err := api.SetAccessPolicy(f.ctx, org.credential, Input[apitypes.TenantsSetAccessPolicyInput](core.NewObject("tenantId", org.id, "accessPolicy", policy)))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	updated := must(set(core.NewObject("requireJustification", true, "maxActivationMs", 3_600_000.0)))
	if !updated.Has("accessPolicy") || member(updated.Get("accessPolicy"), "requireJustification") != true {
		t.Fatalf("unexpected policy %s", core.MustStringify(updated))
	}
	_, err := set(core.NewObject("unknown", true))
	expectError(t, err, "INVALID_INPUT", "Unknown access policy field unknown")
	if empty := must(set(core.NewObject())); empty.Has("accessPolicy") {
		t.Fatal("an empty policy is no policy")
	}
	must(set(core.NewObject("requireMfa", true)))
	if cleared := must(set(nil)); cleared.Has("accessPolicy") {
		t.Fatal("null clears the policy")
	}
	events := f.auditTrail(org.id, "tenant:access-policy")
	if len(events) != 4 || member(events[1].Get("metadata"), "accessPolicy") != nil {
		t.Fatalf("access policy changes are audited: %d", len(events))
	}
}

func TestTenantsRevokeSessionsSignsEveryoneOut(t *testing.T) {
	f := newTenantsFixture(t, nil)
	api := f.tenants()
	org := f.createTenant("acme", "", "")
	second := f.signIn(org.id, "acme@example.test")
	revoke := func(credential core.CredentialInput, tenantID string, includeSelf any) (*core.Object, error) {
		body := core.NewObject("tenantId", tenantID)
		if !isUndefined(includeSelf) {
			body.Set("includeSelf", includeSelf)
		}
		out, err := api.RevokeSessions(f.ctx, credential, Input[apitypes.TenantsRevokeSessionsInput](body))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	result := must(revoke(org.credential, org.id, core.Undefined))
	if core.MustStringify(result) != `{"revoked":1}` {
		t.Fatalf("unexpected result %s", core.MustStringify(result))
	}
	if _, err := f.iam.Auth.GetSession(f.ctx, second); err == nil {
		t.Fatal("the other session ended")
	}
	if _, err := f.iam.Auth.GetSession(f.ctx, org.credential); err != nil {
		t.Fatal("the caller keeps their own session")
	}
	events := f.auditTrail(org.id, "tenant:revoke-sessions")
	if len(events) != 1 || core.MustStringify(events[0].Get("metadata")) != `{"revoked":1,"includeSelf":false}` {
		t.Fatalf("unexpected audit %v", events)
	}
	if result := must(revoke(org.credential, org.id, true)); result.Get("revoked") != 1.0 {
		t.Fatal("includeSelf ends the caller's session too")
	}
	if _, err := f.iam.Auth.GetSession(f.ctx, org.credential); err == nil {
		t.Fatal("the caller's session ended")
	}
}

func TestTenantsBoundariesAndRegionsArePlatformControlled(t *testing.T) {
	f := newTenantsFixture(t, nil)
	api := f.tenants()
	org := f.createTenant("acme", "", "")
	boundary := core.NewObject("version", 1.0, "statements", []any{core.NewObject("effect", "allow", "actions", []any{"iam:*"}, "resources", []any{"*"})})
	_, err := api.SetBoundary(f.ctx, org.credential, Input[apitypes.TenantsSetBoundaryInput](core.NewObject("tenantId", org.id, "boundary", boundary)))
	expectError(t, err, "ACCESS_DENIED", "Tenant ceilings are platform controlled")
	updated := f.call(api.SetBoundary(f.ctx, f.credential, Input[apitypes.TenantsSetBoundaryInput](core.NewObject("tenantId", org.id, "boundary", boundary)))).(*core.Object)
	if core.MustStringify(updated.Get("boundary")) != core.MustStringify(boundary) {
		t.Fatal("root sets the boundary")
	}
	_, err = api.SetRegion(f.ctx, org.credential, Input[apitypes.TenantsSetRegionInput](core.NewObject("tenantId", org.id, "region", "eu")))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	_, err = api.SetRegion(f.ctx, f.credential, Input[apitypes.TenantsSetRegionInput](core.NewObject("tenantId", org.id, "region", "eu")))
	expectError(t, err, "INVALID_INPUT", "This deployment has no regions configured")
	_, err = api.SetRegion(f.ctx, f.credential, Input[apitypes.TenantsSetRegionInput](core.NewObject("tenantId", f.rootID, "region", nil)))
	expectError(t, err, "INVALID_INPUT", "The root tenant has no parent to inherit a region from")
	inherited := f.call(api.SetRegion(f.ctx, f.credential, Input[apitypes.TenantsSetRegionInput](core.NewObject("tenantId", org.id, "region", nil)))).(*core.Object)
	if inherited.Has("region") {
		t.Fatal("null makes the tenant inherit its region")
	}
	events := f.auditTrail(org.id, "tenant:region")
	if len(events) != 1 || core.MustStringify(events[0].Get("metadata")) != `{"from":null,"to":null}` {
		t.Fatalf("unexpected region audit %v", events)
	}
}
