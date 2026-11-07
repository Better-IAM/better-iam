package server

// Ports of the tests of packages/server/src/api/roles.ts: tests/role-inheritance.test.ts, the role parts of
// tests/server.test.ts, and the `roles.revokeSessions` validation and permission tests of
// tests/revoke-older-sessions.test.ts. Organizations are created with `activate: true` (see api_tenants_test.go)
// instead of redeeming an owner invitation. Steps that reach another unit's NOT_IMPLEMENTED stub skip the rest of the
// test (requirePorted, expectCodeOrSkip).

import (
	"context"
	"reflect"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const dayMs = 86_400_000.0

// orgFixture is tests/support/organization.ts organizationFixture: a bootstrapped platform with one active
// organization ("Acme") and its signed-in owner, the documents:read/write catalog, a resolver that answers the
// reference as given, and seven-day sessions.
type orgFixture struct {
	*tenantsFixture
	org      organization
	tenantID string
	owner    core.CredentialInput
	ownerID  string
}

func newOrgFixture(t *testing.T, mutate func(options *BetterIamOptions)) *orgFixture {
	t.Helper()
	week := int64(7 * dayMs)
	f := newTenantsFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}}
		options.ResolveResource = func(_ context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			return &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID}, nil
		}
		options.Authentication.SessionLifetimeMs = &week
		options.Authentication.SessionIdleTimeoutMs = &week
		if mutate != nil {
			mutate(options)
		}
	})
	org := f.createTenant("Acme", "", "")
	return &orgFixture{tenantsFixture: f, org: org, tenantID: org.id, owner: org.credential, ownerID: jsString(org.owner.Get("id"))}
}

// ported unwraps an API answer: another unit's NOT_IMPLEMENTED stub skips the rest of the test, any other error
// fails it.
func (f *orgFixture) ported(value any, err error) any {
	f.t.Helper()
	requirePorted(f.t, err)
	field := reflect.ValueOf(value).FieldByName("Value")
	if !field.IsValid() {
		f.t.Fatalf("unexpected answer %T", value)
	}
	return field.Interface()
}

// object is ported for an answer that is one record.
func (f *orgFixture) object(value any, err error) *core.Object {
	f.t.Helper()
	result, ok := f.ported(value, err).(*core.Object)
	if !ok {
		f.t.Fatalf("expected an object answer, got %T", result)
	}
	return result
}

// items is ported for an answer that is a list.
func (f *orgFixture) items(value any, err error) []*core.Object {
	f.t.Helper()
	answer := f.ported(value, err)
	list, ok := answer.([]any)
	if !ok {
		f.t.Fatalf("expected a list answer, got %T", answer)
	}
	result := make([]*core.Object, len(list))
	for index, item := range list {
		result[index] = item.(*core.Object)
	}
	return result
}

// member creates a person `{name}@acme.test` with a password, as the owner (organizationFixture member).
func (f *orgFixture) member(name string, extra ...any) *core.Object {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID, "email", name+"@acme.test", "name", name, "password", "a strong "+name+" password")
	input.Assign(core.NewObject(extra...))
	return f.object(f.iam.API.Identities.Create(f.ctx, f.owner, Input[apitypes.IdentitiesCreateInput](input)))
}

// login signs a member in with their password (organizationFixture signIn).
func (f *orgFixture) login(name string) core.CredentialInput {
	f.t.Helper()
	result, err := f.iam.Auth.SignIn(f.ctx, core.NewObject("tenantId", f.tenantID, "email", name+"@acme.test", "password", "a strong "+name+" password"))
	requirePorted(f.t, err)
	token, ok := result.Get("token").(string)
	if !ok {
		f.t.Fatalf("sign-in did not answer a session: %s", core.MustStringify(result))
	}
	return core.CredentialInput{Token: token}
}

// ownerSignIn is a fresh, recently authenticated owner session.
func (f *orgFixture) ownerSignIn() core.CredentialInput {
	f.t.Helper()
	return f.signIn(f.tenantID, "Acme@example.test")
}

// bind binds a role to a subject (bindings.create).
func (f *orgFixture) bind(credential core.CredentialInput, roleID, subjectType, subjectID any, extra ...any) *core.Object {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID, "roleId", roleID, "subjectType", subjectType, "subjectId", subjectID)
	input.Assign(core.NewObject(extra...))
	return f.object(f.iam.API.Bindings.Create(f.ctx, credential, Input[apitypes.BindingsCreateInput](input)))
}

// can is iam.authorize(...).allowed for one action on a resource of the organization.
func (f *orgFixture) can(credential core.CredentialInput, action, resourceType, resourceID string) bool {
	f.t.Helper()
	decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{
		Credential: credential, TenantID: f.tenantID, Action: action, Resource: ResourceTarget{Type: resourceType, ID: resourceID},
	})
	requirePorted(f.t, err)
	return decision.Allowed
}

func (f *orgFixture) createRole(credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID)
	input.Assign(core.NewObject(members...))
	return f.object(f.iam.API.Roles.Create(f.ctx, credential, Input[apitypes.RolesCreateInput](input)))
}

func (f *orgFixture) updateRole(credential core.CredentialInput, members ...any) (*core.Object, error) {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID)
	input.Assign(core.NewObject(members...))
	answer, err := f.iam.API.Roles.Update(f.ctx, credential, Input[apitypes.RolesUpdateInput](input))
	if err != nil {
		return nil, err
	}
	return answer.Value.(*core.Object), nil
}

func (f *orgFixture) listRoles(credential core.CredentialInput) []*core.Object {
	f.t.Helper()
	return f.items(f.iam.API.Roles.List(f.ctx, credential, Input[apitypes.RolesListInput](core.NewObject("tenantId", f.tenantID))))
}

// expectCodeOrSkip expects an IamError with code; another unit's NOT_IMPLEMENTED stub skips the rest of the test.
func expectCodeOrSkip(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", code)
	}
	known := iamError(t, err)
	if known.Code == "NOT_IMPLEMENTED" && code != "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
	if known.Code != code {
		t.Fatalf("expected %s, got %s: %s", code, known.Code, known.Message)
	}
}

func expectStrings(t *testing.T, got any, want ...string) {
	t.Helper()
	list, _ := got.([]any)
	actual := make([]string, len(list))
	for index, item := range list {
		actual[index] = jsString(item)
	}
	if want == nil {
		want = []string{}
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("expected %v, got %v", want, actual)
	}
}

func TestRoleInheritanceIncludesInheritedGrantsValidatesTheHierarchyAndProtectsInheritedRoles(t *testing.T) {
	f := newOrgFixture(t, nil)
	owner := f.owner
	viewer := f.createRole(owner, "name", "Viewer", "permissions", []any{"documents:read"})
	editor := f.createRole(owner, "name", "Editor", "permissions", []any{"documents:write"}, "inherits", []any{viewer.Get("id")})
	expectStrings(t, editor.Get("inherits"), jsString(viewer.Get("id")))
	// Cycles, self-inheritance, protected roles, and unknown roles are refused.
	_, err := f.updateRole(owner, "roleId", viewer.Get("id"), "inherits", []any{editor.Get("id")})
	expectCodeOrSkip(t, err, "INVALID_INPUT")
	_, err = f.updateRole(owner, "roleId", viewer.Get("id"), "inherits", []any{viewer.Get("id")})
	expectCodeOrSkip(t, err, "INVALID_INPUT")
	var ownerRole *core.Object
	for _, role := range f.listRoles(owner) {
		if truthy(role.Get("protected")) {
			ownerRole = role
			break
		}
	}
	if ownerRole == nil {
		t.Fatal("the organization has no protected role")
	}
	_, err = f.updateRole(owner, "roleId", editor.Get("id"), "inherits", []any{ownerRole.Get("id")})
	expectCodeOrSkip(t, err, "PROTECTED_RESOURCE")
	_, err = f.iam.API.Roles.Create(f.ctx, owner, Input[apitypes.RolesCreateInput](core.NewObject(
		"tenantId", f.tenantID, "name", "Broken", "inherits", []any{"missing"})))
	expectCodeOrSkip(t, err, "NOT_FOUND")
	// Editors read through Viewer; viewers cannot write.
	alice := f.member("alice")
	bob := f.member("bob")
	f.bind(owner, editor.Get("id"), "identity", alice.Get("id"))
	f.bind(owner, viewer.Get("id"), "identity", bob.Get("id"))
	asAlice, asBob := f.login("alice"), f.login("bob")
	if !f.can(asAlice, "documents:read", "documents", "a") || !f.can(asAlice, "documents:write", "documents", "a") {
		t.Fatal("an editor reads through the inherited viewer role and writes")
	}
	if !f.can(asBob, "documents:read", "documents", "a") || f.can(asBob, "documents:write", "documents", "a") {
		t.Fatal("a viewer reads and cannot write")
	}
	review := f.object(f.iam.API.Policies.EffectiveActions(f.ctx, owner, Input[apitypes.PoliciesEffectiveActionsInput](core.NewObject(
		"tenantId", f.tenantID, "identityId", alice.Get("id"), "resource", core.NewObject("type", "documents", "id", "a"),
		"actions", []any{"documents:read", "documents:write"}))))
	expectStrings(t, review.Get("allowed"), "documents:read", "documents:write")
	// An inherited role cannot be deleted; clearing the inheritance removes the inherited grant.
	_, err = f.iam.API.Roles.Delete(f.ctx, owner, Input[apitypes.RolesDeleteInput](core.NewObject("tenantId", f.tenantID, "roleId", viewer.Get("id"))))
	expectCodeOrSkip(t, err, "RESOURCE_IN_USE")
	cleared, err := f.updateRole(owner, "roleId", editor.Get("id"), "inherits", []any{})
	requirePorted(t, err)
	if cleared.Has("inherits") {
		t.Fatalf("clearing inheritance removes the member: %s", core.MustStringify(cleared))
	}
	if f.can(asAlice, "documents:read", "documents", "a") {
		t.Fatal("the inherited grant ends with the inheritance")
	}
	f.ported(f.iam.API.Roles.Delete(f.ctx, owner, Input[apitypes.RolesDeleteInput](core.NewObject("tenantId", f.tenantID, "roleId", viewer.Get("id")))))
}

func TestRoleInheritanceIsBoundedByTheInheritingRolesAuthorityCeiling(t *testing.T) {
	f := newOrgFixture(t, nil)
	owner := f.owner
	full := f.createRole(owner, "name", "Full", "permissions", []any{"documents:read", "documents:write"})
	// Bob administers under a ceiling that only allows reads, plus the permissions to create roles and bindings.
	bob := f.member("bob")
	carol := f.member("carol")
	admin := f.createRole(owner, "name", "Delegated admin", "permissions", []any{
		"iam:roles:create", "iam:roles:read", "iam:roles:update", "iam:bindings:create",
	})
	f.bind(owner, admin.Get("id"), "identity", bob.Get("id"))
	f.object(f.iam.API.Authorities.Create(f.ctx, owner, Input[apitypes.AuthoritiesCreateInput](core.NewObject(
		"tenantId", f.tenantID, "identityId", bob.Get("id"),
		"ceiling", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"]}]}`)))))
	asBob := f.login("bob")
	narrow := f.createRole(asBob, "name", "Narrow", "inherits", []any{full.Get("id")})
	f.bind(asBob, narrow.Get("id"), "identity", carol.Get("id"))
	asCarol := f.login("carol")
	if !f.can(asCarol, "documents:read", "documents", "a") {
		t.Fatal("the inherited read is within Bob's ceiling")
	}
	if f.can(asCarol, "documents:write", "documents", "a") {
		t.Fatal("the inherited write is beyond Bob's ceiling")
	}
	// Configuration sync carries inheritance by name, parent and child in one document.
	exported := f.object(f.iam.API.Config.Export(f.ctx, owner, Input[apitypes.ConfigExportInput](core.NewObject("tenantId", f.tenantID))))
	var exportedNarrow any
	for _, role := range arrayItems(exported.Get("roles")) {
		if member(role, "name") == "Narrow" {
			exportedNarrow = role
		}
	}
	if got := core.MustStringify(exportedNarrow); got != `{"name":"Narrow","policies":[],"inherits":["Full"]}` {
		t.Fatalf("exported Narrow role: %s", got)
	}
	// A role created under Bob's authority is not the owner's to edit, even through configuration sync.
	_, err := f.iam.API.Config.Apply(f.ctx, owner, Input[apitypes.ConfigApplyInput](core.NewObject("tenantId", f.tenantID,
		"config", obj(t, `{"version":1,"roles":[{"name":"Narrow","inherits":[]}]}`))))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	applied := f.object(f.iam.API.Config.Apply(f.ctx, owner, Input[apitypes.ConfigApplyInput](core.NewObject("tenantId", f.tenantID,
		"config", obj(t, `{"version":1,"roles":[{"name":"Base","permissions":["documents:read"]},{"name":"Lead","permissions":["documents:write"],"inherits":["Base"]}]}`)))))
	if got := core.MustStringify(applied.Get("summary")); got != `{"create":2,"update":0,"delete":0,"unchanged":0}` {
		t.Fatalf("summary: %s", got)
	}
	byName := map[string]*core.Object{}
	for _, role := range f.listRoles(owner) {
		byName[jsString(role.Get("name"))] = role
	}
	expectStrings(t, byName["Lead"].Get("inherits"), jsString(byName["Base"].Get("id")))
	expectStrings(t, byName["Narrow"].Get("inherits"), jsString(full.Get("id")))
	cleared, err := f.updateRole(asBob, "roleId", narrow.Get("id"), "inherits", []any{})
	requirePorted(t, err)
	if cleared.Has("inherits") {
		t.Fatalf("clearing inheritance removes the member: %s", core.MustStringify(cleared))
	}
	_, err = f.iam.API.Config.Plan(f.ctx, owner, Input[apitypes.ConfigPlanInput](core.NewObject("tenantId", f.tenantID,
		"config", obj(t, `{"version":1,"roles":[{"name":"Loop","inherits":["Loop"]}]}`))))
	expectCodeOrSkip(t, err, "INVALID_INPUT")
}

// arrayItems is a model array's items (none for anything else).
func arrayItems(value any) []any {
	list, _ := value.([]any)
	return list
}

func TestRolesSupportDirectPermissionsInlineDocumentsDescriptionsAndBindingIntrospection(t *testing.T) {
	f := newOrgFixture(t, func(options *BetterIamOptions) { options.Permissions.Mode = "tenant-defined" })
	owner := f.owner
	user := f.object(f.iam.API.Identities.Create(f.ctx, owner, Input[apitypes.IdentitiesCreateInput](core.NewObject(
		"tenantId", f.tenantID, "email", "editor@roles.test", "name", "Editor", "password", "a strong editor test password"))))
	group := f.object(f.iam.API.Groups.Create(f.ctx, owner, Input[apitypes.GroupsCreateInput](core.NewObject(
		"tenantId", f.tenantID, "name", "Editors", "description", "Can edit"))))
	f.object(f.iam.API.Groups.AddMember(f.ctx, owner, Input[apitypes.GroupsAddMemberInput](core.NewObject(
		"tenantId", f.tenantID, "groupId", group.Get("id"), "identityId", user.Get("id")))))
	editor := f.createRole(owner, "name", "Editor", "description", "Reads and writes documents", "permissions", []any{"documents:read", "documents:write"})
	statement := arrayItems(member(editor.Get("document"), "statements"))[0].(*core.Object)
	if got := core.MustStringify(statement); got != `{"sid":"RolePermissions","effect":"allow","actions":["documents:read","documents:write"],"resources":["*"]}` {
		t.Fatalf("permissions compile to an inline allow: %s", got)
	}
	_, err := f.iam.API.Roles.Create(f.ctx, owner, Input[apitypes.RolesCreateInput](core.NewObject("tenantId", f.tenantID,
		"name", "Both", "permissions", []any{"documents:read"}, "document", obj(t, `{"version":1,"statements":[]}`))))
	expectError(t, err, "INVALID_INPUT", "Provide either permissions or an inline document")
	binding := f.bind(owner, editor.Get("id"), "group", group.Get("id"))
	login := f.iam.Auth
	result := must(login.SignIn(f.ctx, core.NewObject("tenantId", f.tenantID, "email", "editor@roles.test", "password", "a strong editor test password")))
	asEditor := core.CredentialInput{Token: jsString(result.Get("token"))}
	if !f.can(asEditor, "documents:write", "document", "spec") {
		t.Fatal("the group's role grants writes")
	}
	_, err = f.updateRole(owner, "roleId", editor.Get("id"), "permissions", []any{"documents:read"})
	requirePorted(t, err)
	if f.can(asEditor, "documents:write", "document", "spec") || !f.can(asEditor, "documents:read", "document", "spec") {
		t.Fatal("updated permissions apply at once")
	}
	_, err = f.updateRole(owner, "roleId", editor.Get("id"), "document", nil, "name", "Renamed")
	requirePorted(t, err)
	renamed := f.object(f.iam.API.Roles.Get(f.ctx, owner, Input[apitypes.RolesGetInput](core.NewObject("tenantId", f.tenantID, "roleId", editor.Get("id")))))
	if renamed.Get("name") != "Renamed" || renamed.Has("document") {
		t.Fatalf("document null clears the inline document: %s", core.MustStringify(renamed))
	}
	if f.can(asEditor, "documents:read", "document", "spec") {
		t.Fatal("a role without a document grants nothing")
	}
	effective := f.items(f.iam.API.Identities.ListBindings(f.ctx, owner, Input[apitypes.IdentitiesListBindingsInput](core.NewObject(
		"tenantId", f.tenantID, "identityId", user.Get("id")))))
	if len(effective) != 1 || effective[0].Get("id") != binding.Get("id") ||
		member(effective[0].Get("via"), "groupId") != group.Get("id") || member(effective[0].Get("role"), "name") != "Renamed" {
		t.Fatalf("effective bindings: %s", core.MustStringify(recordValues(effective)))
	}
	holders := f.items(f.iam.API.Roles.ListBindings(f.ctx, owner, Input[apitypes.RolesListBindingsInput](core.NewObject(
		"tenantId", f.tenantID, "roleId", editor.Get("id")))))
	if len(holders) == 0 || holders[0].Get("subjectType") != "group" ||
		core.MustStringify(holders[0].Get("subject")) != core.MustStringify(core.NewObject("id", group.Get("id"), "name", "Editors")) {
		t.Fatalf("role bindings: %s", core.MustStringify(recordValues(holders)))
	}
	members := f.items(f.iam.API.Groups.ListMembers(f.ctx, owner, Input[apitypes.GroupsListMembersInput](core.NewObject(
		"tenantId", f.tenantID, "groupId", group.Get("id")))))
	if len(members) != 1 || members[0].Get("id") != user.Get("id") {
		t.Fatalf("group members: %s", core.MustStringify(recordValues(members)))
	}
	policy := f.object(f.iam.API.Policies.Create(f.ctx, owner, Input[apitypes.PoliciesCreateInput](core.NewObject(
		"tenantId", f.tenantID, "name", "Reader", "description", "v1",
		"document", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"]}]}`)))))
	f.object(f.iam.API.Policies.Update(f.ctx, owner, Input[apitypes.PoliciesUpdateInput](core.NewObject(
		"tenantId", f.tenantID, "policyId", policy.Get("id"), "version", 1.0, "description", "v2"))))
	versions := f.items(f.iam.API.Policies.ListVersions(f.ctx, owner, Input[apitypes.PoliciesListVersionsInput](core.NewObject(
		"tenantId", f.tenantID, "policyId", policy.Get("id")))))
	var history []string
	for _, version := range versions {
		history = append(history, core.NumberString(jsNumber(version.Get("version")))+":"+jsString(version.Get("description")))
	}
	if !reflect.DeepEqual(history, []string{"1:v1", "2:v2"}) {
		t.Fatalf("policy history: %v", history)
	}
	current := f.object(f.iam.API.Policies.Get(f.ctx, owner, Input[apitypes.PoliciesGetInput](core.NewObject("tenantId", f.tenantID, "policyId", policy.Get("id")))))
	if current.Get("version") != 2.0 {
		t.Fatalf("current version: %v", current.Get("version"))
	}
}

func TestRolesRevokeSessionsValidatesBeforeAndNeverMovesTheWatermarkBack(t *testing.T) {
	f := newOrgFixture(t, nil)
	role, _ := revokeTrustFixture(t, f, "Reader")
	owner := f.ownerSignIn()
	revoke := func(members ...any) (*core.Object, error) {
		input := core.NewObject("tenantId", f.tenantID, "roleId", role.Get("id"))
		input.Assign(core.NewObject(members...))
		answer, err := f.iam.API.Roles.RevokeSessions(f.ctx, owner, Input[apitypes.RolesRevokeSessionsInput](input))
		if err != nil {
			return nil, err
		}
		return answer.Value.(*core.Object), nil
	}
	for _, before := range []any{f.now() + 2, -1.0, 1.5, "1000", 9007199254740992.0} {
		_, err := revoke("before", before)
		expectCodeOrSkip(t, err, "INVALID_INPUT")
	}
	high := f.now()
	_, err := revoke("before", high)
	requirePorted(t, err)
	f.clock.Add(1000)
	lower, err := revoke("before", high-5000)
	requirePorted(t, err)
	if lower.Get("sessionsRevokedBefore") != high {
		t.Fatalf("the watermark never moves back: %v", lower.Get("sessionsRevokedBefore"))
	}
	// now + 1 is the latest allowed time.
	latest, err := revoke("before", f.now()+1)
	requirePorted(t, err)
	if latest.Get("sessionsRevokedBefore") != f.now()+1 {
		t.Fatalf("latest watermark: %v", latest.Get("sessionsRevokedBefore"))
	}
}

func TestRolesRevokeSessionsRequiresRecentAuthenticationAndThePermission(t *testing.T) {
	f := newOrgFixture(t, nil)
	role, _ := revokeTrustFixture(t, f, "Reader")
	// A role session allowed to revoke sessions still never passes the recent-authentication check.
	revoker := f.createRole(f.owner, "name", "Revoker", "permissions", []any{"iam:roles:revoke-sessions"})
	revokerTrust := f.object(f.iam.API.Trust.Create(f.ctx, f.credential, Input[apitypes.TrustCreateInput](core.NewObject(
		"tenantId", f.tenantID, "sourceTenantId", f.tenantID, "sourceIdentityId", f.ownerID, "roleId", revoker.Get("id"), "requireMfa", false))))
	assumed := f.object(f.iam.API.Roles.Assume(f.ctx, f.ownerSignIn(), Input[apitypes.RolesAssumeInput](core.NewObject(
		"tenantId", f.tenantID, "trustId", revokerTrust.Get("id")))))
	revoke := func(credential core.CredentialInput, roleID any) error {
		_, err := f.iam.API.Roles.RevokeSessions(f.ctx, credential, Input[apitypes.RolesRevokeSessionsInput](core.NewObject("tenantId", f.tenantID, "roleId", roleID)))
		return err
	}
	expectCodeOrSkip(t, revoke(core.CredentialInput{Token: jsString(assumed.Get("token"))}, role.Get("id")), "RECENT_AUTH_REQUIRED")
	owner := f.ownerSignIn()
	f.member("alice")
	expectCodeOrSkip(t, revoke(f.login("alice"), role.Get("id")), "ACCESS_DENIED")
	expectCodeOrSkip(t, revoke(owner, ID()), "NOT_FOUND")
	f.clock.Add(6 * 60_000)
	expectCodeOrSkip(t, revoke(owner, role.Get("id")), "RECENT_AUTH_REQUIRED")
	if f.record("roles", jsString(role.Get("id"))).Has("sessionsRevokedBefore") {
		t.Fatal("a refused revocation leaves the watermark unset")
	}
}

func TestRolesRevokeSessionsRecordsTheRoleSessionsRevokedEvent(t *testing.T) {
	f := newOrgFixture(t, nil)
	role, trust := revokeTrustFixture(t, f, "Reader")
	f.object(f.iam.API.Roles.Assume(f.ctx, f.ownerSignIn(), Input[apitypes.RolesAssumeInput](core.NewObject("tenantId", f.tenantID, "trustId", trust.Get("id")))))
	result := f.object(f.iam.API.Roles.RevokeSessions(f.ctx, f.ownerSignIn(), Input[apitypes.RolesRevokeSessionsInput](core.NewObject(
		"tenantId", f.tenantID, "roleId", role.Get("id")))))
	events := f.auditTrail(f.tenantID, "role:sessions-revoked")
	if len(events) != 1 {
		t.Fatalf("expected one role:sessions-revoked event, got %d", len(events))
	}
	event := events[0]
	if event.Get("actorId") != f.ownerID || event.Get("resourceId") != role.Get("id") || event.Get("outcome") != "allow" ||
		core.MustStringify(event.Get("metadata")) != core.MustStringify(core.NewObject("sessionsRevokedBefore", result.Get("sessionsRevokedBefore"), "revoked", 1.0)) {
		t.Fatalf("event: %s", core.MustStringify(event))
	}
	if got := len(f.auditTrail(f.tenantID, "iam:roles:revoke-sessions")); got != 1 {
		t.Fatalf("expected the operation's own event, got %d", got)
	}
}

// revokeTrustFixture is revoke-older-sessions.test.ts ownerTrust: a reader role in Acme and a same-tenant trust (no
// MFA) from the owner to it.
func revokeTrustFixture(t *testing.T, f *orgFixture, name string) (*core.Object, *core.Object) {
	t.Helper()
	role := f.createRole(f.owner, "name", name,
		"document", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"]}]}`))
	trust := f.object(f.iam.API.Trust.Create(f.ctx, f.credential, Input[apitypes.TrustCreateInput](core.NewObject(
		"tenantId", f.tenantID, "sourceTenantId", f.tenantID, "sourceIdentityId", f.ownerID, "roleId", role.Get("id"), "requireMfa", false))))
	return role, trust
}
