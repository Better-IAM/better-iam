package server

// Test support for the analysis, roleMining, impact, and accessPaths API groups (after tests/support/organization.ts
// and the fixtures of tests/analysis.test.ts, tests/role-mining.test.ts, tests/impact.test.ts, and
// tests/access-paths.test.ts). Roles, policies, groups, memberships, bindings, packages, and agreements are seeded in
// the store the way roles.create, policies.create, groups.create / anaAddMembers, bindings.create, packages.create, and
// agreements.create write them (those API groups are ported separately); the API groups under test are called through
// iam.API.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// newAnalysisFixture is organizationFixture: documents:read and documents:write, resources resolved as referenced.
func newAnalysisFixture(t *testing.T, mutate func(options *BetterIamOptions)) *directoryFixture {
	t.Helper()
	return newDirectoryFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}}
		options.ResolveResource = func(ctx context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			return &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID, Attributes: core.NewObject()}, nil
		}
		if mutate != nil {
			mutate(options)
		}
	})
}

// anaSkipUnported skips the test when it reached a NOT_IMPLEMENTED stub of a module another unit ports; the test runs
// in full once that module lands.
func anaSkipUnported(t *testing.T, err error) {
	t.Helper()
	var known *core.IamError
	if errors.As(err, &known) && known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("reaches a module not ported yet: %s", known.Message)
	}
}

// anaTry is answer for a call that may reach another unit's stub: it skips the test then, and fails on any other error.
func anaTry[T any](t *testing.T, out Out[T], err error) any {
	t.Helper()
	if err != nil {
		anaSkipUnported(t, err)
		t.Fatalf("unexpected error: %v", err)
	}
	return out.Value
}

func anaTryObject[T any](t *testing.T, out Out[T], err error) *core.Object {
	t.Helper()
	object, ok := anaTry(t, out, err).(*core.Object)
	if !ok {
		t.Fatalf("answer is not an object: %#v", out.Value)
	}
	return object
}

// anaRefuse expects an error with the code, skipping the test when the call reached another unit's stub first.
func anaRefuse(t *testing.T, err error, code string) {
	t.Helper()
	if err != nil {
		var known *core.IamError
		if errors.As(err, &known) && known.Code == "NOT_IMPLEMENTED" && code != "NOT_IMPLEMENTED" {
			anaSkipUnported(t, err)
		}
	}
	expectCode(t, err, code)
}

// anaPermissions is the inline document roles.create writes for `permissions`.
func anaPermissions(actions ...string) *core.Object {
	return core.NewObject("version", 1.0, "statements", []any{core.NewObject(
		"sid", "RolePermissions", "effect", "allow", "actions", stringsOf(actions), "resources", []any{"*"},
	)})
}

// anaDocument is a policy document of statements.
func anaDocument(statements ...*core.Object) *core.Object {
	list := make([]any, len(statements))
	for index, statement := range statements {
		list[index] = statement
	}
	return core.NewObject("version", 1.0, "statements", list)
}

// anaRole writes a role as roles.create does (members: document, inherits, policyIds, ...) and returns it.
func (f *directoryFixture) anaRole(tenantID, name string, members ...any) *core.Object {
	f.t.Helper()
	role := core.NewObject("id", ID(), "tenantId", tenantID, "name", name, "policyIds", []any{}, "protected", false,
		"authorityId", f.authorities[tenantID])
	for index := 0; index+1 < len(members); index += 2 {
		role.Set(members[index].(string), members[index+1])
	}
	f.seed("roles", role)
	return role
}

// anaPolicy writes a policy as policies.create does and returns it.
func (f *directoryFixture) anaPolicy(tenantID, name string, document *core.Object) *core.Object {
	f.t.Helper()
	policy := core.NewObject("id", ID(), "tenantId", tenantID, "name", name, "document", document, "version", 1.0,
		"authorityId", f.authorities[tenantID])
	f.seed("policies", policy)
	return policy
}

// anaBinding writes a binding as bindings.create does (members: eligible, expiresAt, ...) and returns it.
func (f *directoryFixture) anaBinding(tenantID, roleID, subjectType, subjectID string, members ...any) *core.Object {
	f.t.Helper()
	authority := f.authorities[tenantID]
	binding := core.NewObject("id", ID(), "tenantId", tenantID,
		"uniqueKey", subjectType+":"+subjectID+":"+roleID+":"+authority, "subjectType", subjectType, "subjectId", subjectID,
		"roleId", roleID, "authorityId", authority)
	for index := 0; index+1 < len(members); index += 2 {
		binding.Set(members[index].(string), members[index+1])
	}
	f.seed("bindings", binding)
	return binding
}

// anaGroup writes a group as groups.create does and returns it.
func (f *directoryFixture) anaGroup(tenantID, name string) *core.Object {
	f.t.Helper()
	group := core.NewObject("id", ID(), "tenantId", tenantID, "name", name)
	f.seed("groups", group)
	return group
}

// anaAddMembers writes memberships as groups.anaAddMembers does.
func (f *directoryFixture) anaAddMembers(tenantID, groupID string, identityIDs ...string) {
	f.t.Helper()
	for _, identityID := range identityIDs {
		f.seed("groupMembers", core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", groupID+":"+identityID,
			"groupId", groupID, "identityId", identityID))
	}
}

// anaRemoveMember deletes a membership as groups.anaRemoveMember does.
func (f *directoryFixture) anaRemoveMember(tenantID, groupID, identityID string) {
	f.t.Helper()
	for _, member := range f.find("groupMembers", core.NewObject("tenantId", tenantID, "uniqueKey", groupID+":"+identityID)) {
		f.transact(func(ctx context.Context, tx core.IamStore) error {
			return tx.Delete(ctx, "groupMembers", jsString(member.Get("id")))
		})
	}
}

// anaPackage writes an access package as packages.create does and returns it.
func (f *directoryFixture) anaPackage(tenantID, name string, roleIDs, groupIDs []string, members ...any) *core.Object {
	f.t.Helper()
	pkg := core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", "name:"+strings.ToLower(name), "name", name,
		"roleIds", stringsOf(roleIDs), "groupIds", stringsOf(groupIDs), "createdAt", f.now(), "updatedAt", f.now())
	for index := 0; index+1 < len(members); index += 2 {
		pkg.Set(members[index].(string), members[index+1])
	}
	f.seed("accessPackages", pkg)
	return pkg
}

// anaAgreement writes a required agreement as agreements.create does and returns it.
func (f *directoryFixture) anaAgreement(tenantID, name, content string) *core.Object {
	f.t.Helper()
	agreement := core.NewObject("uniqueKey", "name:"+strings.ToLower(name), "name", name, "content", content,
		"required", true, "id", ID(), "tenantId", tenantID, "version", 1.0, "createdAt", f.now(), "updatedAt", f.now())
	f.seed("agreements", agreement)
	return agreement
}

// member is f.member: a person of the tenant with a password, signed in.
func (f *directoryFixture) anaMember(tenantID, name string) (*core.Object, core.CredentialInput) {
	f.t.Helper()
	return f.person(tenantID, name)
}

// anaIdentity creates a member of a tenant with a password, as identities.create does, without signing it in.
func (f *directoryFixture) anaIdentity(tenantID, name string) *core.Object {
	f.t.Helper()
	identity, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: tenantID, Email: name + "@acme.test", Name: name, Password: "a strong " + name + " password",
			HasPassword: true, EmailVerified: true,
		})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return identity
}

func anaID(record *core.Object) string { return jsString(record.Get("id")) }

// anaSorted is `[...values].sort()`.
func anaSorted(values []string) []string { return miningSorted(values) }

// anaObjects is a model array as objects.
func anaObjects(value any) []*core.Object {
	list, _ := value.([]any)
	objects := make([]*core.Object, len(list))
	for index, item := range list {
		objects[index], _ = item.(*core.Object)
	}
	return objects
}
