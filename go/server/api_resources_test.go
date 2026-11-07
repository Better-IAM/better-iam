package server

// Registered managed resources, after the resources sections of tests/server.test.ts, tests/access.test.ts, and
// tests/limits.test.ts. (Deleting a leaf resource goes through clearances.ts keepInheritedLabel, which another unit
// ports; the refusal before it is covered here.)

import (
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

func newResourcesFixture(t *testing.T) (*directoryFixture, string, core.CredentialInput) {
	t.Helper()
	f := newDirectoryFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{
			Actions: []string{"folder:read"},
			ResourceTypes: []core.NamedResourceType{
				{Name: "folder", Definition: core.ResourceTypeDefinition{Actions: []string{"folder:read"}, Managed: true,
					Attributes: []core.NamedAttribute{{Name: "confidential", Type: "boolean"}}}},
				{Name: "file", Definition: core.ResourceTypeDefinition{Actions: []string{"folder:read"}, Managed: true, Parent: "folder",
					Attributes: []core.NamedAttribute{{Name: "size", Type: "number"}}}},
				{Name: "document", Definition: core.ResourceTypeDefinition{Actions: []string{"folder:read"}}},
			},
		}
	})
	tenantID, owner := f.organization("Resources", "owner@resources.test")
	return f, tenantID, owner
}

func registerInput(pairs ...any) In[apitypes.ResourcesRegisterInput] {
	return Input[apitypes.ResourcesRegisterInput](body(pairs...))
}

func TestResourcesRegisterValidateAndLink(t *testing.T) {
	f, tenantID, owner := newResourcesFixture(t)
	resources := f.iam.API.Resources
	register := func(credential core.CredentialInput, pairs ...any) (Out[apitypes.ResourcesRegisterOutput], error) {
		return resources.Register(f.ctx, credential, registerInput(append([]any{"tenantId", tenantID}, pairs...)...))
	}
	for _, refused := range []struct {
		input   []any
		code    string
		message string
	}{
		{[]any{"type", "folder", "id", "shared", "attributes", body("confidential", "yes")}, "INVALID_INPUT", "Attribute confidential must be a boolean"},
		{[]any{"type", "folder", "id", "shared", "attributes", body("color", "red")}, "INVALID_INPUT", "Attribute color is not declared for this resource type"},
		{[]any{"type", "file", "id", "orphan"}, "INVALID_INPUT", "Resources of type file require a folder parent"},
		{[]any{"type", "folder", "id", "child", "parentId", "x"}, "INVALID_INPUT", "This resource type has no parent"},
		{[]any{"type", "nothing", "id", "x"}, "INVALID_RESOURCE_TYPE", "Unknown resource type"},
		{[]any{"type", "document", "id", "x"}, "INVALID_RESOURCE_TYPE", "This resource type is resolved by the application, not registered with IAM"},
		{[]any{"type", "folder", "id", "all*"}, "INVALID_INPUT", "A resource ID cannot contain * or ?"},
		{[]any{"type", "folder"}, "INVALID_INPUT", "Invalid resource id"},
		{[]any{"id", "x"}, "INVALID_INPUT", "Invalid resource type"},
	} {
		_, err := register(owner, refused.input...)
		expectError(t, err, refused.code, refused.message)
	}
	member, memberCredential := f.person(tenantID, "member")
	answer(register(owner, "type", "folder", "id", "shared", "attributes", body("confidential", false)))
	answer(register(owner, "type", "folder", "id", "secret", "attributes", body("confidential", true)))
	owned := answerObject(register(owner, "type", "file", "id", "notes", "parentId", "shared", "ownerId", member.Get("id"), "attributes", body("size", 12.0)))
	if stringify(owned.Keys()) != `["id","tenantId","uniqueKey","type","resourceId","attributes","createdAt","updatedAt","parentType","parentId","ownerId"]` ||
		owned.Get("uniqueKey") != "file/notes" || owned.Get("parentType") != "folder" || owned.Get("parentId") != "shared" ||
		owned.Get("ownerId") != member.Get("id") || stringify(owned.Get("attributes")) != `{"size":12}` || owned.Get("createdAt") != f.now() {
		t.Fatalf("owned = %s", stringify(owned))
	}
	_, err := register(owner, "type", "file", "id", "notes", "parentId", "shared")
	expectError(t, err, "CONFLICT", "Resource is already registered")
	_, err = register(owner, "type", "file", "id", "lost", "parentId", "missing")
	expectError(t, err, "NOT_FOUND", "Parent resource is not registered")
	_, err = register(owner, "type", "folder", "id", "ghost", "ownerId", "nobody")
	expectStatus(t, err, 404)
	answer(register(owner, "type", "file", "id", "plan", "parentId", "secret", "attributes", body("size", 1.0)))
	_, err = register(memberCredential, "type", "folder", "id", "mine")
	expectCode(t, err, "ACCESS_DENIED")

	got := answerObject(resources.Get(f.ctx, owner, Input[apitypes.ResourcesGetInput](body("tenantId", tenantID, "type", "file", "id", "notes"))))
	if got.Get("id") != owned.Get("id") {
		t.Fatalf("get = %s", stringify(got))
	}
	_, err = resources.Get(f.ctx, owner, Input[apitypes.ResourcesGetInput](body("tenantId", tenantID, "type", "file", "id", "none")))
	expectError(t, err, "NOT_FOUND", "Resource is not registered")

	// Updating replaces attributes and moves or clears the owner.
	update := func(pairs ...any) (Out[apitypes.ResourcesUpdateOutput], error) {
		return resources.Update(f.ctx, owner, Input[apitypes.ResourcesUpdateInput](body(append([]any{"tenantId", tenantID, "type", "file", "id", "notes"}, pairs...)...)))
	}
	f.advance(1000)
	updated := answerObject(update("attributes", body("size", 40.0), "ownerId", nil))
	if updated.Has("ownerId") || stringify(updated.Get("attributes")) != `{"size":40}` || updated.Get("updatedAt") != f.now() ||
		updated.Get("createdAt") != owned.Get("createdAt") {
		t.Fatalf("updated = %s", stringify(updated))
	}
	_, err = update("ownerId", "nobody")
	expectStatus(t, err, 404)
	_, err = update("attributes", body("size", "big"))
	expectError(t, err, "INVALID_INPUT", "Attribute size must be a number")
	_, err = resources.Update(f.ctx, owner, Input[apitypes.ResourcesUpdateInput](body("tenantId", tenantID, "type", "folder", "id", "none")))
	expectError(t, err, "NOT_FOUND", "Resource is not registered")

	// Listing filters by type, parent, and owner, ordered by type and ID, and pages.
	list := func(credential core.CredentialInput, pairs ...any) []string {
		t.Helper()
		return pluck(answerList(resources.List(f.ctx, credential, Input[apitypes.ResourcesListInput](body(append([]any{"tenantId", tenantID}, pairs...)...)))), "uniqueKey")
	}
	if got := list(owner); stringify(got) != `["file/notes","file/plan","folder/secret","folder/shared"]` {
		t.Fatalf("list = %v", got)
	}
	if got := list(owner, "type", "file", "parentId", "shared"); stringify(got) != `["file/notes"]` {
		t.Fatalf("list by parent = %v", got)
	}
	if got := list(owner, "limit", 2.0, "offset", 1.0); stringify(got) != `["file/plan","folder/secret"]` {
		t.Fatalf("paged = %v", got)
	}
	if got := list(owner, "offset", 10.0); stringify(got) != `[]` {
		t.Fatalf("past the end = %v", got)
	}
	_, err = resources.List(f.ctx, owner, Input[apitypes.ResourcesListInput](body("tenantId", tenantID, "limit", 0.0)))
	expectError(t, err, "INVALID_INPUT", "Invalid limit")

	// A record a policy keeps from the caller is left out of the listing, as resources.get would refuse it.
	readerRole := f.role(tenantID, "Reader",
		allow(items("iam:resources:read"), items("*")),
		core.NewObject("effect", "deny", "actions", items("iam:resources:read"), "resources", items("iam/folder/secret")))
	f.bind(tenantID, readerRole, "identity", jsString(member.Get("id")))
	if got := list(memberCredential); stringify(got) != `["file/notes","file/plan","folder/shared"]` {
		t.Fatalf("list as a reader = %v", got)
	}
	_, err = resources.Get(f.ctx, memberCredential, Input[apitypes.ResourcesGetInput](body("tenantId", tenantID, "type", "folder", "id", "secret")))
	expectCode(t, err, "ACCESS_DENIED")

	// A resource with children cannot be deleted.
	_, err = resources.Delete(f.ctx, owner, Input[apitypes.ResourcesDeleteInput](body("tenantId", tenantID, "type", "folder", "id", "shared")))
	expectError(t, err, "RESOURCE_IN_USE", "Delete child resources first")
	_, err = resources.Delete(f.ctx, owner, Input[apitypes.ResourcesDeleteInput](body("tenantId", tenantID, "type", "folder", "id", "none")))
	expectError(t, err, "NOT_FOUND", "Resource is not registered")
}

func TestResourcesRegisterManyIsAtomicAndAuthorizedPerItem(t *testing.T) {
	f, tenantID, owner := newResourcesFixture(t)
	resources := f.iam.API.Resources
	registerMany := func(credential core.CredentialInput, list any) (Out[apitypes.ResourcesRegisterManyOutput], error) {
		return resources.RegisterMany(f.ctx, credential, Input[apitypes.ResourcesRegisterManyInput](body("tenantId", tenantID, "resources", list)))
	}
	_, err := registerMany(owner, items())
	expectError(t, err, "INVALID_INPUT", "Provide 1-100 resources")
	_, err = registerMany(owner, "x")
	expectError(t, err, "INVALID_INPUT", "Provide 1-100 resources")
	_, err = registerMany(owner, items("folder/x"))
	expectError(t, err, "INVALID_INPUT", "Expected an object")
	_, err = registerMany(owner, items(body("type", "folder")))
	expectError(t, err, "INVALID_INPUT", "Invalid resource id")

	// A caller allowed folders only is refused the whole batch; the refusal names the item and commits only its audit.
	member, memberCredential := f.person(tenantID, "member")
	creator := f.role(tenantID, "Folder creator", allow(items("iam:resources:create"), items("iam/folder/*")))
	f.bind(tenantID, creator, "identity", jsString(member.Get("id")))
	_, err = registerMany(memberCredential, items(body("type", "folder", "id", "a"), body("type", "file", "id", "b", "parentId", "a")))
	expectError(t, err, "ACCESS_DENIED", "Access denied for file/b")
	if left := f.find("resources", body("tenantId", tenantID)); len(left) != 0 {
		t.Fatalf("a refused batch wrote %d resources", len(left))
	}
	denials := f.find("audit", body("tenantId", tenantID, "action", "iam:resources:create", "outcome", "deny"))
	if len(denials) != 1 || denials[0].Get("resourceId") != "file/b" {
		t.Fatalf("denials = %d", len(denials))
	}

	// The owner registers parents before children in one batch; every item is audited.
	result := answerObject(registerMany(owner, items(
		body("type", "folder", "id", "a", "attributes", body("confidential", true)),
		body("type", "file", "id", "b", "parentId", "a"),
	)))
	registered := objectsOf(result.Get("resources"))
	if len(registered) != 2 || registered[1].Get("parentId") != "a" || stringify(registered[0].Get("attributes")) != `{"confidential":true}` {
		t.Fatalf("registered = %s", stringify(result))
	}
	allowed := f.find("audit", body("tenantId", tenantID, "action", "iam:resources:create", "outcome", "allow"))
	if len(allowed) != 2 {
		t.Fatalf("allow events = %d", len(allowed))
	}
	// A failing item rolls the whole batch back.
	_, err = registerMany(owner, items(body("type", "folder", "id", "c"), body("type", "folder", "id", "a")))
	expectError(t, err, "CONFLICT", "Resource is already registered")
	if found := f.find("resources", body("tenantId", tenantID, "uniqueKey", "folder/c")); len(found) != 0 {
		t.Fatal("a failed batch kept its first item")
	}
}

func TestResourcesRespectTheTenantLimit(t *testing.T) {
	f, tenantID, owner := newResourcesFixture(t)
	f.patch("tenants", tenantID, body("limits", body("resources", 2.0)))
	resources := f.iam.API.Resources
	answer(resources.Register(f.ctx, owner, registerInput("tenantId", tenantID, "type", "folder", "id", "one")))
	_, err := resources.RegisterMany(f.ctx, owner, Input[apitypes.ResourcesRegisterManyInput](body("tenantId", tenantID,
		"resources", items(body("type", "folder", "id", "two"), body("type", "folder", "id", "three")))))
	expectError(t, err, "LIMIT_EXCEEDED", "This tenant has reached its resource limit (2)")
	answer(resources.Register(f.ctx, owner, registerInput("tenantId", tenantID, "type", "folder", "id", "two")))
	_, err = resources.Register(f.ctx, owner, registerInput("tenantId", tenantID, "type", "folder", "id", "three"))
	expectError(t, err, "LIMIT_EXCEEDED", "This tenant has reached its resource limit (2)")
}
