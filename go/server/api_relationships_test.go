package server

// Relationship tuples, after tests/relationships.test.ts. (Deleting a resource goes through clearances.ts
// keepInheritedLabel, which another unit ports, so the resource-deletion step is not repeated here.)

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

func TestRelationshipsGrantAccessThroughHeldRelations(t *testing.T) {
	documents := map[string]string{}
	f := newDirectoryFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{
			Mode: "tenant-defined",
			ResourceTypes: []core.NamedResourceType{
				{Name: "folder", Definition: core.ResourceTypeDefinition{Managed: true, Actions: []string{"folders:read", "folders:share"},
					Relations: []string{"viewer", "editor", "owner"}}},
				{Name: "file", Definition: core.ResourceTypeDefinition{Managed: true, Parent: "folder", Actions: []string{"files:read", "files:write"},
					Relations: []string{"viewer", "editor"}}},
				{Name: "note", Definition: core.ResourceTypeDefinition{Actions: []string{"notes:read"}, Relations: []string{"reader"}}},
			},
		}
		options.ResolveResource = func(ctx context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			title, ok := documents[reference.ID]
			if !ok || reference.Type != "note" {
				return nil, errors.New("unknown")
			}
			return &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID, Attributes: body("title", title)}, nil
		}
	})
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	relationships := f.iam.API.Relationships
	alice, aliceCredential := f.person(tenantID, "alice")
	bob, bobCredential := f.person(tenantID, "bob")
	aliceID, bobID := jsString(alice.Get("id")), jsString(bob.Get("id"))
	f.seed("groups", body("id", "team", "tenantId", tenantID, "name", "Team", "createdAt", f.now()))
	f.seed("groupMembers", body("id", "team-bob", "tenantId", tenantID, "groupId", "team", "identityId", bobID, "createdAt", f.now()))
	holds := func(path string, relations ...any) *core.Object {
		return body("ArrayContains", body(path, items(relations...)))
	}
	sharing := f.role(tenantID, "Sharing",
		allow(items("folders:read", "files:read"), items("*"), "conditions", holds("resource.relations", "viewer", "editor", "owner")),
		allow(items("files:read"), items("file/*"), "conditions", holds("resource.parentRelations", "viewer", "editor", "owner")),
		allow(items("files:write"), items("file/*"), "conditions", holds("resource.relations", "editor")),
		allow(items("folders:share", "iam:relationships:create", "iam:relationships:read"), items("*"), "conditions", holds("resource.relations", "owner")),
		allow(items("iam:relationships:create"), items("iam/file/*"), "conditions", holds("resource.parentRelations", "owner")),
		allow(items("notes:read"), items("note/*"), "conditions", holds("resource.relations", "reader")),
	)
	f.bind(tenantID, sharing, "identity", aliceID)
	f.bind(tenantID, sharing, "identity", bobID)
	answer(f.iam.API.Resources.RegisterMany(f.ctx, owner, Input[apitypes.ResourcesRegisterManyInput](body("tenantId", tenantID, "resources", items(
		body("type", "folder", "id", "plans"),
		body("type", "file", "id", "roadmap", "parentId", "plans"),
		body("type", "folder", "id", "private"),
		body("type", "file", "id", "diary", "parentId", "private"),
	)))))
	check := func(credential core.CredentialInput, action, kind, id string) bool {
		t.Helper()
		decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{Credential: credential, TenantID: tenantID, Action: action,
			Resource: ResourceTarget{Type: kind, ID: id}})
		if err != nil {
			t.Fatalf("authorize %s %s/%s: %v", action, kind, id, err)
		}
		return decision.Allowed
	}
	create := func(credential core.CredentialInput, pairs ...any) (Out[apitypes.RelationshipsCreateOutput], error) {
		return relationships.Create(f.ctx, credential, Input[apitypes.RelationshipsCreateInput](body(append([]any{"tenantId", tenantID}, pairs...)...)))
	}
	if check(aliceCredential, "folders:read", "folder", "plans") {
		t.Fatal("alice reads plans before any relation")
	}
	// Validation: undeclared relations, unknown types, unregistered managed resources, and wrong subjects.
	for _, refused := range []struct {
		input   []any
		code    string
		message string
	}{
		{[]any{"type", "folder", "id", "plans", "relation", "admin", "subjectType", "identity", "subjectId", aliceID}, "INVALID_INPUT", "Relation admin is not declared for folder"},
		{[]any{"type", "nothing", "id", "x", "relation", "viewer", "subjectType", "identity", "subjectId", aliceID}, "INVALID_RESOURCE_TYPE", "Unknown resource type"},
		{[]any{"type", "folder", "id", "missing", "relation", "viewer", "subjectType", "identity", "subjectId", aliceID}, "NOT_FOUND", "Resource is not registered"},
		{[]any{"type", "folder", "id", "plans", "relation", "viewer", "subjectType", "identity", "subjectId", "nobody"}, "NOT_FOUND", "Resource not found"},
		{[]any{"type", "folder", "id", "plans", "relation", "viewer", "subjectType", "robot", "subjectId", aliceID}, "INVALID_INPUT", "Invalid subject type"},
		{[]any{"type", "folder", "relation", "viewer", "subjectType", "identity", "subjectId", aliceID}, "INVALID_INPUT", "Invalid resource id"},
	} {
		_, err := create(owner, refused.input...)
		expectError(t, err, refused.code, refused.message)
	}
	// Alice owns the folder; the team can view it. Relations flow to files through the parent.
	ownerTuple := answerObject(create(owner, "type", "folder", "id", "plans", "relation", "owner", "subjectType", "identity", "subjectId", aliceID))
	if stringify(ownerTuple.Keys()) != `["id","tenantId","uniqueKey","type","resourceId","relation","subjectType","subjectId","createdAt","createdBy"]` ||
		ownerTuple.Get("uniqueKey") != "folder/plans#owner@identity:"+aliceID {
		t.Fatalf("owner tuple = %s", stringify(ownerTuple))
	}
	answer(create(owner, "type", "folder", "id", "plans", "relation", "viewer", "subjectType", "group", "subjectId", "team"))
	for _, expected := range []struct {
		credential core.CredentialInput
		action     string
		kind, id   string
		allowed    bool
	}{
		{aliceCredential, "folders:read", "folder", "plans", true},
		{aliceCredential, "files:read", "file", "roadmap", true},
		{aliceCredential, "files:write", "file", "roadmap", false},
		{bobCredential, "folders:read", "folder", "plans", true},
		{bobCredential, "files:read", "file", "roadmap", true},
		{bobCredential, "files:read", "file", "diary", false},
		{aliceCredential, "folders:read", "folder", "private", false},
	} {
		if got := check(expected.credential, expected.action, expected.kind, expected.id); got != expected.allowed {
			t.Fatalf("%s on %s/%s = %v, want %v", expected.action, expected.kind, expected.id, got, expected.allowed)
		}
	}
	// Creating the same tuple again keeps its ID and creation time.
	f.advance(1000)
	again := answerObject(create(owner, "type", "folder", "id", "plans", "relation", "owner", "subjectType", "identity", "subjectId", aliceID))
	if again.Get("id") != ownerTuple.Get("id") || again.Get("createdAt") != ownerTuple.Get("createdAt") {
		t.Fatalf("upsert = %s", stringify(again))
	}
	// The owner relation lets Alice share the folder's files herself; Bob cannot.
	answer(create(aliceCredential, "type", "file", "id", "roadmap", "relation", "editor", "subjectType", "identity", "subjectId", bobID))
	_, err := create(bobCredential, "type", "folder", "id", "private", "relation", "viewer", "subjectType", "identity", "subjectId", bobID)
	expectCode(t, err, "ACCESS_DENIED")
	if !check(bobCredential, "files:write", "file", "roadmap") {
		t.Fatal("bob cannot write the roadmap he edits")
	}
	list := func(credential core.CredentialInput, pairs ...any) ([]*core.Object, error) {
		out, err := relationships.List(f.ctx, credential, Input[apitypes.RelationshipsListInput](body(append([]any{"tenantId", tenantID}, pairs...)...)))
		if err != nil {
			return nil, err
		}
		return answerList(out, nil), nil
	}
	onFolder, err := list(aliceCredential, "type", "folder", "id", "plans")
	if err != nil {
		t.Fatal(err)
	}
	held := make([]string, len(onFolder))
	for index, tuple := range onFolder {
		held[index] = jsString(tuple.Get("relation")) + ":" + jsString(tuple.Get("subjectType"))
	}
	sort.Strings(held)
	if stringify(held) != `["owner:identity","viewer:group"]` {
		t.Fatalf("tuples on plans = %v", held)
	}
	_, err = list(bobCredential)
	expectCode(t, err, "ACCESS_DENIED")
	ofBob, err := list(owner, "subjectType", "identity", "subjectId", bobID)
	if err != nil || stringify(pluck(ofBob, "relation")) != `["editor"]` {
		t.Fatalf("tuples of bob = %v %v", pluck(ofBob, "relation"), err)
	}
	_, err = list(owner, "subjectType", "robot")
	expectError(t, err, "INVALID_INPUT", "Invalid subject type")
	// A listing leaves out the tuples of resources a policy keeps from the caller.
	readerRole := f.role(tenantID, "Relationship reader",
		allow(items("iam:relationships:read"), items("*")),
		core.NewObject("effect", "deny", "actions", items("iam:relationships:read"), "resources", items("iam/file/roadmap")))
	carol, carolCredential := f.person(tenantID, "carol")
	f.bind(tenantID, readerRole, "identity", jsString(carol.Get("id")))
	visible, err := list(carolCredential)
	if err != nil {
		t.Fatal(err)
	}
	for _, tuple := range visible {
		if tuple.Get("type") == "file" {
			t.Fatalf("a denied resource's tuple is listed: %s", stringify(tuple))
		}
	}
	if len(visible) != 2 {
		t.Fatalf("visible tuples = %d", len(visible))
	}

	// Application-owned resources can carry relations too, with an expiry.
	documents["memo"] = "Memo"
	if check(aliceCredential, "notes:read", "note", "memo") {
		t.Fatal("alice reads the memo before the relation")
	}
	answer(create(owner, "type", "note", "id", "memo", "relation", "reader", "subjectType", "identity", "subjectId", aliceID, "expiresAt", f.now()+60_000))
	if !check(aliceCredential, "notes:read", "note", "memo") {
		t.Fatal("alice cannot read the memo she holds a relation on")
	}
	f.advance(61_000)
	if check(aliceCredential, "notes:read", "note", "memo") {
		t.Fatal("an expired relation still grants")
	}
	if notes, err := list(owner, "type", "note"); err != nil || len(notes) != 0 {
		t.Fatalf("expired tuples listed: %d %v", len(notes), err)
	}
	if notes, err := list(owner, "type", "note", "includeExpired", true); err != nil || len(notes) != 1 {
		t.Fatalf("includeExpired: %d %v", len(notes), err)
	}
	_, err = create(owner, "type", "note", "id", "memo", "relation", "reader", "subjectType", "identity", "subjectId", aliceID, "expiresAt", f.now()-1)
	expectCode(t, err, "INVALID_INPUT")

	// Deleting a tuple removes the access it carried.
	remove := func(credential core.CredentialInput, id any) (Out[apitypes.RelationshipsDeleteOutput], error) {
		return relationships.Delete(f.ctx, credential, Input[apitypes.RelationshipsDeleteInput](body("tenantId", tenantID, "relationshipId", id)))
	}
	_, err = remove(bobCredential, ownerTuple.Get("id"))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = remove(owner, "missing")
	expectError(t, err, "NOT_FOUND", "Resource not found")
	if result := answerObject(remove(owner, ownerTuple.Get("id"))); stringify(result) != `{"deleted":true}` {
		t.Fatalf("delete = %s", stringify(result))
	}
	if check(aliceCredential, "folders:read", "folder", "plans") {
		t.Fatal("a deleted owner tuple still grants")
	}
}
