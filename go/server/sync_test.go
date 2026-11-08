package server

// Configuration sync tests, after tests/config-sync.test.ts, tests/config-governance.test.ts,
// tests/security-sync.test.ts, and tests/config-review.test.ts: plan, apply, export and convergence of a tenant
// configuration; malformed and dangling documents; per-change authorization with all-or-nothing applies; invariants
// and terms of use; SCIM groups that take a configured group's name; what a binding replacement keeps; duration
// bounds; case-insensitive package names. Steps that reach another unit's stub skip until that unit is ported.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

type configFixture struct {
	*orgFixture
}

func newConfigFixture(t *testing.T, mutate func(options *BetterIamOptions)) *configFixture {
	t.Helper()
	return &configFixture{orgFixture: newOrgFixture(t, mutate)}
}

// request is a config API body: tenantId, config, and prune when set.
func (f *configFixture) request(config any, prune bool) *core.Object {
	input := core.NewObject("tenantId", f.tenantID, "config", config)
	if prune {
		input.Set("prune", true)
	}
	return input
}

func (f *configFixture) plan(credential core.CredentialInput, config any, prune bool) *core.Object {
	f.t.Helper()
	return f.object(f.iam.API.Config.Plan(f.ctx, credential, Input[apitypes.ConfigPlanInput](f.request(config, prune))))
}

func (f *configFixture) apply(credential core.CredentialInput, config any, prune bool) *core.Object {
	f.t.Helper()
	return f.object(f.iam.API.Config.Apply(f.ctx, credential, Input[apitypes.ConfigApplyInput](f.request(config, prune))))
}

func (f *configFixture) export(credential core.CredentialInput) *core.Object {
	f.t.Helper()
	return f.object(f.iam.API.Config.Export(f.ctx, credential, Input[apitypes.ConfigExportInput](core.NewObject("tenantId", f.tenantID))))
}

// configFailure expects an IamError (skipping on another unit's stub) and returns it.
func configFailure(t *testing.T, err error) *core.IamError {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got success")
	}
	known := iamError(t, err)
	if known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
	return known
}

func (f *configFixture) planFails(credential core.CredentialInput, config any, prune bool) *core.IamError {
	f.t.Helper()
	_, err := f.iam.API.Config.Plan(f.ctx, credential, Input[apitypes.ConfigPlanInput](f.request(config, prune)))
	return configFailure(f.t, err)
}

func (f *configFixture) applyFails(credential core.CredentialInput, config any, prune bool) *core.IamError {
	f.t.Helper()
	_, err := f.iam.API.Config.Apply(f.ctx, credential, Input[apitypes.ConfigApplyInput](f.request(config, prune)))
	return configFailure(f.t, err)
}

// call invokes another API group with a body for the tenant.
func configCall[I, O any](f *configFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, members ...any) any {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID).Assign(core.NewObject(members...))
	return f.ported(method(f.ctx, credential, Input[I](input)))
}

func configObjects(t *testing.T, value any) []*core.Object {
	t.Helper()
	list, ok := value.([]any)
	if !ok {
		t.Fatalf("expected a list, got %T", value)
	}
	objects := make([]*core.Object, len(list))
	for index, item := range list {
		objects[index], _ = item.(*core.Object)
	}
	return objects
}

// configChangeLines lists a plan's changes as "{action} {kind} {name}".
func configChangeLines(plan *core.Object) []string {
	lines := []string{}
	for _, change := range configObjectsOf(plan.Get("changes")) {
		lines = append(lines, jsString(change.Get("action"))+" "+jsString(change.Get("kind"))+" "+jsString(change.Get("name")))
	}
	return lines
}

func configObjectsOf(value any) []*core.Object {
	list, _ := value.([]any)
	objects := []*core.Object{}
	for _, item := range list {
		if object, ok := item.(*core.Object); ok {
			objects = append(objects, object)
		}
	}
	return objects
}

// configPending is the changes that are not `unchanged`.
func configPending(plan *core.Object) []*core.Object {
	out := []*core.Object{}
	for _, change := range configObjectsOf(plan.Get("changes")) {
		if change.Get("action") != "unchanged" {
			out = append(out, change)
		}
	}
	return out
}

func configChangeOf(plan *core.Object, test func(*core.Object) bool) *core.Object {
	for _, change := range configObjectsOf(plan.Get("changes")) {
		if test(change) {
			return change
		}
	}
	return nil
}

// configSameJSON compares model values like toEqual (member order aside).
func configSameJSON(t *testing.T, label string, got any, want string) {
	t.Helper()
	expected := parse(t, want)
	if !syncSame(got, expected) {
		a, _ := syncCanonical(got)
		b, _ := syncCanonical(expected)
		t.Fatalf("%s:\n got  %s\n want %s", label, a, b)
	}
}

func configLines(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%s:\n got  %q\n want %q", label, got, want)
	}
}

func configSorted(items []string) []string {
	out := append([]string(nil), items...)
	sort.Strings(out)
	return out
}

const configSyncDesired = `{
  "version": 1,
  "resourceTypes": [
    { "name": "project", "description": "A project", "actions": ["read", "write"], "attributes": { "archived": "boolean" }, "relations": ["viewer"] }
  ],
  "policies": [
    { "name": "Readers", "document": { "version": 1, "statements": [ { "effect": "allow", "actions": ["documents:read", "project:read"], "resources": ["*"] } ] } }
  ],
  "roles": [
    { "name": "Reader", "description": "Reads", "policies": ["Readers"] },
    { "name": "Editor", "permissions": ["documents:write", "project:write"] }
  ],
  "groups": [{ "name": "Engineering", "members": ["alice@acme.test"] }],
  "bindings": [
    { "group": "Engineering", "role": "Reader" },
    { "group": "Engineering", "role": "Editor", "eligible": true, "maxActivationMs": 600000, "requireJustification": true }
  ]
}`

func newConfigSyncFixture(t *testing.T) *configFixture {
	t.Helper()
	f := newConfigFixture(t, func(options *BetterIamOptions) { options.Permissions.Mode = "tenant-defined" })
	f.member("alice")
	f.member("bob")
	return f
}

func TestConfigSyncPlansAppliesExportsAndConverges(t *testing.T) {
	f := newConfigSyncFixture(t)
	owner := f.owner
	desired := parse(t, configSyncDesired)
	plan := f.plan(owner, desired, false)
	configSameJSON(t, "summary", plan.Get("summary"), `{"create":7,"update":0,"delete":0,"unchanged":0}`)
	configLines(t, "changes", configChangeLines(plan),
		"create resourceType project",
		"create policy Readers",
		"create role Editor",
		"create role Reader",
		"create group Engineering",
		"create binding Engineering -> Editor",
		"create binding Engineering -> Reader",
	)
	// A plan writes nothing.
	configLines(t, "roles after plan", pluck(configObjects(t, configCall(f, f.iam.API.Roles.List, owner)), "name"), "Owner")
	applied := f.apply(owner, desired, false)
	if applied.Get("applied") != true {
		t.Fatalf("applied = %v", applied.Get("applied"))
	}
	configSameJSON(t, "applied summary", applied.Get("summary"), stringify(plan.Get("summary")))
	roles := configObjects(t, configCall(f, f.iam.API.Roles.List, owner))
	configLines(t, "roles", configSorted(pluck(roles, "name")), "Editor", "Owner", "Reader")
	var reader *core.Object
	for _, role := range roles {
		if role.Get("name") == "Reader" {
			reader = role
		}
	}
	var readers *core.Object
	for _, policy := range configObjects(t, configCall(f, f.iam.API.Policies.List, owner)) {
		if policy.Get("name") == "Readers" {
			readers = policy
		}
	}
	configSameJSON(t, "reader policies", reader.Get("policyIds"), stringify([]any{readers.Get("id")}))
	engineering := configObjects(t, configCall(f, f.iam.API.Groups.List, owner))[0]
	configLines(t, "members", pluck(configObjects(t, configCall(f, f.iam.API.Groups.ListMembers, owner, "groupId", engineering.Get("id"))), "email"), "alice@acme.test")
	eligible := configObjects(t, configCall(f, f.iam.API.Bindings.List, owner, "eligible", true))
	if len(eligible) != 1 || eligible[0].Get("subjectId") != engineering.Get("id") || eligible[0].Get("maxActivationMs") != 600000.0 || eligible[0].Get("requireJustification") != true {
		t.Fatalf("eligible bindings = %s", stringify(eligible))
	}
	resourceType := teamsObject(t, configCall(f, f.iam.API.ResourceTypes.Get, owner, "name", "project"))
	configLines(t, "resource type actions", configSorted(syncStringList(resourceType.Get("actions"))), "project:read", "project:write")
	// The trail records the apply with its summary.
	trail := configObjects(t, configCall(f, f.iam.API.Audit.List, owner, "action", "config:apply"))
	if len(trail) == 0 {
		t.Fatal("no config:apply audit event")
	}
	metadata, _ := trail[0].Get("metadata").(*core.Object)
	if metadata.Get("create") != 7.0 || metadata.Get("prune") != false {
		t.Fatalf("audit metadata = %s", stringify(metadata))
	}
	// Export round-trips, and applying the export changes nothing.
	exported := f.export(owner)
	configSameJSON(t, "export", exported, `{
      "version": 1,
      "resourceTypes": [
        { "name": "project", "description": "A project", "actions": ["read", "write"], "attributes": { "archived": "boolean" }, "relations": ["viewer"] }
      ],
      "policies": [{ "name": "Readers", "document": { "version": 1, "statements": [ { "effect": "allow", "actions": ["documents:read", "project:read"], "resources": ["*"] } ] } }],
      "roles": [
        { "name": "Editor", "policies": [], "permissions": ["documents:write", "project:write"] },
        { "name": "Reader", "description": "Reads", "policies": ["Readers"] }
      ],
      "groups": [{ "name": "Engineering", "members": ["alice@acme.test"] }],
      "bindings": [
        { "group": "Engineering", "role": "Editor", "eligible": true, "maxActivationMs": 600000, "requireJustification": true },
        { "group": "Engineering", "role": "Reader" }
      ],
      "packages": []
    }`)
	configSameJSON(t, "export apply", f.apply(owner, exported, false).Get("summary"), `{"create":0,"update":0,"delete":0,"unchanged":7}`)
	// Drift: change permissions and membership, drop the Reader role; prune decides about deletions.
	next := parse(t, `{
      "version": 1,
      "roles": [{ "name": "Editor", "permissions": ["documents:read", "documents:write", "project:write"] }],
      "groups": [{ "name": "Engineering", "members": ["alice@acme.test", "bob@acme.test"] }],
      "bindings": [{ "group": "Engineering", "role": "Editor" }]
    }`)
	keep := f.plan(owner, next, false)
	configSameJSON(t, "keep summary", keep.Get("summary"), `{"create":0,"update":3,"delete":0,"unchanged":0}`)
	for kind, fields := range map[string]string{
		"role":    `["document"]`,
		"group":   `["members"]`,
		"binding": `["eligible","maxActivationMs","requireJustification"]`,
	} {
		change := configChangeOf(keep, func(change *core.Object) bool { return change.Get("kind") == kind })
		if change == nil || change.Get("action") != "update" {
			t.Fatalf("%s change = %s", kind, stringify(change))
		}
		configSameJSON(t, kind+" fields", change.Get("fields"), fields)
	}
	pruned := f.plan(owner, next, true)
	configSameJSON(t, "pruned summary", pruned.Get("summary"), `{"create":0,"update":3,"delete":2,"unchanged":0}`)
	deletes := []string{}
	for _, change := range configObjectsOf(pruned.Get("changes")) {
		if change.Get("action") == "delete" {
			deletes = append(deletes, jsString(change.Get("kind"))+" "+jsString(change.Get("name")))
		}
	}
	configLines(t, "deletes", deletes, "role Reader", "binding Engineering -> Reader")
	result := f.apply(owner, next, true)
	configSameJSON(t, "prune apply summary", result.Get("summary"), stringify(pruned.Get("summary")))
	configLines(t, "roles after prune", configSorted(pluck(configObjects(t, configCall(f, f.iam.API.Roles.List, owner)), "name")), "Editor", "Owner")
	configLines(t, "members after prune", configSorted(pluck(configObjects(t, configCall(f, f.iam.API.Groups.ListMembers, owner, "groupId", engineering.Get("id"))), "email")), "alice@acme.test", "bob@acme.test")
	if eligible := configObjects(t, configCall(f, f.iam.API.Bindings.List, owner, "eligible", true)); len(eligible) != 0 {
		t.Fatalf("eligible bindings after prune = %s", stringify(eligible))
	}
	// Policies were not listed, so the policy survived; a later prune with policies: [] removes it.
	if !containsString(pluck(configObjects(t, configCall(f, f.iam.API.Policies.List, owner)), "name"), "Readers") {
		t.Fatal("Readers was pruned without being listed")
	}
	cleared := f.apply(owner, obj(t, `{"version":1,"policies":[]}`), true)
	configSameJSON(t, "cleared summary", cleared.Get("summary"), `{"create":0,"update":0,"delete":1,"unchanged":0}`)
	configLines(t, "policies after clear", pluck(configObjects(t, configCall(f, f.iam.API.Policies.List, owner)), "name"), "Owner")
	// A resource type whose actions a role still names cannot be pruned; nothing else is touched.
	if known := f.applyFails(owner, obj(t, `{"version":1,"resourceTypes":[],"groups":[]}`), true); known.Code != "RESOURCE_IN_USE" {
		t.Fatalf("expected RESOURCE_IN_USE, got %s: %s", known.Code, known.Message)
	}
	configLines(t, "groups after refused prune", pluck(configObjects(t, configCall(f, f.iam.API.Groups.List, owner)), "name"), "Engineering")
}

func TestConfigSyncRejectsMalformedConfigurationsAndAppliesAtomically(t *testing.T) {
	f := newConfigSyncFixture(t)
	owner := f.owner
	for _, document := range []string{
		`{"version":2}`,
		`{"version":1,"roles":[{"name":"A"},{"name":"A"}]}`,
		`{"version":1,"roles":[{"name":"A","policies":["Missing"]}]}`,
		`{"version":1,"groups":[{"name":"G","members":["nobody@acme.test"]}]}`,
		`{"version":1,"bindings":[{"group":"G","role":"R"}]}`,
		`{"version":1,"roles":[{"name":"A","permissions":["x"],"document":{"version":1,"statements":[]}}]}`,
	} {
		if known := f.planFails(owner, parse(t, document), false); known.Code != "INVALID_INPUT" {
			t.Fatalf("%s: expected INVALID_INPUT, got %s: %s", document, known.Code, known.Message)
		}
	}
	// Unknown actions are refused by the catalog, like a direct create.
	if known := f.applyFails(owner, obj(t, `{"version":1,"roles":[{"name":"A","permissions":["nope:read"]}]}`), false); known.Code != "INVALID_ACTION" {
		t.Fatalf("expected INVALID_ACTION, got %s: %s", known.Code, known.Message)
	}
	// Members without the config permissions are refused at the door.
	asAlice := f.login("alice")
	if known := f.planFails(asAlice, obj(t, `{"version":1}`), false); known.Code != "ACCESS_DENIED" {
		t.Fatalf("expected ACCESS_DENIED, got %s: %s", known.Code, known.Message)
	}
	// Holding iam:config:apply is not enough: each change needs the equivalent direct permission, and one refusal
	// rolls the whole apply back.
	operator := teamsObject(t, configCall(f, f.iam.API.Roles.Create, owner, "name", "Config operator",
		"permissions", []any{"iam:config:read", "iam:config:apply", "iam:groups:create"}))
	alice := configObjects(t, configCall(f, f.iam.API.Identities.List, owner, "query", "alice"))[0]
	configCall(f, f.iam.API.Bindings.Create, owner, "roleId", operator.Get("id"), "subjectType", "identity", "subjectId", alice.Get("id"))
	document := `{"version":1,"groups":[{"name":"Ops"}],"roles":[{"name":"X","permissions":["documents:read"]}]}`
	if created := member(f.plan(asAlice, parse(t, document), false).Get("summary"), "create"); created != 2.0 {
		t.Fatalf("operator plan creates %v", created)
	}
	if known := f.applyFails(asAlice, parse(t, document), false); known.Code != "ACCESS_DENIED" {
		t.Fatalf("expected ACCESS_DENIED, got %s: %s", known.Code, known.Message)
	}
	if groups := configObjects(t, configCall(f, f.iam.API.Groups.List, owner)); len(groups) != 0 {
		t.Fatalf("groups after refused apply = %s", stringify(groups))
	}
	// The HTTP route serves the group like any other.
	origin := "http://localhost:3000"
	payload, _ := json.Marshal(map[string]any{"tenantId": f.tenantID, "config": map[string]any{"version": 1, "groups": []any{map[string]any{"name": "Ops"}}}})
	request := configHTTPRequest(origin+"/api/iam/config/plan", string(payload), map[string]string{
		"content-type": "application/json", "x-better-iam": "1", "origin": origin, "authorization": "Bearer " + owner.Token,
	})
	response := f.iam.Handle(request)
	if response.Status != 200 {
		t.Fatalf("HTTP status %d: %s", response.Status, response.Body)
	}
	answer := teamsObject(t, parse(t, string(response.Body)))
	if created := member(member(answer.Get("data"), "summary"), "create"); created != 1.0 {
		t.Fatalf("HTTP plan = %s", response.Body)
	}
}

func TestConfigGovernanceInvariantsAndAgreementsByName(t *testing.T) {
	f := newConfigFixture(t, nil)
	owner := f.owner
	alice := f.member("alice")
	// A tenant without either kind exports neither key.
	empty := f.export(owner)
	if empty.Has("invariants") || empty.Has("agreements") {
		t.Fatalf("empty export = %s", stringify(empty))
	}
	document := obj(t, `{
      "version": 1,
      "groups": [{ "name": "Contractors", "members": ["alice@acme.test"] }],
      "agreements": [{ "name": "Acceptable use", "content": "Be nice.\nReally." }],
      "invariants": [
        { "name": "Contractors never write d1", "subject": { "group": "Contractors" }, "action": "documents:write", "resource": { "type": "document", "id": "d1" }, "expect": "deny", "mode": "enforce" },
        { "name": "Alice reads nothing", "subject": { "identity": "ALICE@acme.test" }, "action": "documents:read", "resource": { "type": "document", "id": "d1" }, "expect": "deny" }
      ]
    }`)
	plan := f.plan(owner, document, false)
	configLines(t, "changes", configChangeLines(plan),
		"create group Contractors",
		"create agreement Acceptable use",
		"create invariant Alice reads nothing",
		"create invariant Contractors never write d1",
	)
	f.apply(owner, document, false)
	invariants := configObjects(t, configCall(f, f.iam.API.Invariants.List, owner))
	modes := []string{}
	for _, invariant := range invariants {
		modes = append(modes, jsString(invariant.Get("name"))+":"+jsString(invariant.Get("mode")))
	}
	configLines(t, "invariants", modes, "Alice reads nothing:monitor", "Contractors never write d1:enforce")
	configSameJSON(t, "subject", invariants[0].Get("subject"), stringify(core.NewObject("identityId", alice.Get("id"))))
	// The applied invariant is enforced right away.
	writer := teamsObject(t, configCall(f, f.iam.API.Roles.Create, owner, "name", "Writer", "permissions", []any{"documents:write"}))
	_, err := f.iam.API.Bindings.Create(f.ctx, owner, Input[apitypes.BindingsCreateInput](core.NewObject(
		"tenantId", f.tenantID, "roleId", writer.Get("id"), "subjectType", "identity", "subjectId", alice.Get("id"))))
	if known := configFailure(t, err); known.Code != "INVARIANT_VIOLATION" {
		t.Fatalf("expected INVARIANT_VIOLATION, got %s: %s", known.Code, known.Message)
	}
	// Round trip: the export applies with no changes.
	exported := f.export(owner)
	found := false
	for _, invariant := range configObjectsOf(exported.Get("invariants")) {
		if syncSame(invariant, parse(t, `{"name":"Contractors never write d1","subject":{"group":"Contractors"},"action":"documents:write","resource":{"type":"document","id":"d1"},"expect":"deny","mode":"enforce","assumeMfa":true}`)) {
			found = true
		}
	}
	if !found {
		t.Fatalf("exported invariants = %s", stringify(exported.Get("invariants")))
	}
	configSameJSON(t, "exported agreements", exported.Get("agreements"), `[{"name":"Acceptable use","content":"Be nice.\nReally.","required":true}]`)
	again := f.plan(owner, exported, false)
	for _, key := range []string{"create", "update", "delete"} {
		if member(again.Get("summary"), key) != 0.0 {
			t.Fatalf("round trip summary = %s", stringify(again.Get("summary")))
		}
	}
	// A content change publishes a new version; a URL change does not.
	agreement := configObjects(t, configCall(f, f.iam.API.Agreements.List, owner))[0]
	f.apply(owner, obj(t, `{"version":1,"agreements":[{"name":"Acceptable use","content":"Be nice.\nReally.","url":"https://acme.test/aup"}]}`), false)
	if version := configObjects(t, configCall(f, f.iam.API.Agreements.List, owner))[0].Get("version"); version != agreement.Get("version") {
		t.Fatalf("a URL change published version %v", version)
	}
	edit := obj(t, `{"version":1,"agreements":[{"name":"Acceptable use","content":"Be kind."}]}`)
	edited := f.plan(owner, edit, false)
	first := configObjectsOf(edited.Get("changes"))[0]
	if first.Get("kind") != "agreement" || first.Get("action") != "update" {
		t.Fatalf("edit change = %s", stringify(first))
	}
	configSameJSON(t, "edit fields", first.Get("fields"), `["content","url"]`)
	f.apply(owner, edit, false)
	current := configObjects(t, configCall(f, f.iam.API.Agreements.List, owner))[0]
	if current.Get("version") != jsNumber(agreement.Get("version"))+1 || current.Get("content") != "Be kind." || current.Has("url") {
		t.Fatalf("agreement after edit = %s", stringify(current))
	}
	// Invariant updates and pruning.
	monitored := configObjectsOf(document.Get("invariants"))[0].Spread(core.NewObject("mode", "monitor"))
	f.apply(owner, core.NewObject("version", 1, "invariants", []any{monitored}, "agreements", []any{}), true)
	modes = []string{}
	for _, invariant := range configObjects(t, configCall(f, f.iam.API.Invariants.List, owner)) {
		modes = append(modes, jsString(invariant.Get("name"))+":"+jsString(invariant.Get("mode")))
	}
	configLines(t, "invariants after prune", modes, "Contractors never write d1:monitor")
	if agreements := configObjects(t, configCall(f, f.iam.API.Agreements.List, owner)); len(agreements) != 0 {
		t.Fatalf("agreements after prune = %s", stringify(agreements))
	}
	// References are checked while planning.
	nobody := configObjectsOf(document.Get("invariants"))[0].Spread(core.NewObject("subject", core.NewObject("group", "Nobody")))
	ghost := configObjectsOf(document.Get("invariants"))[1].Spread(core.NewObject("subject", core.NewObject("identity", "ghost@acme.test")))
	for _, config := range []*core.Object{
		core.NewObject("version", 1, "invariants", []any{nobody}),
		core.NewObject("version", 1, "invariants", []any{ghost}),
		obj(t, `{"version":1,"agreements":[{"name":"A","content":"x"},{"name":"a","content":"y"}]}`),
	} {
		if known := f.planFails(owner, config, false); known.Code != "INVALID_INPUT" {
			t.Fatalf("expected INVALID_INPUT, got %s: %s", known.Code, known.Message)
		}
	}
}

// seedRecords inserts raw records in one transaction.
func (f *configFixture) seedRecords(collection string, records ...*core.Object) {
	f.t.Helper()
	if _, err := core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (any, error) {
		for _, record := range records {
			if _, err := tx.Insert(ctx, collection, record); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *configFixture) records(collection string, filter *core.Object) []*core.Object {
	f.t.Helper()
	found, err := f.store.Find(f.ctx, collection, filter, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return found
}

func TestConfigSyncBindsTheConfiguredGroupNotADirectoryGroupThatTookItsName(t *testing.T) {
	f := newConfigFixture(t, nil)
	owner := f.ownerSignIn()
	configCall(f, f.iam.API.Roles.Create, owner, "name", "Writer", "permissions", []any{"documents:write"})
	admins := teamsObject(t, configCall(f, f.iam.API.Groups.Create, owner, "name", "Admins"))
	// An identity provider pushes its own "Admins" group through SCIM.
	planted := ID()
	f.seedRecords("groups", core.NewObject("id", planted, "tenantId", f.tenantID, "name", "Admins", "createdAt", 1))
	f.seedRecords("scimGroups", core.NewObject("id", ID(), "tenantId", f.tenantID, "connectionId", "idp", "groupId", planted,
		"displayName", "Admins", "members", []any{}, "version", 1, "createdAt", 1, "updatedAt", 1))
	f.apply(owner, obj(t, `{
      "version": 1,
      "roles": [{ "name": "Writer", "permissions": ["documents:write"] }],
      "groups": [{ "name": "Admins" }],
      "bindings": [{ "group": "Admins", "role": "Writer" }]
    }`), false)
	bound := f.records("bindings", core.NewObject("tenantId", f.tenantID, "subjectType", "group"))
	configLines(t, "bound groups", pluck(bound, "subjectId"), jsString(admins.Get("id")))
}

func TestConfigSyncKeepsTeamApproverAndTemporaryDatesOnReplacement(t *testing.T) {
	f := newConfigFixture(t, nil)
	owner := f.ownerSignIn()
	writer := teamsObject(t, configCall(f, f.iam.API.Roles.Create, owner, "name", "Writer", "permissions", []any{"documents:write"}))
	oncall := teamsObject(t, configCall(f, f.iam.API.Groups.Create, owner, "name", "On-call"))
	// A team's backing group, which configuration never exports or manages.
	teamGroup := ID()
	f.seedRecords("groups", core.NewObject("id", teamGroup, "tenantId", f.tenantID, "name", "Team: Payments", "teamId", "team-payments", "createdAt", 1))
	expiresAt := float64(f.clock.Load()) + 30*86400000
	original := teamsObject(t, configCall(f, f.iam.API.Bindings.Create, owner, "roleId", writer.Get("id"), "subjectType", "group",
		"subjectId", oncall.Get("id"), "eligible", true, "requireApproval", true, "approverGroupId", teamGroup, "expiresAt", expiresAt))
	f.apply(owner, obj(t, `{
      "version": 1,
      "roles": [{ "name": "Writer", "permissions": ["documents:write"] }],
      "groups": [{ "name": "On-call" }],
      "bindings": [{ "group": "On-call", "role": "Writer", "eligible": true, "requireApproval": true, "requireJustification": true }]
    }`), false)
	replaced := f.records("bindings", core.NewObject("tenantId", f.tenantID, "subjectType", "group", "subjectId", oncall.Get("id")))
	if len(replaced) != 1 || replaced[0].Get("id") == original.Get("id") {
		t.Fatalf("bindings after apply = %s", stringify(replaced))
	}
	if replaced[0].Get("requireJustification") != true || replaced[0].Get("approverGroupId") != teamGroup || replaced[0].Get("expiresAt") != expiresAt {
		t.Fatalf("replacement = %s", stringify(replaced[0]))
	}
}

func TestConfigSyncNullBindingMaxActivationIsNoCap(t *testing.T) {
	f := newConfigFixture(t, nil)
	owner := f.owner
	reader := teamsObject(t, configCall(f, f.iam.API.Roles.Create, owner, "name", "Reader", "permissions", []any{"documents:read"}))
	configCall(f, f.iam.API.Groups.Create, owner, "name", "Engineering")
	ops := teamsObject(t, configCall(f, f.iam.API.Groups.Create, owner, "name", "Ops"))
	configCall(f, f.iam.API.Bindings.Create, owner, "roleId", reader.Get("id"), "subjectType", "group", "subjectId", ops.Get("id"),
		"eligible", true, "maxActivationMs", 600_000)
	config := obj(t, `{"version":1,"bindings":[
      { "group": "Engineering", "role": "Reader", "eligible": true, "maxActivationMs": null },
      { "group": "Ops", "role": "Reader", "eligible": true, "maxActivationMs": null }
    ]}`)
	plan := f.plan(owner, config, false)
	configSameJSON(t, "summary", plan.Get("summary"), `{"create":1,"update":1,"delete":0,"unchanged":0}`)
	bindings := []*core.Object{}
	for _, change := range configObjectsOf(plan.Get("changes")) {
		if change.Get("kind") == "binding" {
			bindings = append(bindings, change)
		}
	}
	if len(bindings) != 2 || bindings[0].Get("name") != "Engineering -> Reader" || bindings[0].Get("action") != "create" ||
		bindings[1].Get("name") != "Ops -> Reader" || bindings[1].Get("action") != "update" {
		t.Fatalf("binding changes = %s", stringify(bindings))
	}
	configSameJSON(t, "fields", bindings[1].Get("fields"), `["maxActivationMs"]`)
	f.apply(owner, config, false)
	stored := f.records("bindings", core.NewObject("tenantId", f.tenantID, "subjectType", "group"))
	if len(stored) != 2 {
		t.Fatalf("stored = %s", stringify(stored))
	}
	for _, binding := range stored {
		if binding.Get("eligible") != true || binding.Has("maxActivationMs") {
			t.Fatalf("binding = %s", stringify(binding))
		}
	}
	// Repeated applies are no-ops: the bindings are not replaced.
	for round := 0; round < 2; round++ {
		configSameJSON(t, "again", f.apply(owner, config, false).Get("summary"), `{"create":0,"update":0,"delete":0,"unchanged":2}`)
	}
	configLines(t, "binding ids", configSorted(pluck(f.records("bindings", core.NewObject("tenantId", f.tenantID, "subjectType", "group")), "id")),
		configSorted(pluck(stored, "id"))...)
	// Strings and out-of-range values are refused before anything is planned.
	for _, value := range []any{"600000", 59_999, 0, 1.5, 7*86400000 + 1, false, []any{}} {
		bad := core.NewObject("version", 1, "bindings", []any{core.NewObject("group", "Ops", "role", "Reader", "eligible", true, "maxActivationMs", value)})
		known := f.planFails(owner, bad, false)
		if known.Code != "INVALID_INPUT" || !strings.Contains(known.Message, "maxActivationMs") {
			t.Fatalf("plan %v: %s %s", value, known.Code, known.Message)
		}
		if known := f.applyFails(owner, bad, false); known.Code != "INVALID_INPUT" {
			t.Fatalf("apply %v: %s %s", value, known.Code, known.Message)
		}
	}
	week := f.plan(owner, obj(t, `{"version":1,"bindings":[{"group":"Ops","role":"Reader","eligible":true,"maxActivationMs":604800000}]}`), false)
	if member(week.Get("summary"), "update") != 1.0 {
		t.Fatalf("week plan = %s", stringify(week.Get("summary")))
	}
}

func TestConfigSyncRejectsPackageNamesThatDifferOnlyByCase(t *testing.T) {
	f := newConfigFixture(t, nil)
	owner := f.owner
	reader := teamsObject(t, configCall(f, f.iam.API.Roles.Create, owner, "name", "Reader", "permissions", []any{"documents:read"}))
	configCall(f, f.iam.API.Packages.Create, owner, "name", "Kit", "roleIds", []any{reader.Get("id")})
	config := obj(t, `{"version":1,"packages":[{"name":"Vendor","roles":["Reader"]},{"name":"vendor","roles":["Reader"]}]}`)
	known := f.planFails(owner, config, false)
	if known.Code != "INVALID_INPUT" || !strings.Contains(strings.ToLower(known.Message), "duplicate package") {
		t.Fatalf("plan: %s %s", known.Code, known.Message)
	}
	if known := f.planFails(owner, config, true); known.Code != "INVALID_INPUT" {
		t.Fatalf("plan with prune: %s %s", known.Code, known.Message)
	}
	if known := f.applyFails(owner, config, false); known.Code != "INVALID_INPUT" {
		t.Fatalf("apply: %s %s", known.Code, known.Message)
	}
	configLines(t, "packages", pluck(configObjects(t, configCall(f, f.iam.API.Packages.List, owner)), "name"), "Kit")
}

func TestValidateTenantConfigShapes(t *testing.T) {
	for document, message := range map[string]string{
		`{"version":1,"roles":{}}`:                                                     "roles must be an array of at most 1000 items",
		`{"version":1,"roles":[1]}`:                                                    "Expected an object",
		`{"version":1,"groups":[{"name":"G"},{"name":"G"}]}`:                           "Duplicate group G",
		`{"version":1,"bindings":[{"group":"G","role":"R"},{"group":"G","role":"R"}]}`: "Duplicate binding G -> R",
		`{"version":1,"bindings":[{"group":"G","role":"R","eligible":"yes"}]}`:         "eligible must be boolean",
		`{"version":1,"invariants":[{"name":"I","subject":{},"action":"a","resource":{"type":"t","id":"i"},"expect":"deny"}]}`:                                                                                                                             "Invariant I: subject must be one of everyone, group, identity, or attribute",
		`{"version":1,"invariants":[{"name":"I","subject":{"everyone":true},"action":"a","resource":{"type":"t","id":"i"},"expect":"maybe"}]}`:                                                                                                             "Invariant I: expect must be allow or deny",
		`{"version":1,"invariants":[{"name":"Same","subject":{"everyone":true},"action":"a","resource":{"type":"t","id":"i"},"expect":"deny"},{"name":"same","subject":{"everyone":true},"action":"a","resource":{"type":"t","id":"i"},"expect":"deny"}]}`: "Duplicate invariant same",
		`{"version":1,"agreements":[{"name":"A","content":"  "}]}`:                                     "Agreement A: content is required",
		`{"version":1,"teams":[{"name":"T","maintainers":["a@acme.test"],"members":["A@acme.test"]}]}`: "Team t: a@acme.test is listed as both maintainer and member",
		`{"version":1,"teams":[{"name":"!!!"}]}`:                                                       "Team !!!: choose a slug",
		`{"version":1,"teams":[{"name":"T","joinPolicy":"open"}]}`:                                     "Team t: joinPolicy must be closed or request",
		`{"version":1,"teams":[{"name":"One","slug":"x"},{"name":"Two","slug":"x"}]}`:                  "Duplicate team x",
		`{"version":1,"departments":[{"name":"Eng"},{"name":" eng "}]}`:                                "Duplicate department eng",
		`{"version":1,"departments":[{"name":"A","code":"X"},{"name":"B","code":"x"}]}`:                "Duplicate department code x",
	} {
		_, err := ValidateTenantConfig(parse(t, document))
		expectError(t, err, "INVALID_INPUT", message)
	}
	config, err := ValidateTenantConfig(parse(t, `{"version":1,"groups":[{"name":"G","members":[" Alice@Acme.TEST "]}],"teams":[{"name":"Site Reliability","maintainers":["B@acme.test","b@acme.test"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	configSameJSON(t, "group members", member(syncObjectsFirst(config.Get("groups")), "members"), `["alice@acme.test"]`)
	team := syncObjectsFirst(config.Get("teams"))
	if team.Get("slug") != "site-reliability" {
		t.Fatalf("team = %s", stringify(team))
	}
	configSameJSON(t, "maintainers", team.Get("maintainers"), `["b@acme.test"]`)
}

func syncObjectsFirst(value any) *core.Object {
	list := configObjectsOf(value)
	if len(list) == 0 {
		return nil
	}
	return list[0]
}

// configHTTPRequest is a POST request with a body and headers.
func configHTTPRequest(url, body string, headers map[string]string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	return request
}
