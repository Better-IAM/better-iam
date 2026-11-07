package server

// Tests of workflows.go and api_workflows.go: unit tests of the pure trigger, step, scope and template functions, and
// ports of tests/workflows.test.ts (lifecycle workflows, workflow review fixes). People are created through the auth
// service (identities.create waits on package automation), and identity changes made through the API tolerate the
// post-commit package-automation hook while that unit is a stub (the change itself is committed before it runs).
// Steps that reach another unit's stub (packages.allow, package automation, threats containment, package rules) end
// the run with NOT_IMPLEMENTED, which skips the rest of the test until that unit is ported.

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// --- pure functions ----------------------------------------------------------------------------------------------------

func workflowTestAttributes() *core.Object {
	return core.NewObject("department", "string", "startDate", "string", "title", "string", "level", "number")
}

func TestWorkflowsParseTrigger(t *testing.T) {
	attributes := workflowTestAttributes()
	for _, kind := range []string{"joiner", "leaver", "manual"} {
		trigger := must(ParseTrigger(obj(t, `{"kind":"`+kind+`","extra":1}`), attributes))
		if core.MustStringify(trigger) != `{"kind":"`+kind+`"}` {
			t.Fatalf("%s parsed as %s", kind, core.MustStringify(trigger))
		}
	}
	mover := must(ParseTrigger(obj(t, `{"kind":"mover","attributes":["title","managerId","department","title"]}`), attributes))
	if got := core.MustStringify(mover); got != `{"kind":"mover","attributes":["department","managerId","title"]}` {
		t.Fatalf("mover parsed as %s", got)
	}
	_, err := ParseTrigger(obj(t, `{"kind":"mover","attributes":[]}`), attributes)
	expectError(t, err, "INVALID_INPUT", "trigger.attributes must name 1-20 attributes to watch")
	_, err = ParseTrigger(obj(t, `{"kind":"mover","attributes":["shoeSize"]}`), attributes)
	expectError(t, err, "INVALID_INPUT", "trigger.attributes: shoeSize is not a declared identity attribute (or managerId)")
	_, err = ParseTrigger(obj(t, `{"kind":"mover","attributes":[1]}`), attributes)
	expectError(t, err, "INVALID_INPUT", "Invalid trigger.attributes")
	date := must(ParseTrigger(obj(t, `{"kind":"date","attribute":"startDate"}`), attributes))
	if got := core.MustStringify(date); got != `{"kind":"date","attribute":"startDate","offsetDays":0}` {
		t.Fatalf("date parsed as %s", got)
	}
	_, err = ParseTrigger(obj(t, `{"kind":"date","attribute":"level"}`), attributes)
	expectError(t, err, "INVALID_INPUT", "trigger.attribute must be createdAt, expiresAt, or a declared string attribute holding an ISO date")
	_, err = ParseTrigger(obj(t, `{"kind":"date","attribute":"title","offsetDays":400000}`), attributes)
	expectError(t, err, "INVALID_INPUT", "Invalid trigger.offsetDays")
	_, err = ParseTrigger(obj(t, `{"kind":"hourly"}`), attributes)
	expectError(t, err, "INVALID_INPUT", "trigger.kind must be joiner, mover, leaver, date or manual")
	_, err = ParseTrigger("joiner", attributes)
	expectError(t, err, "INVALID_INPUT", "Expected an object")
}

func TestWorkflowsParseSteps(t *testing.T) {
	attributes := workflowTestAttributes()
	steps := must(WorkflowsParseSteps(parse(t, `[
		{"kind":"add-to-group","groupId":"g1","days":30},
		{"kind":"remove-from-group","groupId":"g2"},
		{"kind":"assign-package","packageId":"p1"},
		{"kind":"revoke-packages"},
		{"kind":"send-email","to":" HR@Acme.test ","subject":"Hi {name}","body":"Welcome"},
		{"kind":"set-attributes","attributes":{"department":"Sales","level":3,"title":null}},
		{"kind":"set-expiry","days":null},
		{"kind":"wait","hours":2},
		{"kind":"emit-event","name":"person.moved"},
		{"kind":"delete"}
	]`), attributes))
	got := make([]string, len(steps))
	for index, step := range steps {
		got[index] = core.MustStringify(step)
	}
	want := []string{
		`{"kind":"add-to-group","groupId":"g1","days":30}`,
		`{"kind":"remove-from-group","groupId":"g2"}`,
		`{"kind":"assign-package","packageId":"p1"}`,
		`{"kind":"revoke-packages"}`,
		`{"kind":"send-email","to":"hr@acme.test","subject":"Hi {name}","body":"Welcome"}`,
		`{"kind":"set-attributes","attributes":{"department":"Sales","level":3,"title":null}}`,
		`{"kind":"set-expiry","days":null}`,
		`{"kind":"wait","hours":2}`,
		`{"kind":"emit-event","name":"person.moved"}`,
		`{"kind":"delete"}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("steps parsed as\n%s", strings.Join(got, "\n"))
	}
	if brake := must(DefaultBrake(steps)); brake != 25 {
		t.Fatalf("destructive brake %v", brake)
	}
	if brake := must(DefaultBrake(steps[:3])); brake != 200 {
		t.Fatalf("default brake %v", brake)
	}
	cases := []struct{ steps, message string }{
		{`[]`, "steps must list 1-20 steps"},
		{`"x"`, "steps must list 1-20 steps"},
		{`[1]`, "steps[0] must be an object"},
		{`[{"kind":"disable","why":1}]`, "steps[0]: unknown field why"},
		{`[{"kind":"teleport"}]`, "steps[0].kind must be one of add-to-group, remove-from-group, remove-from-all-groups, assign-package, revoke-packages, send-email, revoke-sessions, disable, enable, set-attributes, set-expiry, delete, emit-event, wait"},
		{`[{"kind":"add-to-group","groupId":"g","days":0}]`, "Invalid steps[0].days"},
		{`[{"kind":"send-email","to":"nobody","subject":"s","body":"b"}]`, "steps[0].to must be subject, manager, or an email address"},
		{`[{"kind":"send-email","to":"manager","subject":"s","body":"   "}]`, "steps[0].body must be text of at most 5000 characters"},
		{`[{"kind":"send-email","to":"manager","subject":"s","body":"a\u0007b"}]`, "steps[0].body must be text of at most 5000 characters"},
		{`[{"kind":"set-attributes","attributes":{}}]`, "steps[0].attributes must set at least one attribute"},
		{`[{"kind":"set-attributes","attributes":{"shoe":"x"}}]`, "steps[0].attributes: shoe is not a declared identity attribute"},
		{`[{"kind":"set-attributes","attributes":{"level":"high"}}]`, "steps[0].attributes: level must be a number (or null to clear it)"},
		{`[{"kind":"emit-event","name":"Bad Name"}]`, "steps[0].name uses lowercase letters, digits, dots, underscores or hyphens"},
		{`[{"kind":"wait","hours":0}]`, "Invalid steps[0].hours"},
		{`[{"kind":"wait","hours":2}]`, "A workflow needs at least one step that does something"},
		{`[{"kind":"disable"},{"kind":"wait","hours":2}]`, "A workflow cannot end with a wait"},
		{`[{"kind":"delete"},{"kind":"emit-event","name":"after"}]`, "delete must be the last step"},
		{`[{"kind":"wait","hours":1},{"kind":"wait","hours":1},{"kind":"wait","hours":1},{"kind":"wait","hours":1},{"kind":"wait","hours":1},{"kind":"wait","hours":1},{"kind":"disable"}]`, "A workflow may wait at most 5 times"},
	}
	for _, item := range cases {
		_, err := WorkflowsParseSteps(parse(t, item.steps), attributes)
		expectError(t, err, "INVALID_INPUT", item.message)
	}
}

func TestWorkflowsParseScopeShapes(t *testing.T) {
	if scope, err := ParseScope(nil, core.NewObject()); err != nil || scope != nil {
		t.Fatalf("null scope: %v %v", scope, err)
	}
	if scope, err := ParseScope(core.Undefined, core.NewObject()); err != nil || scope != nil {
		t.Fatalf("absent scope: %v %v", scope, err)
	}
	_, err := ParseScope([]any{}, core.NewObject())
	expectError(t, err, "INVALID_INPUT", "scope must be an object")
	_, err = ParseScope(obj(t, `{"include":[],"when":1}`), core.NewObject())
	expectError(t, err, "INVALID_INPUT", "scope: unknown field when (use include and exclude)")
}

func TestWorkflowsTriggerOccurrence(t *testing.T) {
	now := int64(1_767_225_600_000)
	person := obj(t, `{"id":"p1","kind":"user","status":"active","createdAt":1767225500000,"managerId":"m1","attributes":{"department":"Engineering"}}`)
	joiner := obj(t, `{"trigger":{"kind":"joiner"},"activeSince":1767225400000,"includeExisting":false}`)
	if got := core.MustStringify(must(TriggerOccurrence(joiner, person, nil, now))); got != `{"occurrence":"joiner"}` {
		t.Fatalf("joiner: %s", got)
	}
	joiner.Set("activeSince", 1767225550000.0)
	if got := core.MustStringify(must(TriggerOccurrence(joiner, person, nil, now))); got != `{}` {
		t.Fatalf("joiner before the workflow: %s", got)
	}
	joiner.Set("includeExisting", true)
	if got := core.MustStringify(must(TriggerOccurrence(joiner, person, nil, now))); got != `{"occurrence":"joiner"}` {
		t.Fatalf("existing joiner: %s", got)
	}

	mover := obj(t, `{"trigger":{"kind":"mover","attributes":["department","managerId","title"]},"activeSince":0}`)
	first := must(TriggerOccurrence(mover, person, nil, now))
	if got := core.MustStringify(first); got != `{"snapshot":{"values":{"department":"Engineering","managerId":"m1","title":null},"status":"active","fired":0}}` {
		t.Fatalf("mover baseline: %s", got)
	}
	snapshot := first.Get("snapshot").(*core.Object)
	if got := core.MustStringify(must(TriggerOccurrence(mover, person, snapshot, now))); got != `{}` {
		t.Fatalf("mover without change: %s", got)
	}
	moved := person.Clone()
	moved.Get("attributes").(*core.Object).Set("department", "Sales")
	fired := must(TriggerOccurrence(mover, moved, snapshot, now))
	occurrence := jsString(fired.Get("occurrence"))
	expected := "mover:1:" + workflowDigest(obj(t, `{"department":"Sales","managerId":"m1","title":null}`))
	if occurrence != expected || len(occurrence) != len("mover:1:")+16 {
		t.Fatalf("mover occurrence %q, want %q", occurrence, expected)
	}
	if got := core.MustStringify(member(fired, "snapshot")); !strings.Contains(got, `"fired":1`) {
		t.Fatalf("mover snapshot %s", got)
	}
	disabledMover := moved.Clone()
	disabledMover.Set("status", "disabled")
	if got := must(TriggerOccurrence(mover, disabledMover, snapshot, now)); got.Has("occurrence") || !got.Has("snapshot") {
		t.Fatalf("a disabled mover keeps its baseline without firing: %s", core.MustStringify(got))
	}

	leaver := obj(t, `{"trigger":{"kind":"leaver"},"activeSince":0}`)
	base := must(TriggerOccurrence(leaver, person, nil, now)).Get("snapshot").(*core.Object)
	disabled := person.Spread(core.NewObject("status", "disabled"))
	left := must(TriggerOccurrence(leaver, disabled, base, now))
	if got := core.MustStringify(left); got != `{"occurrence":"leaver:1","snapshot":{"values":{},"status":"disabled","fired":1}}` {
		t.Fatalf("leaver: %s", got)
	}
	back := must(TriggerOccurrence(leaver, person, left.Get("snapshot").(*core.Object), now))
	if got := core.MustStringify(back); got != `{"snapshot":{"values":{},"status":"active","fired":1}}` {
		t.Fatalf("re-enabled: %s", got)
	}

	dated := person.Spread(core.NewObject("attributes", core.NewObject("startDate", "2026-01-05")))
	date := obj(t, `{"trigger":{"kind":"date","attribute":"startDate","offsetDays":-7},"activeSince":1766966400000}`)
	target := must(DateTarget(date.Get("trigger").(*core.Object), dated))
	if target == nil || *target != 1767571200000-7*WorkflowsDayMs {
		t.Fatalf("date target %v", target)
	}
	if got := core.MustStringify(must(TriggerOccurrence(date, dated, nil, now))); got != `{"occurrence":"date:2025-12-29"}` {
		t.Fatalf("date occurrence: %s", got)
	}
	if got := core.MustStringify(must(TriggerOccurrence(date, dated, nil, now-4*WorkflowsDayMs))); got != `{}` {
		t.Fatalf("a date ahead does not fire: %s", got)
	}
	old := date.Spread(core.NewObject("activeSince", 1766966400000.0+2*WorkflowsDayMs))
	if got := core.MustStringify(must(TriggerOccurrence(old, dated, nil, now))); got != `{}` {
		t.Fatalf("a date before the workflow existed does not fire: %s", got)
	}
	manual := obj(t, `{"trigger":{"kind":"manual"}}`)
	if got := core.MustStringify(must(TriggerOccurrence(manual, person, nil, now))); got != `{}` {
		t.Fatalf("manual: %s", got)
	}
}

func TestWorkflowsDateTarget(t *testing.T) {
	trigger := obj(t, `{"kind":"date","attribute":"startDate","offsetDays":1}`)
	at := func(value any) *float64 {
		identity := core.NewObject("attributes", core.NewObject("startDate", value))
		return must(DateTarget(trigger, identity))
	}
	cases := map[string]float64{
		"2024-01-01":                     1704067200000,
		"2024-01-01T10:00Z":              1704103200000,
		"2024-01-01T10:00:00.123456789Z": 1704103200123,
		"2024-01-01T10:00:00+02:00":      1704096000000,
		"2024-02-30T00:00:00Z":           1709251200000,
		"2024-01-01T24:00Z":              1704153600000,
	}
	for raw, base := range cases {
		target := at(raw)
		if target == nil || *target != base+WorkflowsDayMs {
			t.Fatalf("%s: target %v, want %v", raw, target, base+WorkflowsDayMs)
		}
	}
	for _, raw := range []any{"2024-01-01T10:00", "2024-13-01", "2024-01-00", "2024-01-01T24:01Z", "2024-01-01T10:00+24:00", "soon", 1704067200000.0} {
		if target := at(raw); target != nil {
			t.Fatalf("%v: unexpected target %v", raw, *target)
		}
	}
	created := must(DateTarget(obj(t, `{"kind":"date","attribute":"createdAt","offsetDays":-1}`), obj(t, `{"createdAt":172800000}`)))
	if created == nil || *created != 86400000 {
		t.Fatalf("createdAt target %v", created)
	}
	if expires := must(DateTarget(obj(t, `{"kind":"date","attribute":"expiresAt","offsetDays":0}`), obj(t, `{}`))); expires != nil {
		t.Fatalf("no expiresAt: %v", *expires)
	}
	if day := must(UtcDay(1704067199999)); day != "2023-12-31" {
		t.Fatalf("utcDay %s", day)
	}
}

func TestWorkflowsFillTemplate(t *testing.T) {
	values := core.NewObject(
		"identity", obj(t, `{"name":"alice","email":"alice@acme.test","attributes":{"department":"Engineering","level":3,"none":null}}`),
		"organization", "Acme",
		"workflow", "Joiners",
	)
	got := must(FillTemplate("{name} <{email}> joined {organization} via {workflow}: {attribute.department}/{attribute.level}/{attribute.none}/{attribute.missing} {unknown} {1bad}", values))
	if got != "alice <alice@acme.test> joined Acme via Joiners: Engineering/3// {unknown} {1bad}" {
		t.Fatalf("filled %q", got)
	}
	noEmail := core.NewObject("identity", obj(t, `{"name":"bob"}`), "organization", "Acme", "workflow", "W")
	if got := must(FillTemplate("[{email}] {attribute.department}", noEmail)); got != "[] " {
		t.Fatalf("filled %q", got)
	}
}

// --- tests/workflows.test.ts -------------------------------------------------------------------------------------------

const workflowDay = 86_400_000

type workflowFixture struct {
	*orgFixture
	engineering *core.Object
	everyone    *core.Object
}

func newWorkflowFixture(t *testing.T) *workflowFixture {
	t.Helper()
	base := newOrgFixture(t, func(options *BetterIamOptions) {
		options.Permissions.IdentityAttributes = []core.NamedAttribute{
			{Name: "department", Type: "string"}, {Name: "startDate", Type: "string"}, {Name: "title", Type: "string"},
		}
	})
	f := &workflowFixture{orgFixture: base}
	f.engineering = f.createGroup("Engineering")
	f.everyone = f.createGroup("Everyone")
	return f
}

func (f *workflowFixture) body(members ...any) *core.Object {
	body := core.NewObject("tenantId", f.tenantID)
	body.Assign(core.NewObject(members...))
	return body
}

// person creates `{name}@acme.test` with a password through the auth service and gives them attributes
// (organizationFixture member and identities.update).
func (f *workflowFixture) person(name string, attributes ...any) *core.Object {
	f.t.Helper()
	identity, err := core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: f.tenantID, Email: name + "@acme.test", Name: name, Password: "a strong " + name + " password", HasPassword: true,
		})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if len(attributes) > 0 {
		f.updateIdentity(identity.Get("id"), core.NewObject(attributes...))
	}
	return f.record("identities", jsString(identity.Get("id")))
}

// afterChange accepts an identities mutation whose only failure is the package-automation hook it runs after
// committing (a stub until that unit is ported).
func (f *workflowFixture) afterChange(err error) {
	f.t.Helper()
	if err == nil {
		return
	}
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" && strings.Contains(known.Message, "afterIdentityChange") {
		return
	}
	requirePorted(f.t, err)
}

func (f *workflowFixture) updateIdentity(identityID any, attributes *core.Object) {
	f.t.Helper()
	_, err := f.iam.API.Identities.Update(f.ctx, f.owner, Input[apitypes.IdentitiesUpdateInput](f.body("identityId", identityID, "attributes", attributes)))
	f.afterChange(err)
}

func (f *workflowFixture) groupsOf(identityID any) []string {
	f.t.Helper()
	groups := f.items(f.iam.API.Identities.ListGroups(f.ctx, f.owner, Input[apitypes.IdentitiesListGroupsInput](f.body("identityId", identityID))))
	names := []string{}
	for _, group := range groups {
		names = append(names, jsString(group.Get("name")))
	}
	sort.Strings(names)
	return names
}

func (f *workflowFixture) expectGroups(identityID any, want ...string) {
	f.t.Helper()
	got := f.groupsOf(identityID)
	if want == nil {
		want = []string{}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		f.t.Fatalf("groups %v, want %v", got, want)
	}
}

// blocked skips the rest of the test when a run ended at another unit's stub.
func (f *workflowFixture) blocked() {
	f.t.Helper()
	for _, run := range f.find("workflowRuns", core.NewObject("tenantId", f.tenantID)) {
		if member(run.Get("error"), "code") == "NOT_IMPLEMENTED" {
			f.t.Skipf("blocked by another unit: %s", jsString(member(run.Get("error"), "message")))
		}
	}
}

func (f *workflowFixture) create(credential core.CredentialInput, members ...any) (*core.Object, error) {
	answer, err := f.iam.API.Workflows.Create(f.ctx, credential, Input[apitypes.WorkflowsCreateInput](f.body(members...)))
	if err != nil {
		return nil, err
	}
	return answer.Value.(*core.Object), nil
}

func (f *workflowFixture) mustCreate(credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	workflow, err := f.create(credential, members...)
	requirePorted(f.t, err)
	return workflow
}

func (f *workflowFixture) update(credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	return f.object(f.iam.API.Workflows.Update(f.ctx, credential, Input[apitypes.WorkflowsUpdateInput](f.body(members...))))
}

func (f *workflowFixture) run(credential core.CredentialInput, members ...any) ([]*core.Object, error) {
	answer, err := f.iam.API.Workflows.Run(f.ctx, credential, Input[apitypes.WorkflowsRunInput](f.body(members...)))
	if err != nil {
		return nil, err
	}
	list := answer.Value.([]any)
	runs := make([]*core.Object, len(list))
	for index, item := range list {
		runs[index] = item.(*core.Object)
	}
	return runs, nil
}

func (f *workflowFixture) mustRun(credential core.CredentialInput, members ...any) []*core.Object {
	f.t.Helper()
	runs, err := f.run(credential, members...)
	requirePorted(f.t, err)
	return runs
}

func (f *workflowFixture) runDue() *core.Object {
	f.t.Helper()
	result, err := f.iam.Workflows.RunDue(f.ctx, core.NewObject("tenantId", f.tenantID))
	requirePorted(f.t, err)
	return result
}

func (f *workflowFixture) started() float64 {
	f.t.Helper()
	return jsNumber(f.runDue().Get("started"))
}

func expectCounts(t *testing.T, result *core.Object, members ...any) {
	t.Helper()
	for index := 0; index+1 < len(members); index += 2 {
		key := members[index].(string)
		if got := jsNumber(result.Get(key)); got != jsNumber(core.Normalize(members[index+1])) {
			t.Fatalf("%s = %v in %s", key, got, core.MustStringify(result))
		}
	}
}

func TestWorkflowsRunsJoinerStepsForPeopleWhoJoinAfterTheWorkflowExistsWithinItsScope(t *testing.T) {
	f := newWorkflowFixture(t)
	existing := f.person("early", "department", "Engineering")
	f.clock.Add(1000)
	workflow := f.mustCreate(f.owner,
		"name", "Engineering joiners",
		"trigger", obj(t, `{"kind":"joiner"}`),
		"scope", obj(t, `{"include":[{"StringEquals":{"principal.department":"Engineering"}}]}`),
		"steps", []any{
			core.NewObject("kind", "add-to-group", "groupId", f.engineering.Get("id")),
			obj(t, `{"kind":"send-email","to":"subject","subject":"Welcome to {organization}, {name}","body":"You joined {attribute.department}."}`),
			obj(t, `{"kind":"emit-event","name":"engineer.joined"}`),
		},
	)
	if workflow.Get("enabled") != true || jsNumber(workflow.Get("version")) != 1 || jsNumber(workflow.Get("maxRunsPerDay")) != 200 {
		t.Fatalf("created %s", core.MustStringify(workflow))
	}
	alice := f.person("alice", "department", "Engineering")
	bob := f.person("bob", "department", "Sales")
	result := f.runDue()
	f.blocked()
	expectCounts(t, result, "started", 1, "executed", 1, "completed", 1)
	f.expectGroups(alice.Get("id"), "Engineering")
	f.expectGroups(bob.Get("id"))
	f.expectGroups(existing.Get("id"))
	f.dispatch()
	welcome := f.messages(f.tenantID, "workflow-message")
	if len(welcome) == 0 || welcome[0].To != "alice@acme.test" {
		t.Fatalf("welcome %v", welcome)
	}
	payload := welcome[0].Payload
	if payload["subject"] != "Welcome to Acme, alice" || payload["body"] != "You joined Engineering." {
		t.Fatalf("payload %v", payload)
	}
	// Each joiner runs once.
	if started := f.started(); started != 0 {
		t.Fatalf("started again: %v", started)
	}
	runs := f.object(f.iam.API.Workflows.ListRuns(f.ctx, f.owner, Input[apitypes.WorkflowsListRunsInput](f.body("workflowId", workflow.Get("id")))))
	first := runs.Get("runs").([]any)[0].(*core.Object)
	if first.Get("identityId") != alice.Get("id") || first.Get("status") != "completed" {
		t.Fatalf("run %s", core.MustStringify(first))
	}
	results := first.Get("results").([]any)
	expected := [][3]string{{"add-to-group", "done", "Engineering"}, {"send-email", "done", ""}, {"emit-event", "done", ""}}
	for index, want := range expected {
		item := results[index].(*core.Object)
		if item.Get("kind") != want[0] || item.Get("outcome") != want[1] || (want[2] != "" && item.Get("detail") != want[2]) {
			t.Fatalf("result %d: %s", index, core.MustStringify(item))
		}
	}
	if len(f.auditTrail(f.tenantID, "workflow:event")) == 0 {
		t.Fatal("no workflow:event audit event")
	}
}

func TestWorkflowsFiresMoverWorkflowsOnWatchedAttributeChangesAndLeaverWorkflowsOnDisabling(t *testing.T) {
	f := newWorkflowFixture(t)
	carol := f.person("carol", "department", "Engineering")
	_, err := f.addMember("groupId", f.engineering.Get("id"), "identityId", carol.Get("id"))
	requirePorted(t, err)
	f.mustCreate(f.owner,
		"name", "Department movers",
		"trigger", obj(t, `{"kind":"mover","attributes":["department"]}`),
		"steps", []any{core.NewObject("kind", "remove-from-group", "groupId", f.engineering.Get("id"))},
	)
	leaver := f.mustCreate(f.owner,
		"name", "Leavers",
		"trigger", obj(t, `{"kind":"leaver"}`),
		"steps", parse(t, `[{"kind":"remove-from-all-groups"},{"kind":"wait","hours":720},{"kind":"delete"}]`),
	)
	if jsNumber(leaver.Get("maxRunsPerDay")) != 25 {
		t.Fatalf("leaver brake %v", leaver.Get("maxRunsPerDay"))
	}
	// No change yet: the baselines were taken when the workflows were created.
	if started := f.started(); started != 0 {
		t.Fatalf("started without a change: %v", started)
	}
	f.updateIdentity(carol.Get("id"), core.NewObject("department", "Sales"))
	if started := f.started(); started != 1 {
		t.Fatalf("mover started %v", started)
	}
	f.blocked()
	f.expectGroups(carol.Get("id"))
	// Moving back fires again.
	_, err = f.addMember("groupId", f.engineering.Get("id"), "identityId", carol.Get("id"))
	requirePorted(t, err)
	_, err = f.addMember("groupId", f.everyone.Get("id"), "identityId", carol.Get("id"))
	requirePorted(t, err)
	f.updateIdentity(carol.Get("id"), core.NewObject("department", "Engineering"))
	if started := f.started(); started != 1 {
		t.Fatalf("mover started again %v", started)
	}
	f.blocked()
	f.expectGroups(carol.Get("id"), "Everyone")

	// Leaving: groups go now, the account is deleted after the wait.
	owner := f.ownerSignIn()
	_, err = f.iam.API.Identities.SetStatus(f.ctx, owner, Input[apitypes.IdentitiesSetStatusInput](f.body("identityId", carol.Get("id"), "status", "disabled")))
	f.afterChange(err)
	first := f.runDue()
	f.blocked()
	expectCounts(t, first, "started", 1, "waiting", 1)
	f.expectGroups(carol.Get("id"))
	if status := f.record("identities", jsString(carol.Get("id"))).Get("status"); status != "disabled" {
		t.Fatalf("status %v", status)
	}
	f.clock.Add(31 * workflowDay)
	later := f.runDue()
	f.blocked()
	expectCounts(t, later, "started", 0, "completed", 1)
	if status := f.record("identities", jsString(carol.Get("id"))).Get("status"); status != "deleted" {
		t.Fatalf("status %v", status)
	}
}

func TestWorkflowsRunsDateWorkflowsRelativeToADateAttribute(t *testing.T) {
	f := newWorkflowFixture(t)
	start := isoString(f.now() + 10*workflowDay)[:10]
	dave := f.person("dave", "startDate", start)
	f.mustCreate(f.owner,
		"name", "Before the first day",
		"trigger", obj(t, `{"kind":"date","attribute":"startDate","offsetDays":-7}`),
		"steps", []any{core.NewObject("kind", "add-to-group", "groupId", f.everyone.Get("id"), "days", 30)},
	)
	list := f.items(f.iam.API.Workflows.List(f.ctx, f.owner, Input[apitypes.WorkflowsListInput](f.body())))
	preview := f.object(f.iam.API.Workflows.Preview(f.ctx, f.owner, Input[apitypes.WorkflowsPreviewInput](f.body("workflowId", list[0].Get("id")))))
	expectStrings(t, upcomingIDs(preview), jsString(dave.Get("id")))
	if wouldStart := preview.Get("wouldStart").([]any); len(wouldStart) != 0 {
		t.Fatalf("wouldStart %s", core.MustStringify(wouldStart))
	}
	if started := f.started(); started != 0 {
		t.Fatalf("started early: %v", started)
	}
	f.clock.Add(4 * workflowDay)
	if started := f.started(); started != 1 {
		t.Fatalf("started %v", started)
	}
	f.blocked()
	f.expectGroups(dave.Get("id"), "Everyone")
	if started := f.started(); started != 0 {
		t.Fatalf("started twice: %v", started)
	}
}

func upcomingIDs(preview *core.Object) []any {
	ids := []any{}
	for _, item := range preview.Get("upcoming").([]any) {
		ids = append(ids, item.(*core.Object).Get("id"))
	}
	return ids
}

func TestWorkflowsRefusesToSaveStepsTheCallerCouldNotDoByHandAndFailsRunsWhenTheOwnerLosesRights(t *testing.T) {
	f := newWorkflowFixture(t)
	manager := f.person("manager")
	role := f.createRole(f.owner, "name", "Workflow author", "document", core.NewObject(
		"version", 1,
		"statements", []any{
			obj(t, `{"effect":"allow","actions":["iam:workflows:*"],"resources":["*"]}`),
			core.NewObject("effect", "allow", "actions", []any{"iam:groups:update"}, "resources", []any{"iam/" + jsString(f.everyone.Get("id"))}),
		},
	))
	binding := f.bind(f.owner, role.Get("id"), "identity", manager.Get("id"))
	token := f.login("manager")
	_, err := f.create(token,
		"name", "Too much",
		"trigger", obj(t, `{"kind":"joiner"}`),
		"steps", []any{core.NewObject("kind", "add-to-group", "groupId", f.engineering.Get("id"))},
	)
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	workflow := f.mustCreate(token,
		"name", "Everyone",
		"trigger", obj(t, `{"kind":"manual"}`),
		"steps", []any{core.NewObject("kind", "add-to-group", "groupId", f.everyone.Get("id"))},
	)
	erin := f.person("erin")
	done := f.mustRun(token, "workflowId", workflow.Get("id"), "identityIds", []any{erin.Get("id")})
	f.blocked()
	if done[0].Get("status") != "completed" {
		t.Fatalf("run %s", core.MustStringify(done[0]))
	}
	// The author loses the right: the owner's next run fails at the step, and retrying needs the right back.
	_, err = f.iam.API.Bindings.Delete(f.ctx, f.owner, Input[apitypes.BindingsDeleteInput](f.body("bindingId", binding.Get("id"))))
	requirePorted(t, err)
	frank := f.person("frank")
	owner := f.ownerSignIn()
	failed := f.mustRun(owner, "workflowId", workflow.Get("id"), "identityIds", []any{frank.Get("id")})
	f.blocked()
	if failed[0].Get("status") != "failed" || member(failed[0].Get("error"), "code") != "ACCESS_DENIED" {
		t.Fatalf("run %s", core.MustStringify(failed[0]))
	}
	// Saving it again makes the owner the one with the rights.
	f.update(owner, "workflowId", workflow.Get("id"), "name", "Everyone")
	retried := f.object(f.iam.API.Workflows.RetryRun(f.ctx, owner, Input[apitypes.WorkflowsRetryRunInput](f.body("runId", failed[0].Get("id")))))
	f.blocked()
	if retried.Get("status") != "completed" {
		t.Fatalf("retried %s", core.MustStringify(retried))
	}
	f.expectGroups(frank.Get("id"), "Everyone")
}

func TestWorkflowsNeverStripsOwnersAndStopsAtTheDailyBrake(t *testing.T) {
	f := newWorkflowFixture(t)
	workflow := f.mustCreate(f.owner,
		"name", "Disable",
		"trigger", obj(t, `{"kind":"manual"}`),
		"steps", parse(t, `[{"kind":"disable"}]`),
	)
	owner := f.ownerSignIn()
	other := f.person("gina")
	_, err := f.iam.API.Identities.SetOwner(f.ctx, owner, Input[apitypes.IdentitiesSetOwnerInput](f.body("identityId", other.Get("id"), "owner", true)))
	f.afterChange(err)
	runs := f.mustRun(owner, "workflowId", workflow.Get("id"), "identityIds", []any{other.Get("id")})
	f.blocked()
	if runs[0].Get("status") != "failed" || member(runs[0].Get("error"), "code") != "PROTECTED_RESOURCE" {
		t.Fatalf("run %s", core.MustStringify(runs[0]))
	}

	brake := f.mustCreate(f.owner,
		"name", "Tag everyone",
		"trigger", obj(t, `{"kind":"joiner"}`),
		"includeExisting", true,
		"maxRunsPerDay", 2,
		"steps", []any{core.NewObject("kind", "add-to-group", "groupId", f.everyone.Get("id"))},
	)
	for _, name := range []string{"h1", "h2", "h3"} {
		f.person(name)
	}
	// Five people qualify: two start today, the rest wait for tomorrow (or a higher limit).
	if started := f.started(); started != 2 {
		t.Fatalf("started %v", started)
	}
	if started := f.started(); started != 0 {
		t.Fatalf("started past the brake: %v", started)
	}
	if len(f.auditTrail(f.tenantID, "workflow:brake")) == 0 {
		t.Fatal("no workflow:brake audit event")
	}
	raised := f.update(owner, "workflowId", brake.Get("id"), "maxRunsPerDay", 50)
	if raised.Has("brakedOn") {
		t.Fatalf("brakedOn kept: %s", core.MustStringify(raised))
	}
	if started := f.started(); started != 3 {
		t.Fatalf("started after raising the limit: %v", started)
	}
}

func TestWorkflowsReactsToChangesThroughSubscribeWhenAuditHooksAreDispatched(t *testing.T) {
	f := newWorkflowFixture(t)
	f.mustCreate(f.owner,
		"name", "Welcome",
		"trigger", obj(t, `{"kind":"joiner"}`),
		"steps", []any{core.NewObject("kind", "add-to-group", "groupId", f.everyone.Get("id"))},
	)
	stop := must(f.iam.Workflows.Subscribe())
	defer stop()
	ivan := f.person("ivan")
	// The auth service's identity creation is not an administrator's change; the attribute change is.
	f.updateIdentity(ivan.Get("id"), core.NewObject("title", "Engineer"))
	if _, err := f.iam.DispatchAuditHooks(f.ctx); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 30*time.Second)
	defer cancel()
	if err := f.iam.Workflows.Idle(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.find("workflowRuns", core.NewObject("tenantId", f.tenantID))) == 0 {
		t.Fatal("subscribe started no run")
	}
	f.blocked()
	f.expectGroups(ivan.Get("id"), "Everyone")
}

func TestWorkflowsValidatesDefinitions(t *testing.T) {
	f := newWorkflowFixture(t)
	attempt := func(members ...any) error {
		input := core.NewObject(
			"name", "Bad",
			"trigger", obj(t, `{"kind":"joiner"}`),
			"steps", parse(t, `[{"kind":"emit-event","name":"x"}]`),
		)
		input.Assign(core.NewObject(members...))
		args := []any{}
		input.Entries(func(key string, value any) bool {
			args = append(args, key, value)
			return true
		})
		_, err := f.create(f.owner, args...)
		return err
	}
	expectCodeOrSkip(t, attempt("trigger", obj(t, `{"kind":"mover","attributes":["shoeSize"]}`)), "INVALID_INPUT")
	expectCodeOrSkip(t, attempt("trigger", obj(t, `{"kind":"date","attribute":"title","offsetDays":400000}`)), "INVALID_INPUT")
	expectCodeOrSkip(t, attempt("steps", parse(t, `[{"kind":"wait","hours":2}]`)), "INVALID_INPUT")
	expectCodeOrSkip(t, attempt("steps", parse(t, `[{"kind":"delete"},{"kind":"emit-event","name":"after"}]`)), "INVALID_INPUT")
	expectCodeOrSkip(t, attempt("steps", parse(t, `[{"kind":"send-email","to":"nobody","subject":"s","body":"b"}]`)), "INVALID_INPUT")
	expectCodeOrSkip(t, attempt("steps", parse(t, `[{"kind":"add-to-group","groupId":"missing"}]`)), "INVALID_INPUT")
	expectCodeOrSkip(t, attempt("scope", obj(t, `{"include":[{"StringEquals":{"principal.unknown":"x"}}]}`)), "INVALID_INPUT")
}

func TestWorkflowReviewFixesRefusesWorkflowsThatChangeTheAccountOfWhoeverRunsThem(t *testing.T) {
	f := newWorkflowFixture(t)
	admin := f.person("admin")
	role := f.createRole(f.owner, "name", "Directory admin", "document", obj(t,
		`{"version":1,"statements":[{"effect":"allow","actions":["iam:workflows:*","iam:identities:update","iam:identities:read"],"resources":["*"]}]}`))
	f.bind(f.owner, role.Get("id"), "identity", admin.Get("id"))
	token := f.login("admin")
	workflow := f.mustCreate(token,
		"name", "Move to finance",
		"trigger", obj(t, `{"kind":"manual"}`),
		"steps", parse(t, `[{"kind":"set-attributes","attributes":{"department":"Finance"}}]`),
	)
	_, err := f.run(token, "workflowId", workflow.Get("id"), "identityIds", []any{admin.Get("id")})
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	// Someone else may run it on the admin, but it still refuses to act on the workflow's own owner.
	owner := f.ownerSignIn()
	runs := f.mustRun(owner, "workflowId", workflow.Get("id"), "identityIds", []any{admin.Get("id")})
	f.blocked()
	if runs[0].Get("status") != "failed" || member(runs[0].Get("error"), "code") != "INVALID_INPUT" {
		t.Fatalf("run %s", core.MustStringify(runs[0]))
	}
	if department := member(f.record("identities", jsString(admin.Get("id"))).Get("attributes"), "department"); !isUndefined(department) {
		t.Fatalf("department %v", department)
	}
}

func TestWorkflowReviewFixesSendsWorkflowEmailOnlyInsideTheOrganization(t *testing.T) {
	f := newWorkflowFixture(t)
	f.person("hr")
	email := func(to string) []any {
		return []any{
			"name", "Notify " + to,
			"trigger", obj(t, `{"kind":"joiner"}`),
			"steps", []any{core.NewObject("kind", "send-email", "to", to, "subject", "New person", "body", "{name} {email}")},
		}
	}
	_, err := f.create(f.owner, email("collector@evil.example")...)
	expectCodeOrSkip(t, err, "INVALID_INPUT")
	if created := f.mustCreate(f.owner, email("hr@acme.test")...); created.Get("enabled") != true {
		t.Fatalf("created %s", core.MustStringify(created))
	}
}

func TestWorkflowReviewFixesCanCancelRunsInProgressWhenTheWorkflowChanges(t *testing.T) {
	f := newWorkflowFixture(t)
	workflow := f.mustCreate(f.owner,
		"name", "Grace period",
		"trigger", obj(t, `{"kind":"manual"}`),
		"steps", parse(t, `[{"kind":"wait","hours":48},{"kind":"disable"}]`),
	)
	jane := f.person("jane")
	waiting := f.mustRun(f.owner, "workflowId", workflow.Get("id"), "identityIds", []any{jane.Get("id")})
	if waiting[0].Get("status") != "waiting" {
		t.Fatalf("run %s", core.MustStringify(waiting[0]))
	}
	f.update(f.owner, "workflowId", workflow.Get("id"), "steps", parse(t, `[{"kind":"emit-event","name":"kept"}]`), "activeRuns", "cancel")
	f.clock.Add(3 * workflowDay)
	f.runDue()
	if status := f.record("identities", jsString(jane.Get("id"))).Get("status"); status != "active" {
		t.Fatalf("status %v", status)
	}
	owner := f.ownerSignIn()
	runs := f.object(f.iam.API.Workflows.ListRuns(f.ctx, owner, Input[apitypes.WorkflowsListRunsInput](f.body("workflowId", workflow.Get("id")))))
	if status := runs.Get("runs").([]any)[0].(*core.Object).Get("status"); status != "cancelled" {
		t.Fatalf("status %v", status)
	}
}

// --- further API behavior ----------------------------------------------------------------------------------------------

func TestWorkflowsGetDeleteCancelAndViews(t *testing.T) {
	f := newWorkflowFixture(t)
	workflow := f.mustCreate(f.owner,
		"name", "Grace period",
		"description", "Two days, then an event",
		"trigger", obj(t, `{"kind":"manual"}`),
		"steps", parse(t, `[{"kind":"wait","hours":48},{"kind":"emit-event","name":"later"}]`),
	)
	keys := strings.Join(workflow.Keys(), ",")
	if keys != "id,tenantId,name,description,enabled,trigger,steps,includeExisting,maxRunsPerDay,ownerId,ownerName,version,activeSince,createdAt,updatedAt" {
		t.Fatalf("view keys %s", keys)
	}
	if workflow.Get("ownerName") != "acme@example.test" {
		t.Fatalf("ownerName %v", workflow.Get("ownerName"))
	}
	_, err := f.create(f.owner, "name", " grace PERIOD ", "trigger", obj(t, `{"kind":"manual"}`), "steps", parse(t, `[{"kind":"emit-event","name":"x"}]`))
	expectError(t, err, "CONFLICT", "A workflow with this name exists")
	jane := f.person("jane")
	runs := f.mustRun(f.owner, "workflowId", workflow.Get("id"), "identityIds", []any{jane.Get("id"), jane.Get("id")})
	if len(runs) != 1 || runs[0].Get("status") != "waiting" || runs[0].Has("identityName") {
		t.Fatalf("runs %s", core.MustStringify(runs))
	}
	got := f.object(f.iam.API.Workflows.Get(f.ctx, f.owner, Input[apitypes.WorkflowsGetInput](f.body("workflowId", workflow.Get("id")))))
	stats := got.Get("runs").(*core.Object)
	if jsNumber(stats.Get("active")) != 1 || jsNumber(stats.Get("last30Days")) != 1 || jsNumber(stats.Get("lastRunAt")) != f.now() {
		t.Fatalf("stats %s", core.MustStringify(stats))
	}
	recent := got.Get("recentRuns").([]any)[0].(*core.Object)
	if recent.Get("identityName") != "jane@acme.test" {
		t.Fatalf("recent %s", core.MustStringify(recent))
	}
	run := f.object(f.iam.API.Workflows.GetRun(f.ctx, f.owner, Input[apitypes.WorkflowsGetRunInput](f.body("runId", runs[0].Get("id")))))
	if run.Get("identityName") != "jane@acme.test" || run.Get("startedBy") != f.ownerID {
		t.Fatalf("run %s", core.MustStringify(run))
	}
	cancelled := f.object(f.iam.API.Workflows.CancelRun(f.ctx, f.owner, Input[apitypes.WorkflowsCancelRunInput](f.body("runId", runs[0].Get("id")))))
	if cancelled.Get("status") != "cancelled" || jsNumber(cancelled.Get("finishedAt")) != f.now() {
		t.Fatalf("cancelled %s", core.MustStringify(cancelled))
	}
	_, err = f.iam.API.Workflows.CancelRun(f.ctx, f.owner, Input[apitypes.WorkflowsCancelRunInput](f.body("runId", runs[0].Get("id"))))
	expectError(t, err, "INVALID_TRANSITION", "This run already finished")
	_, err = f.iam.API.Workflows.RetryRun(f.ctx, f.owner, Input[apitypes.WorkflowsRetryRunInput](f.body("runId", runs[0].Get("id"))))
	expectError(t, err, "INVALID_TRANSITION", "Only failed runs can be retried")
	second := f.mustRun(f.owner, "workflowId", workflow.Get("id"), "identityIds", []any{jane.Get("id")})
	filtered := f.object(f.iam.API.Workflows.ListRuns(f.ctx, f.owner, Input[apitypes.WorkflowsListRunsInput](f.body("status", "waiting"))))
	if jsNumber(filtered.Get("total")) != 1 || filtered.Get("runs").([]any)[0].(*core.Object).Get("id") != second[0].Get("id") {
		t.Fatalf("filtered %s", core.MustStringify(filtered))
	}
	_, err = f.iam.API.Workflows.Update(f.ctx, f.owner, Input[apitypes.WorkflowsUpdateInput](f.body("workflowId", workflow.Get("id"), "activeRuns", "stop")))
	expectError(t, err, "INVALID_INPUT", "activeRuns must be 'keep' or 'cancel'")
	updated := f.update(f.owner, "workflowId", workflow.Get("id"), "description", nil, "enabled", false)
	if updated.Has("description") || jsNumber(updated.Get("version")) != 2 || updated.Get("enabled") != false {
		t.Fatalf("updated %s", core.MustStringify(updated))
	}
	deleted := f.object(f.iam.API.Workflows.Delete(f.ctx, f.owner, Input[apitypes.WorkflowsDeleteInput](f.body("workflowId", workflow.Get("id")))))
	if core.MustStringify(deleted) != `{"deleted":true,"runsCancelled":1}` {
		t.Fatalf("deleted %s", core.MustStringify(deleted))
	}
	if left := f.items(f.iam.API.Workflows.List(f.ctx, f.owner, Input[apitypes.WorkflowsListInput](f.body()))); len(left) != 0 {
		t.Fatalf("left %d workflows", len(left))
	}
	_, err = f.iam.API.Workflows.Run(f.ctx, f.owner, Input[apitypes.WorkflowsRunInput](f.body("workflowId", workflow.Get("id"), "identityIds", []any{})))
	expectError(t, err, "INVALID_INPUT", "Provide 1-100 identityIds")
}

func TestWorkflowsNeedTheirPermissions(t *testing.T) {
	f := newWorkflowFixture(t)
	f.person("mallory")
	mallory := f.login("mallory")
	_, err := f.create(mallory, "name", "Mine", "trigger", obj(t, `{"kind":"manual"}`), "steps", parse(t, `[{"kind":"emit-event","name":"x"}]`))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	_, err = f.iam.API.Workflows.List(f.ctx, mallory, Input[apitypes.WorkflowsListInput](f.body()))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	_, err = f.iam.API.Workflows.Evaluate(f.ctx, mallory, Input[apitypes.WorkflowsEvaluateInput](f.body()))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	result := f.object(f.iam.API.Workflows.Evaluate(f.ctx, f.owner, Input[apitypes.WorkflowsEvaluateInput](f.body())))
	if core.MustStringify(result) != `{"started":0,"executed":0,"completed":0,"failed":0,"waiting":0}` {
		t.Fatalf("evaluate %s", core.MustStringify(result))
	}
}
