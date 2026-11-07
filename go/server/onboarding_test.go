package server

// Onboarding tests, after tests/onboarding.test.ts: platform flows inherited by organizations and projects, settings
// that switch off unlocked flows, policies gated on principal.pendingOnboarding, tenant setup checklists with check
// steps and administrator-verified tasks, flow validation and versioning, and the member routes over HTTP. Members are
// created through the auth service (identities.create runs package automation, another unit). Parts that reach
// another unit's stub (package rules, the packages API's allow(), package automation) skip from that point.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// onbFixture is a composed server with a root, an organization (Acme) and its owner.
type onbFixture struct {
	*tenantsFixture
	acme organization
	api  *OnboardingAPI
}

func newOnbFixture(t *testing.T, attributes bool) *onbFixture {
	t.Helper()
	base := newTenantsFixture(t, func(options *BetterIamOptions) {
		if attributes {
			options.Permissions = &core.PermissionsConfig{
				Actions:            []string{"documents:read", "documents:write"},
				IdentityAttributes: []core.NamedAttribute{{Name: "department", Type: "string"}, {Name: "title", Type: "string"}},
			}
		} else {
			options.Permissions = &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}}
		}
		options.ResolveResource = func(ctx context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			return &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID, Attributes: core.NewObject()}, nil
		}
	})
	f := &onbFixture{tenantsFixture: base}
	f.acme = base.createTenant("Acme", "", "")
	f.api = base.iam.API.Onboarding
	return f
}

// member creates an active person `{name}@acme.test` in a tenant with a password and signs them in.
func (f *onbFixture) member(tenantID, name string) (*core.Object, core.CredentialInput) {
	f.t.Helper()
	email := name + "@acme.test"
	identity, err := core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: tenantID, Email: email, Name: name, Password: tenantsTestPassword, HasPassword: true, EmailVerified: true,
		})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return identity, f.signIn(tenantID, email)
}

// onbCall runs an API method and answers its value.
func onbCall[T, O any](method func(context.Context, core.CredentialInput, In[T]) (Out[O], error), credential core.CredentialInput, body *core.Object) (any, error) {
	out, err := method(context.Background(), credential, Input[T](body))
	return out.Value, err
}

func (f *onbFixture) object(value any, err error) *core.Object {
	f.t.Helper()
	requirePorted(f.t, err)
	object, ok := value.(*core.Object)
	if !ok {
		f.t.Fatalf("expected an object, got %T", value)
	}
	return object
}

func (f *onbFixture) createFlow(credential core.CredentialInput, body *core.Object) (*core.Object, error) {
	value, err := onbCall(f.api.CreateFlow, credential, body)
	object, _ := value.(*core.Object)
	return object, err
}

func (f *onbFixture) mine(credential core.CredentialInput, tenantID string) *core.Object {
	f.t.Helper()
	return f.object(onbCall(f.api.Mine, credential, core.NewObject("tenantId", tenantID)))
}

// flowNames are the `name` members of a model array of flow statuses.
func onbFlowNames(value any) []string {
	names := []string{}
	for _, flow := range onboardingObjects(value) {
		names = append(names, jsString(flow.Get("name")))
	}
	return names
}

func onbExpectCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", code)
	}
	known := iamError(t, err)
	if known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
	if known.Code != code {
		t.Fatalf("expected %s, got %s: %s", code, known.Code, known.Message)
	}
}

func onbSteps(items ...*core.Object) []any { return onboardingList(items) }

func onbAckStep(id string) []any {
	return onbSteps(core.NewObject("id", id, "kind", "acknowledge", "title", id, "content", "Read "+id+"."))
}

var onbDepartmentField = func() *core.Object {
	return core.NewObject("name", "department", "label", "Department", "type", "select", "options", []any{"Engineering", "Sales"}, "required", true)
}

// gatedReader gives a person a role that reads documents only once every required onboarding flow is complete.
func (f *onbFixture) gatedReader(identityID string) {
	f.t.Helper()
	role := f.object(onbCall(f.iam.API.Roles.Create, f.acme.credential, core.NewObject(
		"tenantId", f.acme.id,
		"name", "Onboarded reader",
		"document", document(
			allowStatement("documents:read", "*"),
			core.NewObject("effect", "deny", "actions", []any{"documents:*"}, "resources", []any{"*"},
				"conditions", core.NewObject("NumericGreaterThan", core.NewObject("principal.pendingOnboarding", 0.0))),
		),
	)))
	f.object(onbCall(f.iam.API.Bindings.Create, f.acme.credential, core.NewObject(
		"tenantId", f.acme.id, "roleId", role.Get("id"), "subjectType", "identity", "subjectId", identityID,
	)))
}

func (f *onbFixture) canRead(credential core.CredentialInput) bool {
	f.t.Helper()
	decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{
		Credential: credential, TenantID: f.acme.id, Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "d1"},
	})
	requirePorted(f.t, err)
	return decision.Allowed
}

func TestOnboardingInheritsPlatformFlowsAndGatesAccess(t *testing.T) {
	f := newOnbFixture(t, true)
	root := f.credential
	owner := f.acme.credential
	// The owner joined before any flow existed; flows ask newcomers only unless includeExisting.
	f.clock.Add(1_000)

	// A flow that reaches only the tenants below may not write their people's attributes.
	_, err := f.createFlow(root, core.NewObject("tenantId", f.rootID, "name", "Platform profile", "audience", "member",
		"steps", onbSteps(core.NewObject("id", "profile", "kind", "form", "title", "About you",
			"fields", []any{onbDepartmentField().Set("attribute", "department")}))))
	onbExpectCode(t, err, "INVALID_INPUT")
	essentials := f.object(f.createFlow(root, core.NewObject("tenantId", f.rootID, "name", "Platform essentials", "audience", "member", "locked", true,
		"steps", onbSteps(
			core.NewObject("id", "conduct", "kind", "acknowledge", "title", "Code of conduct", "content", "Be kind.\n\n1. Report incidents."),
			core.NewObject("id", "profile", "kind", "form", "title", "About you",
				"fields", []any{onbDepartmentField(), core.NewObject("name", "phone", "label", "Desk phone", "type", "text")}),
		))))
	// Flows at the platform root reach the tenants below it by default.
	if essentials.Get("appliesTo") != "descendants" || essentials.Get("version") != 1.0 || essentials.Get("locked") != true {
		t.Fatalf("essentials = %s", stringify(essentials))
	}
	expectJSON(t, "flow member order", essentials.Keys(),
		`["id","tenantId","uniqueKey","name","audience","appliesTo","required","locked","includeExisting","enabled","effectiveFrom","steps","version","authorId","createdAt","updatedAt"]`)
	f.clock.Add(1)
	tour := f.object(f.createFlow(root, core.NewObject("tenantId", f.rootID, "name", "Product tour", "audience", "member", "required", false,
		"steps", onbSteps(core.NewObject("id", "tour", "kind", "task", "title", "Take the tour", "url", "https://example.test/tour")))))
	f.object(onbCall(f.api.SetSettings, root, core.NewObject("tenantId", f.rootID, "welcomeTitle", "Welcome to Example Cloud",
		"welcomeMessage", "Platform message", "supportEmail", "help@example.test")))

	// The organization sees both, may switch off only the unlocked one, and adds its own.
	effective := f.object(onbCall(f.api.Effective, owner, core.NewObject("tenantId", f.acme.id)))
	levels := []string{}
	for _, level := range onboardingObjects(effective.Get("levels")) {
		levels = append(levels, jsString(level.Get("type")))
	}
	expectJSON(t, "levels", levels, `["root","organization"]`)
	rows := []any{}
	for _, item := range onboardingObjects(effective.Get("memberFlows")) {
		rows = append(rows, []any{member(item.Get("flow"), "name"), item.Get("inherited"), item.Get("canDisable")})
	}
	expectJSON(t, "member flows", rows, `[["Platform essentials",true,false],["Product tour",true,true]]`)
	if first := onboardingObjects(effective.Get("memberFlows"))[0]; !isUndefined(member(first.Get("flow"), "authorId")) {
		t.Fatal("inherited flows leave out their author")
	}
	_, err = onbCall(f.api.SetSettings, owner, core.NewObject("tenantId", f.acme.id, "disabledFlowIds", []any{essentials.Get("id")}))
	onbExpectCode(t, err, "INVALID_INPUT")
	f.object(onbCall(f.api.SetSettings, owner, core.NewObject("tenantId", f.acme.id, "welcomeMessage", "Welcome to Acme!", "disabledFlowIds", []any{tour.Get("id")})))
	team := f.object(f.createFlow(owner, core.NewObject("tenantId", f.acme.id, "name", "Acme profile", "audience", "member",
		"steps", onbSteps(core.NewObject("id", "team", "kind", "form", "title", "Your team", "fields", []any{onbDepartmentField()})))))
	if team.Get("appliesTo") != "tenant" {
		t.Fatalf("an organization's flow reaches its own people by default: %s", stringify(team))
	}

	f.clock.Add(1)
	alice, aliceToken := f.member(f.acme.id, "alice")
	aliceID := jsString(alice.Get("id"))

	mine := f.mine(aliceToken, f.acme.id)
	expectJSON(t, "alice's flows", onbFlowNames(mine.Get("flows")), `["Platform essentials","Acme profile"]`)
	if mine.Get("pending") != 2.0 || mine.Get("complete") != false {
		t.Fatalf("mine = %s", stringify(mine))
	}
	welcome := mine.Get("welcome").(*core.Object)
	if welcome.Get("welcomeTitle") != "Welcome to Example Cloud" || welcome.Get("welcomeMessage") != "Welcome to Acme!" || welcome.Get("supportEmail") != "help@example.test" {
		t.Fatalf("welcome = %s", stringify(welcome))
	}
	if member(member(welcome.Get("sources"), "welcomeTitle"), "type") != "root" || member(member(welcome.Get("sources"), "welcomeMessage"), "tenantId") != f.acme.id {
		t.Fatalf("welcome sources = %s", stringify(welcome.Get("sources")))
	}
	expectJSON(t, "welcome member order", welcome.Keys(), `["sources","welcomeMessage","welcomeTitle","supportEmail"]`)
	// The owner predates the flows.
	if flows := f.mine(owner, f.acme.id).Get("flows"); len(flows.([]any)) != 0 {
		t.Fatalf("the owner predates the flows: %s", stringify(flows))
	}

	_, err = onbCall(f.api.SubmitStep, aliceToken, core.NewObject("tenantId", f.acme.id, "flowId", essentials.Get("id"), "stepId", "conduct"))
	expectError(t, err, "INVALID_INPUT", "Confirm that you have read this (acknowledged: true)")
	f.object(onbCall(f.api.SubmitStep, aliceToken, core.NewObject("tenantId", f.acme.id, "flowId", essentials.Get("id"), "stepId", "conduct", "acknowledged", true)))
	_, err = onbCall(f.api.SubmitStep, aliceToken, core.NewObject("tenantId", f.acme.id, "flowId", essentials.Get("id"), "stepId", "profile",
		"answers", core.NewObject("department", "Marketing")))
	expectError(t, err, "INVALID_INPUT", "Department is not valid")
	// The platform's answers stay answers; they never write Acme's identities.
	profile := f.object(onbCall(f.api.SubmitStep, aliceToken, core.NewObject("tenantId", f.acme.id, "flowId", essentials.Get("id"), "stepId", "profile",
		"answers", core.NewObject("department", "Engineering", "phone", " 555-0100 "))))
	expectJSON(t, "attributes filled", profile.Get("attributesFilled"), `[]`)
	flow := profile.Get("flow").(*core.Object)
	if flow.Get("complete") != true || flow.Get("done") != 2.0 || flow.Get("total") != 2.0 {
		t.Fatalf("profile flow = %s", stringify(flow))
	}
	expectJSON(t, "answers", member(flow.Get("steps").([]any)[1], "answers"), `{"department":"Engineering","phone":"555-0100"}`)
	steps := onboardingObjects(flow.Get("steps"))
	expectJSON(t, "step status member order", steps[0].Keys(), `["id","kind","title","content","optional","state","completedAt"]`)
	if f.canRead(aliceToken) {
		// Acme profile is still open.
		t.Fatal("a required open flow holds back access")
	}
	f.object(onbCall(f.api.SubmitStep, aliceToken, core.NewObject("tenantId", f.acme.id, "flowId", team.Get("id"), "stepId", "team",
		"answers", core.NewObject("department", "Engineering"))))
	f.gatedReader(aliceID)
	if !f.canRead(aliceToken) {
		t.Fatal("every required flow is complete")
	}
	mine = f.mine(aliceToken, f.acme.id)
	if mine.Get("pending") != 0.0 || mine.Get("complete") != true {
		t.Fatalf("mine = %s", stringify(mine))
	}
	completions := f.auditTrail(f.acme.id, "onboarding:complete")
	if len(completions) != 2 {
		t.Fatalf("each flow's completion is audited once: %d", len(completions))
	}
	expectJSON(t, "completion metadata", completions[0].Get("metadata"),
		`{"flowId":"`+jsString(essentials.Get("id"))+`","flow":"Platform essentials","version":1,"subjectType":"identity"}`)
	if len(f.auditTrail(f.acme.id, "onboarding:step")) != 3 {
		t.Fatal("each completed step is audited")
	}

	// The platform's report counts Acme's people without naming them.
	platformReport := f.object(onbCall(f.api.Progress, root, core.NewObject("tenantId", f.rootID, "flowId", essentials.Get("id"))))
	expectJSON(t, "platform members", platformReport.Get("members"), `[]`)
	expectJSON(t, "platform descendants", platformReport.Get("descendants"),
		`[{"tenant":{"tenantId":"`+f.acme.id+`","name":"Acme","type":"organization"},"people":1,"complete":1}]`)
	expectJSON(t, "report member order", platformReport.Keys(), `["flow","summary","members","descendants"]`)
	report := f.object(onbCall(f.api.Progress, owner, core.NewObject("tenantId", f.acme.id, "flowId", team.Get("id"))))
	rowsOut := onboardingObjects(report.Get("members"))
	if len(rowsOut) != 1 || member(rowsOut[0].Get("identity"), "id") != aliceID || rowsOut[0].Get("complete") != true {
		t.Fatalf("report = %s", stringify(report))
	}
	expectJSON(t, "report answers", rowsOut[0].Get("answers"), `{"team":{"department":"Engineering"}}`)

	// Resetting one step reopens the flow for her.
	reset := f.object(onbCall(f.api.ResetProgress, owner, core.NewObject("tenantId", f.acme.id, "flowId", team.Get("id"), "subjectId", aliceID, "stepId", "team")))
	if reset.Get("reset") != 1.0 {
		t.Fatalf("reset = %s", stringify(reset))
	}
	if f.canRead(aliceToken) {
		t.Fatal("the reset step reopens the flow")
	}
	memberView := f.object(onbCall(f.api.MemberProgress, owner, core.NewObject("tenantId", f.acme.id, "identityId", aliceID)))
	if memberView.Get("pending") != 1.0 {
		t.Fatalf("member progress = %s", stringify(memberView))
	}
}

func TestOnboardingAttributeAnswersAndCompletionGroups(t *testing.T) {
	f := newOnbFixture(t, true)
	owner := f.acme.credential
	f.clock.Add(1_000)
	engineers := f.object(onbCall(f.iam.API.Groups.Create, owner, core.NewObject("tenantId", f.acme.id, "name", "Engineers")))
	// Acme's own flow may fill its people's department.
	team := f.object(f.createFlow(owner, core.NewObject("tenantId", f.acme.id, "name", "Acme profile", "audience", "member",
		"steps", onbSteps(core.NewObject("id", "team", "kind", "form", "title", "Your team", "fields", []any{onbDepartmentField().Set("attribute", "department")})))))
	f.clock.Add(1)
	engineering := f.object(f.createFlow(owner, core.NewObject("tenantId", f.acme.id, "name", "Engineering onboarding", "audience", "member",
		"rule", core.NewObject("include", []any{core.NewObject("StringEquals", core.NewObject("principal.department", "Engineering"))}),
		"completionGroupIds", []any{engineers.Get("id")},
		"steps", onbSteps(core.NewObject("id", "laptop", "kind", "task", "title", "Collect your laptop", "verification", "admin")))))
	if engineering.Get("appliesTo") != "tenant" || engineering.Get("groupsOwnerId") != f.acme.owner.Get("id") {
		t.Fatalf("engineering = %s", stringify(engineering))
	}
	f.clock.Add(1)
	alice, aliceToken := f.member(f.acme.id, "alice")
	aliceID := jsString(alice.Get("id"))
	expectJSON(t, "flows before the answer", onbFlowNames(f.mine(aliceToken, f.acme.id).Get("flows")), `["Acme profile"]`)
	filled := f.object(onbCall(f.api.SubmitStep, aliceToken, core.NewObject("tenantId", f.acme.id, "flowId", team.Get("id"), "stepId", "team",
		"answers", core.NewObject("department", "Engineering"))))
	expectJSON(t, "filled", filled.Get("attributesFilled"), `["department"]`)
	// The answer filled her department, so the engineering flow now applies to her.
	mine := f.mine(aliceToken, f.acme.id)
	expectJSON(t, "flows after the answer", onbFlowNames(mine.Get("flows")), `["Acme profile","Engineering onboarding"]`)
	// Onboarding only fills empty attributes.
	again := f.object(onbCall(f.api.SubmitStep, aliceToken, core.NewObject("tenantId", f.acme.id, "flowId", team.Get("id"), "stepId", "team",
		"answers", core.NewObject("department", "Sales"))))
	expectJSON(t, "filled again", again.Get("attributesFilled"), `[]`)
	expectJSON(t, "attributes", f.record("identities", aliceID).Get("attributes"), `{"department":"Engineering"}`)

	// An administrator-verified task waits for the owner.
	laptop := f.object(onbCall(f.api.SubmitStep, aliceToken, core.NewObject("tenantId", f.acme.id, "flowId", engineering.Get("id"), "stepId", "laptop")))
	if member(member(laptop.Get("flow"), "steps").([]any)[0], "state") != "submitted" {
		t.Fatalf("laptop = %s", stringify(laptop))
	}
	_, err := onbCall(f.api.VerifyStep, aliceToken, core.NewObject("tenantId", f.acme.id, "flowId", engineering.Get("id"), "subjectId", aliceID, "stepId", "laptop"))
	onbExpectCode(t, err, "ACCESS_DENIED")
	report := f.object(onbCall(f.api.Progress, owner, core.NewObject("tenantId", f.acme.id, "flowId", engineering.Get("id"))))
	rows := onboardingObjects(report.Get("members"))
	if len(rows) != 1 || rows[0].Get("complete") != false {
		t.Fatalf("report = %s", stringify(report))
	}
	expectJSON(t, "awaiting", rows[0].Get("awaiting"), `["laptop"]`)
	verified := f.object(onbCall(f.api.VerifyStep, owner, core.NewObject("tenantId", f.acme.id, "flowId", engineering.Get("id"), "subjectId", aliceID, "stepId", "laptop")))
	if member(verified.Get("flow"), "complete") != true {
		t.Fatalf("verified = %s", stringify(verified))
	}
	// Completion groups are applied when she next reads her onboarding.
	mine = f.mine(aliceToken, f.acme.id)
	if mine.Get("pending") != 0.0 || mine.Get("complete") != true {
		t.Fatalf("mine = %s", stringify(mine))
	}
	memberships := f.find("groupMembers", core.NewObject("tenantId", f.acme.id, "groupId", engineers.Get("id")))
	if len(memberships) != 1 || memberships[0].Get("identityId") != aliceID {
		t.Fatalf("memberships = %s", stringify(onboardingList(memberships)))
	}
	for _, action := range []string{"onboarding:step", "onboarding:complete", "onboarding:verify", "onboarding:groups"} {
		if len(f.auditTrail(f.acme.id, action)) == 0 {
			t.Fatalf("%s is audited", action)
		}
	}
}

func TestOnboardingReachesProjectsThroughTheSubtree(t *testing.T) {
	f := newOnbFixture(t, true)
	root := f.credential
	owner := f.acme.credential
	f.object(f.createFlow(root, core.NewObject("tenantId", f.rootID, "name", "Organizations only", "audience", "member",
		"tenantTypes", []any{"organization"}, "steps", onbAckStep("org-only"))))
	f.clock.Add(1)
	f.object(f.createFlow(root, core.NewObject("tenantId", f.rootID, "name", "Everyone", "audience", "member", "steps", onbAckStep("everyone"))))
	f.object(onbCall(f.api.SetSettings, root, core.NewObject("tenantId", f.rootID, "welcomeTitle", "Platform title", "supportUrl", "https://help.example.test")))
	f.clock.Add(1)
	basics := f.object(f.createFlow(owner, core.NewObject("tenantId", f.acme.id, "name", "Acme basics", "audience", "member", "appliesTo", "subtree", "steps", onbAckStep("basics"))))
	f.clock.Add(1)
	apollo := f.createTenant("Apollo", f.acme.id, "project")
	_, err := f.createFlow(apollo.credential, core.NewObject("tenantId", apollo.id, "name", "Below projects", "audience", "member",
		"appliesTo", "descendants", "steps", onbAckStep("nothing")))
	expectError(t, err, "INVALID_INPUT", "project tenants have no descendants; use appliesTo: tenant")
	f.object(f.createFlow(apollo.credential, core.NewObject("tenantId", apollo.id, "name", "Project kickoff", "audience", "member", "steps", onbAckStep("kickoff"))))
	f.object(onbCall(f.api.SetSettings, apollo.credential, core.NewObject("tenantId", apollo.id, "welcomeTitle", "Welcome to Apollo")))
	f.clock.Add(1)
	bob, bobToken := f.member(apollo.id, "bob")

	mine := f.mine(bobToken, apollo.id)
	rows := []any{}
	for _, flow := range onboardingObjects(mine.Get("flows")) {
		rows = append(rows, []any{flow.Get("name"), member(flow.Get("source"), "type")})
	}
	expectJSON(t, "bob's flows", rows, `[["Everyone","root"],["Acme basics","organization"],["Project kickoff","project"]]`)
	welcome := mine.Get("welcome").(*core.Object)
	if welcome.Get("welcomeTitle") != "Welcome to Apollo" || welcome.Get("supportUrl") != "https://help.example.test" || mine.Get("pending") != 3.0 {
		t.Fatalf("mine = %s", stringify(mine))
	}

	// The project switches off the organization's unlocked flow for itself...
	f.object(onbCall(f.api.SetSettings, apollo.credential, core.NewObject("tenantId", apollo.id, "welcomeTitle", "Welcome to Apollo", "disabledFlowIds", []any{basics.Get("id")})))
	expectJSON(t, "flows switched off", onbFlowNames(f.mine(bobToken, apollo.id).Get("flows")), `["Everyone","Project kickoff"]`)
	effective := f.object(onbCall(f.api.Effective, apollo.credential, core.NewObject("tenantId", apollo.id)))
	var basicsEntry *core.Object
	for _, item := range onboardingObjects(effective.Get("memberFlows")) {
		if member(item.Get("flow"), "id") == basics.Get("id") {
			basicsEntry = item
		}
	}
	if basicsEntry == nil || member(basicsEntry.Get("disabledBy"), "tenantId") != apollo.id || basicsEntry.Get("canDisable") != true {
		t.Fatalf("basics = %s", stringify(basicsEntry))
	}
	// ...until the organization locks it.
	f.object(onbCall(f.api.UpdateFlow, owner, core.NewObject("tenantId", f.acme.id, "flowId", basics.Get("id"), "locked", true)))
	expectJSON(t, "locked flow", onbFlowNames(f.mine(bobToken, apollo.id).Get("flows")), `["Everyone","Acme basics","Project kickoff"]`)
	// Re-saving the project's settings quietly drops the switch that no longer applies.
	saved := f.object(onbCall(f.api.SetSettings, apollo.credential, core.NewObject("tenantId", apollo.id, "welcomeTitle", "Welcome to Apollo", "disabledFlowIds", []any{basics.Get("id")})))
	expectJSON(t, "dropped switch", saved.Get("disabledFlowIds"), `[]`)

	f.object(onbCall(f.api.SubmitStep, bobToken, core.NewObject("tenantId", apollo.id, "flowId", basics.Get("id"), "stepId", "basics", "acknowledged", true)))
	report := f.object(onbCall(f.api.Progress, owner, core.NewObject("tenantId", f.acme.id, "flowId", basics.Get("id"))))
	expectJSON(t, "descendants", report.Get("descendants"), `[{"tenant":{"tenantId":"`+apollo.id+`","name":"Apollo","type":"project"},"people":2,"complete":1}]`)
	// A flow inherited from above is reported at the project for its own people.
	projectReport := f.object(onbCall(f.api.Progress, apollo.credential, core.NewObject("tenantId", apollo.id, "flowId", basics.Get("id"))))
	reported := projectReport.Get("flow").(*core.Object)
	if reported.Get("inherited") != true || member(reported.Get("source"), "type") != "organization" {
		t.Fatalf("project report = %s", stringify(projectReport))
	}
	found := false
	for _, row := range onboardingObjects(projectReport.Get("members")) {
		if member(row.Get("identity"), "id") == bob.Get("id") && row.Get("complete") == true {
			found = true
		}
	}
	if !found {
		t.Fatalf("bob is reported complete: %s", stringify(projectReport))
	}

	// An organization's subtree flow fills its own people's attributes, never a project member's.
	directory := f.object(f.createFlow(owner, core.NewObject("tenantId", f.acme.id, "name", "Directory profile", "audience", "member", "appliesTo", "subtree",
		"steps", onbSteps(core.NewObject("id", "title", "kind", "form", "title", "Your title",
			"fields", []any{core.NewObject("name", "title", "label", "Title", "type", "text", "attribute", "title")})))))
	answered := f.object(onbCall(f.api.SubmitStep, bobToken, core.NewObject("tenantId", apollo.id, "flowId", directory.Get("id"), "stepId", "title",
		"answers", core.NewObject("title", "Engineer"))))
	if member(answered.Get("flow"), "complete") != true || len(answered.Get("attributesFilled").([]any)) != 0 {
		t.Fatalf("answered = %s", stringify(answered))
	}
	if attributes := f.record("identities", jsString(bob.Get("id"))).Get("attributes"); truthy(attributes) && attributes.(*core.Object).Len() > 0 {
		t.Fatalf("a project member's attributes are never written: %s", stringify(attributes))
	}
}

func TestOnboardingTenantSetupChecklists(t *testing.T) {
	f := newOnbFixture(t, false)
	root := f.credential
	owner := f.acme.credential
	// Tenants record creation on the wall clock; move the test clock past Acme's creation.
	f.clock.Add(60_000)
	setup := f.object(f.createFlow(root, core.NewObject("tenantId", f.rootID, "name", "Organization setup", "audience", "tenant",
		"tenantTypes", []any{"organization"}, "includeExisting", true,
		"steps", onbSteps(
			core.NewObject("id", "team", "kind", "check", "title", "Invite your team", "check", "members", "minimum", 2.0),
			core.NewObject("id", "alias", "kind", "check", "title", "Choose a sign-in alias", "check", "slug"),
			core.NewObject("id", "company", "kind", "form", "title", "About your company",
				"fields", []any{core.NewObject("name", "size", "label", "Company size", "type", "select", "options", []any{"1-10", "11-50", "51+"}, "required", true)}),
			core.NewObject("id", "kyc", "kind", "task", "title", "Business verification", "verification", "admin"),
			core.NewObject("id", "sso", "kind", "check", "title", "Connect SSO", "check", "sso", "optional", true),
		))))
	// Flows for projects, and flows that ask only organizations created from now on, leave Acme alone.
	f.object(f.createFlow(root, core.NewObject("tenantId", f.rootID, "name", "Project setup", "audience", "tenant",
		"tenantTypes", []any{"project"}, "includeExisting", true, "steps", onbSteps(core.NewObject("id", "p", "kind", "task", "title", "Project task")))))
	f.object(f.createFlow(root, core.NewObject("tenantId", f.rootID, "name", "New organizations", "audience", "tenant",
		"steps", onbSteps(core.NewObject("id", "n", "kind", "task", "title", "New task")))))

	state := f.object(onbCall(f.api.Setup, owner, core.NewObject("tenantId", f.acme.id)))
	expectJSON(t, "setup flows", onbFlowNames(state.Get("flows")), `["Organization setup"]`)
	rows := []any{}
	for _, step := range onboardingObjects(member(state.Get("flows").([]any)[0], "steps")) {
		rows = append(rows, []any{step.Get("id"), step.Get("state"), step.Get("detail")})
	}
	expectJSON(t, "setup steps", rows, `[["team","pending","1 of 2 members"],["alias","pending","No sign-in alias yet"],["company","pending",null],["kyc","pending",null],["sso","pending","0 of 1 SSO connection"]]`)
	if state.Get("pending") != 1.0 || state.Get("complete") != false {
		t.Fatalf("state = %s", stringify(state))
	}

	// Checks follow the organization's real state.
	_, aliceToken := f.member(f.acme.id, "alice")
	f.call(f.tenants().SetSlug(f.ctx, owner, Input[apitypes.TenantsSetSlugInput](core.NewObject("tenantId", f.acme.id, "slug", "acme"))))
	_, err := onbCall(f.api.SubmitSetupStep, owner, core.NewObject("tenantId", f.acme.id, "flowId", setup.Get("id"), "stepId", "team"))
	expectError(t, err, "INVALID_INPUT", "This step completes when the organization’s setup meets it")
	f.object(onbCall(f.api.SubmitSetupStep, owner, core.NewObject("tenantId", f.acme.id, "flowId", setup.Get("id"), "stepId", "company",
		"answers", core.NewObject("size", "11-50"))))
	f.object(onbCall(f.api.SubmitSetupStep, owner, core.NewObject("tenantId", f.acme.id, "flowId", setup.Get("id"), "stepId", "kyc")))
	// People without iam:onboarding:manage cannot complete setup.
	_, err = onbCall(f.api.SubmitSetupStep, aliceToken, core.NewObject("tenantId", f.acme.id, "flowId", setup.Get("id"), "stepId", "company",
		"answers", core.NewObject("size", "1-10")))
	onbExpectCode(t, err, "ACCESS_DENIED")

	// The platform sees every organization's setup, with its answers, and verifies the task.
	report := f.object(onbCall(f.api.Progress, root, core.NewObject("tenantId", f.rootID, "flowId", setup.Get("id"))))
	tenants := onboardingObjects(report.Get("tenants"))
	if len(tenants) != 1 {
		t.Fatalf("report = %s", stringify(report))
	}
	row := tenants[0]
	if member(row.Get("tenant"), "tenantId") != f.acme.id || member(row.Get("tenant"), "name") != "Acme" || row.Get("complete") != false ||
		row.Get("done") != 3.0 || row.Get("total") != 4.0 {
		t.Fatalf("row = %s", stringify(row))
	}
	expectJSON(t, "awaiting", row.Get("awaiting"), `["kyc"]`)
	expectJSON(t, "answers", row.Get("answers"), `{"company":{"size":"11-50"}}`)
	f.object(onbCall(f.api.VerifyStep, root, core.NewObject("tenantId", f.rootID, "flowId", setup.Get("id"), "subjectId", f.acme.id, "stepId", "kyc",
		"approve", false, "note", "Upload the registration certificate")))
	state = f.object(onbCall(f.api.Setup, owner, core.NewObject("tenantId", f.acme.id)))
	var kyc *core.Object
	for _, step := range onboardingObjects(member(state.Get("flows").([]any)[0], "steps")) {
		if step.Get("id") == "kyc" {
			kyc = step
		}
	}
	if kyc.Get("state") != "rejected" || kyc.Get("note") != "Upload the registration certificate" {
		t.Fatalf("kyc = %s", stringify(kyc))
	}
	f.object(onbCall(f.api.SubmitSetupStep, owner, core.NewObject("tenantId", f.acme.id, "flowId", setup.Get("id"), "stepId", "kyc")))
	verified := f.object(onbCall(f.api.VerifyStep, root, core.NewObject("tenantId", f.rootID, "flowId", setup.Get("id"), "subjectId", f.acme.id, "stepId", "kyc")))
	flow := verified.Get("flow").(*core.Object)
	if flow.Get("complete") != true || flow.Get("done") != 4.0 || flow.Get("total") != 4.0 {
		t.Fatalf("verified = %s", stringify(verified))
	}
	state = f.object(onbCall(f.api.Setup, owner, core.NewObject("tenantId", f.acme.id)))
	if state.Get("pending") != 0.0 || state.Get("complete") != true {
		t.Fatalf("state = %s", stringify(state))
	}
	if len(f.auditTrail(f.acme.id, "onboarding:complete")) == 0 {
		t.Fatal("the setup's completion is audited")
	}
	if len(f.auditTrail(f.rootID, "onboarding:reject")) != 1 || len(f.auditTrail(f.rootID, "onboarding:verify")) != 1 {
		t.Fatal("the platform's decisions are audited")
	}

	// The organization cannot verify its own setup task: the flow belongs to the platform.
	_, err = onbCall(f.api.VerifyStep, owner, core.NewObject("tenantId", f.acme.id, "flowId", setup.Get("id"), "subjectId", f.acme.id, "stepId", "kyc"))
	expectError(t, err, "NOT_FOUND", "Onboarding flow not found")
}

func TestOnboardingFlowManagement(t *testing.T) {
	f := newOnbFixture(t, true)
	owner := f.acme.credential
	tenantID := f.acme.id
	alice, aliceToken := f.member(tenantID, "alice")
	task := onbSteps(core.NewObject("id", "hello", "kind", "task", "title", "Say hello"))
	_, err := f.createFlow(aliceToken, core.NewObject("tenantId", tenantID, "name", "Mine", "audience", "member", "steps", task))
	onbExpectCode(t, err, "ACCESS_DENIED")
	invalid := func(message string, members ...any) {
		t.Helper()
		body := core.NewObject("tenantId", tenantID, "name", "Invalid", "audience", "member", "steps", task)
		credential := owner
		for index := 0; index+1 < len(members); index += 2 {
			if members[index] == "credential" {
				credential = members[index+1].(core.CredentialInput)
				continue
			}
			body.Set(members[index].(string), members[index+1])
		}
		_, err := f.createFlow(credential, body)
		expectError(t, err, "INVALID_INPUT", message)
	}
	form := func(field *core.Object) []any {
		return onbSteps(core.NewObject("id", "f", "kind", "form", "title", "Form", "fields", []any{field}))
	}
	invalid("steps[0].kind must be one of form, acknowledge, task, agreement, verify-email, mfa, passkey in a member flow",
		"steps", onbSteps(core.NewObject("id", "c", "kind", "check", "title", "Check", "check", "slug")))
	invalid("steps[0].fields[0].attribute favouriteColour is not a declared identity attribute",
		"steps", form(core.NewObject("name", "x", "label", "X", "type", "text", "attribute", "favouriteColour")))
	invalid("steps[0].fields[0].attribute department holds a string; a number field cannot fill it",
		"steps", form(core.NewObject("name", "x", "label", "X", "type", "number", "attribute", "department")))
	invalid("steps[0].fields[0].attribute: a textarea answer cannot fill an attribute",
		"steps", form(core.NewObject("name", "x", "label", "X", "type", "textarea", "attribute", "department")))
	invalid("steps[0].id must use lowercase letters, digits and dashes (at most 40)",
		"steps", onbSteps(core.NewObject("id", "Bad Id", "kind", "task", "title", "Task")))
	invalid("steps must have distinct IDs", "steps", append(append([]any{}, task...), task...))
	invalid("Tenant setup flows apply to descendant tenants", "audience", "tenant", "appliesTo", "tenant")
	invalid("tenantTypes applies to flows that reach descendants", "tenantTypes", []any{"project"})
	invalid("tenantTypes: organization tenants cannot exist below a organization tenant", "appliesTo", "descendants", "tenantTypes", []any{"organization"})
	invalid("completionGroupIds apply to member flows that reach the defining tenant’s own people",
		"credential", f.credential, "tenantId", f.rootID, "appliesTo", "descendants", "completionGroupIds", []any{"group"})

	flow := f.object(f.createFlow(owner, core.NewObject("tenantId", tenantID, "name", "Welcome", "audience", "member", "steps", task)))
	_, err = f.createFlow(owner, core.NewObject("tenantId", tenantID, "name", "welcome", "audience", "member", "steps", task))
	expectError(t, err, "CONFLICT", "An onboarding flow with this name exists")
	renamed := f.object(onbCall(f.api.UpdateFlow, owner, core.NewObject("tenantId", tenantID, "flowId", flow.Get("id"), "name", "Welcome aboard")))
	if renamed.Get("version") != 1.0 || renamed.Get("uniqueKey") != "name:welcome aboard" {
		t.Fatalf("renamed = %s", stringify(renamed))
	}
	_, err = onbCall(f.api.UpdateFlow, owner, core.NewObject("tenantId", tenantID, "flowId", flow.Get("id"), "audience", "tenant"))
	expectError(t, err, "INVALID_INPUT", "A flow keeps its audience; create a new flow instead")
	f.object(onbCall(f.api.SubmitStep, aliceToken, core.NewObject("tenantId", tenantID, "flowId", flow.Get("id"), "stepId", "hello")))
	extended := f.object(onbCall(f.api.UpdateFlow, owner, core.NewObject("tenantId", tenantID, "flowId", flow.Get("id"),
		"steps", append(append([]any{}, task...), core.NewObject("id", "coffee", "kind", "task", "title", "Get coffee", "optional", true)))))
	if extended.Get("version") != 2.0 {
		t.Fatalf("extended = %s", stringify(extended))
	}
	// Finished steps stay finished; the new step is optional, so the flow stays complete.
	first := f.mine(aliceToken, tenantID).Get("flows").([]any)[0].(*core.Object)
	if first.Get("complete") != true || first.Get("done") != 1.0 || first.Get("total") != 1.0 {
		t.Fatalf("first = %s", stringify(first))
	}
	listed := onboardingObjects(must(onbCall(f.api.ListFlows, owner, core.NewObject("tenantId", tenantID, "audience", "member"))))
	if len(listed) != 1 || listed[0].Get("name") != "Welcome aboard" {
		t.Fatalf("listed = %s", stringify(onboardingList(listed)))
	}
	if got := f.object(onbCall(f.api.GetFlow, owner, core.NewObject("tenantId", tenantID, "flowId", flow.Get("id")))); got.Get("version") != 2.0 {
		t.Fatalf("got = %s", stringify(got))
	}
	_, err = onbCall(f.api.GetFlow, f.credential, core.NewObject("tenantId", f.rootID, "flowId", flow.Get("id")))
	expectError(t, err, "NOT_FOUND", "Onboarding flow not found")

	// Deleting a person removes their progress, which holds their answers.
	records := func() int { return len(f.find("onboardingProgress", core.NewObject("tenantId", tenantID))) }
	if records() != 1 {
		t.Fatalf("progress records = %d", records())
	}
	_, err = onbCall(f.iam.API.Identities.Delete, owner, core.NewObject("tenantId", tenantID, "identityId", alice.Get("id")))
	requirePorted(t, err)
	if records() != 0 {
		t.Fatal("deleting a person removes their progress")
	}
	second := f.object(onbCall(f.api.DeleteFlow, owner, core.NewObject("tenantId", tenantID, "flowId", flow.Get("id"))))
	expectJSON(t, "deleted", second, `{"deleted":true,"progressRemoved":0}`)

	// A group test names the defining tenant's groups, which people of the tenants below never belong to.
	group := f.object(onbCall(f.iam.API.Groups.Create, owner, core.NewObject("tenantId", tenantID, "name", "Staff")))
	_, err = f.createFlow(owner, core.NewObject("tenantId", tenantID, "name", "Invalid", "audience", "member", "steps", task,
		"appliesTo", "descendants", "rule", core.NewObject("include", []any{core.NewObject("ArrayContains", core.NewObject("identity.groups", group.Get("id")))})))
	onbExpectCode(t, err, "INVALID_INPUT")
}

func TestOnboardingDeleteFlowCleansSettingsAndProgress(t *testing.T) {
	f := newOnbFixture(t, false)
	f.clock.Add(1)
	tour := f.object(f.createFlow(f.credential, core.NewObject("tenantId", f.rootID, "name", "Tour", "audience", "member", "required", false, "steps", onbAckStep("tour"))))
	f.object(onbCall(f.api.SetSettings, f.acme.credential, core.NewObject("tenantId", f.acme.id, "disabledFlowIds", []any{tour.Get("id")})))
	removed := f.object(onbCall(f.api.DeleteFlow, f.credential, core.NewObject("tenantId", f.rootID, "flowId", tour.Get("id"))))
	expectJSON(t, "deleted", removed, `{"deleted":true,"progressRemoved":0}`)
	expectJSON(t, "settings", f.record("onboardingSettings", "settings:"+f.acme.id).Get("disabledFlowIds"), `[]`)
	_, err := onbCall(f.api.SetSettings, f.acme.credential, core.NewObject("tenantId", f.acme.id, "disabledFlowIds", []any{"missing"}))
	expectError(t, err, "INVALID_INPUT", "disabledFlowIds: missing is not an inherited member flow of this tenant")
	_, err = onbCall(f.api.SetSettings, f.acme.credential, core.NewObject("tenantId", f.acme.id, "colour", "blue"))
	expectError(t, err, "INVALID_INPUT", "settings: unknown field colour")
}

func TestOnboardingMemberRoutesOverHTTPAndImpersonation(t *testing.T) {
	f := newOnbFixture(t, false)
	tenantID := f.acme.id
	flow := f.object(f.createFlow(f.acme.credential, core.NewObject("tenantId", tenantID, "name", "Hello", "audience", "member",
		"steps", onbSteps(core.NewObject("id", "hello", "kind", "acknowledge", "title", "Hello", "content", "Hi")))))
	f.clock.Add(1)
	alice, aliceToken := f.member(tenantID, "alice")
	post := func(path, body string) *core.Object {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "http://localhost:3000/api/iam/"+path, strings.NewReader(body))
		request.Header.Set("content-type", "application/json")
		request.Header.Set("x-better-iam", "1")
		request.Header.Set("authorization", "Bearer "+aliceToken.Token)
		response := f.iam.Handle(request)
		parsed, err := core.ParseJSON(response.Body)
		if err != nil || response.Status != 200 {
			t.Fatalf("%s: %d %s", path, response.Status, response.Body)
		}
		return parsed.(*core.Object).Get("data").(*core.Object)
	}
	expectJSON(t, "mine over HTTP", onbFlowNames(post("onboarding/mine", `{"tenantId":"`+tenantID+`"}`).Get("flows")), `["Hello"]`)
	done := post("onboarding/submitStep", `{"tenantId":"`+tenantID+`","flowId":"`+jsString(flow.Get("id"))+`","stepId":"hello","acknowledged":true}`)
	if member(done.Get("flow"), "complete") != true {
		t.Fatalf("done = %s", stringify(done))
	}

	f.call(f.tenants().SetAuthPolicy(f.ctx, f.acme.credential, Input[apitypes.TenantsSetAuthPolicyInput](core.NewObject(
		"tenantId", tenantID, "authPolicy", core.NewObject("allowImpersonation", true)))))
	view, err := onbCall(f.iam.API.Identities.Impersonate, f.signIn(tenantID, "Acme@example.test"), core.NewObject(
		"tenantId", tenantID, "identityId", alice.Get("id"), "reason", "Support ticket 42"))
	requirePorted(t, err)
	viewToken := core.CredentialInput{Token: jsString(member(view, "token"))}
	_, err = onbCall(f.api.SubmitStep, viewToken, core.NewObject("tenantId", tenantID, "flowId", flow.Get("id"), "stepId", "hello", "acknowledged", true))
	expectError(t, err, "IMPERSONATION_RESTRICTED", "Onboarding steps cannot be completed while impersonating")
	// An administrator viewing as the member sees their checklist.
	if first := f.mine(viewToken, tenantID).Get("flows").([]any)[0]; member(first, "complete") != true {
		t.Fatalf("the view shows the checklist: %s", stringify(first))
	}
}

func TestOnboardingParsers(t *testing.T) {
	attributes := core.NewObject("department", "string")
	parsed, err := ParseSteps(onbSteps(
		core.NewObject("id", "about", "kind", "form", "title", " About ", "optional", true, "fields", []any{
			core.NewObject("name", "size", "label", " Size ", "type", "number", "min", 1.0, "max", 10.0, "required", true),
			core.NewObject("name", "when", "label", "When", "type", "date"),
			core.NewObject("name", "site", "label", "Site", "type", "url"),
			core.NewObject("name", "ok", "label", "OK", "type", "boolean"),
			core.NewObject("name", "notes", "label", "Notes", "type", "textarea", "maxLength", 20.0),
		}),
	), "member", attributes)
	if err != nil {
		t.Fatal(err)
	}
	step := parsed[0]
	expectJSON(t, "step", step, `{"id":"about","kind":"form","title":"About","optional":true,"fields":[{"name":"size","label":"Size","type":"number","required":true,"min":1,"max":10},{"name":"when","label":"When","type":"date"},{"name":"site","label":"Site","type":"url"},{"name":"ok","label":"OK","type":"boolean"},{"name":"notes","label":"Notes","type":"textarea","maxLength":20}]}`)
	answers, err := ParseAnswers(step, core.NewObject("size", 3.0, "when", "2024-02-29", "site", " https://acme.test/x ", "ok", false, "notes", "two\nlines"))
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, "answers", answers, `{"size":3,"when":"2024-02-29","site":"https://acme.test/x","ok":false,"notes":"two\nlines"}`)
	for _, c := range []struct {
		answers *core.Object
		message string
	}{
		{core.NewObject(), "Size is required"},
		{core.NewObject("size", 11.0), "Size is not valid"},
		{core.NewObject("size", 1.0, "when", "2023-02-29"), "When is not valid"},
		{core.NewObject("size", 1.0, "site", "ftp://acme.test"), "Site is not valid"},
		{core.NewObject("size", 1.0, "notes", "bad\x01"), "Invalid Notes"},
		{core.NewObject("size", 1.0, "extra", 1.0), "Unknown answer extra"},
	} {
		_, err := ParseAnswers(step, c.answers)
		expectError(t, err, "INVALID_INPUT", c.message)
	}
	_, err = ParseAnswers(step, "nope")
	expectError(t, err, "INVALID_INPUT", "answers must be an object")
	_, err = ParseSteps(onbSteps(core.NewObject("id", "x", "kind", "task", "title", "X", "content", "c")), "member", attributes)
	expectError(t, err, "INVALID_INPUT", "steps[0].content does not apply to task steps")
	_, err = ParseSteps(onbSteps(core.NewObject("id", "x", "kind", "check", "title", "X", "check", "slug", "minimum", 3.0)), "tenant", attributes)
	expectError(t, err, "INVALID_INPUT", "steps[0].minimum applies to members and owners checks")
	_, err = ParseSteps([]any{}, "member", attributes)
	expectError(t, err, "INVALID_INPUT", "steps must list 1-25 steps")

	settings, err := ParseSettings(core.NewObject("tenantId", "t", "welcomeTitle", " Hi ", "supportEmail", " Help@Acme.Test ", "supportUrl", "", "disabledFlowIds", []any{"b", "a", "b"}))
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, "settings", settings, `{"welcomeTitle":"Hi","supportEmail":"help@acme.test","disabledFlowIds":["a","b"]}`)
	_, err = ParseSettings(core.NewObject("supportUrl", "mailto:help@acme.test"))
	expectError(t, err, "INVALID_INPUT", "supportUrl must be an http(s) URL")

	// Check steps describe the fact behind them.
	tenant := core.NewObject("id", "t", "name", "T", "type", "organization")
	flow := core.NewObject("id", "f", "name", "F", "audience", "tenant", "required", true, "locked", false, "version", 1.0, "steps", onbSteps(
		core.NewObject("id", "owners", "kind", "check", "title", "Owners", "check", "owners", "minimum", 1.0),
		core.NewObject("id", "mfa", "kind", "check", "title", "MFA", "check", "mfa-policy"),
		core.NewObject("id", "domains", "kind", "check", "title", "Domains", "check", "verified-domain"),
	))
	status, err := EvaluateFlow(onboardingCandidate(flow, tenant, true, 1), nil, core.NewObject("tenant", core.NewObject("owners", 3.0, "mfa-policy", true)), nil)
	if err != nil {
		t.Fatal(err)
	}
	details := []any{}
	for _, item := range onboardingObjects(status.Get("steps")) {
		details = append(details, item.Get("detail"))
	}
	expectJSON(t, "details", details, `["1 of 1 owner","MFA is required","0 of 1 verified domain"]`)
	expectJSON(t, "status", []any{status.Get("done"), status.Get("total"), status.Get("complete")}, `[2,3,false]`)
}
