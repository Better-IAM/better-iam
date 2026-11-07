package server

// Ports of tests/compliance.test.ts (packages/server/src/compliance.ts and api/compliance.ts) on the orgFixture of
// api_roles_test.go, plus unit tests of the check helpers. Steps that reach another unit's NOT_IMPLEMENTED stub skip
// the rest of the test (requirePorted).

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const complianceMinute = 60_000

// complianceIn is an input of the fixture's organization with extra members.
func (f *orgFixture) complianceIn(members ...any) *core.Object {
	input := core.NewObject("tenantId", f.tenantID)
	input.Assign(core.NewObject(members...))
	return input
}

// complianceRootSignIn is a fresh root administrator session (MFA), for steps after the first one expired.
func (f *orgFixture) complianceRootSignIn() core.CredentialInput {
	f.t.Helper()
	roots := f.find("identities", core.NewObject("tenantId", f.rootID, "email", "root@example.test"))
	if len(roots) == 0 {
		f.t.Fatal("no root identity")
	}
	issued, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.IssueSession(ctx, tx, roots[0], auth.IssueSessionOptions{Mfa: true, Method: "password"})
	})
	requirePorted(f.t, err)
	return core.CredentialInput{Token: jsString(issued.Get("token"))}
}

func (f *orgFixture) complianceEvaluate(credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	return f.object(f.iam.API.Compliance.Evaluate(f.ctx, credential, Input[apitypes.ComplianceEvaluateInput](f.complianceIn(members...))))
}

func (f *orgFixture) complianceResults(credential core.CredentialInput, members ...any) []*core.Object {
	f.t.Helper()
	return f.items(f.iam.API.Compliance.ListResults(f.ctx, credential, Input[apitypes.ComplianceListResultsInput](f.complianceIn(members...))))
}

func (f *orgFixture) complianceStatus(credential core.CredentialInput, framework string) []*core.Object {
	f.t.Helper()
	return f.items(f.iam.API.Compliance.Status(f.ctx, credential, Input[apitypes.ComplianceStatusInput](f.complianceIn("framework", framework))))
}

func (f *orgFixture) createComplianceControl(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := f.iam.API.Compliance.CreateControl(f.ctx, credential, Input[apitypes.ComplianceCreateControlInput](f.complianceIn(members...)))
	result, _ := out.Value.(*core.Object)
	return result, err
}

func (f *orgFixture) createComplianceException(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := f.iam.API.Compliance.CreateException(f.ctx, credential, Input[apitypes.ComplianceCreateExceptionInput](f.complianceIn(members...)))
	result, _ := out.Value.(*core.Object)
	return result, err
}

// resultsByKey indexes evaluate's results by control key.
func resultsByKey(evaluation *core.Object) map[string]*core.Object {
	byKey := map[string]*core.Object{}
	for _, item := range evaluation.Get("results").([]any) {
		result := item.(*core.Object)
		byKey[jsString(result.Get("controlKey"))] = result
	}
	return byKey
}

// requirementStatus is the status of one requirement of a framework status.
func requirementStatus(t *testing.T, status *core.Object, id string) any {
	t.Helper()
	for _, item := range status.Get("requirements").([]any) {
		if member(item, "id") == id {
			return member(item, "status")
		}
	}
	t.Fatalf("no requirement %s", id)
	return nil
}

func findingSubjects(result *core.Object) []string {
	var subjects []string
	for _, finding := range result.Get("findings").([]any) {
		subjects = append(subjects, jsString(member(finding, "subject")))
	}
	return subjects
}

func expectComplianceCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got no error", code)
	}
	if got := errorCodeOf(t, err); got != code {
		if got == "NOT_IMPLEMENTED" {
			t.Skipf("blocked by another unit: %v", err)
		}
		t.Fatalf("expected %s, got %s (%v)", code, got, err)
	}
}

func TestComplianceAdoptEvaluateAndStatus(t *testing.T) {
	f := newOrgFixture(t, nil)
	api := f.iam.API.Compliance
	adopted := f.object(api.AdoptFramework(f.ctx, f.owner, Input[apitypes.ComplianceAdoptFrameworkInput](f.complianceIn("framework", "soc2"))))
	var keys []string
	for _, control := range adopted.Get("controls").([]any) {
		keys = append(keys, jsString(member(control, "key")))
	}
	if !containsString(keys, "mfa-coverage") {
		t.Fatalf("adopted %v", keys)
	}
	// Adopting a second framework reuses the controls and adds its mappings.
	f.object(api.AdoptFramework(f.ctx, f.owner, Input[apitypes.ComplianceAdoptFrameworkInput](f.complianceIn("framework", "iso27001"))))
	controls := f.items(api.ListControls(f.ctx, f.owner, Input[apitypes.ComplianceListControlsInput](f.complianceIn())))
	var coverage *core.Object
	for _, control := range controls {
		if control.Get("key") == "mfa-coverage" {
			coverage = control
		}
	}
	mappings := stringList(coverage.Get("mappings"))
	if !containsString(mappings, "soc2:CC6.1") || !containsString(mappings, "iso27001:8.5") {
		t.Fatalf("mappings %v", mappings)
	}

	f.complianceMember("alice")
	evaluation := f.complianceEvaluate(f.owner)
	byKey := resultsByKey(evaluation)
	// Nobody enrolled a second factor and the policy does not require one.
	for key, want := range map[string]string{
		"mfa-coverage":         "fail",
		"mfa-enforced":         "fail",
		"audit-integrity":      "pass",
		"owner-redundancy":     "warn",
		"separation-of-duties": "warn",
		"access-reviews":       "fail",
	} {
		if got := byKey[key].Get("status"); got != want {
			t.Fatalf("%s: status %v (%v), want %s", key, got, byKey[key].Get("summary"), want)
		}
	}
	run := evaluation.Get("run").(*core.Object)
	if jsNumber(member(run.Get("counts"), "fail")) <= 0 {
		t.Fatalf("counts %s", core.MustStringify(run.Get("counts")))
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(jsString(run.Get("digest"))) {
		t.Fatalf("digest %v", run.Get("digest"))
	}
	// The evaluation returns counts; findings are read separately.
	if byKey["mfa-coverage"].Has("findings") {
		t.Fatal("evaluate answered findings")
	}

	soc2 := f.complianceStatus(f.owner, "soc2")[0]
	if member(soc2.Get("framework"), "id") != "soc2" {
		t.Fatalf("framework %s", core.MustStringify(soc2.Get("framework")))
	}
	if got := requirementStatus(t, soc2, "CC7.2"); got != "pass" {
		t.Fatalf("CC7.2 %v", got)
	}
	if got := requirementStatus(t, soc2, "CC6.1"); got != "fail" {
		t.Fatalf("CC6.1 %v", got)
	}
	if jsNumber(soc2.Get("covered")) != float64(len(soc2.Get("requirements").([]any))) {
		t.Fatalf("covered %v", soc2.Get("covered"))
	}
	_, err := api.Status(f.ctx, f.owner, Input[apitypes.ComplianceStatusInput](f.complianceIn("framework", "nope")))
	expectComplianceCode(t, err, "INVALID_INPUT")

	// Manual evaluations are limited to one a minute per tenant.
	_, err = api.Evaluate(f.ctx, f.owner, Input[apitypes.ComplianceEvaluateInput](f.complianceIn()))
	expectComplianceCode(t, err, "RATE_LIMITED")
	f.clock.Add(complianceMinute + 1)

	// Requiring MFA fixes the policy control; the next evaluation records the recovery.
	owner := f.ownerSignIn()
	f.object(f.iam.API.Tenants.SetAuthPolicy(f.ctx, owner, Input[apitypes.TenantsSetAuthPolicyInput](f.complianceIn("authPolicy", core.NewObject("requireMfa", true)))))
	// Owners without a second factor are now refused; the (MFA) root administrator carries on.
	second := f.complianceEvaluate(f.credential, "controlKeys", []any{"mfa-enforced"})
	results := second.Get("results").([]any)
	if len(results) != 1 || member(results[0], "controlKey") != "mfa-enforced" || member(results[0], "status") != "pass" {
		t.Fatalf("second evaluation %s", core.MustStringify(results))
	}
	if len(f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "compliance:control:recover"))) == 0 {
		t.Fatal("no compliance:control:recover event")
	}
	// A control failing on its first run is recorded too.
	if len(f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "compliance:control:fail"))) == 0 {
		t.Fatal("no compliance:control:fail event")
	}

	// Disabling a mapped control keeps its requirements from passing; old results turn stale after three days.
	var audit *core.Object
	for _, control := range f.items(api.ListControls(f.ctx, f.credential, Input[apitypes.ComplianceListControlsInput](f.complianceIn()))) {
		if control.Get("key") == "audit-integrity" {
			audit = control
		}
	}
	f.object(api.UpdateControl(f.ctx, f.credential, Input[apitypes.ComplianceUpdateControlInput](f.complianceIn("controlId", audit.Get("id"), "enabled", false))))
	after := f.complianceStatus(f.credential, "soc2")[0]
	if got := requirementStatus(t, after, "CC7.2"); got != "disabled" {
		t.Fatalf("CC7.2 after disabling %v", got)
	}
	f.clock.Add(4 * int64(dayMs))
	stale := f.complianceStatus(f.credential, "soc2")[0]
	if got := requirementStatus(t, stale, "CC6.1"); got != "not-evaluated" {
		t.Fatalf("CC6.1 when stale %v", got)
	}
}

func TestComplianceExceptionsNeedASecondPerson(t *testing.T) {
	f := newOrgFixture(t, nil)
	api := f.iam.API.Compliance
	_, err := f.createComplianceControl(f.owner, "key", "inactive-90", "name", "Inactive accounts", "checkId", "inactive-accounts",
		"params", core.NewObject("days", 30.0), "mappings", []any{"internal:POL-7"})
	requirePorted(t, err)
	alice := f.complianceMember("alice")
	f.clock.Add(40 * int64(dayMs))
	owner := f.ownerSignIn()
	first := f.complianceEvaluate(owner)
	if got := member(first.Get("results").([]any)[0], "status"); got != "fail" {
		t.Fatalf("first status %v", got)
	}
	// The owner signed in just now; Alice never did. Stored findings carry IDs; directory readers see names.
	result := f.complianceResults(owner, "controlKey", "inactive-90")[0]
	want := `[{"subject":"identity:` + jsString(alice.Get("id")) + `","detail":"Has never signed in","name":"alice@acme.test"}]`
	if got := core.MustStringify(result.Get("findings")); got != want {
		t.Fatalf("findings %s, want %s", got, want)
	}
	exception, err := f.createComplianceException(owner, "controlKey", "inactive-90", "subject", "identity:"+jsString(alice.Get("id")),
		"reason", "On parental leave until December", "expiresAt", f.now()+10*dayMs)
	requirePorted(t, err)
	if exception.Get("status") != "pending" {
		t.Fatalf("exception %s", core.MustStringify(exception))
	}
	// Pending exceptions cover nothing, and their author cannot approve them.
	f.clock.Add(complianceMinute + 1)
	pending := f.ownerSignIn()
	if got := member(f.complianceEvaluate(pending).Get("results").([]any)[0], "status"); got != "fail" {
		t.Fatalf("status with a pending exception %v", got)
	}
	_, err = api.ApproveException(f.ctx, pending, Input[apitypes.ComplianceApproveExceptionInput](f.complianceIn("exceptionId", exception.Get("id"))))
	expectComplianceCode(t, err, "ACCESS_DENIED")
	// The root session from the fixture's start has expired by now.
	root := f.complianceRootSignIn()
	f.object(api.ApproveException(f.ctx, root, Input[apitypes.ComplianceApproveExceptionInput](f.complianceIn("exceptionId", exception.Get("id")))))
	f.clock.Add(complianceMinute + 1)
	excepted := member(f.complianceEvaluate(root).Get("results").([]any)[0], "status")
	if excepted != "pass" {
		t.Fatalf("status with an approved exception %v", excepted)
	}
	latest := f.complianceResults(root, "controlKey", "inactive-90")[0]
	if latest.Get("rawStatus") != "fail" || latest.Get("excepted") != 1.0 {
		t.Fatalf("excepted result %s", core.MustStringify(latest))
	}
	f.clock.Add(11 * int64(dayMs))
	later := f.ownerSignIn()
	if got := member(f.complianceEvaluate(later).Get("results").([]any)[0], "status"); got != "fail" {
		t.Fatalf("status after expiry %v", got)
	}
	// Revoking keeps the record as history.
	f.object(api.RevokeException(f.ctx, later, Input[apitypes.ComplianceRevokeExceptionInput](f.complianceIn("exceptionId", exception.Get("id")))))
	exceptions := f.items(api.ListExceptions(f.ctx, later, Input[apitypes.ComplianceListExceptionsInput](f.complianceIn())))
	if len(exceptions) != 1 || exceptions[0].Get("id") != exception.Get("id") || exceptions[0].Get("status") != "revoked" || exceptions[0].Get("active") != false {
		t.Fatalf("exceptions %s", core.MustStringify(objectList(exceptions)))
	}
	// Nobody excepts their own finding, and audit-chain breaks are never excepted.
	_, err = f.createComplianceException(later, "controlKey", "inactive-90", "subject", "identity:"+f.ownerID, "reason", "Me", "expiresAt", f.now()+dayMs)
	expectComplianceCode(t, err, "ACCESS_DENIED")
	_, err = f.createComplianceControl(later, "key", "audit", "name", "Audit", "checkId", "audit-integrity")
	requirePorted(t, err)
	_, err = f.createComplianceException(later, "controlKey", "audit", "subject", "tenant:"+f.tenantID+":audit-chain", "reason", "Known", "expiresAt", f.now()+dayMs)
	expectComplianceCode(t, err, "INVALID_INPUT")
	_, err = f.createComplianceControl(later, "key", "bad", "name", "Bad", "checkId", "inactive-accounts", "params", core.NewObject("days", 1.0))
	expectComplianceCode(t, err, "INVALID_INPUT")
}

func TestComplianceCountsEveryPathToFullAdministration(t *testing.T) {
	f := newOrgFixture(t, nil)
	_, err := f.createComplianceControl(f.owner, "key", "admins", "name", "Admins", "checkId", "privileged-access", "params", core.NewObject("maxHolders", 1.0))
	requirePorted(t, err)
	// Full access to the iam service on iam/* (not the literal `*`), behind an MFA condition, inherited by "Ops".
	admin := f.createRole(f.owner, "name", "Admin", "document", core.NewObject("version", 1.0, "statements", []any{core.NewObject(
		"effect", "allow", "actions", []any{"iam:*"}, "resources", []any{"iam/*"},
		"conditions", core.NewObject("Bool", core.NewObject("principal.mfa", true)),
	)}))
	ops := f.createRole(f.owner, "name", "Ops", "permissions", []any{"iam:audit:read"}, "inherits", []any{admin.Get("id")})
	reader := f.createRole(f.owner, "name", "Reader", "permissions", []any{"iam:identities:read"})
	alice, bob, carol, dave := f.complianceMember("alice"), f.complianceMember("bob"), f.complianceMember("carol"), f.complianceMember("dave")
	f.complianceBind(ops.Get("id"), alice.Get("id"))
	f.complianceBind(admin.Get("id"), bob.Get("id"), "eligible", true)
	f.complianceBind(admin.Get("id"), carol.Get("id"), "eligible", true, "requireApproval", true)
	f.complianceBind(reader.Get("id"), dave.Get("id"))
	f.complianceEvaluate(f.owner)
	result := f.complianceResults(f.owner, "controlKey", "admins")[0]
	subjects := findingSubjects(result)
	// The owner, Alice (through the inherited role) and Bob (eligible without approval); not Carol or Dave.
	for _, person := range []*core.Object{alice, bob} {
		if !containsString(subjects, "identity:"+jsString(person.Get("id"))) {
			t.Fatalf("missing %v in %v", person.Get("name"), subjects)
		}
	}
	for _, person := range []*core.Object{carol, dave} {
		if containsString(subjects, "identity:"+jsString(person.Get("id"))) {
			t.Fatalf("unexpected %v in %v", person.Get("name"), subjects)
		}
	}
	metrics := result.Get("metrics").(*core.Object)
	if metrics.Get("holders") != 3.0 || metrics.Get("eligibleWithApproval") != 1.0 {
		t.Fatalf("metrics %s", core.MustStringify(metrics))
	}
	if result.Get("status") != "fail" {
		t.Fatalf("status %v", result.Get("status"))
	}
}

func TestComplianceDoesNotCountReviewsNobodyDecided(t *testing.T) {
	f := newOrgFixture(t, nil)
	_, err := f.createComplianceControl(f.owner, "key", "reviews", "name", "Reviews", "checkId", "access-reviews")
	requirePorted(t, err)
	reader := f.createRole(f.owner, "name", "Reader", "permissions", []any{"iam:identities:read"})
	alice := f.complianceMember("alice")
	f.complianceBind(reader.Get("id"), alice.Get("id"))
	campaign := f.object(f.iam.API.Certifications.Create(f.ctx, f.owner, Input[apitypes.CertificationsCreateInput](f.complianceIn("name", "Q3"))))
	f.object(f.iam.API.Certifications.Close(f.ctx, f.owner, Input[apitypes.CertificationsCloseInput](f.complianceIn("campaignId", campaign.Get("id")))))
	f.complianceEvaluate(f.owner)
	result := f.complianceResults(f.owner, "controlKey", "reviews")[0]
	metrics := result.Get("metrics").(*core.Object)
	if result.Get("status") != "fail" || metrics.Get("qualifying") != 0.0 || metrics.Get("lastDecidedPercent") != 0.0 {
		t.Fatalf("result %s", core.MustStringify(result))
	}
	if got := findingSubjects(result)[0]; got != "tenant:"+f.tenantID+":no-review" {
		t.Fatalf("first finding %s", got)
	}
}

func TestComplianceSignedEvidence(t *testing.T) {
	f := newOrgFixture(t, nil)
	api := f.iam.API.Compliance
	f.object(api.AdoptFramework(f.ctx, f.owner, Input[apitypes.ComplianceAdoptFrameworkInput](f.complianceIn("framework", "nist-800-53"))))
	f.complianceEvaluate(f.owner)
	exported := f.object(api.ExportEvidence(f.ctx, f.owner, Input[apitypes.ComplianceExportEvidenceInput](f.complianceIn("framework", "nist-800-53"))))
	// What an auditor receives: the pack as JSON.
	pack := must(core.ParseJSON([]byte(core.MustStringify(exported)))).(*core.Object)
	if got := core.MustStringify(pack.Get("framework")); got != `{"id":"nist-800-53","name":"NIST SP 800-53 Rev. 5"}` {
		t.Fatalf("framework %s", got)
	}
	for _, control := range pack.Get("controls").([]any) {
		if isUndefined(member(control, "result")) {
			t.Fatalf("control without a result %s", core.MustStringify(control))
		}
	}
	if jsNumber(member(pack.Get("auditHead"), "sequence")) <= 0 {
		t.Fatalf("audit head %s", core.MustStringify(pack.Get("auditHead")))
	}
	verify := func(members ...any) string {
		t.Helper()
		return core.MustStringify(f.object(api.VerifyEvidence(f.ctx, f.owner, Input[apitypes.ComplianceVerifyEvidenceInput](f.complianceIn(members...)))))
	}
	if got := verify("pack", pack); got != `{"valid":true}` {
		t.Fatalf("verify pack %s", got)
	}
	// Large packs: the digest and signature alone.
	if got := verify("digest", pack.Get("digest"), "signature", pack.Get("signature")); got != `{"valid":true}` {
		t.Fatalf("verify digest %s", got)
	}
	keys := f.object(api.EvidenceKeys(f.ctx, f.owner, Input[apitypes.ComplianceEvidenceKeysInput](f.complianceIn())))
	offline := VerifyEvidencePack(pack, keys)
	if offline.Get("valid") != true || offline.Get("kid") != member(pack.Get("signature"), "kid") {
		t.Fatalf("offline %s", core.MustStringify(offline))
	}
	edited := core.CloneValue(pack).(*core.Object)
	member(edited.Get("controls").([]any)[0], "result").(*core.Object).Set("summary", "Edited after export")
	if got := verify("pack", edited); got != `{"valid":false}` {
		t.Fatalf("verify edited %s", got)
	}
	if got := VerifyEvidencePack(edited, keys); got.Get("valid") != false || got.Get("reason") != "digest mismatch" {
		t.Fatalf("offline edited %s", core.MustStringify(got))
	}
	// The export is anchored in the audit chain with its digest.
	if !strings.Contains(core.MustStringify(objectList(f.find("audit", core.NewObject("tenantId", f.tenantID)))), jsString(pack.Get("digest"))) {
		t.Fatal("the export's digest is not in the audit log")
	}
	// Another tenant's pack is not this tenant's evidence.
	foreign := pack.Spread(core.NewObject("tenant", core.NewObject("id", "other", "name", "Other")))
	if got := verify("pack", foreign); got != `{"valid":false}` {
		t.Fatalf("verify foreign %s", got)
	}
}

func TestComplianceVerifiesTheAuditChainFromACheckpoint(t *testing.T) {
	f := newOrgFixture(t, nil)
	_, err := f.createComplianceControl(f.owner, "key", "audit", "name", "Audit", "checkId", "audit-integrity")
	requirePorted(t, err)
	f.complianceEvaluate(f.owner)
	first := f.complianceResults(f.owner, "controlKey", "audit")[0]
	if first.Get("status") != "pass" {
		t.Fatalf("first %s", core.MustStringify(first))
	}
	verified := jsNumber(member(first.Get("metrics"), "verifiedThrough"))
	f.complianceMember("erin")
	f.clock.Add(complianceMinute + 1)
	f.complianceEvaluate(f.owner)
	second := f.complianceResults(f.owner, "controlKey", "audit")[0]
	if second.Get("status") != "pass" {
		t.Fatalf("second %s", core.MustStringify(second))
	}
	// Only the events since the checkpoint were read.
	through := jsNumber(member(second.Get("metrics"), "verifiedThrough"))
	if checked := jsNumber(member(second.Get("metrics"), "checked")); checked != through-verified {
		t.Fatalf("checked %v, verified %v through %v", checked, verified, through)
	}
	// Tampering after the checkpoint is found.
	err = f.store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		events, err := tx.Find(ctx, "audit", core.NewObject("tenantId", f.tenantID), nil)
		if err != nil {
			return err
		}
		for _, event := range events {
			if jsNumber(coalesce(event.Get("sequence"), 0.0)) > through {
				_, err := tx.Put(ctx, "audit", event.Spread(core.NewObject("action", "edited")))
				return err
			}
		}
		t.Fatal("no event after the checkpoint")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Add(complianceMinute + 1)
	f.complianceEvaluate(f.owner)
	third := f.complianceResults(f.owner, "controlKey", "audit")[0]
	if third.Get("status") != "fail" {
		t.Fatalf("third %s", core.MustStringify(third))
	}
}

func TestComplianceEvaluateAllAndPermissions(t *testing.T) {
	f := newOrgFixture(t, nil)
	api := f.iam.API.Compliance
	f.object(api.AdoptFramework(f.ctx, f.owner, Input[apitypes.ComplianceAdoptFrameworkInput](f.complianceIn("framework", "gdpr"))))
	job, err := f.iam.Compliance.EvaluateAll(f.ctx, nil)
	requirePorted(t, err)
	evaluated := job.Get("evaluated").([]any)
	if len(evaluated) != 1 || member(evaluated[0], "tenantId") != f.tenantID {
		t.Fatalf("evaluated %s", core.MustStringify(job))
	}
	if got := core.MustStringify(job.Get("failed")); got != `[]` {
		t.Fatalf("failed %s", got)
	}
	bobRecord := f.complianceMember("bob")
	bob := f.complianceLogin(bobRecord)
	_, err = api.Evaluate(f.ctx, bob, Input[apitypes.ComplianceEvaluateInput](f.complianceIn()))
	expectComplianceCode(t, err, "ACCESS_DENIED")
	_, err = api.ListControls(f.ctx, bob, Input[apitypes.ComplianceListControlsInput](f.complianceIn()))
	expectComplianceCode(t, err, "ACCESS_DENIED")
}

func TestComplianceCheckParams(t *testing.T) {
	check := CheckByID["session-lifetime"]
	params := must(CheckParams(check, nil))
	if got := core.MustStringify(params); got != `{"maxHours":168,"idleMinutes":1440}` {
		t.Fatalf("defaults %s", got)
	}
	_, err := CheckParams(check, []any{})
	expectError(t, err, "INVALID_INPUT", "params must be an object")
	_, err = CheckParams(check, core.NewObject("other", 1.0))
	expectError(t, err, "INVALID_INPUT", "session-lifetime has no parameter other")
	_, err = CheckParams(check, core.NewObject("maxHours", 0.0))
	expectError(t, err, "INVALID_INPUT", "Invalid params.maxHours")
	effective := must(EffectiveParams(check, core.NewObject("maxHours", 10_000.0, "idleMinutes", "x")))
	if got := core.MustStringify(effective); got != `{"maxHours":720,"idleMinutes":1440}` {
		t.Fatalf("effective %s", got)
	}
	if !exceptionActive(core.NewObject("expiresAt", 10.0), 5) || exceptionActive(core.NewObject("status", "pending", "expiresAt", 10.0), 5) ||
		exceptionActive(core.NewObject("status", "approved", "expiresAt", 5.0), 5) {
		t.Fatal("exceptionActive")
	}
	if id, _ := CheckpointID("t1"); id != "audit:t1" {
		t.Fatalf("checkpoint %s", id)
	}
}

func TestComplianceAdministers(t *testing.T) {
	document := func(actions, resources []any, effect string) *core.Object {
		return core.NewObject("statements", []any{core.NewObject("effect", effect, "actions", actions, "resources", resources)})
	}
	if !Administers([]any{document([]any{"iam:*"}, []any{"iam/*"}, "allow")}, "t1") {
		t.Fatal("iam:* on iam/* administers")
	}
	if Administers([]any{document([]any{"iam:*"}, []any{"iam/*"}, "deny")}, "t1") {
		t.Fatal("a deny does not administer")
	}
	if Administers([]any{document([]any{"iam:bindings:create", "iam:roles:update"}, []any{"*"}, "allow")}, "t1") {
		t.Fatal("two of three probes do not administer")
	}
	if !Administers([]any{core.Undefined, document([]any{"iam:bindings:create", "iam:roles:update", "iam:policies:*"}, []any{"iam/t1"}, "allow")}, "t1") {
		t.Fatal("every probe on the tenant administers")
	}
	if Administers([]any{document([]any{"iam:*"}, []any{"iam/t2"}, "allow")}, "t1") {
		t.Fatal("another tenant's resource does not administer")
	}
}

func TestComplianceEvidencePackOffline(t *testing.T) {
	key := evidenceKey("a deployment secret with at least 32 characters")
	if again := evidenceKey("a deployment secret with at least 32 characters"); again != key {
		t.Fatal("keys are cached per secret")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(key.kid) {
		t.Fatalf("kid %s", key.kid)
	}
	if got := VerifyEvidencePack("text", []any{key.jwk}); got.Get("reason") != "not a pack" {
		t.Fatalf("not a pack %s", core.MustStringify(got))
	}
	if got := VerifyEvidencePack(core.NewObject("format", "x"), []any{key.jwk}); got.Get("reason") != "unsigned" {
		t.Fatalf("unsigned %s", core.MustStringify(got))
	}
	body := core.NewObject("format", "better-iam.compliance-evidence", "version", 2.0)
	digest := evidencePackDigest(body)
	pack := body.Spread(core.NewObject("digest", digest, "signature", core.NewObject("alg", "EdDSA", "kid", key.kid, "value", "AAAA")))
	if got := VerifyEvidencePack(pack, core.NewObject("keys", []any{key.jwk})); got.Get("reason") != "bad signature" {
		t.Fatalf("bad signature %s", core.MustStringify(got))
	}
	if got := VerifyEvidencePack(pack, []any{}); got.Get("reason") != "unknown key" {
		t.Fatalf("unknown key %s", core.MustStringify(got))
	}
}

// complianceMember is organizationFixture member: identities.create as the owner, or, while that path still reaches
// another unit's stub, the person's record written directly (`{name}@acme.test`, created now).
func (f *orgFixture) complianceMember(name string) *core.Object {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID, "email", name+"@acme.test", "name", name, "password", "a strong "+name+" password")
	out, err := f.iam.API.Identities.Create(f.ctx, f.owner, Input[apitypes.IdentitiesCreateInput](input))
	if err == nil {
		return out.Value.(*core.Object)
	}
	if errorCodeOf(f.t, err) != "NOT_IMPLEMENTED" {
		f.t.Fatal(err)
	}
	// The stub may run after the person was committed.
	if existing := f.find("identities", core.NewObject("tenantId", f.tenantID, "email", name+"@acme.test")); len(existing) > 0 {
		return existing[0]
	}
	record := identity(ID(), f.tenantID, "email", name+"@acme.test", "name", name, "createdAt", f.now(), "updatedAt", f.now())
	f.seed("identities", record)
	return record
}

// complianceLogin is a session for a member: a password sign-in, or one issued directly.
func (f *orgFixture) complianceLogin(person *core.Object) core.CredentialInput {
	f.t.Helper()
	issued, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.IssueSession(ctx, tx, person, auth.IssueSessionOptions{Method: "password"})
	})
	requirePorted(f.t, err)
	return core.CredentialInput{Token: jsString(issued.Get("token"))}
}

// complianceBind is bindings.create as the owner, or, while that path still reaches another unit's stub, the binding
// written directly.
func (f *orgFixture) complianceBind(roleID, subjectID any, extra ...any) {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID, "roleId", roleID, "subjectType", "identity", "subjectId", subjectID)
	input.Assign(core.NewObject(extra...))
	_, err := f.iam.API.Bindings.Create(f.ctx, f.owner, Input[apitypes.BindingsCreateInput](input))
	if err == nil {
		return
	}
	if errorCodeOf(f.t, err) != "NOT_IMPLEMENTED" {
		f.t.Fatal(err)
	}
	if existing := f.find("bindings", core.NewObject("tenantId", f.tenantID, "roleId", roleID, "subjectId", subjectID)); len(existing) > 0 {
		return
	}
	record := core.NewObject("id", ID(), "createdAt", f.now())
	record.Assign(input)
	f.seed("bindings", record)
}
