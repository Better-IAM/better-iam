package server

// The secrets vault, after tests/vault.test.ts, tests/vault-security.test.ts and tests/vault-review.test.ts. The
// vault's records, validation and sealing (vault.ts), the KMS keys (kms.ts, api/keys.ts) and a few other modules are
// ported by other units: a step that reaches one of their NOT_IMPLEMENTED stubs ends the test with a skip.
// Organizations, people, roles and bindings are seeded the way their API groups write them.

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	vaultTestHour = 3_600_000.0
	vaultTestDay  = 24 * vaultTestHour
)

type vaultFixture struct {
	*directoryFixture
	tenantID string
	owner    core.CredentialInput
	ownerID  string
}

func newVaultFixture(t *testing.T, mutate func(options *BetterIamOptions)) *vaultFixture {
	t.Helper()
	f := newDirectoryFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}}
		if mutate != nil {
			mutate(options)
		}
	})
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	owners := f.find("identities", core.NewObject("tenantId", tenantID, "owner", true))
	return &vaultFixture{directoryFixture: f, tenantID: tenantID, owner: owner, ownerID: jsString(owners[0].Get("id"))}
}

// vaultSkip ends the test with a skip when err is another unit's NOT_IMPLEMENTED stub.
func vaultSkip(t *testing.T, err error) {
	t.Helper()
	var known *core.IamError
	if errors.As(err, &known) && known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("reached a stub of another unit: %s", known.Message)
	}
}

// memberWith is a member holding a role with the statements, signed in.
func (f *vaultFixture) memberWith(name string, statements ...*core.Object) (*core.Object, core.CredentialInput) {
	f.t.Helper()
	identity, credential := f.person(f.tenantID, name)
	roleID := f.role(f.tenantID, name+" vault role", statements...)
	f.bind(f.tenantID, roleID, "identity", jsString(identity.Get("id")))
	return identity, credential
}

// call runs a vault method with the fixture's tenant.
func (f *vaultFixture) call(method string, credential core.CredentialInput, pairs ...any) (any, error) {
	b := body(append([]any{"tenantId", f.tenantID}, pairs...)...)
	api := f.iam.API.Vault
	ctx := f.ctx
	value := func(out any, err error) (any, error) { return out, err }
	switch method {
	case "create":
		out, err := api.Create(ctx, credential, Input[apitypes.VaultCreateInput](b))
		return value(out.Value, err)
	case "update":
		out, err := api.Update(ctx, credential, Input[apitypes.VaultUpdateInput](b))
		return value(out.Value, err)
	case "delete":
		out, err := api.Delete(ctx, credential, Input[apitypes.VaultDeleteInput](b))
		return value(out.Value, err)
	case "restore":
		out, err := api.Restore(ctx, credential, Input[apitypes.VaultRestoreInput](b))
		return value(out.Value, err)
	case "get":
		out, err := api.Get(ctx, credential, Input[apitypes.VaultGetInput](b))
		return value(out.Value, err)
	case "list":
		out, err := api.List(ctx, credential, Input[apitypes.VaultListInput](b))
		return value(out.Value, err)
	case "reveal":
		out, err := api.Reveal(ctx, credential, Input[apitypes.VaultRevealInput](b))
		return value(out.Value, err)
	case "put":
		out, err := api.Put(ctx, credential, Input[apitypes.VaultPutInput](b))
		return value(out.Value, err)
	case "listVersions":
		out, err := api.ListVersions(ctx, credential, Input[apitypes.VaultListVersionsInput](b))
		return value(out.Value, err)
	case "promote":
		out, err := api.Promote(ctx, credential, Input[apitypes.VaultPromoteInput](b))
		return value(out.Value, err)
	case "setStage":
		out, err := api.SetStage(ctx, credential, Input[apitypes.VaultSetStageInput](b))
		return value(out.Value, err)
	case "setVersionState":
		out, err := api.SetVersionState(ctx, credential, Input[apitypes.VaultSetVersionStateInput](b))
		return value(out.Value, err)
	case "destroyVersion":
		out, err := api.DestroyVersion(ctx, credential, Input[apitypes.VaultDestroyVersionInput](b))
		return value(out.Value, err)
	case "rotate":
		out, err := api.Rotate(ctx, credential, Input[apitypes.VaultRotateInput](b))
		return value(out.Value, err)
	case "checkout":
		out, err := api.Checkout(ctx, credential, Input[apitypes.VaultCheckoutInput](b))
		return value(out.Value, err)
	case "checkin":
		out, err := api.Checkin(ctx, credential, Input[apitypes.VaultCheckinInput](b))
		return value(out.Value, err)
	case "lease":
		out, err := api.Lease(ctx, credential, Input[apitypes.VaultLeaseInput](b))
		return value(out.Value, err)
	case "renewLease":
		out, err := api.RenewLease(ctx, credential, Input[apitypes.VaultRenewLeaseInput](b))
		return value(out.Value, err)
	case "revokeLease":
		out, err := api.RevokeLease(ctx, credential, Input[apitypes.VaultRevokeLeaseInput](b))
		return value(out.Value, err)
	case "listLeases":
		out, err := api.ListLeases(ctx, credential, Input[apitypes.VaultListLeasesInput](b))
		return value(out.Value, err)
	case "listMine":
		out, err := api.ListMine(ctx, credential, Input[apitypes.VaultListMineInput](b))
		return value(out.Value, err)
	case "accessLog":
		out, err := api.AccessLog(ctx, credential, Input[apitypes.VaultAccessLogInput](b))
		return value(out.Value, err)
	case "generate":
		out, err := api.Generate(ctx, credential, Input[apitypes.VaultGenerateInput](body(pairs...)))
		return value(out.Value, err)
	}
	f.t.Fatalf("unknown vault method %s", method)
	return nil, nil
}

// ok runs a vault method that must succeed and returns its object answer.
func (f *vaultFixture) ok(method string, credential core.CredentialInput, pairs ...any) *core.Object {
	f.t.Helper()
	value, err := f.call(method, credential, pairs...)
	vaultSkip(f.t, err)
	if err != nil {
		f.t.Fatalf("vault.%s: %v", method, err)
	}
	object, _ := value.(*core.Object)
	return object
}

// list runs a vault method that must succeed and returns its list answer.
func (f *vaultFixture) list(method string, credential core.CredentialInput, pairs ...any) []*core.Object {
	f.t.Helper()
	value, err := f.call(method, credential, pairs...)
	vaultSkip(f.t, err)
	if err != nil {
		f.t.Fatalf("vault.%s: %v", method, err)
	}
	items, _ := value.([]any)
	objects := make([]*core.Object, len(items))
	for index, item := range items {
		objects[index], _ = item.(*core.Object)
	}
	return objects
}

// fails runs a vault method that must fail with code.
func (f *vaultFixture) fails(code, method string, credential core.CredentialInput, pairs ...any) *core.IamError {
	f.t.Helper()
	_, err := f.call(method, credential, pairs...)
	if code != "NOT_IMPLEMENTED" {
		vaultSkip(f.t, err)
	}
	if err == nil {
		f.t.Fatalf("vault.%s: expected %s, got no error", method, code)
	}
	known := iamError(f.t, err)
	if known.Code != code {
		f.t.Fatalf("vault.%s: expected %s, got %s %q", method, code, known.Code, known.Message)
	}
	return known
}

// job runs one of the runtime's jobs.
func (f *vaultFixture) job(result *core.Object, err error) *core.Object {
	f.t.Helper()
	vaultSkip(f.t, err)
	if err != nil {
		f.t.Fatal(err)
	}
	return result
}

// auditActions is `{action}:{outcome}` of every audit event whose action starts with prefix.
func (f *vaultFixture) auditActions(prefix string) []string {
	actions := []string{}
	for _, event := range f.find("audit", core.NewObject()) {
		if action := jsString(event.Get("action")); strings.HasPrefix(action, prefix) {
			actions = append(actions, action+":"+jsString(event.Get("outcome")))
		}
	}
	return actions
}

func vaultContains(list []string, items ...string) bool {
	for _, item := range items {
		found := false
		for _, entry := range list {
			if entry == item {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func vaultExpect(t *testing.T, label string, got any, want string) {
	t.Helper()
	if text := stringify(got); text != want {
		t.Fatalf("%s = %s, want %s", label, text, want)
	}
}

func TestVaultStoresVersionsMovesStagesRevealsAndLogsAccess(t *testing.T) {
	f := newVaultFixture(t, nil)
	created := f.ok("create", f.owner, "name", "prod/db/password", "description", "Primary database",
		"tags", core.NewObject("environment", "prod", "team", "payments"), "value", "first-password-value")
	vaultExpect(t, "kind", created.Get("kind"), `"static"`)
	vaultExpect(t, "format", created.Get("format"), `"text"`)
	vaultExpect(t, "status", created.Get("status"), `"active"`)
	vaultExpect(t, "stages", created.Get("stages"), `{"current":1}`)
	vaultExpect(t, "latestVersion", created.Get("latestVersion"), `1`)
	vaultExpect(t, "tags", created.Get("tags"), `{"environment":"prod","team":"payments"}`)
	if strings.Contains(stringify(created), "first-password-value") {
		t.Fatal("the view carries the value")
	}
	// Values are sealed at rest.
	if strings.Contains(stringify(f.find("vaultVersions", core.NewObject())), "first-password-value") {
		t.Fatal("the value is stored in the clear")
	}
	name := []any{"name", "prod/db/password"}
	f.ok("put", f.owner, append(name, "value", "second-password-value")...)
	revealed := f.ok("reveal", f.owner, name...)
	vaultExpect(t, "reveal", core.NewObject("version", revealed.Get("version"), "stages", revealed.Get("stages"), "value", revealed.Get("value")),
		`{"version":2,"stages":["current"],"value":"second-password-value"}`)
	vaultExpect(t, "previous", f.ok("reveal", f.owner, append(name, "stage", "previous")...).Get("value"), `"first-password-value"`)

	// Staged values wait for promotion; promote also rolls back.
	staged := f.ok("put", f.owner, append(name, "value", "third-password-value", "stage", "pending")...)
	vaultExpect(t, "staged", core.NewObject("version", staged.Get("version"), "stages", staged.Get("stages")), `{"version":3,"stages":["pending"]}`)
	promoted := f.ok("promote", f.owner, append(name, "version", 3.0)...)
	vaultExpect(t, "promoted stages", promoted.Get("stages"), `{"current":3,"previous":2}`)
	f.ok("promote", f.owner, append(name, "version", 1.0)...)
	vaultExpect(t, "rolled back", f.ok("reveal", f.owner, name...).Get("value"), `"first-password-value"`)

	// Disabled and destroyed versions are not revealed; the current version is protected.
	f.fails("INVALID_TRANSITION", "setVersionState", f.owner, append(name, "version", 1.0, "state", "disabled")...)
	f.ok("setVersionState", f.owner, append(name, "version", 2.0, "state", "disabled")...)
	f.fails("VERSION_DISABLED", "reveal", f.owner, append(name, "version", 2.0)...)
	f.ok("destroyVersion", f.owner, append(name, "version", 3.0)...)
	f.fails("VERSION_DESTROYED", "reveal", f.owner, append(name, "version", 3.0)...)
	versions := f.list("listVersions", f.owner, name...)
	shown := []any{}
	for _, version := range versions {
		shown = append(shown, []any{version.Get("version"), version.Get("state"), version.Get("stages")})
	}
	vaultExpect(t, "versions", shown, `[[3,"destroyed",[]],[2,"disabled",[]],[1,"enabled",["current"]]]`)

	log := f.list("accessLog", f.owner, name...)
	actions := pluck(log, "action")
	sort.Strings(actions)
	// Three successful reveals and three new versions (the refused reveals are not uses).
	vaultExpect(t, "access log", actions, `["put","put","put","reveal","reveal","reveal"]`)
	for _, entry := range log {
		if entry.Get("identityId") != f.ownerID || entry.Get("identityName") != "Owner" {
			t.Fatalf("access entry = %s", stringify(entry))
		}
	}
	if !vaultContains(f.auditActions("vault:"), "vault:create:allow", "vault:reveal:allow", "vault:promote:allow") {
		t.Fatalf("audit = %v", f.auditActions("vault:"))
	}
}

func TestVaultDecidesAccessByNameAndByTagAndListsOnlyWhatTheCallerMayRead(t *testing.T) {
	f := newVaultFixture(t, nil)
	for _, entry := range [][2]string{{"team-a/api-key", "a"}, {"team-a/db", "a"}, {"team-b/api-key", "b"}, {"shared/smtp", "a"}} {
		f.ok("create", f.owner, "name", entry[0], "tags", core.NewObject("team", entry[1]), "value", "value of "+entry[0])
	}
	_, alice := f.memberWith("alice", allow(items("iam:vault:read", "iam:vault:reveal"), items("iam/vault/secrets/team-a/*")))
	_, bob := f.memberWith("bob", allow(items("iam:vault:read", "iam:vault:reveal"), items("iam/vault/secrets/*"),
		"conditions", core.NewObject("StringEquals", core.NewObject("resource.tag.team", "a"))))
	vaultExpect(t, "alice reveal", f.ok("reveal", alice, "name", "team-a/db").Get("value"), `"value of team-a/db"`)
	f.fails("ACCESS_DENIED", "reveal", alice, "name", "team-b/api-key")
	aliceList := f.ok("list", alice)
	vaultExpect(t, "alice list", pluck(objectsOf(aliceList.Get("secrets")), "name"), `["team-a/api-key","team-a/db"]`)

	// Tag conditions: bob reads every team-a secret wherever it lives, and nothing else.
	bobList := f.ok("list", bob)
	vaultExpect(t, "bob list", pluck(objectsOf(bobList.Get("secrets")), "name"), `["shared/smtp","team-a/api-key","team-a/db"]`)
	f.fails("ACCESS_DENIED", "reveal", bob, "name", "team-b/api-key")
	// A name nobody uses has no tags: the condition fails closed.
	f.fails("ACCESS_DENIED", "get", bob, "name", "team-c/new")

	// Prefix and tag filters.
	vaultExpect(t, "prefix total", f.ok("list", f.owner, "prefix", "team-").Get("total"), `3`)
	tagged := f.ok("list", f.owner, "tags", core.NewObject("team", "b"))
	vaultExpect(t, "tagged", pluck(objectsOf(tagged.Get("secrets")), "name"), `["team-b/api-key"]`)

	// Reading metadata never reveals values, and the denied reveal was audited.
	if strings.Contains(stringify(bobList), "value of") {
		t.Fatal("the listing carries values")
	}
	if !vaultContains(f.auditActions("iam:vault:reveal"), "iam:vault:reveal:deny") {
		t.Fatalf("audit = %v", f.auditActions("iam:vault:reveal"))
	}
}

func TestVaultRotatesWithAGeneratorAndARotatorRetriesFailuresWithTheSameValueAndRunsOnSchedule(t *testing.T) {
	type applied struct {
		value    string
		previous *string
		version  float64
	}
	var mu sync.Mutex
	var appliedValues []applied
	failNext := false
	f := newVaultFixture(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Rotators: map[string]VaultRotator{"postgres": {Rotate: func(ctx context.Context, input RotatorInput) error {
			mu.Lock()
			defer mu.Unlock()
			if failNext {
				failNext = false
				return errors.New("database refused password " + input.Value)
			}
			appliedValues = append(appliedValues, applied{input.Value, input.Previous, input.Version})
			return nil
		}}}}
	})
	f.ok("create", f.owner, "name", "db/app", "value", "initial-app-password", "rotation", core.NewObject(
		"intervalDays", 30.0, "rotator", "postgres",
		"generator", core.NewObject("length", 24.0, "charset", "ascii", "exclude", "%"),
	))
	rotated := f.ok("rotate", f.owner, "name", "db/app")
	vaultExpect(t, "rotated", core.NewObject("name", rotated.Get("name"), "version", rotated.Get("version"), "rotator", rotated.Get("rotator")),
		`{"name":"db/app","version":2,"rotator":"postgres"}`)
	if appliedValues[0].version != 2 || appliedValues[0].previous == nil || *appliedValues[0].previous != "initial-app-password" {
		t.Fatalf("applied = %+v", appliedValues[0])
	}
	current := jsString(f.ok("reveal", f.owner, "name", "db/app").Get("value"))
	if current != appliedValues[0].value || len(current) != 24 || strings.Contains(current, "%") {
		t.Fatalf("current = %q", current)
	}
	for _, class := range []string{`[a-z]`, `[A-Z]`, `[0-9]`, `[^a-zA-Z0-9]`} {
		if !regexp.MustCompile(class).MatchString(current) {
			t.Fatalf("%q lacks %s", current, class)
		}
	}

	// A failing rotator leaves the pending version; the error is stored redacted; the retry reuses the value.
	failNext = true
	failure := f.fails("ROTATION_FAILED", "rotate", f.owner, "name", "db/app")
	if failure.Status != 502 || !strings.Contains(failure.Message, "[redacted]") {
		t.Fatalf("failure = %d %q", failure.Status, failure.Message)
	}
	afterFailure := f.ok("get", f.owner, "name", "db/app")
	stages := vaultObject(afterFailure.Get("stages"))
	if jsNumber(stages.Get("current")) != 2 || jsNumber(stages.Get("pending")) != 3 {
		t.Fatalf("stages = %s", stringify(stages))
	}
	if jsNumber(member(afterFailure.Get("rotation"), "failures")) != 1 {
		t.Fatalf("rotation = %s", stringify(afterFailure.Get("rotation")))
	}
	if regexp.MustCompile(`refused password [^\[]`).MatchString(jsString(member(member(afterFailure.Get("rotation"), "lastFailure"), "message"))) {
		t.Fatal("the failure message leaks the value")
	}
	f.ok("rotate", f.owner, "name", "db/app")
	if last := appliedValues[len(appliedValues)-1]; last.version != 3 {
		t.Fatalf("retry applied %+v", last)
	}
	afterRetry := f.ok("get", f.owner, "name", "db/app")
	vaultExpect(t, "stages after retry", afterRetry.Get("stages"), `{"current":3,"previous":2}`)
	rotation := vaultObject(afterRetry.Get("rotation"))
	if rotation.Get("intervalDays") != 30.0 || rotation.Get("due") != false || !isUndefined(rotation.Get("lastFailure")) {
		t.Fatalf("rotation = %s", stringify(rotation))
	}

	// Nothing is due yet; after 31 days the scheduler rotates it.
	vaultExpect(t, "nothing due", f.job(f.iam.Vault.RotateDue(f.ctx, nil)).Get("rotated"), `[]`)
	f.advance(int64(31 * vaultTestDay))
	run := f.job(f.iam.Vault.RotateDue(f.ctx, nil))
	vaultExpect(t, "scheduled", run.Get("rotated"), `[{"tenantId":"`+f.tenantID+`","name":"db/app","version":4}]`)
	if !vaultContains(f.auditActions("vault:"), "vault:rotate:allow", "vault:rotate:deny") {
		t.Fatalf("audit = %v", f.auditActions("vault:"))
	}
}

func TestVaultRecordsAReminderOnceWhenAManualRotationIsDue(t *testing.T) {
	f := newVaultFixture(t, nil)
	f.ok("create", f.owner, "name", "vendor/api-key", "value", "vendor-issued-key", "rotation", core.NewObject("intervalDays", 7.0))
	f.advance(int64(8 * vaultTestDay))
	vaultExpect(t, "reminded", f.job(f.iam.Vault.RotateDue(f.ctx, nil)).Get("reminded"), `[{"tenantId":"`+f.tenantID+`","name":"vendor/api-key"}]`)
	vaultExpect(t, "reminded again", f.job(f.iam.Vault.RotateDue(f.ctx, nil)).Get("reminded"), `[]`)
	owner := f.ownerSignIn(f.tenantID)
	if member(f.ok("get", owner, "name", "vendor/api-key").Get("rotation"), "due") != true {
		t.Fatal("the rotation is not due")
	}
	// A new current version resets the schedule.
	f.ok("put", owner, "name", "vendor/api-key", "value", "a newly issued key")
	if member(f.ok("get", owner, "name", "vendor/api-key").Get("rotation"), "due") != false {
		t.Fatal("the rotation is still due")
	}
	if !vaultContains(f.auditActions("vault:"), "vault:rotation-due:allow") {
		t.Fatalf("audit = %v", f.auditActions("vault:"))
	}
}

func TestVaultChecksOutSharedCredentialsExclusivelyAndRotatesThemWhenTheyComeBack(t *testing.T) {
	f := newVaultFixture(t, nil)
	name := []any{"name", "break-glass/root"}
	f.ok("create", f.owner, append(name, "generate", true, "checkout", core.NewObject(
		"exclusive", true, "rotateOnCheckin", true, "requireReason", true, "maxDurationMs", 2*vaultTestHour,
	))...)
	operators := allow(items("iam:vault:lease", "iam:vault:reveal", "iam:vault:read"), items("iam/vault/secrets/break-glass/*"))
	aliceIdentity, alice := f.memberWith("alice", operators)
	_, bob := f.memberWith("bob", operators)

	f.fails("CHECKOUT_REQUIRED", "reveal", alice, name...)
	f.fails("INVALID_INPUT", "checkout", alice, name...)
	checkout := f.ok("checkout", alice, append(name, "reason", "INC-1234 database outage")...)
	vaultExpect(t, "checkout", core.NewObject("version", checkout.Get("version"), "stages", checkout.Get("stages")), `{"version":1,"stages":["current"]}`)
	if len(jsString(checkout.Get("value"))) != 32 || jsNumber(checkout.Get("expiresAt"))-f.now() != 2*vaultTestHour {
		t.Fatalf("checkout = %s", stringify(checkout))
	}
	// The holder may reveal what they checked out; others wait.
	vaultExpect(t, "holder reveal", f.ok("reveal", alice, name...).Get("value"), stringify(checkout.Get("value")))
	f.fails("SECRET_CHECKED_OUT", "checkout", bob, append(name, "reason", "me too")...)
	vaultExpect(t, "checkedOut", f.ok("get", f.owner, name...).Get("checkedOut"),
		`[{"leaseId":`+stringify(checkout.Get("leaseId"))+`,"holderId":`+stringify(aliceIdentity.Get("id"))+`,"expiresAt":`+stringify(checkout.Get("expiresAt"))+`}]`)
	// Others cannot return someone else's check-out without iam:vault:manage.
	f.fails("ACCESS_DENIED", "checkin", bob, "leaseId", checkout.Get("leaseId"))

	returned := f.ok("checkin", alice, "leaseId", checkout.Get("leaseId"))
	vaultExpect(t, "returned", returned, `{"leaseId":`+stringify(checkout.Get("leaseId"))+`,"state":"ended","rotated":2}`)
	next := f.ok("checkout", bob, append(name, "reason", "INC-1235", "durationMs", vaultTestHour)...)
	if next.Get("version") != 2.0 || next.Get("value") == checkout.Get("value") {
		t.Fatalf("next = %s", stringify(next))
	}

	// An expired check-out ends by itself and rotates too.
	f.advance(int64(vaultTestHour) + 1)
	run := f.job(f.iam.Vault.ExpireLeases(f.ctx, nil))
	if run.Get("expired") != 1.0 || run.Get("rotated") != 1.0 {
		t.Fatalf("run = %s", stringify(run))
	}
	view := f.ok("get", f.ownerSignIn(f.tenantID), name...)
	if member(view.Get("stages"), "current") != 3.0 || stringify(view.Get("checkedOut")) != "[]" {
		t.Fatalf("view = %s", stringify(view))
	}
	if !vaultContains(f.auditActions("vault:"), "vault:checkout:allow", "vault:checkin:allow", "vault:checkout-expired:allow") {
		t.Fatalf("audit = %v", f.auditActions("vault:"))
	}
}

func TestVaultMintsDynamicCredentialsPerLeaseAndRevokesThemAtTheEngine(t *testing.T) {
	var mu sync.Mutex
	issued := map[string]string{}
	revoked := []string{}
	renewals := []float64{}
	failRevoke := 0
	failIssue := false
	f := newVaultFixture(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Engines: map[string]VaultEngine{"postgres": {
			Issue: func(ctx context.Context, input EngineIssueInput) (*EngineIssued, error) {
				mu.Lock()
				defer mu.Unlock()
				if failIssue {
					return nil, errors.New("database unavailable")
				}
				username := "v-" + input.Holder.Name + "-" + input.LeaseID[:8]
				issued[input.LeaseID] = username
				return &EngineIssued{
					Fields: core.NewObject("username", username, "password", "pw-"+input.LeaseID, "role", member(input.Config, "role")),
					Handle: &username,
				}, nil
			},
			Revoke: func(ctx context.Context, input EngineLeaseInput) error {
				mu.Lock()
				defer mu.Unlock()
				if failRevoke > 0 {
					failRevoke--
					return errors.New("revoke refused")
				}
				// A lease whose issue failed has no handle (TypeScript pushes undefined).
				handle := ""
				if input.Handle != nil {
					handle = *input.Handle
				}
				revoked = append(revoked, handle)
				return nil
			},
			Renew: func(ctx context.Context, input EngineLeaseInput) error {
				renewals = append(renewals, *input.TtlMs)
				return nil
			},
		}}}
	})
	name := []any{"name", "db/readonly"}
	f.ok("create", f.owner, append(name, "kind", "dynamic", "format", "json", "engine", "postgres",
		"engineConfig", core.NewObject("role", "readonly"), "lease", core.NewObject("defaultTtlMs", vaultTestHour, "maxTtlMs", 4*vaultTestHour))...)
	_, alice := f.memberWith("alice", allow(items("iam:vault:lease"), items("iam/vault/secrets/db/*")))
	lease := f.ok("lease", alice, name...)
	leaseID := jsString(lease.Get("leaseId"))
	fields := vaultObject(lease.Get("fields"))
	if fields.Get("role") != "readonly" || fields.Get("username") != issued[leaseID] {
		t.Fatalf("lease = %s", stringify(lease))
	}
	if jsNumber(lease.Get("expiresAt"))-jsNumber(lease.Get("issuedAt")) != vaultTestHour || lease.Get("renewable") != true {
		t.Fatalf("lease = %s", stringify(lease))
	}
	// The credential is never stored; only the sealed handle is.
	rows := stringify(f.find("vaultLeases", core.NewObject()))
	if strings.Contains(rows, "pw-"+leaseID) || strings.Contains(rows, issued[leaseID]) {
		t.Fatal("the credential is stored")
	}
	// Static operations do not apply.
	f.fails("INVALID_INPUT", "reveal", f.owner, name...)

	renewed := f.ok("renewLease", alice, "leaseId", leaseID, "ttlMs", 3*vaultTestHour)
	if jsNumber(renewed.Get("expiresAt"))-f.now() != 3*vaultTestHour || len(renewals) != 1 || renewals[0] != 3*vaultTestHour {
		t.Fatalf("renewed = %s, renewals = %v", stringify(renewed), renewals)
	}
	if mine := f.list("listMine", alice); len(mine) != 1 {
		t.Fatalf("listMine = %d", len(mine))
	}
	ended := f.ok("revokeLease", alice, "leaseId", leaseID)
	if ended.Get("state") != "ended" || len(revoked) != 1 || revoked[0] != issued[leaseID] {
		t.Fatalf("ended = %s, revoked = %v", stringify(ended), revoked)
	}

	// An expiring lease is revoked by the job; a refused revocation is retried.
	second := jsString(f.ok("lease", alice, name...).Get("leaseId"))
	failRevoke = 1
	f.advance(int64(vaultTestHour) + 1)
	expectCounts := func(run *core.Object, expired, retrying float64) {
		t.Helper()
		if run.Get("expired") != expired || run.Get("retrying") != retrying {
			t.Fatalf("run = %s", stringify(run))
		}
	}
	expectCounts(f.job(f.iam.Vault.ExpireLeases(f.ctx, nil)), 0, 1)
	// Retries back off: nothing happens until the retry is due.
	expectCounts(f.job(f.iam.Vault.ExpireLeases(f.ctx, nil)), 0, 0)
	f.advance(2 * 60_000)
	expectCounts(f.job(f.iam.Vault.ExpireLeases(f.ctx, nil)), 1, 0)
	if !vaultContains(revoked, issued[second]) {
		t.Fatalf("revoked = %v", revoked)
	}

	// A failing engine fails the call and leaves no live lease.
	failIssue = true
	_, again := f.issueFor("alice")
	failure := f.fails("ENGINE_FAILED", "lease", again, name...)
	if failure.Status != 502 {
		t.Fatalf("status = %d", failure.Status)
	}
	history := f.list("listLeases", f.ownerSignIn(f.tenantID), append(name, "includeEnded", true)...)
	states := pluck(history, "state")
	sort.Strings(states)
	vaultExpect(t, "history", states, `["ended","expired","failed"]`)
	for _, entry := range history {
		if entry.Get("holderName") != "alice" {
			t.Fatalf("entry = %s", stringify(entry))
		}
	}
}

// issueFor signs a member of the fixture's tenant in again.
func (f *vaultFixture) issueFor(name string) (*core.Object, core.CredentialInput) {
	f.t.Helper()
	identities := f.find("identities", core.NewObject("tenantId", f.tenantID, "name", name))
	if len(identities) == 0 {
		f.t.Fatalf("no member %s", name)
	}
	return identities[0], f.issue(identities[0], false)
}

func TestVaultKeepsDeletedSecretsRestorableDuringTheRecoveryWindowThenPurgesThem(t *testing.T) {
	f := newVaultFixture(t, nil)
	f.ok("create", f.owner, "name", "old/key", "value", "old-key-value")
	f.ok("create", f.owner, "name", "tmp/key", "value", "tmp-key-value")
	scheduled := f.ok("delete", f.owner, "name", "old/key", "recoveryDays", 7.0)
	if scheduled.Get("status") != "pending-deletion" {
		t.Fatalf("scheduled = %s", stringify(scheduled))
	}
	f.fails("SECRET_PENDING_DELETION", "reveal", f.owner, "name", "old/key")
	f.fails("CONFLICT", "create", f.owner, "name", "old/key", "value", "x-value")
	vaultExpect(t, "active total", f.ok("list", f.owner).Get("total"), `1`)
	vaultExpect(t, "all total", f.ok("list", f.owner, "status", "all").Get("total"), `2`)
	f.ok("restore", f.owner, "name", "old/key")
	vaultExpect(t, "restored", f.ok("reveal", f.owner, "name", "old/key").Get("value"), `"old-key-value"`)

	f.ok("delete", f.owner, "name", "old/key", "recoveryDays", 7.0)
	f.advance(int64(6 * vaultTestDay))
	vaultExpect(t, "early purge", f.job(f.iam.Vault.PurgeDeleted(f.ctx, nil)), `{"purged":0}`)
	f.advance(int64(2 * vaultTestDay))
	vaultExpect(t, "purge", f.job(f.iam.Vault.PurgeDeleted(f.ctx, nil)), `{"purged":1}`)
	if left := f.find("vaultVersions", core.NewObject("tenantId", f.tenantID)); len(left) != 1 {
		t.Fatalf("versions left = %d", len(left))
	}

	// Immediate deletion.
	gone := f.ok("delete", f.ownerSignIn(f.tenantID), "name", "tmp/key", "recoveryDays", 0.0)
	if gone.Get("status") != "deleted" || len(f.find("vaultSecrets", core.NewObject("tenantId", f.tenantID))) != 0 {
		t.Fatalf("gone = %s", stringify(gone))
	}
	if !vaultContains(f.auditActions("vault:"), "vault:delete:allow", "vault:restore:allow", "vault:purge:allow") {
		t.Fatalf("audit = %v", f.auditActions("vault:"))
	}
}

func TestVaultServesTrustedCodeResolvesReferencesAndReSealsUnderANewDeploymentSecret(t *testing.T) {
	f := newVaultFixture(t, nil)
	f.ok("create", f.owner, "name", "smtp", "format", "json", "fields", core.NewObject("host", "smtp.acme.test", "password", "smtp-password"))
	f.ok("create", f.owner, "name", "stripe/key", "value", "sk_test_123456")
	smtp := f.job(f.iam.Vault.Get(f.ctx, f.tenantID, "smtp", nil))
	vaultExpect(t, "fields", smtp.Get("fields"), `{"host":"smtp.acme.test","password":"smtp-password"}`)
	resolved, err := f.iam.Vault.Resolve(f.ctx, f.tenantID, core.NewObject(
		"mail", core.NewObject("host", "vault://smtp#host", "password", "vault://smtp#password"),
		"payments", items("vault://stripe/key", "plain"),
		"retries", 3.0,
	))
	vaultSkip(t, err)
	if err != nil {
		t.Fatal(err)
	}
	vaultExpect(t, "resolved", resolved, `{"mail":{"host":"smtp.acme.test","password":"smtp-password"},"payments":["sk_test_123456","plain"],"retries":3}`)
	_, err = f.iam.Vault.Resolve(f.ctx, f.tenantID, "vault://smtp#user")
	expectError(t, err, "NOT_FOUND", "The secret smtp has no field user")

	// A new deployment secret with the old one kept as previous: values still open, then are re-sealed.
	secret := f.iam.Context.Options.Secret
	rotated, err := New(&BetterIamOptions{
		Database: f.iam.Context.Options.Database, Secret: "a brand new deployment secret with 32+ characters",
		PreviousSecrets: []string{secret}, BaseURL: directoryOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	vaultExpect(t, "old secret", f.job(rotated.Vault.Get(f.ctx, f.tenantID, "stripe/key", nil)).Get("value"), `"sk_test_123456"`)
	result, err := rotated.RotateSecrets(f.ctx, SecretRotationOptions{})
	vaultSkip(t, err)
	if err != nil {
		t.Fatal(err)
	}
	vaultExpect(t, "resealed", result.Resealed.Get("vaultVersions"), `2`)
	fresh, err := New(&BetterIamOptions{
		Database: f.iam.Context.Options.Database, Secret: "a brand new deployment secret with 32+ characters", BaseURL: directoryOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	vaultExpect(t, "fresh", member(f.job(fresh.Vault.Get(f.ctx, f.tenantID, "smtp", nil)).Get("fields"), "password"), `"smtp-password"`)
}

// createKey creates a KMS key (api/keys.ts, another unit) and returns it.
func (f *vaultFixture) createKey(pairs ...any) *core.Object {
	f.t.Helper()
	out, err := f.iam.API.Keys.Create(f.ctx, f.owner, Input[apitypes.KeysCreateInput](body(append([]any{"tenantId", f.tenantID}, pairs...)...)))
	vaultSkip(f.t, err)
	if err != nil {
		f.t.Fatal(err)
	}
	return vaultObject(out.Value)
}

func TestVaultEncryptsValuesUnderACustomerManagedKeyAndDisablingTheKeyShredsThem(t *testing.T) {
	f := newVaultFixture(t, nil)
	key := f.createKey("alias", "alias/vault")
	keyID := key.Get("id")
	f.ok("create", f.owner, "name", "cmk/api", "value", "under-the-customer-key", "kmsKey", "alias/vault")
	f.ok("create", f.owner, "name", "cmk/later", "value", "first-under-deployment-secret")
	f.ok("put", f.owner, "name", "cmk/later", "value", "second-value")
	rows := f.find("vaultVersions", core.NewObject("tenantId", f.tenantID, "version", 1.0, "kmsKeyId", keyID))
	if len(rows) != 1 || strings.Contains(jsString(rows[0].Get("sealed")), "under-the-customer-key") {
		t.Fatalf("rows = %s", stringify(rows))
	}
	vaultExpect(t, "cmk reveal", f.ok("reveal", f.owner, "name", "cmk/api").Get("value"), `"under-the-customer-key"`)
	// Moving a secret under the key re-encrypts every kept version.
	moved := f.ok("update", f.owner, "name", "cmk/later", "kmsKey", keyID)
	if moved.Get("kmsKeyId") != keyID {
		t.Fatalf("moved = %s", stringify(moved))
	}
	if later := f.find("vaultVersions", core.NewObject("tenantId", f.tenantID, "kmsKeyId", keyID)); len(later) != 3 {
		t.Fatalf("versions under the key = %d", len(later))
	}
	vaultExpect(t, "previous", f.ok("reveal", f.owner, "name", "cmk/later", "stage", "previous").Get("value"), `"first-under-deployment-secret"`)
	// Vault rights alone do not let someone bind secrets to a key they cannot use.
	_, alice := f.memberWith("alice", allow(items("iam:vault:*"), items("iam/vault/secrets/*")))
	f.fails("ACCESS_DENIED", "create", alice, "name", "alice/secret", "value", "value", "kmsKey", keyID)
	// Moving back under the deployment secret.
	back := f.ok("update", f.owner, "name", "cmk/api", "kmsKey", nil)
	if !isUndefined(back.Get("kmsKeyId")) {
		t.Fatalf("back = %s", stringify(back))
	}
	vaultExpect(t, "back reveal", f.ok("reveal", f.owner, "name", "cmk/api").Get("value"), `"under-the-customer-key"`)
}

func TestVaultAPIValidatesNamesValuesAndSettings(t *testing.T) {
	f := newVaultFixture(t, nil)
	for _, name := range []string{"../etc", "a//b", ".hidden", "a/-b", strings.Repeat("x", 65)} {
		f.fails("INVALID_INPUT", "create", f.owner, "name", name, "value", "value")
	}
	f.fails("INVALID_INPUT", "create", f.owner, "name", "j", "format", "json", "value", "[1,2]")
	f.fails("INVALID_INPUT", "create", f.owner, "name", "r", "value", "value", "rotation", core.NewObject("rotator", "nope"))
	f.fails("INVALID_INPUT", "create", f.owner, "name", "d", "kind", "dynamic", "engine", "none")
	f.fails("INVALID_INPUT", "create", f.owner, "name", "k", "kind", "secretive", "value", "value")
	generated := f.ok("generate", f.owner, "generator", core.NewObject("length", 12.0, "charset", "numeric", "eachClass", false))
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(jsString(generated.Get("value"))) {
		t.Fatalf("generated = %s", stringify(generated))
	}
	// Validation comes before authentication.
	f.fails("INVALID_INPUT", "create", core.CredentialInput{Token: "nope"}, "name", "../etc", "value", "value")
	f.fails("UNAUTHENTICATED", "generate", core.CredentialInput{Token: "nope"})

	// A bad `vault` option: TypeScript refuses it when the server is built; here every vault call fails with it.
	bad := newVaultFixture(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Rotators: map[string]VaultRotator{"Bad": {Rotate: func(context.Context, RotatorInput) error { return nil }}}}
	})
	failure := bad.fails("INVALID_CONFIG", "create", bad.owner, "name", "x", "value", "value")
	if !strings.Contains(failure.Message, "rotators") {
		t.Fatalf("failure = %q", failure.Message)
	}
}

func TestVaultServesTheVaultOverHTTP(t *testing.T) {
	f := newVaultFixture(t, nil)
	f.ok("create", f.owner, "name", "http/secret", "value", "over-the-wire")
	response := f.post(directoryOrigin, "vault/reveal", `{"tenantId":"`+f.tenantID+`","name":"http/secret"}`,
		map[string]string{"authorization": "Bearer " + f.owner.Token})
	if response.Status != 200 {
		t.Fatalf("status = %d %s", response.Status, response.Body)
	}
	data := vaultObject(jsonBody(t, response).Get("data"))
	if data.Get("value") != "over-the-wire" || data.Get("version") != 1.0 {
		t.Fatalf("data = %s", stringify(data))
	}
}

// --- security review ---------------------------------------------------------------------------

func TestVaultRedactsEveryFieldOfAJsonValueFromRotatorErrors(t *testing.T) {
	f := newVaultFixture(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Rotators: map[string]VaultRotator{"db": {Rotate: func(ctx context.Context, input RotatorInput) error {
			return errors.New("ALTER ROLE app PASSWORD '" + jsString(input.Fields.Get("password")) + "' failed")
		}}}}
	})
	f.ok("create", f.owner, "name", "db/app", "format", "json", "fields", core.NewObject("username", "app", "password", "initial-password"),
		"rotation", core.NewObject("rotator", "db", "field", "password", "intervalDays", 30.0))
	f.fails("ROTATION_FAILED", "rotate", f.owner, "name", "db/app")
	_, reader := f.memberWith("reader", allow(items("iam:vault:read"), items("iam/vault/secrets/*")))
	seen := f.ok("get", reader, "name", "db/app")
	if !strings.Contains(jsString(member(member(seen.Get("rotation"), "lastFailure"), "message")), "[redacted]") {
		t.Fatalf("seen = %s", stringify(seen))
	}
	pending := f.ok("reveal", f.owner, "name", "db/app", "stage", "pending")
	password := jsString(member(pending.Get("fields"), "password"))
	if strings.Contains(stringify(seen), password) || strings.Contains(stringify(f.find("audit", core.NewObject())), password) {
		t.Fatal("the pending password leaked")
	}
}

func TestVaultNeverHandsAPendingValueSomeoneStagedByHandToTheRotator(t *testing.T) {
	var applied []string
	f := newVaultFixture(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Rotators: map[string]VaultRotator{"db": {Rotate: func(ctx context.Context, input RotatorInput) error {
			applied = append(applied, input.Value)
			return nil
		}}}}
	})
	f.ok("create", f.owner, "name", "shared/root", "generate", true, "rotation", core.NewObject("rotator", "db"),
		"checkout", core.NewObject("rotateOnCheckin", true, "required", false))
	_, writer := f.memberWith("writer", allow(items("iam:vault:write"), items("iam/vault/secrets/*")))
	f.ok("put", writer, "name", "shared/root", "value", "writer-chosen-password", "stage", "pending")
	f.ok("rotate", f.owner, "name", "shared/root")
	if len(applied) != 1 || applied[0] == "writer-chosen-password" {
		t.Fatalf("applied = %v", applied)
	}
	vaultExpect(t, "current", f.ok("reveal", f.owner, "name", "shared/root").Get("value"), stringify(applied[0]))
}

func TestVaultRotatesACheckOutEndedWithRevokeLeaseAndNeedsAPolicyToCheckOutAtAll(t *testing.T) {
	f := newVaultFixture(t, nil)
	f.ok("create", f.owner, "name", "shared/admin", "generate", true, "checkout", core.NewObject("rotateOnCheckin", true, "required", false))
	f.ok("create", f.owner, "name", "plain/key", "value", "plain-value")
	_, holder := f.memberWith("holder", allow(items("iam:vault:lease"), items("iam/vault/secrets/*")))
	// A lease grant does not read static secrets without a check-out policy.
	f.fails("INVALID_INPUT", "checkout", holder, "name", "plain/key")
	out := f.ok("checkout", holder, "name", "shared/admin")
	ended := f.ok("revokeLease", holder, "leaseId", out.Get("leaseId"))
	if ended.Get("state") != "ended" || ended.Get("rotated") != 2.0 {
		t.Fatalf("ended = %s", stringify(ended))
	}
	if f.ok("reveal", f.owner, "name", "shared/admin").Get("value") == out.Get("value") {
		t.Fatal("the secret did not rotate")
	}
}

func TestVaultRefusesReTaggingASecretOutOfTheCallersReach(t *testing.T) {
	f := newVaultFixture(t, nil)
	f.ok("create", f.owner, "name", "team-a/secret", "tags", core.NewObject("team", "a"), "value", "team-a-value")
	_, mallory := f.memberWith("mallory",
		allow(items("iam:vault:manage"), items("iam/vault/secrets/*"), "conditions", core.NewObject("StringEquals", core.NewObject("resource.tag.team", "a"))),
		allow(items("iam:vault:reveal"), items("iam/vault/secrets/*"), "conditions", core.NewObject("StringEquals", core.NewObject("resource.tag.team", "b"))),
	)
	f.fails("ACCESS_DENIED", "update", mallory, "name", "team-a/secret", "tags", core.NewObject("team", "b"))
	f.fails("ACCESS_DENIED", "reveal", mallory, "name", "team-a/secret")
	vaultExpect(t, "tags", f.ok("get", f.owner, "name", "team-a/secret").Get("tags"), `{"team":"a"}`)
}

func TestVaultValidatesRotationSettingsThatCouldNeverRotate(t *testing.T) {
	f := newVaultFixture(t, nil)
	f.fails("INVALID_INPUT", "create", f.owner, "name", "j/one", "format", "json", "fields", core.NewObject("password", "p-value"),
		"checkout", core.NewObject("rotateOnCheckin", true))
	for _, field := range []string{"__proto__", "constructor", "prototype"} {
		f.fails("INVALID_INPUT", "create", f.owner, "name", "j/two", "format", "json", "fields", core.NewObject("password", "p-value"),
			"rotation", core.NewObject("field", field, "generator", true))
	}
	f.ok("create", f.owner, "name", "j/three", "format", "json", "fields", core.NewObject("password", "p-value"))
	for _, reference := range []string{"vault://j/three#constructor", "vault://j/three#__proto__"} {
		_, err := f.iam.Vault.Resolve(f.ctx, f.tenantID, reference)
		vaultSkip(t, err)
		expectCode(t, err, "NOT_FOUND")
	}
}

func TestVaultDoesNotPromoteAVersionDisabledWhileTheRotatorRan(t *testing.T) {
	var f *vaultFixture
	f = newVaultFixture(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Rotators: map[string]VaultRotator{"db": {Rotate: func(ctx context.Context, input RotatorInput) error {
			_, err := f.call("setVersionState", f.owner, "name", input.Name, "version", input.Version, "state", "disabled")
			return err
		}}}}
	})
	f.ok("create", f.owner, "name", "db/x", "value", "first-value", "rotation", core.NewObject("rotator", "db"))
	f.fails("ROTATION_FAILED", "rotate", f.owner, "name", "db/x")
	if member(f.ok("get", f.owner, "name", "db/x").Get("stages"), "current") != 1.0 {
		t.Fatal("the disabled version became current")
	}
}

func TestVaultRevokesWhatAnEngineMintedWhenTheIssueFailsAfterTheCall(t *testing.T) {
	var revoked []string
	mode := "bad-handle"
	f := newVaultFixture(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Engines: map[string]VaultEngine{"e": {
			Issue: func(ctx context.Context, input EngineIssueInput) (*EngineIssued, error) {
				value := "pw-" + input.LeaseID
				handle := input.LeaseID
				if mode == "bad-handle" {
					handle = strings.Repeat("x", 5000)
				}
				return &EngineIssued{Value: &value, Handle: &handle}, nil
			},
			Revoke: func(ctx context.Context, input EngineLeaseInput) error {
				revoked = append(revoked, input.LeaseID)
				return nil
			},
		}}}
	})
	f.ok("create", f.owner, "name", "dyn/x", "kind", "dynamic", "engine", "e", "lease", core.NewObject("defaultTtlMs", vaultTestHour, "maxTtlMs", 4*vaultTestHour))
	f.fails("ENGINE_FAILED", "lease", f.owner, "name", "dyn/x")
	if len(revoked) != 1 {
		t.Fatalf("revoked = %v", revoked)
	}
	// Renewals extend by the original length, not by how long the lease has lasted so far.
	mode = "ok"
	lease := f.ok("lease", f.owner, "name", "dyn/x", "ttlMs", vaultTestHour)
	f.advance(30 * 60_000)
	first := f.ok("renewLease", f.owner, "leaseId", lease.Get("leaseId"))
	if jsNumber(first.Get("expiresAt"))-f.now() != vaultTestHour {
		t.Fatalf("first = %s", stringify(first))
	}
	f.advance(30 * 60_000)
	second := f.ok("renewLease", f.owner, "leaseId", lease.Get("leaseId"))
	if jsNumber(second.Get("expiresAt"))-f.now() != vaultTestHour {
		t.Fatalf("second = %s", stringify(second))
	}
}

func TestVaultKeepsCustomerManagedKeysInChargeOfTheValues(t *testing.T) {
	f := newVaultFixture(t, nil)
	key := f.createKey()
	f.ok("create", f.owner, "name", "cmk/x", "value", "under-the-key", "kmsKey", key.Get("id"))
	_, manager := f.memberWith("manager", allow(items("iam:vault:*"), items("iam/vault/secrets/*")))
	// Vault rights alone neither read a key-protected value nor move it off its key.
	f.fails("ACCESS_DENIED", "reveal", manager, "name", "cmk/x")
	f.fails("ACCESS_DENIED", "update", manager, "name", "cmk/x", "kmsKey", nil)
	// Non-AES keys cannot be bound.
	signing := f.createKey("keySpec", "ed25519")
	f.fails("INVALID_INPUT", "create", f.owner, "name", "cmk/y", "value", "v-value", "kmsKey", signing.Get("id"))
}

// --- second security review --------------------------------------------------------------------

func TestVaultRefusesChangesThatMoveASecretIntoWhatTheCallerMayRevealAndCreationsADenyTargets(t *testing.T) {
	engine := VaultEngine{Issue: func(ctx context.Context, input EngineIssueInput) (*EngineIssued, error) {
		value := "minted"
		return &EngineIssued{Value: &value}, nil
	}}
	f := newVaultFixture(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Engines: map[string]VaultEngine{"pg-app": engine, "pg-admin": engine}}
	})
	f.ok("create", f.owner, "name", "prod/db", "tags", core.NewObject("environment", "prod"), "value", "prod-password")
	_, admin := f.memberWith("vaultadmin",
		allow(items("iam:vault:manage", "iam:vault:read"), items("iam/vault/secrets/*")),
		allow(items("iam:vault:reveal"), items("iam/vault/secrets/*"), "conditions", core.NewObject("StringEquals", core.NewObject("resource.tag.environment", "staging"))),
	)
	failure := f.fails("ACCESS_DENIED", "update", admin, "name", "prod/db", "tags", core.NewObject("environment", "staging"))
	if failure.Message != "The change would give you iam:vault:reveal on the secret, which you do not have on it now" {
		t.Fatalf("failure = %q", failure.Message)
	}
	vaultExpect(t, "tags", f.ok("get", admin, "name", "prod/db").Get("tags"), `{"environment":"prod"}`)
	// Changes that open nothing new still pass.
	f.ok("update", admin, "name", "prod/db", "description", "Payments database")
	f.fails("ACCESS_DENIED", "reveal", admin, "name", "prod/db")

	// A deny on an attribute other than tags applies to the creation itself.
	_, dev := f.memberWith("dev",
		allow(items("iam:vault:manage", "iam:vault:lease"), items("iam/vault/secrets/*")),
		core.NewObject("effect", "deny", "actions", items("iam:vault:manage", "iam:vault:lease"), "resources", items("iam/vault/secrets/*"),
			"conditions", core.NewObject("StringEquals", core.NewObject("resource.engine", "pg-admin"))),
	)
	f.fails("ACCESS_DENIED", "create", dev, "name", "mine/admin", "kind", "dynamic", "engine", "pg-admin")
	f.fails("NOT_FOUND", "get", f.owner, "name", "mine/admin")
	f.ok("create", dev, "name", "mine/app", "kind", "dynamic", "engine", "pg-app")
}

func TestVaultRotatesToAChosenValueOnlyForCallersWhoMayWriteAndRevealItNeverBehindCheckOuts(t *testing.T) {
	var applied []string
	f := newVaultFixture(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Rotators: map[string]VaultRotator{"db": {Rotate: func(ctx context.Context, input RotatorInput) error {
			applied = append(applied, input.Value)
			return nil
		}}}}
	})
	f.ok("create", f.owner, "name", "break-glass/root", "generate", true, "rotation", core.NewObject("rotator", "db", "intervalDays", 30.0),
		"checkout", core.NewObject("required", true, "exclusive", true))
	f.ok("create", f.owner, "name", "svc/token", "value", "first-token", "rotation", core.NewObject("rotator", "db"))
	_, operator := f.memberWith("operator", allow(items("iam:vault:rotate", "iam:vault:read"), items("iam/vault/secrets/*")))
	f.fails("INVALID_INPUT", "rotate", operator, "name", "break-glass/root", "value", "known-to-me")
	f.fails("INVALID_INPUT", "rotate", f.owner, "name", "break-glass/root", "value", "known-to-me")
	f.fails("ACCESS_DENIED", "rotate", operator, "name", "svc/token", "value", "known-to-me")
	if len(applied) != 0 {
		t.Fatalf("applied = %v", applied)
	}
	// Generated values rotate as before.
	f.ok("rotate", operator, "name", "svc/token")
	if len(applied) != 1 {
		t.Fatalf("applied = %v", applied)
	}
	_, writer := f.memberWith("writer", allow(items("iam:vault:rotate", "iam:vault:write", "iam:vault:reveal"), items("iam/vault/secrets/*")))
	f.ok("rotate", writer, "name", "svc/token", "value", "chosen-token")
	if applied[len(applied)-1] != "chosen-token" {
		t.Fatalf("applied = %v", applied)
	}
}

func TestVaultFindsADepartedHoldersLeaseHoweverManyLiveLeasesSortBeforeIt(t *testing.T) {
	var revoked []string
	f := newVaultFixture(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Engines: map[string]VaultEngine{"pg": {
			Issue: func(ctx context.Context, input EngineIssueInput) (*EngineIssued, error) {
				value := "pw-" + input.LeaseID
				handle := input.LeaseID
				return &EngineIssued{Value: &value, Handle: &handle}, nil
			},
			Revoke: func(ctx context.Context, input EngineLeaseInput) error {
				revoked = append(revoked, input.LeaseID)
				return nil
			},
		}}}
	})
	f.ok("create", f.owner, "name", "prod/db", "kind", "dynamic", "engine", "pg", "lease", core.NewObject("defaultTtlMs", 7*vaultTestDay, "maxTtlMs", 30*vaultTestDay))
	holders := map[string]string{}
	for n := 0; n < 6; n++ {
		person, credential := f.memberWith("p"+string(rune('0'+n)), allow(items("iam:vault:lease"), items("iam/vault/secrets/*")))
		taken := f.ok("lease", credential, "name", "prod/db")
		holders[jsString(taken.Get("leaseId"))] = jsString(person.Get("id"))
	}
	order := pluck(f.find("vaultLeases", core.NewObject("state", "active")), "id")
	last := order[len(order)-1]
	// The departed holder is disabled the way identities.setStatus leaves them.
	departed := f.record("identities", holders[last])
	f.patch("identities", jsString(departed.Get("id")), core.NewObject("status", "disabled"))
	f.job(f.iam.Vault.ExpireLeases(f.ctx, core.NewObject("limit", 5.0)))
	vaultExpect(t, "revoked", revoked, stringify([]string{last}))
}

func TestVaultKeepsValuesFromPluginHooks(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	spy := &core.IamPlugin{ID: "spy", Hooks: &core.PluginHooks{AfterOperation: func(ctx context.Context, input core.OperationHookInput) error {
		mu.Lock()
		defer mu.Unlock()
		result := input.Result
		if result == nil {
			result = core.Undefined
		}
		text, _, _ := core.Stringify(result)
		if text == "" {
			text = "null"
		}
		seen = append(seen, text)
		return nil
	}}}
	f := newVaultFixture(t, func(options *BetterIamOptions) {
		options.Plugins = append(options.Plugins, spy)
		options.Vault = &VaultOptions{Rotators: map[string]VaultRotator{"db": {Rotate: func(context.Context, RotatorInput) error { return nil }}}}
	})
	f.ok("create", f.owner, "name", "shared/admin", "value", "first-admin-password", "rotation", core.NewObject("rotator", "db"),
		"checkout", core.NewObject("required", false))
	_, alice := f.memberWith("alice", allow(items("iam:vault:*"), items("iam/vault/secrets/*")))
	vaultExpect(t, "reveal", f.ok("reveal", alice, "name", "shared/admin").Get("value"), `"first-admin-password"`)
	f.ok("rotate", alice, "name", "shared/admin")
	out := f.ok("checkout", alice, "name", "shared/admin")
	current := f.job(f.iam.Vault.Get(f.ctx, f.tenantID, "shared/admin", nil))
	if out.Get("value") != current.Get("value") {
		t.Fatalf("checkout %s, current %s", stringify(out.Get("value")), stringify(current.Get("value")))
	}
	if len(seen) < 3 {
		t.Fatalf("seen = %v", seen)
	}
	for _, result := range seen {
		if strings.Contains(result, "first-admin-password") || strings.Contains(result, jsString(current.Get("value"))) {
			t.Fatalf("a hook saw a value: %s", result)
		}
	}
	// Another session of hers that may lease can return it.
	_, again := f.issueFor("alice")
	if returned := f.ok("checkin", again, "leaseId", out.Get("leaseId")); returned.Get("state") != "ended" {
		t.Fatalf("returned = %s", stringify(returned))
	}
}

func TestVaultDestroysValuesForGoodOnlyFromARecentlySignedInSession(t *testing.T) {
	f := newVaultFixture(t, nil)
	f.ok("create", f.owner, "name", "old/key", "value", "value-one")
	f.ok("put", f.owner, "name", "old/key", "value", "value-two")
	f.advance(10 * 60_000)
	f.fails("RECENT_AUTH_REQUIRED", "destroyVersion", f.owner, "name", "old/key", "version", 1.0)
	f.fails("RECENT_AUTH_REQUIRED", "delete", f.owner, "name", "old/key", "recoveryDays", 0.0)
	// A recovery window needs no fresh sign-in.
	if scheduled := f.ok("delete", f.owner, "name", "old/key", "recoveryDays", 7.0); scheduled.Get("status") != "pending-deletion" {
		t.Fatalf("scheduled = %s", stringify(scheduled))
	}
}

func TestVaultValidatesInputBeforeTheOperation(t *testing.T) {
	f := newVaultFixture(t, nil)
	nobody := core.CredentialInput{Token: "nope"}
	f.fails("INVALID_INPUT", "put", nobody, "name", "a", "stage", "previous")
	f.fails("INVALID_INPUT", "setStage", nobody, "name", "a", "stage", "current", "version", 1.0)
	f.fails("INVALID_INPUT", "promote", nobody, "name", "a", "version", 0.0)
	f.fails("INVALID_INPUT", "setVersionState", nobody, "name", "a", "version", 1.0, "state", "gone")
	f.fails("INVALID_INPUT", "delete", nobody, "name", "a", "recoveryDays", 3.0)
	f.fails("INVALID_INPUT", "list", nobody, "status", "deleted")
	f.fails("INVALID_INPUT", "list", nobody, "limit", 501.0)
	f.fails("INVALID_INPUT", "accessLog", nobody, "name", "a", "limit", 0.0)
	f.fails("INVALID_INPUT", "checkin", nobody, "leaseId", "")
	f.fails("UNAUTHENTICATED", "checkin", nobody, "leaseId", "lease-1")
	f.fails("NOT_FOUND", "checkin", f.owner, "leaseId", "lease-1")
	f.fails("INVALID_INPUT", "listMine", nobody, "tenantId", 42.0)
	_, err := f.iam.Vault.RotateDue(f.ctx, core.NewObject("limit", 0.0))
	expectError(t, err, "INVALID_INPUT", "Invalid limit")
}

// actingFor is an agent acting for a person under a delegation of scopes (held back for confirmation when confirm
// lists them): the agent, its own key, the delegation, and the delegated session's credential.
func (f *vaultFixture) actingFor(person core.CredentialInput, scopes []any, confirm []any, sponsorID string) (*core.Object, core.CredentialInput, *core.Object, core.CredentialInput) {
	f.t.Helper()
	api := f.iam.API
	agentBody := body("tenantId", f.tenantID, "name", "Agent "+strings.Join(stringsFrom(scopes), " "))
	if sponsorID != "" {
		agentBody.Set("sponsorId", sponsorID)
	}
	agentOut, err := api.Agents.Create(f.ctx, f.owner, Input[apitypes.AgentsCreateInput](agentBody))
	vaultSkip(f.t, err)
	if err != nil {
		f.t.Fatal(err)
	}
	agent := vaultObject(agentOut.Value)
	keyOut, err := api.Credentials.Create(f.ctx, f.owner, Input[apitypes.CredentialsCreateInput](body("tenantId", f.tenantID, "identityId", agent.Get("id"))))
	vaultSkip(f.t, err)
	if err != nil {
		f.t.Fatal(err)
	}
	agentKey := core.CredentialInput{Token: jsString(vaultObject(keyOut.Value).Get("token"))}
	grant := body("tenantId", f.tenantID, "agentId", agent.Get("id"), "scopes", scopes)
	if len(confirm) > 0 {
		grant.Set("confirm", confirm)
	}
	delegationOut, err := api.Delegations.Grant(f.ctx, person, Input[apitypes.DelegationsGrantInput](grant))
	vaultSkip(f.t, err)
	if err != nil {
		f.t.Fatal(err)
	}
	delegation := vaultObject(delegationOut.Value)
	assumed, err := api.Delegations.Assume(f.ctx, agentKey, Input[apitypes.DelegationsAssumeInput](body("tenantId", f.tenantID, "delegationId", delegation.Get("id"))))
	vaultSkip(f.t, err)
	if err != nil {
		f.t.Fatal(err)
	}
	return agent, agentKey, delegation, core.CredentialInput{Token: jsString(vaultObject(assumed.Value).Get("token"))}
}

func stringsFrom(values []any) []string {
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = jsString(value)
	}
	return out
}

func TestVaultEndsLeasesWhenTheDelegationBehindThemEndsOrTheAgentMayNoLongerAct(t *testing.T) {
	var mu sync.Mutex
	var revoked []string
	f := newVaultFixture(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Engines: map[string]VaultEngine{"pg": {
			Issue: func(ctx context.Context, input EngineIssueInput) (*EngineIssued, error) {
				value := "pw-" + input.LeaseID
				handle := input.LeaseID
				return &EngineIssued{Value: &value, Handle: &handle}, nil
			},
			Revoke: func(ctx context.Context, input EngineLeaseInput) error {
				mu.Lock()
				defer mu.Unlock()
				revoked = append(revoked, input.LeaseID)
				return nil
			},
		}}}
	})
	f.ok("create", f.owner, "name", "prod/db", "kind", "dynamic", "engine", "pg", "lease", core.NewObject("defaultTtlMs", 7*vaultTestDay, "maxTtlMs", 30*vaultTestDay))
	lease := allow(items("iam:vault:lease"), items("iam/vault/secrets/*"))
	sponsor, _ := f.memberWith("sponsor")
	_, alice := f.memberWith("alice", lease)
	agent, agentKey, delegation, acting := f.actingFor(alice, items("iam:vault:lease"), nil, jsString(sponsor.Get("id")))
	roleID := f.role(f.tenantID, "Agent lease", lease)
	f.bind(f.tenantID, roleID, "identity", jsString(agent.Get("id")))
	own := f.ok("lease", agentKey, "name", "prod/db")
	forAlice := f.ok("lease", acting, "name", "prod/db")
	kept := f.ok("lease", alice, "name", "prod/db")

	_, err := f.iam.API.Delegations.Revoke(f.ctx, alice, Input[apitypes.DelegationsRevokeInput](body("tenantId", f.tenantID, "delegationId", delegation.Get("id"))))
	vaultSkip(t, err)
	if err != nil {
		t.Fatal(err)
	}
	f.job(f.iam.Vault.ExpireLeases(f.ctx, nil))
	vaultExpect(t, "revoked", revoked, stringify([]string{jsString(forAlice.Get("leaseId"))}))

	// The sponsor leaves the way identities.setStatus disables them (that call reaches another unit's stub).
	f.patch("identities", jsString(sponsor.Get("id")), core.NewObject("status", "disabled"))
	f.job(f.iam.Vault.ExpireLeases(f.ctx, nil))
	vaultExpect(t, "revoked", revoked, stringify([]string{jsString(forAlice.Get("leaseId")), jsString(own.Get("leaseId"))}))
	active := []string{}
	for _, item := range f.list("listLeases", f.owner, "name", "prod/db") {
		if item.Get("state") == "active" {
			active = append(active, jsString(item.Get("id")))
		}
	}
	vaultExpect(t, "active", active, stringify([]string{jsString(kept.Get("leaseId"))}))
}

func TestVaultLetsOnlyASessionThatMayLeaseActOnAnotherSessionsLease(t *testing.T) {
	f := newVaultFixture(t, nil)
	f.ok("create", f.owner, "name", "shared/admin", "value", "first-admin-password", "checkout", core.NewObject("required", false))
	_, alice := f.memberWith("alice", allow(items("iam:vault:*"), items("iam/vault/secrets/*")))
	out := f.ok("checkout", alice, "name", "shared/admin")
	// An agent acting for alice without iam:vault:lease cannot end the check-out she took herself.
	_, _, _, acting := f.actingFor(alice, items("iam:vault:read"), nil, "")
	f.fails("ACCESS_DENIED", "checkin", acting, "leaseId", out.Get("leaseId"))
	f.fails("ACCESS_DENIED", "revokeLease", acting, "leaseId", out.Get("leaseId"))
	// Another session of hers that may lease can.
	_, again := f.issueFor("alice")
	if returned := f.ok("checkin", again, "leaseId", out.Get("leaseId")); returned.Get("state") != "ended" {
		t.Fatalf("returned = %s", stringify(returned))
	}
}
