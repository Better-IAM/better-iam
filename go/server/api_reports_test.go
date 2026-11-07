package server

// The access report, after tests/reports.test.ts. Roles, bindings, activations, and memberships are seeded as the
// bindings and groups API groups write them.

import (
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const reportTestDay = 86_400_000.0

func TestReportsCollectExpiringAccessActivationsAndRequests(t *testing.T) {
	f := newDirectoryFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{Actions: []string{"documents:read"}}
	})
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	alice, asAlice := f.person(tenantID, "alice")
	contractor, _ := f.person(tenantID, "contractor", "expiresAt", f.now()+5*reportTestDay)
	f.person(tenantID, "later", "expiresAt", f.now()+90*reportTestDay)
	reader := f.role(tenantID, "Reader", allow(items("documents:read"), items("*")))
	memberRole := f.role(tenantID, "Member", allow(items("iam:bindings:activate"), items("*")))
	f.bind(tenantID, memberRole, "identity", jsString(alice.Get("id")))
	temporary := f.bind(tenantID, reader, "identity", jsString(contractor.Get("id")), "expiresAt", f.now()+5*reportTestDay)
	eligible := f.bind(tenantID, reader, "identity", jsString(alice.Get("id")), "eligible", true,
		"window", body("from", "00:00", "to", "23:59", "timeZone", "UTC"))
	scheduled := f.bind(tenantID, reader, "identity", jsString(alice.Get("id")), "startsAt", f.now()+2*reportTestDay)
	f.seed("groups", body("id", "group-1", "tenantId", tenantID, "name", "Team", "createdAt", f.now()))
	f.seed("groupMembers", body("id", "membership-1", "tenantId", tenantID, "groupId", "group-1",
		"identityId", jsString(alice.Get("id")), "expiresAt", f.now()+3*reportTestDay, "createdAt", f.now()))
	f.seed("bindingActivations",
		body("id", "activation-1", "tenantId", tenantID, "bindingId", eligible, "identityId", alice.Get("id"), "roleId", reader,
			"activatedAt", f.now(), "expiresAt", f.now()+3_600_000, "justification", "report", "sessionId", "s", "status", "active"),
		body("id", "activation-2", "tenantId", tenantID, "bindingId", eligible, "identityId", alice.Get("id"), "roleId", reader,
			"activatedAt", f.now(), "expiresAt", f.now()+3_600_000, "sessionId", "s", "status", "pending"),
	)
	access := func(credential core.CredentialInput, pairs ...any) (Out[apitypes.ReportsAccessOutput], error) {
		return f.iam.API.Reports.Access(f.ctx, credential, Input[apitypes.ReportsAccessInput](body(append([]any{"tenantId", tenantID}, pairs...)...)))
	}
	report := answerObject(access(owner, "withinMs", 30*reportTestDay, "unusedForMs", reportTestDay))
	if stringify(report.Keys()) != `["generatedAt","withinMs","unusedForMs","identities","omitted","bindings","credentials"]` {
		t.Fatalf("report members %v", report.Keys())
	}
	if stringify(report.Get("omitted")) != `[]` {
		t.Fatalf("omitted = %s", stringify(report.Get("omitted")))
	}
	identities := report.Get("identities").(*core.Object)
	if identities.Get("total") != 4.0 || identities.Get("disabled") != 0.0 {
		t.Fatalf("identities = %s", stringify(identities))
	}
	want := `[{"id":"` + jsString(contractor.Get("id")) + `","name":"contractor","email":"contractor@acme.test","kind":"user","status":"active","expiresAt":` +
		jsString(f.now()+5*reportTestDay) + `,"expired":false}]`
	if got := stringify(identities.Get("expiring")); got != want {
		t.Fatalf("expiring identities = %s, want %s", got, want)
	}
	// The owner's protected binding, Member, the temporary Reader, the eligible Reader, and the scheduled Reader.
	bindings := report.Get("bindings").(*core.Object)
	if bindings.Get("total") != 5.0 || bindings.Get("eligible") != 1.0 || bindings.Get("windowed") != 1.0 || bindings.Get("pendingRequests") != 1.0 {
		t.Fatalf("bindings = %s", stringify(bindings))
	}
	want = `[{"id":"` + temporary + `","roleId":"` + reader + `","roleName":"Reader","subjectType":"identity","subjectId":"` + jsString(contractor.Get("id")) +
		`","subjectName":"contractor","expiresAt":` + jsString(f.now()+5*reportTestDay) + `,"eligible":false}]`
	if got := stringify(bindings.Get("expiring")); got != want {
		t.Fatalf("expiring bindings = %s, want %s", got, want)
	}
	if got := pluck(objectsOf(bindings.Get("starting")), "id"); len(got) != 1 || got[0] != scheduled {
		t.Fatalf("starting = %s", stringify(bindings.Get("starting")))
	}
	want = `[{"groupId":"group-1","groupName":"Team","identityId":"` + jsString(alice.Get("id")) + `","identityName":"alice","expiresAt":` + jsString(f.now()+3*reportTestDay) + `}]`
	if got := stringify(bindings.Get("expiringMemberships")); got != want {
		t.Fatalf("expiring memberships = %s, want %s", got, want)
	}
	want = `[{"id":"activation-1","identityId":"` + jsString(alice.Get("id")) + `","identityName":"alice","roleId":"` + reader + `","roleName":"Reader","activatedAt":` +
		jsString(f.now()) + `,"expiresAt":` + jsString(f.now()+3_600_000) + `,"justification":"report"}]`
	if got := stringify(bindings.Get("activations")); got != want {
		t.Fatalf("activations = %s, want %s", got, want)
	}
	if got := stringify(report.Get("credentials")); got != `{"total":0,"unused":[],"expiring":[]}` {
		t.Fatalf("credentials = %s", got)
	}
	if found, err := ReportHasFindings(report); err != nil || !found {
		t.Fatalf("findings = %v %v", found, err)
	}

	// Past the deadline the identity is reported as expired until the worker disables it.
	f.advance(int64(6 * reportTestDay))
	owner = f.ownerSignIn(tenantID)
	later := answerObject(access(owner))
	if got := stringify(member(later.Get("identities"), "expiring")); got != `[{"id":"`+jsString(contractor.Get("id"))+
		`","name":"contractor","email":"contractor@acme.test","kind":"user","status":"active","expiresAt":`+jsString(f.now()-reportTestDay)+`,"expired":true}]` {
		t.Fatalf("expired identity = %s", got)
	}
	if got := stringify(member(later.Get("bindings"), "activations")); got != `[]` {
		t.Fatalf("activations after expiry = %s", got)
	}
	if later.Get("withinMs") != 30*reportTestDay || later.Get("unusedForMs") != 30*reportTestDay {
		t.Fatalf("default windows = %v %v", later.Get("withinMs"), later.Get("unusedForMs"))
	}

	// A caller without the binding and credential permissions gets those sections omitted.
	viewer := f.role(tenantID, "Directory viewer", allow(items("iam:identities:read"), items("*")))
	bob, asBob := f.person(tenantID, "bob")
	f.bind(tenantID, viewer, "identity", jsString(bob.Get("id")))
	partial := answerObject(access(asBob))
	if stringify(partial.Get("omitted")) != `["bindings","credentials"]` || partial.Has("bindings") || partial.Has("credentials") ||
		member(partial.Get("identities"), "total") != 5.0 {
		t.Fatalf("partial = %s", stringify(partial))
	}
	asAlice = f.issue(f.record("identities", jsString(alice.Get("id"))), false)
	_, err := access(asAlice)
	expectCode(t, err, "ACCESS_DENIED")
	_, err = access(owner, "withinMs", -1.0)
	expectError(t, err, "INVALID_INPUT", "Invalid withinMs")
	_, err = access(owner, "unusedForMs", 11*365*reportTestDay)
	expectError(t, err, "INVALID_INPUT", "Invalid unusedForMs")
}

func TestReportWindowsAndFindings(t *testing.T) {
	windows, err := ReportWindows(body())
	if err != nil || stringify(windows) != `{"withinMs":2592000000,"unusedForMs":2592000000}` {
		t.Fatalf("defaults = %s %v", stringify(windows), err)
	}
	windows, err = ReportWindows(body("withinMs", 0.0, "unusedForMs", 10*365*reportTestDay))
	if err != nil || stringify(windows) != `{"withinMs":0,"unusedForMs":315360000000}` {
		t.Fatalf("bounds = %s %v", stringify(windows), err)
	}
	if _, err := ReportWindows(body("withinMs", 1.5)); err == nil {
		t.Fatal("a fractional window was accepted")
	}
	quiet := body("identities", body("total", 1.0, "disabled", 0.0, "expiring", items()), "omitted", items("bindings", "credentials"))
	if found, _ := ReportHasFindings(quiet); found {
		t.Fatal("a quiet report has findings")
	}
	quiet.Set("bindings", body("expiring", items(), "starting", items(), "expiringMemberships", items(), "activations", items(), "pendingRequests", 1.0))
	if found, _ := ReportHasFindings(quiet); !found {
		t.Fatal("a pending request is not a finding")
	}
	quiet.Set("bindings", body("expiring", items(), "starting", items(), "expiringMemberships", items(), "activations", items(), "pendingRequests", 0.0))
	quiet.Set("credentials", body("total", 1.0, "unused", items(body("id", "k")), "expiring", items()))
	if found, _ := ReportHasFindings(quiet); !found {
		t.Fatal("an unused key is not a finding")
	}
}

// objectsOf is a model array as objects.
func objectsOf(value any) []*core.Object {
	list, _ := value.([]any)
	objects := make([]*core.Object, len(list))
	for index, item := range list {
		objects[index], _ = item.(*core.Object)
	}
	return objects
}
