package server

// Change impact preview, after tests/impact.test.ts. (The simulation applies the change through the roles and
// policies API helpers and compares invariants.ts evaluations, which other units port; those tests skip until they
// land.)

import (
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

type impactScenario struct {
	f                       *directoryFixture
	tenantID                string
	owner                   core.CredentialInput
	alice, bob, carol, dave *core.Object
	reader, senior, writer  *core.Object
	writing                 *core.Object
}

var impactDoc = body("type", "document", "id", "d1")

func newImpactScenario(t *testing.T) *impactScenario {
	t.Helper()
	f := newAnalysisFixture(t, nil)
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	s := &impactScenario{f: f, tenantID: tenantID, owner: owner}
	s.alice = f.anaIdentity(tenantID, "alice")
	s.bob = f.anaIdentity(tenantID, "bob")
	s.carol = f.anaIdentity(tenantID, "carol")
	s.dave = f.anaIdentity(tenantID, "dave")
	s.reader = f.anaRole(tenantID, "Reader", "document", anaPermissions("documents:read"))
	s.senior = f.anaRole(tenantID, "Senior", "inherits", items(anaID(s.reader)))
	s.writing = f.anaPolicy(tenantID, "Writing", anaDocument(allow(items("documents:write"), items("*"))))
	s.writer = f.anaRole(tenantID, "Writer", "policyIds", items(anaID(s.writing)))
	team := f.anaGroup(tenantID, "Team")
	f.anaAddMembers(tenantID, anaID(team), anaID(s.bob))
	f.anaBinding(tenantID, anaID(s.reader), "identity", anaID(s.alice))
	f.anaBinding(tenantID, anaID(s.reader), "group", anaID(team))
	f.anaBinding(tenantID, anaID(s.senior), "identity", anaID(s.carol))
	f.anaBinding(tenantID, anaID(s.writer), "identity", anaID(s.dave))
	return s
}

func (s *impactScenario) preview(credential core.CredentialInput, pairs ...any) (Out[apitypes.ImpactPreviewOutput], error) {
	return s.f.iam.API.Impact.Preview(s.f.ctx, credential, Input[apitypes.ImpactPreviewInput](body(append([]any{"tenantId", s.tenantID}, pairs...)...)))
}

func TestImpactPreviewShowsGainsWithoutSaving(t *testing.T) {
	s := newImpactScenario(t)
	f := s.f
	out, err := s.preview(s.owner,
		"change", body("role", body("roleId", anaID(s.reader), "permissions", items("documents:read", "documents:write"))),
		"resources", items(impactDoc))
	preview := anaTryObject(t, out, err)
	if got := stringify(pluck(anaObjects(preview.Get("roles")), "name")); got != `["Reader","Senior"]` {
		t.Fatalf("roles = %s", got)
	}
	if stringify(preview.Get("evaluated")) != "3" || preview.Get("truncated") != false ||
		stringify(preview.Get("gainedTotal")) != "3" || stringify(preview.Get("lostTotal")) != "0" {
		t.Fatalf("preview = %s", stringify(preview))
	}
	if got := stringify(preview.Keys()); got != `["roles","evaluated","truncated","identities","gainedTotal","lostTotal","invariants"]` {
		t.Fatalf("preview keys = %s", got)
	}
	identities := anaObjects(preview.Get("identities"))
	got := anaSorted(pluck(pluckObjects(identities, "identity"), "id"))
	if want := anaSorted([]string{anaID(s.alice), anaID(s.bob), anaID(s.carol)}); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("identities = %v", got)
	}
	if got := stringify(identities[0].Get("changes")); got != `[{"resource":"document/d1","gained":["documents:write"],"lost":[]}]` {
		t.Fatalf("changes = %s", got)
	}
	if got := stringify(preview.Get("invariants")); got != `{"detailed":true,"brokenCount":0,"fixedCount":0,"broken":[],"fixed":[]}` {
		t.Fatalf("invariants = %s", got)
	}
	// Nothing was saved.
	if strings.Contains(stringify(f.record("roles", anaID(s.reader))), "documents:write") {
		t.Fatal("the role change was saved")
	}
	decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{Credential: f.issue(s.alice, false), TenantID: s.tenantID,
		Action: "documents:write", Resource: ResourceTarget{Type: "document", ID: "d1"}})
	if err != nil || decision.Allowed {
		t.Fatalf("authorize = %+v, %v", decision, err)
	}
}

func TestImpactPreviewsPolicyEditsAndRoleDeletion(t *testing.T) {
	s := newImpactScenario(t)
	f := s.f
	out, err := s.preview(s.owner,
		"change", body("policy", body("policyId", anaID(s.writing), "document", anaDocument(allow(items("documents:read"), items("*"))))),
		"resources", items(impactDoc))
	policy := anaTryObject(t, out, err)
	if got, want := stringify(policy.Get("identities")), stringify([]any{body(
		"identity", body("id", anaID(s.dave), "name", "dave@acme.test"),
		"changes", []any{body("resource", "document/d1", "gained", items("documents:read"), "lost", items("documents:write"))},
	)}); got != want {
		t.Fatalf("policy identities = %s", got)
	}
	if version := f.record("policies", anaID(s.writing)).Get("version"); stringify(version) != "1" {
		t.Fatalf("policy version = %v", version)
	}

	out, err = s.preview(s.owner, "change", body("deleteRole", anaID(s.writer)), "resources", items(impactDoc),
		"actions", items("documents:write"))
	removal := anaTryObject(t, out, err)
	if stringify(removal.Get("lostTotal")) != "1" ||
		stringify(anaObjects(anaObjects(removal.Get("identities"))[0].Get("changes"))[0].Get("lost")) != `["documents:write"]` {
		t.Fatalf("removal = %s", stringify(removal))
	}
	// Deleting a role others inherit is refused exactly as roles.delete would refuse it.
	_, err = s.preview(s.owner, "change", body("deleteRole", anaID(s.reader)), "resources", items(impactDoc))
	anaRefuse(t, err, "RESOURCE_IN_USE")
	kept := false
	for _, binding := range f.find("bindings", core.NewObject("tenantId", s.tenantID)) {
		kept = kept || binding.Get("roleId") == anaID(s.writer)
	}
	if !kept {
		t.Fatal("the writer binding was deleted")
	}
}

func TestImpactPreviewValidatesInput(t *testing.T) {
	s := newImpactScenario(t)
	_, err := s.preview(s.owner, "change", body("deleteRole", anaID(s.writer), "role", body("roleId", anaID(s.reader))),
		"resources", items(impactDoc))
	expectError(t, err, "INVALID_INPUT", "Provide exactly one of role, policy, or deleteRole")
	_, err = s.preview(s.owner, "change", body(), "resources", items(impactDoc))
	expectError(t, err, "INVALID_INPUT", "Provide exactly one of role, policy, or deleteRole")
	_, err = s.preview(s.owner, "change", body("deleteRole", anaID(s.writer)), "resources", items())
	expectError(t, err, "INVALID_INPUT", "Provide 1-10 resources")
	eleven := make([]any, 11)
	for index := range eleven {
		eleven[index] = impactDoc
	}
	_, err = s.preview(s.owner, "change", body("deleteRole", anaID(s.writer)), "resources", eleven)
	expectError(t, err, "INVALID_INPUT", "Provide 1-10 resources")
	_, err = s.preview(s.owner, "change", body("role", body()), "resources", items(impactDoc))
	expectError(t, err, "INVALID_INPUT", "Invalid roleId")
	_, err = s.preview(s.owner, "change", body("policy", body("policyId", anaID(s.writing))), "resources", items(impactDoc))
	expectCode(t, err, "INVALID_INPUT")
	_, err = s.preview(s.owner, "change", body("deleteRole", 5.0), "resources", items(impactDoc))
	expectError(t, err, "INVALID_INPUT", "Invalid deleteRole")
	_, err = s.preview(s.owner, "change", body("deleteRole", anaID(s.writer)), "resources", items(impactDoc), "actions", items())
	expectError(t, err, "INVALID_INPUT", "Compare 1-200 actions")
	_, err = s.preview(s.owner, "change", body("deleteRole", anaID(s.writer)), "resources", items(body("type", "document")))
	expectError(t, err, "INVALID_INPUT", "Invalid resource id")
	_, err = s.preview(s.owner, "change", body("deleteRole", anaID(s.writer)), "resources", items(impactDoc),
		"actions", items("documents:fly"))
	expectError(t, err, "INVALID_ACTION", "Unknown action documents:fly")
}

func TestImpactPreviewRequiresSimulateAndChangeRights(t *testing.T) {
	s := newImpactScenario(t)
	f := s.f
	_, err := s.preview(f.issue(s.alice, false), "change", body("deleteRole", anaID(s.writer)), "resources", items(impactDoc))
	expectCode(t, err, "ACCESS_DENIED")
	// Simulating is not enough: the preview also needs the permission the real change needs.
	simulator := f.anaRole(s.tenantID, "Simulator", "document", anaPermissions("iam:policies:simulate"))
	f.anaBinding(s.tenantID, anaID(simulator), "identity", anaID(s.bob))
	bob := f.issue(s.bob, false)
	for _, change := range []*core.Object{
		body("deleteRole", anaID(s.writer)),
		body("role", body("roleId", anaID(s.reader), "permissions", items("documents:write"))),
	} {
		_, err := s.preview(bob, "change", change, "resources", items(impactDoc))
		anaRefuse(t, err, "ACCESS_DENIED")
	}
}
