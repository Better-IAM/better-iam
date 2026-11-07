package server

// Self-service access paths, after tests/access-paths.test.ts.

import (
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

type accessPathsScenario struct {
	f          *directoryFixture
	tenantID   string
	owner      core.CredentialInput
	alice      *core.Object
	aliceToken core.CredentialInput
	bobToken   core.CredentialInput
	eligible   *core.Object
	pkg        *core.Object
	agreement  *core.Object
	writer     *core.Object
}

func newAccessPathsScenario(t *testing.T) *accessPathsScenario {
	t.Helper()
	f := newAnalysisFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{
			Actions: []string{"documents:read", "documents:write", "documents:delete", "documents:share"},
		}
	})
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	alice, aliceToken := f.anaMember(tenantID, "alice")
	_, bobToken := f.anaMember(tenantID, "bob")
	role := func(name string, statements ...*core.Object) *core.Object {
		return f.anaRole(tenantID, name, "document", anaDocument(statements...))
	}
	member := f.anaRole(tenantID, "Member", "document", anaPermissions("iam:packages:request", "iam:bindings:activate"))
	f.anaBinding(tenantID, anaID(member), "identity", anaID(alice))
	// Reading needs MFA.
	reader := role("MFA reader", allow(items("documents:read"), items("*"),
		"conditions", body("Bool", body("principal.mfa", true))))
	f.anaBinding(tenantID, anaID(reader), "identity", anaID(alice))
	// Writing through a just-in-time binding.
	writer := role("Writer", allow(items("documents:write"), items("*")))
	eligible := f.anaBinding(tenantID, anaID(writer), "identity", anaID(alice), "eligible", true, "requireJustification", true)
	// Deleting through a requestable package.
	deleter := role("Deleter", allow(items("documents:delete"), items("*")))
	pkg := f.anaPackage(tenantID, "Cleanup crew", []string{anaID(deleter)}, []string{}, "requestable", true)
	// Sharing once the acceptable-use policy is accepted.
	sharer := role("Sharer",
		allow(items("documents:share"), items("*")),
		core.NewObject("effect", "deny", "actions", items("documents:share"), "resources", items("*"),
			"conditions", body("NumericGreaterThan", body("principal.pendingAgreements", 0.0))),
	)
	f.anaBinding(tenantID, anaID(sharer), "identity", anaID(alice))
	agreement := f.anaAgreement(tenantID, "Acceptable use", "Be nice.")
	return &accessPathsScenario{f: f, tenantID: tenantID, owner: owner, alice: alice, aliceToken: aliceToken,
		bobToken: bobToken, eligible: eligible, pkg: pkg, agreement: agreement, writer: writer}
}

func (s *accessPathsScenario) find(credential core.CredentialInput, action string) (Out[apitypes.AccessPathsFindOutput], error) {
	return s.f.iam.API.AccessPaths.Find(s.f.ctx, credential, Input[apitypes.AccessPathsFindInput](body(
		"tenantId", s.tenantID, "action", action, "resource", body("type", "document", "id", "d1"),
	)))
}

func TestAccessPathsFindsEachWayToBeAllowed(t *testing.T) {
	s := newAccessPathsScenario(t)
	f := s.f
	paths := func(action string, credential core.CredentialInput) *core.Object {
		out, err := s.find(credential, action)
		return anaTryObject(t, out, err)
	}

	read := paths("documents:read", s.aliceToken)
	if read.Get("allowed") != false || !anaIsString(read.Get("reason")) || stringify(read.Get("paths")) != `[{"kind":"mfa"}]` ||
		stringify(read.Keys()) != `["allowed","reason","paths"]` {
		t.Fatalf("read = %s", stringify(read))
	}
	if got := stringify(paths("documents:share", s.aliceToken).Get("paths")); got != stringify([]any{body(
		"kind", "accept-agreements", "agreements", []any{body("id", anaID(s.agreement), "name", "Acceptable use", "version", 1.0)},
	)}) {
		t.Fatalf("share = %s", got)
	}
	if got := stringify(paths("documents:write", s.aliceToken).Get("paths")); got != stringify([]any{body(
		"kind", "activate", "bindingId", anaID(s.eligible), "role", body("id", anaID(s.writer), "name", "Writer"),
		"requireApproval", false, "requireJustification", true, "requireMfa", false,
	)}) {
		t.Fatalf("write = %s", got)
	}
	if got := stringify(paths("documents:delete", s.aliceToken).Get("paths")); got != stringify([]any{body(
		"kind", "request-package", "package", body("id", anaID(s.pkg), "name", "Cleanup crew"), "requireJustification", false,
	)}) {
		t.Fatalf("delete = %s", got)
	}
	// Someone with none of these options gets no paths.
	if bob := paths("documents:delete", s.bobToken); bob.Get("allowed") != false || stringify(bob.Get("paths")) != `[]` {
		t.Fatalf("bob = %s", stringify(bob))
	}

	// Nothing was saved by the simulations.
	if activations := f.find("bindingActivations", core.NewObject("tenantId", s.tenantID)); len(activations) != 0 {
		t.Fatalf("activations = %s", stringify(activations))
	}
	if accepted := f.find("agreementAcceptances", core.NewObject("tenantId", s.tenantID)); len(accepted) != 0 {
		t.Fatalf("acceptances = %s", stringify(accepted))
	}
	for _, binding := range f.find("bindings", core.NewObject("tenantId", s.tenantID)) {
		if key, _ := binding.Get("uniqueKey").(string); len(key) >= 11 && key[:11] == "simulation:" {
			t.Fatalf("simulated binding left behind: %s", stringify(binding))
		}
	}
	decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{
		Credential: s.aliceToken, TenantID: s.tenantID, Action: "documents:delete",
		Resource: ResourceTarget{Type: "document", ID: "d1"},
	})
	if err != nil || decision.Allowed {
		t.Fatalf("authorize = %+v, %v", decision, err)
	}

	// Taking a path works: accepting the agreement allows sharing, and then no paths are needed.
	f.seed("agreementAcceptances", core.NewObject(
		"id", anaID(s.agreement)+":"+anaID(s.alice), "tenantId", s.tenantID, "agreementId", anaID(s.agreement),
		"identityId", anaID(s.alice), "version", 1.0, "acceptedAt", f.now(),
	))
	if share := paths("documents:share", s.aliceToken); share.Get("allowed") != true || !anaIsString(share.Get("reason")) ||
		stringify(share.Get("paths")) != `[]` {
		t.Fatalf("share after accepting = %s", stringify(share))
	}
}

func TestAccessPathsServesOrdinarySessionsAndKnownActions(t *testing.T) {
	s := newAccessPathsScenario(t)
	_, err := s.find(s.f.rootCred, "documents:read")
	expectError(t, err, "ACCESS_DENIED", "Access paths are for an ordinary session of the tenant")
	_, err = s.find(s.aliceToken, "documents:fly")
	expectError(t, err, "INVALID_ACTION", "Unknown action documents:fly")
}

func TestAccessPathsValidatesInput(t *testing.T) {
	s := newAccessPathsScenario(t)
	find := func(pairs ...any) error {
		_, err := s.f.iam.API.AccessPaths.Find(s.f.ctx, s.aliceToken, Input[apitypes.AccessPathsFindInput](body(pairs...)))
		return err
	}
	expectError(t, find("action", "documents:read", "resource", body("type", "document", "id", "d1")), "INVALID_INPUT", "Invalid tenantId")
	expectError(t, find("tenantId", s.tenantID, "resource", body("type", "document", "id", "d1")), "INVALID_INPUT", "Invalid action")
	expectError(t, find("tenantId", s.tenantID, "action", "documents:read", "resource", body("id", "d1")), "INVALID_INPUT", "Invalid resource type")
	expectError(t, find("tenantId", s.tenantID, "action", "documents:read", "resource", body("type", "document")), "INVALID_INPUT", "Invalid resource id")
	expectCode(t, find("tenantId", s.tenantID, "action", "documents:read"), "INVALID_INPUT")
}

func anaIsString(value any) bool {
	_, ok := value.(string)
	return ok
}
