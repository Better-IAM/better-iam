package server

// Ports of the tests of packages/server/src/api/policies.ts: the policy-version and document-test case of
// tests/policy-tools.test.ts, tests/reviews.test.ts (whoCan, effectiveActions), the policy parts of
// tests/server.test.ts, and the "an editor cannot lift a deny another administrator relies on" cases of
// tests/security-engine.test.ts. See api_roles_test.go for the fixture.

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

func (f *orgFixture) createPolicy(credential core.CredentialInput, name string, document any) (*core.Object, error) {
	f.t.Helper()
	answer, err := f.iam.API.Policies.Create(f.ctx, credential, Input[apitypes.PoliciesCreateInput](core.NewObject(
		"tenantId", f.tenantID, "name", name, "document", document)))
	if err != nil {
		return nil, err
	}
	return answer.Value.(*core.Object), nil
}

func (f *orgFixture) updatePolicy(credential core.CredentialInput, members ...any) (*core.Object, error) {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID)
	input.Assign(core.NewObject(members...))
	answer, err := f.iam.API.Policies.Update(f.ctx, credential, Input[apitypes.PoliciesUpdateInput](input))
	if err != nil {
		return nil, err
	}
	return answer.Value.(*core.Object), nil
}

func (f *orgFixture) restoreVersion(version any, policyID any) (*core.Object, error) {
	f.t.Helper()
	answer, err := f.iam.API.Policies.RestoreVersion(f.ctx, f.owner, Input[apitypes.PoliciesRestoreVersionInput](core.NewObject(
		"tenantId", f.tenantID, "policyId", policyID, "version", version)))
	if err != nil {
		return nil, err
	}
	return answer.Value.(*core.Object), nil
}

func (f *orgFixture) testDocument(members ...any) (*core.Object, error) {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID)
	input.Assign(core.NewObject(members...))
	answer, err := f.iam.API.Policies.Test(f.ctx, f.owner, Input[apitypes.PoliciesTestInput](input))
	if err != nil {
		return nil, err
	}
	return answer.Value.(*core.Object), nil
}

func TestPoliciesRestoreEarlierVersionsAndEvaluateCandidateDocuments(t *testing.T) {
	f := newOrgFixture(t, nil)
	readOnly := `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"]}]}`
	readWrite := `{"version":1,"statements":[{"effect":"allow","actions":["documents:read","documents:write"],"resources":["document/*"]}]}`
	policy, err := f.createPolicy(f.owner, "Documents", obj(t, readOnly))
	requirePorted(t, err)
	if policy.Get("version") != 1.0 {
		t.Fatalf("a new policy starts at version 1: %s", core.MustStringify(policy))
	}
	_, err = f.updatePolicy(f.owner, "policyId", policy.Get("id"), "version", 1.0, "document", obj(t, readWrite))
	requirePorted(t, err)
	_, err = f.restoreVersion(2.0, policy.Get("id"))
	expectError(t, err, "INVALID_INPUT", "That version is already current")
	_, err = f.restoreVersion(9.0, policy.Get("id"))
	expectCode(t, err, "INVALID_INPUT")
	restored, err := f.restoreVersion(1.0, policy.Get("id"))
	requirePorted(t, err)
	if restored.Get("version") != 3.0 || core.MustStringify(restored.Get("document")) != readOnly {
		t.Fatalf("restored: %s", core.MustStringify(restored))
	}
	versions := f.items(f.iam.API.Policies.ListVersions(f.ctx, f.owner, Input[apitypes.PoliciesListVersionsInput](core.NewObject(
		"tenantId", f.tenantID, "policyId", policy.Get("id")))))
	var numbers []float64
	for _, version := range versions {
		numbers = append(numbers, jsNumber(version.Get("version")))
		if version.Has("uniqueKey") {
			t.Fatalf("versions are listed without their unique key: %s", core.MustStringify(version))
		}
	}
	if !reflect.DeepEqual(numbers, []float64{1, 2, 3}) {
		t.Fatalf("versions: %v", numbers)
	}
	if core.MustStringify(versions[1].Get("document")) != readWrite {
		t.Fatalf("version 2: %s", core.MustStringify(versions[1]))
	}
	if versions[0].Get("policyId") != policy.Get("id") {
		t.Fatalf("archived versions name their policy: %s", core.MustStringify(versions[0]))
	}
	// Candidate documents evaluate against caller-supplied context without being stored.
	conditional := `{"version":1,"statements":[{"effect":"allow","actions":["documents:write"],"resources":["document/${principal.id}-*"],"conditions":{"Bool":{"principal.mfa":true}}}]}`
	allowed, err := f.testDocument("document", obj(t, conditional), "action", "documents:write", "resource", "document/alice-notes",
		"context", obj(t, `{"principal.id":"alice","principal.mfa":true}`))
	requirePorted(t, err)
	if allowed.Get("allowed") != true || len(asList(allowed.Get("matched"))) != 1 {
		t.Fatalf("allowed: %s", core.MustStringify(allowed))
	}
	denied, err := f.testDocument("document", obj(t, conditional), "action", "documents:write", "resource", "document/alice-notes",
		"context", obj(t, `{"principal.id":"alice","principal.mfa":false}`))
	requirePorted(t, err)
	if denied.Get("allowed") != false {
		t.Fatalf("denied: %s", core.MustStringify(denied))
	}
	_, err = f.testDocument("document", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:burn"],"resources":["*"]}]}`),
		"action", "documents:burn", "resource", "document/x")
	expectCode(t, err, "INVALID_ACTION")
	count := 0
	for _, item := range f.items(f.iam.API.Policies.List(f.ctx, f.owner, Input[apitypes.PoliciesListInput](core.NewObject("tenantId", f.tenantID)))) {
		if item.Get("name") == "Documents" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("a document test stores nothing: %d policies named Documents", count)
	}
}

func TestPoliciesTestValidatesItsContextAndDefaultsTheServerKeys(t *testing.T) {
	f := newOrgFixture(t, nil)
	tooMany := core.NewObject()
	for index := 0; index < 201; index++ {
		tooMany.Set("k"+core.NumberString(float64(index)), true)
	}
	document := obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"],"conditions":{"StringEquals":{"principal.sessionId":"simulation","principal.tenantId":"${resource.tenantId}"}}}]}`)
	_, err := f.testDocument("document", document, "action", "documents:read", "resource", "document/x", "context", tooMany)
	expectError(t, err, "INVALID_INPUT", "context may hold at most 200 keys")
	// The synthetic session's keys match the document; the caller's context overrides them.
	result, err := f.testDocument("document", document, "action", "documents:read", "resource", "document/x")
	requirePorted(t, err)
	if result.Get("allowed") != true {
		t.Fatalf("defaults: %s", core.MustStringify(result))
	}
	result, err = f.testDocument("document", document, "action", "documents:read", "resource", "document/x",
		"context", obj(t, `{"principal.sessionId":"other"}`))
	requirePorted(t, err)
	if result.Get("allowed") != false {
		t.Fatalf("override: %s", core.MustStringify(result))
	}
}

func TestPoliciesAreValidatedAgainstTheActionCatalogAndConfiguredResourceTypes(t *testing.T) {
	f := newOrgFixture(t, func(options *BetterIamOptions) { options.Permissions.Mode = "tenant-defined" })
	_, err := f.createPolicy(f.owner, "Typo", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:raed"],"resources":["*"]}]}`))
	expectCode(t, err, "INVALID_ACTION")
	_, err = f.iam.API.Roles.Create(f.ctx, f.owner, Input[apitypes.RolesCreateInput](core.NewObject(
		"tenantId", f.tenantID, "name", "Typo", "permissions", []any{"documents:read", "nope:read"})))
	expectCode(t, err, "INVALID_ACTION")
	wildcards, err := f.createPolicy(f.owner, "Wildcards", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:*"],"resources":["anything/*"]}]}`))
	requirePorted(t, err)
	if wildcards.Get("version") != 1.0 {
		t.Fatalf("wildcards: %s", core.MustStringify(wildcards))
	}
	strict, err := New(&BetterIamOptions{
		Database: f.store, Secret: "tenants-test-secret-with-at-least-32-characters", BaseURL: "http://localhost:3000",
		Permissions: &core.PermissionsConfig{Mode: "tenant-defined", ResourceTypes: []core.NamedResourceType{{
			Name: "document", Definition: core.ResourceTypeDefinition{
				Actions: []string{"documents:read", "documents:write"}, Attributes: []core.NamedAttribute{{Name: "classification", Type: "string"}},
			},
		}}},
		ResolveResource: func(_ context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			return &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID}, nil
		},
		WallClock:      func() int64 { return f.clock.Load() },
		Authentication: &auth.Options{Now: func() int64 { return f.clock.Load() }},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(strict.Close)
	_, err = strict.API.Policies.Create(f.ctx, f.owner, Input[apitypes.PoliciesCreateInput](core.NewObject("tenantId", f.tenantID,
		"name", "Unknown type", "document", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["folder/*"]}]}`))))
	expectCode(t, err, "INVALID_RESOURCE_TYPE")
	known, err := strict.API.Policies.Create(f.ctx, f.owner, Input[apitypes.PoliciesCreateInput](core.NewObject("tenantId", f.tenantID,
		"name", "Known type", "document", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["document/*","iam/*"]}]}`))))
	requirePorted(t, err)
	if member(known.Value, "name") != "Known type" {
		t.Fatalf("known type: %s", core.MustStringify(known.Value))
	}
}

func TestPoliciesRequireMatchingVersionsAndBoundariesApplyImmediately(t *testing.T) {
	f := newOrgFixture(t, func(options *BetterIamOptions) { options.Permissions.Mode = "tenant-defined" })
	policy, err := f.createPolicy(f.owner, "Versioned", obj(t, `{"version":1,"statements":[]}`))
	requirePorted(t, err)
	update := func() (*core.Object, error) {
		return f.updatePolicy(f.owner, "policyId", policy.Get("id"), "version", 1.0,
			"document", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"]}]}`))
	}
	updated, err := update()
	requirePorted(t, err)
	if updated.Get("version") != 2.0 {
		t.Fatalf("updated: %s", core.MustStringify(updated))
	}
	_, err = update()
	expectError(t, err, "VERSION_CONFLICT", "Policy version changed")
	f.ported(f.iam.API.Tenants.SetBoundary(f.ctx, f.credential, Input[apitypes.TenantsSetBoundaryInput](core.NewObject(
		"tenantId", f.tenantID, "boundary", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["iam:*"],"resources":["*"]}]}`)))))
	if f.can(f.owner, "documents:read", "document", "report") {
		t.Fatal("a restrictive boundary applies at once")
	}
}

func TestPoliciesGuardTheOwnerPolicyAndAttachedPolicies(t *testing.T) {
	f := newOrgFixture(t, nil)
	var ownerPolicy *core.Object
	for _, policy := range f.items(f.iam.API.Policies.List(f.ctx, f.owner, Input[apitypes.PoliciesListInput](core.NewObject("tenantId", f.tenantID)))) {
		if policy.Get("uniqueKey") == "system:owner" {
			ownerPolicy = policy
		}
	}
	if ownerPolicy == nil {
		t.Fatal("the organization has an Owner policy")
	}
	_, err := f.updatePolicy(f.owner, "policyId", ownerPolicy.Get("id"), "version", ownerPolicy.Get("version"), "name", "Mine")
	expectCode(t, err, "PROTECTED_RESOURCE")
	_, err = f.iam.API.Policies.Delete(f.ctx, f.owner, Input[apitypes.PoliciesDeleteInput](core.NewObject("tenantId", f.tenantID, "policyId", ownerPolicy.Get("id"))))
	expectCode(t, err, "PROTECTED_RESOURCE")
	policy, err := f.createPolicy(f.owner, "Readers", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"]}]}`))
	requirePorted(t, err)
	_, err = f.updatePolicy(f.owner, "policyId", policy.Get("id"), "version", 1.0)
	expectError(t, err, "INVALID_INPUT", "Nothing to update")
	role := f.createRole(f.owner, "name", "Reader", "policyIds", []any{policy.Get("id")})
	_, err = f.iam.API.Policies.Delete(f.ctx, f.owner, Input[apitypes.PoliciesDeleteInput](core.NewObject("tenantId", f.tenantID, "policyId", policy.Get("id"))))
	expectError(t, err, "RESOURCE_IN_USE", "Detach policy before deletion")
	_, err = f.updateRole(f.owner, "roleId", role.Get("id"), "policyIds", []any{})
	requirePorted(t, err)
	deleted := f.object(f.iam.API.Policies.Delete(f.ctx, f.owner, Input[apitypes.PoliciesDeleteInput](core.NewObject("tenantId", f.tenantID, "policyId", policy.Get("id")))))
	if deleted.Get("deleted") != true {
		t.Fatalf("deleted: %s", core.MustStringify(deleted))
	}
}

func TestPoliciesAccessReviewsListWhoCanActAndWhichActionsAnIdentityHolds(t *testing.T) {
	f := newOrgFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{ResourceTypes: []core.NamedResourceType{{Name: "folder", Definition: core.ResourceTypeDefinition{
			Managed: true, Actions: []string{"folders:read", "folders:write"}, Relations: []string{"viewer", "editor"},
		}}}}
		options.ResolveResource = nil
	})
	alice, bob, carol := f.member("alice"), f.member("bob"), f.member("carol")
	bot := f.object(f.iam.API.ServiceAccounts.Create(f.ctx, f.owner, Input[apitypes.ServiceAccountsCreateInput](core.NewObject("tenantId", f.tenantID, "name", "bot"))))
	readers := f.createRole(f.owner, "name", "Readers", "permissions", []any{"folders:read"})
	mfaWriters := f.createRole(f.owner, "name", "MFA writers", "document", obj(t,
		`{"version":1,"statements":[{"effect":"allow","actions":["folders:write"],"resources":["folder/*"],"conditions":{"Bool":{"principal.mfa":true}}}]}`))
	sharing := f.createRole(f.owner, "name", "Sharing", "document", obj(t,
		`{"version":1,"statements":[{"effect":"allow","actions":["folders:read"],"resources":["folder/*"],"conditions":{"ArrayContains":{"resource.relations":["viewer","editor"]}}}]}`))
	f.bind(f.owner, readers.Get("id"), "identity", alice.Get("id"))
	f.bind(f.owner, mfaWriters.Get("id"), "identity", alice.Get("id"))
	f.bind(f.owner, readers.Get("id"), "identity", bot.Get("id"))
	f.bind(f.owner, sharing.Get("id"), "identity", carol.Get("id"))
	f.ported(f.iam.API.Resources.Register(f.ctx, f.owner, Input[apitypes.ResourcesRegisterInput](core.NewObject("tenantId", f.tenantID, "type", "folder", "id", "plans"))))
	f.ported(f.iam.API.Relationships.Create(f.ctx, f.owner, Input[apitypes.RelationshipsCreateInput](core.NewObject(
		"tenantId", f.tenantID, "type", "folder", "id", "plans", "relation", "viewer", "subjectType", "identity", "subjectId", carol.Get("id")))))
	whoCan := func(credential core.CredentialInput, members ...any) (*core.Object, error) {
		input := core.NewObject("tenantId", f.tenantID)
		input.Assign(core.NewObject(members...))
		answer, err := f.iam.API.Policies.WhoCan(f.ctx, credential, Input[apitypes.PoliciesWhoCanInput](input))
		if err != nil {
			return nil, err
		}
		return answer.Value.(*core.Object), nil
	}
	plans := core.NewObject("type", "folder", "id", "plans")
	names := func(review *core.Object, sorted bool) []string {
		var result []string
		for _, item := range asList(review.Get("identities")) {
			result = append(result, jsString(member(item, "name")))
		}
		if sorted {
			sort.Strings(result)
		}
		return result
	}
	ownerName := jsString(f.org.owner.Get("name"))
	// Who can read: the owner (Owner role), alice (Readers), bot (Readers), carol (relation). Bob cannot.
	readersOfPlans, err := whoCan(f.owner, "action", "folders:read", "resource", plans)
	requirePorted(t, err)
	if readersOfPlans.Get("total") != 4.0 {
		t.Fatalf("readers: %s", core.MustStringify(readersOfPlans))
	}
	want := []string{ownerName, "alice", "bot", "carol"}
	sort.Strings(want)
	if got := names(readersOfPlans, true); !reflect.DeepEqual(got, want) {
		t.Fatalf("readers: %v", got)
	}
	for _, item := range asList(readersOfPlans.Get("identities")) {
		if member(item, "reason") != "allowed" || member(item, "identityId") == bob.Get("id") {
			t.Fatalf("reader: %s", core.MustStringify(item))
		}
	}
	// Filters and pagination.
	people, err := whoCan(f.owner, "action", "folders:read", "resource", plans, "kind", "user", "limit", 2.0)
	requirePorted(t, err)
	if people.Get("total") != 3.0 || len(asList(people.Get("identities"))) != 2 {
		t.Fatalf("people: %s", core.MustStringify(people))
	}
	// Writing needs MFA: nobody without a simulated MFA session, alice and the owner with one.
	writers, err := whoCan(f.owner, "action", "folders:write", "resource", plans)
	requirePorted(t, err)
	if got := names(writers, false); !reflect.DeepEqual(got, []string{ownerName}) {
		t.Fatalf("writers: %v", got)
	}
	mfaReview, err := whoCan(f.owner, "action", "folders:write", "resource", plans, "assumeMfa", true)
	requirePorted(t, err)
	want = []string{ownerName, "alice"}
	sort.Strings(want)
	if got := names(mfaReview, true); !reflect.DeepEqual(got, want) {
		t.Fatalf("MFA writers: %v", got)
	}
	// Unknown actions and unregistered resources are rejected; reviews need iam:policies:simulate.
	_, err = whoCan(f.owner, "action", "folders:burn", "resource", plans)
	expectError(t, err, "INVALID_ACTION", "Unknown action folders:burn")
	_, err = whoCan(f.owner, "action", "folders:read", "resource", core.NewObject("type", "folder", "id", "missing"))
	expectCode(t, err, "NOT_FOUND")
	_, err = whoCan(f.login("alice"), "action", "folders:read", "resource", plans)
	expectCode(t, err, "ACCESS_DENIED")
	effective := func(members ...any) (*core.Object, error) {
		input := core.NewObject("tenantId", f.tenantID)
		input.Assign(core.NewObject(members...))
		answer, err := f.iam.API.Policies.EffectiveActions(f.ctx, f.owner, Input[apitypes.PoliciesEffectiveActionsInput](input))
		if err != nil {
			return nil, err
		}
		return answer.Value.(*core.Object), nil
	}
	// Effective actions of one identity on the resource, over the whole catalog or a chosen list.
	aliceActions, err := effective("identityId", alice.Get("id"), "resource", plans)
	requirePorted(t, err)
	expectStrings(t, aliceActions.Get("allowed"), "folders:read")
	results := asList(aliceActions.Get("results"))
	if len(results) <= 50 {
		t.Fatalf("the whole catalog is reviewed: %d actions", len(results))
	}
	var tenantsRead any
	for _, item := range results {
		if member(item, "action") == "iam:tenants:read" {
			tenantsRead = item
		}
	}
	if member(tenantsRead, "allowed") != false || member(tenantsRead, "reason") != "NO_APPLICABLE_GRANT" {
		t.Fatalf("iam:tenants:read: %s", core.MustStringify(tenantsRead))
	}
	aliceWithMfa, err := effective("identityId", alice.Get("id"), "resource", plans,
		"actions", []any{"folders:read", "folders:write", "iam:groups:read"}, "assumeMfa", true)
	requirePorted(t, err)
	expectStrings(t, aliceWithMfa.Get("allowed"), "folders:read", "folders:write")
	var reviewed []any
	for _, item := range asList(aliceWithMfa.Get("results")) {
		reviewed = append(reviewed, member(item, "action"))
	}
	expectStrings(t, reviewed, "folders:read", "folders:write", "iam:groups:read")
	_, err = effective("identityId", alice.Get("id"), "resource", plans, "actions", []any{"nothing:here"})
	expectError(t, err, "INVALID_ACTION", "Unknown action nothing:here")
	// The owner holds everything through the protected Owner role.
	ownerActions, err := effective("identityId", f.ownerID, "resource", plans, "actions", []any{"folders:read", "folders:write", "iam:policies:simulate"})
	requirePorted(t, err)
	expectStrings(t, ownerActions.Get("allowed"), "folders:read", "folders:write", "iam:policies:simulate")
	// Reviews are audited like other administrative reads.
	if got := len(f.auditTrail(f.tenantID, "iam:policies:simulate")); got < 6 {
		t.Fatalf("expected at least 6 audited reviews, got %d", got)
	}
}

// guardAttachedByOwner is security-engine.test.ts guardAttachedByOwner: an editor with a read-only grant authority
// creates a policy that allows reads and denies writes to legal documents.
func guardAttachedByOwner(t *testing.T) (f *orgFixture, editor core.CredentialInput, policy *core.Object, allowRead, denyLegal string) {
	t.Helper()
	f = newOrgFixture(t, nil)
	person := f.member("editor")
	policyAdmin := f.createRole(f.owner, "name", "Policy editor", "permissions", []any{"iam:policies:create", "iam:policies:update", "iam:policies:read"})
	f.bind(f.owner, policyAdmin.Get("id"), "identity", person.Get("id"))
	f.object(f.iam.API.Authorities.Create(f.ctx, f.ownerSignIn(), Input[apitypes.AuthoritiesCreateInput](core.NewObject(
		"tenantId", f.tenantID, "identityId", person.Get("id"),
		"ceiling", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"]}]}`)))))
	editor = f.login("editor")
	allowRead = `{"effect":"allow","actions":["documents:read"],"resources":["document/*"]}`
	denyLegal = `{"effect":"deny","actions":["documents:write"],"resources":["document/legal-*"]}`
	policy, err := f.createPolicy(editor, "Legal guard", obj(t, `{"version":1,"statements":[`+allowRead+`,`+denyLegal+`]}`))
	requirePorted(t, err)
	return f, editor, policy, allowRead, denyLegal
}

func TestPoliciesEditorCannotRemoveADenyOnceASuperiorAttachedThePolicy(t *testing.T) {
	f, editor, policy, allowRead, denyLegal := guardAttachedByOwner(t)
	staff := f.createRole(f.owner, "name", "Staff", "permissions", []any{"documents:read", "documents:write"})
	_, err := f.updateRole(f.owner, "roleId", staff.Get("id"), "policyIds", []any{policy.Get("id")})
	requirePorted(t, err)
	_, err = f.updatePolicy(editor, "policyId", policy.Get("id"), "version", policy.Get("version"),
		"document", obj(t, `{"version":1,"statements":[`+allowRead+`]}`))
	expectCode(t, err, "PROTECTED_RESOURCE")
	// Adding a deny, or changing only allows, stays possible.
	_, err = f.updatePolicy(editor, "policyId", policy.Get("id"), "version", policy.Get("version"),
		"document", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["document/public-*"]},`+
			denyLegal+`,{"effect":"deny","actions":["documents:write"],"resources":["document/hr-*"]}]}`))
	requirePorted(t, err)
}

func TestPoliciesEditorChangesTheirPolicyWhileNobodyElseReliesOnIt(t *testing.T) {
	f, editor, policy, allowRead, _ := guardAttachedByOwner(t)
	_, err := f.updatePolicy(editor, "policyId", policy.Get("id"), "version", policy.Get("version"),
		"document", obj(t, `{"version":1,"statements":[`+allowRead+`]}`))
	requirePorted(t, err)
}
