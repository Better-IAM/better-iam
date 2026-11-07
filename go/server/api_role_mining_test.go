package server

// Role mining and peer outliers, after tests/role-mining.test.ts. (Suggestions and apply go through teams.ts
// isTeamGroup and the bindings API, which other units port; those tests skip until they land.)

import (
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

type miningScenario struct {
	f                                 *directoryFixture
	tenantID                          string
	owner                             core.CredentialInput
	ana, ben, cai, dee, eve           *core.Object
	eveToken                          core.CredentialInput
	reader, writer, auditor, deployer *core.Object
	eng, ops                          *core.Object
	direct                            *core.Object
}

func newMiningScenario(t *testing.T) *miningScenario {
	t.Helper()
	f := newAnalysisFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{
			Actions:            []string{"documents:read", "documents:write"},
			IdentityAttributes: []core.NamedAttribute{{Name: "department", Type: "string"}},
		}
	})
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	person := func(name, department string) (*core.Object, core.CredentialInput) {
		return f.person(tenantID, name, "attributes", body("department", department))
	}
	s := &miningScenario{f: f, tenantID: tenantID, owner: owner}
	s.ana, _ = person("ana", "eng")
	s.ben, _ = person("ben", "eng")
	s.cai, _ = person("cai", "eng")
	s.dee, _ = person("dee", "eng")
	s.eve, s.eveToken = person("eve", "sales")
	role := func(name string, permissions ...string) *core.Object {
		return f.anaRole(tenantID, name, "document", anaPermissions(permissions...))
	}
	s.reader = role("Reader", "documents:read")
	s.writer = role("Writer", "documents:write")
	s.auditor = role("Auditor", "documents:read")
	s.deployer = role("Deployer", "documents:read", "documents:write")
	for _, who := range []*core.Object{s.ana, s.ben, s.cai} {
		f.anaBinding(tenantID, anaID(s.reader), "identity", anaID(who))
		f.anaBinding(tenantID, anaID(s.writer), "identity", anaID(who))
	}
	s.eng = f.anaGroup(tenantID, "Engineering")
	f.anaAddMembers(tenantID, anaID(s.eng), anaID(s.ana), anaID(s.ben), anaID(s.cai))
	s.ops = f.anaGroup(tenantID, "Operations")
	f.anaAddMembers(tenantID, anaID(s.ops), anaID(s.dee), anaID(s.eve))
	f.anaBinding(tenantID, anaID(s.deployer), "group", anaID(s.ops))
	s.direct = f.anaBinding(tenantID, anaID(s.deployer), "identity", anaID(s.dee))
	return s
}

func (s *miningScenario) suggest(t *testing.T, credential core.CredentialInput, pairs ...any) (Out[apitypes.RoleMiningSuggestOutput], error) {
	return s.f.iam.API.RoleMining.Suggest(s.f.ctx, credential, Input[apitypes.RoleMiningSuggestInput](body(append([]any{"tenantId", s.tenantID}, pairs...)...)))
}

func (s *miningScenario) outliers(credential core.CredentialInput, pairs ...any) (Out[apitypes.RoleMiningOutliersOutput], error) {
	return s.f.iam.API.RoleMining.Outliers(s.f.ctx, credential, Input[apitypes.RoleMiningOutliersInput](body(append([]any{"tenantId", s.tenantID}, pairs...)...)))
}

func (s *miningScenario) apply(credential core.CredentialInput, suggestionID string) (Out[apitypes.RoleMiningApplyOutput], error) {
	return s.f.iam.API.RoleMining.Apply(s.f.ctx, credential, Input[apitypes.RoleMiningApplyInput](body("tenantId", s.tenantID, "suggestionId", suggestionID)))
}

func refNames(refs any, key string) []string {
	return pluck(anaObjects(refs), key)
}

func suggestionOf(suggestions []*core.Object, keep func(*core.Object) bool) *core.Object {
	for _, suggestion := range suggestions {
		if keep(suggestion) {
			return suggestion
		}
	}
	return nil
}

func ofKind(kind string) func(*core.Object) bool {
	return func(suggestion *core.Object) bool { return suggestion.Get("kind") == kind }
}

func TestRoleMiningSuggestsSimplerGrants(t *testing.T) {
	s := newMiningScenario(t)
	out, err := s.suggest(t, s.owner)
	result := anaTryObject(t, out, err)
	if got := stringify(result.Get("summary")); got != `{"bundle":1,"group-binding":2,"redundant-binding":1,"duplicate-roles":1}` {
		t.Fatalf("summary = %s", got)
	}
	suggestions := anaObjects(result.Get("suggestions"))
	first := suggestions[0]
	if first.Get("kind") != "redundant-binding" || stringify(first.Get("group")) != stringify(body("id", anaID(s.ops), "name", "Operations")) ||
		stringify(first.Get("bindingIds")) != stringify([]any{anaID(s.direct)}) ||
		stringify(first.Get("identities")) != stringify([]any{body("id", anaID(s.dee), "name", "dee@acme.test")}) ||
		first.Get("applicable") != true {
		t.Fatalf("first = %s", stringify(first))
	}
	bundle := suggestionOf(suggestions, ofKind("bundle"))
	if got := anaSorted(refNames(bundle.Get("roles"), "name")); strings.Join(got, ",") != "Reader,Writer" {
		t.Fatalf("bundle roles = %v", got)
	}
	if got, want := anaSorted(refNames(bundle.Get("identities"), "id")), anaSorted([]string{anaID(s.ana), anaID(s.ben), anaID(s.cai)}); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("bundle identities = %v", got)
	}
	if bundle.Get("savings") != 3.0 && bundle.Get("savings") != 3 {
		t.Fatalf("bundle savings = %v", bundle.Get("savings"))
	}
	duplicate := suggestionOf(suggestions, ofKind("duplicate-roles"))
	if got := anaSorted(refNames(duplicate.Get("roles"), "name")); strings.Join(got, ",") != "Auditor,Reader" {
		t.Fatalf("duplicate roles = %v", got)
	}
	var groupRoles []string
	for _, suggestion := range suggestions {
		if suggestion.Get("kind") != "group-binding" {
			continue
		}
		groupRoles = append(groupRoles, jsString(anaObjects(suggestion.Get("roles"))[0].Get("name")))
		if member(suggestion.Get("group"), "id") != anaID(s.eng) || stringify(suggestion.Get("savings")) != "2" {
			t.Fatalf("group binding = %s", stringify(suggestion))
		}
	}
	if strings.Join(anaSorted(groupRoles), ",") != "Reader,Writer" {
		t.Fatalf("group binding roles = %v", groupRoles)
	}
	// Stable IDs across runs; kinds and thresholds filter.
	out, err = s.suggest(t, s.owner)
	again := anaTryObject(t, out, err)
	if stringify(pluck(anaObjects(again.Get("suggestions")), "id")) != stringify(pluck(suggestions, "id")) {
		t.Fatal("suggestion IDs changed between runs")
	}
	out, err = s.suggest(t, s.owner, "kinds", items("bundle"))
	bundles := anaTryObject(t, out, err)
	if got := stringify(pluck(anaObjects(bundles.Get("suggestions")), "kind")); got != `["bundle"]` {
		t.Fatalf("bundles = %s", got)
	}
	out, err = s.suggest(t, s.owner, "minIdentities", 4.0)
	strict := anaTryObject(t, out, err)
	if member(strict.Get("summary"), "bundle") != 0 && stringify(member(strict.Get("summary"), "bundle")) != "0" {
		t.Fatalf("strict = %s", stringify(strict.Get("summary")))
	}
	if stringify(member(strict.Get("summary"), "group-binding")) != "0" {
		t.Fatalf("strict = %s", stringify(strict.Get("summary")))
	}
	_, err = s.suggest(t, s.owner, "minIdentities", 1.0)
	expectError(t, err, "INVALID_INPUT", "Invalid minIdentities")
}

func TestRoleMiningSuggestValidatesInput(t *testing.T) {
	s := newMiningScenario(t)
	_, err := s.suggest(t, s.owner, "kinds", items("bundle", "everything"))
	expectError(t, err, "INVALID_INPUT", "Unknown suggestion kind")
	_, err = s.suggest(t, s.owner, "limit", 0.0)
	expectError(t, err, "INVALID_INPUT", "Invalid limit")
	_, err = s.suggest(t, s.owner, "minRoles", 51.0)
	expectError(t, err, "INVALID_INPUT", "Invalid minRoles")
}

func TestRoleMiningAppliesGroupAndRedundantBindings(t *testing.T) {
	s := newMiningScenario(t)
	f := s.f
	out, err := s.suggest(t, s.owner)
	suggestions := anaObjects(anaTryObject(t, out, err).Get("suggestions"))
	readerToGroup := suggestionOf(suggestions, func(entry *core.Object) bool {
		return entry.Get("kind") == "group-binding" && anaObjects(entry.Get("roles"))[0].Get("id") == anaID(s.reader)
	})
	applied, err := s.apply(s.owner, anaID(readerToGroup))
	result := anaTryObject(t, applied, err)
	if result.Get("applied") != "group-binding" || len(anaObjects(result.Get("removedBindingIds"))) != 3 {
		t.Fatalf("applied = %s", stringify(result))
	}
	var readerBindings []*core.Object
	for _, binding := range f.find("bindings", core.NewObject("tenantId", s.tenantID)) {
		if binding.Get("roleId") == anaID(s.reader) {
			readerBindings = append(readerBindings, binding)
		}
	}
	if len(readerBindings) != 1 || readerBindings[0].Get("subjectType") != "group" || readerBindings[0].Get("subjectId") != anaID(s.eng) ||
		readerBindings[0].Get("id") != result.Get("createdBindingId") {
		t.Fatalf("reader bindings = %s", stringify(readerBindings))
	}
	// Same suggestion again: it no longer holds.
	_, err = s.apply(s.owner, anaID(readerToGroup))
	anaRefuse(t, err, "NOT_FOUND")

	redundant := suggestionOf(suggestions, ofKind("redundant-binding"))
	applied, err = s.apply(s.owner, anaID(redundant))
	anaTry(t, applied, err)
	after := f.find("bindings", core.NewObject("tenantId", s.tenantID))
	direct, grouped := false, false
	for _, binding := range after {
		direct = direct || binding.Get("id") == anaID(s.direct)
		grouped = grouped || (binding.Get("roleId") == anaID(s.deployer) && binding.Get("subjectId") == anaID(s.ops))
	}
	if direct || !grouped {
		t.Fatalf("bindings after = %s", stringify(after))
	}

	bundle := suggestionOf(suggestions, ofKind("bundle"))
	_, err = s.apply(s.owner, anaID(bundle))
	expectError(t, err, "INVALID_INPUT", "Create an access package from a bundle with packages.create")
	out, err = s.suggest(t, s.owner)
	remaining := anaTryObject(t, out, err).Get("summary")
	if stringify(member(remaining, "group-binding")) != "1" || stringify(member(remaining, "redundant-binding")) != "0" ||
		stringify(member(remaining, "bundle")) != "1" {
		t.Fatalf("remaining = %s", stringify(remaining))
	}
}

func TestRoleMiningFindsPeerOutliers(t *testing.T) {
	s := newMiningScenario(t)
	out, err := s.outliers(s.owner, "peerBy", "attribute:department")
	byDepartment := anaTryObject(t, out, err)
	// Sales has one person, so only the four engineers are compared.
	if stringify(byDepartment.Get("identitiesCompared")) != "4" {
		t.Fatalf("compared = %s", stringify(byDepartment))
	}
	outliers := anaObjects(byDepartment.Get("outliers"))
	if len(outliers) != 1 {
		t.Fatalf("outliers = %s", stringify(outliers))
	}
	dee := outliers[0]
	if member(dee.Get("identity"), "id") != anaID(s.dee) || dee.Get("peerValue") != "eng" || stringify(dee.Get("peers")) != "3" ||
		stringify(dee.Get("unusualRoles")) != stringify([]any{body("role", body("id", anaID(s.deployer), "name", "Deployer"), "peersHolding", 0, "share", 0)}) {
		t.Fatalf("dee = %s", stringify(dee))
	}
	if got := anaSorted(pluck(pluckObjects(anaObjects(dee.Get("missingRoles")), "role"), "name")); strings.Join(got, ",") != "Reader,Writer" {
		t.Fatalf("missing = %v", got)
	}
	if got := stringify(dee.Keys()); got != `["identity","peerValue","peers","unusualRoles","missingRoles"]` {
		t.Fatalf("outlier keys = %s", got)
	}

	// Manager cohorts: everyone reporting to Eve.
	for _, who := range []*core.Object{s.ana, s.ben, s.cai, s.dee} {
		s.f.patch("identities", anaID(who), core.NewObject("managerId", anaID(s.eve)))
	}
	out, err = s.outliers(s.owner)
	byManager := anaTryObject(t, out, err)
	if byManager.Get("peerBy") != "manager" {
		t.Fatalf("peerBy = %v", byManager.Get("peerBy"))
	}
	managed := anaObjects(byManager.Get("outliers"))
	if got := stringify(pluck(pluckObjects(managed, "identity"), "id")); got != stringify([]string{anaID(s.dee)}) {
		t.Fatalf("by manager = %s", got)
	}
	if managed[0].Get("peerValue") != anaID(s.eve) {
		t.Fatalf("peer value = %v", managed[0].Get("peerValue"))
	}

	_, err = s.outliers(s.owner, "peerBy", "attribute:shoe")
	expectError(t, err, "INVALID_INPUT", "Unknown identity attribute shoe")
	_, err = s.outliers(s.owner, "threshold", 2.0)
	expectError(t, err, "INVALID_INPUT", "threshold must be a number above 0 and at most 1")
	_, err = s.outliers(s.owner, "peerBy", "team")
	expectError(t, err, "INVALID_INPUT", "peerBy must be manager or attribute:{name}")
	_, err = s.outliers(s.owner, "minPeers", 0.0)
	expectError(t, err, "INVALID_INPUT", "Invalid minPeers")
}

func TestRoleMiningIgnoresPackageMembershipsAndInactiveMembers(t *testing.T) {
	s := newMiningScenario(t)
	f := s.f
	// Operations' Deployer binding reaches Dee only through a package-owned membership from now on.
	f.anaRemoveMember(s.tenantID, anaID(s.ops), anaID(s.dee))
	pkg := f.anaPackage(s.tenantID, "Ops kit", []string{}, []string{anaID(s.ops)})
	assignmentID := ID()
	f.seed("packageAssignments", core.NewObject("id", assignmentID, "tenantId", s.tenantID,
		"uniqueKey", anaID(pkg)+":"+anaID(s.dee), "packageId", anaID(pkg), "identityId", anaID(s.dee), "createdAt", f.now()))
	f.seed("groupMembers", core.NewObject("id", ID(), "tenantId", s.tenantID, "uniqueKey", anaID(s.ops)+":"+anaID(s.dee),
		"groupId", anaID(s.ops), "identityId", anaID(s.dee), "packageAssignmentId", assignmentID))
	// A disabled engineer makes "every member holds it directly" unsafe for Engineering.
	f.patch("identities", anaID(s.cai), core.NewObject("status", "disabled"))
	out, err := s.suggest(t, s.owner, "minIdentities", 2.0)
	summary := anaTryObject(t, out, err).Get("summary")
	if stringify(member(summary, "redundant-binding")) != "0" || stringify(member(summary, "group-binding")) != "0" {
		t.Fatalf("summary = %s", stringify(summary))
	}
}

func TestRoleMiningRequiresAnalysisPermissions(t *testing.T) {
	s := newMiningScenario(t)
	_, err := s.suggest(t, s.eveToken)
	expectCode(t, err, "ACCESS_DENIED")
	_, err = s.outliers(s.eveToken)
	expectCode(t, err, "ACCESS_DENIED")
	_, err = s.apply(s.eveToken, strings.Repeat("a", 24))
	expectCode(t, err, "ACCESS_DENIED")
}

func pluckObjects(objects []*core.Object, key string) []*core.Object {
	out := make([]*core.Object, len(objects))
	for index, object := range objects {
		out[index], _ = object.Get(key).(*core.Object)
	}
	return out
}
