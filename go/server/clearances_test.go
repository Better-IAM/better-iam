package server

// Security clearance tests, after tests/clearances.test.ts, tests/clearances-enforcement.test.ts,
// tests/clearances-fail-closed.test.ts, tests/clearances-hardening.test.ts, tests/clearances-integrations.test.ts and
// tests/clearances-decision-paths.test.ts. The clearances API group is ported separately, so the schemes, clearances
// and labels it would write are seeded directly in the store in the shape it writes them; the scenarios then go
// through the decision paths (authorize, plans) and the module's lifecycle helpers.

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const usDefinitionJSON = `{"levels":[{"id":"U","name":"UNCLASSIFIED","rank":0,"abbreviation":"U"},` +
	`{"id":"C","name":"CONFIDENTIAL","rank":1,"abbreviation":"C"},{"id":"S","name":"SECRET","rank":2,"abbreviation":"S"},` +
	`{"id":"TS","name":"TOP SECRET","rank":3,"abbreviation":"TS"}],"compartments":[{"id":"GAMMA","name":"Gamma"}],` +
	`"ownerCountries":["USA"],"caveats":["NOFORN","RELTO"]}`

// schemeRecord is a scheme as clearances.defineScheme writes it, with members overriding the defaults.
func schemeRecord(t *testing.T, tenantID string, members string) *core.Object {
	t.Helper()
	record := core.NewObject("id", "scheme-"+tenantID, "tenantId", tenantID, "uniqueKey", "scheme", "name", "Acme",
		"definition", obj(t, usDefinitionJSON), "requireLabels", []any{}, "guestCeiling", nil, "interimAllowed", false,
		"adjudication", "within-own", "createdAt", 1.0, "createdBy", "owner", "updatedAt", 1.0, "updatedBy", "owner", "version", 1.0)
	if members != "" {
		record.Assign(obj(t, members))
	}
	return record
}

// clearanceRecord is a clearance as clearances.grant writes it.
func clearanceRecord(t *testing.T, identityID, tenantID, schemeTenantID, level string, members string) *core.Object {
	t.Helper()
	record := core.NewObject("id", identityID, "tenantId", tenantID, "uniqueKey", identityID, "identityId", identityID,
		"schemeTenantId", schemeTenantID, "level", level, "citizenship", []any{"USA"}, "status", "active", "readIns", []any{},
		"grantedAt", 1.0, "grantedBy", "owner", "updatedAt", 1.0, "updatedBy", "owner")
	if members != "" {
		record.Assign(obj(t, members))
	}
	return record
}

// labelRecord is a resource label as clearances.label writes it.
func labelRecord(t *testing.T, tenantID, schemeTenantID, typeValue, resourceID, label string, inherit bool) *core.Object {
	t.Helper()
	key := labelKey(typeValue, resourceID)
	return core.NewObject("id", "label-"+key, "tenantId", tenantID, "uniqueKey", key, "type", typeValue, "resourceId", resourceID,
		"label", obj(t, label), "inheritToChildren", inherit, "schemeTenantId", schemeTenantID, "labeledBy", "owner",
		"labeledAt", 1.0, "version", 1.0)
}

// registration is a managed resource record as resources.register writes it.
func registration(tenantID, typeValue, resourceID, parentType, parentID string) *core.Object {
	record := core.NewObject("id", "resource-"+typeValue+"-"+resourceID, "tenantId", tenantID, "uniqueKey", typeValue+"/"+resourceID,
		"type", typeValue, "resourceId", resourceID, "attributes", core.NewObject(), "createdAt", 1.0)
	if parentType != "" {
		record.Set("parentType", parentType)
		record.Set("parentId", parentID)
	}
	return record
}

func newClearanceFixture(t *testing.T, mutate func(options *BetterIamOptions)) *decisionFixture {
	t.Helper()
	return newDecisionFixture(t, func(options *BetterIamOptions) {
		options.Clearances = &ClearanceOptions{}
		if mutate != nil {
			mutate(options)
		}
	})
}

func (f *decisionFixture) plan(token, action, resourceType string) (*core.Object, error) {
	return f.iam.PlanResources(context.Background(), PlanResourcesRequest{Credential: core.CredentialInput{Token: token}, TenantID: f.tenantID, Action: action, Type: resourceType})
}

func expectDecision(t *testing.T, label string, decision core.Decision, allowed bool, reason string) {
	t.Helper()
	if decision.Allowed != allowed || (reason != "" && decision.Reason != reason) {
		t.Errorf("%s: got %+v, want allowed=%v reason=%s", label, decision, allowed, reason)
	}
}

func TestClearancesAssertAndLabelKey(t *testing.T) {
	k := newKernel(t, nil)
	expectError(t, AssertClearances(k.server), "FEATURE_DISABLED", "Security clearances are not enabled on this deployment")
	if known := iamError(t, AssertClearances(k.server)); known.Status != 403 {
		t.Errorf("status = %d", known.Status)
	}
	on := newKernel(t, func(options *BetterIamOptions) { options.Clearances = &ClearanceOptions{} })
	if err := AssertClearances(on.server); err != nil {
		t.Fatal(err)
	}
	if key := must(LabelKey("document", "d1")); key != "document/d1" {
		t.Errorf("key = %s", key)
	}
	long := strings.Repeat("é", 300)
	if key := must(LabelKey("document", long)); key != "sha256:"+Hash("document/"+long) {
		t.Errorf("long key = %s", key)
	}
	// 512 bytes exactly is kept as it is.
	exact := strings.Repeat("a", 512-len("document/"))
	if key := must(LabelKey("document", exact)); key != "document/"+exact {
		t.Errorf("512-byte key hashed: %s", key)
	}
}

func TestClearancesSchemeInForce(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) { options.Clearances = &ClearanceOptions{} })
	k.tenantTree()
	ctx := k.ctx
	if scheme := must(SchemeForTenant(ctx, k.store, "project")); scheme != nil {
		t.Fatalf("no scheme expected: %v", scheme)
	}
	k.insert("classificationSchemes", schemeRecord(t, "project", ""))
	if scheme := must(SchemeForTenant(ctx, k.store, "project")); scheme == nil || scheme.Get("tenantId") != "project" {
		t.Fatalf("project scheme: %v", scheme)
	}
	// The scheme defined closest to the root is the one in force.
	k.insert("classificationSchemes", schemeRecord(t, "org", ""))
	if scheme := must(SchemeForTenant(ctx, k.store, "project")); scheme.Get("tenantId") != "org" {
		t.Errorf("closest to the root: %v", scheme.Get("tenantId"))
	}
	if defined := must(DefinedScheme(ctx, k.store, "project")); defined == nil || defined.Get("tenantId") != "project" {
		t.Errorf("defined: %v", defined)
	}
	if defined := must(DefinedScheme(ctx, k.store, "root")); defined != nil {
		t.Errorf("root defines none: %v", defined)
	}
	chain := []*core.Object{core.NewObject("id", "project"), core.NewObject("id", "org"), core.NewObject("id", "root")}
	if effective := must(EffectiveScheme(ctx, k.store, chain)); effective.Get("tenantId") != "org" {
		t.Errorf("effective: %v", effective)
	}
	if effective := must(EffectiveScheme(ctx, k.store, chain[2:])); effective != nil {
		t.Errorf("root chain: %v", effective)
	}
	// Labels left where no scheme applies: a stand-in scheme under which each refuses everyone.
	k.insert("resourceLabels", labelRecord(t, "root", "gone", "document", "d1", `{"level":"U"}`, false))
	lapsed := must(SchemeForTenant(ctx, k.store, "root"))
	if lapsed == nil || lapsed.Get("tenantId") != "!no-scheme-in-force" || len(lapsed.Get("definition").(*core.Object).Get("levels").([]any)) != 0 {
		t.Fatalf("lapsed: %v", lapsed)
	}
	labels := must(LabelsForType(ctx, k.store, "root", "document"))
	if label := labels["d1"]; label == nil || label.Get("level") != "!invalid" {
		t.Errorf("lapsed label: %v", label)
	}
	// A broken chain fails closed.
	k.insert("tenants", core.NewObject("id", "orphan", "tenantId", "orphan", "name", "Orphan", "type", "project", "parentId", "missing", "status", "active", "createdAt", 4.0))
	_, err := SchemeForTenant(ctx, k.store, "orphan")
	expectError(t, err, "NOT_FOUND", "Tenant not found")
	// Levels by id.
	scheme := schemeRecord(t, "org", "")
	if level := must(SchemeLevel(scheme, "S")); level == nil || level.Get("name") != "SECRET" {
		t.Errorf("level: %v", level)
	}
	if level := must(SchemeLevel(scheme, "X")); level != nil {
		t.Errorf("unknown level: %v", level)
	}
}

func TestClearancesRefuseReadingUp(t *testing.T) {
	f := newClearanceFixture(t, nil)
	alice := f.createIdentity("alice@example.test", "alice", "a strong alice password")
	aliceID := jsString(alice.Get("id"))
	token := f.signIn(alice, false)
	f.grant("reader", "identity", aliceID, document(allowStatement("documents:read", "document/*")))
	// Labels are inert until a scheme is in force.
	f.seed("resourceLabels", labelRecord(t, f.tenantID, f.tenantID, "document", "d-ts", `{"level":"TS"}`, false))
	f.seed("classificationSchemes", schemeRecord(t, f.tenantID, ""))
	f.seed("resourceLabels",
		labelRecord(t, f.tenantID, f.tenantID, "document", "d-s", `{"level":"S"}`, false),
		labelRecord(t, f.tenantID, f.tenantID, "document", "d-gamma", `{"level":"S","compartments":["GAMMA"]}`, false),
		labelRecord(t, f.tenantID, f.tenantID, "document", "d-noforn", `{"level":"C","noforn":true}`, false),
		labelRecord(t, f.tenantID, f.tenantID, "document", "d-rel", `{"level":"C","releasableTo":["GBR"]}`, false),
	)
	// No clearance yet: unlabeled resources only.
	expectDecision(t, "uncleared unlabeled", f.authorize(token, "documents:read", "document", "plain"), true, "")
	expectDecision(t, "uncleared labeled", f.authorize(token, "documents:read", "document", "d-s"), false, "ACCESS_DENIED")
	f.seed("clearances", clearanceRecord(t, aliceID, f.tenantID, f.tenantID, "S", ""))
	expectDecision(t, "secret", f.authorize(token, "documents:read", "document", "d-s"), true, "")
	expectDecision(t, "top secret", f.authorize(token, "documents:read", "document", "d-ts"), false, "ACCESS_DENIED")
	expectDecision(t, "compartment", f.authorize(token, "documents:read", "document", "d-gamma"), false, "ACCESS_DENIED")
	expectDecision(t, "noforn citizen", f.authorize(token, "documents:read", "document", "d-noforn"), true, "")
	// REL TO GBR still reads for citizens of the owner countries.
	expectDecision(t, "rel to", f.authorize(token, "documents:read", "document", "d-rel"), true, "")
	// Citizenship comes from the adjudicated record only.
	f.seed("clearances", clearanceRecord(t, aliceID, f.tenantID, f.tenantID, "S", `{"citizenship":["FRA"]}`))
	expectDecision(t, "noforn foreigner", f.authorize(token, "documents:read", "document", "d-noforn"), false, "ACCESS_DENIED")
	expectDecision(t, "rel to foreigner", f.authorize(token, "documents:read", "document", "d-rel"), false, "ACCESS_DENIED")
	// Read into GAMMA: the compartment counts.
	f.seed("clearances", clearanceRecord(t, aliceID, f.tenantID, f.tenantID, "S", `{"readIns":[{"compartmentId":"GAMMA","readInAt":1,"readInBy":"owner"}]}`))
	expectDecision(t, "read in", f.authorize(token, "documents:read", "document", "d-gamma"), true, "")
	// Status and expiry are decided at the time.
	f.seed("clearances", clearanceRecord(t, aliceID, f.tenantID, f.tenantID, "S", `{"status":"suspended"}`))
	expectDecision(t, "suspended", f.authorize(token, "documents:read", "document", "d-s"), false, "ACCESS_DENIED")
	f.seed("clearances", clearanceRecord(t, aliceID, f.tenantID, f.tenantID, "S", `{"status":"interim"}`))
	expectDecision(t, "interim not allowed", f.authorize(token, "documents:read", "document", "d-s"), false, "ACCESS_DENIED")
	f.seed("classificationSchemes", schemeRecord(t, f.tenantID, `{"interimAllowed":true}`))
	expectDecision(t, "interim allowed", f.authorize(token, "documents:read", "document", "d-s"), true, "")
	f.seed("clearances", clearanceRecord(t, aliceID, f.tenantID, f.tenantID, "S", `{"expiresAt":1}`))
	expectDecision(t, "expired", f.authorize(token, "documents:read", "document", "d-s"), false, "ACCESS_DENIED")
	// A clearance issued under another scheme does not count.
	f.seed("clearances", clearanceRecord(t, aliceID, f.tenantID, "elsewhere", "TS", ""))
	expectDecision(t, "other scheme", f.authorize(token, "documents:read", "document", "d-s"), false, "ACCESS_DENIED")
	// iam: administration is never subject.
	f.seed("clearances", clearanceRecord(t, aliceID, f.tenantID, f.tenantID, "S", ""))
	current := f.principal(token)
	prepared := must(core.Transact(context.Background(), f.iam.Store, func(ctx context.Context, tx core.IamStore) (*PreparedDecision, error) {
		realm, err := tx.Get(ctx, "tenants", f.tenantID)
		if err != nil {
			return nil, err
		}
		return f.iam.Context.Decisions.PrepareDecision(ctx, tx, current, realm, "documents:read")
	}))
	mandatory := prepared.Inputs.Mandatory
	if mandatory == nil {
		t.Fatal("no mandatory check")
	}
	labeled := ResolvedResource{TenantID: f.tenantID, Type: "document", ID: "x", HasClassification: true, Classification: obj(t, `{"level":"TS"}`)}
	if mandatory.Check(labeled, "iam:resources:read") != nil || mandatory.Check(labeled, "documents:read") == nil {
		t.Errorf("iam actions exempt, others checked")
	}
	if text := core.MustStringify(mandatory.Keys); text != `{"principal.clearanceRank":2,"principal.clearanceLevel":"S","principal.clearanceStatus":"active","principal.clearanceCompartments":[],"principal.clearanceCitizenship":["USA"]}` {
		t.Errorf("keys = %s", text)
	}
	// A resource whose label was never looked up is refused (fail closed).
	if mandatory.Check(ResolvedResource{TenantID: f.tenantID, Type: "document", ID: "x"}, "documents:read") == nil {
		t.Errorf("unlooked-up resource passed")
	}
	if rank := mandatory.Rank(obj(t, `{"level":"C"}`)); rank == nil || *rank != 1 {
		t.Errorf("rank = %v", rank)
	}
	if rank := mandatory.Rank(obj(t, `{"level":"X"}`)); rank != nil {
		t.Errorf("unknown rank = %v", *rank)
	}
}

func TestClearancesFailClosed(t *testing.T) {
	f := newClearanceFixture(t, nil)
	alice := f.createIdentity("alice@example.test", "alice", "a strong alice password")
	aliceID := jsString(alice.Get("id"))
	token := f.signIn(alice, false)
	f.grant("reader", "identity", aliceID, document(allowStatement("documents:read", "document/*")))
	f.seed("classificationSchemes", schemeRecord(t, f.tenantID, ""))
	f.seed("clearances", clearanceRecord(t, aliceID, f.tenantID, f.tenantID, "S", ""))
	// A label written under another scheme refuses everyone.
	f.seed("resourceLabels", labelRecord(t, f.tenantID, "a-scheme-no-longer-in-force", "document", "d1", `{"level":"U"}`, false))
	expectDecision(t, "label of another scheme", f.authorize(token, "documents:read", "document", "d1"), false, "ACCESS_DENIED")
	expectDecision(t, "unlabeled", f.authorize(token, "documents:read", "document", "d2"), true, "")
	// A required label: unlabeled resources are refused unless a default applies.
	f.seed("classificationSchemes", schemeRecord(t, f.tenantID, `{"requireLabels":["document"]}`))
	expectDecision(t, "required, unlabeled", f.authorize(token, "documents:read", "document", "d2"), false, "ACCESS_DENIED")
	f.seed("classificationSchemes", schemeRecord(t, f.tenantID, `{"requireLabels":["document"],"defaultLabel":{"level":"C"}}`))
	expectDecision(t, "default label", f.authorize(token, "documents:read", "document", "d2"), true, "")
	f.seed("classificationSchemes", schemeRecord(t, f.tenantID, `{"requireLabels":["document"],"defaultLabel":{"level":"TS"}}`))
	expectDecision(t, "default above", f.authorize(token, "documents:read", "document", "d2"), false, "ACCESS_DENIED")
	// `*` covers application types, not built-in ones.
	scheme := schemeRecord(t, f.tenantID, `{"requireLabels":["*"]}`)
	if !labelRequired(scheme, "document") || labelRequired(scheme, "model") || labelRequired(scheme, "iam") {
		t.Errorf("requireLabels *")
	}
	// iam/{type}/{id} is labeled and refused like the resource it names, for application actions.
	required := schemeRecord(t, f.tenantID, `{"requireLabels":["document"]}`)
	alias := ResolvedResource{TenantID: f.tenantID, Type: "iam", ID: "document/d2"}
	labeled := must(AttachLabel(context.Background(), f.iam.Context, f.iam.Store, f.tenantID, alias, AttachLabelOptions{Scheme: required}))
	if !labeled.HasClassification || labeled.Classification != nil {
		t.Fatalf("alias label = %v", labeled.Classification)
	}
	if label, refuse := applicableLabel(required, labeled); label != nil || !refuse {
		t.Errorf("alias of a required type should refuse")
	}
	if label := must(ApplicableLabel(required, labeled)); label != false {
		t.Errorf("ApplicableLabel = %v", label)
	}
	ts := must(AttachLabel(context.Background(), f.iam.Context, f.iam.Store, f.tenantID,
		ResolvedResource{TenantID: f.tenantID, Type: "iam", ID: "document/d1"}, AttachLabelOptions{Scheme: required}))
	if level := member(ts.Classification, "level"); level != "!invalid" {
		t.Errorf("alias of a label from another scheme = %v", ts.Classification)
	}
	// A failed resolution of the named resource refuses everyone.
	failed := must(AttachLabel(context.Background(), f.iam.Context, f.iam.Store, f.tenantID, alias, AttachLabelOptions{Scheme: required, HasNamed: true}))
	if member(failed.Classification, "level") != "!invalid" {
		t.Errorf("failed named = %v", failed.Classification)
	}
	// What the application resolves for the named resource counts too.
	named := &ResolvedResource{TenantID: f.tenantID, Type: "document", ID: "d2", HasClassification: true, Classification: obj(t, `{"level":"S"}`)}
	raised := must(AttachLabel(context.Background(), f.iam.Context, f.iam.Store, f.tenantID, alias, AttachLabelOptions{Scheme: required, HasNamed: true, Named: named}))
	if core.MustStringify(raised.Classification) != `{"level":"S"}` {
		t.Errorf("named classification = %v", raised.Classification)
	}
	// Other internal resources and malformed aliases carry nothing.
	for _, resource := range []ResolvedResource{{TenantID: f.tenantID, Type: "role", ID: "r1"}, {TenantID: f.tenantID, Type: "iam", ID: "nothing"}, {TenantID: f.tenantID, Type: "iam", ID: "role/r1"}} {
		if out := must(AttachLabel(context.Background(), f.iam.Context, f.iam.Store, f.tenantID, resource, AttachLabelOptions{Scheme: required})); out.HasClassification {
			t.Errorf("%s/%s labeled: %v", resource.Type, resource.ID, out.Classification)
		}
	}
	// No scheme: unchanged.
	if out := must(AttachLabel(context.Background(), f.iam.Context, f.iam.Store, f.tenantID, ResolvedResource{TenantID: f.tenantID, Type: "document", ID: "d1"}, AttachLabelOptions{})); out.HasClassification {
		t.Errorf("labeled without a scheme")
	}
}

func TestClearancesResolverRaisesNeverLowers(t *testing.T) {
	asserted := map[string]any{}
	f := newClearanceFixture(t, func(options *BetterIamOptions) {
		options.ResolveResource = func(ctx context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			resource := &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID, Attributes: core.NewObject("ownerId", "alice")}
			if label, ok := asserted[reference.ID]; ok {
				resource.HasClassification, resource.Classification = true, label
			}
			return resource, nil
		}
	})
	alice := f.createIdentity("alice@example.test", "alice", "a strong alice password")
	aliceID := jsString(alice.Get("id"))
	token := f.signIn(alice, false)
	f.grant("reader", "identity", aliceID, document(allowStatement("documents:read", "document/*")))
	f.seed("classificationSchemes", schemeRecord(t, f.tenantID, ""))
	f.seed("clearances", clearanceRecord(t, aliceID, f.tenantID, f.tenantID, "S", ""))
	f.seed("resourceLabels", labelRecord(t, f.tenantID, f.tenantID, "document", "high", `{"level":"TS"}`, false))
	asserted["high"] = obj(t, `{"level":"U"}`)
	asserted["raised"] = obj(t, `{"level":"TS"}`)
	asserted["bogus"] = obj(t, `{"level":"NOPE"}`)
	asserted["plain"] = nil
	expectDecision(t, "resolver cannot lower", f.authorize(token, "documents:read", "document", "high"), false, "ACCESS_DENIED")
	expectDecision(t, "resolver raises", f.authorize(token, "documents:read", "document", "raised"), false, "ACCESS_DENIED")
	expectDecision(t, "unreadable assertion", f.authorize(token, "documents:read", "document", "bogus"), false, "ACCESS_DENIED")
	expectDecision(t, "asserted null", f.authorize(token, "documents:read", "document", "plain"), true, "")
}

func TestClearancesInheritanceDownManagedParents(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) { options.Clearances = &ClearanceOptions{} })
	k.tenantTree()
	ctx := k.ctx
	k.insert("classificationSchemes", schemeRecord(t, "org", ""))
	k.insert("resources",
		registration("org", "folder", "top", "", ""),
		registration("org", "folder", "mid", "folder", "top"),
		registration("org", "doc", "leaf", "folder", "mid"),
		registration("org", "doc", "other", "", ""),
	)
	k.insert("resourceLabels",
		labelRecord(t, "org", "org", "folder", "top", `{"level":"S","compartments":["GAMMA"]}`, true),
		labelRecord(t, "org", "org", "folder", "mid", `{"level":"C","noforn":true}`, false),
		labelRecord(t, "org", "org", "doc", "other", `{"level":"C"}`, false),
	)
	scheme := must(SchemeForTenant(ctx, k.store, "org"))
	inherited := must(InheritedLabel(ctx, k.store, "org", scheme, "doc", "leaf"))
	// mid's own label does not pass down (inheritToChildren false); top's does.
	if text := core.MustStringify(inherited); text != `{"level":"S","compartments":["GAMMA"]}` {
		t.Errorf("inherited = %s", text)
	}
	labels := must(LabelsForType(ctx, k.store, "org", "doc"))
	if text := core.MustStringify(labels["leaf"]); text != `{"level":"S","compartments":["GAMMA"]}` {
		t.Errorf("leaf = %s", text)
	}
	if text := core.MustStringify(labels["other"]); text != `{"level":"C"}` {
		t.Errorf("other = %s", text)
	}
	labeled := must(AttachLabel(ctx, k.server, k.store, "org", ResolvedResource{TenantID: "org", Type: "doc", ID: "leaf"}, AttachLabelOptions{Scheme: scheme}))
	if text := core.MustStringify(labeled.Classification); text != `{"level":"S","compartments":["GAMMA"]}` {
		t.Errorf("attached = %s", text)
	}
	// A parent the resolver reports counts as well.
	reported := must(AttachLabel(ctx, k.server, k.store, "org", ResolvedResource{TenantID: "org", Type: "note", ID: "n1",
		Attributes: core.NewObject("parentType", "folder", "parentId", "mid")}, AttachLabelOptions{Scheme: scheme}))
	if text := core.MustStringify(reported.Classification); text != `{"level":"S","compartments":["GAMMA"]}` {
		t.Errorf("reported parent = %s", text)
	}
	// Deeper than 16 ancestors inherits the invalid label.
	var records []*core.Object
	for index := 0; index < 18; index++ {
		parentType, parentID := "", ""
		if index > 0 {
			parentType, parentID = "node", "n"+core.NumberString(float64(index-1))
		}
		records = append(records, registration("org", "node", "n"+core.NumberString(float64(index)), parentType, parentID))
	}
	k.insert("resources", records...)
	k.insert("resourceLabels", labelRecord(t, "org", "org", "node", "n0", `{"level":"U"}`, true))
	if deep := must(InheritedLabel(ctx, k.store, "org", scheme, "node", "n17")); member(deep, "level") != "!invalid" {
		t.Errorf("deep = %v", deep)
	}
	if shallow := must(InheritedLabel(ctx, k.store, "org", scheme, "node", "n3")); member(shallow, "level") != "U" {
		t.Errorf("shallow = %v", shallow)
	}
	// A cycle fails closed.
	k.insert("resources", registration("org", "loop", "a", "loop", "b"), registration("org", "loop", "b", "loop", "a"))
	if cyclic := must(InheritedLabel(ctx, k.store, "org", scheme, "loop", "a")); member(cyclic, "level") != "!invalid" {
		t.Errorf("cyclic = %v", cyclic)
	}
	// Nothing inherited: nil.
	if none := must(InheritedLabel(ctx, k.store, "org", scheme, "doc", "other")); none != nil {
		t.Errorf("other inherits %v", none)
	}
}

func TestClearancesCarriedLabels(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) { options.Clearances = &ClearanceOptions{} })
	k.tenantTree()
	ctx := k.ctx
	k.insert("classificationSchemes", schemeRecord(t, "org", ""))
	k.insert("resourceLabels",
		labelRecord(t, "org", "org", "model", "gpt", `{"level":"S"}`, false),
		labelRecord(t, "project", "org", "ssh-host", "web", `{"level":"C"}`, false),
	)
	scheme := must(SchemeForTenant(ctx, k.store, "project"))
	// A model's label written where it is defined applies in every tenant below.
	model := must(AttachLabel(ctx, k.server, k.store, "project", ResolvedResource{TenantID: "project", Type: "model", ID: "gpt"}, AttachLabelOptions{Scheme: scheme}))
	if member(model.Classification, "level") != "S" {
		t.Errorf("model = %v", model.Classification)
	}
	if labels := must(LabelsForType(ctx, k.store, "project", "model")); member(labels["gpt"], "level") != "S" {
		t.Errorf("model labels = %v", labels)
	}
	// An SSH host's label applies to every login of the host.
	login := must(AttachLabel(ctx, k.server, k.store, "project", ResolvedResource{TenantID: "project", Type: "ssh-login", ID: "web/deploy"}, AttachLabelOptions{Scheme: scheme}))
	if member(login.Classification, "level") != "C" {
		t.Errorf("login = %v", login.Classification)
	}
	if inherited := must(InheritedLabel(ctx, k.store, "project", scheme, "ssh-login", "web/root")); member(inherited, "level") != "C" {
		t.Errorf("login inherits %v", inherited)
	}
}

func TestClearancesPlansFollowLabels(t *testing.T) {
	f := newClearanceFixture(t, nil)
	alice := f.createIdentity("alice@example.test", "alice", "a strong alice password")
	aliceID := jsString(alice.Get("id"))
	token := f.signIn(alice, false)
	f.grant("reader", "identity", aliceID, document(allowStatement("documents:read", "*")))
	f.seed("classificationSchemes", schemeRecord(t, f.tenantID, ""))
	f.seed("clearances", clearanceRecord(t, aliceID, f.tenantID, f.tenantID, "S", ""))
	f.seed("resourceLabels",
		labelRecord(t, f.tenantID, f.tenantID, "document", "n2", `{"level":"TS"}`, false),
		labelRecord(t, f.tenantID, f.tenantID, "document", "n1", `{"level":"TS"}`, false),
		labelRecord(t, f.tenantID, f.tenantID, "document", "n0", `{"level":"S"}`, false),
	)
	plan, err := f.plan(token, "documents:read", "document")
	if err != nil {
		t.Fatal(err)
	}
	if text := core.MustStringify(plan); !strings.Contains(text, `{"kind":"not","filter":{"kind":"equals","field":"id","values":["n1","n2"]}}`) {
		t.Errorf("plan = %s", text)
	}
	// Managed types: the registered resources that pass.
	f.seed("resources", registration(f.tenantID, "project", "p1", "", ""), registration(f.tenantID, "project", "p2", "", ""), registration(f.tenantID, "project", "p3", "", ""))
	f.seed("resourceLabels", labelRecord(t, f.tenantID, f.tenantID, "project", "p2", `{"level":"TS"}`, false), labelRecord(t, f.tenantID, f.tenantID, "project", "p3", `{"level":"C"}`, false))
	f.seed("classificationSchemes", schemeRecord(t, f.tenantID, `{"requireLabels":["project","document"]}`))
	current := f.principal(token)
	var managedFilter, iamFilter *core.Object
	err = f.iam.Store.Transaction(context.Background(), func(ctx context.Context, tx core.IamStore) error {
		realm, err := tx.Get(ctx, "tenants", f.tenantID)
		if err != nil {
			return err
		}
		prepared, err := f.iam.Context.Decisions.PrepareDecision(ctx, tx, current, realm, "documents:read")
		if err != nil {
			return err
		}
		if managedFilter, err = prepared.Inputs.Mandatory.Filter(ctx, "project", "documents:read"); err != nil {
			return err
		}
		iamFilter, err = prepared.Inputs.Mandatory.Filter(ctx, "project", "iam:resources:read")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if text := core.MustStringify(managedFilter); text != `{"kind":"equals","field":"id","values":["p3"]}` {
		t.Errorf("managed filter = %s", text)
	}
	if text := core.MustStringify(iamFilter); text != `{"kind":"true"}` {
		t.Errorf("iam filter = %s", text)
	}
	// An application type the scheme requires labels on cannot be planned.
	_, err = f.plan(token, "documents:read", "document")
	expectError(t, err, "UNSUPPORTED_FILTER", "Resources of this type must carry a classification label, which a filter cannot check for application resources; check them with authorize")
	// Nor any application type while a label passes down to children.
	f.seed("classificationSchemes", schemeRecord(t, f.tenantID, ""))
	f.seed("resourceLabels", labelRecord(t, f.tenantID, f.tenantID, "folder", "f1", `{"level":"TS"}`, true))
	_, err = f.plan(token, "documents:read", "document")
	expectError(t, err, "UNSUPPORTED_FILTER", "Classification labels pass down to application resources through the parents their resolver reports, which a filter cannot check; check them with authorize")
}

func TestClearancesSessionParties(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) { options.Clearances = &ClearanceOptions{} })
	k.tenantTree()
	ctx := k.ctx
	scheme := schemeRecord(t, "org", `{"guestCeiling":"C"}`)
	k.insert("classificationSchemes", scheme)
	person := identity("person", "org")
	guest := identity("guest", "org", "guest", core.NewObject("sponsorId", "person"))
	agent := identity("agent", "org", "kind", "agent", "agent", core.NewObject("sponsorId", "person"))
	orphan := identity("orphan-agent", "org", "kind", "agent", "agent", core.NewObject())
	k.insert("identities", person, guest, agent, orphan)
	k.insert("clearances",
		clearanceRecord(t, "person", "org", "org", "TS", `{"citizenship":["USA","GBR"],"readIns":[{"compartmentId":"GAMMA","readInAt":1,"readInBy":"owner","agreementId":"nda"}]}`),
		clearanceRecord(t, "guest", "org", "org", "TS", `{"readIns":[{"compartmentId":"GAMMA","readInAt":1,"readInBy":"owner"}]}`),
		clearanceRecord(t, "agent", "org", "org", "S", `{"citizenship":["USA"]}`),
	)
	target := core.NewObject("id", "org")
	state := func(identityRecord *core.Object, id string) *core.Object {
		return must(PartyState(ctx, k.store, scheme, identityRecord, id, "org", k.server.Now()))
	}
	// The NDA backing a read-in must be accepted in its current version.
	personState := state(person, "person")
	if text := core.MustStringify(personState.Get("party")); text != `{"identityId":"person","rank":3,"compartments":[],"citizenship":["USA","GBR"]}` {
		t.Errorf("person without NDA = %s", text)
	}
	k.insert("agreements", core.NewObject("id", "nda", "tenantId", "org", "name", "NDA", "version", 2.0))
	k.insert("agreementAcceptances", core.NewObject("id", "nda:person", "tenantId", "org", "agreementId", "nda", "identityId", "person", "version", 2.0, "acceptedAt", 1.0))
	personState = state(person, "person")
	if text := core.MustStringify(personState.Get("party")); text != `{"identityId":"person","rank":3,"compartments":["GAMMA"],"citizenship":["USA","GBR"]}` {
		t.Errorf("person with NDA = %s", text)
	}
	if personState.Get("status") != "active" || member(personState.Get("level"), "id") != "TS" {
		t.Errorf("person state = %s", core.MustStringify(personState))
	}
	// Guests count at most at the ceiling and never hold compartments.
	guestState := state(guest, "guest")
	if text := core.MustStringify(guestState.Get("party")); text != `{"identityId":"guest","rank":1,"compartments":[],"citizenship":["USA"]}` {
		t.Errorf("guest = %s", text)
	}
	noCeiling := must(PartyState(ctx, k.store, schemeRecord(t, "org", ""), guest, "guest", "org", k.server.Now()))
	if noCeiling.Get("status") != "none" || !isUndefined(noCeiling.Get("level")) {
		t.Errorf("guest without a ceiling = %s", core.MustStringify(noCeiling))
	}
	// Another tenant, or an inactive identity, is no clearance.
	if other := must(PartyState(ctx, k.store, scheme, person, "person", "project", k.server.Now())); other.Get("status") != "none" || other.Has("record") {
		t.Errorf("other tenant = %s", core.MustStringify(other))
	}
	inactive := person.Clone().Set("status", "disabled")
	if text := core.MustStringify(must(PartyState(ctx, k.store, scheme, inactive, "person", "org", k.server.Now())).Get("status")); text != `"none"` {
		t.Errorf("inactive = %s", text)
	}
	// Sessions: a person; an agent key with its sponsor; a delegated session with every agent; a role session.
	user := principalOf(person, session("s1", "person", "org", "user"))
	parties := must(SessionParties(ctx, k.store, user, target, nil, scheme, k.server.Now(), false))
	if len(parties) != 1 || member(parties[0].Get("party"), "identityId") != "person" {
		t.Errorf("user parties = %v", parties)
	}
	key := principalOf(agent, session("s2", "agent", "org", "api-key"))
	parties = must(SessionParties(ctx, k.store, key, target, nil, scheme, k.server.Now(), false))
	if len(parties) != 2 || member(parties[1].Get("party"), "identityId") != "person" || member(parties[0].Get("party"), "rank") != 2.0 {
		t.Errorf("agent key parties = %s", core.MustStringify(parties))
	}
	orphanKey := principalOf(orphan, session("s3", "orphan-agent", "org", "session-token"))
	parties = must(SessionParties(ctx, k.store, orphanKey, target, nil, scheme, k.server.Now(), false))
	if len(parties) != 2 || member(parties[1].Get("party"), "identityId") != "orphan-agent#sponsor" {
		t.Errorf("orphan parties = %s", core.MustStringify(parties))
	}
	delegated := principalOf(person, session("s4", "person", "org", "delegated", "agentId", "agent"))
	parties = must(SessionParties(ctx, k.store, delegated, target, &AgentDecisionScope{Keys: core.NewObject(), AgentIDs: []string{"agent", "guest"}}, scheme, k.server.Now(), false))
	if len(parties) != 3 || member(parties[2].Get("party"), "identityId") != "guest" || parties[2].Get("status") != "none" {
		t.Errorf("delegated parties = %s", core.MustStringify(parties))
	}
	lone := principalOf(person, session("s5", "person", "org", "delegated"))
	parties = must(SessionParties(ctx, k.store, lone, target, nil, scheme, k.server.Now(), false))
	if len(parties) != 2 || member(parties[1].Get("party"), "identityId") != "person#agent" {
		t.Errorf("agentless delegated = %s", core.MustStringify(parties))
	}
	role := principalOf(person, session("s6", "person", "org", "role"))
	parties = must(SessionParties(ctx, k.store, role, target, nil, scheme, k.server.Now(), false))
	if len(parties) != 1 || member(parties[0].Get("party"), "rank") != -1.0 {
		t.Errorf("role parties = %s", core.MustStringify(parties))
	}
	// Outside its own tenant a session is uncleared.
	parties = must(SessionParties(ctx, k.store, user, core.NewObject("id", "project"), nil, scheme, k.server.Now(), false))
	if len(parties) != 1 || member(parties[0].Get("party"), "rank") != -1.0 {
		t.Errorf("cross-tenant parties = %s", core.MustStringify(parties))
	}
	// Every party must dominate the label.
	label := obj(t, `{"level":"TS"}`)
	definition := scheme.Get("definition").(*core.Object)
	both := must(SessionParties(ctx, k.store, key, target, nil, scheme, k.server.Now(), false))
	if failure := must(PartiesFail([]*core.Object{both[0].Get("party").(*core.Object), both[1].Get("party").(*core.Object)}, label, definition)); failure != "level" {
		t.Errorf("failure = %q", failure)
	}
	if failure := must(PartiesFail([]*core.Object{both[1].Get("party").(*core.Object)}, label, definition)); failure != "" {
		t.Errorf("sponsor alone = %q", failure)
	}
	if failure := must(PartiesFail(nil, label, definition)); failure != "level" {
		t.Errorf("no parties = %q", failure)
	}
	// The keys: the weakest party, shared compartments and citizenship.
	states := must(sessionStates(ctx, k.store, key, target, nil, viewScheme(scheme), k.server.Now(), false))
	if text := core.MustStringify(clearanceKeys(states)); text != `{"principal.clearanceRank":2,"principal.clearanceLevel":"S","principal.clearanceStatus":"active","principal.clearanceCompartments":[],"principal.clearanceCitizenship":["USA"]}` {
		t.Errorf("keys = %s", text)
	}
}

func TestClearancesLifecycle(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) { options.Clearances = &ClearanceOptions{} })
	k.tenantTree()
	ctx := k.ctx
	k.insert("classificationSchemes", schemeRecord(t, "org", ""))
	leaver := identity("leaver", "org")
	officer := principalOf(identity("officer", "org"), session("so", "officer", "org", "user"))
	k.insert("identities", leaver)
	k.insert("clearances", clearanceRecord(t, "leaver", "org", "org", "S",
		`{"readIns":[{"compartmentId":"GAMMA","readInAt":1,"readInBy":"owner"}],"suspended":{"by":"x","at":1,"reason":"r","previousStatus":"active"}}`))
	var terminated float64
	err := k.tx(func(ctx context.Context, tx core.IamStore) (err error) {
		terminated, err = TerminateClearancesOf(ctx, k.server, tx, officer, leaver, "left the company")
		return err
	})
	if err != nil || terminated != 1 {
		t.Fatalf("terminate = %v %v", terminated, err)
	}
	record := must(ReadClearance(ctx, k.store, leaver))
	if record.Get("status") != "terminated" || len(record.Get("readIns").([]any)) != 0 || record.Has("suspended") ||
		member(record.Get("terminated"), "reason") != "left the company" || record.Get("updatedBy") != "officer" {
		t.Errorf("terminated record = %s", core.MustStringify(record))
	}
	audits := must(k.store.Find(ctx, "audit", core.NewObject("resourceId", "leaver"), nil))
	actions := map[string]bool{}
	for _, event := range audits {
		actions[jsString(event.Get("action"))] = true
	}
	if !actions["clearance:debrief"] || !actions["clearance:terminate"] {
		t.Errorf("audit = %v", actions)
	}
	// An ended clearance is left as it is.
	err = k.tx(func(ctx context.Context, tx core.IamStore) (err error) {
		terminated, err = TerminateClearancesOf(ctx, k.server, tx, officer, leaver, "again")
		return err
	})
	if err != nil || terminated != 0 {
		t.Errorf("second terminate = %v %v", terminated, err)
	}
	// Deletion: terminated history; a revocation keeps its status and only loses its read-ins.
	deleted := identity("deleted", "org")
	revoked := identity("revoked", "org")
	k.insert("clearances",
		clearanceRecord(t, "deleted", "org", "org", "C", ""),
		clearanceRecord(t, "revoked", "org", "org", "C", `{"status":"revoked","readIns":[{"compartmentId":"GAMMA","readInAt":1,"readInBy":"owner"}],"revoked":{"by":"o","at":1,"reason":"cause"}}`),
	)
	if err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		if err := ReleaseClearancesOf(ctx, tx, deleted, 500, "identity-deleted"); err != nil {
			return err
		}
		return ReleaseClearancesOf(ctx, tx, revoked, 500, "identity-deleted")
	}); err != nil {
		t.Fatal(err)
	}
	if record := must(ReadClearance(ctx, k.store, deleted)); record.Get("status") != "terminated" || core.MustStringify(record.Get("terminated")) != `{"by":"identity-deleted","at":500,"reason":"identity deleted"}` {
		t.Errorf("deleted = %s", core.MustStringify(record))
	}
	if record := must(ReadClearance(ctx, k.store, revoked)); record.Get("status") != "revoked" || record.Has("terminated") || len(record.Get("readIns").([]any)) != 0 {
		t.Errorf("revoked = %s", core.MustStringify(record))
	}
	// Suspension.
	held := identity("held", "org")
	suspend := func(target *core.Object, input *core.Object) (result *core.Object) {
		if err := k.tx(func(ctx context.Context, tx core.IamStore) (err error) {
			result, err = SuspendClearance(ctx, tx, target, input)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}
	k.insert("clearances", clearanceRecord(t, "held", "org", "org", "S", `{"status":"interim"}`))
	input := core.NewObject("by", "officer", "at", 700.0, "reason", strings.Repeat("r", 600), "incidentId", "inc-1")
	result := suspend(held, input)
	suspended := result.Get("record").(*core.Object)
	if result.Get("outcome") != "suspended" || suspended.Get("status") != "suspended" ||
		member(suspended.Get("suspended"), "previousStatus") != "interim" || len(jsString(member(suspended.Get("suspended"), "reason"))) != 512 ||
		member(suspended.Get("suspended"), "incidentId") != "inc-1" || suspended.Get("updatedAt") != 700.0 {
		t.Errorf("suspend = %s", core.MustStringify(result))
	}
	if again := suspend(held, input); again.Get("outcome") != "already-applied" {
		t.Errorf("again = %v", again.Get("outcome"))
	}
	if none := suspend(identity("nobody", "org"), input); none.Get("outcome") != "no-clearance" || none.Has("record") {
		t.Errorf("none = %s", core.MustStringify(none))
	}
	if ended := suspend(revoked, input); ended.Get("outcome") != "no-clearance" {
		t.Errorf("revoked suspension = %v", ended.Get("outcome"))
	}
	// A record of another tenant is not the identity's.
	if record := must(ReadClearance(ctx, k.store, identity("held", "project"))); record != nil {
		t.Errorf("other tenant read: %v", record)
	}
	// Without the option nothing is read or changed.
	off := newKernel(t, nil)
	off.tenantTree()
	off.insert("clearances", clearanceRecord(t, "leaver", "org", "org", "S", ""))
	if count := must(TerminateClearancesOf(ctx, off.server, off.store, officer, leaver, "x")); count != 0 {
		t.Errorf("terminated without the option")
	}
	if record := must(ReadClearance(ctx, off.store, leaver)); record.Get("status") != "active" {
		t.Errorf("changed without the option")
	}
}

func TestClearancesKeepInheritedLabel(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) { options.Clearances = &ClearanceOptions{} })
	k.tenantTree()
	ctx := k.ctx
	officer := principalOf(identity("officer", "org"), session("so", "officer", "org", "user"))
	k.insert("classificationSchemes", schemeRecord(t, "org", ""))
	k.insert("resources", registration("org", "folder", "top", "", ""), registration("org", "doc", "leaf", "folder", "top"), registration("org", "doc", "own", "folder", "top"))
	k.insert("resourceLabels",
		labelRecord(t, "org", "org", "folder", "top", `{"level":"S","releasableTo":["GBR"]}`, true),
		labelRecord(t, "org", "org", "doc", "own", `{"level":"C","compartments":["GAMMA"]}`, false),
	)
	keep := func(resourceID string) error {
		return k.tx(func(ctx context.Context, tx core.IamStore) error {
			record := must(ManagedResource(ctx, tx, "org", "doc", resourceID))
			return KeepInheritedLabel(ctx, k.server, tx, officer, record)
		})
	}
	if err := keep("leaf"); err != nil {
		t.Fatal(err)
	}
	stored := must(StoredLabel(ctx, k.store, "org", "doc", "leaf"))
	if stored == nil || core.MustStringify(stored.Get("label")) != `{"level":"S","releasableTo":["GBR"]}` || stored.Get("inheritToChildren") != false || stored.Get("version") != 1.0 {
		t.Fatalf("kept = %v", stored)
	}
	if err := keep("own"); err != nil {
		t.Fatal(err)
	}
	stored = must(StoredLabel(ctx, k.store, "org", "doc", "own"))
	if core.MustStringify(stored.Get("label")) != `{"level":"S","compartments":["GAMMA"],"releasableTo":["GBR"]}` || stored.Get("version") != 2.0 {
		t.Errorf("joined = %s", core.MustStringify(stored))
	}
	events := must(k.store.Find(ctx, "audit", core.NewObject("action", "classification:label"), nil))
	if len(events) != 2 {
		t.Fatalf("audits = %d", len(events))
	}
	for _, event := range events {
		metadata := event.Get("metadata").(*core.Object)
		if event.Get("resourceId") == "doc/own" {
			if text := core.MustStringify(metadata); text != `{"type":"doc","level":"S","compartments":["GAMMA"],"releasableTo":["GBR"],"inheritToChildren":false,"previousLevel":"C","reason":"resource-deleted"}` {
				t.Errorf("metadata = %s", text)
			}
		}
	}
	// Already covered: nothing written again.
	if err := keep("own"); err != nil {
		t.Fatal(err)
	}
	if again := must(k.store.Find(ctx, "audit", core.NewObject("action", "classification:label"), nil)); len(again) != 2 {
		t.Errorf("rewrote a covered label")
	}
	// What it inherits must be readable under the scheme in force.
	k.insert("resources", registration("org", "folder", "stale", "", ""), registration("org", "doc", "under-stale", "folder", "stale"))
	k.insert("resourceLabels", labelRecord(t, "org", "elsewhere", "folder", "stale", `{"level":"S"}`, true))
	expectError(t, keep("under-stale"), "RESOURCE_IN_USE", "This resource inherits a classification label the scheme in force cannot read; repair that label before deleting it")
}

func TestClearancesAssertSchemeKept(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) { options.Clearances = &ClearanceOptions{} })
	k.tenantTree()
	ctx := k.ctx
	k.insert("tenants", core.NewObject("id", "other", "tenantId", "other", "name", "Other", "type", "organization", "parentId", "root", "status", "active", "createdAt", 4.0))
	k.insert("classificationSchemes", schemeRecord(t, "org", ""))
	project := must(k.store.Get(ctx, "tenants", "project"))
	other := must(k.store.Get(ctx, "tenants", "other"))
	org := must(k.store.Get(ctx, "tenants", "org"))
	// Nothing labeled: free to move.
	if err := AssertSchemeKept(ctx, k.server, k.store, project, other, []string{"project"}); err != nil {
		t.Fatal(err)
	}
	k.insert("resourceLabels", labelRecord(t, "project", "org", "document", "d1", `{"level":"S"}`, false))
	expectError(t, AssertSchemeKept(ctx, k.server, k.store, project, other, []string{"project"}), "RESOURCE_IN_USE",
		"Moving this tenant changes the classification scheme in force for it while it holds classification labels or clearances; declassify and revoke them first")
	// The same scheme stays in force: free to move.
	k.insert("tenants", core.NewObject("id", "team", "tenantId", "team", "name", "Team", "type", "project", "parentId", "org", "status", "active", "createdAt", 5.0))
	team := must(k.store.Get(ctx, "tenants", "team"))
	if err := AssertSchemeKept(ctx, k.server, k.store, project, team, []string{"project"}); err != nil {
		t.Errorf("same scheme: %v", err)
	}
	// Live clearances count too; ended ones do not.
	k.insert("clearances", clearanceRecord(t, "ended", "other", "org", "S", `{"status":"revoked"}`))
	if err := AssertSchemeKept(ctx, k.server, k.store, other, org, []string{"other"}); err != nil {
		t.Errorf("ended clearance: %v", err)
	}
	k.insert("clearances", clearanceRecord(t, "live", "other", "org", "S", `{"status":"suspended"}`))
	if err := AssertSchemeKept(ctx, k.server, k.store, other, org, []string{"other"}); err == nil {
		t.Errorf("live clearance moved")
	}
}

func TestClearancesClearedForAndNotify(t *testing.T) {
	var sent []auth.DeliveryMessage
	k := newKernel(t, func(options *BetterIamOptions) {
		options.Clearances = &ClearanceOptions{}
		options.Authentication = &auth.Options{SendEmail: func(ctx context.Context, message auth.DeliveryMessage) error {
			sent = append(sent, message)
			return nil
		}}
	})
	k.tenantTree()
	ctx := k.ctx
	k.insert("classificationSchemes", schemeRecord(t, "org", ""))
	person := identity("person", "org", "email", "person@example.test")
	k.insert("identities", person)
	k.insert("clearances", clearanceRecord(t, "person", "org", "org", "C", ""))
	k.insert("resourceLabels", labelRecord(t, "org", "org", "credential-type", "badge", `{"level":"S"}`, false))
	org := must(k.store.Get(ctx, "tenants", "org"))
	principal := principalOf(person, session("sp", "person", "org", "user"))
	badge := ResolvedResource{TenantID: "org", Type: "credential-type", ID: "badge"}
	if cleared := must(ClearedFor(ctx, k.server, k.store, principal, org, badge, "credentials:issue")); cleared {
		t.Errorf("cleared above the clearance")
	}
	if cleared := must(ClearedFor(ctx, k.server, k.store, principal, org, badge, "iam:credentials:issue")); !cleared {
		t.Errorf("iam action refused")
	}
	if cleared := must(ClearedFor(ctx, k.server, k.store, principal, org, ResolvedResource{TenantID: "org", Type: "credential-type", ID: "open"}, "credentials:issue")); !cleared {
		t.Errorf("unlabeled refused")
	}
	scheme := must(SchemeForTenant(ctx, k.store, "org"))
	record := must(ReadClearance(ctx, k.store, person))
	if err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		return NotifyClearanceStatus(ctx, k.server, tx, person, scheme, record, "suspended")
	}); err != nil {
		t.Fatal(err)
	}
	messages := must(k.store.Find(ctx, "outbox", core.NewObject(), nil))
	if len(messages) != 1 {
		t.Fatalf("outbox = %d", len(messages))
	}
	// Nobody without an address is told.
	if err := NotifyClearanceStatus(ctx, k.server, k.store, identity("silent", "org"), scheme, record, "revoked"); err != nil {
		t.Fatal(err)
	}
	if again := must(k.store.Find(ctx, "outbox", core.NewObject(), nil)); len(again) != 1 {
		t.Errorf("emailed someone without an address")
	}
	off := newKernel(t, nil)
	if cleared := must(ClearedFor(ctx, off.server, off.store, principal, org, badge, "credentials:issue")); !cleared {
		t.Errorf("refused without the option")
	}
}

func TestClearancesRootUnderMandatoryAccess(t *testing.T) {
	for _, appliesToRoot := range []bool{true, false} {
		f := newClearanceFixture(t, func(options *BetterIamOptions) { options.Clearances = &ClearanceOptions{AppliesToRoot: &appliesToRoot} })
		rootIdentity := f.root.Get("identity").(*core.Object)
		token := f.signIn(rootIdentity, true)
		f.seed("classificationSchemes", schemeRecord(t, f.tenantID, ""))
		f.seed("resourceLabels", labelRecord(t, f.tenantID, f.tenantID, "document", "d-s", `{"level":"S"}`, false))
		decision := f.authorize(token, "documents:read", "document", "d-s")
		if appliesToRoot {
			expectDecision(t, "root reads up", decision, false, "ACCESS_DENIED")
			f.seed("clearances", clearanceRecord(t, jsString(rootIdentity.Get("id")), f.tenantID, f.tenantID, "S", ""))
			expectDecision(t, "root cleared", f.authorize(token, "documents:read", "document", "d-s"), true, "ROOT_OVERRIDE")
		} else {
			expectDecision(t, "appliesToRoot false", decision, true, "ROOT_OVERRIDE")
		}
		expectDecision(t, "root unlabeled", f.authorize(token, "documents:read", "document", "plain"), true, "ROOT_OVERRIDE")
	}
}
