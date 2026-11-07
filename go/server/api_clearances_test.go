package server

// Clearances API tests, after tests/clearances.test.ts: FEATURE_DISABLED without the option, scheme validation and
// guarded definition changes, and labels that only rise until declassified by someone cleared to read them; plus
// unit tests of the API's private helpers (label resource names, citizenship, required types, notify addresses,
// retired levels and the definition-change guard). The API steps go through the clearances module (clearances.ts,
// its own unit); while a step reaches one of its NOT_IMPLEMENTED stubs the rest of the test is skipped.

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

var clearanceOfficerPermissions = []string{
	"iam:clearances:read",
	"iam:clearances:adjudicate",
	"iam:clearances:suspend",
	"iam:classifications:label",
	"iam:classifications:declassify",
}

// clearanceUSWithCompartments is the us template with two compartments.
func clearanceUSWithCompartments() *core.Object {
	definition := core.Normalize(core.ClassificationTemplates["us"]).(*core.Object)
	definition.Set("compartments", []any{
		core.NewObject("id", "GAMMA", "name", "Gamma codeword"),
		core.NewObject("id", "HCS", "name", "Humint control"),
	})
	return definition
}

// clearanceWithoutLevels is the definition without the given level ids.
func clearanceWithoutLevels(definition *core.Object, ids ...string) *core.Object {
	out := definition.Spread()
	levels := []any{}
	for _, level := range definition.Get("levels").([]any) {
		if !containsString(ids, jsString(member(level, "id"))) {
			levels = append(levels, level)
		}
	}
	out.Set("levels", levels)
	return out
}

// clearanceSkip skips the rest of the test when err is a NOT_IMPLEMENTED stub of another unit.
func clearanceSkip(t *testing.T, err error) {
	t.Helper()
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
}

// clearanceCheck unwraps answers for a test.
type clearanceCheck struct{ t *testing.T }

// ok unwraps an answer (skipping on another unit's stub).
func (c clearanceCheck) ok(value any, err error) any {
	t := c.t
	t.Helper()
	clearanceSkip(t, err)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return value
}

func (c clearanceCheck) object(value any, err error) *core.Object {
	t := c.t
	t.Helper()
	object, ok := c.ok(value, err).(*core.Object)
	if !ok {
		t.Fatalf("expected an object, got %#v", value)
	}
	return object
}

// clearanceRefused expects the error code (skipping on another unit's stub).
func clearanceRefused(t *testing.T, label string, err error, code string) {
	t.Helper()
	clearanceSkip(t, err)
	if err == nil {
		t.Fatalf("%s: expected %s, got no error", label, code)
	}
	if known := iamError(t, err); known.Code != code {
		t.Fatalf("%s: expected %s, got %s %q", label, code, known.Code, known.Message)
	}
}

func newClearanceFixture(t *testing.T, enabled bool) *govFixture {
	t.Helper()
	f := newGovFixture(t, func(options *BetterIamOptions) {
		if enabled {
			options.Clearances = &ClearanceOptions{}
		}
	})
	// The administrator is the tenant's owner (owners may bootstrap levels nobody holds yet).
	f.change("identities", f.adminID, "owner", true)
	return f
}

func TestClearancesAnswerFeatureDisabledWithoutTheOption(t *testing.T) {
	f := newClearanceFixture(t, false)
	api := f.iam.API.Clearances
	body := func() *core.Object {
		return core.NewObject("tenantId", f.tenantID, "identityId", f.adminID, "type", "document", "id", "x")
	}
	methods := map[string]func() (any, error){
		"debrief":      func() (any, error) { return call(api.Debrief, f.adminToken, body()) },
		"declassify":   func() (any, error) { return call(api.Declassify, f.adminToken, body()) },
		"defineScheme": func() (any, error) { return call(api.DefineScheme, f.adminToken, body()) },
		"explain":      func() (any, error) { return call(api.Explain, f.adminToken, body()) },
		"get":          func() (any, error) { return call(api.Get, f.adminToken, body()) },
		"getLabel":     func() (any, error) { return call(api.GetLabel, f.adminToken, body()) },
		"getScheme":    func() (any, error) { return call(api.GetScheme, f.adminToken, body()) },
		"grant":        func() (any, error) { return call(api.Grant, f.adminToken, body()) },
		"label":        func() (any, error) { return call(api.Label, f.adminToken, body()) },
		"list":         func() (any, error) { return call(api.List, f.adminToken, body()) },
		"listLabels":   func() (any, error) { return call(api.ListLabels, f.adminToken, body()) },
		"mine":         func() (any, error) { return call(api.Mine, f.adminToken, body()) },
		"readIn":       func() (any, error) { return call(api.ReadIn, f.adminToken, body()) },
		"reinstate":    func() (any, error) { return call(api.Reinstate, f.adminToken, body()) },
		"revoke":       func() (any, error) { return call(api.Revoke, f.adminToken, body()) },
		"suspend":      func() (any, error) { return call(api.Suspend, f.adminToken, body()) },
		"templates":    func() (any, error) { return call(api.Templates, f.adminToken, body()) },
		"update":       func() (any, error) { return call(api.Update, f.adminToken, body()) },
		"updateScheme": func() (any, error) { return call(api.UpdateScheme, f.adminToken, body()) },
	}
	for name, method := range methods {
		_, err := method()
		clearanceSkip(t, err)
		if err == nil {
			t.Fatalf("%s: expected FEATURE_DISABLED", name)
		}
		if known := iamError(t, err); known.Code != "FEATURE_DISABLED" || known.Status != 403 {
			t.Fatalf("%s: expected FEATURE_DISABLED 403, got %s %d", name, known.Code, known.Status)
		}
	}
	_, err := f.iam.Clearances.SendReminders(context.Background(), nil)
	clearanceRefused(t, "sendReminders", err, "FEATURE_DISABLED")
}

func TestClearancesValidateSchemesAndChangeOnlyWhatNothingUses(t *testing.T) {
	c := clearanceCheck{t}
	f := newClearanceFixture(t, true)
	api := f.iam.API.Clearances
	tenantID := f.tenantID
	owner := f.adminToken
	define := func(input *core.Object) (any, error) {
		return call(api.DefineScheme, owner, core.NewObject("tenantId", tenantID, "name", "Acme").Assign(input))
	}
	invalid := []*core.Object{
		core.NewObject(),
		core.NewObject("template", "us", "definition", clearanceUSWithCompartments()),
		core.NewObject("template", "secret-service"),
		core.NewObject("definition", core.NewObject("levels", []any{core.NewObject("id", "U", "name", "UNCLASSIFIED", "rank", 0.0)})),
		core.NewObject("definition", clearanceUSWithCompartments().Spread(core.NewObject("colour", "red"))),
		core.NewObject("template", "us", "name", ""),
		core.NewObject("template", "us", "requireLabels", []any{"iam"}),
		core.NewObject("template", "us", "requireLabels", "document"),
		core.NewObject("template", "us", "guestCeiling", "COSMIC"),
		core.NewObject("template", "us", "guestCeiling", 2.0),
		core.NewObject("template", "us", "adjudication", "anyone"),
		core.NewObject("template", "us", "interimAllowed", "yes"),
		core.NewObject("template", "us", "defaultLabel", core.NewObject("level", "Q")),
		core.NewObject("template", "us", "defaultLabel", core.NewObject("level", "C", "compartments", []any{"GAMMA"})),
		core.NewObject("template", "corporate", "defaultLabel", core.NewObject("level", "internal", "noforn", true)),
		core.NewObject("template", "us", "notify", core.NewObject("emails", []any{"not an address"})),
	}
	for _, input := range invalid {
		_, err := define(input)
		clearanceRefused(t, stringify(input), err, "INVALID_INPUT")
	}
	if scheme := c.ok(call(api.GetScheme, owner, core.NewObject("tenantId", tenantID))); scheme != nil {
		t.Fatalf("getScheme = %s", stringify(scheme))
	}
	_, err := call(api.UpdateScheme, owner, core.NewObject("tenantId", tenantID, "interimAllowed", true))
	clearanceRefused(t, "update without a scheme", err, "NOT_FOUND")

	scheme := c.object(define(core.NewObject(
		"definition", clearanceUSWithCompartments(),
		"requireLabels", []any{"document", "*", "document"},
		"defaultLabel", core.NewObject("level", "C"),
		"guestCeiling", "C",
		"notify", core.NewObject("emails", []any{"Security@Acme.test", "security@acme.test"}),
	)))
	expectJSON(t, "requireLabels", scheme.Get("requireLabels"), `["*","document"]`)
	expectJSON(t, "defaultLabel", scheme.Get("defaultLabel"), `{"level":"C"}`)
	expectJSON(t, "notify", scheme.Get("notify"), `{"emails":["security@acme.test"]}`)
	if scheme.Get("name") != "Acme" || scheme.Get("guestCeiling") != "C" || scheme.Get("inherited") != false || scheme.Get("version") != 1.0 {
		t.Fatalf("scheme = %s", stringify(scheme))
	}
	_, err = call(api.UpdateScheme, owner, core.NewObject("tenantId", tenantID, "template", "uk"))
	clearanceRefused(t, "update with a template", err, "INVALID_INPUT")
	base := clearanceUSWithCompartments()
	withoutC := clearanceWithoutLevels(base, "C")
	// Settings that name a level must follow the definition: drop them first.
	_, err = call(api.UpdateScheme, owner, core.NewObject("tenantId", tenantID, "definition", withoutC))
	clearanceRefused(t, "default label left behind", err, "INVALID_INPUT")
	_, err = call(api.UpdateScheme, owner, core.NewObject("tenantId", tenantID, "definition", withoutC, "defaultLabel", nil))
	clearanceRefused(t, "guest ceiling left behind", err, "INVALID_INPUT")

	// Levels and compartments that only ended clearances used are free to go; a suspended one still holds them.
	bob := jsString(f.person("bob").Get("id"))
	carol := jsString(f.person("carol").Get("id"))
	c.object(call(api.Grant, owner, core.NewObject("tenantId", tenantID, "identityId", bob, "level", "C", "citizenship", []any{"USA"})))
	c.object(call(api.ReadIn, owner, core.NewObject("tenantId", tenantID, "identityId", bob, "compartmentId", "HCS")))
	revoked := c.object(call(api.Revoke, owner, core.NewObject("tenantId", tenantID, "identityId", bob, "reason", "left the program")))
	if revoked.Get("status") != "revoked" || stringify(revoked.Get("readIns")) != "[]" {
		t.Fatalf("revoked = %s", stringify(revoked))
	}
	c.object(call(api.Grant, owner, core.NewObject("tenantId", tenantID, "identityId", carol, "level", "TS", "citizenship", []any{"USA"})))
	suspended := c.object(call(api.Suspend, owner, core.NewObject("tenantId", tenantID, "identityId", carol, "reason", "review", "notifyPerson", false)))
	if suspended.Get("status") != "suspended" || member(suspended.Get("suspended"), "reason") != "review" {
		t.Fatalf("suspended = %s", stringify(suspended))
	}
	_, err = call(api.UpdateScheme, owner, core.NewObject("tenantId", tenantID,
		"definition", clearanceWithoutLevels(withoutC, "TS"), "defaultLabel", nil, "guestCeiling", nil))
	clearanceRefused(t, "a suspended clearance holds its level", err, "RESOURCE_IN_USE")
	renamed := withoutC.Spread(core.NewObject("compartments", []any{core.NewObject("id", "GAMMA", "name", "Gamma renamed")}))
	updated := c.object(call(api.UpdateScheme, owner, core.NewObject("tenantId", tenantID,
		"name", "Acme programs", "definition", renamed, "defaultLabel", nil, "guestCeiling", nil, "notify", nil, "requireLabels", []any{})))
	var ranks []string
	for _, level := range member(updated.Get("definition"), "levels").([]any) {
		ranks = append(ranks, jsString(member(level, "id"))+":"+jsString(member(level, "rank")))
	}
	if strings.Join(ranks, ",") != "U:0,S:2,TS:3" {
		t.Fatalf("levels = %v", ranks)
	}
	expectJSON(t, "compartments", member(updated.Get("definition"), "compartments"), `[{"id":"GAMMA","name":"Gamma renamed"}]`)
	if updated.Get("name") != "Acme programs" || stringify(updated.Get("requireLabels")) != "[]" || updated.Get("guestCeiling") != nil ||
		updated.Has("defaultLabel") || updated.Has("notify") || updated.Get("version") != 2.0 {
		t.Fatalf("updated = %s", stringify(updated))
	}
	// A level removed cannot come back below the levels kept.
	_, err = call(api.UpdateScheme, owner, core.NewObject("tenantId", tenantID, "definition", base))
	clearanceRefused(t, "a removed level comes back below", err, "INVALID_INPUT")
	var update *core.Object
	for _, event := range f.find("audit", core.NewObject("tenantId", tenantID, "action", "classification:scheme-update")) {
		if member(event.Get("metadata"), "version") == 2.0 {
			update = event
		}
	}
	if update == nil {
		t.Fatal("no classification:scheme-update audit event for version 2")
	}
	metadata := update.Get("metadata")
	expectJSON(t, "changed", member(metadata, "changed"), `["definition","name","requireLabels","defaultLabel","guestCeiling","notify"]`)
	expectJSON(t, "levels", member(metadata, "levels"), `["U","S","TS"]`)
	expectJSON(t, "audit compartments", member(metadata, "compartments"), `["GAMMA"]`)
	if strings.Contains(stringify(metadata), "Gamma renamed") {
		t.Fatal("the audit names a compartment")
	}
}

func TestClearancesLabelsRiseInEveryDimensionAndDeclassifyOnlyOnPurpose(t *testing.T) {
	c := clearanceCheck{t}
	f := newClearanceFixture(t, true)
	api := f.iam.API.Clearances
	tenantID := f.tenantID
	olga := f.person("olga")
	olgaID := jsString(olga.Get("id"))
	f.role("role-officer", "Officers", false, clearanceOfficerPermissions...)
	f.bind("binding-officer", "role-officer", "identity", olgaID, adminAuthority)
	o := f.token(olga)
	document := func(id string, members ...any) *core.Object {
		return core.NewObject(append([]any{"tenantId", tenantID, "type", "document", "id", id}, members...)...)
	}
	label := func(id string, value any) (any, error) {
		return call(api.Label, o, document(id, "label", value))
	}
	// Without a scheme there is nothing to label against.
	_, err := label("a", core.NewObject("level", "C"))
	clearanceRefused(t, "label without a scheme", err, "NOT_FOUND")
	c.object(call(api.DefineScheme, f.adminToken, core.NewObject("tenantId", tenantID, "name", "Acme",
		"definition", clearanceUSWithCompartments(), "adjudication", "unrestricted")))
	c.object(call(api.Grant, f.adminToken, core.NewObject("tenantId", tenantID, "identityId", olgaID, "level", "TS", "citizenship", []any{"USA"})))
	c.object(call(api.ReadIn, f.adminToken, core.NewObject("tenantId", tenantID, "identityId", olgaID, "compartmentId", "HCS")))
	first := c.object(label("a", core.NewObject("level", "C", "releasableTo", []any{"GBR", "AUS"})))
	expectJSON(t, "first label", first.Get("label"), `{"level":"C","releasableTo":["AUS","GBR"]}`)
	if first.Get("levelName") != "CONFIDENTIAL" || first.Get("inheritToChildren") != false || first.Get("labeledBy") != olgaID || first.Get("version") != 1.0 {
		t.Fatalf("first = %s", stringify(first))
	}
	// Releasable to fewer countries, NOFORN, a compartment: all raise.
	for _, value := range []*core.Object{
		core.NewObject("level", "C", "releasableTo", []any{"AUS"}),
		core.NewObject("level", "C", "releasableTo", []any{}),
		core.NewObject("level", "C", "noforn", true),
		core.NewObject("level", "S", "noforn", true, "compartments", []any{"HCS"}),
	} {
		c.object(label("a", value))
	}
	same := c.object(label("a", core.NewObject("level", "S", "noforn", true, "compartments", []any{"HCS"})))
	if same.Get("version") != 5.0 {
		t.Fatalf("same = %s", stringify(same))
	}
	// Releasable again, or to more, or without the compartment: declassifications.
	for _, value := range []*core.Object{
		core.NewObject("level", "S", "compartments", []any{"HCS"}),
		core.NewObject("level", "S", "noforn", true),
		core.NewObject("level", "C", "noforn", true, "compartments", []any{"HCS"}),
		core.NewObject("level", "S", "compartments", []any{"HCS"}, "releasableTo", []any{"AUS"}),
	} {
		_, err := label("a", value)
		clearanceRefused(t, stringify(value), err, "ACCESS_DENIED")
	}
	for _, value := range []any{
		core.NewObject("level", "Q"),
		core.NewObject("level", "C", "releasableTo", []any{"gbr"}),
		core.NewObject("level", "C", "caveats", []any{"NOFORN"}),
		"C",
	} {
		_, err := label("b", value)
		clearanceRefused(t, stringify(value), err, "INVALID_INPUT")
	}
	// Declassifying: a reason, a label (or null) and an existing label.
	for _, item := range []struct {
		input *core.Object
		code  string
	}{
		{document("a", "label", core.NewObject("level", "C")), "INVALID_INPUT"},
		{document("a", "reason", "x"), "INVALID_INPUT"},
		{document("none", "label", nil, "reason", "x"), "NOT_FOUND"},
		{document("a", "label", core.NewObject("level", "Q"), "reason", "x"), "INVALID_INPUT"},
	} {
		_, err := call(api.Declassify, o, item.input)
		clearanceRefused(t, stringify(item.input), err, item.code)
	}
	lowered := c.object(call(api.Declassify, o, document("a", "label", core.NewObject("level", "C"), "reason", "reviewed")))
	expectJSON(t, "lowered label", lowered.Get("label"), `{"level":"C"}`)
	if lowered.Get("version") != 6.0 {
		t.Fatalf("lowered = %s", stringify(lowered))
	}
	// An officer cleared below the label cannot declassify it, even with the permission.
	c.object(label("t", core.NewObject("level", "TS", "compartments", []any{"GAMMA"})))
	_, err = call(api.Declassify, o, document("t", "label", nil, "reason", "x"))
	clearanceRefused(t, "declassify above one's clearance", err, "ACCESS_DENIED")
	c.object(call(api.ReadIn, f.adminToken, core.NewObject("tenantId", tenantID, "identityId", olgaID, "compartmentId", "GAMMA")))
	if removed := c.ok(call(api.Declassify, o, document("t", "label", nil, "reason", "done"))); removed != nil {
		t.Fatalf("removed = %s", stringify(removed))
	}

	for _, id := range []string{"c", "d", "e"} {
		level := "U"
		if id == "d" {
			level = "S"
		}
		c.object(label(id, core.NewObject("level", level)))
	}
	c.object(call(api.Label, o, core.NewObject("tenantId", tenantID, "type", "memo", "id", "m", "label", core.NewObject("level", "U"))))
	names := func(page *core.Object, full bool) string {
		var out []string
		for _, item := range page.Get("labels").([]any) {
			if full {
				out = append(out, jsString(member(item, "type"))+"/"+jsString(member(item, "id")))
			} else {
				out = append(out, jsString(member(item, "id")))
			}
		}
		return strings.Join(out, ",")
	}
	all := c.object(call(api.ListLabels, o, core.NewObject("tenantId", tenantID)))
	if got := names(all, true); got != "document/a,document/c,document/d,document/e,memo/m" {
		t.Fatalf("labels = %s", got)
	}
	filtered := c.object(call(api.ListLabels, o, core.NewObject("tenantId", tenantID, "type", "document", "level", "U")))
	if got := names(filtered, false); got != "c,e" {
		t.Fatalf("filtered = %s", got)
	}
	second := c.object(call(api.ListLabels, o, core.NewObject("tenantId", tenantID, "limit", 2.0, "offset", 2.0)))
	if got := names(second, false); got != "d,e" || second.Get("total") != 5.0 {
		t.Fatalf("second page = %s (%v)", got, second.Get("total"))
	}
	_, err = call(api.ListLabels, o, core.NewObject("tenantId", tenantID, "type", "iam"))
	clearanceRefused(t, "a platform type", err, "INVALID_INPUT")
}

// --- private helpers -------------------------------------------------------------------------------

func TestClearanceLabelResourceHashesLongNames(t *testing.T) {
	if got := clearanceLabelResource("document", "plan"); got != "classifications/labels/document/plan" {
		t.Fatalf("plain = %s", got)
	}
	long := strings.Repeat("é", 300)
	if got := clearanceLabelResource("document", long); got != "classifications/labels/document/sha256:"+Hash(long) {
		t.Fatalf("long id = %s", got)
	}
	longType := strings.Repeat("a", 64)
	if got := clearanceLabelResource(longType, strings.Repeat("x", 200)); got != "classifications/labels/"+longType+"/sha256:"+Hash(strings.Repeat("x", 200)) {
		t.Fatalf("long type = %s", got)
	}
	veryLong := strings.Repeat("t", 240)
	if got := clearanceLabelResource(veryLong, "id"); got != "classifications/labels/sha256:"+Hash(veryLong+"/id") {
		t.Fatalf("very long type = %s", got)
	}
}

func TestClearanceInputValidators(t *testing.T) {
	citizenship, err := clearanceCitizenship([]any{"USA", "GBR", "USA"})
	if err != nil || stringify(citizenship) != `["GBR","USA"]` {
		t.Fatalf("citizenship = %s %v", stringify(citizenship), err)
	}
	if empty, err := clearanceCitizenship([]any{}); err != nil || stringify(empty) != "[]" {
		t.Fatalf("empty citizenship = %s %v", stringify(empty), err)
	}
	_, err = clearanceCitizenship([]any{"usa"})
	expectError(t, err, "INVALID_INPUT", "citizenship must hold ISO 3166-1 alpha-3 codes in upper case")
	_, err = clearanceCitizenship("USA")
	expectError(t, err, "INVALID_INPUT", "citizenship must list at most 10 countries")
	eleven := make([]any, 11)
	for index := range eleven {
		eleven[index] = "AAA"
	}
	_, err = clearanceCitizenship(eleven)
	expectError(t, err, "INVALID_INPUT", "citizenship must list at most 10 countries")

	types, err := clearanceRequiredTypes([]any{"document", "*", "document", "memo"})
	if err != nil || stringify(types) != `["*","document","memo"]` {
		t.Fatalf("types = %s %v", stringify(types), err)
	}
	_, err = clearanceRequiredTypes([]any{"iam"})
	expectError(t, err, "INVALID_INPUT", "Platform resource types cannot be labeled")
	_, err = clearanceRequiredTypes([]any{"Doc/x"})
	expectError(t, err, "INVALID_INPUT", `type must be a resource type name: a lowercase letter, then up to 63 lowercase letters, digits or "-"`)
	_, err = clearanceRequiredTypes([]any{3.0})
	expectError(t, err, "INVALID_INPUT", "Invalid type")
	_, err = clearanceRequiredTypes("document")
	expectError(t, err, "INVALID_INPUT", "requireLabels must list at most 100 resource types")

	notify, err := clearanceNotifyEmails(core.NewObject("emails", []any{"B@acme.test", "a@acme.test", "b@acme.test"}))
	if err != nil || stringify(notify) != `{"emails":["a@acme.test","b@acme.test"]}` {
		t.Fatalf("notify = %s %v", stringify(notify), err)
	}
	if none, err := clearanceNotifyEmails(core.NewObject("emails", []any{})); err != nil || none != nil {
		t.Fatalf("an empty notify list = %v %v", none, err)
	}
	if none, err := clearanceNotifyEmails(nil); err != nil || none != nil {
		t.Fatalf("a null notify = %v %v", none, err)
	}
	_, err = clearanceNotifyEmails("a@acme.test")
	expectError(t, err, "INVALID_INPUT", "Expected an object")
	_, err = clearanceNotifyEmails(core.NewObject("emails", []any{"nope"}))
	expectError(t, err, "INVALID_INPUT", "Invalid email")

	if _, set, err := clearanceFlag(core.Undefined, "interim"); set || err != nil {
		t.Fatal("an absent flag is unset")
	}
	if value, set, err := clearanceFlag(true, "interim"); !value || !set || err != nil {
		t.Fatal("a true flag")
	}
	_, _, err = clearanceFlag("yes", "interimAllowed")
	expectError(t, err, "INVALID_INPUT", "interimAllowed must be a boolean")
}

func TestClearanceSchemeSettingsWithoutLevelNames(t *testing.T) {
	typed, err := core.ValidateScheme(clearanceUSWithCompartments())
	if err != nil {
		t.Fatal(err)
	}
	definition := clearanceDefinitionModel(typed)
	settings, err := clearanceSchemeSettings(core.NewObject("name", "  Acme  ", "defaultLabel", core.NewObject("level", "S", "compartments", []any{"HCS", "GAMMA"})), definition, typed, nil)
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, "settings", settings, `{"name":"Acme","requireLabels":[],"defaultLabel":{"level":"S","compartments":["GAMMA","HCS"]},"guestCeiling":null,"interimAllowed":false,"adjudication":"within-own"}`)
	_, err = clearanceSchemeSettings(core.NewObject(), definition, typed, nil)
	expectError(t, err, "INVALID_INPUT", "name is required")
	_, err = clearanceSchemeSettings(core.NewObject("name", "Acme", "adjudication", "anyone"), definition, typed, nil)
	expectError(t, err, "INVALID_INPUT", "adjudication must be within-own or unrestricted")
	_, err = clearanceSchemeSettings(core.NewObject("name", "Acme", "guestCeiling", 2.0), definition, typed, nil)
	expectError(t, err, "INVALID_INPUT", "guestCeiling must be a level id of the scheme, or null")

	// Over a stored scheme: unchanged settings carry over, null clears, the default label is re-checked.
	previous := core.NewObject("name", "Old", "requireLabels", []any{"document"}, "defaultLabel", core.NewObject("level", "C"),
		"guestCeiling", nil, "interimAllowed", true, "adjudication", "unrestricted", "notify", core.NewObject("emails", []any{"a@acme.test"}))
	kept, err := clearanceSchemeSettings(core.NewObject("notify", nil), definition, typed, previous)
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, "kept", kept, `{"name":"Old","requireLabels":["document"],"defaultLabel":{"level":"C"},"guestCeiling":null,"interimAllowed":true,"adjudication":"unrestricted"}`)
	narrower, err := core.ValidateScheme(clearanceWithoutLevels(clearanceUSWithCompartments(), "C"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = clearanceSchemeSettings(core.NewObject(), clearanceDefinitionModel(narrower), narrower, previous)
	expectError(t, err, "INVALID_INPUT", "The default label is not valid under the new definition; set a new defaultLabel or null")
	cleared, err := clearanceSchemeSettings(core.NewObject("defaultLabel", nil), clearanceDefinitionModel(narrower), narrower, previous)
	if err != nil || cleared.Has("defaultLabel") {
		t.Fatalf("cleared = %s %v", stringify(cleared), err)
	}
}

func TestClearanceRetiredLevelsAndDefinitionChanges(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	base := clearanceUSWithCompartments()
	scheme := core.NewObject("id", "s1", "tenantId", "t1", "uniqueKey", "scheme", "definition", base, "version", 1.0)
	withoutC, _ := core.ValidateScheme(clearanceWithoutLevels(base, "C"))
	retired, err := clearanceRetiredLevelsAfter(scheme, withoutC)
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, "retired", retired, `[{"id":"C","rank":1}]`)
	// A level that comes back leaves the retired list.
	stored := scheme.Spread(core.NewObject("definition", clearanceDefinitionModel(withoutC), "retiredLevels", retired))
	back, _ := core.ValidateScheme(base)
	if again, err := clearanceRetiredLevelsAfter(stored, back); err != nil || len(again) != 0 {
		t.Fatalf("again = %s %v", stringify(again), err)
	}

	err = store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		// New levels go above every level kept, and a level keeps its rank.
		lower := clearanceUSWithCompartments()
		usLevels := lower.Get("levels").([]any)
		lower.Set("levels", []any{usLevels[0], core.NewObject("id", "R", "name", "RESTRICTED", "rank", 1.0), usLevels[2], usLevels[3]})
		typed, err := core.ValidateScheme(lower)
		if err != nil {
			return err
		}
		expectError(t, clearanceAssertDefinitionChange(ctx, tx, scheme, typed), "INVALID_INPUT", "New levels go above every existing level")
		reranked := clearanceUSWithCompartments()
		levels := reranked.Get("levels").([]any)
		levels[3] = levels[3].(*core.Object).Spread(core.NewObject("rank", 5.0))
		typed, _ = core.ValidateScheme(reranked)
		expectError(t, clearanceAssertDefinitionChange(ctx, tx, scheme, typed), "RESOURCE_IN_USE", "Levels keep their rank: labels, including those your application asserts, may use any level")
		// A retired level comes back only at its former rank.
		atAnotherRank := clearanceWithoutLevels(base, "C")
		atAnotherRank.Set("levels", append(atAnotherRank.Get("levels").([]any), core.NewObject("id", "C", "name", "CONFIDENTIAL", "rank", 7.0)))
		typed, _ = core.ValidateScheme(atAnotherRank)
		expectError(t, clearanceAssertDefinitionChange(ctx, tx, stored, typed), "RESOURCE_IN_USE", "Levels keep their rank: labels, including those your application asserts, may use any level")

		// What live clearances and labels use stays.
		if _, err := tx.Insert(ctx, ClearanceCollections.Clearances, core.NewObject("id", "u1", "tenantId", "t1", "uniqueKey", "identity:u1", "identityId", "u1",
			"schemeTenantId", "t1", "level", "S", "citizenship", []any{}, "status", "suspended", "readIns", []any{core.NewObject("compartmentId", "HCS")})); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, ClearanceCollections.Clearances, core.NewObject("id", "u2", "tenantId", "t1", "uniqueKey", "identity:u2", "identityId", "u2",
			"schemeTenantId", "t1", "level", "TS", "citizenship", []any{}, "status", "revoked", "readIns", []any{core.NewObject("compartmentId", "GAMMA")})); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, ClearanceCollections.Labels, core.NewObject("id", "l1", "tenantId", "t1", "uniqueKey", "document/a", "type", "document", "resourceId", "a",
			"label", core.NewObject("level", "C", "releasableTo", []any{"GBR"}), "inheritToChildren", false, "schemeTenantId", "t1", "labeledBy", "x", "labeledAt", 1.0, "version", 1.0)); err != nil {
			return err
		}
		typed, _ = core.ValidateScheme(clearanceWithoutLevels(base, "S"))
		expectError(t, clearanceAssertDefinitionChange(ctx, tx, scheme, typed), "RESOURCE_IN_USE", "A level that clearances or labels use cannot be removed")
		typed, _ = core.ValidateScheme(clearanceWithoutLevels(base, "C"))
		expectError(t, clearanceAssertDefinitionChange(ctx, tx, scheme, typed), "RESOURCE_IN_USE", "A level that clearances or labels use cannot be removed")
		withoutHCS := base.Spread(core.NewObject("compartments", []any{core.NewObject("id", "GAMMA", "name", "Gamma codeword")}))
		typed, _ = core.ValidateScheme(withoutHCS)
		expectError(t, clearanceAssertDefinitionChange(ctx, tx, scheme, typed), "RESOURCE_IN_USE", "A compartment that clearances or labels use cannot be removed")
		// Only a revoked clearance used GAMMA: it may go. Dropping RELTO would invalidate the label.
		withoutGamma := base.Spread(core.NewObject("compartments", []any{core.NewObject("id", "HCS", "name", "Humint control")}))
		typed, _ = core.ValidateScheme(withoutGamma)
		if err := clearanceAssertDefinitionChange(ctx, tx, scheme, typed); err != nil {
			t.Errorf("removing a compartment only an ended clearance used: %v", err)
		}
		withoutRelto := base.Spread(core.NewObject("caveats", []any{"NOFORN"}))
		typed, _ = core.ValidateScheme(withoutRelto)
		expectError(t, clearanceAssertDefinitionChange(ctx, tx, scheme, typed), "RESOURCE_IN_USE", "The change would invalidate existing labels")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestClearancePartyAndLabelViews(t *testing.T) {
	state := core.NewObject("party", core.NewObject("identityId", "u1", "rank", 2.0, "compartments", []any{"HCS", "GAMMA"}, "citizenship", []any{"USA"}),
		"status", "active", "level", core.NewObject("id", "S", "name", "SECRET", "rank", 2.0))
	expectJSON(t, "party", clearancePartyView(state), `{"identityId":"u1","status":"active","level":"S","rank":2,"compartments":["GAMMA","HCS"],"citizenship":["USA"]}`)
	uncleared := core.NewObject().SetRaw("party", &core.ClearanceParty{IdentityID: "u2", Rank: -1, Compartments: map[string]bool{}, Citizenship: map[string]bool{"GBR": true}}).Set("status", "none")
	expectJSON(t, "uncleared", clearancePartyView(uncleared), `{"identityId":"u2","status":"none","rank":-1,"compartments":[],"citizenship":["GBR"]}`)
	if !clearancePartyHas(clearanceParty(state), "HCS") || clearancePartyHas(clearanceParty(uncleared), "HCS") {
		t.Fatal("party compartments")
	}
	expectJSON(t, "metadata", clearanceLabelMetadata(core.NewObject("level", "S", "compartments", []any{"HCS"}, "noforn", true, "releasableTo", []any{})),
		`{"level":"S","compartments":["HCS"],"noforn":true,"releasableTo":[]}`)
	expectJSON(t, "plain metadata", clearanceLabelMetadata(core.NewObject("level", "U", "compartments", []any{})), `{"level":"U"}`)
	scheme := core.NewObject("tenantId", "t1", "name", "Acme", "definition", clearanceUSWithCompartments(), "requireLabels", []any{"*"},
		"guestCeiling", nil, "interimAllowed", false, "adjudication", "within-own", "notify", core.NewObject("emails", []any{"a@acme.test"}),
		"createdAt", 1.0, "createdBy", "x", "updatedAt", 2.0, "updatedBy", "y", "version", 3.0)
	view := clearanceSchemeView(scheme, "t2")
	if view.Get("inherited") != true || view.Has("defaultLabel") || stringify(view.Get("notify")) != `{"emails":["a@acme.test"]}` {
		t.Fatalf("view = %s", stringify(view))
	}
	expectJSON(t, "view keys", view.Keys(), `["tenantId","inherited","name","definition","requireLabels","guestCeiling","interimAllowed","adjudication","notify","createdAt","createdBy","updatedAt","updatedBy","version"]`)
}
