package server

// Tests of package_rules.go, ported from tests/guests-policies.test.ts ("knows identity.guest in the rule
// language") and tests/session-key-registries.test.ts ("package rules refuse session-scoped keys and session tags"),
// plus the validation, warning and mapping rules of package-rules.ts at the module level (the access package API
// that drives them belongs to another unit).

import (
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func ruleEnv(t *testing.T, text string) *core.Object { return obj(t, text) }

func TestPackageRulesRefuseSessionScopedKeysAndSessionTags(t *testing.T) {
	env := ruleEnv(t, `{"identityAttributes":{"department":"string"}}`)
	for _, key := range []string{
		"principal.sessionName",
		"principal.sessionId",
		"principal.tokenIssueTime",
		"principal.mfaTime",
		"principal.sessionTagKeys",
		"principal.sourceIdentity",
		"principal.sessionTags.team",
	} {
		rule := core.NewObject("include", []any{core.NewObject("StringEquals", core.NewObject(key, "x"))})
		_, err := ParseAutoAssign(rule, env, "")
		expectContains(t, err, key+" describes a session or grant and is not available to package rules")
	}
	// Identity keys still work.
	parsed, err := ParseAutoAssign(obj(t, `{"include":[{"StringEquals":{"principal.department":"eng"}}]}`), env, "")
	if err != nil {
		t.Fatal(err)
	}
	if include, _ := parsed.Get("include").([]any); len(include) != 1 {
		t.Fatalf("include: %v", parsed.Get("include"))
	}
}

func TestRuleLanguageKnowsIdentityGuest(t *testing.T) {
	keys := must(RuleKeys(core.NewObject(), nil))
	found := false
	for _, key := range keys {
		if key.Get("key") == "identity.guest" {
			found = true
			if got := core.MustStringify(key); got != `{"key":"identity.guest","type":"boolean","operators":["Bool","Exists"]}` {
				t.Fatalf("identity.guest key: %s", got)
			}
		}
	}
	if !found {
		t.Fatal("identity.guest is not a rule key")
	}
	empty := ruleEnv(t, `{"identityAttributes":{}}`)
	_, err := ParseAutoAssign(obj(t, `{"include":[{"StringEquals":{"identity.guest":"true"}}]}`), empty, "")
	expectContains(t, err, "StringEquals cannot test identity.guest (boolean); use Bool, Exists")
	_, err = ParseAutoAssign(obj(t, `{"include":[{"Bool":{"identity.visitor":true}}]}`), empty, "")
	expectContains(t, err, "identity.guest")
	person := obj(t, `{"id":"usr_1","tenantId":"t","kind":"user","name":"Gina","email":"gina@partner.test","emailVerified":true,"status":"active","owner":false,"rootAdmin":false,"createdAt":0}`)
	guest := person.Spread(core.NewObject("guest", obj(t, `{"sponsorId":"usr_2","since":0}`)))
	if must(RuleContext(guest, []string{}, nil)).Get("identity.guest") != true {
		t.Fatal("a guest's context says identity.guest false")
	}
	if must(RuleContext(person, []string{}, nil)).Get("identity.guest") != false {
		t.Fatal("a member's context says identity.guest true")
	}
	members := must(RuleDocument(obj(t, `{"include":[{"StringEquals":{"principal.kind":"user"}}]}`)))
	if must(RuleMatch(members, person, must(RuleContext(person, []string{}, nil)))).Get("matched") != true {
		t.Fatal("members rule does not match the member")
	}
	if got := core.MustStringify(must(RuleMatch(members, guest, must(RuleContext(guest, []string{}, nil))))); got != `{"matched":false,"matchedBy":[],"excludedBy":[]}` {
		t.Fatalf("members rule for the guest: %s", got)
	}
	guests := must(RuleDocument(obj(t, `{"include":[{"StringEquals":{"principal.kind":"user"},"Bool":{"identity.guest":true}}]}`)))
	if got := core.MustStringify(must(RuleMatch(guests, guest, must(RuleContext(guest, []string{}, nil))))); got != `{"matched":true,"matchedBy":["include-0"],"excludedBy":[]}` {
		t.Fatalf("guests rule for the guest: %s", got)
	}
	if must(RuleMatch(guests, person, must(RuleContext(person, []string{}, nil)))).Get("matched") != false {
		t.Fatal("guests rule matches the member")
	}
	warnings := must(RuleWarnings(obj(t, `{"include":[{"StringEquals":{"principal.kind":"user"}}]}`), nil))
	if strings.Contains(strings.Join(warnings, " "), "identity.guest") {
		t.Fatalf("warnings mention identity.guest: %v", warnings)
	}
}

func TestParseAutoAssignValidation(t *testing.T) {
	env := ruleEnv(t, `{"identityAttributes":{"level":"number","department":"string"},"groups":["g-eng","g-ops","g-pkg"],"packagedGroups":["g-pkg"]}`)
	cases := []struct {
		rule, code, message string
	}{
		{`[]`, "INVALID_INPUT", "autoAssign must be an object"},
		{`{"include":[],"extra":1}`, "INVALID_INPUT", "autoAssign: unknown field extra"},
		{`{"include":[]}`, "INVALID_INPUT", "autoAssign.include must list 1-10 condition sets"},
		{`{"include":[{"Bool":{"principal.owner":true}}],"exclude":{}}`, "INVALID_INPUT", "autoAssign.exclude must list at most 10 condition sets"},
		{`{"include":[{}]}`, "INVALID_INPUT", "autoAssign.include[0] must be a nonempty condition set"},
		{`{"include":[{"Bogus":{"principal.id":"x"}}]}`, "INVALID_POLICY", "autoAssign.include[0]: Unknown operator or invalid condition attributes"},
		{`{"include":[{"ArrayContains":{"principal.groups":"g-eng"}}]}`, "INVALID_INPUT", "autoAssign.include[0]: use identity.groups (memberships not created by access packages) instead of principal.groups"},
		{`{"include":[{"Bool":{"principal.mfa":true}}]}`, "INVALID_INPUT", "autoAssign.include[0]: principal.mfa describes a session or grant and is not available to package rules"},
		{`{"include":[{"ArrayContains":{"identity.teams":"t1"}}]}`, "INVALID_INPUT", "autoAssign.include[0]: identity.teams is available to access package rules only"},
		{`{"include":[{"StringEquals":{"principal.region":"eu"}}]}`, "INVALID_INPUT", "autoAssign.include[0]: unknown key principal.region; use principal.id, principal.kind, principal.owner, identity.email, identity.emailDomain, identity.emailVerified, identity.managerId, identity.groups, identity.guest, or principal.<declared attribute> (department, level)"},
		{`{"include":[{"StringEquals":{"principal.level":"3"}}]}`, "INVALID_INPUT", "autoAssign.include[0]: StringEquals cannot test principal.level (number); use NumericEquals, NumericNotEquals, NumericLessThan, NumericLessThanEquals, NumericGreaterThan, NumericGreaterThanEquals, Exists"},
		{`{"include":[{"StringEquals":{"principal.department":"${principal.id}"}}]}`, "INVALID_INPUT", "autoAssign.include[0]: policy variables are not available in package rules"},
		{`{"include":[{"StringEquals":{"principal.kind":"robot"}}]}`, "INVALID_INPUT", "autoAssign.include[0]: principal.kind is 'user' or 'service'"},
		{`{"include":[{"ArrayContains":{"identity.groups":"g-nope"}}]}`, "INVALID_INPUT", "autoAssign.include[0]: unknown group g-nope"},
		{`{"include":[{"Bool":{"principal.owner":true}}],"exclude":[{"ArrayContains":{"identity.groups":"g-pkg"}}]}`, "INVALID_INPUT", "autoAssign.exclude[0]: identity.groups cannot name g-pkg, a group this package grants"},
		{`{"include":[{"Bool":{"principal.owner":true}}],"graceMs":-1}`, "INVALID_INPUT", "Invalid autoAssign.graceMs"},
		{`{"include":[{"Bool":{"principal.owner":true}}],"maxGrants":0}`, "INVALID_INPUT", "Invalid autoAssign.maxGrants"},
		{`{"include":[{"Bool":{"principal.owner":true}}],"maxRemovals":100001}`, "INVALID_INPUT", "Invalid autoAssign.maxRemovals"},
	}
	for _, c := range cases {
		_, err := ParseAutoAssign(parse(t, c.rule), env, "")
		if strings.HasSuffix(c.message, ": ") {
			expectErrorPrefix(t, err, c.code, c.message)
			continue
		}
		expectError(t, err, c.code, c.message)
	}
	// Org keys with the org environment: values are checked against the known teams, departments and licenses.
	org := ruleEnv(t, `{"identityAttributes":{},"org":{"teams":["t1"],"departments":["d1"],"licenses":["figma"]}}`)
	if _, err := ParseAutoAssign(obj(t, `{"include":[{"ArrayContains":{"identity.teams":"t1","identity.departments":["d1"],"identity.licenses":"figma"}}]}`), org, "packages[0].autoAssign"); err != nil {
		t.Fatal(err)
	}
	_, err := ParseAutoAssign(obj(t, `{"include":[{"ArrayContains":{"identity.teams":"t2"}}]}`), org, "packages[0].autoAssign")
	expectError(t, err, "INVALID_INPUT", "packages[0].autoAssign.include[0]: unknown team t2")
	_, err = ParseAutoAssign(obj(t, `{"include":[{"ArrayContains":{"identity.departments":5}}]}`), org, "")
	expectError(t, err, "INVALID_INPUT", "autoAssign.include[0]: identity.departments lists departments")
	_, err = ParseAutoAssign(obj(t, `{"include":[{"StringEquals":{"principal.x":"y"}}]}`), org, "")
	expectError(t, err, "INVALID_INPUT", "autoAssign.include[0]: unknown key principal.x; use principal.id, principal.kind, principal.owner, identity.email, identity.emailDomain, identity.emailVerified, identity.managerId, identity.groups, identity.guest, identity.teams, identity.departments, identity.licenses, or principal.<declared attribute> (none declared)")
	// Size limit.
	values := []any{}
	for index := 0; index < 20; index++ {
		values = append(values, strings.Repeat("x", 99)+string(rune('a'+index)))
	}
	clauses := []any{}
	for index := 0; index < 10; index++ {
		clauses = append(clauses, core.NewObject("StringEquals", core.NewObject("principal.department", values)))
	}
	_, err = ParseAutoAssign(core.NewObject("include", clauses), env, "")
	expectError(t, err, "INVALID_INPUT", "autoAssign is larger than 16384 bytes")
	// A zero grace period is dropped; limits stay; values keep their scalar or array form.
	parsed, err := ParseAutoAssign(obj(t, `{"maxRemovals":3,"include":[{"StringEquals":{"principal.kind":["User"]}}],"graceMs":0,"maxGrants":5,"exclude":[]}`), env, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := core.MustStringify(parsed); got != `{"include":[{"StringEquals":{"principal.kind":["User"]}}],"maxGrants":5,"maxRemovals":3}` {
		t.Fatalf("parsed: %s", got)
	}
	if problem := must(RuleProblem(obj(t, `{"include":[{"StringEquals":{"principal.gone":"x"}}],"ownerId":"o","revision":1}`), env)); !strings.HasPrefix(problem, "autoAssign.include[0]: unknown key principal.gone") {
		t.Fatalf("problem: %q", problem)
	}
	if problem := must(RuleProblem(parsed.Spread(core.NewObject("ownerId", "o", "approved", core.NewObject("grants", 1.0))), env)); problem != "" {
		t.Fatalf("a valid rule has a problem: %q", problem)
	}
}

func TestRuleContextAndInput(t *testing.T) {
	alice := obj(t, `{"id":"usr_a","kind":"user","owner":false,"email":"Alice@Example.COM","emailVerified":false,"managerId":"usr_m","attributes":{"department":"eng","id":"spoof"}}`)
	context := must(RuleContext(alice, []string{"g2", "g1", "g2"}, obj(t, `{"teams":["t2","t1"],"departments":["d"]}`)))
	if got := core.MustStringify(context); got != `{"principal.department":"eng","principal.id":"usr_a","principal.kind":"user","principal.owner":false,"identity.email":"alice@example.com","identity.emailDomain":"example.com","identity.emailVerified":false,"identity.managerId":"usr_m","identity.groups":["g1","g2"],"identity.guest":false,"identity.teams":["t1","t2"],"identity.departments":["d"],"identity.licenses":[]}` {
		t.Fatalf("context: %s", got)
	}
	input := must(RuleInput(obj(t, `{"include":[{"Bool":{"principal.owner":true}}],"exclude":[],"graceMs":0,"maxGrants":7,"ownerId":"o","authorityId":"a","revision":2,"updatedAt":5}`)))
	if got := core.MustStringify(input); got != `{"include":[{"Bool":{"principal.owner":true}}],"maxGrants":7}` {
		t.Fatalf("rule input: %s", got)
	}
	same := must(SameRuleInput(obj(t, `{"include":[{"Bool":{"principal.owner":true}}],"maxGrants":7,"revision":9}`), input))
	if !same {
		t.Fatal("rules that say the same thing differ")
	}
	document := must(RuleDocument(obj(t, `{"include":[{"Bool":{"principal.owner":true}}],"exclude":[{"Bool":{"identity.emailVerified":false}}]}`)))
	if got := core.MustStringify(document); got != `{"version":1,"statements":[{"sid":"include-0","effect":"allow","actions":["auto-assign"],"resources":["identity/*"],"conditions":{"Bool":{"principal.owner":true}}},{"sid":"exclude-0","effect":"deny","actions":["auto-assign"],"resources":["identity/*"],"conditions":{"Bool":{"identity.emailVerified":false}}}]}` {
		t.Fatalf("document: %s", got)
	}
	owner := obj(t, `{"id":"usr_o","kind":"user","owner":true,"emailVerified":false}`)
	match := must(RuleMatch(document, owner, must(RuleContext(owner, nil, nil))))
	if got := core.MustStringify(match); got != `{"matched":false,"matchedBy":["include-0"],"excludedBy":["exclude-0"]}` {
		t.Fatalf("excluded match: %s", got)
	}
}

func TestRuleWarnings(t *testing.T) {
	rule := obj(t, `{
		"include":[
			{"StringEquals":{"identity.emailDomain":"example.com","principal.department":"eng"},"ArrayContains":{"identity.groups":["g-free","g-bound"],"identity.licenses":"figma"}},
			{"StringEquals":{"principal.kind":"user"},"Bool":{"identity.emailVerified":true,"identity.guest":false},"StringLike":{"identity.email":"*@example.com"}}
		],
		"exclude":[{"StringEquals":{"identity.managerId":"usr_m"}}]
	}`)
	warnings := must(RuleWarnings(rule, core.NewObject("boundGroups", []any{"g-bound"})))
	want := []string{
		"include[0] does not test identity.guest while the rule does elsewhere, so it also matches guests",
		"include[0] does not test principal.kind, so it also matches service accounts",
		"include[0] tests an email address without requiring Bool identity.emailVerified: true, so unverified addresses match (SCIM-provisioned and administrator-set addresses are unverified)",
		"include[0] tests principal.department, which anyone holding iam:identities:update can set, so they choose who receives this package under its owner’s authority",
		"include[0] tests identity.groups for g-free, a group without role bindings whose members anyone holding iam:groups:update can change, so they choose who receives this package under its owner’s authority",
		"include[0] tests identity.licenses, which anyone holding iam:licenses:assign can change, as can whoever manages the members of a group a product is assigned to without it (a team's maintainers, directory sync), so they choose who receives this package under its owner’s authority",
		"exclude[0] tests identity.managerId, which anyone holding iam:identities:update can set, so they can lift the exclusion",
	}
	if strings.Join(warnings, "\n") != strings.Join(want, "\n") {
		t.Fatalf("warnings:\n%s", strings.Join(warnings, "\n"))
	}
	// Without boundGroups, groups are not checked; an empty set marks every tested group unbound.
	if got := must(RuleWarnings(rule, nil)); len(got) != len(want)-1 {
		t.Fatalf("warnings without boundGroups: %v", got)
	}
	got := must(RuleWarnings(obj(t, `{"include":[{"StringEquals":{"principal.kind":"user"},"ArrayContains":{"identity.groups":["a","b"]}}]}`), core.NewObject("boundGroups", []any{})))
	if len(got) != 1 || !strings.Contains(got[0], "tests identity.groups for a, b, groups without role bindings") {
		t.Fatalf("unbound groups: %v", got)
	}
}

func TestRuleValuesAndMapping(t *testing.T) {
	rule := obj(t, `{"include":[{"ArrayContains":{"identity.groups":["g1",3,"g2"]},"StringEquals":{"identity.groups":"ignored"}}],"exclude":[{"ArrayContainsAll":{"identity.groups":"g1","identity.teams":"t1"}}],"ownerId":"o"}`)
	if got := strings.Join(must(RuleGroupIDs(rule)), ","); got != "g1,g2" {
		t.Fatalf("group IDs: %s", got)
	}
	if got := strings.Join(must(RuleValues(rule, "identity.teams")), ","); got != "t1" {
		t.Fatalf("teams: %s", got)
	}
	if got := must(RuleValues(nil, "identity.groups")); len(got) != 0 {
		t.Fatalf("nil rule: %v", got)
	}
	mapped := must(MapRuleGroups(rule, func(value string) string { return "name-" + value })).(*core.Object)
	if got := core.MustStringify(mapped); got != `{"include":[{"ArrayContains":{"identity.groups":["name-g1",3,"name-g2"]},"StringEquals":{"identity.groups":"ignored"}}],"exclude":[{"ArrayContainsAll":{"identity.groups":"name-g1","identity.teams":"t1"}}],"ownerId":"o"}` {
		t.Fatalf("mapped: %s", got)
	}
	// The original is untouched.
	if got := strings.Join(must(RuleGroupIDs(rule)), ","); got != "g1,g2" {
		t.Fatalf("original changed: %s", got)
	}
}
