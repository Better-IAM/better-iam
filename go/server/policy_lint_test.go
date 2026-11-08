package server

// Port of the `policy linter` tests of tests/policy-lint.test.ts (the `analysis.lintPolicy` API tests belong to the
// analysis module).

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

func lintDoc(statements ...*core.Object) *core.Object {
	list := make([]any, len(statements))
	for index, statement := range statements {
		list[index] = statement
	}
	return core.NewObject("version", 1.0, "statements", list)
}

func lintAllow(t *testing.T, extra string) *core.Object {
	t.Helper()
	statement := obj(t, `{"effect":"allow","actions":["documents:read"],"resources":["documents/*"]}`)
	if extra != "" {
		statement.Assign(obj(t, extra))
	}
	return statement
}

func lintDeny(t *testing.T, extra string) *core.Object {
	t.Helper()
	statement := lintAllow(t, extra)
	statement.Set("effect", "deny")
	if extra != "" {
		statement.Assign(obj(t, extra))
	}
	return statement
}

func lintRaw(t *testing.T, document any, context string) *core.Object {
	t.Helper()
	var options *core.Object
	if context != "" {
		options = obj(t, context)
	}
	result, err := LintPolicy(document, options)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func lintWarnings(t *testing.T, document any, context string) []*core.Object {
	t.Helper()
	list, _ := lintRaw(t, document, context).Get("warnings").([]any)
	warnings := make([]*core.Object, len(list))
	for index, item := range list {
		warnings[index] = item.(*core.Object)
	}
	return warnings
}

// lintCodes is `{statement}:{code}` for every warning, in the linter's order.
func lintCodes(t *testing.T, document any, context string) []string {
	t.Helper()
	codes := []string{}
	for _, warning := range lintWarnings(t, document, context) {
		codes = append(codes, jsString(warning.Get("statement"))+":"+jsString(warning.Get("code")))
	}
	return codes
}

func lintOnly(t *testing.T, code string, document any, context string) []*core.Object {
	t.Helper()
	result := []*core.Object{}
	for _, warning := range lintWarnings(t, document, context) {
		if warning.Get("code") == code {
			result = append(result, warning)
		}
	}
	return result
}

func expectCodes(t *testing.T, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("codes: got %q, want %q", got, want)
	}
}

func repeat(value string, count int) []any {
	list := make([]any, count)
	for index := range list {
		list[index] = value
	}
	return list
}

func TestPolicyLintAcceptsASoundDocument(t *testing.T) {
	result := lintRaw(t, lintDoc(
		lintAllow(t, `{"conditions":{
			"Bool":{"principal.mfa":true},
			"StringEquals":{"resource.ownerId":"${principal.id}","principal.kind":"user"},
			"ArrayContains":{"principal.groups":"writers","resource.relations":"editor"},
			"DateBefore":{"request.time":"2030-01-01T00:00:00Z"},
			"Exists":{"principal.authMethod":true}}}`),
		lintAllow(t, `{"actions":["documents:write"],"resources":["documents/${principal.id}/*"]}`),
	), "")
	if got := core.MustStringify(result); got != `{"valid":true,"warnings":[]}` {
		t.Fatalf("got %s", got)
	}
}

func TestPolicyLintReportsInvalidDocuments(t *testing.T) {
	invalid := lintRaw(t, obj(t, `{"version":2,"statements":[]}`), "")
	if invalid.Get("valid") != false || member(invalid.Get("error"), "code") != "INVALID_POLICY" ||
		len(invalid.Get("warnings").([]any)) != 0 {
		t.Fatalf("got %s", core.MustStringify(invalid))
	}
	if _, ok := member(invalid.Get("error"), "message").(string); !ok {
		t.Fatal("message missing")
	}
	if result := lintRaw(t, "not a policy", ""); result.Get("valid") != false || len(result.Get("warnings").([]any)) != 0 {
		t.Fatalf("got %s", core.MustStringify(result))
	}
	for _, document := range []any{
		lintDoc(lintAllow(t, `{"resources":["documents/${broken"]}`)),
		lintDoc(lintAllow(t, `{"conditions":{"Bool":{"principal.mfa":"yes"}}}`)),
	} {
		if result := lintRaw(t, document, ""); result.Get("valid") != false || member(result.Get("error"), "code") != "INVALID_POLICY" {
			t.Fatalf("got %s", core.MustStringify(result))
		}
	}
}

func TestPolicyLintFlagsUnrestrictedAdministrationAndServiceWildcards(t *testing.T) {
	expectCodes(t, lintCodes(t, lintDoc(obj(t, `{"effect":"allow","actions":["*"],"resources":["*"]}`)), ""), "0:unrestricted-admin")
	expectCodes(t, lintCodes(t, lintDoc(obj(t, `{"effect":"allow","actions":["iam:*"],"resources":["iam/*"]}`)), ""), "0:unrestricted-admin")
	warnings := lintWarnings(t, lintDoc(obj(t, `{"effect":"allow","actions":["*","documents:*"],"resources":["*"]}`)), "")
	if len(warnings) != 1 || warnings[0].Get("code") != "unrestricted-admin" || warnings[0].Get("severity") != "warning" {
		t.Fatalf("got %v", warnings)
	}
	// Conditions or scoped resources are not unrestricted.
	expectCodes(t, lintCodes(t, lintDoc(obj(t, `{"effect":"allow","actions":["*"],"resources":["*"],"conditions":{"Bool":{"principal.mfa":true}}}`)), ""))
	expectCodes(t, lintCodes(t, lintDoc(obj(t, `{"effect":"allow","actions":["*"],"resources":["documents/*"]}`)), ""))

	wildcard := lintWarnings(t, lintDoc(lintAllow(t, `{"actions":["documents:*","documents:read"]}`)), "")
	if len(wildcard) != 1 || wildcard[0].Get("code") != "service-wildcard" || wildcard[0].Get("severity") != "info" ||
		wildcard[0].Get("statement") != 0.0 || !strings.Contains(jsString(wildcard[0].Get("message")), "documents:*") {
		t.Fatalf("got %v", wildcard)
	}
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"actions":["documents:*"],"conditions":{"Bool":{"principal.mfa":true}}}`)), ""))
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"actions":["documents:re*"]}`)), ""))
}

func TestPolicyLintFlagsKeysTheServerNeverSets(t *testing.T) {
	ip := lintOnly(t, "unknown-context-key", lintDoc(lintAllow(t, `{"conditions":{"IpAddress":{"request.ip":"10.0.0.0/8"}}}`)), "")
	if len(ip) != 1 || ip[0].Get("severity") != "warning" || ip[0].Get("statement") != 0.0 ||
		!strings.Contains(jsString(ip[0].Get("message")), "request.ip is never set by the server; supply it with resolveContext") {
		t.Fatalf("got %v", ip)
	}
	// resource.type and resource.id do not exist even when any resource attribute is accepted.
	kind := lintOnly(t, "unknown-context-key", lintDoc(lintAllow(t, `{"conditions":{"StringEquals":{"resource.type":"document"}}}`)), "")
	if !strings.Contains(jsString(kind[0].Get("message")), "resource pattern") {
		t.Fatalf("got %v", kind)
	}
	// A variable naming an unknown key is reported once per statement, like a condition key.
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"resources":["documents/${principal.email}"],"conditions":{"StringEquals":{"principal.email":"a@b.test"}}}`)), ""),
		"0:unknown-context-key")

	department := lintDoc(lintAllow(t, `{"conditions":{"StringEquals":{"principal.department":"x"}}}`))
	expectCodes(t, lintCodes(t, department, ""), "0:unknown-context-key")
	expectCodes(t, lintCodes(t, department, `{"identityAttributes":{"department":"string"}}`))
	expectCodes(t, lintCodes(t, department, `{"contextKeys":["principal.department"]}`))

	resource := lintDoc(lintAllow(t, `{"conditions":{"StringEquals":{"resource.classification":"secret","resource.ownerId":"x"}}}`))
	// Without a resource attribute list any resource attribute is accepted.
	expectCodes(t, lintCodes(t, resource, ""))
	expectCodes(t, lintCodes(t, resource, `{"resourceAttributes":["classification"]}`))
	unknown := lintOnly(t, "unknown-context-key", resource, `{"resourceAttributes":["size"]}`)
	if len(unknown) != 1 || !strings.Contains(jsString(unknown[0].Get("message")), "resource.classification") {
		t.Fatalf("got %v", unknown)
	}
}

func TestPolicyLintFlagsDeniesThatSilentlyNeverApply(t *testing.T) {
	context := `{"identityAttributes":{"department":"string"}}`
	risky := func() *core.Object {
		return lintDeny(t, `{"conditions":{"StringNotEquals":{"principal.department":"finance"}}}`)
	}
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, ""), risky()), context), "1:optional-key-deny")
	if message := jsString(lintOnly(t, "optional-key-deny", lintDoc(lintAllow(t, ""), risky()), context)[0].Get("message")); !strings.Contains(message, `Exists { "principal.department": false }`) {
		t.Fatalf("got %s", message)
	}
	// Sign-in method and resource attributes are optional too.
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, ""), lintDeny(t, `{"conditions":{"StringEquals":{"principal.authMethod":"password","resource.ownerId":"x"}}}`)), ""),
		"1:optional-key-deny", "1:optional-key-deny")
	// An Exists test in the statement, a deny for the missing case, always-present keys, and allows are fine.
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, ""), lintDeny(t, `{"conditions":{"StringNotEquals":{"principal.department":"finance"},"Exists":{"principal.department":true}}}`)), context))
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, ""), risky(), lintDeny(t, `{"conditions":{"Exists":{"principal.department":false}}}`)), context))
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, ""), lintDeny(t, `{"conditions":{"Bool":{"principal.mfa":false}}}`)), ""))
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"StringEquals":{"principal.department":"finance"}}}`)), context))
}

func TestPolicyLintAcceptsAMissingKeyDenyOnlyWhenItCovers(t *testing.T) {
	context := `{"identityAttributes":{"department":"string"}}`
	risky := func() *core.Object {
		return lintDeny(t, `{"actions":["documents:delete","documents:write"],"resources":["documents/a","documents/b/1"],"conditions":{"StringNotEquals":{"principal.department":"finance"}}}`)
	}
	absent := func(extra string) *core.Object {
		statement := lintDeny(t, `{"conditions":{"Exists":{"principal.department":false}}}`)
		if extra != "" {
			statement.Assign(obj(t, extra))
		}
		return statement
	}
	// Wildcards covering every action and resource make the risky deny safe.
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, ""), risky(), absent(`{"actions":["documents:*"],"resources":["*"]}`)), context))
	expectCodes(t, lintCodes(t, lintDoc(absent(`{"actions":["documents:delete","documents:wr*"],"resources":["documents/a","documents/b/*"]}`), lintAllow(t, ""), risky()), context))
	// A deny with further conditions only applies to some of the requests missing the key.
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, ""), risky(), lintDeny(t, `{"actions":["*"],"resources":["*"],"conditions":{"Exists":{"principal.department":false},"Bool":{"principal.mfa":false}}}`)), context),
		"1:optional-key-deny")
	// An unrelated action, a narrower resource, or another key leaves the risky deny open.
	for _, other := range []*core.Object{
		absent(`{"actions":["iam:policies:create"],"resources":["*"]}`),
		absent(`{"actions":["documents:*"],"resources":["documents/archive"]}`),
		absent(`{"actions":["documents:*"],"resources":["documents/b/*"]}`),
		lintDeny(t, `{"actions":["*"],"resources":["*"],"conditions":{"Exists":{"principal.authMethod":false}}}`),
	} {
		expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, ""), risky(), other), context), "1:optional-key-deny")
	}
	// Covering the actions and the resources through two different denies is not enough either.
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, ""), risky(),
		absent(`{"actions":["documents:*"],"resources":["documents/a"]}`),
		absent(`{"actions":["documents:delete"],"resources":["*"]}`)), context), "1:optional-key-deny")
}

func TestPolicyLintFlagsNegatedOperatorsWithMissingVariables(t *testing.T) {
	context := `{"identityAttributes":{"department":"string"}}`
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"StringNotEquals":{"resource.department":"${principal.department}"}}}`)), context), "0:negated-variable")
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"StringNotLike":{"resource.ownerId":"x-${resource.team}"}}}`)), ""), "0:negated-variable")
	// Always-present keys, an Exists guard, and positive operators are fine.
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"StringNotEquals":{"resource.ownerId":"${principal.id}"}}}`)), ""))
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"StringNotEquals":{"resource.department":"${principal.department}"},"Exists":{"principal.department":true}}}`)), context))
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"StringEquals":{"resource.department":"${principal.department}"}}}`)), context))
}

func TestPolicyLintFlagsIgnoreCaseVariablesWithCapitals(t *testing.T) {
	context := `{"identityAttributes":{"costCenter":"string","team":"string"}}`
	risky := lintOnly(t, "ignorecase-variable", lintDoc(lintAllow(t, `{"conditions":{"StringLikeIgnoreCase":{"resource.name":"${principal.costCenter}-*"}}}`)), context)
	if len(risky) != 1 || risky[0].Get("severity") != "warning" || !strings.Contains(jsString(risky[0].Get("message")), "${principal.costcenter}") {
		t.Fatalf("got %v", risky)
	}
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"StringLike":{"resource.name":"${principal.costCenter}-*"}}}`)), context))
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"StringLikeIgnoreCase":{"resource.name":"${principal.team}-*"}}}`)), context))
}

func TestPolicyLintFlagsListKeys(t *testing.T) {
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"StringEquals":{"principal.groups":"admins"}}}`)), ""), "0:array-key-string-operator")
	// A list key with Bool is a list problem, not a type mismatch.
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"Bool":{"resource.relations":true}}}`)), ""), "0:array-key-string-operator")
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"ArrayContains":{"principal.groups":"admins"},"ArrayContainsAll":{"principal.roles":["a","b"]},"Exists":{"resource.parentRelations":true}}}`)), ""))
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"resources":["documents/${principal.groups}"]}`)), ""), "0:array-variable")
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"StringEquals":{"resource.ownerId":"${principal.roles}"}}}`)), ""), "0:array-variable")
}

func TestPolicyLintFlagsTypeMismatches(t *testing.T) {
	mismatches := func(conditions string, context string) []string {
		messages := []string{}
		for _, warning := range lintOnly(t, "type-mismatch", lintDoc(lintAllow(t, `{"conditions":`+conditions+`}`)), context) {
			messages = append(messages, jsString(warning.Get("message")))
		}
		return messages
	}
	expectCodes(t, mismatches(`{"Bool":{"principal.id":true}}`, ""), "Bool never matches principal.id, which holds a string.")
	expectCodes(t, mismatches(`{"StringEquals":{"principal.mfa":"true"}}`, ""), "StringEquals never matches principal.mfa, which is a boolean; use Bool.")
	for _, conditions := range []string{
		`{"NumericEquals":{"principal.kind":1}}`,
		`{"DateAfter":{"principal.id":"2024-01-01T00:00:00Z"}}`,
		`{"ArrayContains":{"principal.kind":"user"}}`,
	} {
		if got := mismatches(conditions, ""); len(got) != 1 {
			t.Fatalf("%s: got %q", conditions, got)
		}
	}
	expectCodes(t, mismatches(`{"DateAfter":{"request.time":"2024-01-01T00:00:00Z"}}`, ""))
	// Unknown keys have no known type.
	expectCodes(t, mismatches(`{"DateAfter":{"session.expires":"2024-01-01T00:00:00Z"}}`, `{"contextKeys":["session.expires"]}`))
	// Identity attributes follow their declared types.
	attributes := `{"identityAttributes":{"level":"number","contractor":"boolean","hiredAt":"string"}}`
	expectCodes(t, mismatches(`{"NumericGreaterThan":{"principal.level":2},"Bool":{"principal.contractor":false},"DateBefore":{"principal.hiredAt":"2024-01-01T00:00:00Z"}}`, attributes))
	expectCodes(t, mismatches(`{"StringEquals":{"principal.level":"2"},"NumericEquals":{"principal.contractor":1}}`, attributes),
		"NumericEquals never matches principal.contractor, which is a boolean; use Bool.",
		"StringEquals never matches principal.level, which is a number; use a Numeric operator.")
}

func TestPolicyLintNotesAlwaysTrueConditionsAndDuplicates(t *testing.T) {
	warnings := lintWarnings(t, lintDoc(lintAllow(t, `{"conditions":{"Bool":{"principal.mfa":[true,false]},"Exists":{"resource.ownerId":[false,true]}}}`)), "")
	if len(warnings) != 2 {
		t.Fatalf("got %v", warnings)
	}
	for _, warning := range warnings {
		if warning.Get("code") != "always-true-condition" || warning.Get("severity") != "info" {
			t.Fatalf("got %v", warning)
		}
	}
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"conditions":{"Bool":{"principal.mfa":true}}}`)), ""))

	first := lintAllow(t, `{"sid":"Read","actions":["documents:read","documents:write"],"conditions":{"StringEquals":{"principal.kind":["user","service"]}}}`)
	same := lintAllow(t, `{"sid":"ReadAgain","actions":["documents:write","documents:read"],"conditions":{"StringEquals":{"principal.kind":["service","user"]}}}`)
	duplicate := lintWarnings(t, lintDoc(first, same), "")
	if len(duplicate) != 1 || duplicate[0].Get("code") != "duplicate-statement" || duplicate[0].Get("statement") != 1.0 ||
		duplicate[0].Get("sid") != "ReadAgain" || !strings.Contains(jsString(duplicate[0].Get("message")), "statement 0 (Read)") {
		t.Fatalf("got %v", duplicate)
	}
	expectCodes(t, lintCodes(t, lintDoc(first, lintAllow(t, `{"actions":["documents:read","documents:write"],"conditions":{"StringEquals":{"principal.kind":"user"}}}`)), ""))
}

func TestPolicyLintFlagsShadowedAllows(t *testing.T) {
	expectCodes(t, lintCodes(t, lintDoc(
		lintAllow(t, `{"resources":["documents/1","documents/team-*"]}`),
		lintDeny(t, `{"actions":["documents:*"],"resources":["documents/*"]}`),
	), ""), "0:shadowed-allow")
	// Earlier denies count too, and several denies may cover one allow together.
	split := lintWarnings(t, lintDoc(
		lintDeny(t, `{"actions":["documents:read"],"resources":["*"]}`),
		lintDeny(t, `{"actions":["documents:write"],"resources":["*"]}`),
		lintAllow(t, `{"actions":["documents:read","documents:write"]}`),
	), "")
	if len(split) != 1 || split[0].Get("code") != "shadowed-allow" || split[0].Get("statement") != 2.0 ||
		!strings.Contains(jsString(split[0].Get("message")), "statement 0, 1") {
		t.Fatalf("got %v", split)
	}
	// Conditional denies, partial coverage, and wider allow patterns are not shadowed.
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, ""), lintDeny(t, `{"resources":["*"],"conditions":{"Bool":{"principal.mfa":false}}}`)), ""))
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"resources":["documents/1","reports/1"]}`), lintDeny(t, `{"resources":["documents/*"]}`)), ""))
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, `{"resources":["doc*"]}`), lintDeny(t, `{"resources":["documents/*"]}`)), ""))
}

func TestPolicyLintBoundsTheShadowCheck(t *testing.T) {
	timed := func(document any) ([]*core.Object, time.Duration) {
		started := time.Now()
		warnings := lintWarnings(t, document, "")
		return warnings, time.Since(started)
	}
	// Repeated patterns: once took over a minute; each distinct value is now resolved once.
	var statements []*core.Object
	for range 29 {
		statements = append(statements, lintAllow(t, "").Set("actions", repeat("x", 128)).Set("resources", repeat("x", 128)))
	}
	for range 58 {
		statements = append(statements, lintDeny(t, `{"resources":["*"]}`).Set("actions", repeat("y", 128)))
	}
	statements = append(statements, lintDeny(t, `{"actions":["*"],"resources":["*"]}`))
	repeated, elapsed := timed(lintDoc(statements...))
	if elapsed > time.Second {
		t.Fatalf("repeated patterns took %v", elapsed)
	}
	var shadowed []*core.Object
	for _, warning := range repeated {
		if warning.Get("code") == "shadowed-allow" {
			shadowed = append(shadowed, warning)
		}
	}
	if len(shadowed) != 29 || !strings.Contains(jsString(shadowed[0].Get("message")), "(statement 87)") {
		t.Fatalf("got %d shadowed: %v", len(shadowed), shadowed)
	}

	// Distinct literal values against distinct wildcards exhaust the budget: the rest of the check is skipped.
	statements = nil
	for i := range 64 {
		actions := make([]any, 128)
		for j := range actions {
			actions[j] = fmt.Sprintf("a%d-%d", i, j)
		}
		statements = append(statements, lintAllow(t, "").Set("actions", actions))
	}
	for i := range 64 {
		actions := make([]any, 128)
		for j := range actions {
			actions[j] = fmt.Sprintf("?%d.%d*z", i, j)
		}
		statements = append(statements, lintDeny(t, `{"resources":["*"]}`).Set("actions", actions))
	}
	distinct, elapsed := timed(lintDoc(statements...))
	if elapsed > time.Second {
		t.Fatalf("distinct patterns took %v", elapsed)
	}
	if len(distinct) != 1 || distinct[0].Get("code") != "shadowed-allow-skipped" || distinct[0].Get("severity") != "info" ||
		distinct[0].Get("statement") != -1.0 {
		t.Fatalf("got %v", distinct)
	}

	// Many patterns that do not interact are still checked in full.
	statements = nil
	for i := range 100 {
		actions := make([]any, 10)
		for j := range actions {
			actions[j] = fmt.Sprintf("service%d:action%d", i, j)
		}
		statements = append(statements, lintAllow(t, "").Set("actions", actions).Set("resources", []any{fmt.Sprintf("service%d/*", i)}))
	}
	for i := range 20 {
		statements = append(statements, lintDeny(t, "").
			Set("actions", []any{fmt.Sprintf("*:dangerous%d", i), fmt.Sprintf("service%d:*", i)}).
			Set("resources", []any{fmt.Sprintf("service%d/*", i)}))
	}
	want := make([]string, 20)
	for i := range want {
		want[i] = fmt.Sprintf("%d:shadowed-allow", i)
	}
	expectCodes(t, lintCodes(t, lintDoc(statements...), ""), want...)
}

func TestPolicyLintNotesDenyOnlyDocumentsAndOrdersWarnings(t *testing.T) {
	expectCodes(t, lintCodes(t, lintDoc(lintDeny(t, "")), ""), "-1:deny-only")
	empty := lintWarnings(t, lintDoc(), "")
	if len(empty) != 1 || empty[0].Get("code") != "deny-only" || empty[0].Get("severity") != "info" || empty[0].Get("statement") != -1.0 {
		t.Fatalf("got %v", empty)
	}
	expectCodes(t, lintCodes(t, lintDoc(lintAllow(t, ""), lintDeny(t, "")), ""), "0:shadowed-allow")

	ordered := lintWarnings(t, lintDoc(
		lintAllow(t, `{"sid":"First","conditions":{"StringEquals":{"principal.groups":"x"}}}`),
		obj(t, `{"effect":"allow","actions":["*"],"resources":["*"]}`),
		lintAllow(t, `{"conditions":{"IpAddress":{"request.ip":"10.0.0.0/8"},"Bool":{"principal.id":true}}}`),
	), "")
	var got []string
	for _, warning := range ordered {
		got = append(got, jsString(warning.Get("statement"))+":"+jsString(warning.Get("code")))
	}
	expectCodes(t, got, "0:array-key-string-operator", "1:unrestricted-admin", "2:type-mismatch", "2:unknown-context-key")
	if ordered[0].Get("sid") != "First" || ordered[1].Has("sid") {
		t.Fatalf("sids: %v %v", ordered[0], ordered[1])
	}
}
