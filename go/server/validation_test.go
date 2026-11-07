package server

// Tests for validation.go, utils.go (with the server cases of spec/vectors/tokens.json and the assertionKey cases of
// spec/vectors/derivations.json), tenant-policy.ts, access-policy.ts, context-keys.ts, session-kinds.ts, plugins.ts
// and client-info.ts.

import (
	"context"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

func TestValidators(t *testing.T) {
	for _, bad := range []any{nil, core.Undefined, 1.0, "", "   ", "a\x01", strings.Repeat("x", 257)} {
		_, err := Text(bad, "name")
		expectError(t, err, "INVALID_INPUT", "Invalid name")
	}
	if got := must(Text("ok", "name")); got != "ok" {
		t.Fatal(got)
	}
	if _, err := Text(strings.Repeat("é", 10), "name", 9); err == nil {
		t.Fatal("max length counts UTF-16 units")
	}
	if got := must(Email("  Ada@Example.COM ")); got != "ada@example.com" {
		t.Fatal(got)
	}
	for _, bad := range []string{"ada", "ada@example", "a da@example.com", "ada@exa mple.com", "@example.com"} {
		_, err := Email(bad)
		expectError(t, err, "INVALID_INPUT", "Invalid email")
	}
	for _, bad := range []any{nil, []any{}, "x", 1.0} {
		_, err := Object(bad)
		expectError(t, err, "INVALID_INPUT", "Expected an object")
	}
	for _, bad := range []any{"1", 1.5, 0.0, 11.0, 9007199254740992.0} {
		_, err := Integer(bad, "count", 1, 10)
		expectError(t, err, "INVALID_INPUT", "Invalid count")
	}
	if got := must(Integer(10, "count", 1, 10)); got != 10 {
		t.Fatal(got)
	}
	if got := must(Strings([]any{"a", "b"}, "list")); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatal(got)
	}
	_, err := Strings(make([]any, 101), "list")
	expectError(t, err, "INVALID_INPUT", "Invalid list")
	_, err = Strings([]any{"a", 1.0}, "list")
	expectError(t, err, "INVALID_INPUT", "Invalid list")
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func TestUtilsVectors(t *testing.T) {
	file := spectest.Load(t, "tokens")
	ran := 0
	for _, c := range file.Cases {
		switch {
		case c.Name == "server id":
			want, _ := c.Output.(string)
			if !uuidPattern.MatchString(want) || !uuidPattern.MatchString(ID()) {
				t.Fatalf("server id format: %s / %s", want, ID())
			}
		case c.Name == "server token":
			want, _ := c.Output.(string)
			if !tokenPattern.MatchString(want) || !tokenPattern.MatchString(Token()) {
				t.Fatalf("server token format: %s / %s", want, Token())
			}
		case strings.HasPrefix(c.Name, "sameHash"):
			spectest.Check(t, c, SameHash(c.Input.Get("a"), c.Input.Get("b")))
		default:
			continue
		}
		ran++
	}
	if ran != 5 {
		t.Fatalf("ran %d server token cases", ran)
	}
	derivations := spectest.Load(t, "derivations")
	ran = 0
	for _, c := range derivations.Cases {
		if strings.HasPrefix(c.Name, "assertionKey") {
			secret, _ := c.Input.String("secret")
			spectest.Check(t, c, AssertionKey(secret))
			ran++
		}
	}
	if ran != 3 {
		t.Fatalf("ran %d assertionKey cases", ran)
	}
	if SameHash("abc", 1.0) || SameHash(nil, "abc") {
		t.Fatal("non-strings never match")
	}
	if Hash("token") != "3c469e9d6c5875d37a43f353d4f88e61fcf812c66eee3457465a40b0da4153e0" {
		t.Fatal(Hash("token"))
	}
}

func TestPublicIdentityAndOrderings(t *testing.T) {
	record := core.NewObject("id", "i", "passwordHash", "$argon2id$x", "name", "Ada")
	if safe := PublicIdentity(record); safe.Has("passwordHash") || !record.Has("passwordHash") || core.MustStringify(safe) != `{"id":"i","name":"Ada"}` {
		t.Fatal(core.MustStringify(safe))
	}
	a := core.NewObject("id", "b", "createdAt", 2.0)
	b := core.NewObject("id", "a", "createdAt", 2.0)
	c := core.NewObject("id", "c", "createdAt", 3.0)
	if ByNewest(c, a) >= 0 || ByNewest(b, a) >= 0 || ByNewest(a, b) <= 0 || ByID(b, a) >= 0 {
		t.Fatal("orderings")
	}
	if core.MustStringify(All()) != `{"version":1,"statements":[{"effect":"allow","actions":["*"],"resources":["*"]}]}` {
		t.Fatal(core.MustStringify(All()))
	}
}

func TestTenantAuthPolicy(t *testing.T) {
	_, err := TenantAuthPolicy(parse(t, `{"colour":"blue"}`))
	expectError(t, err, "INVALID_INPUT", "Unknown authentication policy field colour")
	_, err = TenantAuthPolicy(parse(t, `{"requireMfa":"yes"}`))
	expectError(t, err, "INVALID_INPUT", "requireMfa must be a boolean")
	_, err = TenantAuthPolicy(parse(t, `{"allowedMethods":["password","telepathy"]}`))
	expectError(t, err, "INVALID_INPUT", "allowedMethods must list one or more of password, passwordless-email, passwordless-sms, passkey, federated")
	_, err = TenantAuthPolicy(parse(t, `{"allowedMethods":[]}`))
	expectErrorPrefix(t, err, "INVALID_INPUT", "allowedMethods must list")
	_, err = TenantAuthPolicy(parse(t, `{"sessionLifetimeMs":60000,"sessionIdleTimeoutMs":120000}`))
	expectError(t, err, "INVALID_INPUT", "sessionIdleTimeoutMs cannot exceed sessionLifetimeMs")
	_, err = TenantAuthPolicy(parse(t, `{"minPasswordLength":11}`))
	expectError(t, err, "INVALID_INPUT", "Invalid minPasswordLength")
	_, err = TenantAuthPolicy(parse(t, `{"allowedIpRanges":["10.0.0.0/8","not-a-range"]}`))
	expectError(t, err, "INVALID_INPUT", "allowedIpRanges must list one or more IPv4/IPv6 addresses or CIDR blocks")
	_, err = TenantAuthPolicy(parse(t, `[]`))
	expectError(t, err, "INVALID_INPUT", "Expected an object")
	policy := must(TenantAuthPolicy(parse(t, `{"bindSessionsToIp":true,"allowedIpRanges":["10.0.0.0/8","10.0.0.0/8"],"maxSessions":3,"allowedMethods":["passkey","password","passkey"],"requireMfa":false}`)))
	if got := core.MustStringify(policy); got != `{"requireMfa":false,"allowedMethods":["passkey","password"],"maxSessions":3,"allowedIpRanges":["10.0.0.0/8"],"bindSessionsToIp":true}` {
		t.Fatal(got)
	}
}

func TestTenantLimits(t *testing.T) {
	_, err := TenantLimits(parse(t, `{"seats":1}`))
	expectError(t, err, "INVALID_INPUT", "Unknown limit seats")
	_, err = TenantLimits(parse(t, `{"roles":-1}`))
	expectError(t, err, "INVALID_INPUT", "Invalid roles")
	limits := must(TenantLimits(parse(t, `{"webhooks":2,"identities":5}`)))
	if got := core.MustStringify(limits); got != `{"identities":5,"webhooks":2}` {
		t.Fatal(got)
	}
}

func TestTenantAccessPolicyAndActivationRules(t *testing.T) {
	_, err := TenantAccessPolicy(parse(t, `{"maxActivationMinutes":5}`))
	expectError(t, err, "INVALID_INPUT", "Unknown access policy field maxActivationMinutes")
	_, err = TenantAccessPolicy(parse(t, `{"maxActivationMs":59999}`))
	expectError(t, err, "INVALID_INPUT", "Invalid maxActivationMs")
	_, err = TenantAccessPolicy(parse(t, `{"approvalLifetimeMs":299999}`))
	expectError(t, err, "INVALID_INPUT", "Invalid approvalLifetimeMs")
	_, err = TenantAccessPolicy(parse(t, `{"requireMfa":"true"}`))
	expectError(t, err, "INVALID_INPUT", "requireMfa must be boolean")
	policy := must(TenantAccessPolicy(parse(t, `{"requireApproval":true,"requireMfa":false,"approvalLifetimeMs":600000,"maxActivationMs":1800000}`)))
	if got := core.MustStringify(policy); got != `{"maxActivationMs":1800000,"approvalLifetimeMs":600000,"requireApproval":true}` {
		t.Fatal(got)
	}
	rules := ActivationRulesFor(core.NewObject("maxActivationMs", 7200000.0, "requireJustification", true), policy)
	if rules != (ActivationRules{RequireJustification: true, RequireApproval: true, MaxActivationMs: 1800000, ApprovalLifetimeMs: 600000}) {
		t.Fatalf("%+v", rules)
	}
	defaults := ActivationRulesFor(core.NewObject(), nil)
	if defaults != (ActivationRules{MaxActivationMs: DefaultActivationMs, ApprovalLifetimeMs: DefaultApprovalLifetimeMs}) {
		t.Fatalf("%+v", defaults)
	}
}

func TestContextKeyRegistries(t *testing.T) {
	if PrincipalServerKeys.Len() != 57 || ResourceServerKeys.Len() != 5 || TenantServerKeys.Len() != 1 || OptionalPrincipalServerKeys.Len() != 21 {
		t.Fatalf("registry sizes %d %d %d %d", PrincipalServerKeys.Len(), ResourceServerKeys.Len(), TenantServerKeys.Len(), OptionalPrincipalServerKeys.Len())
	}
	for key, kind := range map[string]string{
		"principal.sessionId": "identifier", "principal.tokenIssueTime": "timestamp", "principal.mfa": "boolean",
		"principal.groups": "list", "principal.riskScore": "number", "principal.webIdentitySubject": "string",
		"request.sourceIp": "identifier",
	} {
		if got, _ := PrincipalServerKeys.Get(key); got != kind {
			t.Fatalf("%s: %s", key, got)
		}
	}
	for _, key := range OptionalPrincipalServerKeys.Values() {
		if !PrincipalServerKeys.Has(key) {
			t.Fatalf("optional key %s is not registered", key)
		}
	}
	if !IsServerOwnedKey("principal.sessionTags.team", true) || !IsServerOwnedKey("tenant.features", true) ||
		!IsServerOwnedKey("resource.noforn", true) || IsServerOwnedKey("resource.noforn", false) ||
		IsServerOwnedKey("principal.clearanceRank", false) || !IsServerOwnedKey("principal.clearanceRank", true) ||
		IsServerOwnedKey("principal.department", true) || !IsServerOwnedKey("principal.id", false) {
		t.Fatal("server-owned keys")
	}
	if SessionTagName("team_1") != "principal.sessionTags.team_1" || SessionTagName("bad-name") != "" || SessionTagName("1team") != "" ||
		SessionTagName(strings.Repeat("a", 65)) != "" {
		t.Fatal("session tag names")
	}
	if len(SessionScopedPrincipalKeys) != 17 || containsString(SessionScopedPrincipalKeys, "principal.sessionTags") ||
		!containsString(SessionScopedPrincipalKeys, "principal.delegationChain") {
		t.Fatalf("session scoped keys %v", SessionScopedPrincipalKeys)
	}
	if ClearanceServerKeys.Len() != 10 {
		t.Fatalf("clearance keys %v", ClearanceServerKeys.Values())
	}
}

func TestSessionKinds(t *testing.T) {
	for kind, own := range map[string]bool{"user": true, "api-key": true, "role": false, "session-token": false, "delegated": false, "other": false} {
		if ActsInOwnRight(core.NewObject("kind", kind)) != own {
			t.Fatalf("%s", kind)
		}
	}
	if !TemporarySessionKinds.Has("delegated") || TemporarySessionKinds.Has("user") {
		t.Fatal("temporary kinds")
	}
	if !RevokedByWatermark(10, core.Undefined, 11.0) || RevokedByWatermark(10, 10.0) || RevokedByWatermark(10, "11", core.Undefined) {
		t.Fatal("watermarks")
	}
	if got := must(NextWatermark(core.Undefined, core.Undefined, 1000)); got != 1001 {
		t.Fatal(got)
	}
	if got := must(NextWatermark(2000.0, 500.0, 1000)); got != 2000 {
		t.Fatal(got)
	}
	if got := must(NextWatermark(100.0, 500, 1000)); got != 500 {
		t.Fatal(got)
	}
	for _, bad := range []any{1002.0, -1.0, 1.5, "500", nil} {
		_, err := NextWatermark(core.Undefined, bad, 1000)
		expectError(t, err, "INVALID_INPUT", "before must be a time no later than now")
	}
}

func TestValidatePlugins(t *testing.T) {
	config := must(resolve(t, ""))
	catalog := must(NewCatalog(optionsValue(t, `{"permissions":{"actions":["documents:read"]}}`), nil, config))
	handler := func(context.Context, core.PluginEndpointContext, *core.Object) (any, error) { return nil, nil }
	validate := func(any) (*core.Object, error) { return core.NewObject(), nil }
	endpoint := func(path, method, action string) core.PluginEndpoint {
		return core.PluginEndpoint{Method: method, Path: path, Action: action, Validate: validate, Handler: handler}
	}
	if err := ValidatePlugins([]*core.IamPlugin{{ID: "a"}, {ID: "a"}}, catalog); err == nil || err.Error() != "Duplicate plugin ID" {
		t.Fatalf("duplicate: %v", err)
	}
	err := ValidatePlugins([]*core.IamPlugin{{ID: "a", Endpoints: []core.PluginEndpoint{endpoint("x", "POST", "documents:write")}}}, catalog)
	expectError(t, err, "INVALID_CONFIG", "Plugin endpoint action must be registered")
	for _, bad := range [][]core.PluginEndpoint{
		{endpoint("x", "GET", "documents:read")},
		{endpoint("x/../y", "POST", "documents:read")},
		{endpoint("/x", "POST", "documents:read"), endpoint("x", "POST", "documents:read")},
		{{Method: "POST", Path: "x", Action: "documents:read", Handler: handler}},
	} {
		err := ValidatePlugins([]*core.IamPlugin{{ID: "a", Endpoints: bad}}, catalog)
		expectError(t, err, "INVALID_CONFIG", "Plugin endpoints require unique paths, POST, validation, and a handler")
	}
	if err := ValidatePlugins([]*core.IamPlugin{{ID: "a", Endpoints: []core.PluginEndpoint{endpoint("/reports/run", "POST", "documents:read")}}}, catalog); err != nil {
		t.Fatal(err)
	}
	configErr := core.NewIamError("INVALID_CONFIG", "plugin says no")
	if err := ValidatePlugins([]*core.IamPlugin{{ID: "a", ValidateConfig: func() error { return configErr }}}, catalog); err != configErr {
		t.Fatalf("validateConfig: %v", err)
	}
}

func TestClientInfo(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
	if ClientFromRequest(&BetterIamOptions{}, request) != nil {
		t.Fatal("no user agent, no client")
	}
	request.Header.Set("User-Agent", "curl/8")
	if client := ClientFromRequest(&BetterIamOptions{}, request); client == nil || client.UserAgent != "curl/8" {
		t.Fatalf("%+v", client)
	}
	options := &BetterIamOptions{HTTP: &HttpOptions{ClientInfo: func(r *http.Request) *core.SessionClientInfo {
		return &core.SessionClientInfo{IP: r.Header.Get("x-real-ip")}
	}}}
	headers := http.Header{}
	headers.Set("x-real-ip", "192.0.2.1")
	if client := ClientFromHeaders(options, headers, "http://localhost:3000"); client == nil || client.IP != "192.0.2.1" {
		t.Fatalf("%+v", client)
	}
	if ClientFromHeaders(options, nil, "http://localhost:3000") != nil {
		t.Fatal("no headers")
	}
	panicking := &BetterIamOptions{HTTP: &HttpOptions{ClientInfo: func(*http.Request) *core.SessionClientInfo { panic("boom") }}}
	if ClientFromHeaders(panicking, headers, "http://localhost:3000") != nil {
		t.Fatal("a failing clientInfo yields no client")
	}
}
