package server

// Ports of tests/sts-config.test.ts and the configuration cases of tests/regions.test.ts, tests/tenant-hosts.test.ts,
// tests/signals-receiver.test.ts, tests/tenant-defaults.test.ts and tests/security-activity.test.ts, plus the rest
// of resolveConfig. Invalid values are written as JSON model values, as the TypeScript tests pass them `as never`.

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

func resolve(t *testing.T, members string) (*ServerConfig, error) {
	t.Helper()
	return resolveConfigValue(optionsValue(t, members), nil)
}

func asJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestStsConfigAppliesTheDefaults(t *testing.T) {
	config := must(resolve(t, ""))
	want := `{"maxRoleSessionSeconds":3600,"maxSessionTokenSeconds":43200,"maxSessionTokensPerIdentity":50,` +
		`"webIdentity":{"enabled":false,"jwksCacheSeconds":600,"fetchTimeoutMs":5000,"maxJwksBytes":65536,` +
		`"maxExchangesPerWindow":600,"maxSessionsPerTrust":1000,"allowPrivateNetworks":false,"allowInsecureLocalhost":false}}`
	if got := asJSON(t, config.Sts); got != want {
		t.Fatalf("defaults:\n got %s\nwant %s", got, want)
	}
	if got := asJSON(t, must(resolve(t, `{"sts":{}}`)).Sts); got != want {
		t.Fatalf("empty sts: %s", got)
	}
}

func TestStsConfigAcceptsEveryBoundAtItsLimit(t *testing.T) {
	for _, edge := range []string{"min", "max"} {
		pick := func(min, max float64) float64 {
			if edge == "min" {
				return min
			}
			return max
		}
		options := &BetterIamOptions{Database: newStore(t), Secret: testSecret, BaseURL: "http://localhost:3000", Sts: &StsOptions{
			MaxRoleSessionSeconds:       float(pick(900, 43200)),
			MaxSessionTokenSeconds:      float(pick(900, 129600)),
			MaxSessionTokensPerIdentity: float(pick(1, 1000)),
			WebIdentity: &StsWebIdentityOptions{
				Enabled:                flag(true),
				AllowedIssuers:         []string{"https://token.actions.githubusercontent.com"},
				JwksCacheSeconds:       float(pick(60, 3600)),
				FetchTimeoutMs:         float(pick(500, 10000)),
				MaxJwksBytes:           float(pick(1024, 1048576)),
				MaxExchangesPerWindow:  float(pick(1, 100000)),
				MaxSessionsPerTrust:    float(pick(1, 100000)),
				AllowPrivateNetworks:   flag(true),
				AllowInsecureLocalhost: flag(true),
				FetchJSON:              func(ctx contextT, url string) (any, error) { return core.NewObject(), nil },
			},
		}}
		config := must(ResolveConfig(options))
		sts := config.Sts
		if sts.MaxRoleSessionSeconds != int64(*options.Sts.MaxRoleSessionSeconds) ||
			sts.MaxSessionTokenSeconds != int64(*options.Sts.MaxSessionTokenSeconds) ||
			sts.MaxSessionTokensPerIdentity != int64(*options.Sts.MaxSessionTokensPerIdentity) {
			t.Fatalf("%s: ceilings %+v", edge, sts)
		}
		web := sts.WebIdentity
		if !web.Enabled || !reflect.DeepEqual(web.AllowedIssuers, []string{"https://token.actions.githubusercontent.com"}) ||
			web.JwksCacheSeconds != int64(*options.Sts.WebIdentity.JwksCacheSeconds) || !web.AllowPrivateNetworks ||
			!web.AllowInsecureLocalhost {
			t.Fatalf("%s: web identity %+v", edge, web)
		}
		if strings.Contains(asJSON(t, web), "fetchJson") {
			t.Fatal("resolved config must not carry fetchJson")
		}
	}
}

func TestStsConfigRefusesInvalidValues(t *testing.T) {
	issuers := make([]string, 101)
	for index := range issuers {
		issuers[index] = `"https://idp` + core.NumberString(float64(index)) + `.example.com"`
	}
	cases := []struct{ field, sts string }{
		{"maxRoleSessionSeconds", `{"maxRoleSessionSeconds":899}`},
		{"maxRoleSessionSeconds", `{"maxRoleSessionSeconds":43201}`},
		{"maxRoleSessionSeconds", `{"maxRoleSessionSeconds":1000.5}`},
		{"maxRoleSessionSeconds", `{"maxRoleSessionSeconds":"3600"}`},
		{"maxSessionTokenSeconds", `{"maxSessionTokenSeconds":899}`},
		{"maxSessionTokenSeconds", `{"maxSessionTokenSeconds":129601}`},
		{"maxSessionTokensPerIdentity", `{"maxSessionTokensPerIdentity":0}`},
		{"maxSessionTokensPerIdentity", `{"maxSessionTokensPerIdentity":1001}`},
		{"webIdentity.jwksCacheSeconds", `{"webIdentity":{"jwksCacheSeconds":59}}`},
		{"webIdentity.jwksCacheSeconds", `{"webIdentity":{"jwksCacheSeconds":3601}}`},
		{"webIdentity.fetchTimeoutMs", `{"webIdentity":{"fetchTimeoutMs":499}}`},
		{"webIdentity.fetchTimeoutMs", `{"webIdentity":{"fetchTimeoutMs":10001}}`},
		{"webIdentity.maxJwksBytes", `{"webIdentity":{"maxJwksBytes":1023}}`},
		{"webIdentity.maxJwksBytes", `{"webIdentity":{"maxJwksBytes":1048577}}`},
		{"webIdentity.maxExchangesPerWindow", `{"webIdentity":{"maxExchangesPerWindow":0}}`},
		{"webIdentity.maxExchangesPerWindow", `{"webIdentity":{"maxExchangesPerWindow":100001}}`},
		{"webIdentity.maxSessionsPerTrust", `{"webIdentity":{"maxSessionsPerTrust":0}}`},
		{"webIdentity.maxSessionsPerTrust", `{"webIdentity":{"maxSessionsPerTrust":100001}}`},
		{"webIdentity.enabled", `{"webIdentity":{"enabled":"yes"}}`},
		{"webIdentity.allowPrivateNetworks", `{"webIdentity":{"allowPrivateNetworks":1}}`},
		{"webIdentity.allowInsecureLocalhost", `{"webIdentity":{"allowInsecureLocalhost":"true"}}`},
		{"webIdentity.fetchJson", `{"webIdentity":{"fetchJson":"https://proxy"}}`},
		{"webIdentity", `{"webIdentity":"on"}`},
		{"options", `"on"`},
		{"webIdentity.allowedIssuers", `{"webIdentity":{"allowedIssuers":"https://token.actions.githubusercontent.com"}}`},
		{"webIdentity.allowedIssuers", `{"webIdentity":{"allowedIssuers":[` + strings.Join(issuers, ",") + `]}}`},
		{"webIdentity.allowedIssuers", `{"webIdentity":{"allowedIssuers":["http://idp.example.com"]}}`},
		{"webIdentity.allowedIssuers", `{"webIdentity":{"allowedIssuers":["https://idp.example.com/?a"]}}`},
		{"webIdentity.allowedIssuers", `{"webIdentity":{"allowedIssuers":["http://localhost:3000/api/iam"],"allowInsecureLocalhost":true}}`},
	}
	for _, c := range cases {
		_, err := resolve(t, `{"sts":`+c.sts+`}`)
		if err == nil {
			t.Fatalf("%s %s: expected INVALID_CONFIG", c.field, c.sts)
		}
		known := iamError(t, err)
		pattern := regexp.MustCompile(`^sts\.` + regexp.QuoteMeta(c.field) + ` `)
		if known.Code != "INVALID_CONFIG" || !pattern.MatchString(known.Message) {
			t.Fatalf("%s %s: got %s %q", c.field, c.sts, known.Code, known.Message)
		}
	}
	_, err := resolve(t, `{"sts":{"maxRoleSessionSeconds":899}}`)
	expectError(t, err, "INVALID_CONFIG", "sts.maxRoleSessionSeconds must be an integer from 900 to 43200")
	_, err = resolve(t, `{"sts":{"webIdentity":{"allowedIssuers":["http://localhost:3000/api/iam"],"allowInsecureLocalhost":true}}}`)
	expectError(t, err, "INVALID_CONFIG", "sts.webIdentity.allowedIssuers contains an invalid issuer: IAM cannot trust its own issuer as a web identity provider")
}

func TestStsConfigAcceptsLoopbackIssuersOnlyWithAllowInsecureLocalhostAndDeduplicates(t *testing.T) {
	config := must(resolve(t, `{"sts":{"webIdentity":{"allowInsecureLocalhost":true,"allowedIssuers":["http://127.0.0.1:9000","http://127.0.0.1:9000"]}}}`))
	if !reflect.DeepEqual(config.Sts.WebIdentity.AllowedIssuers, []string{"http://127.0.0.1:9000"}) {
		t.Fatalf("issuers %v", config.Sts.WebIdentity.AllowedIssuers)
	}
	_, err := resolve(t, `{"sts":{"webIdentity":{"allowedIssuers":["http://127.0.0.1:9000"]}}}`)
	expectError(t, err, "INVALID_CONFIG", "sts.webIdentity.allowedIssuers contains an invalid issuer: The issuer must use https")
}

func TestRegionConfigValidation(t *testing.T) {
	cases := []struct{ regions, message string }{
		{`{"current":"us-east-1","regions":{"eu-west-1":{}}}`, "current must be one of regions"},
		{`{"current":"US East","regions":{"us-east-1":{}}}`, "current must be a region name"},
		{`{"current":"us-east-1","regions":{}}`, "1 to 64 regions"},
		{`{"current":"us-east-1","regions":{"us-east-1":{"baseURL":"http://eu.example.com"}}}`, "must use HTTPS outside localhost"},
		{`{"current":"us-east-1","regions":{"us-east-1":{}},"locate":"nope"}`, "locate must be a function"},
	}
	for _, c := range cases {
		_, err := resolve(t, `{"regions":`+c.regions+`}`)
		expectContains(t, err, c.message)
		if code := iamError(t, err).Code; code != "INVALID_CONFIG" {
			t.Fatalf("%s: code %s", c.regions, code)
		}
	}
	config := must(resolve(t, `{"regions":{"current":"us-east-1","regions":{"us-east-1":{"baseURL":"https://us.example.com/iam/","label":" US East "},"eu-west-1":null}}}`))
	if config.Regions.Current != "us-east-1" || !reflect.DeepEqual(config.Regions.Names, []string{"us-east-1", "eu-west-1"}) ||
		*config.Regions.Regions["us-east-1"].BaseURL != "https://us.example.com/iam" || *config.Regions.Regions["us-east-1"].Label != "US East" {
		t.Fatalf("regions %+v", config.Regions)
	}
}

func TestHostConfigValidation(t *testing.T) {
	cases := []struct{ hosts, message string }{
		{`{"patterns":["signin.localhost"]}`, "{tenant} exactly once"},
		{`{"patterns":["{tenant}.{tenant}.localhost"]}`, "{tenant} exactly once"},
		{`{"patterns":["{tenant}.{region}.localhost"]}`, "needs the regions option"},
		{`{"patterns":["{tenant}.signin.example.com"]}`, "HTTPS baseURL outside localhost"},
		{`{"patterns":["{tenant}"]}`, "not a valid hostname template"},
		{`{"patterns":["{tenant}.local_host"]}`, "not a valid hostname template"},
		{`{"signInPath":"login"}`, "signInPath"},
		{`{"cnameTarget":"not a host"}`, "cnameTarget"},
	}
	for _, c := range cases {
		_, err := resolve(t, `{"hosts":`+c.hosts+`}`)
		expectContains(t, err, c.message)
	}
	// Passkeys belong to one domain, so every organization address must sit under the RP ID.
	_, err := resolve(t, `{"baseURL":"https://signin.example.com","authentication":{"passkeys":{"rpID":"example.com"}},"hosts":{"patterns":["{tenant}.signin.other.net"]}}`)
	expectError(t, err, "INVALID_CONFIG", "hosts.patterns entry {tenant}.signin.other.net must be under the passkey RP ID example.com")
	config := must(resolve(t, `{"baseURL":"https://signin.example.com","authentication":{"passkeys":{"rpID":"example.com"}},"hosts":{"patterns":["{tenant}.signin.example.com"]}}`))
	pattern := config.Hosts.Patterns[0]
	if !config.Hosts.Enabled || pattern.Suffix != ".signin.example.com" || pattern.Fill("acme", nil) != "acme.signin.example.com" {
		t.Fatalf("hosts %+v", config.Hosts)
	}
	if match := pattern.Regex.FindStringSubmatch("acme.signin.example.com"); match == nil || match[pattern.Regex.SubexpIndex("tenant")] != "acme" {
		t.Fatalf("pattern %s does not match", pattern.Regex)
	}
	regional := must(resolve(t, `{"regions":{"current":"us-east-1","regions":{"us-east-1":{},"eu-west-1":{}}},"hosts":{"patterns":["{tenant}.signin.{region}.localhost:3000"],"cnameTarget":"Custom.Signin.Localhost.","customHostnames":true}}`))
	compiled := regional.Hosts.Patterns[0]
	if match := compiled.Regex.FindStringSubmatch("acme.signin.eu-west-1.localhost:3000"); match == nil || match[compiled.Regex.SubexpIndex("region")] != "eu-west-1" {
		t.Fatalf("regional pattern %s", compiled.Regex)
	}
	if compiled.Fill("acme", nil) != "acme.signin.us-east-1.localhost:3000" || regional.Hosts.CnameTarget != "custom.signin.localhost" || !regional.Hosts.CustomHostnames {
		t.Fatalf("regional hosts %+v", regional.Hosts)
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Acme.Example.COM.":      "acme.example.com",
		"acme.example.com.:8443": "acme.example.com:8443",
		"[::1]:3000":             "[::1]:3000",
		" localhost ":            "localhost",
		"bad host":               "",
		"a_b.example.com":        "",
		"":                       "",
	}
	for input, want := range cases {
		if got := NormalizeHost(input); got != want {
			t.Fatalf("NormalizeHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSignalsConfigValidation(t *testing.T) {
	for _, signals := range []string{
		`{"pushPath":"signals/push"}`, `{"pushPath":"/signals/push/"}`, `{"pushPath":"/signals//push"}`,
		`{"pushPath":"/signals push"}`, `{"allowPrivateNetworks":"yes"}`, `{"allowInsecureLocalhost":1}`, `"on"`,
	} {
		_, err := resolve(t, `{"signals":`+signals+`}`)
		expectErrorPrefix(t, err, "INVALID_CONFIG", "signals")
	}
	config := must(resolve(t, `{"signals":{"pushPath":"/ssf/push"}}`))
	if config.Signals.PushPath != "/ssf/push" {
		t.Fatalf("push path %s", config.Signals.PushPath)
	}
	if must(resolve(t, "")).Signals.PushPath != "/api/iam/signals/push" {
		t.Fatal("default push path")
	}
}

func TestTenantDefaultsAreValidatedAtConstruction(t *testing.T) {
	_, err := resolve(t, `{"tenantDefaults":{"limits":{"seats":1}}}`)
	expectError(t, err, "INVALID_CONFIG", "tenantDefaults: Unknown limit seats")
	_, err = resolve(t, `{"tenantDefaults":{"authPolicy":{"minPasswordLength":4}}}`)
	expectError(t, err, "INVALID_CONFIG", "tenantDefaults: Invalid minPasswordLength")
	_, err = resolve(t, `{"tenantDefaults":{"authPolicy":{"notifyNewSignIn":"no"}}}`)
	expectContains(t, err, "notifyNewSignIn")
	config := must(resolve(t, `{"tenantDefaults":{"limits":{"identities":2},"authPolicy":{"minPasswordLength":16}}}`))
	if core.MustStringify(config.TenantDefaults.Limits) != `{"identities":2}` || core.MustStringify(config.TenantDefaults.AuthPolicy) != `{"minPasswordLength":16}` {
		t.Fatalf("defaults %+v", config.TenantDefaults)
	}
	typed := must(ResolveConfig(&BetterIamOptions{Database: newStore(t), Secret: testSecret, BaseURL: "http://localhost:3000",
		TenantDefaults: &TenantDefaults{Limits: &core.TenantLimits{Identities: ptr64(2)}}}))
	if core.MustStringify(typed.TenantDefaults.Limits) != `{"identities":2}` {
		t.Fatalf("typed limits %s", core.MustStringify(typed.TenantDefaults.Limits))
	}
}

func ptr64(value int64) *int64 { return &value }

func TestClearanceConfig(t *testing.T) {
	if must(resolve(t, "")).Clearances != nil {
		t.Fatal("clearances must be off by default")
	}
	_, err := resolve(t, `{"clearances":true}`)
	expectError(t, err, "INVALID_CONFIG", "clearances must be an object")
	_, err = resolve(t, `{"clearances":[]}`)
	expectError(t, err, "INVALID_CONFIG", "clearances must be an object")
	_, err = resolve(t, `{"clearances":{"strict":true}}`)
	expectError(t, err, "INVALID_CONFIG", "clearances.strict is not a known setting")
	_, err = resolve(t, `{"clearances":{"appliesToRoot":"no"}}`)
	expectError(t, err, "INVALID_CONFIG", "clearances.appliesToRoot must be a boolean")
	if config := must(resolve(t, `{"clearances":{}}`)); !config.Clearances.AppliesToRoot {
		t.Fatal("appliesToRoot defaults to true")
	}
	if config := must(resolve(t, `{"clearances":{"appliesToRoot":false}}`)); config.Clearances.AppliesToRoot {
		t.Fatal("appliesToRoot false")
	}
}

func TestResolveConfigBasics(t *testing.T) {
	_, err := ResolveConfig(&BetterIamOptions{Secret: testSecret, BaseURL: "http://localhost:3000"})
	expectError(t, err, "INVALID_CONFIG", "database is required")
	_, err = resolve(t, `{"baseURL":"http://iam.example.com"}`)
	expectError(t, err, "INVALID_CONFIG", "HTTPS is required outside localhost")
	_, err = resolve(t, `{"baseURL":"not a url"}`)
	expectError(t, err, "INVALID_CONFIG", "baseURL must be an absolute URL")
	for _, basePath := range []string{`"api"`, `"/api/"`, `"/api iam"`, `""`} {
		_, err = resolve(t, `{"basePath":`+basePath+`}`)
		expectError(t, err, "INVALID_CONFIG", "Invalid basePath")
	}
	_, err = resolve(t, `{"hierarchy":{"types":{"organization":{"allowedChildren":[]}}}}`)
	expectError(t, err, "INVALID_CONFIG", "Hierarchy must define root")
	_, err = resolve(t, `{"hierarchy":{"types":{"root":{"allowedChildren":["team"]}}}}`)
	expectError(t, err, "INVALID_CONFIG", "Invalid allowed child type")
	_, err = resolve(t, `{"hierarchy":{"types":{"root":{"allowedChildren":["root"]}}}}`)
	expectError(t, err, "INVALID_CONFIG", "Invalid allowed child type")
	_, err = resolve(t, `{"hierarchy":{"maxDepth":0,"types":{"root":{"allowedChildren":[]}}}}`)
	expectError(t, err, "INVALID_INPUT", "Invalid maxDepth")
	_, err = resolve(t, `{"accessRequests":{"lifetimeMs":59999}}`)
	expectError(t, err, "INVALID_INPUT", "Invalid accessRequests.lifetimeMs")
	_, err = resolve(t, `{"accessRequests":{"maxDurationSeconds":59}}`)
	expectError(t, err, "INVALID_INPUT", "Invalid accessRequests.maxDurationSeconds")
	_, err = resolve(t, `{"events":{"webhookTimeoutMs":999}}`)
	expectError(t, err, "INVALID_INPUT", "Invalid events.webhookTimeoutMs")

	config := must(resolve(t, `{"trustedOrigins":["https://app.example.com","http://localhost:3000"],"permissions":{"mode":"tenant-defined","resourceTypes":{}},"onboarding":{"mode":"linked"}}`))
	if config.BasePath != "/api/iam" || config.MaxDepth != 8 || len(config.Hierarchy.Types) != 3 ||
		!reflect.DeepEqual(config.TrustedOrigins, []string{"http://localhost:3000", "https://app.example.com"}) ||
		!config.TrustedOrigin("https://app.example.com") || !config.TenantDefined || !config.StrictResourceTypes ||
		!config.LinkedOnboarding || config.InvitationLifetimeMs != 86400000 || config.AccessRequestLifetimeMs != 7*86400000 ||
		config.AccessRequestMaxDurationSeconds != 90*86400 || config.WebhookTimeoutMs != 10000 || config.Hosts.Enabled ||
		config.Regions != nil || config.BaseOrigin() != "http://localhost:3000" {
		t.Fatalf("config %+v", config)
	}
	if names := []string{config.Hierarchy.Types[0].Name, config.Hierarchy.Types[1].Name, config.Hierarchy.Types[2].Name}; !reflect.DeepEqual(names, []string{"root", "organization", "project"}) {
		t.Fatalf("hierarchy %v", names)
	}
}

func TestOptionsValueOfTypedOptions(t *testing.T) {
	options := &BetterIamOptions{
		Database: newStore(t), Secret: testSecret, BaseURL: "https://iam.example.com", BasePath: str("/iam"),
		Authentication: &auth.Options{Passkeys: &auth.PasskeyOptions{RPID: "example.com"}, SessionLifetimeMs: ptr64(60000)},
		Hierarchy: &core.HierarchyConfig{Types: []core.NamedTenantType{
			{Name: "root", Type: core.TenantType{AllowedChildren: []string{"team"}}}, {Name: "team"},
		}},
		Regions:     &RegionOptions{Current: "eu", Regions: map[string]RegionSettings{"eu": {}}},
		Hosts:       &HostOptions{Patterns: []string{"{tenant}.example.com"}},
		Sts:         &StsOptions{WebIdentity: &StsWebIdentityOptions{FetchJSON: func(contextT, string) (any, error) { return nil, nil }}},
		AccessUsage: On[AccessUsageOptions](),
		Billing:     &BillingOptions{PaymentReminderDays: []float64{}},
	}
	value := OptionsValue(options)
	if typeOf(member(member(member(value, "sts"), "webIdentity"), "fetchJson")) != "function" || value.Get("accessUsage") != true ||
		member(member(member(value, "authentication"), "passkeys"), "rpID") != "example.com" ||
		core.MustStringify(member(value, "billing")) != `{"paymentReminderDays":[]}` ||
		core.MustStringify(member(value, "hierarchy")) != `{"types":{"root":{"allowedChildren":["team"]},"team":{"allowedChildren":[]}}}` {
		t.Fatalf("value %s", core.MustStringify(value))
	}
	config := must(ResolveConfig(options))
	if config.BasePath != "/iam" || config.Regions.Current != "eu" || len(config.Hosts.Patterns) != 1 || config.MaxDepth != 8 {
		t.Fatalf("config %+v", config)
	}
}
