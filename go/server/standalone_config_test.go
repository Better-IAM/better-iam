package server

// The standalone configuration reader: a differential test against the TypeScript reader plus resolveConfig and the
// Catalog (testdata/config.json, written by testdata/config.mjs), and the reader's behavior (deliveries, client info,
// scripted callbacks, typed decoding, the startup error line).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

func sqliteAdapters() ConfigAdapters {
	return ConfigAdapters{SQLite: func(store StoreConfig) (core.IamStore, error) {
		return sqlite.New(sqlite.Options{Filename: store.Path, BusyTimeoutMs: store.BusyTimeoutMs, JournalMode: store.JournalMode, Durability: store.Durability})
	}}
}

func configSummary(config *ServerConfig, catalog *Catalog) *core.Object {
	var hierarchy []string
	for _, entry := range config.Hierarchy.Types {
		hierarchy = append(hierarchy, entry.Name)
	}
	defaults := core.NewObject()
	if config.TenantDefaults.Limits != nil {
		defaults.Set("limits", config.TenantDefaults.Limits)
	}
	if config.TenantDefaults.AuthPolicy != nil {
		defaults.Set("authPolicy", config.TenantDefaults.AuthPolicy)
	}
	hosts := []any{}
	for _, pattern := range config.Hosts.Patterns {
		hosts = append(hosts, pattern.Source)
	}
	var regions any
	if config.Regions != nil {
		regions = []any{config.Regions.Current, stringsOf(config.Regions.Names)}
	}
	var clearances any
	if config.Clearances != nil {
		clearances = core.Normalize(config.Clearances)
	}
	summary := core.NewObject(
		"basePath", config.BasePath,
		"trustedOrigins", stringsOf(config.TrustedOrigins),
		"maxDepth", float64(config.MaxDepth),
		"hierarchy", stringsOf(hierarchy),
		"tenantDefined", config.TenantDefined,
		"strictResourceTypes", config.StrictResourceTypes,
		"linkedOnboarding", config.LinkedOnboarding,
		"invitationLifetimeMs", config.InvitationLifetimeMs,
		"accessRequestLifetimeMs", float64(config.AccessRequestLifetimeMs),
		"webhookTimeoutMs", float64(config.WebhookTimeoutMs),
		"tenantDefaults", defaults,
		"sts", core.Normalize(config.Sts),
		"signals", core.Normalize(config.Signals),
		"hosts", hosts,
		"regions", regions,
		"clearances", clearances,
	)
	resourceTypes := stringsOf(catalog.ResourceTypeNames)
	if resourceTypes == nil {
		resourceTypes = []any{}
	}
	return core.NewObject("config", summary, "actions", float64(catalog.Actions.Len()), "resourceTypes", resourceTypes)
}

func TestStandaloneConfigMatchesTheTypeScriptReader(t *testing.T) {
	fixture := readFixture(t, "config.json")
	env := map[string]string{}
	member(fixture, "env").(*core.Object).Entries(func(key string, value any) bool {
		env[key] = value.(string)
		return true
	})
	runtimes := map[string]ConfigRuntime{
		"standalone": {Adapters: sqliteAdapters(), Env: env},
		"conformance": {Adapters: sqliteAdapters(), Env: env, Now: func() int64 { return 0 },
			Deliver: func(context.Context, string, any) error { return nil },
			Scripted: func(path string) ScriptedCallback {
				return func(context.Context, ...any) (any, error) { return path, nil }
			}},
	}
	cases, _ := fixture.Array("cases")
	for index, item := range cases {
		for name, runtime := range runtimes {
			want := member(item, name)
			var got any
			options, err := OptionsFromConfig(core.CloneValue(member(item, "config")), runtime)
			if err == nil {
				var config *ServerConfig
				if config, err = ResolveConfig(options); err == nil {
					var catalog *Catalog
					if catalog, err = NewCatalog(OptionsValue(options), options.Plugins, config); err == nil {
						got = configSummary(config, catalog)
					}
				}
			}
			if options != nil && options.Database != nil {
				_ = options.Database.Close(context.Background())
			}
			if err != nil {
				code := any(nil)
				if known, ok := asIamError(err); ok {
					code = known.Code
				}
				got = core.NewObject("error", core.NewObject("name", errorName(err), "code", code, "message", errorMessageOf(err)))
			}
			if core.CanonicalJSON(got) != core.CanonicalJSON(want) {
				t.Errorf("case %d (%s) %s:\n go %s\n ts %s", index, name, core.MustStringify(member(item, "config")), core.CanonicalJSON(got), core.CanonicalJSON(want))
			}
		}
	}
}

func errorMessageOf(err error) string {
	if known, ok := asIamError(err); ok {
		return known.Message
	}
	return err.Error()
}

func TestStandaloneConfigDeliveriesAndCallbacks(t *testing.T) {
	var mu sync.Mutex
	var captured []string
	var posted []string
	var logged []string
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		posted = append(posted, r.Header.Get("x-api-key")+" "+string(body))
		mu.Unlock()
		if strings.Contains(string(body), "fail") {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer endpoint.Close()
	calls := []string{}
	runtime := ConfigRuntime{
		Adapters: sqliteAdapters(),
		Now:      func() int64 { return 42 },
		Wall:     func() int64 { return 43 },
		Deliver: func(ctx context.Context, kind string, message any) error {
			captured = append(captured, kind+" "+core.MustStringify(deliveryValue(message)))
			return nil
		},
		Log: func(line string) { logged = append(logged, line) },
		Scripted: func(path string) ScriptedCallback {
			return func(ctx context.Context, args ...any) (any, error) {
				calls = append(calls, path+" "+core.MustStringify(args))
				switch path {
				case "authentication.requireMfa", "authentication.passwordPolicy.isBreached":
					return true, nil
				case "authentication.passwordPolicy.check":
					return "too predictable", nil
				case "regions.locate":
					return "eu", nil
				case "domains.resolveTxt":
					return []any{[]any{"a", "b"}}, nil
				case "resolveResource":
					return core.NewObject("tenantId", "t", "type", "doc", "id", "1", "attributes", core.NewObject("owner", "ada"), "classification", nil), nil
				case "vault.engines.pg.issue":
					return core.NewObject("value", "secret", "handle", "h1"), nil
				}
				return nil, nil
			}
		},
	}
	document := `{
		"secret": "standalone-config-secret-with-at-least-32-characters",
		"baseURL": "http://localhost:3000",
		"authentication": {"sessionLifetimeMs": 3600000, "passkeys": {"rpID": "localhost"}, "rateLimits": {"attempts": 3},
			"requireMfa": {"$scripted": true}, "passwordPolicy": {"blockCommonPasswords": false, "isBreached": {"$scripted": true}, "check": {"$scripted": true}}},
		"delivery": {"email": {"kind": "capture"}, "sms": {"kind": "log"}, "webhook": {"kind": "http", "url": "` + endpoint.URL + `", "headers": {"x-api-key": "k1"}}, "events": {"kind": "capture"}},
		"http": {"cookieSameSite": "strict", "clientInfo": {"ipHeader": "x-forwarded-for", "labelHeader": "x-device"}},
		"resolveResource": {"$scripted": true},
		"regions": {"current": "us", "regions": {"us": {}, "eu": {"baseURL": "https://eu.example.com"}}, "locate": {"$scripted": true}},
		"domains": {"resolveTxt": {"$scripted": true}, "recordName": "_verify"},
		"vault": {"maxValueBytes": 1024, "engines": {"pg": {"issue": {"$scripted": true}}}},
		"sts": {"maxRoleSessionSeconds": 1800, "jwt": {"signingKeys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1"}]}},
		"accessUsage": {"flushIntervalMs": 5000},
		"inference": true,
		"billing": {"currency": "EUR", "paymentReminderDays": []},
		"tenantDefaults": {"limits": {"identities": 10}},
		"hierarchy": {"types": {"root": {"allowedChildren": ["team"]}, "team": {"allowedChildren": []}}},
		"permissions": {"actions": ["docs:read"], "identityAttributes": {"level": "number"}}
	}`
	options := must(LoadStandaloneConfig([]byte(document), runtime))
	defer options.Database.Close(context.Background())
	config := must(ResolveConfig(options))
	if config.Sts.MaxRoleSessionSeconds != 1800 || config.Regions.Current != "us" {
		t.Fatalf("%+v", config)
	}
	authentication := options.Authentication
	if *authentication.SessionLifetimeMs != 3600000 || authentication.Passkeys.RPID != "localhost" || *authentication.RateLimits.Attempts != 3 ||
		*authentication.PasswordPolicy.BlockCommonPasswords || authentication.Now() != 42 || options.WallClock() != 43 {
		t.Fatalf("authentication %+v", authentication)
	}
	if *options.Vault.MaxValueBytes != 1024 || *options.Domains.RecordName != "_verify" || *options.Billing.Currency != "EUR" ||
		options.Billing.PaymentReminderDays == nil || !options.Inference.IsOn() || *options.AccessUsage.Options.FlushIntervalMs != 5000 ||
		options.Sts.JWT.SigningKeys[0].Get("kid") != "k1" || *options.HTTP.CookieSameSite != "strict" ||
		len(options.Hierarchy.Types) != 2 || options.Permissions.IdentityAttributes[0].Name != "level" {
		t.Fatal("typed options")
	}
	ctx := context.Background()
	must(0, authentication.SendEmail(ctx, auth.DeliveryMessage{ID: "m1", TenantID: "t", To: "a@example.com", Template: "verify-email", Payload: map[string]string{"token": "x"}}))
	must(0, authentication.SendSms(ctx, auth.DeliveryMessage{ID: "m2", TenantID: "t", To: "+1555", Template: "sms-code", Payload: map[string]string{"code": "1"}}))
	headers := core.NewObject("content-type", "application/json")
	must(0, options.Events.DeliverWebhook(ctx, WebhookDelivery{ID: "m3", TenantID: "t", WebhookID: "h", URL: "u", Event: "e", Body: "{}", Headers: headers}))
	if err := options.Events.DeliverWebhook(ctx, WebhookDelivery{ID: "fail", Headers: headers}); err == nil || err.Error() != "delivery endpoint answered 503" {
		t.Fatalf("failing endpoint: %v", err)
	}
	must(0, options.Events.OnEvent(ctx, core.NewObject("id", "evt")))
	if len(captured) != 2 || captured[0] != `email {"id":"m1","tenantId":"t","to":"a@example.com","template":"verify-email","payload":{"token":"x"}}` || captured[1] != `events {"id":"evt"}` {
		t.Fatalf("captured %v", captured)
	}
	if len(logged) != 1 || logged[0] != `{"delivery":"sms","message":{"id":"m2","tenantId":"t","to":"+1555","template":"sms-code","payload":{"code":"1"}}}` {
		t.Fatalf("logged %v", logged)
	}
	if len(posted) != 2 || !strings.HasPrefix(posted[0], `k1 {"kind":"webhook","message":{"id":"m3"`) {
		t.Fatalf("posted %v", posted)
	}
	// Client info from headers.
	request, _ := http.NewRequest(http.MethodGet, "http://localhost:3000/", nil)
	request.Header.Set("x-forwarded-for", " 192.0.2.1 , 198.51.100.2")
	request.Header.Set("user-agent", "curl/8")
	request.Header.Set("x-device", "laptop")
	if client := options.HTTP.ClientInfo(request); client.IP != "192.0.2.1" || client.UserAgent != "curl/8" || client.Label != "laptop" {
		t.Fatalf("%+v", client)
	}
	if ClientInfoFunction(core.NewObject("userAgent", false))(request) != nil {
		t.Fatal("no headers read, no client")
	}
	whole := ClientInfoFunction(core.NewObject("ipHeader", "x-forwarded-for", "ipValue", "whole", "userAgent", false))(request)
	if whole.IP != " 192.0.2.1 , 198.51.100.2" {
		t.Fatalf("%+v", whole)
	}
	// Scripted callbacks receive model values and answer for the typed callbacks.
	if required := must(authentication.RequireMfa(ctx, core.NewObject("id", "t"), core.NewObject("id", "i"))); !required {
		t.Fatal("requireMfa")
	}
	if breached := must(authentication.PasswordPolicy.IsBreached(ctx, "hunter2")); !breached {
		t.Fatal("isBreached")
	}
	if message := must(authentication.PasswordPolicy.Check(ctx, "hunter2", auth.PasswordCheckContext{TenantID: "t"})); message != "too predictable" {
		t.Fatal(message)
	}
	if region := must(options.Regions.Locate(ctx, "acme")); *region != "eu" {
		t.Fatal(*region)
	}
	if records := must(options.Domains.ResolveTxt(ctx, "_verify.acme.com")); len(records) != 1 || records[0][1] != "b" {
		t.Fatal(records)
	}
	resolved := must(options.ResolveResource(ctx, core.ResourceRef{TenantID: "t", Type: "doc", ID: "1"}))
	if resolved.Attributes.Get("owner") != "ada" || !resolved.HasClassification || resolved.Classification != nil {
		t.Fatalf("%+v", resolved)
	}
	issued := must(options.Vault.Engines["pg"].Issue(ctx, EngineIssueInput{TenantID: "t", Name: "pg", LeaseID: "l", TtlMs: 1000}))
	if *issued.Value != "secret" || *issued.Handle != "h1" {
		t.Fatal(issued)
	}
	if calls[0] != `authentication.requireMfa [{"id":"t"},{"id":"i"}]` || !strings.HasPrefix(calls[len(calls)-1], `vault.engines.pg.issue [{"tenantId":"t","name":"pg","leaseId":"l","config":null,"ttlMs":1000`) {
		t.Fatalf("calls %v", calls)
	}
}

func TestStandaloneConfigMismatchesAndErrors(t *testing.T) {
	runtime := ConfigRuntime{Adapters: sqliteAdapters()}
	options := must(LoadStandaloneConfig([]byte(`{"secret":"standalone-config-secret-with-at-least-32-characters","baseURL":"http://localhost:3000","billing":{"currency":5},"authentication":{"sessionLifetimeMs":1.5}}`), runtime))
	defer options.Database.Close(context.Background())
	_, err := ResolveConfig(options)
	expectError(t, err, "INVALID_CONFIG", "Invalid better-iam.json: billing.currency must be a string")
	_, err = LoadStandaloneConfig([]byte(`{"secret":`), runtime)
	if err == nil || errorName(err) != "SyntaxError" {
		t.Fatalf("syntax error: %v", err)
	}
	// The CLI's "cli" member is refused like any unknown member, with the TypeScript server's exact message.
	_, err = LoadStandaloneConfig([]byte(`{"secret":"standalone-config-secret-with-at-least-32-characters","baseURL":"http://localhost:3000","cli":{"defaults":{}}}`), runtime)
	expectError(t, err, "INVALID_CONFIG", `Invalid better-iam.json: unknown member "cli"`)
	line := ConfigErrorLine(core.NewIamError("INVALID_CONFIG", "Invalid basePath"))
	if line != `{"error":{"code":"INVALID_CONFIG","status":400,"message":"Invalid basePath"}}` {
		t.Fatal(line)
	}
	if line := ConfigErrorLine(&core.TypeError{Message: "Invalid URL"}); line != `{"error":{"code":"INTERNAL_ERROR","status":500,"message":"Internal server error","thrown":{"name":"TypeError","message":"Invalid URL"}}}` {
		t.Fatal(line)
	}
	if !IsScriptable("vault.rotators.db.rotate") || IsScriptable("vault.rotators.db") || IsScriptable("authentication.sendEmail") {
		t.Fatal("scriptable paths")
	}
}
