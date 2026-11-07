package server

// The standalone server configuration (`better-iam.json`, spec/conformance/CONFIG.md): the Go counterpart of
// scripts/conformance/lib/config.mjs optionsFromConfig. The checks run in the same order with the same messages
// (`Invalid better-iam.json: ...`, INVALID_CONFIG), and the options it returns carry the JSON they were read from as
// their value (OptionsValue), so ResolveConfig and the module settings refuse exactly what the TypeScript server
// refuses for the same file.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// ConfigKeys are the top-level configuration members, in the order CONFIG.md documents them.
var ConfigKeys = []string{
	"$schema", "store", "secret", "previousSecrets", "baseURL", "basePath", "trustedOrigins", "authentication",
	"delivery", "resolveResource", "resolveContext", "hierarchy", "permissions", "onboarding", "events",
	"accessRequests", "observability", "accessUsage", "inference", "a2a", "billing", "ssh", "verifiableCredentials",
	"clearances", "vault", "http", "tenantDefaults", "domains", "hosts", "regions", "sts", "signals", "auditArchive",
}

// jsonOptionKeys are the BetterIamOptions members whose value is copied as JSON.
var jsonOptionKeys = []string{
	"secret", "previousSecrets", "baseURL", "basePath", "trustedOrigins", "hierarchy", "permissions", "onboarding",
	"accessRequests", "accessUsage", "inference", "a2a", "billing", "ssh", "verifiableCredentials", "clearances",
	"tenantDefaults", "hosts", "signals",
}

// ScriptablePaths are the application callbacks a conformance server answers from the recording
// ({"$scripted": true}, CONTROL.md "Script"), as option paths.
var ScriptablePaths = []*regexp.Regexp{
	regexp.MustCompile(`^resolveResource$`),
	regexp.MustCompile(`^resolveContext$`),
	regexp.MustCompile(`^authentication\.requireMfa$`),
	regexp.MustCompile(`^authentication\.passwordPolicy\.(?:isBreached|check)$`),
	regexp.MustCompile(`^domains\.resolveTxt$`),
	regexp.MustCompile(`^regions\.locate$`),
	regexp.MustCompile(`^sts\.webIdentity\.fetchJson$`),
	regexp.MustCompile(`^vault\.rotators\.[^.]+\.rotate$`),
	regexp.MustCompile(`^vault\.engines\.[^.]+\.(?:issue|revoke|renew)$`),
	regexp.MustCompile(`^auditArchive\.write$`),
}

// IsScriptable reports whether a callback at this option path may be scripted.
func IsScriptable(path string) bool {
	for _, pattern := range ScriptablePaths {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// ScriptedCallback answers a scripted application callback: the arguments are model values (as the TypeScript
// callback receives them), the result a model value.
type ScriptedCallback func(ctx context.Context, args ...any) (any, error)

// StoreConfig is the `store` member: the database the configuration names.
type StoreConfig struct {
	// Kind is sqlite, postgres or libsql.
	Kind string
	// Path is the SQLite file (":memory:" by default).
	Path          string
	BusyTimeoutMs *int
	JournalMode   string
	Durability    string
	// URL is the PostgreSQL connection string or the libSQL URL (environment references resolved).
	URL           string
	PoolSize      *int
	LockTimeoutMs *int
	AuthToken     string
	EncryptionKey string
	SyncURL       string
	SyncInterval  *float64
}

// ConfigAdapters open the database a configuration names; a nil adapter is not available.
type ConfigAdapters struct {
	SQLite   func(store StoreConfig) (core.IamStore, error)
	Postgres func(store StoreConfig) (core.IamStore, error)
	LibSQL   func(store StoreConfig) (core.IamStore, error)
}

// ConfigRuntime supplies what JSON cannot (optionsFromConfig's runtime).
type ConfigRuntime struct {
	Adapters ConfigAdapters
	// Env resolves {"env": "NAME"} references (nil: the process environment).
	Env map[string]string
	// Now is the conformance server's injected clock (authentication.now); nil outside conformance mode.
	Now func() int64
	// Wall is the conformance server's wall clock (WallClock); nil outside conformance mode.
	Wall func() int64
	// Deliver receives `capture` deliveries (conformance mode only): kind is email, sms, webhook or events; message
	// is the auth.DeliveryMessage, the WebhookDelivery, or the audit event (*core.Object).
	Deliver func(ctx context.Context, kind string, message any) error
	// Log writes `log` deliveries (default: a line on stdout).
	Log func(line string)
	// Scripted returns the scripted callback for an option path (conformance mode only).
	Scripted func(path string) ScriptedCallback
	// HTTPClient sends `http` deliveries (default: http.DefaultClient).
	HTTPClient *http.Client
}

func configError(message string) *core.IamError {
	return core.NewIamError("INVALID_CONFIG", "Invalid better-iam.json: "+message)
}

func isScriptedMarker(value any) bool {
	o, ok := value.(*core.Object)
	return ok && o != nil && o.Len() == 1 && o.Get("$scripted") == true
}

func secretValue(value any, path string, env func(string) (string, bool)) (string, error) {
	if text, ok := value.(string); ok {
		return text, nil
	}
	if name, ok := member(value, "env").(string); ok && isPlainObject(value) {
		resolved, ok := env(name)
		if !ok || resolved == "" {
			return "", configError(path + " names environment variable " + name + ", which is not set")
		}
		return resolved, nil
	}
	return "", configError(path + ` must be a string or { "env": "NAME" }`)
}

// LoadStandaloneConfig reads a better-iam.json document into options (optionsFromConfig).
func LoadStandaloneConfig(data []byte, runtime ConfigRuntime) (*BetterIamOptions, error) {
	parsed, err := core.ParseJSON(data)
	if err != nil {
		return nil, err
	}
	return OptionsFromConfig(parsed, runtime)
}

// OptionsFromConfig turns a parsed JSON configuration into options.
func OptionsFromConfig(config any, runtime ConfigRuntime) (*BetterIamOptions, error) {
	env := func(name string) (string, bool) {
		if runtime.Env != nil {
			value, ok := runtime.Env[name]
			return value, ok
		}
		return os.LookupEnv(name)
	}
	if !isPlainObject(config) {
		return nil, configError("the configuration must be a JSON object")
	}
	raw := config.(*core.Object)
	for _, key := range raw.Keys() {
		if !containsString(ConfigKeys, key) {
			return nil, configError(`unknown member "` + key + `"`)
		}
	}
	store := coalesce(raw.Get("store"), core.NewObject("kind", "sqlite", "path", ":memory:"))
	if !isPlainObject(store) {
		return nil, configError("store must be an object")
	}
	database, err := openConfiguredStore(store.(*core.Object), runtime.Adapters, env)
	if err != nil {
		return nil, err
	}
	options := &BetterIamOptions{Database: database}
	value := core.NewObject()
	for _, key := range jsonOptionKeys {
		if item := raw.Get(key); !isUndefined(item) {
			value.Set(key, core.CloneValue(item))
		}
	}
	if isUndefined(raw.Get("secret")) {
		return nil, configError("secret is required")
	}
	if options.Secret, err = secretValue(raw.Get("secret"), "secret", env); err != nil {
		return nil, err
	}
	value.Set("secret", options.Secret)
	if previous := raw.Get("previousSecrets"); !isUndefined(previous) {
		list, ok := previous.([]any)
		if !ok {
			return nil, configError("previousSecrets must be an array")
		}
		options.PreviousSecrets = []string{}
		for index, item := range list {
			secret, err := secretValue(item, "previousSecrets["+strconv.Itoa(index)+"]", env)
			if err != nil {
				return nil, err
			}
			options.PreviousSecrets = append(options.PreviousSecrets, secret)
		}
		value.Set("previousSecrets", stringsOf(options.PreviousSecrets))
	}
	baseURL, ok := raw.Get("baseURL").(string)
	if !ok {
		return nil, configError("baseURL is required")
	}
	options.BaseURL = baseURL
	for _, key := range []string{"vault", "domains", "regions", "sts", "auditArchive"} {
		if item := raw.Get(key); !isUndefined(item) {
			value.Set(key, core.CloneValue(item))
		}
	}
	authentication := core.NewObject()
	if given := raw.Get("authentication"); truthy(given) {
		if object, ok := core.CloneValue(given).(*core.Object); ok {
			authentication = object
		}
	}
	value.Set("authentication", authentication)
	if runtime.Now != nil {
		authentication.SetRaw("now", Function{})
	}
	delivery := coalesce(raw.Get("delivery"), core.NewObject())
	if !isPlainObject(delivery) {
		return nil, configError("delivery must be an object")
	}
	for _, key := range delivery.(*core.Object).Keys() {
		if !containsString([]string{"email", "sms", "webhook", "events"}, key) {
			return nil, configError("delivery." + key + " is not a channel")
		}
	}
	transports := map[string]func(ctx context.Context, message any) error{}
	for _, kind := range []string{"email", "sms", "webhook", "events"} {
		transport, err := deliveryTransport(kind, delivery.(*core.Object).Get(kind), runtime)
		if err != nil {
			return nil, err
		}
		if transport != nil {
			transports[kind] = transport
		}
	}
	if transports["email"] != nil {
		authentication.SetRaw("sendEmail", Function{})
	}
	if transports["sms"] != nil {
		authentication.SetRaw("sendSms", Function{})
	}
	if events := raw.Get("events"); !isUndefined(events) || transports["webhook"] != nil || transports["events"] != nil {
		copied := core.CloneValue(coalesce(events, core.NewObject()))
		value.Set("events", copied)
		if object, ok := copied.(*core.Object); ok {
			if transports["webhook"] != nil {
				object.SetRaw("deliverWebhook", Function{})
			}
			if transports["events"] != nil {
				object.SetRaw("onEvent", Function{})
			}
		}
	}
	if observability := raw.Get("observability"); !isUndefined(observability) {
		value.Set("observability", core.CloneValue(observability))
	}
	var clientInfo func(request *http.Request) *core.SessionClientInfo
	if httpOptions := raw.Get("http"); !isUndefined(httpOptions) {
		rest := core.NewObject()
		if object, ok := httpOptions.(*core.Object); ok {
			rest = object.Clone()
		}
		info := rest.Get("clientInfo")
		rest.Delete("clientInfo")
		value.Set("http", rest)
		if !isUndefined(info) {
			if !isPlainObject(info) {
				return nil, configError("http.clientInfo must be an object")
			}
			if ipValue := member(info, "ipValue"); !isUndefined(ipValue) && ipValue != "first" && ipValue != "whole" {
				return nil, configError(`http.clientInfo.ipValue must be "first" or "whole"`)
			}
			clientInfo = ClientInfoFunction(info.(*core.Object))
			rest.SetRaw("clientInfo", Function{})
		}
	}
	echo := false
	if resolver := raw.Get("resolveResource"); !isUndefined(resolver) {
		switch {
		case isScriptedMarker(resolver):
			value.Set("resolveResource", core.NewObject("$scripted", true))
		case !isPlainObject(resolver) || member(resolver, "kind") != "echo":
			return nil, configError(`resolveResource.kind must be "echo"`)
		default:
			echo = true
			value.SetRaw("resolveResource", Function{})
		}
	}
	if resolver := raw.Get("resolveContext"); !isUndefined(resolver) {
		if !isScriptedMarker(resolver) {
			return nil, configError(`resolveContext has no JSON form other than {"$scripted": true}`)
		}
		value.Set("resolveContext", core.NewObject("$scripted", true))
	}
	scripted := map[string]ScriptedCallback{}
	if err := injectScripted(value, "", runtime, scripted); err != nil {
		return nil, err
	}

	// Typed options: read leniently (a JSON value a Go field cannot hold is recorded and refused once validation of
	// the value, which reports it as TypeScript would, has passed).
	decoder := &configDecoder{}
	decoder.decode(value, reflect.ValueOf(options).Elem(), "")
	options.Hierarchy = decodeHierarchy(value.Get("hierarchy"))
	options.Permissions = decodePermissions(value.Get("permissions"))
	options.Authentication = decoder.authentication(authentication)
	options.value = value
	options.mismatches = decoder.mismatches

	// Callbacks.
	if runtime.Now != nil {
		options.Authentication.Now = runtime.Now
	}
	options.WallClock = runtime.Wall
	if send := transports["email"]; send != nil {
		options.Authentication.SendEmail = func(ctx context.Context, message auth.DeliveryMessage) error { return send(ctx, message) }
	}
	if send := transports["sms"]; send != nil {
		options.Authentication.SendSms = func(ctx context.Context, message auth.DeliveryMessage) error { return send(ctx, message) }
	}
	if send := transports["webhook"]; send != nil {
		ensure(&options.Events).DeliverWebhook = func(ctx context.Context, delivery WebhookDelivery) error { return send(ctx, delivery) }
	}
	if send := transports["events"]; send != nil {
		ensure(&options.Events).OnEvent = func(ctx context.Context, event *core.Object) error { return send(ctx, event) }
	}
	if clientInfo != nil {
		ensure(&options.HTTP).ClientInfo = clientInfo
	}
	if echo {
		options.ResolveResource = func(ctx context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			return &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID}, nil
		}
	}
	wireScripted(options, scripted)
	return options, nil
}

// ensure allocates an option section.
func ensure[T any](target **T) *T {
	if *target == nil {
		*target = new(T)
	}
	return *target
}

func openConfiguredStore(store *core.Object, adapters ConfigAdapters, env func(string) (string, bool)) (core.IamStore, error) {
	intOf := func(key string) *int {
		if number, ok := store.Get(key).(float64); ok {
			value := int(number)
			return &value
		}
		return nil
	}
	stringOf := func(key string) string {
		text, _ := store.Get(key).(string)
		return text
	}
	switch store.Get("kind") {
	case "sqlite":
		path := ":memory:"
		if given := store.Get("path"); !nullish(given) {
			path = jsString(given)
		}
		if adapters.SQLite == nil {
			return nil, configError("the sqlite adapter is not available")
		}
		return adapters.SQLite(StoreConfig{Kind: "sqlite", Path: path, BusyTimeoutMs: intOf("busyTimeoutMs"),
			JournalMode: stringOf("journalMode"), Durability: stringOf("durability")})
	case "postgres":
		if adapters.Postgres == nil {
			return nil, configError("the postgres adapter is not available")
		}
		url, err := secretValue(store.Get("url"), "store.url", env)
		if err != nil {
			return nil, err
		}
		return adapters.Postgres(StoreConfig{Kind: "postgres", URL: url, PoolSize: intOf("poolSize"), LockTimeoutMs: intOf("lockTimeoutMs")})
	case "libsql":
		if adapters.LibSQL == nil {
			return nil, configError("the libsql adapter is not available")
		}
		url, err := secretValue(store.Get("url"), "store.url", env)
		if err != nil {
			return nil, err
		}
		config := StoreConfig{Kind: "libsql", URL: url, SyncURL: stringOf("syncUrl")}
		if !isUndefined(store.Get("authToken")) {
			if config.AuthToken, err = secretValue(store.Get("authToken"), "store.authToken", env); err != nil {
				return nil, err
			}
		}
		if !isUndefined(store.Get("encryptionKey")) {
			if config.EncryptionKey, err = secretValue(store.Get("encryptionKey"), "store.encryptionKey", env); err != nil {
				return nil, err
			}
		}
		if interval, ok := store.Get("syncInterval").(float64); ok {
			config.SyncInterval = &interval
		}
		return adapters.LibSQL(config)
	}
	return nil, configError("store.kind must be sqlite, postgres or libsql")
}

// deliveryTransport builds the transport of one delivery channel (nil when the channel is absent).
func deliveryTransport(kind string, spec any, runtime ConfigRuntime) (func(ctx context.Context, message any) error, error) {
	if isUndefined(spec) {
		return nil, nil
	}
	if !isPlainObject(spec) {
		return nil, configError("delivery." + kind + " must be an object")
	}
	switch member(spec, "kind") {
	case "capture":
		if runtime.Deliver == nil {
			return nil, configError("delivery." + kind + ` "capture" needs the server's conformance mode`)
		}
		return func(ctx context.Context, message any) error { return runtime.Deliver(ctx, kind, message) }, nil
	case "log":
		log := runtime.Log
		if log == nil {
			log = func(line string) { fmt.Fprintln(os.Stdout, line) }
		}
		return func(ctx context.Context, message any) error {
			log(core.MustStringify(core.NewObject("delivery", kind, "message", deliveryValue(message))))
			return nil
		}, nil
	case "http":
		url, ok := member(spec, "url").(string)
		if !ok {
			return nil, configError("delivery." + kind + ".url is required")
		}
		headers := http.Header{}
		headers.Set("content-type", "application/json")
		if extra, ok := member(spec, "headers").(*core.Object); ok {
			extra.Entries(func(key string, value any) bool {
				headers.Set(key, jsString(value))
				return true
			})
		}
		timeout := 10_000.0
		if given, ok := member(spec, "timeoutMs").(float64); ok {
			timeout = given
		}
		client := runtime.HTTPClient
		if client == nil {
			client = http.DefaultClient
		}
		return func(ctx context.Context, message any) error {
			body := core.MustStringify(core.NewObject("kind", kind, "message", deliveryValue(message)))
			requestCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
			defer cancel()
			request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, url, bytes.NewReader(utf8Bytes(body)))
			if err != nil {
				return err
			}
			request.Header = headers.Clone()
			response, err := client.Do(request)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode > 299 {
				return fmt.Errorf("delivery endpoint answered %d", response.StatusCode)
			}
			return nil
		}, nil
	}
	return nil, configError("delivery." + kind + ".kind must be capture, log or http")
}

// deliveryValue is a delivery message as a model value.
func deliveryValue(message any) any {
	switch value := message.(type) {
	case *core.Object:
		return value
	case WebhookDelivery:
		return core.NewObject("id", value.ID, "tenantId", value.TenantID, "webhookId", value.WebhookID, "url", value.URL,
			"event", value.Event, "body", value.Body, "headers", value.Headers)
	case auth.DeliveryMessage:
		payload := core.NewObject()
		for _, key := range sortedKeys(value.Payload) {
			payload.Set(key, value.Payload[key])
		}
		out := core.NewObject("id", value.ID, "tenantId", value.TenantID, "to", value.To, "template", value.Template, "payload", payload)
		if value.SignInURL != "" {
			out.Set("signInUrl", value.SignInURL)
		}
		return out
	}
	return core.Normalize(message)
}

// ClientInfoFunction is the http.clientInfo(request) function of the JSON form {userAgent?, ipHeader?, labelHeader?,
// ipValue?}: the User-Agent (unless userAgent is false), the client IP from ipHeader (its first comma-separated
// entry, trimmed, or with ipValue "whole" the header as sent) and the device label from labelHeader; no client when
// none is present.
func ClientInfoFunction(spec *core.Object) func(request *http.Request) *core.SessionClientInfo {
	userAgent := coalesce(spec.Get("userAgent"), true)
	ipHeader := spec.Get("ipHeader")
	labelHeader := spec.Get("labelHeader")
	whole := spec.Get("ipValue") == "whole"
	return func(request *http.Request) *core.SessionClientInfo {
		info := &core.SessionClientInfo{}
		found := false
		if truthy(ipHeader) {
			header, present := headerGet(request.Header, jsString(ipHeader))
			ip := header
			if present && !whole {
				first, _, _ := strings.Cut(header, ",")
				ip = core.JSTrim(first)
			}
			if ip != "" {
				info.IP = ip
				found = true
			}
		}
		if truthy(userAgent) {
			if agent, _ := headerGet(request.Header, "user-agent"); agent != "" {
				info.UserAgent = agent
				found = true
			}
		}
		if truthy(labelHeader) {
			if label, _ := headerGet(request.Header, jsString(labelHeader)); label != "" {
				info.Label = label
				found = true
			}
		}
		if !found {
			return nil
		}
		return info
	}
}

// injectScripted replaces every {"$scripted": true} of the options value with a Function marker, refusing markers
// at paths that cannot be scripted or outside conformance mode, and records the scripted callbacks by path.
func injectScripted(value any, path string, runtime ConfigRuntime, scripted map[string]ScriptedCallback) error {
	switch v := value.(type) {
	case []any:
		for index, item := range v {
			itemPath := path + "[" + strconv.Itoa(index) + "]"
			if isScriptedMarker(item) {
				return scriptedMarker(itemPath, runtime, scripted)
			}
			if err := injectScripted(item, itemPath, runtime, scripted); err != nil {
				return err
			}
		}
	case *core.Object:
		for _, key := range v.Keys() {
			item := v.Get(key)
			itemPath := key
			if path != "" {
				itemPath = path + "." + key
			}
			if isScriptedMarker(item) {
				if err := scriptedMarker(itemPath, runtime, scripted); err != nil {
					return err
				}
				v.SetRaw(key, Function{})
				continue
			}
			if err := injectScripted(item, itemPath, runtime, scripted); err != nil {
				return err
			}
		}
	}
	return nil
}

func scriptedMarker(path string, runtime ConfigRuntime, scripted map[string]ScriptedCallback) error {
	if !IsScriptable(path) {
		return configError(path + " cannot be scripted")
	}
	if runtime.Scripted == nil {
		return configError(path + " is scripted, which needs the server's conformance mode")
	}
	scripted[path] = runtime.Scripted(path)
	return nil
}

// wireScripted sets the typed callbacks of the scripted option paths.
func wireScripted(options *BetterIamOptions, scripted map[string]ScriptedCallback) {
	for path, callback := range scripted {
		call := callback
		switch {
		case path == "resolveResource":
			options.ResolveResource = func(ctx context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
				result, err := call(ctx, core.NewObject("tenantId", reference.TenantID, "type", reference.Type, "id", reference.ID))
				if err != nil {
					return nil, err
				}
				return resolvedResourceOf(result), nil
			}
		case path == "resolveContext":
			options.ResolveContext = func(ctx context.Context, principal *Principal) (*core.Object, error) {
				argument := core.NewObject("identity", principal.Identity, "session", principal.Session)
				if principal.DeviceProof != "" {
					argument.Set("deviceProof", principal.DeviceProof)
				}
				result, err := call(ctx, argument)
				if err != nil {
					return nil, err
				}
				object, _ := result.(*core.Object)
				return object, nil
			}
		case path == "authentication.requireMfa":
			options.Authentication.RequireMfa = func(ctx context.Context, tenant, identity *core.Object) (bool, error) {
				result, err := call(ctx, tenant, identity)
				return truthy(result), err
			}
		case path == "authentication.passwordPolicy.isBreached":
			ensure(&options.Authentication.PasswordPolicy).IsBreached = func(ctx context.Context, password string) (bool, error) {
				result, err := call(ctx, password)
				return truthy(result), err
			}
		case path == "authentication.passwordPolicy.check":
			ensure(&options.Authentication.PasswordPolicy).Check = func(ctx context.Context, password string, check auth.PasswordCheckContext) (string, error) {
				argument := core.NewObject("tenantId", check.TenantID)
				if check.Identity != nil {
					argument.Set("identity", check.Identity)
				}
				result, err := call(ctx, password, argument)
				message, _ := result.(string)
				return message, err
			}
		case path == "domains.resolveTxt":
			ensure(&options.Domains).ResolveTxt = func(ctx context.Context, hostname string) ([][]string, error) {
				result, err := call(ctx, hostname)
				if err != nil {
					return nil, err
				}
				var records [][]string
				list, _ := result.([]any)
				for _, entry := range list {
					parts, _ := entry.([]any)
					record := make([]string, len(parts))
					for index, part := range parts {
						record[index] = jsString(part)
					}
					records = append(records, record)
				}
				return records, nil
			}
		case path == "regions.locate":
			ensure(&options.Regions).Locate = func(ctx context.Context, alias string) (*string, error) {
				result, err := call(ctx, alias)
				if text, ok := result.(string); ok {
					return &text, err
				}
				return nil, err
			}
		case path == "sts.webIdentity.fetchJson":
			ensure(&ensure(&options.Sts).WebIdentity).FetchJSON = func(ctx context.Context, url string) (any, error) {
				return call(ctx, url)
			}
		case path == "auditArchive.write":
			ensure(&options.AuditArchive).Write = func(ctx context.Context, batch AuditArchiveBatch) error {
				_, err := call(ctx, core.Normalize(batch))
				return err
			}
		case strings.HasPrefix(path, "vault.rotators."):
			name := strings.TrimSuffix(strings.TrimPrefix(path, "vault.rotators."), ".rotate")
			vault := ensure(&options.Vault)
			if vault.Rotators == nil {
				vault.Rotators = map[string]VaultRotator{}
			}
			vault.Rotators[name] = VaultRotator{Rotate: func(ctx context.Context, input RotatorInput) error {
				_, err := call(ctx, core.Normalize(input))
				return err
			}}
		case strings.HasPrefix(path, "vault.engines."):
			rest := strings.TrimPrefix(path, "vault.engines.")
			dot := strings.LastIndex(rest, ".")
			name, method := rest[:dot], rest[dot+1:]
			vault := ensure(&options.Vault)
			if vault.Engines == nil {
				vault.Engines = map[string]VaultEngine{}
			}
			engine := vault.Engines[name]
			switch method {
			case "issue":
				engine.Issue = func(ctx context.Context, input EngineIssueInput) (*EngineIssued, error) {
					result, err := call(ctx, core.Normalize(input))
					if err != nil {
						return nil, err
					}
					issued := &EngineIssued{}
					if value, ok := member(result, "value").(string); ok {
						issued.Value = &value
					}
					issued.Fields, _ = member(result, "fields").(*core.Object)
					if handle, ok := member(result, "handle").(string); ok {
						issued.Handle = &handle
					}
					return issued, nil
				}
			case "revoke":
				engine.Revoke = func(ctx context.Context, input EngineLeaseInput) error {
					_, err := call(ctx, core.Normalize(input))
					return err
				}
			case "renew":
				engine.Renew = func(ctx context.Context, input EngineLeaseInput) error {
					_, err := call(ctx, core.Normalize(input))
					return err
				}
			}
			vault.Engines[name] = engine
		}
	}
}

// resolvedResourceOf reads a resolver's answer (a model value).
func resolvedResourceOf(value any) *ResolvedResource {
	if !isPlainObject(value) {
		return nil
	}
	resolved := &ResolvedResource{
		TenantID: jsString(member(value, "tenantId")), Type: jsString(member(value, "type")), ID: jsString(member(value, "id")),
	}
	resolved.Attributes, _ = member(value, "attributes").(*core.Object)
	if object := value.(*core.Object); object.Has("classification") && !isUndefined(object.Get("classification")) {
		resolved.HasClassification = true
		resolved.Classification = object.Get("classification")
	}
	return resolved
}

// --- lenient typed decoding ----------------------------------------------------------------------------------------

type configDecoder struct {
	mismatches []string
}

func (d *configDecoder) mismatch(path, expected string) {
	d.mismatches = append(d.mismatches, path+" must be "+expected)
}

var objectType = reflect.TypeOf((*core.Object)(nil))
var anyType = reflect.TypeOf((*any)(nil)).Elem()

// toggleConfig is implemented by Toggle[T] (boolean | options).
type toggleConfig interface {
	decodeConfig(d *configDecoder, value any, path string)
}

func (t *Toggle[T]) decodeConfig(d *configDecoder, value any, path string) {
	switch v := value.(type) {
	case bool:
		t.Enabled = v
	case *core.Object:
		t.Enabled = true
		t.Options = new(T)
		d.decode(v, reflect.ValueOf(t.Options).Elem(), path)
	default:
		d.mismatch(path, "a boolean or an object")
	}
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// decode reads a model value into a Go value through its json tags; Function markers and JSON null leave the zero
// value; values of the wrong kind are recorded as mismatches.
func (d *configDecoder) decode(value any, target reflect.Value, path string) {
	if nullish(value) {
		return
	}
	if _, isFunction := value.(Function); isFunction {
		return
	}
	if target.Type() == objectType {
		if object, ok := value.(*core.Object); ok {
			target.Set(reflect.ValueOf(object))
		} else {
			d.mismatch(path, "an object")
		}
		return
	}
	if target.Type() == anyType {
		target.Set(reflect.ValueOf(&value).Elem())
		return
	}
	if target.CanAddr() {
		if toggle, ok := target.Addr().Interface().(toggleConfig); ok {
			toggle.decodeConfig(d, value, path)
			return
		}
	}
	switch target.Kind() {
	case reflect.Pointer:
		if target.Type().Elem() == objectType.Elem() {
			d.decode(value, target, path)
			return
		}
		element := reflect.New(target.Type().Elem())
		before := len(d.mismatches)
		d.decode(value, element.Elem(), path)
		if len(d.mismatches) == before {
			target.Set(element)
		}
	case reflect.String:
		if text, ok := value.(string); ok {
			target.SetString(text)
		} else {
			d.mismatch(path, "a string")
		}
	case reflect.Bool:
		if flag, ok := value.(bool); ok {
			target.SetBool(flag)
		} else {
			d.mismatch(path, "a boolean")
		}
	case reflect.Float64:
		if number, ok := value.(float64); ok {
			target.SetFloat(number)
		} else {
			d.mismatch(path, "a number")
		}
	case reflect.Int, reflect.Int64:
		if number, ok := value.(float64); ok && core.IsSafeInteger(number) {
			target.SetInt(int64(number))
		} else {
			d.mismatch(path, "an integer")
		}
	case reflect.Slice:
		list, ok := value.([]any)
		if !ok {
			d.mismatch(path, "an array")
			return
		}
		slice := reflect.MakeSlice(target.Type(), len(list), len(list))
		for index, item := range list {
			d.decode(item, slice.Index(index), path+"["+strconv.Itoa(index)+"]")
		}
		target.Set(slice)
	case reflect.Map:
		object, ok := value.(*core.Object)
		if !ok {
			d.mismatch(path, "an object")
			return
		}
		m := reflect.MakeMap(target.Type())
		object.Entries(func(key string, item any) bool {
			element := reflect.New(target.Type().Elem()).Elem()
			d.decode(item, element, joinPath(path, key))
			m.SetMapIndex(reflect.ValueOf(key), element)
			return true
		})
		target.Set(m)
	case reflect.Struct:
		object, ok := value.(*core.Object)
		if !ok {
			d.mismatch(path, "an object")
			return
		}
		structType := target.Type()
		for index := 0; index < structType.NumField(); index++ {
			field := structType.Field(index)
			if !field.IsExported() || field.Type.Kind() == reflect.Func {
				continue
			}
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "-" || name == "" {
				continue
			}
			d.decode(object.Get(name), target.Field(index), joinPath(path, name))
		}
	}
}

// authentication reads the authentication member into auth.Options.
func (d *configDecoder) authentication(value *core.Object) *auth.Options {
	options := &auth.Options{}
	text := func(key string, target *string) {
		if item := value.Get(key); !nullish(item) {
			if s, ok := item.(string); ok {
				*target = s
			} else {
				d.mismatch("authentication."+key, "a string")
			}
		}
	}
	flag := func(object *core.Object, path string, target *bool) {
		if item := member(object, path[strings.LastIndex(path, ".")+1:]); !nullish(item) {
			if b, ok := item.(bool); ok {
				*target = b
			} else {
				d.mismatch(path, "a boolean")
			}
		}
	}
	optionalFlag := func(object *core.Object, path string) *bool {
		var result bool
		item := member(object, path[strings.LastIndex(path, ".")+1:])
		if nullish(item) {
			return nil
		}
		before := len(d.mismatches)
		flag(object, path, &result)
		if len(d.mismatches) != before {
			return nil
		}
		return &result
	}
	integer := func(object *core.Object, path string) *int64 {
		item := member(object, path[strings.LastIndex(path, ".")+1:])
		if nullish(item) {
			return nil
		}
		number, ok := item.(float64)
		if !ok || !core.IsSafeInteger(number) {
			d.mismatch(path, "an integer")
			return nil
		}
		result := int64(number)
		return &result
	}
	text("appName", &options.AppName)
	flag(value, "authentication.signUpEnabled", &options.SignUpEnabled)
	options.RequireEmailVerification = optionalFlag(value, "authentication.requireEmailVerification")
	options.EmailPassword = optionalFlag(value, "authentication.emailPassword")
	flag(value, "authentication.passwordlessEmail", &options.PasswordlessEmail)
	flag(value, "authentication.passwordlessSms", &options.PasswordlessSms)
	options.MaxDeliveryAttempts = integer(value, "authentication.maxDeliveryAttempts")
	options.SessionLifetimeMs = integer(value, "authentication.sessionLifetimeMs")
	options.SessionIdleTimeoutMs = integer(value, "authentication.sessionIdleTimeoutMs")
	options.RecentAuthenticationMs = integer(value, "authentication.recentAuthenticationMs")
	options.TrustedDeviceLifetimeMs = integer(value, "authentication.trustedDeviceLifetimeMs")
	flag(value, "authentication.signInNotifications", &options.SignInNotifications)
	flag(value, "authentication.mfaEmailCodes", &options.MfaEmailCodes)
	if alerts := integer(value, "authentication.failedSignInAlerts"); alerts != nil {
		options.FailedSignInAlerts = *alerts
	}
	if limits, ok := value.Get("rateLimits").(*core.Object); ok {
		options.RateLimits = &auth.RateLimitOptions{
			Attempts:          integer(limits, "authentication.rateLimits.attempts"),
			SensitiveAttempts: integer(limits, "authentication.rateLimits.sensitiveAttempts"),
			WindowMs:          integer(limits, "authentication.rateLimits.windowMs"),
			IPAttempts:        integer(limits, "authentication.rateLimits.ipAttempts"),
		}
	} else if !nullish(value.Get("rateLimits")) {
		d.mismatch("authentication.rateLimits", "an object")
	}
	if passkeys, ok := value.Get("passkeys").(*core.Object); ok {
		options.Passkeys = &auth.PasskeyOptions{}
		if rpID, ok := passkeys.Get("rpID").(string); ok {
			options.Passkeys.RPID = rpID
		} else if !nullish(passkeys.Get("rpID")) {
			d.mismatch("authentication.passkeys.rpID", "a string")
		}
		if rpName, ok := passkeys.Get("rpName").(string); ok {
			options.Passkeys.RPName = rpName
		} else if !nullish(passkeys.Get("rpName")) {
			d.mismatch("authentication.passkeys.rpName", "a string")
		}
	} else if !nullish(value.Get("passkeys")) {
		d.mismatch("authentication.passkeys", "an object")
	}
	if policy, ok := value.Get("passwordPolicy").(*core.Object); ok {
		options.PasswordPolicy = &auth.PasswordPolicyOptions{
			BlockCommonPasswords: optionalFlag(policy, "authentication.passwordPolicy.blockCommonPasswords"),
		}
	} else if !nullish(value.Get("passwordPolicy")) {
		d.mismatch("authentication.passwordPolicy", "an object")
	}
	return options
}

// decodeHierarchy reads a hierarchy model value (validated by ResolveConfig).
func decodeHierarchy(value any) *core.HierarchyConfig {
	if !isPlainObject(value) {
		return nil
	}
	hierarchy := &core.HierarchyConfig{}
	for _, entry := range objectEntries(member(value, "types")) {
		named := core.NamedTenantType{Name: entry.key, Type: core.TenantType{AllowedChildren: []string{}}}
		children, _ := member(entry.value, "allowedChildren").([]any)
		for _, child := range children {
			named.Type.AllowedChildren = append(named.Type.AllowedChildren, jsString(child))
		}
		hierarchy.Types = append(hierarchy.Types, named)
	}
	if depth, ok := member(value, "maxDepth").(float64); ok && core.IsSafeInteger(depth) {
		maxDepth := int(depth)
		hierarchy.MaxDepth = &maxDepth
	}
	return hierarchy
}

// attributeList reads a Record<string, AttributeType> model value.
func attributeList(value any) []core.NamedAttribute {
	var attributes []core.NamedAttribute
	for _, entry := range objectEntries(value) {
		attributes = append(attributes, core.NamedAttribute{Name: entry.key, Type: jsString(entry.value)})
	}
	return attributes
}

func stringList(value any) []string {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(list))
	for index, item := range list {
		out[index] = jsString(item)
	}
	return out
}

// decodePermissions reads a permissions model value (validated by the catalog).
func decodePermissions(value any) *core.PermissionsConfig {
	if !isPlainObject(value) {
		return nil
	}
	permissions := &core.PermissionsConfig{Actions: stringList(member(value, "actions"))}
	permissions.Mode, _ = member(value, "mode").(string)
	if types := member(value, "resourceTypes"); isPlainObject(types) {
		permissions.ResourceTypes = []core.NamedResourceType{}
		for _, entry := range objectEntries(types) {
			definition := core.ResourceTypeDefinition{
				Actions: stringList(member(entry.value, "actions")), Relations: stringList(member(entry.value, "relations")),
				Managed: truthy(member(entry.value, "managed")),
			}
			definition.Description, _ = member(entry.value, "description").(string)
			definition.Parent, _ = member(entry.value, "parent").(string)
			if attributes := member(entry.value, "attributes"); isPlainObject(attributes) {
				definition.Attributes = attributeList(attributes)
			}
			permissions.ResourceTypes = append(permissions.ResourceTypes, core.NamedResourceType{Name: entry.key, Definition: definition})
		}
	}
	if attributes := member(value, "identityAttributes"); isPlainObject(attributes) {
		permissions.IdentityAttributes = attributeList(attributes)
	}
	return permissions
}

// errorName is the JavaScript name of an error (error.name).
func errorName(err error) string {
	if named, ok := err.(interface{ Name() string }); ok {
		return named.Name()
	}
	var typeError *core.TypeError
	var syntaxError *core.SyntaxError
	switch {
	case errors.As(err, &typeError):
		return "TypeError"
	case errors.As(err, &syntaxError):
		return "SyntaxError"
	}
	return "Error"
}

// ConfigErrorLine is the one JSON line a standalone server writes to stderr when it cannot start (CONTROL.md,
// "Startup"): {"error": {"code", "status", "message"}} for an IamError, otherwise the INTERNAL_ERROR shape with the
// thrown error's name and message (scripts/conformance/lib/encode.mjs errorShape).
func ConfigErrorLine(err error) string {
	var shape *core.Object
	var known *core.IamError
	if errors.As(err, &known) {
		shape = core.NewObject("code", known.Code, "status", float64(known.Status), "message", known.Message)
		var limited *auth.RateLimitedError
		if errors.As(err, &limited) && limited.RetryAfterMs > 0 {
			shape.Set("retryAfterMs", float64(limited.RetryAfterMs))
		}
	} else {
		shape = core.NewObject("code", "INTERNAL_ERROR", "status", 500.0, "message", "Internal server error",
			"thrown", core.NewObject("name", errorName(err), "message", err.Error()))
	}
	return core.MustStringify(core.NewObject("error", shape))
}
