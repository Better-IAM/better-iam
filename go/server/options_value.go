package server

// The options as a model value: what the TypeScript validators see when they read `options` (resolveConfig, the
// catalog, and the module settings resolvers). Members are spelled as in TypeScript; callbacks appear as Function
// markers; absent options are absent. Options read from a standalone JSON file (LoadStandaloneConfig) carry the JSON
// they were read from, with callbacks the reader supplied (deliveries, scripted callbacks) as Function markers.

import (
	"encoding/json"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// OptionsValue returns the options as a model value. The result must be treated as read-only.
func OptionsValue(options *BetterIamOptions) *core.Object {
	if options == nil {
		return core.NewObject()
	}
	if options.value != nil {
		return options.value
	}
	encoded, err := json.Marshal(*options)
	if err != nil {
		// Every member without a JSON form is tagged `json:"-"`; reaching this is a bug in the option types.
		panic("server: options have no JSON form: " + err.Error())
	}
	value, ok := core.Normalize(json.RawMessage(encoded)).(*core.Object)
	if !ok || value == nil {
		panic("server: options did not encode as an object")
	}
	if options.Database != nil {
		value.SetRaw("database", Function{})
	}
	if options.Authentication != nil {
		value.Set("authentication", AuthOptionsValue(options.Authentication))
	}
	if options.Hierarchy != nil {
		value.Set("hierarchy", HierarchyValue(options.Hierarchy))
	}
	if options.Permissions != nil {
		value.Set("permissions", PermissionsValue(options.Permissions))
	}
	if options.Plugins != nil {
		plugins := make([]any, len(options.Plugins))
		for index, plugin := range options.Plugins {
			plugins[index] = PluginValue(plugin)
		}
		value.Set("plugins", plugins)
	}
	if options.Protocols != nil {
		protocols := make([]any, len(options.Protocols))
		for index, protocol := range options.Protocols {
			mount := core.NewObject()
			if protocol.Handle != nil {
				mount.SetRaw("handle", Function{})
			}
			protocols[index] = mount
		}
		value.Set("protocols", protocols)
	}
	if options.ResolveResource != nil {
		value.SetRaw("resolveResource", Function{})
	}
	if options.ResolveContext != nil {
		value.SetRaw("resolveContext", Function{})
	}
	markFunction := func(section string, path []string, present bool) {
		if !present {
			return
		}
		target, _ := value.Get(section).(*core.Object)
		if target == nil {
			target = core.NewObject()
			value.Set(section, target)
		}
		for _, key := range path[:len(path)-1] {
			next, _ := target.Get(key).(*core.Object)
			if next == nil {
				next = core.NewObject()
				target.Set(key, next)
			}
			target = next
		}
		target.SetRaw(path[len(path)-1], Function{})
	}
	if options.Events != nil {
		markFunction("events", []string{"onEvent"}, options.Events.OnEvent != nil)
		markFunction("events", []string{"deliverWebhook"}, options.Events.DeliverWebhook != nil)
	}
	if options.AuditArchive != nil {
		markFunction("auditArchive", []string{"write"}, options.AuditArchive.Write != nil)
	}
	if options.Observability != nil {
		markFunction("observability", []string{"onSpan"}, options.Observability.OnSpan != nil)
	}
	if options.HTTP != nil {
		markFunction("http", []string{"clientInfo"}, options.HTTP.ClientInfo != nil)
	}
	if options.Domains != nil {
		markFunction("domains", []string{"resolveTxt"}, options.Domains.ResolveTxt != nil)
	}
	if options.Regions != nil {
		markFunction("regions", []string{"locate"}, options.Regions.Locate != nil)
	}
	if options.Sts != nil && options.Sts.WebIdentity != nil {
		markFunction("sts", []string{"webIdentity", "fetchJson"}, options.Sts.WebIdentity.FetchJSON != nil)
	}
	if options.Vault != nil {
		vault, _ := value.Get("vault").(*core.Object)
		if vault == nil {
			vault = core.NewObject()
			value.Set("vault", vault)
		}
		if options.Vault.Rotators != nil {
			rotators := core.NewObject()
			for _, name := range sortedKeys(options.Vault.Rotators) {
				rotator := core.NewObject()
				if options.Vault.Rotators[name].Rotate != nil {
					rotator.SetRaw("rotate", Function{})
				}
				rotators.Set(name, rotator)
			}
			vault.Set("rotators", rotators)
		}
		if options.Vault.Engines != nil {
			engines := core.NewObject()
			for _, name := range sortedKeys(options.Vault.Engines) {
				engine := core.NewObject()
				spec := options.Vault.Engines[name]
				for _, item := range []struct {
					key     string
					present bool
				}{{"issue", spec.Issue != nil}, {"revoke", spec.Revoke != nil}, {"renew", spec.Renew != nil}} {
					if item.present {
						engine.SetRaw(item.key, Function{})
					}
				}
				engines.Set(name, engine)
			}
			vault.Set("engines", engines)
		}
	}
	return value
}

// sortedKeys lists a map's keys in UTF-16 order (Go maps have no insertion order).
func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sortStrings(keys)
	return keys
}

// sortStrings sorts in place by UTF-16 code units (Array.prototype.sort's default order for strings).
func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && compareUTF16(items[j], items[j-1]) < 0; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

// AuthOptionsValue is auth.Options as the TypeScript AuthOptions model value (`authentication`).
func AuthOptionsValue(options *auth.Options) *core.Object {
	value := core.NewObject()
	if options == nil {
		return value
	}
	if options.AppName != "" {
		value.Set("appName", options.AppName)
	}
	if options.SignUpEnabled {
		value.Set("signUpEnabled", true)
	}
	setBool := func(key string, item *bool) {
		if item != nil {
			value.Set(key, *item)
		}
	}
	setInt := func(target *core.Object, key string, item *int64) {
		if item != nil {
			target.Set(key, float64(*item))
		}
	}
	setBool("requireEmailVerification", options.RequireEmailVerification)
	setBool("emailPassword", options.EmailPassword)
	if options.PasswordlessEmail {
		value.Set("passwordlessEmail", true)
	}
	if options.PasswordlessSms {
		value.Set("passwordlessSms", true)
	}
	if options.SendEmail != nil {
		value.SetRaw("sendEmail", Function{})
	}
	if options.SendSms != nil {
		value.SetRaw("sendSms", Function{})
	}
	if options.DeliverWebhook != nil {
		value.SetRaw("deliverWebhook", Function{})
	}
	setInt(value, "maxDeliveryAttempts", options.MaxDeliveryAttempts)
	setInt(value, "sessionLifetimeMs", options.SessionLifetimeMs)
	setInt(value, "sessionIdleTimeoutMs", options.SessionIdleTimeoutMs)
	setInt(value, "recentAuthenticationMs", options.RecentAuthenticationMs)
	setInt(value, "trustedDeviceLifetimeMs", options.TrustedDeviceLifetimeMs)
	if options.SignInNotifications {
		value.Set("signInNotifications", true)
	}
	if options.MfaEmailCodes {
		value.Set("mfaEmailCodes", true)
	}
	if options.FailedSignInAlerts != 0 {
		value.Set("failedSignInAlerts", float64(options.FailedSignInAlerts))
	}
	if limits := options.RateLimits; limits != nil {
		rate := core.NewObject()
		setInt(rate, "attempts", limits.Attempts)
		setInt(rate, "sensitiveAttempts", limits.SensitiveAttempts)
		setInt(rate, "windowMs", limits.WindowMs)
		setInt(rate, "ipAttempts", limits.IPAttempts)
		if limits.Limiter != nil {
			rate.SetRaw("limiter", Function{})
		}
		value.Set("rateLimits", rate)
	}
	if options.RequireMfa != nil {
		value.SetRaw("requireMfa", Function{})
	}
	if passkeys := options.Passkeys; passkeys != nil {
		item := core.NewObject("rpID", passkeys.RPID)
		if passkeys.RPName != "" {
			item.Set("rpName", passkeys.RPName)
		}
		value.Set("passkeys", item)
	}
	if options.OnAudit != nil {
		value.SetRaw("onAudit", Function{})
	}
	if options.Now != nil {
		value.SetRaw("now", Function{})
	}
	if policy := options.PasswordPolicy; policy != nil {
		item := core.NewObject()
		if policy.BlockCommonPasswords != nil {
			item.Set("blockCommonPasswords", *policy.BlockCommonPasswords)
		}
		if policy.IsBreached != nil {
			item.SetRaw("isBreached", Function{})
		}
		if policy.Check != nil {
			item.SetRaw("check", Function{})
		}
		value.Set("passwordPolicy", item)
	}
	return value
}

// HierarchyValue is a HierarchyConfig as its TypeScript model value.
func HierarchyValue(hierarchy *core.HierarchyConfig) *core.Object {
	types := core.NewObject()
	for _, entry := range hierarchy.Types {
		children := entry.Type.AllowedChildren
		if children == nil {
			children = []string{}
		}
		types.Set(entry.Name, core.NewObject("allowedChildren", stringsOf(children)))
	}
	value := core.NewObject("types", types)
	if hierarchy.MaxDepth != nil {
		value.Set("maxDepth", float64(*hierarchy.MaxDepth))
	}
	return value
}

// attributesValue is an ordered attribute list as a TypeScript Record<string, AttributeType>.
func attributesValue(attributes []core.NamedAttribute) *core.Object {
	value := core.NewObject()
	for _, attribute := range attributes {
		value.Set(attribute.Name, attribute.Type)
	}
	return value
}

// ResourceTypesValue is a resource type list as the TypeScript Record<string, ResourceTypeDefinition>.
func ResourceTypesValue(types []core.NamedResourceType) *core.Object {
	value := core.NewObject()
	for _, entry := range types {
		definition := core.NewObject()
		d := entry.Definition
		if d.Description != "" {
			definition.Set("description", d.Description)
		}
		if d.Actions != nil {
			definition.Set("actions", stringsOf(d.Actions))
		}
		if d.Attributes != nil {
			definition.Set("attributes", attributesValue(d.Attributes))
		}
		if d.Parent != "" {
			definition.Set("parent", d.Parent)
		}
		if d.Managed {
			definition.Set("managed", true)
		}
		if d.Relations != nil {
			definition.Set("relations", stringsOf(d.Relations))
		}
		value.Set(entry.Name, definition)
	}
	return value
}

// PermissionsValue is a PermissionsConfig as its TypeScript model value.
func PermissionsValue(permissions *core.PermissionsConfig) *core.Object {
	value := core.NewObject()
	if permissions.Mode != "" {
		value.Set("mode", permissions.Mode)
	}
	if permissions.Actions != nil {
		value.Set("actions", stringsOf(permissions.Actions))
	}
	if permissions.ResourceTypes != nil {
		value.Set("resourceTypes", ResourceTypesValue(permissions.ResourceTypes))
	}
	if permissions.IdentityAttributes != nil {
		value.Set("identityAttributes", attributesValue(permissions.IdentityAttributes))
	}
	return value
}

// PluginValue is an IamPlugin as its TypeScript model value (callbacks as Function markers).
func PluginValue(plugin *core.IamPlugin) *core.Object {
	value := core.NewObject()
	if plugin == nil {
		return value
	}
	value.Set("id", plugin.ID)
	if plugin.Actions != nil {
		value.Set("actions", stringsOf(plugin.Actions))
	}
	if plugin.ResourceTypes != nil {
		value.Set("resourceTypes", ResourceTypesValue(plugin.ResourceTypes))
	}
	if plugin.Endpoints != nil {
		endpoints := make([]any, len(plugin.Endpoints))
		for index, endpoint := range plugin.Endpoints {
			item := core.NewObject("method", endpoint.Method, "path", endpoint.Path, "action", endpoint.Action)
			if endpoint.Validate != nil {
				item.SetRaw("validate", Function{})
			}
			if endpoint.Resource != nil {
				item.SetRaw("resource", Function{})
			}
			if endpoint.Handler != nil {
				item.SetRaw("handler", Function{})
			}
			endpoints[index] = item
		}
		value.Set("endpoints", endpoints)
	}
	for _, item := range []struct {
		key     string
		present bool
	}{
		{"validateConfig", plugin.ValidateConfig != nil}, {"migrate", plugin.Migrate != nil},
		{"resolveContext", plugin.ResolveContext != nil}, {"afterAudit", plugin.AfterAudit != nil},
		{"purge", plugin.Purge != nil},
	} {
		if item.present {
			value.SetRaw(item.key, Function{})
		}
	}
	if plugin.Hooks != nil {
		hooks := core.NewObject()
		if plugin.Hooks.BeforeOperation != nil {
			hooks.SetRaw("beforeOperation", Function{})
		}
		if plugin.Hooks.AfterOperation != nil {
			hooks.SetRaw("afterOperation", Function{})
		}
		value.Set("hooks", hooks)
	}
	return value
}
