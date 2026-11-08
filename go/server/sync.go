package server

// Port of packages/server/src/sync.ts: declarative tenant configuration ("configuration as code"). The roles,
// policies, groups, tenant-defined resource types, group role bindings, access packages, invariants, agreements,
// teams, departments, and AI kinds of one tenant, keyed by name so the same file applies to several environments.
// Identities, their direct bindings, credentials, and webhooks are runtime state and are not part of it.
//
// A TenantConfig is a model object ({ version: 1, resourceTypes?, policies?, ... }) whose list members are model
// arrays of objects; each item's members follow the TypeScript object literals of validateTenantConfig, with
// core.Undefined where TypeScript leaves a member undefined. A ConfigChange is a model object
// { kind, name, action, fields?, before?, after? }.
//
// The AI kinds go through ai-sync.go: readAiState's result is handed back unchanged to exportAi and planAi; the
// environments are model objects whose members are stored raw (SetRaw) as Go values:
//
//	exportAi names: identityEmails, groupNames (map[string]string)
//	planAi env:     identityEmails, groupNames (map[string]string), identitiesByEmail (map[string]*core.Object),
//	                groupNamesAfter (*orderedSet), prune (bool)
//	planAi result:  { agents, models, budgets }, each a model array of { change, desired?, record? } objects
//	applyAi env:    *SyncApplyEnv

import (
	"context"
	"math"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ConfigAPI is the `config` API group (packages/server/src/sync.ts createConfigApi): every method runs through the
// operation envelope; the router maps POST {basePath}/config/{method} onto it.
type ConfigAPI struct {
	server *ServerContext
}

// CreateConfigAPI builds the `config` API group.
func CreateConfigAPI(server *ServerContext) *ConfigAPI {
	return &ConfigAPI{server: server}
}

// configKindOrder is sync.ts kindOrder.
var configKindOrder = []string{
	"accessPolicy",
	"resourceType",
	"policy",
	"role",
	"group",
	"binding",
	"package",
	"agreement",
	"invariant",
	"department",
	"team",
	"agent",
	"inferenceModel",
	"inferenceBudget",
}

const syncPermissionsSid = "RolePermissions"

// configKindIndex is kindOrder.indexOf(kind).
func configKindIndex(kind string) int {
	for index, item := range configKindOrder {
		if item == kind {
			return index
		}
	}
	return -1
}

// syncCanonicalValue is the value JSON.stringify sees through the canonical replacer: object keys sorted at every
// level, undefined members dropped.
func syncCanonicalValue(value any) any {
	switch v := core.Normalize(value).(type) {
	case *core.Object:
		if v == nil {
			return nil
		}
		keys := []string{}
		v.Entries(func(key string, item any) bool {
			if !isUndefined(item) {
				keys = append(keys, key)
			}
			return true
		})
		sort.SliceStable(keys, func(i, j int) bool { return compareUTF16(keys[i], keys[j]) < 0 })
		out := core.NewObject()
		for _, key := range keys {
			out.SetRaw(key, syncCanonicalValue(v.Get(key)))
		}
		return out
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = syncCanonicalValue(item)
		}
		return out
	default:
		return v
	}
}

// syncCanonical is sync.ts canonical: stable JSON for comparisons (ok is false for undefined).
func syncCanonical(value any) (string, bool) {
	text, ok, err := core.Stringify(syncCanonicalValue(value))
	if err != nil {
		return "", false
	}
	return text, ok
}

// syncSame is sync.ts same.
func syncSame(a, b any) bool {
	x, xok := syncCanonical(a)
	y, yok := syncCanonical(b)
	return xok == yok && x == y
}

// syncSorted is sync.ts sorted: [...new Set(items)].sort().
func syncSorted(items []string) []string { return syncSortedUnique(items) }

// syncSortedList is sorted() as a model array.
func syncSortedList(items []string) []any { return stringsOf(syncSorted(items)) }

// syncDiffFields is sync.ts diffFields (org-sync.ts diff): the keys whose values differ, sorted.
func syncDiffFields(before, after *core.Object) []string {
	keys := newOrderedSet(before.Keys()...)
	for _, key := range after.Keys() {
		keys.Add(key)
	}
	fields := []string{}
	for _, key := range keys.Values() {
		if !syncSame(before.Get(key), after.Get(key)) {
			fields = append(fields, key)
		}
	}
	sort.SliceStable(fields, func(i, j int) bool { return compareUTF16(fields[i], fields[j]) < 0 })
	return fields
}

// syncChange builds a ConfigChange: creates carry `after`, updates `fields`, `before` and `after`, the other actions
// neither.
func syncChange(kind, name, action string, fields []string, before, after any) *core.Object {
	change := core.NewObject("kind", kind, "name", name, "action", action)
	switch action {
	case "create":
		change.Set("after", after)
	case "update":
		change.Set("fields", stringsOf(fields))
		change.Set("before", before)
		change.Set("after", after)
	}
	return change
}

// syncUpdateOrUnchanged is `fields.length ? { ..., action: 'update', fields, before, after } : { ..., action: 'unchanged' }`.
func syncUpdateOrUnchanged(kind, name string, fields []string, before, after any) *core.Object {
	if len(fields) > 0 {
		return syncChange(kind, name, "update", fields, before, after)
	}
	return syncChange(kind, name, "unchanged", nil, nil, nil)
}

func syncChangeAction(change *core.Object) string { return jsString(change.Get("action")) }
func syncChangeName(change *core.Object) string   { return jsString(change.Get("name")) }
func syncChangeKind(change *core.Object) string   { return jsString(change.Get("kind")) }

// syncChangeFields is `change.fields ?? []`.
func syncChangeFields(change *core.Object) []string { return syncStringList(change.Get("fields")) }

// syncConfigItems is a list member of a configuration document: its objects, and whether the member is present.
func syncConfigItems(config *core.Object, key string) ([]*core.Object, bool) {
	list, ok := member(config, key).([]any)
	if !ok {
		return nil, false
	}
	items := make([]*core.Object, 0, len(list))
	for _, item := range list {
		if object, ok := item.(*core.Object); ok {
			items = append(items, object)
		}
	}
	return items, true
}

// syncObjects converts objects into a model array.
func syncObjects(items []*core.Object) []any {
	out := make([]any, len(items))
	for index, item := range items {
		out[index] = item
	}
	return out
}

// syncRoleDocument is sync.ts roleDocument: a role's inline document, from a permissions list or a document; undefined
// when it has neither.
func syncRoleDocument(role *core.Object) (any, error) {
	permissions := role.Get("permissions")
	document := role.Get("document")
	if !isUndefined(permissions) && !isUndefined(document) {
		return nil, invalidInput("Role " + jsString(role.Get("name")) + ": provide permissions or a document")
	}
	if !isUndefined(permissions) {
		return core.NewObject(
			"version", 1.0,
			"statements", []any{core.NewObject(
				"sid", syncPermissionsSid, "effect", "allow", "actions", permissions, "resources", []any{"*"},
			)},
		), nil
	}
	return document, nil
}

// syncExportedDocument is sync.ts exportedDocument: a stored inline document as a permissions list when it is exactly
// the compiled form.
func syncExportedDocument(document any) *core.Object {
	if !truthy(document) {
		return core.NewObject()
	}
	statements, _ := member(document, "statements").([]any)
	var statement any = core.Undefined
	if len(statements) > 0 {
		statement = statements[0]
	}
	resources, _ := member(statement, "resources").([]any)
	if len(statements) == 1 && truthy(statement) &&
		member(statement, "sid") == syncPermissionsSid &&
		member(statement, "effect") == "allow" &&
		len(resources) == 1 && resources[0] == "*" &&
		!truthy(member(statement, "conditions")) {
		actions, _ := member(statement, "actions").([]any)
		return core.NewObject("permissions", append([]any{}, actions...))
	}
	return core.NewObject("document", document)
}

// syncUniqueNames is sync.ts names: refuses duplicate names.
func syncUniqueNames(names []string, kind string) error {
	seen := newOrderedSet()
	for _, name := range names {
		if seen.Has(name) {
			return invalidInput("Duplicate " + kind + " " + name)
		}
		seen.Add(name)
	}
	return nil
}

// syncValidator holds the field helpers of validateTenantConfig.
type syncValidator struct{}

func (syncValidator) optionalText(item *core.Object, key string, max ...int) (any, error) {
	limit := 512
	if len(max) > 0 {
		limit = max[0]
	}
	if isUndefined(item.Get(key)) {
		return core.Undefined, nil
	}
	return Text(item.Get(key), key, limit)
}

func (syncValidator) optionalStrings(item *core.Object, key string) (any, error) {
	if isUndefined(item.Get(key)) {
		return core.Undefined, nil
	}
	list, err := Strings(item.Get(key), key)
	if err != nil {
		return nil, err
	}
	return stringsOf(list), nil
}

func (syncValidator) optionalBoolean(item *core.Object, key string) (any, error) {
	value := item.Get(key)
	if isUndefined(value) {
		return core.Undefined, nil
	}
	if _, ok := value.(bool); !ok {
		return nil, invalidInput(key + " must be boolean")
	}
	return value, nil
}

// optionalDuration is a duration in milliseconds from a minute up to max; null and absent both mean none.
func (syncValidator) optionalDuration(item *core.Object, key string, max float64) (any, error) {
	if nullish(item.Get(key)) {
		return core.Undefined, nil
	}
	return Integer(item.Get(key), key, 60_000, max)
}

// optionalObject is `item[key] === undefined ? undefined : object(item[key])`.
func (syncValidator) optionalObject(item *core.Object, key string) (any, error) {
	if isUndefined(item.Get(key)) {
		return core.Undefined, nil
	}
	return Object(item.Get(key))
}

// syncField is one member of a parsed item, evaluated in order.
type syncField struct {
	key   string
	value func() (any, error)
}

// syncBuildItem evaluates the members in order (the TypeScript object literal) and stops at the first error.
func syncBuildItem(steps ...syncField) (*core.Object, error) {
	item := core.NewObject()
	for _, step := range steps {
		value, err := step.value()
		if err != nil {
			return nil, err
		}
		item.Set(step.key, value)
	}
	return item, nil
}

// ValidateTenantConfig   validateTenantConfig): Validates the shape of a desired configuration; references are
// checked against the tenant during planning.
func ValidateTenantConfig(value any) (*core.Object, error) {
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	if !core.StrictEquals(input.Get("version"), 1.0) {
		return nil, invalidInput("Configuration version must be 1")
	}
	list := func(key string) ([]*core.Object, bool, error) {
		raw := input.Get(key)
		if isUndefined(raw) {
			return nil, false, nil
		}
		items, ok := raw.([]any)
		if !ok || len(items) > 1000 {
			return nil, false, invalidInput(key + " must be an array of at most 1000 items")
		}
		out := make([]*core.Object, len(items))
		for index, item := range items {
			object, err := Object(item)
			if err != nil {
				return nil, false, err
			}
			out[index] = object
		}
		return out, true, nil
	}
	v := syncValidator{}
	text := func(item *core.Object, key, name string, max ...int) func() (any, error) {
		return func() (any, error) { return Text(item.Get(key), name, max...) }
	}
	mapItems := func(items []*core.Object, parse func(*core.Object) (*core.Object, error)) ([]any, error) {
		out := make([]any, len(items))
		for index, item := range items {
			parsed, err := parse(item)
			if err != nil {
				return nil, err
			}
			out[index] = parsed
		}
		return out, nil
	}
	config := core.NewObject("version", 1.0)

	resourceTypes, ok, err := list("resourceTypes")
	if err != nil {
		return nil, err
	}
	if ok {
		parsed, err := mapItems(resourceTypes, func(item *core.Object) (*core.Object, error) {
			return syncBuildItem(
				syncField{"name", text(item, "name", "resource type name", 64)},
				syncField{"description", func() (any, error) { return v.optionalText(item, "description") }},
				syncField{"actions", func() (any, error) { return v.optionalStrings(item, "actions") }},
				syncField{"attributes", func() (any, error) { return v.optionalObject(item, "attributes") }},
				syncField{"parent", func() (any, error) { return v.optionalText(item, "parent", 64) }},
				syncField{"relations", func() (any, error) { return v.optionalStrings(item, "relations") }},
			)
		})
		if err != nil {
			return nil, err
		}
		config.Set("resourceTypes", parsed)
	}
	policies, ok, err := list("policies")
	if err != nil {
		return nil, err
	}
	if ok {
		parsed, err := mapItems(policies, func(item *core.Object) (*core.Object, error) {
			return syncBuildItem(
				syncField{"name", text(item, "name", "policy name")},
				syncField{"description", func() (any, error) { return v.optionalText(item, "description") }},
				syncField{"document", func() (any, error) { return Object(item.Get("document")) }},
			)
		})
		if err != nil {
			return nil, err
		}
		config.Set("policies", parsed)
	}
	roles, ok, err := list("roles")
	if err != nil {
		return nil, err
	}
	if ok {
		parsed, err := mapItems(roles, func(item *core.Object) (*core.Object, error) {
			return syncBuildItem(
				syncField{"name", text(item, "name", "role name")},
				syncField{"description", func() (any, error) { return v.optionalText(item, "description") }},
				syncField{"policies", func() (any, error) { return v.optionalStrings(item, "policies") }},
				syncField{"permissions", func() (any, error) { return v.optionalStrings(item, "permissions") }},
				syncField{"document", func() (any, error) { return v.optionalObject(item, "document") }},
				syncField{"inherits", func() (any, error) { return v.optionalStrings(item, "inherits") }},
			)
		})
		if err != nil {
			return nil, err
		}
		config.Set("roles", parsed)
	}
	groups, ok, err := list("groups")
	if err != nil {
		return nil, err
	}
	if ok {
		parsed, err := mapItems(groups, func(item *core.Object) (*core.Object, error) {
			return syncBuildItem(
				syncField{"name", text(item, "name", "group name")},
				syncField{"description", func() (any, error) { return v.optionalText(item, "description") }},
				syncField{"members", func() (any, error) {
					members, err := v.optionalStrings(item, "members")
					if err != nil || isUndefined(members) {
						return members, err
					}
					lowered := []string{}
					for _, email := range syncStringList(members) {
						lowered = append(lowered, core.JSLower(core.JSTrim(email)))
					}
					return stringsOf(lowered), nil
				}},
			)
		})
		if err != nil {
			return nil, err
		}
		config.Set("groups", parsed)
	}
	bindings, ok, err := list("bindings")
	if err != nil {
		return nil, err
	}
	if ok {
		parsed, err := mapItems(bindings, func(item *core.Object) (*core.Object, error) {
			return syncBuildItem(
				syncField{"group", text(item, "group", "binding group")},
				syncField{"role", text(item, "role", "binding role")},
				syncField{"eligible", func() (any, error) { return v.optionalBoolean(item, "eligible") }},
				syncField{"maxActivationMs", func() (any, error) { return v.optionalDuration(item, "maxActivationMs", MaxActivationMs) }},
				syncField{"requireJustification", func() (any, error) { return v.optionalBoolean(item, "requireJustification") }},
				syncField{"requireMfa", func() (any, error) { return v.optionalBoolean(item, "requireMfa") }},
				syncField{"requireApproval", func() (any, error) { return v.optionalBoolean(item, "requireApproval") }},
				syncField{"approverGroup", func() (any, error) { return v.optionalText(item, "approverGroup") }},
				syncField{"managerApproval", func() (any, error) { return v.optionalBoolean(item, "managerApproval") }},
				syncField{"window", func() (any, error) { return v.optionalObject(item, "window") }},
			)
		})
		if err != nil {
			return nil, err
		}
		config.Set("bindings", parsed)
	}
	if accessPolicy := input.Get("accessPolicy"); !isUndefined(accessPolicy) {
		policy, err := TenantAccessPolicy(accessPolicy)
		if err != nil {
			return nil, err
		}
		config.Set("accessPolicy", policy)
	}
	packages, ok, err := list("packages")
	if err != nil {
		return nil, err
	}
	if ok {
		parsed, err := mapItems(packages, func(item *core.Object) (*core.Object, error) {
			return syncBuildItem(
				syncField{"name", text(item, "name", "package name", 128)},
				syncField{"description", func() (any, error) { return v.optionalText(item, "description") }},
				syncField{"roles", func() (any, error) { return v.optionalStrings(item, "roles") }},
				syncField{"groups", func() (any, error) { return v.optionalStrings(item, "groups") }},
				syncField{"maxDurationMs", func() (any, error) { return v.optionalDuration(item, "maxDurationMs", 315360000000) }},
				syncField{"requireJustification", func() (any, error) { return v.optionalBoolean(item, "requireJustification") }},
				syncField{"requestable", func() (any, error) { return v.optionalBoolean(item, "requestable") }},
				syncField{"approverGroup", func() (any, error) { return v.optionalText(item, "approverGroup") }},
				syncField{"managerApproval", func() (any, error) { return v.optionalBoolean(item, "managerApproval") }},
				// Checked fully during planning, where the group names are known.
				syncField{"autoAssign", func() (any, error) {
					rule := item.Get("autoAssign")
					if isUndefined(rule) || rule == nil {
						return rule, nil
					}
					return Object(rule)
				}},
			)
		})
		if err != nil {
			return nil, err
		}
		config.Set("packages", parsed)
	}
	invariants, ok, err := list("invariants")
	if err != nil {
		return nil, err
	}
	if ok {
		parsed, err := mapItems(invariants, parseInvariantConfig)
		if err != nil {
			return nil, err
		}
		config.Set("invariants", parsed)
	}
	agreements, ok, err := list("agreements")
	if err != nil {
		return nil, err
	}
	if ok {
		parsed, err := mapItems(agreements, func(item *core.Object) (*core.Object, error) {
			name, err := Text(item.Get("name"), "agreement name", 100)
			if err != nil {
				return nil, err
			}
			content, isText := item.Get("content").(string)
			if !isText || core.JSTrim(content) == "" {
				return nil, invalidInput("Agreement " + name + ": content is required")
			}
			return syncBuildItem(
				syncField{"name", func() (any, error) { return name, nil }},
				syncField{"content", func() (any, error) { return content, nil }},
				syncField{"url", func() (any, error) { return v.optionalText(item, "url", 2048) }},
				syncField{"required", func() (any, error) { return v.optionalBoolean(item, "required") }},
				syncField{"reacceptAfterDays", func() (any, error) {
					if nullish(item.Get("reacceptAfterDays")) {
						return core.Undefined, nil
					}
					return Integer(item.Get("reacceptAfterDays"), "reacceptAfterDays", 1, 3650)
				}},
			)
		})
		if err != nil {
			return nil, err
		}
		config.Set("agreements", parsed)
	}
	// Teams and departments (org-sync.ts).
	teams, ok, err := list("teams")
	if err != nil {
		return nil, err
	}
	if ok {
		parsed, err := ParseTeamsConfig(teams)
		if err != nil {
			return nil, err
		}
		config.Set("teams", syncObjects(parsed))
	}
	departments, ok, err := list("departments")
	if err != nil {
		return nil, err
	}
	if ok {
		parsed, err := ParseDepartmentsConfig(departments)
		if err != nil {
			return nil, err
		}
		config.Set("departments", syncObjects(parsed))
	}
	// AI agents, models and budgets (ai-sync.ts).
	for _, kind := range []struct {
		key   string
		parse func([]*core.Object) ([]*core.Object, error)
	}{
		{"agents", ParseAgentsConfig},
		{"inferenceModels", ParseModelsConfig},
		{"inferenceBudgets", ParseBudgetsConfig},
	} {
		items, ok, err := list(kind.key)
		if err != nil {
			return nil, err
		}
		if ok {
			parsed, err := kind.parse(items)
			if err != nil {
				return nil, err
			}
			config.Set(kind.key, syncObjects(parsed))
		}
	}
	itemNames := func(key string, normalize bool) ([]string, bool) {
		items, ok := syncConfigItems(config, key)
		if !ok {
			return nil, false
		}
		names := make([]string, len(items))
		for index, item := range items {
			names[index] = jsString(item.Get("name"))
			if normalize {
				names[index] = orgLower(names[index])
			}
		}
		return names, true
	}
	for _, kind := range []struct{ key, label string }{
		{"resourceTypes", "resource type"},
		{"policies", "policy"},
		{"roles", "role"},
		{"groups", "group"},
	} {
		if names, ok := itemNames(kind.key, false); ok {
			if err := syncUniqueNames(names, kind.label); err != nil {
				return nil, err
			}
		}
	}
	// Invariant and agreement names are unique regardless of case, as their APIs enforce.
	for _, kind := range []struct{ key, label string }{
		{"invariants", "invariant"},
		{"agreements", "agreement"},
	} {
		if names, ok := itemNames(kind.key, true); ok {
			if err := syncUniqueNames(names, kind.label); err != nil {
				return nil, err
			}
		}
	}
	// Package names are unique regardless of case, as `packages.create` enforces.
	if names, ok := itemNames("packages", true); ok {
		if err := syncUniqueNames(names, "package"); err != nil {
			return nil, err
		}
	}
	if items, ok := syncConfigItems(config, "bindings"); ok {
		seen := newOrderedSet()
		for _, binding := range items {
			key := jsString(binding.Get("group")) + " -> " + jsString(binding.Get("role"))
			if seen.Has(key) {
				return nil, invalidInput("Duplicate binding " + key)
			}
			seen.Add(key)
		}
	}
	return config, nil
}

// parseInvariantConfig validates one item of the `invariants` list.
func parseInvariantConfig(item *core.Object) (*core.Object, error) {
	v := syncValidator{}
	name, err := Text(item.Get("name"), "invariant name", 100)
	if err != nil {
		return nil, err
	}
	subject, err := Object(item.Get("subject"))
	if err != nil {
		return nil, err
	}
	keys := subject.Keys()
	var parsed *core.Object
	switch {
	case len(keys) == 1 && subject.Get("everyone") == true:
		parsed = core.NewObject("everyone", true)
	case len(keys) == 1 && !isUndefined(subject.Get("group")):
		group, err := Text(subject.Get("group"), "invariant subject group")
		if err != nil {
			return nil, err
		}
		parsed = core.NewObject("group", group)
	case len(keys) == 1 && !isUndefined(subject.Get("identity")):
		identity, err := Text(subject.Get("identity"), "invariant subject identity")
		if err != nil {
			return nil, err
		}
		parsed = core.NewObject("identity", core.JSLower(identity))
	case len(keys) == 1 && !isUndefined(subject.Get("attribute")):
		attribute, err := Object(subject.Get("attribute"))
		if err != nil {
			return nil, err
		}
		attributeName, err := Text(attribute.Get("name"), "invariant subject attribute")
		if err != nil {
			return nil, err
		}
		parsed = core.NewObject("attribute", core.NewObject("name", attributeName, "value", attribute.Get("value")))
	default:
		return nil, invalidInput("Invariant " + name + ": subject must be one of everyone, group, identity, or attribute")
	}
	resource, err := Object(item.Get("resource"))
	if err != nil {
		return nil, err
	}
	expect := item.Get("expect")
	if expect != "allow" && expect != "deny" {
		return nil, invalidInput("Invariant " + name + ": expect must be allow or deny")
	}
	mode := item.Get("mode")
	if !isUndefined(mode) && mode != "enforce" && mode != "monitor" {
		return nil, invalidInput("Invariant " + name + ": mode must be enforce or monitor")
	}
	return syncBuildItem(
		syncField{"name", func() (any, error) { return name, nil }},
		syncField{"description", func() (any, error) { return v.optionalText(item, "description", 500) }},
		syncField{"subject", func() (any, error) { return parsed, nil }},
		syncField{"action", func() (any, error) { return Text(item.Get("action"), "invariant action") }},
		syncField{"resource", func() (any, error) {
			resourceType, err := Text(resource.Get("type"), "invariant resource type")
			if err != nil {
				return nil, err
			}
			resourceID, err := Text(resource.Get("id"), "invariant resource id")
			if err != nil {
				return nil, err
			}
			return core.NewObject("type", resourceType, "id", resourceID), nil
		}},
		syncField{"expect", func() (any, error) { return expect, nil }},
		syncField{"mode", func() (any, error) { return mode, nil }},
		syncField{"assumeMfa", func() (any, error) { return v.optionalBoolean(item, "assumeMfa") }},
	)
}

// configState is sync.ts CurrentState: the tenant's current state in configuration form, with the records behind
// each item.
type configState struct {
	tenant              *core.Object
	resourceTypes       []*core.Object
	resourceTypeActions map[string][]string
	policies            []*core.Object
	roles               []*core.Object
	groups              []*core.Object
	members             map[string][]*core.Object
	bindings            []*core.Object
	packages            []*core.Object
	identitiesByEmail   map[string]*core.Object
	identityEmails      map[string]string
	invariants          []*core.Object
	agreements          []*core.Object
	// org holds the teams and departments (org-sync.ts).
	org *OrgState
	// ai holds the AI agents, models and budgets (ai-sync.ts).
	ai *core.Object
	// licenseKeys are the keys of the license products visible to the tenant: the valid identity.licenses values.
	licenseKeys []string
}

// syncSortByName sorts records by name (`a.name < b.name`), stably.
func syncSortByName(records []*core.Object) []*core.Object {
	sort.SliceStable(records, func(i, j int) bool {
		return compareUTF16(jsString(records[i].Get("name")), jsString(records[j].Get("name"))) < 0
	})
	return records
}

// syncSliceUTF16 is String.prototype.slice(start) over UTF-16 code units.
func syncSliceUTF16(s string, start int) string {
	units := core.ToUTF16(s)
	if start >= len(units) {
		return ""
	}
	return core.FromUTF16(units[start:])
}

// names maps records by ID to their names.
func syncNamesByID(records []*core.Object) map[string]string {
	names := map[string]string{}
	for _, record := range records {
		names[jsString(record.Get("id"))] = jsString(record.Get("name"))
	}
	return names
}

// syncMappedNames is `ids.flatMap((id) => names.get(id) ?? [])`.
func syncMappedNames(ids any, names map[string]string) []string {
	out := []string{}
	list, _ := ids.([]any)
	for _, id := range list {
		if name, ok := names[jsString(id)]; ok {
			out = append(out, name)
		}
	}
	return out
}

func readConfigState(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (*configState, error) {
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	byTenant := core.NewObject("tenantId", tenantID)
	resourceTypes, err := tx.Find(ctx, "resourceTypes", byTenant, nil)
	if err != nil {
		return nil, err
	}
	syncSortByName(resourceTypes)
	resourceTypeActions := map[string][]string{}
	for _, record := range resourceTypes {
		name := jsString(record.Get("name"))
		definition, err := server.Catalog.ResourceTypeDefinition(ctx, tx, tenantID, name)
		if err != nil {
			return nil, err
		}
		actions := []string{}
		if definition != nil {
			for _, action := range definition.Actions {
				actions = append(actions, syncSliceUTF16(action, utf16Len(name)+1))
			}
			sort.SliceStable(actions, func(i, j int) bool { return compareUTF16(actions[i], actions[j]) < 0 })
		}
		resourceTypeActions[name] = actions
	}
	allPolicies, err := tx.Find(ctx, "policies", byTenant, nil)
	if err != nil {
		return nil, err
	}
	policies := []*core.Object{}
	for _, policy := range allPolicies {
		if policy.Get("uniqueKey") != "system:owner" {
			policies = append(policies, policy)
		}
	}
	syncSortByName(policies)
	allRoles, err := tx.Find(ctx, "roles", byTenant, nil)
	if err != nil {
		return nil, err
	}
	roles := []*core.Object{}
	for _, role := range allRoles {
		if !truthy(role.Get("protected")) {
			roles = append(roles, role)
		}
	}
	syncSortByName(roles)
	// Teams' backing groups (and what is bound to them) belong to the teams API, never to configuration sync.
	allGroups, err := tx.Find(ctx, "groups", byTenant, nil)
	if err != nil {
		return nil, err
	}
	outsideGroupIDs := map[string]bool{}
	for _, group := range allGroups {
		teamGroup, err := IsTeamGroup(group)
		if err != nil {
			return nil, err
		}
		if teamGroup {
			outsideGroupIDs[jsString(group.Get("id"))] = true
		}
	}
	// Configuration names groups, and an identity provider's directory sync (SCIM) names the groups it creates: when
	// such a group shares its name with another group, the name means the other one, so an IdP cannot capture the
	// roles and approvals configuration gives a group by creating one of the same name. Those groups stay out of
	// sync's view.
	links, err := tx.Find(ctx, "scimGroups", byTenant, nil)
	if err != nil {
		return nil, err
	}
	scimGroupIDs := map[string]bool{}
	for _, link := range links {
		scimGroupIDs[jsString(link.Get("groupId"))] = true
	}
	ownNames := map[string]bool{}
	for _, group := range allGroups {
		id := jsString(group.Get("id"))
		if !outsideGroupIDs[id] && !scimGroupIDs[id] {
			ownNames[jsString(group.Get("name"))] = true
		}
	}
	for _, group := range allGroups {
		id := jsString(group.Get("id"))
		if scimGroupIDs[id] && ownNames[jsString(group.Get("name"))] {
			outsideGroupIDs[id] = true
		}
	}
	groups := []*core.Object{}
	for _, group := range allGroups {
		if !outsideGroupIDs[jsString(group.Get("id"))] {
			groups = append(groups, group)
		}
	}
	syncSortByName(groups)
	allIdentities, err := tx.Find(ctx, "identities", byTenant, nil)
	if err != nil {
		return nil, err
	}
	identities := []*core.Object{}
	for _, identity := range allIdentities {
		if identity.Get("status") != "deleted" {
			identities = append(identities, identity)
		}
	}
	identitiesByEmail := map[string]*core.Object{}
	for _, identity := range identities {
		if email := identity.Get("email"); truthy(email) {
			identitiesByEmail[core.JSLower(jsString(email))] = identity
		}
	}
	members := map[string][]*core.Object{}
	byID := syncByID(identities)
	memberships, err := tx.Find(ctx, "groupMembers", byTenant, nil)
	if err != nil {
		return nil, err
	}
	for _, membership := range memberships {
		identity := byID[jsString(membership.Get("identityId"))]
		if identity == nil || !server.LiveMembership(membership) {
			continue
		}
		groupID := jsString(membership.Get("groupId"))
		members[groupID] = append(members[groupID], identity)
	}
	groupBindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group"), nil)
	if err != nil {
		return nil, err
	}
	bindings := []*core.Object{}
	for _, binding := range groupBindings {
		if !server.ExpiredBinding(binding) && !outsideGroupIDs[jsString(binding.Get("subjectId"))] {
			bindings = append(bindings, binding)
		}
	}
	packages, err := tx.Find(ctx, "accessPackages", byTenant, nil)
	if err != nil {
		return nil, err
	}
	syncSortByName(packages)
	invariants, err := tx.Find(ctx, "accessInvariants", byTenant, nil)
	if err != nil {
		return nil, err
	}
	syncSortByName(invariants)
	agreements, err := tx.Find(ctx, "agreements", byTenant, nil)
	if err != nil {
		return nil, err
	}
	syncSortByName(agreements)
	identityEmails := map[string]string{}
	for _, identity := range identities {
		if email := identity.Get("email"); truthy(email) {
			identityEmails[jsString(identity.Get("id"))] = core.JSLower(jsString(email))
		}
	}
	org, err := ReadOrgState(ctx, server, tx, tenantID)
	if err != nil {
		return nil, err
	}
	ai, err := ReadAiState(ctx, server, tx, tenantID)
	if err != nil {
		return nil, err
	}
	licenseKeys, err := LicenseRuleKeys(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	return &configState{
		tenant:              tenant,
		resourceTypes:       resourceTypes,
		resourceTypeActions: resourceTypeActions,
		policies:            policies,
		roles:               roles,
		groups:              groups,
		members:             members,
		bindings:            bindings,
		packages:            packages,
		identitiesByEmail:   identitiesByEmail,
		identityEmails:      identityEmails,
		invariants:          invariants,
		agreements:          agreements,
		org:                 org,
		ai:                  ai,
		licenseKeys:         licenseKeys,
	}, nil
}

// syncPortableSubject is sync.ts portableSubject: an invariant's stored subject in document form (group names, member
// emails); unknown references keep their IDs.
func syncPortableSubject(subject any, groupNames, identityEmails map[string]string) *core.Object {
	stored, _ := subject.(*core.Object)
	switch {
	case stored.Has("groupId"):
		return core.NewObject("group", syncLookup(groupNames, jsString(stored.Get("groupId"))))
	case stored.Has("identityId"):
		return core.NewObject("identity", syncLookup(identityEmails, jsString(stored.Get("identityId"))))
	case stored.Has("attribute"):
		return core.NewObject("attribute", stored.Get("attribute"))
	}
	return core.NewObject("everyone", true)
}

// syncExportedInvariant is sync.ts exportedInvariant: an invariant record in document form, with defaults filled in so
// plans compare like with like.
func syncExportedInvariant(invariant *core.Object, groupNames, identityEmails map[string]string) *core.Object {
	result := core.NewObject("name", invariant.Get("name"))
	if description := invariant.Get("description"); !isUndefined(description) {
		result.Set("description", description)
	}
	result.Set("subject", syncPortableSubject(invariant.Get("subject"), groupNames, identityEmails))
	result.Set("action", invariant.Get("action"))
	result.Set("resource", invariant.Get("resource"))
	result.Set("expect", invariant.Get("expect"))
	result.Set("mode", invariant.Get("mode"))
	result.Set("assumeMfa", invariant.Get("assumeMfa"))
	return result
}

// syncExportedAgreement is sync.ts exportedAgreement.
func syncExportedAgreement(agreement *core.Object) *core.Object {
	result := core.NewObject("name", agreement.Get("name"), "content", agreement.Get("content"))
	if url := agreement.Get("url"); !isUndefined(url) {
		result.Set("url", url)
	}
	result.Set("required", agreement.Get("required"))
	if days := agreement.Get("reacceptAfterDays"); !isUndefined(days) {
		result.Set("reacceptAfterDays", days)
	}
	return result
}

// syncExportedRule is a stored birthright rule in document form: group, team and department names.
func syncExportedRule(state *configState, rule any, groupNames map[string]string) (any, error) {
	ruleObject, _ := rule.(*core.Object)
	input, err := RuleInput(ruleObject)
	if err != nil {
		return nil, err
	}
	named, err := MapRuleGroups(input, func(groupID string) string { return syncLookup(groupNames, groupID) })
	if err != nil {
		return nil, err
	}
	return OrgRuleNames(state.org, named)
}

// syncAiNames is the `names` argument of exportAi: { identityEmails, groupNames } as raw Go maps.
func syncAiNames(identityEmails, groupNames map[string]string) *core.Object {
	names := core.NewObject()
	names.SetRaw("identityEmails", identityEmails)
	names.SetRaw("groupNames", groupNames)
	return names
}

func exportConfigState(state *configState) (*core.Object, error) {
	policyNames := syncNamesByID(state.policies)
	roleNames := syncNamesByID(state.roles)
	groupNames := syncNamesByID(state.groups)
	resourceTypes := make([]any, len(state.resourceTypes))
	for index, record := range state.resourceTypes {
		item := core.NewObject("name", record.Get("name"))
		if description := record.Get("description"); !isUndefined(description) {
			item.Set("description", description)
		}
		actions := state.resourceTypeActions[jsString(record.Get("name"))]
		if actions == nil {
			actions = []string{}
		}
		item.Set("actions", stringsOf(actions))
		item.Set("attributes", record.Get("attributes"))
		if parent := record.Get("parent"); !isUndefined(parent) {
			item.Set("parent", parent)
		}
		relations := syncStringList(coalesce(record.Get("relations"), []any{}))
		sort.SliceStable(relations, func(i, j int) bool { return compareUTF16(relations[i], relations[j]) < 0 })
		item.Set("relations", stringsOf(relations))
		resourceTypes[index] = item
	}
	policies := make([]any, len(state.policies))
	for index, record := range state.policies {
		item := core.NewObject("name", record.Get("name"))
		if description := record.Get("description"); !isUndefined(description) {
			item.Set("description", description)
		}
		item.Set("document", record.Get("document"))
		policies[index] = item
	}
	roles := make([]any, len(state.roles))
	for index, record := range state.roles {
		item := core.NewObject("name", record.Get("name"))
		if description := record.Get("description"); !isUndefined(description) {
			item.Set("description", description)
		}
		item.Set("policies", syncSortedList(syncMappedNames(record.Get("policyIds"), policyNames)))
		item.Assign(syncExportedDocument(record.Get("document")))
		if inherits, ok := record.Get("inherits").([]any); ok && len(inherits) > 0 {
			item.Set("inherits", syncSortedList(syncMappedNames(inherits, roleNames)))
		}
		roles[index] = item
	}
	groups := make([]any, len(state.groups))
	for index, record := range state.groups {
		item := core.NewObject("name", record.Get("name"))
		if description := record.Get("description"); !isUndefined(description) {
			item.Set("description", description)
		}
		item.Set("members", syncSortedList(syncMemberEmails(state.members[jsString(record.Get("id"))])))
		groups[index] = item
	}
	type exportedBinding struct {
		key  string
		item *core.Object
	}
	var exportedBindings []exportedBinding
	for _, binding := range state.bindings {
		group, groupOK := groupNames[jsString(binding.Get("subjectId"))]
		role, roleOK := roleNames[jsString(binding.Get("roleId"))]
		if !groupOK || !roleOK {
			continue
		}
		item := core.NewObject("group", group, "role", role)
		if truthy(binding.Get("eligible")) {
			item.Set("eligible", true)
			if value := binding.Get("maxActivationMs"); !isUndefined(value) {
				item.Set("maxActivationMs", value)
			}
			for _, flag := range []string{"requireJustification", "requireMfa", "requireApproval"} {
				if truthy(binding.Get(flag)) {
					item.Set(flag, true)
				}
			}
			if approver := binding.Get("approverGroupId"); truthy(approver) {
				if name, ok := groupNames[jsString(approver)]; ok {
					item.Set("approverGroup", name)
				}
			}
			if truthy(binding.Get("managerApproval")) {
				item.Set("managerApproval", true)
			}
		}
		if window := binding.Get("window"); truthy(window) {
			item.Set("window", window)
		}
		exportedBindings = append(exportedBindings, exportedBinding{group + " -> " + role, item})
	}
	sort.SliceStable(exportedBindings, func(i, j int) bool {
		return localeCompare(exportedBindings[i].key, exportedBindings[j].key) < 0
	})
	bindings := make([]any, len(exportedBindings))
	for index, binding := range exportedBindings {
		bindings[index] = binding.item
	}
	packages := make([]any, len(state.packages))
	for index, record := range state.packages {
		item := core.NewObject("name", record.Get("name"))
		if description := record.Get("description"); !isUndefined(description) {
			item.Set("description", description)
		}
		item.Set("roles", syncSortedList(syncMappedNames(record.Get("roleIds"), roleNames)))
		item.Set("groups", syncSortedList(syncMappedNames(record.Get("groupIds"), groupNames)))
		if value := record.Get("maxDurationMs"); !isUndefined(value) {
			item.Set("maxDurationMs", value)
		}
		if truthy(record.Get("requireJustification")) {
			item.Set("requireJustification", true)
		}
		if truthy(record.Get("requestable")) {
			item.Set("requestable", true)
		}
		if approver := record.Get("approverGroupId"); truthy(approver) {
			if name, ok := groupNames[jsString(approver)]; ok {
				item.Set("approverGroup", name)
			}
		}
		if truthy(record.Get("managerApproval")) {
			item.Set("managerApproval", true)
		}
		// The rule as written, with group names; owner, authority, revision, and approval are runtime state.
		if rule := record.Get("autoAssign"); truthy(rule) {
			named, err := syncExportedRule(state, rule, groupNames)
			if err != nil {
				return nil, err
			}
			item.Set("autoAssign", named)
		}
		packages[index] = item
	}
	config := core.NewObject(
		"version", 1.0,
		"resourceTypes", resourceTypes,
		"policies", policies,
		"roles", roles,
		"groups", groups,
		"bindings", bindings,
		"packages", packages,
	)
	if accessPolicy := state.tenant.Get("accessPolicy"); truthy(accessPolicy) {
		config.Set("accessPolicy", accessPolicy)
	}
	// Listed only when the tenant has some, so documents of tenants that use neither stay unchanged.
	if len(state.invariants) > 0 {
		invariants := make([]any, len(state.invariants))
		for index, invariant := range state.invariants {
			invariants[index] = syncExportedInvariant(invariant, groupNames, state.identityEmails)
		}
		config.Set("invariants", invariants)
	}
	if len(state.agreements) > 0 {
		agreements := make([]any, len(state.agreements))
		for index, agreement := range state.agreements {
			agreements[index] = syncExportedAgreement(agreement)
		}
		config.Set("agreements", agreements)
	}
	// Teams and departments (org-sync.ts), each only when the tenant has some.
	org, err := ExportOrg(state.org, &OrgDirectory{IdentityEmails: state.identityEmails, RoleNames: roleNames, GroupNames: groupNames})
	if err != nil {
		return nil, err
	}
	config.Assign(org)
	// AI agents, models and budgets (ai-sync.ts), each only when the tenant has some.
	ai, err := ExportAi(state.ai, syncAiNames(state.identityEmails, groupNames))
	if err != nil {
		return nil, err
	}
	config.Assign(ai)
	return config, nil
}

// syncMemberEmails is the lowercase emails of the identities that have one.
func syncMemberEmails(identities []*core.Object) []string {
	emails := []string{}
	for _, identity := range identities {
		if email := identity.Get("email"); truthy(email) {
			emails = append(emails, core.JSLower(jsString(email)))
		}
	}
	return emails
}

// configPlanned is sync.ts Planned: one desired item next to the record it matches, if any.
type configPlanned struct {
	change  *core.Object
	desired *core.Object
	record  *core.Object
	// records are the bindings behind a binding change.
	records []*core.Object
}

// configPlanResult is sync.ts PlanResult.
type configPlanResult struct {
	plan          *core.Object
	changes       []*core.Object
	summary       map[string]int
	accessPolicy  *configPlanned
	resourceTypes []*configPlanned
	policies      []*configPlanned
	roles         []*configPlanned
	groups        []*configPlanned
	bindings      []*configPlanned
	packages      []*configPlanned
	invariants    []*configPlanned
	agreements    []*configPlanned
	// org holds the teams and departments (org-sync.ts).
	org *OrgPlan
	// ai holds the AI agents, models and budgets (ai-sync.ts): { agents, models, budgets }.
	ai *core.Object
}

// add records a change in the plan and its summary.
func (r *configPlanResult) add(change *core.Object) {
	r.changes = append(r.changes, change)
	r.summary[syncChangeAction(change)]++
}

// push is computePlan's push.
func (r *configPlanResult) push(list *[]*configPlanned, item *configPlanned) {
	*list = append(*list, item)
	r.add(item.change)
}

// summaryObject is the plan summary { create, update, delete, unchanged }.
func (r *configPlanResult) summaryObject() *core.Object {
	return core.NewObject("create", r.summary["create"], "update", r.summary["update"], "delete", r.summary["delete"],
		"unchanged", r.summary["unchanged"])
}

// syncStrings is the strings of a model array member, or [] when absent (`item.key ?? []`).
func syncStrings(value any) []string {
	if nullish(value) {
		return []string{}
	}
	return syncStringList(value)
}

func computeConfigPlan(server *ServerContext, tenantID any, desired *core.Object, state *configState, prune bool) (*configPlanResult, error) {
	result := &configPlanResult{
		summary: map[string]int{},
		org:     &OrgPlan{Teams: []*OrgPlanned{}, Departments: []*OrgPlanned{}},
		ai:      core.NewObject("agents", []any{}, "models", []any{}, "budgets", []any{}),
	}
	// Access policy (one record; a present document value replaces it, `{}` clears it)
	if accessPolicy, ok := desired.Get("accessPolicy").(*core.Object); ok {
		before, _ := state.tenant.Get("accessPolicy").(*core.Object)
		if before == nil {
			before = core.NewObject()
		}
		after := accessPolicy
		fields := syncDiffFields(before.Spread(), after.Spread())
		change := syncUpdateOrUnchanged("accessPolicy", "accessPolicy", fields, before, after)
		result.accessPolicy = &configPlanned{change: change, desired: after, record: state.tenant}
		result.add(change)
	}
	// Resource types
	if desiredTypes, ok := syncConfigItems(desired, "resourceTypes"); ok {
		existing := map[string]*core.Object{}
		for _, record := range state.resourceTypes {
			existing[jsString(record.Get("name"))] = record
		}
		for _, item := range desiredTypes {
			name := jsString(item.Get("name"))
			record := existing[name]
			after := core.NewObject(
				"description", item.Get("description"),
				"actions", syncSortedList(syncStrings(item.Get("actions"))),
				"attributes", coalesce(item.Get("attributes"), core.NewObject()),
				"parent", item.Get("parent"),
				"relations", syncSortedList(syncStrings(item.Get("relations"))),
			)
			if record == nil {
				result.push(&result.resourceTypes, &configPlanned{change: syncChange("resourceType", name, "create", nil, nil, after), desired: item})
				continue
			}
			actions := state.resourceTypeActions[jsString(record.Get("name"))]
			if actions == nil {
				actions = []string{}
			}
			before := core.NewObject(
				"description", record.Get("description"),
				"actions", stringsOf(actions),
				"attributes", record.Get("attributes"),
				"parent", record.Get("parent"),
				"relations", syncSortedList(syncStrings(record.Get("relations"))),
			)
			fields := syncDiffFields(before, after)
			if containsString(fields, "parent") {
				return nil, invalidInput("Resource type " + name + ": the parent cannot change; delete and recreate the type")
			}
			result.push(&result.resourceTypes, &configPlanned{change: syncUpdateOrUnchanged("resourceType", name, fields, before, after), desired: item, record: record})
		}
		if prune {
			for _, record := range state.resourceTypes {
				name := jsString(record.Get("name"))
				if !syncSome(desiredTypes, func(item *core.Object) bool { return jsString(item.Get("name")) == name }) {
					result.push(&result.resourceTypes, &configPlanned{change: syncChange("resourceType", name, "delete", nil, nil, nil), record: record})
				}
			}
		}
	}
	// Policies
	policyNamesAfter := newOrderedSet()
	if desiredPolicies, ok := syncConfigItems(desired, "policies"); ok {
		existing := map[string]*core.Object{}
		for _, record := range state.policies {
			existing[jsString(record.Get("name"))] = record
		}
		inDocument := func(name string) bool {
			return syncSome(desiredPolicies, func(item *core.Object) bool { return jsString(item.Get("name")) == name })
		}
		for _, item := range desiredPolicies {
			name := jsString(item.Get("name"))
			policyNamesAfter.Add(name)
			record := existing[name]
			after := core.NewObject("description", item.Get("description"), "document", item.Get("document"))
			if record == nil {
				result.push(&result.policies, &configPlanned{change: syncChange("policy", name, "create", nil, nil, after), desired: item})
				continue
			}
			before := core.NewObject("description", record.Get("description"), "document", record.Get("document"))
			fields := syncDiffFields(before, after)
			result.push(&result.policies, &configPlanned{change: syncUpdateOrUnchanged("policy", name, fields, before, after), desired: item, record: record})
		}
		for _, record := range state.policies {
			name := jsString(record.Get("name"))
			if _, known := existing[name]; !known || !inDocument(name) {
				if inDocument(name) {
					continue
				}
				if prune {
					result.push(&result.policies, &configPlanned{change: syncChange("policy", name, "delete", nil, nil, nil), record: record})
				} else {
					policyNamesAfter.Add(name)
				}
			}
		}
	} else {
		for _, record := range state.policies {
			policyNamesAfter.Add(jsString(record.Get("name")))
		}
	}
	// Roles
	roleNamesAfter := newOrderedSet()
	if desiredRoles, ok := syncConfigItems(desired, "roles"); ok {
		existing := map[string]*core.Object{}
		for _, record := range state.roles {
			existing[jsString(record.Get("name"))] = record
		}
		policyNames := syncNamesByID(state.policies)
		roleNames := syncNamesByID(state.roles)
		// Every role of the document plus the survivors decides which inheritance targets exist afterwards.
		rolesAfterApply := newOrderedSet()
		for _, role := range desiredRoles {
			rolesAfterApply.Add(jsString(role.Get("name")))
		}
		if !prune {
			for _, record := range state.roles {
				rolesAfterApply.Add(jsString(record.Get("name")))
			}
		}
		for _, role := range desiredRoles {
			name := jsString(role.Get("name"))
			roleNamesAfter.Add(name)
			for _, policy := range syncStrings(role.Get("policies")) {
				if !policyNamesAfter.Has(policy) {
					return nil, invalidInput("Role " + name + " attaches unknown policy " + policy)
				}
			}
			for _, inherited := range syncStrings(role.Get("inherits")) {
				if inherited == name {
					return nil, invalidInput("Role " + name + " cannot inherit itself")
				}
				if !rolesAfterApply.Has(inherited) {
					return nil, invalidInput("Role " + name + " inherits unknown role " + inherited)
				}
			}
			record := existing[name]
			document, err := syncRoleDocument(role)
			if err != nil {
				return nil, err
			}
			after := core.NewObject(
				"description", role.Get("description"),
				"policies", syncSortedList(syncStrings(role.Get("policies"))),
				"document", document,
				"inherits", syncSortedList(syncStrings(role.Get("inherits"))),
			)
			if record == nil {
				result.push(&result.roles, &configPlanned{change: syncChange("role", name, "create", nil, nil, after), desired: role})
				continue
			}
			before := core.NewObject(
				"description", record.Get("description"),
				"policies", syncSortedList(syncMappedNames(record.Get("policyIds"), policyNames)),
				"document", record.Get("document"),
				"inherits", syncSortedList(syncMappedNames(coalesce(record.Get("inherits"), []any{}), roleNames)),
			)
			fields := syncDiffFields(before, after)
			result.push(&result.roles, &configPlanned{change: syncUpdateOrUnchanged("role", name, fields, before, after), desired: role, record: record})
		}
		for _, record := range state.roles {
			name := jsString(record.Get("name"))
			if syncSome(desiredRoles, func(item *core.Object) bool { return jsString(item.Get("name")) == name }) {
				continue
			}
			if prune {
				result.push(&result.roles, &configPlanned{change: syncChange("role", name, "delete", nil, nil, nil), record: record})
			} else {
				roleNamesAfter.Add(name)
			}
		}
	} else {
		for _, record := range state.roles {
			roleNamesAfter.Add(jsString(record.Get("name")))
		}
	}
	// Groups
	groupNamesAfter := newOrderedSet()
	if desiredGroups, ok := syncConfigItems(desired, "groups"); ok {
		existing := map[string]*core.Object{}
		for _, record := range state.groups {
			existing[jsString(record.Get("name"))] = record
		}
		for _, group := range desiredGroups {
			name := jsString(group.Get("name"))
			groupNamesAfter.Add(name)
			for _, email := range syncStrings(group.Get("members")) {
				if state.identitiesByEmail[email] == nil {
					return nil, invalidInput("Group " + name + ": unknown member " + email)
				}
			}
			record := existing[name]
			after := core.NewObject("description", group.Get("description"))
			if !isUndefined(group.Get("members")) {
				after.Set("members", syncSortedList(syncStrings(group.Get("members"))))
			}
			if record == nil {
				result.push(&result.groups, &configPlanned{change: syncChange("group", name, "create", nil, nil, after), desired: group})
				continue
			}
			before := core.NewObject("description", record.Get("description"))
			if !isUndefined(group.Get("members")) {
				before.Set("members", syncSortedList(syncMemberEmails(state.members[jsString(record.Get("id"))])))
			}
			fields := syncDiffFields(before, after)
			result.push(&result.groups, &configPlanned{change: syncUpdateOrUnchanged("group", name, fields, before, after), desired: group, record: record})
		}
		for _, record := range state.groups {
			name := jsString(record.Get("name"))
			if syncSome(desiredGroups, func(item *core.Object) bool { return jsString(item.Get("name")) == name }) {
				continue
			}
			if prune {
				result.push(&result.groups, &configPlanned{change: syncChange("group", name, "delete", nil, nil, nil), record: record})
			} else {
				groupNamesAfter.Add(name)
			}
		}
	} else {
		for _, record := range state.groups {
			groupNamesAfter.Add(jsString(record.Get("name")))
		}
	}
	// Group bindings
	if desiredBindings, ok := syncConfigItems(desired, "bindings"); ok {
		roleNames := syncNamesByID(state.roles)
		groupNames := syncNamesByID(state.groups)
		key := func(binding *core.Object) string {
			return syncLookup(groupNames, jsString(binding.Get("subjectId"))) + " -> " + syncLookup(roleNames, jsString(binding.Get("roleId")))
		}
		existingOrder := newOrderedSet()
		existing := map[string][]*core.Object{}
		for _, binding := range state.bindings {
			_, groupOK := groupNames[jsString(binding.Get("subjectId"))]
			_, roleOK := roleNames[jsString(binding.Get("roleId"))]
			if groupOK && roleOK {
				existingOrder.Add(key(binding))
				existing[key(binding)] = append(existing[key(binding)], binding)
			}
		}
		wanted := newOrderedSet()
		for _, binding := range desiredBindings {
			group, role := jsString(binding.Get("group")), jsString(binding.Get("role"))
			name := group + " -> " + role
			wanted.Add(name)
			if !groupNamesAfter.Has(group) {
				return nil, invalidInput("Binding " + name + ": unknown group " + group)
			}
			if !roleNamesAfter.Has(role) {
				return nil, invalidInput("Binding " + name + ": unknown role " + role)
			}
			eligible := truthy(binding.Get("eligible"))
			var window any = core.Undefined
			if value := binding.Get("window"); !isUndefined(value) {
				checked, err := server.AccessWindow(value)
				if err != nil {
					return nil, err
				}
				window = checked
			}
			after := core.NewObject(
				"eligible", binding.Get("eligible") == true,
				"maxActivationMs", syncIf(eligible, binding.Get("maxActivationMs"), core.Undefined),
				"requireJustification", eligible && binding.Get("requireJustification") == true,
				"requireMfa", eligible && binding.Get("requireMfa") == true,
				"requireApproval", eligible && binding.Get("requireApproval") == true,
				"approverGroup", syncIf(eligible, binding.Get("approverGroup"), core.Undefined),
				"managerApproval", eligible && binding.Get("managerApproval") == true,
				"window", window,
			)
			if approver, ok := after.Get("approverGroup").(string); ok && !groupNamesAfter.Has(approver) {
				return nil, invalidInput("Binding " + name + ": unknown approver group " + approver)
			}
			records := existing[name]
			if records == nil {
				result.push(&result.bindings, &configPlanned{change: syncChange("binding", name, "create", nil, nil, after), desired: binding})
				continue
			}
			first := records[0]
			var approverGroup any = core.Undefined
			if approverID := first.Get("approverGroupId"); !isUndefined(approverID) {
				if name, ok := groupNames[jsString(approverID)]; ok && approverID != nil {
					approverGroup = name
				}
			}
			before := core.NewObject(
				"eligible", first.Get("eligible") == true,
				"maxActivationMs", first.Get("maxActivationMs"),
				"requireJustification", first.Get("requireJustification") == true,
				"requireMfa", first.Get("requireMfa") == true,
				"requireApproval", first.Get("requireApproval") == true,
				"approverGroup", approverGroup,
				"managerApproval", first.Get("managerApproval") == true,
				"window", first.Get("window"),
			)
			fields := syncDiffFields(before, after)
			result.push(&result.bindings, &configPlanned{change: syncUpdateOrUnchanged("binding", name, fields, before, after), desired: binding, records: records})
		}
		if prune {
			for _, name := range existingOrder.Values() {
				if !wanted.Has(name) {
					result.push(&result.bindings, &configPlanned{change: syncChange("binding", name, "delete", nil, nil, nil), records: existing[name]})
				}
			}
		}
	}
	// Access packages
	if desiredPackages, ok := syncConfigItems(desired, "packages"); ok {
		if err := planPackages(server, result, desired, desiredPackages, state, prune, roleNamesAfter, groupNamesAfter); err != nil {
			return nil, err
		}
	}
	// Terms of use (matched by name regardless of case)
	if desiredAgreements, ok := syncConfigItems(desired, "agreements"); ok {
		existing := map[string]*core.Object{}
		for _, record := range state.agreements {
			existing[orgLower(jsString(record.Get("name")))] = record
		}
		for _, agreement := range desiredAgreements {
			name := jsString(agreement.Get("name"))
			record := existing[orgLower(name)]
			after := syncExportedAgreement(agreement.Spread(core.NewObject("required", coalesce(agreement.Get("required"), true))))
			if record == nil {
				result.push(&result.agreements, &configPlanned{change: syncChange("agreement", name, "create", nil, nil, after), desired: agreement})
				continue
			}
			before := syncExportedAgreement(record)
			fields := syncDiffFields(before, after)
			result.push(&result.agreements, &configPlanned{change: syncUpdateOrUnchanged("agreement", name, fields, before, after), desired: agreement, record: record})
		}
		if prune {
			for _, record := range state.agreements {
				name := jsString(record.Get("name"))
				if !syncSome(desiredAgreements, func(item *core.Object) bool { return orgLower(jsString(item.Get("name"))) == orgLower(name) }) {
					result.push(&result.agreements, &configPlanned{change: syncChange("agreement", name, "delete", nil, nil, nil), record: record})
				}
			}
		}
	}
	// Access invariants: their groups must exist after the apply, their people now.
	if desiredInvariants, ok := syncConfigItems(desired, "invariants"); ok {
		groupNames := syncNamesByID(state.groups)
		existing := map[string]*core.Object{}
		for _, record := range state.invariants {
			existing[orgLower(jsString(record.Get("name")))] = record
		}
		for _, invariant := range desiredInvariants {
			name := jsString(invariant.Get("name"))
			subject, _ := invariant.Get("subject").(*core.Object)
			if group, ok := subject.Get("group").(string); subject.Has("group") && ok && !groupNamesAfter.Has(group) {
				return nil, invalidInput("Invariant " + name + ": unknown group " + group)
			}
			if identity, ok := subject.Get("identity").(string); subject.Has("identity") && ok && state.identitiesByEmail[identity] == nil {
				return nil, invalidInput("Invariant " + name + ": unknown person " + identity)
			}
			after := core.NewObject()
			if description := invariant.Get("description"); !isUndefined(description) {
				after.Set("description", description)
			}
			after.Set("subject", subject)
			after.Set("action", invariant.Get("action"))
			after.Set("resource", invariant.Get("resource"))
			after.Set("expect", invariant.Get("expect"))
			after.Set("mode", coalesce(invariant.Get("mode"), "monitor"))
			after.Set("assumeMfa", coalesce(invariant.Get("assumeMfa"), true))
			record := existing[orgLower(name)]
			if record == nil {
				result.push(&result.invariants, &configPlanned{change: syncChange("invariant", name, "create", nil, nil, after), desired: invariant})
				continue
			}
			before := syncExportedInvariant(record, groupNames, state.identityEmails)
			before.Delete("name")
			fields := syncDiffFields(before, after)
			if jsString(record.Get("name")) != name {
				fields = append(fields, "name")
			}
			result.push(&result.invariants, &configPlanned{change: syncUpdateOrUnchanged("invariant", name, fields, before, after), desired: invariant, record: record})
		}
		if prune {
			for _, record := range state.invariants {
				name := jsString(record.Get("name"))
				if !syncSome(desiredInvariants, func(item *core.Object) bool { return orgLower(jsString(item.Get("name"))) == orgLower(name) }) {
					result.push(&result.invariants, &configPlanned{change: syncChange("invariant", name, "delete", nil, nil, nil), record: record})
				}
			}
		}
	}
	// Teams and departments (org-sync.ts): their roles must exist after the apply, their people now.
	_, hasTeams := syncConfigItems(desired, "teams")
	_, hasDepartments := syncConfigItems(desired, "departments")
	if hasTeams || hasDepartments {
		org, err := PlanOrg(desired, state.org, &OrgPlanEnv{
			OrgDirectory: OrgDirectory{
				IdentityEmails: state.identityEmails,
				RoleNames:      syncNamesByID(state.roles),
				GroupNames:     syncNamesByID(state.groups),
			},
			IdentitiesByEmail: state.identitiesByEmail,
			RoleNamesAfter:    roleNamesAfter,
			GroupNamesAfter:   groupNamesAfter,
			Prune:             prune,
		})
		if err != nil {
			return nil, err
		}
		result.org = org
		for _, item := range append(append([]*OrgPlanned{}, org.Departments...), org.Teams...) {
			result.add(item.Change)
		}
	}
	// AI agents, models and budgets (ai-sync.ts): sponsors are people now, budget groups exist after the apply.
	_, hasAgents := syncConfigItems(desired, "agents")
	_, hasModels := syncConfigItems(desired, "inferenceModels")
	_, hasBudgets := syncConfigItems(desired, "inferenceBudgets")
	if hasAgents || hasModels || hasBudgets {
		env := core.NewObject()
		env.SetRaw("identityEmails", state.identityEmails)
		env.SetRaw("groupNames", syncNamesByID(state.groups))
		env.SetRaw("identitiesByEmail", state.identitiesByEmail)
		env.SetRaw("groupNamesAfter", groupNamesAfter)
		env.SetRaw("prune", prune)
		ai, err := PlanAi(desired, state.ai, env)
		if err != nil {
			return nil, err
		}
		result.ai = ai
		for _, key := range []string{"agents", "models", "budgets"} {
			list, _ := member(ai, key).([]any)
			for _, item := range list {
				if change, ok := member(item, "change").(*core.Object); ok {
					result.add(change)
				}
			}
		}
	}
	sort.SliceStable(result.changes, func(i, j int) bool {
		a, b := result.changes[i], result.changes[j]
		if order := configKindIndex(syncChangeKind(a)) - configKindIndex(syncChangeKind(b)); order != 0 {
			return order < 0
		}
		return localeCompare(syncChangeName(a), syncChangeName(b)) < 0
	})
	result.plan = core.NewObject(
		"tenantId", tenantID,
		"prune", prune,
		"changes", syncObjects(result.changes),
		"summary", result.summaryObject(),
	)
	return result, nil
}

// syncIf is `condition ? a : b`.
func syncIf(condition bool, a, b any) any {
	if condition {
		return a
	}
	return b
}

// planPackages plans the access packages of a document (computePlan's package section).
func planPackages(server *ServerContext, result *configPlanResult, desired *core.Object, desiredPackages []*core.Object, state *configState, prune bool, roleNamesAfter, groupNamesAfter *orderedSet) error {
	roleNames := syncNamesByID(state.roles)
	groupNames := syncNamesByID(state.groups)
	// Matched regardless of case, like package uniqueness; a case-only difference is a rename.
	existing := map[string]*core.Object{}
	for _, record := range state.packages {
		existing[orgLower(jsString(record.Get("name")))] = record
	}
	// Rules name teams by slug and departments by name (org-sync.ts).
	orgAfter, err := OrgRuleEnvironmentAfter(desired, state.org, prune)
	if err != nil {
		return err
	}
	for _, pkg := range desiredPackages {
		name := jsString(pkg.Get("name"))
		for _, role := range syncStrings(pkg.Get("roles")) {
			if !roleNamesAfter.Has(role) {
				return invalidInput("Package " + name + ": unknown role " + role)
			}
		}
		for _, group := range syncStrings(pkg.Get("groups")) {
			if !groupNamesAfter.Has(group) {
				return invalidInput("Package " + name + ": unknown group " + group)
			}
		}
		if len(syncStrings(pkg.Get("roles"))) == 0 && len(syncStrings(pkg.Get("groups"))) == 0 {
			return invalidInput("Package " + name + " needs at least one role or group")
		}
		if approver, ok := pkg.Get("approverGroup").(string); ok && !groupNamesAfter.Has(approver) {
			return invalidInput("Package " + name + ": unknown approver group " + approver)
		}
		// A rule is compared only when the document names one: omission leaves it alone, null removes it.
		var rule any = core.Undefined
		if autoAssign := pkg.Get("autoAssign"); autoAssign == nil {
			rule = nil
		} else if !isUndefined(autoAssign) {
			org := orgAfter.Env.Spread()
			// Rules name license products by key, checked at plan time as apply checks them (licenses.ts).
			org.SetRaw("licenses", newOrderedSet(state.licenseKeys...))
			env := core.NewObject()
			env.SetRaw("identityAttributes", server.Catalog.IdentityAttributes)
			env.SetRaw("groups", groupNamesAfter)
			env.SetRaw("packagedGroups", newOrderedSet(syncStrings(pkg.Get("groups"))...))
			env.SetRaw("org", org)
			parsed, err := ParseAutoAssign(autoAssign, env, "Package "+name+": autoAssign")
			if err != nil {
				return err
			}
			if rule, err = orgAfter.Canonical(parsed); err != nil {
				return err
			}
			if !isUndefined(pkg.Get("maxDurationMs")) {
				return invalidInput("Package " + name + ": a package with autoAssign cannot have maxDurationMs")
			}
		}
		normalized := pkg
		if !isUndefined(rule) {
			normalized = pkg.Spread()
			normalized.Set("autoAssign", rule)
		}
		renamed := existing[orgLower(name)]
		after := core.NewObject()
		if !isUndefined(rule) {
			after.Set("autoAssign", rule)
		}
		if renamed != nil && jsString(renamed.Get("name")) != name {
			after.Set("name", name)
		}
		after.Set("description", pkg.Get("description"))
		after.Set("roles", syncSortedList(syncStrings(pkg.Get("roles"))))
		after.Set("groups", syncSortedList(syncStrings(pkg.Get("groups"))))
		after.Set("maxDurationMs", pkg.Get("maxDurationMs"))
		after.Set("requireJustification", pkg.Get("requireJustification") == true)
		after.Set("requestable", pkg.Get("requestable") == true)
		after.Set("approverGroup", pkg.Get("approverGroup"))
		after.Set("managerApproval", pkg.Get("managerApproval") == true)
		record := existing[orgLower(name)]
		if record == nil {
			result.push(&result.packages, &configPlanned{change: syncChange("package", name, "create", nil, nil, after), desired: normalized})
			continue
		}
		before := core.NewObject()
		if !isUndefined(rule) {
			var stored any = nil
			if autoAssign := record.Get("autoAssign"); truthy(autoAssign) {
				if stored, err = syncExportedRule(state, autoAssign, groupNames); err != nil {
					return err
				}
			}
			before.Set("autoAssign", stored)
		}
		if jsString(record.Get("name")) != name {
			before.Set("name", record.Get("name"))
		}
		before.Set("description", record.Get("description"))
		before.Set("roles", syncSortedList(syncMappedNames(record.Get("roleIds"), roleNames)))
		before.Set("groups", syncSortedList(syncMappedNames(record.Get("groupIds"), groupNames)))
		before.Set("maxDurationMs", record.Get("maxDurationMs"))
		before.Set("requireJustification", record.Get("requireJustification") == true)
		before.Set("requestable", record.Get("requestable") == true)
		var approverGroup any = core.Undefined
		if approverID := record.Get("approverGroupId"); !isUndefined(approverID) {
			if name, ok := groupNames[jsString(approverID)]; ok && approverID != nil {
				approverGroup = name
			}
		}
		before.Set("approverGroup", approverGroup)
		before.Set("managerApproval", record.Get("managerApproval") == true)
		fields := syncDiffFields(before, after)
		result.push(&result.packages, &configPlanned{change: syncUpdateOrUnchanged("package", name, fields, before, after), desired: normalized, record: record})
	}
	if prune {
		for _, record := range state.packages {
			name := jsString(record.Get("name"))
			if !syncSome(desiredPackages, func(item *core.Object) bool { return orgLower(jsString(item.Get("name"))) == orgLower(name) }) {
				result.push(&result.packages, &configPlanned{change: syncChange("package", name, "delete", nil, nil, nil), record: record})
			}
		}
	}
	return nil
}

// configApply is the state of one configuration apply (createConfigApi's apply).
type configApply struct {
	server    *ServerContext
	tx        core.IamStore
	principal *Principal
	tenant    *core.Object
	tenantID  string
	planned   *configPlanResult
	state     *configState
}

// allow is createConfigApi's allow: every change is authorized like the equivalent direct API call; one denial
// rejects the whole apply.
func (a *configApply) allow(ctx context.Context, action, resourceID, what string) error {
	decision, err := a.server.Decisions.Decide(ctx, a.tx, a.principal, AuthorizationRequest{
		TenantID: a.tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: resourceID},
	}, true)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return core.NewIamError("ACCESS_DENIED", "Not allowed to "+what+" ("+action+")", 403)
	}
	return nil
}

// syncIDsOf maps names to IDs, failing with `Unknown {noun} {name}`.
func syncIDsOf(names []string, ids map[string]string, noun string) ([]any, error) {
	out := make([]any, len(names))
	for index, name := range names {
		id, ok := ids[name]
		if !ok || id == "" {
			return nil, invalidInput("Unknown " + noun + " " + name)
		}
		out[index] = id
	}
	return out, nil
}

// syncGroupIDOrNull is `groupIds.get(name) ?? null`.
func syncGroupIDOrNull(groupIDs map[string]string, name string) any {
	if id, ok := groupIDs[name]; ok {
		return id
	}
	return nil
}

func (a *configApply) run(ctx context.Context) error {
	server, tx, principal, tenant, tenantID, planned, state := a.server, a.tx, a.principal, a.tenant, a.tenantID, a.planned, a.state
	if planned.accessPolicy != nil && syncChangeAction(planned.accessPolicy.change) == "update" {
		if err := a.allow(ctx, "iam:tenants:update", tenantID, "change the access policy"); err != nil {
			return err
		}
		// As `tenants.setAccessPolicy`: loosening elevation floors needs a fresh sign-in in person (not a stale,
		// impersonated, assumed-role or delegated session), and is audited as such.
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return err
		}
		rest := planned.accessPolicy.record.Spread()
		rest.Delete("accessPolicy")
		policy := planned.accessPolicy.desired
		if policy.Len() > 0 {
			rest.Set("accessPolicy", policy)
		}
		if _, err := tx.Put(ctx, "tenants", rest); err != nil {
			return err
		}
		var recorded any = nil
		if policy.Len() > 0 {
			recorded = policy
		}
		if err := server.Events.Audit(ctx, tx, principal, "tenant:access-policy", tenantID, tenantID, "allow", false,
			core.NewObject("accessPolicy", recorded)); err != nil {
			return err
		}
	}
	// Resource types first: policies and roles may name their actions.
	for _, item := range planned.resourceTypes {
		name := syncChangeName(item.change)
		switch syncChangeAction(item.change) {
		case "create":
			if err := a.allow(ctx, "iam:resource-types:create", tenantID, "create resource type "+name); err != nil {
				return err
			}
			if _, err := RegisterResourceType(ctx, server, tx, core.NewObject("tenantId", tenantID).Assign(item.desired)); err != nil {
				return err
			}
		case "update":
			if err := a.allow(ctx, "iam:resource-types:update", tenantID, "update resource type "+name); err != nil {
				return err
			}
			if _, err := UpdateResourceType(ctx, server, tx, core.NewObject(
				"tenantId", tenantID,
				"name", item.desired.Get("name"),
				"description", item.desired.Get("description"),
				"attributes", coalesce(item.desired.Get("attributes"), core.NewObject()),
				"actions", coalesce(item.desired.Get("actions"), []any{}),
				"relations", coalesce(item.desired.Get("relations"), []any{}),
			), true); err != nil {
				return err
			}
		case "delete":
			if err := a.allow(ctx, "iam:resource-types:delete", tenantID, "delete resource type "+name); err != nil {
				return err
			}
			if err := DeleteResourceType(ctx, server, tx, item.record); err != nil {
				return err
			}
		}
	}
	// Policies
	policyIDs := map[string]string{}
	for _, policy := range state.policies {
		policyIDs[jsString(policy.Get("name"))] = jsString(policy.Get("id"))
	}
	for _, item := range planned.policies {
		name := syncChangeName(item.change)
		switch syncChangeAction(item.change) {
		case "create":
			if err := a.allow(ctx, "iam:policies:create", tenantID, "create policy "+name); err != nil {
				return err
			}
			created, err := CreatePolicy(ctx, server, tx, principal, tenant, core.NewObject("tenantId", tenantID).Assign(item.desired))
			if err != nil {
				return err
			}
			policyIDs[jsString(created.Get("name"))] = jsString(created.Get("id"))
		case "update":
			if err := a.allow(ctx, "iam:policies:update", jsString(item.record.Get("id")), "update policy "+name); err != nil {
				return err
			}
			if _, err := UpdatePolicy(ctx, server, tx, principal, core.NewObject(
				"tenantId", tenantID,
				"policyId", item.record.Get("id"),
				"version", item.record.Get("version"),
				"description", item.desired.Get("description"),
				"document", item.desired.Get("document"),
			)); err != nil {
				return err
			}
		}
	}
	// Roles (creates and updates), then deletions after bindings are gone.
	roleIDs := map[string]string{}
	for _, role := range state.roles {
		roleIDs[jsString(role.Get("name"))] = jsString(role.Get("id"))
	}
	for _, item := range planned.roles {
		action := syncChangeAction(item.change)
		if action == "unchanged" || action == "delete" {
			continue
		}
		name := syncChangeName(item.change)
		policies, err := syncIDsOf(syncStrings(item.desired.Get("policies")), policyIDs, "policy")
		if err != nil {
			return err
		}
		document, err := syncRoleDocument(item.desired)
		if err != nil {
			return err
		}
		if action == "create" {
			if err := a.allow(ctx, "iam:roles:create", tenantID, "create role "+name); err != nil {
				return err
			}
			input := core.NewObject(
				"tenantId", tenantID,
				"name", item.desired.Get("name"),
				"description", item.desired.Get("description"),
				"policyIds", policies,
			)
			if truthy(document) {
				input.Set("document", document)
			}
			created, err := CreateRole(ctx, server, tx, principal, tenant, input)
			if err != nil {
				return err
			}
			roleIDs[jsString(created.Get("name"))] = jsString(created.Get("id"))
		} else {
			if err := a.allow(ctx, "iam:roles:update", jsString(item.record.Get("id")), "update role "+name); err != nil {
				return err
			}
			if _, err := UpdateRole(ctx, server, tx, principal, core.NewObject(
				"tenantId", tenantID,
				"roleId", item.record.Get("id"),
				"description", item.desired.Get("description"),
				"policyIds", policies,
				"document", coalesce(document, nil),
			)); err != nil {
				return err
			}
		}
	}
	// Inheritance is applied once every role exists, so a document may introduce parent and child together.
	for _, item := range planned.roles {
		action := syncChangeAction(item.change)
		if action == "delete" {
			continue
		}
		wanted := syncStrings(item.desired.Get("inherits"))
		var current []string
		if item.record != nil {
			for _, roleID := range syncStringList(coalesce(item.record.Get("inherits"), []any{})) {
				for _, role := range state.roles {
					if jsString(role.Get("id")) == roleID {
						current = append(current, jsString(role.Get("name")))
						break
					}
				}
			}
		}
		if action == "unchanged" || syncSame(syncSortedList(wanted), syncSortedList(current)) {
			continue
		}
		roleID, ok := roleIDs[jsString(item.desired.Get("name"))]
		if !ok || roleID == "" {
			continue
		}
		if err := a.allow(ctx, "iam:roles:update", roleID, "set inheritance of role "+syncChangeName(item.change)); err != nil {
			return err
		}
		inherits, err := syncIDsOf(wanted, roleIDs, "role")
		if err != nil {
			return err
		}
		if _, err := UpdateRole(ctx, server, tx, principal, core.NewObject("tenantId", tenantID, "roleId", roleID, "inherits", inherits)); err != nil {
			return err
		}
	}
	// Groups and their members
	groupIDs := map[string]string{}
	for _, group := range state.groups {
		groupIDs[jsString(group.Get("name"))] = jsString(group.Get("id"))
	}
	// Groups configuration sync manages; others (teams' backing groups) never appear in a document.
	managedGroupIDs := map[string]bool{}
	for _, group := range state.groups {
		managedGroupIDs[jsString(group.Get("id"))] = true
	}
	for _, item := range planned.groups {
		action := syncChangeAction(item.change)
		if action == "delete" {
			continue
		}
		name := syncChangeName(item.change)
		fields := syncChangeFields(item.change)
		groupID := ""
		if item.record != nil {
			groupID = jsString(item.record.Get("id"))
		}
		if action == "create" {
			if err := a.allow(ctx, "iam:groups:create", tenantID, "create group "+name); err != nil {
				return err
			}
			created, err := CreateGroup(ctx, server, tx, tenant, core.NewObject("tenantId", tenantID).Assign(item.desired))
			if err != nil {
				return err
			}
			groupID = jsString(created.Get("id"))
			groupIDs[jsString(item.desired.Get("name"))] = groupID
		} else if action == "update" && containsString(fields, "description") {
			if err := a.allow(ctx, "iam:groups:update", groupID, "update group "+name); err != nil {
				return err
			}
			next := item.record.Spread()
			if description := item.desired.Get("description"); !isUndefined(description) {
				checked, err := Text(description, "description", 512)
				if err != nil {
					return err
				}
				next.Set("description", checked)
			}
			if _, err := tx.Put(ctx, "groups", next); err != nil {
				return err
			}
		}
		if isUndefined(item.desired.Get("members")) || (action != "create" && !containsString(fields, "members")) {
			continue
		}
		if err := a.allow(ctx, "iam:groups:update", groupID, "change members of "+name); err != nil {
			return err
		}
		wantedIDs := newOrderedSet()
		for _, email := range syncStrings(item.desired.Get("members")) {
			identity := state.identitiesByEmail[email]
			if identity == nil {
				return invalidInput("Group " + name + ": unknown member " + email)
			}
			wantedIDs.Add(jsString(identity.Get("id")))
		}
		currentIDs := newOrderedSet()
		for _, identity := range state.members[groupID] {
			currentIDs.Add(jsString(identity.Get("id")))
		}
		// License seats of the group's products are reconciled once, after its members changed.
		if _, err := BatchGroupLicenses(ctx, server, tx, func(ctx context.Context) (any, error) {
			for _, identityID := range wantedIDs.Values() {
				if !currentIDs.Has(identityID) {
					if _, err := AddGroupMember(ctx, server, tx, principal, core.NewObject("tenantId", tenantID, "groupId", groupID, "identityId", identityID)); err != nil {
						return nil, err
					}
				}
			}
			for _, identityID := range currentIDs.Values() {
				if !wantedIDs.Has(identityID) {
					if err := RemoveGroupMember(ctx, server, tx, principal, core.NewObject("tenantId", tenantID, "groupId", groupID, "identityId", identityID)); err != nil {
						return nil, err
					}
				}
			}
			return nil, nil
		}); err != nil {
			return err
		}
	}
	// Group bindings
	for _, item := range planned.bindings {
		action := syncChangeAction(item.change)
		name := syncChangeName(item.change)
		if action == "unchanged" {
			continue
		}
		if action == "delete" {
			for _, binding := range item.records {
				if err := a.allow(ctx, "iam:bindings:delete", jsString(binding.Get("id")), "delete binding "+name); err != nil {
					return err
				}
				if err := DeleteBinding(ctx, server, tx, principal, binding); err != nil {
					return err
				}
			}
			continue
		}
		desired := item.desired
		roleID := roleIDs[jsString(desired.Get("role"))]
		groupID := groupIDs[jsString(desired.Get("group"))]
		if roleID == "" || groupID == "" {
			return invalidInput("Unknown binding " + name)
		}
		if err := a.allow(ctx, "iam:bindings:create", roleID, "bind "+name); err != nil {
			return err
		}
		// What configuration cannot express survives a replacement: an approver group sync does not manage (a team's
		// backing group, left out of exports), and the start and end dates of a temporary or future-dated grant.
		previous := item.records
		var keptApprover any = core.Undefined
		for _, binding := range previous {
			if approver := binding.Get("approverGroupId"); truthy(approver) && !managedGroupIDs[jsString(approver)] {
				keptApprover = approver
				break
			}
		}
		now := float64(server.Now())
		dates := core.NewObject()
		if len(previous) > 0 {
			every := true
			latest := math.Inf(-1)
			for _, binding := range previous {
				if isUndefined(binding.Get("expiresAt")) {
					every = false
					break
				}
				latest = math.Max(latest, jsNumber(binding.Get("expiresAt")))
			}
			if every {
				dates.Set("expiresAt", latest)
			}
		}
		var pending []*core.Object
		for _, binding := range previous {
			if startsAt := binding.Get("startsAt"); !isUndefined(startsAt) && jsNumber(startsAt) > now {
				pending = append(pending, binding)
			}
		}
		starts := core.NewObject()
		if len(previous) > 0 && len(pending) == len(previous) {
			earliest := math.Inf(1)
			for _, binding := range pending {
				earliest = math.Min(earliest, jsNumber(binding.Get("startsAt")))
			}
			starts.Set("startsAt", earliest)
		}
		eligibility := core.NewObject()
		if truthy(desired.Get("eligible")) {
			eligibility.Set("eligible", true)
			eligibility.Set("maxActivationMs", desired.Get("maxActivationMs"))
			eligibility.Set("requireJustification", desired.Get("requireJustification"))
			eligibility.Set("requireMfa", desired.Get("requireMfa"))
			eligibility.Set("requireApproval", desired.Get("requireApproval"))
			if approver := desired.Get("approverGroup"); !isUndefined(approver) {
				eligibility.Set("approverGroupId", syncGroupIDOrNull(groupIDs, jsString(approver)))
			} else if truthy(keptApprover) {
				eligibility.Set("approverGroupId", keptApprover)
			}
			eligibility.Set("managerApproval", desired.Get("managerApproval"))
		} else {
			eligibility.Set("eligible", false)
		}
		if window := desired.Get("window"); !isUndefined(window) {
			eligibility.Set("window", window)
		}
		if action != "create" {
			eligibility.Assign(dates, starts)
		}
		input := core.NewObject("tenantId", tenantID, "roleId", roleID, "subjectType", "group", "subjectId", groupID).Assign(eligibility)
		if action != "create" {
			// Eligibility changes replace the binding so the authority and activations start clean.
			for _, binding := range item.records {
				if err := DeleteBinding(ctx, server, tx, principal, binding); err != nil {
					return err
				}
			}
		}
		if _, err := CreateBinding(ctx, server, tx, principal, input, nil); err != nil {
			return err
		}
	}
	env := &SyncApplyEnv{
		Allow:             a.allow,
		RoleIDs:           roleIDs,
		GroupIDs:          groupIDs,
		IdentitiesByEmail: state.identitiesByEmail,
	}
	// Teams and departments (org-sync.ts) are created and updated before packages, whose rules may name them.
	if err := ApplyOrg(ctx, server, tx, principal, tenant, planned.org, env, "upsert"); err != nil {
		return err
	}
	// AI agents, models and budgets (ai-sync.ts), once groups exist; agents before the budgets that name them.
	if err := ApplyAi(ctx, server, tx, principal, tenant, planned.ai, env, "upsert"); err != nil {
		return err
	}
	if err := a.applyPackages(ctx, roleIDs, groupIDs, managedGroupIDs); err != nil {
		return err
	}
	// Terms of use: a content change publishes a new version (people accept what they were shown).
	for _, item := range planned.agreements {
		action := syncChangeAction(item.change)
		if action == "unchanged" {
			continue
		}
		resourceID := tenantID
		if item.record != nil {
			resourceID = jsString(item.record.Get("id"))
		}
		if err := a.allow(ctx, "iam:agreements:manage", resourceID, action+" agreement "+syncChangeName(item.change)); err != nil {
			return err
		}
		if action == "delete" {
			if err := DeleteAgreement(ctx, tx, item.record); err != nil {
				return err
			}
			continue
		}
		desired := item.desired
		if _, err := SaveAgreement(ctx, server, tx, tenantID, core.NewObject(
			"name", desired.Get("name"),
			"content", desired.Get("content"),
			"url", coalesce(desired.Get("url"), ""),
			"required", coalesce(desired.Get("required"), true),
			"reacceptAfterDays", coalesce(desired.Get("reacceptAfterDays"), nil),
		), item.record, action == "update" && containsString(syncChangeFields(item.change), "content")); err != nil {
			return err
		}
	}
	// Access invariants, once their groups exist and before any group is deleted.
	for _, item := range planned.invariants {
		action := syncChangeAction(item.change)
		if action == "unchanged" {
			continue
		}
		resourceID := tenantID
		if item.record != nil {
			resourceID = jsString(item.record.Get("id"))
		}
		if err := a.allow(ctx, "iam:invariants:manage", resourceID, action+" invariant "+syncChangeName(item.change)); err != nil {
			return err
		}
		if action == "delete" {
			if err := tx.Delete(ctx, "accessInvariants", jsString(item.record.Get("id"))); err != nil {
				return err
			}
			continue
		}
		desired := item.desired
		subject, _ := desired.Get("subject").(*core.Object)
		var stored *core.Object
		switch {
		case subject.Has("group"):
			stored = core.NewObject("groupId", syncIDOrUndefined(groupIDs, jsString(subject.Get("group"))))
		case subject.Has("identity"):
			identity := state.identitiesByEmail[jsString(subject.Get("identity"))]
			if identity == nil {
				return invalidInput("Invariant " + syncChangeName(item.change) + ": unknown person " + jsString(subject.Get("identity")))
			}
			stored = core.NewObject("identityId", identity.Get("id"))
		default:
			stored = subject
		}
		if _, err := SaveInvariant(ctx, server, tx, tenantID, core.NewObject(
			"name", desired.Get("name"),
			"description", coalesce(desired.Get("description"), ""),
			"subject", stored,
			"action", desired.Get("action"),
			"resource", desired.Get("resource"),
			"expect", desired.Get("expect"),
			"mode", coalesce(desired.Get("mode"), "monitor"),
			"assumeMfa", coalesce(desired.Get("assumeMfa"), true),
		), jsString(principal.Identity.Get("id")), item.record); err != nil {
			return err
		}
	}
	// Team and department deletions (org-sync.ts), once packages stopped naming them and before any role is deleted.
	if err := ApplyOrg(ctx, server, tx, principal, tenant, planned.org, env, "delete"); err != nil {
		return err
	}
	// AI budget, model and agent deletions (ai-sync.ts), before the groups budgets name are deleted.
	if err := ApplyAi(ctx, server, tx, principal, tenant, planned.ai, env, "delete"); err != nil {
		return err
	}
	// Deletions, dependents first.
	for _, item := range planned.groups {
		if syncChangeAction(item.change) != "delete" {
			continue
		}
		if err := a.allow(ctx, "iam:groups:delete", jsString(item.record.Get("id")), "delete group "+syncChangeName(item.change)); err != nil {
			return err
		}
		if err := DeleteGroup(ctx, server, tx, principal, item.record); err != nil {
			return err
		}
	}
	for _, item := range planned.roles {
		if syncChangeAction(item.change) != "delete" {
			continue
		}
		if err := a.allow(ctx, "iam:roles:delete", jsString(item.record.Get("id")), "delete role "+syncChangeName(item.change)); err != nil {
			return err
		}
		if err := DeleteRole(ctx, server, tx, principal, item.record); err != nil {
			return err
		}
	}
	for _, item := range planned.policies {
		if syncChangeAction(item.change) != "delete" {
			continue
		}
		if err := a.allow(ctx, "iam:policies:delete", jsString(item.record.Get("id")), "delete policy "+syncChangeName(item.change)); err != nil {
			return err
		}
		if err := DeletePolicy(ctx, server, tx, principal, item.record); err != nil {
			return err
		}
	}
	return nil
}

// applyPackages creates and updates access packages once their roles and groups exist, and deletes them before those
// go.
func (a *configApply) applyPackages(ctx context.Context, roleIDs, groupIDs map[string]string, managedGroupIDs map[string]bool) error {
	server, tx, principal, tenantID := a.server, a.tx, a.principal, a.tenantID
	orgIDs, err := OrgRuleIDs(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	// Rules name groups; the tenant stores their IDs (including groups this apply just created).
	ruleIDs := func(rule any) (any, error) {
		mapped, err := MapRuleGroups(rule, func(name string) string { return syncLookup(groupIDs, name) })
		if err != nil {
			return nil, err
		}
		return orgIDs(mapped)
	}
	for _, item := range a.planned.packages {
		action := syncChangeAction(item.change)
		name := syncChangeName(item.change)
		if action == "unchanged" {
			continue
		}
		if action == "delete" {
			if err := a.allow(ctx, "iam:packages:delete", jsString(item.record.Get("id")), "delete package "+name); err != nil {
				return err
			}
			if err := DeletePackage(ctx, server, tx, item.record); err != nil {
				return err
			}
			continue
		}
		desired := item.desired
		roles, err := syncIDsOf(syncStrings(desired.Get("roles")), roleIDs, "role")
		if err != nil {
			return err
		}
		groups, err := syncIDsOf(syncStrings(desired.Get("groups")), groupIDs, "group")
		if err != nil {
			return err
		}
		if action == "create" {
			if err := a.allow(ctx, "iam:packages:create", tenantID, "create package "+name); err != nil {
				return err
			}
			input := core.NewObject(
				"tenantId", tenantID,
				"name", desired.Get("name"),
				"description", desired.Get("description"),
				"roleIds", roles,
				"groupIds", groups,
				"maxDurationMs", desired.Get("maxDurationMs"),
				"requireJustification", desired.Get("requireJustification"),
				"requestable", desired.Get("requestable"),
			)
			if approver := desired.Get("approverGroup"); !isUndefined(approver) {
				input.Set("approverGroupId", syncGroupIDOrNull(groupIDs, jsString(approver)))
			}
			input.Set("managerApproval", desired.Get("managerApproval"))
			if rule := desired.Get("autoAssign"); truthy(rule) {
				mapped, err := ruleIDs(rule)
				if err != nil {
					return err
				}
				input.Set("autoAssign", mapped)
			}
			if _, err := CreatePackage(ctx, server, tx, input, principal); err != nil {
				return err
			}
			continue
		}
		record := item.record
		if err := a.allow(ctx, "iam:packages:update", jsString(record.Get("id")), "update package "+name); err != nil {
			return err
		}
		input := core.NewObject()
		if !core.StrictEquals(record.Get("name"), desired.Get("name")) {
			input.Set("name", desired.Get("name"))
		}
		input.Set("description", coalesce(desired.Get("description"), nil))
		input.Set("roleIds", roles)
		input.Set("groupIds", groups)
		input.Set("maxDurationMs", coalesce(desired.Get("maxDurationMs"), nil))
		input.Set("requireJustification", desired.Get("requireJustification") == true)
		input.Set("requestable", desired.Get("requestable") == true)
		// An approver group sync does not manage (a team's backing group) is not in the document; keep it.
		var approverGroupID any = nil
		if approver := desired.Get("approverGroup"); !isUndefined(approver) {
			approverGroupID = syncGroupIDOrNull(groupIDs, jsString(approver))
		} else if kept := record.Get("approverGroupId"); truthy(kept) && !managedGroupIDs[jsString(kept)] {
			approverGroupID = kept
		}
		input.Set("approverGroupId", approverGroupID)
		input.Set("managerApproval", desired.Get("managerApproval") == true)
		// Passed only when the plan lists the rule, so an unrelated edit never moves its ownership.
		if containsString(syncChangeFields(item.change), "autoAssign") {
			var rule any = nil
			if value := desired.Get("autoAssign"); value != nil {
				if rule, err = ruleIDs(value); err != nil {
					return err
				}
			}
			input.Set("autoAssign", rule)
		}
		if _, err := UpdatePackage(ctx, server, tx, record, input, principal); err != nil {
			return err
		}
	}
	return nil
}

// configInput reads the tenantId and prune members of a plan or apply request.
func configInput(body *core.Object) (tenantID any, prune bool) {
	return body.Get("tenantId"), body.Get("prune") == true
}

// Apply is POST {basePath}/config/apply. Applies a desired configuration in one transaction: every change is
// authorized like the direct API call (create/update/delete on the item) under the caller's grant authority, and one
// failure rolls everything back. Requires iam:config:apply; audited as `config:apply` with the change summary.
func (api *ConfigAPI) Apply(ctx context.Context, credential core.CredentialInput, input In[apitypes.ConfigApplyInput]) (Out[apitypes.ConfigApplyOutput], error) {
	server := api.server
	tenantID, prune := configInput(input.Body)
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:config:apply", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		desired, err := ValidateTenantConfig(input.Get("config"))
		if err != nil {
			return nil, err
		}
		state, err := readConfigState(ctx, server, call.Tx, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		planned, err := computeConfigPlan(server, tenantID, desired, state, prune)
		if err != nil {
			return nil, err
		}
		apply := &configApply{server: server, tx: call.Tx, principal: call.Principal, tenant: call.Tenant,
			tenantID: jsString(call.Tenant.Get("id")), planned: planned, state: state}
		if err := apply.run(ctx); err != nil {
			return nil, err
		}
		changed := []string{}
		for _, change := range planned.changes {
			if syncChangeAction(change) != "unchanged" {
				changed = append(changed, strings.Join([]string{syncChangeAction(change), syncChangeKind(change), syncChangeName(change)}, " "))
			}
		}
		metadata := core.NewObject("prune", planned.plan.Get("prune")).Assign(planned.summaryObject())
		metadata.Set("changed", stringsOf(changed))
		if err := server.Events.Audit(ctx, call.Tx, call.Principal, "config:apply", jsString(tenantID), jsString(tenantID), "allow", false, metadata); err != nil {
			return nil, err
		}
		return planned.plan.Spread(core.NewObject("applied", true)), nil
	}, false)
	return Out[apitypes.ConfigApplyOutput]{Value: result}, err
}

// Export is POST {basePath}/config/export. The tenant's roles, policies, groups (with member emails), tenant-defined
// resource types, group bindings, and access packages (and the other configuration kinds) as a configuration
// document that `plan`/`apply` accept. Requires iam:config:read.
func (api *ConfigAPI) Export(ctx context.Context, credential core.CredentialInput, input In[apitypes.ConfigExportInput]) (Out[apitypes.ConfigExportOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:config:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		state, err := readConfigState(ctx, server, call.Tx, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		return exportConfigState(state)
	}, false)
	return Out[apitypes.ConfigExportOutput]{Value: result}, err
}

// Plan is POST {basePath}/config/plan. Dry run: the changes `apply` would make for a desired configuration, by name.
// Kinds absent from the configuration are left alone; with `prune`, items of a listed kind that the configuration
// omits are deleted. Requires iam:config:read; nothing is written.
func (api *ConfigAPI) Plan(ctx context.Context, credential core.CredentialInput, input In[apitypes.ConfigPlanInput]) (Out[apitypes.ConfigPlanOutput], error) {
	server := api.server
	tenantID, prune := configInput(input.Body)
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:config:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		desired, err := ValidateTenantConfig(input.Get("config"))
		if err != nil {
			return nil, err
		}
		state, err := readConfigState(ctx, server, call.Tx, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		planned, err := computeConfigPlan(server, tenantID, desired, state, prune)
		if err != nil {
			return nil, err
		}
		return planned.plan, nil
	}, false)
	return Out[apitypes.ConfigPlanOutput]{Value: result}, err
}
