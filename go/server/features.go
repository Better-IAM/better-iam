package server

// Port of packages/server/src/features.ts: feature flags at platform and tenant level. Flags the root tenant defines
// are platform flags and reach every tenant; flags another tenant defines reach only that tenant and its descendants.
// Keys are unique per defining tenant (`uniqueKey` = key), and when an ancestor defines the same key its flag wins, so
// a tenant can never shadow a platform flag.
//
// featureFlags records: id, tenantId, uniqueKey (the key), key, description?, defaultValue, rolloutPercentage?,
// tenantOverridable, killSwitch, internal, createdAt, createdBy, updatedAt, updatedBy.
//
// featureTargets records (in the tenant they apply to): id, tenantId, uniqueKey `{flagId}:{source}`, flagId, key,
// definerId, source ('target' | 'override'), value, setAt, setBy, locked?, expiresAt?, note?.
//
// A FeatureState is a model value: { chain: Tenant[] (nearest first), flags: { key: FeatureFlag } (the Map, in
// insertion order), shadowed: FeatureFlag[], entries: { flagId: FeatureTarget[] } }.

import (
	"context"
	"regexp"
	"strconv"

	"github.com/Better-IAM/better-iam/go/core"
)

// featureKeyPattern is keyPattern: lowercase letters and digits in segments joined by `-`, `_`, or `.`, starting
// with a letter: `new-billing`, `reports.v2`.
var featureKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)

// EnabledFeatureKeys (features.ts enabledFeatureKeys): The sorted keys of every flag (internal ones included) that
// is on for the tenant: the `tenant.features` context.
func EnabledFeatureKeys(state *core.Object) (result []string, err error) {
	evaluations, err := EvaluateFeatures(state, core.NewObject("includeInternal", true))
	if err != nil {
		return nil, err
	}
	result = []string{}
	for _, evaluation := range evaluations {
		if truthy(evaluation.Get("value")) {
			result = append(result, jsString(evaluation.Get("key")))
		}
	}
	return result, nil
}

// featureStateParts unpacks a FeatureState model value.
func featureStateParts(state *core.Object) (chain []*core.Object, flags *core.Object, entries *core.Object) {
	if list, ok := state.Get("chain").([]any); ok {
		for _, item := range list {
			if realm, ok := item.(*core.Object); ok {
				chain = append(chain, realm)
			}
		}
	}
	flags, _ = state.Get("flags").(*core.Object)
	if flags == nil {
		flags = core.NewObject()
	}
	entries, _ = state.Get("entries").(*core.Object)
	if entries == nil {
		entries = core.NewObject()
	}
	return chain, flags, entries
}

// EvaluateFeatures (features.ts evaluateFeatures): Evaluates the flags that reach a tenant, sorted by key. `keys`
// restricts the result (unknown keys evaluate to `false` with reason `UNKNOWN`); internal flags are included only
// with `includeInternal`.
func EvaluateFeatures(state *core.Object, options *core.Object) (result []*core.Object, err error) {
	if options == nil {
		options = core.NewObject()
	}
	chain, flags, _ := featureStateParts(state)
	visible := func(flag *core.Object) bool {
		return options.Get("includeInternal") == true || !truthy(flag.Get("internal")) ||
			// Internal flags stay visible to the tenant that defines them.
			(len(chain) > 0 && flag.Get("tenantId") == chain[0].Get("id"))
	}
	if keys := options.Get("keys"); !nullish(keys) {
		var list []string
		switch typed := keys.(type) {
		case []string:
			list = typed
		case []any:
			for _, item := range typed {
				list = append(list, jsString(item))
			}
		}
		sorted := unique(list)
		sortStable(sorted, compareUTF16)
		result = make([]*core.Object, 0, len(sorted))
		for _, key := range sorted {
			flag, _ := flags.Get(key).(*core.Object)
			if flag != nil && visible(flag) {
				evaluation, err := EvaluateFlag(state, flag)
				if err != nil {
					return nil, err
				}
				result = append(result, evaluation)
			} else {
				result = append(result, unknownFeature(key))
			}
		}
		return result, nil
	}
	var reaching []*core.Object
	flags.Entries(func(_ string, value any) bool {
		if flag, ok := value.(*core.Object); ok && visible(flag) {
			reaching = append(reaching, flag)
		}
		return true
	})
	sortStable(reaching, byFeatureKey)
	result = make([]*core.Object, 0, len(reaching))
	for _, flag := range reaching {
		evaluation, err := EvaluateFlag(state, flag)
		if err != nil {
			return nil, err
		}
		result = append(result, evaluation)
	}
	return result, nil
}

// byFeatureKey orders records by their `key` (a.key < b.key ? -1 : a.key > b.key ? 1 : 0).
func byFeatureKey(a, b *core.Object) int {
	return compareUTF16(jsString(a.Get("key")), jsString(b.Get("key")))
}

// EvaluateFlag (features.ts evaluateFlag): One flag's value for `state.chain[0]`. Precedence: the kill switch; then,
// walking from the tenant up to (not including) the defining tenant, the nearest tenant with an override or a
// target, where a tenant's own override beats a target on the same tenant and a locked target silences overrides at
// and below its tenant; then the rollout; then the default.
func EvaluateFlag(state *core.Object, flag *core.Object) (result *core.Object, err error) {
	chain, _, stateEntries := featureStateParts(state)
	definer := flag.Get("tenantId")
	depth := -1
	for index, realm := range chain {
		if realm.Get("id") == definer {
			depth = index
			break
		}
	}
	scope := "tenant"
	if len(chain) > 0 && chain[len(chain)-1].Get("id") == definer {
		scope = "platform"
	}
	base := func() *core.Object {
		return core.NewObject("key", flag.Get("key"), "scope", scope, "definedBy", definer)
	}
	// Only tenants strictly below the defining tenant carry targets and overrides for its flag.
	var below []*core.Object
	if depth >= 0 {
		below = chain[:depth]
	}
	var entries []*core.Object
	if list, ok := stateEntries.Get(jsString(flag.Get("id"))).([]any); ok {
		for _, item := range list {
			if entry, ok := item.(*core.Object); ok && entry.Get("definerId") == definer {
				entries = append(entries, entry)
			}
		}
	}
	at := func(realm *core.Object, source string) *core.Object {
		for _, entry := range entries {
			if entry.Get("tenantId") == realm.Get("id") && entry.Get("source") == source {
				return entry
			}
		}
		return nil
	}
	lockedAt := -1
	for index, realm := range below {
		if target := at(realm, "target"); target != nil && truthy(target.Get("locked")) {
			lockedAt = index
		}
	}
	overridesApply := truthy(flag.Get("tenantOverridable")) && !truthy(flag.Get("internal"))
	overridable := overridesApply && depth > 0 && lockedAt < 0
	locked := lockedAt >= 0
	if truthy(flag.Get("killSwitch")) {
		return base().Set("value", false).Set("reason", "KILL_SWITCH").Set("locked", locked).Set("overridable", overridable), nil
	}
	for index, realm := range below {
		var decided *core.Object
		if overridesApply && index > lockedAt {
			decided = at(realm, "override")
		}
		if decided == nil {
			decided = at(realm, "target")
		}
		if decided != nil {
			reason := "TARGET"
			if decided.Get("source") == "override" {
				reason = "OVERRIDE"
			}
			out := base().Set("value", decided.Get("value")).Set("reason", reason).Set("decidedBy", realm.Get("id"))
			if expiresAt := decided.Get("expiresAt"); !isUndefined(expiresAt) {
				out.Set("expiresAt", expiresAt)
			}
			return out.Set("locked", locked).Set("overridable", overridable), nil
		}
	}
	if percentage := flag.Get("rolloutPercentage"); !isUndefined(percentage) {
		// The branch directly below the defining tenant, so an organization and its projects agree.
		var unit *core.Object
		if len(below) > 0 {
			unit = below[len(below)-1]
		} else if len(chain) > 0 {
			unit = chain[0]
		}
		value := false
		if unit != nil {
			value = RolloutBucket(jsString(flag.Get("key")), jsString(unit.Get("id"))) < jsNumber(percentage)
		}
		return base().Set("value", value).Set("reason", "ROLLOUT").Set("locked", locked).Set("overridable", overridable), nil
	}
	return base().Set("value", flag.Get("defaultValue")).Set("reason", "DEFAULT").Set("locked", locked).Set("overridable", overridable), nil
}

// RolloutBucket (features.ts rolloutBucket): the rollout position (0 to 99.99) of a tenant branch for a flag: stable
// per key and tenant, so raising the percentage only ever adds tenants, and different flags spread over different
// tenants.
func RolloutBucket(key, tenantID string) float64 {
	prefix, _ := strconv.ParseUint(Hash("feature:" + key + ":" + tenantID)[:8], 16, 64)
	return float64(prefix%10_000) / 100
}

// unknownFeature is the evaluation reported for a key no flag defines along the tenant's ancestry.
func unknownFeature(key string) *core.Object {
	return core.NewObject("key", key, "value", false, "reason", "UNKNOWN", "scope", "platform", "locked", false, "overridable", false)
}

// FeatureKey (features.ts featureKey): Validates a flag key: at most 64 characters matching `keyPattern`.
func FeatureKey(value any) (result string, err error) {
	key, err := Text(value, "key", 64)
	if err != nil {
		return "", err
	}
	if !featureKeyPattern.MatchString(key) {
		return "", invalidInput(`Flag keys are lowercase letters and digits joined by "-", "_", or ".", starting with a letter`)
	}
	return key, nil
}

// featureSettingKeys are the settings a patch may carry.
var featureSettingKeys = newOrderedSet("description", "defaultValue", "rolloutPercentage", "tenantOverridable", "killSwitch", "internal")

// FeatureSettings (features.ts featureSettings): Applies a settings patch to `current` (defaults for a new flag) and
// validates the result. `null` clears `description` and `rolloutPercentage`; unknown fields are refused.
func FeatureSettings(input *core.Object, current *core.Object) (result *core.Object, err error) {
	if current == nil {
		current = core.NewObject("defaultValue", false, "tenantOverridable", false, "killSwitch", false, "internal", false)
	}
	checked, err := Object(input)
	if err != nil {
		return nil, err
	}
	for _, field := range checked.Keys() {
		if !featureSettingKeys.Has(field) && field != "tenantId" && field != "key" {
			return nil, invalidInput("Unknown flag field " + field)
		}
	}
	next := core.NewObject(
		"defaultValue", current.Get("defaultValue"),
		"tenantOverridable", current.Get("tenantOverridable"),
		"killSwitch", current.Get("killSwitch"),
		"internal", current.Get("internal"),
	)
	if description := current.Get("description"); !isUndefined(description) {
		next.Set("description", description)
	}
	if percentage := current.Get("rolloutPercentage"); !isUndefined(percentage) {
		next.Set("rolloutPercentage", percentage)
	}
	for _, field := range []string{"defaultValue", "tenantOverridable", "killSwitch", "internal"} {
		value := input.Get(field)
		if isUndefined(value) {
			continue
		}
		if _, ok := value.(bool); !ok {
			return nil, invalidInput(field + " must be a boolean")
		}
		next.Set(field, value)
	}
	if description := input.Get("description"); description == nil {
		next.Delete("description")
	} else if !isUndefined(description) {
		text, err := Text(description, "description", 512)
		if err != nil {
			return nil, err
		}
		next.Set("description", core.JSTrim(text))
	}
	if percentage := input.Get("rolloutPercentage"); percentage == nil {
		next.Delete("rolloutPercentage")
	} else if !isUndefined(percentage) {
		value, err := Integer(percentage, "rolloutPercentage", 0, 100)
		if err != nil {
			return nil, err
		}
		next.Set("rolloutPercentage", value)
	}
	if !isUndefined(next.Get("rolloutPercentage")) && truthy(next.Get("defaultValue")) {
		return nil, invalidInput("A rollout turns a flag on gradually: set defaultValue to false or remove rolloutPercentage")
	}
	if truthy(next.Get("internal")) && truthy(next.Get("tenantOverridable")) {
		return nil, invalidInput("Internal flags cannot be tenant-overridable")
	}
	return next, nil
}

// FeatureState (features.ts featureState): Reads the flags and pinned values along a tenant's ancestry (two lookups
// per tenant in the chain).
func FeatureState(ctx context.Context, tx core.IamStore, chain []*core.Object, now int64) (result *core.Object, err error) {
	flags := core.NewObject()
	shadowed := []any{}
	// Root first, so a flag defined closer to the root claims its key before a descendant's flag of the same key.
	for index := len(chain) - 1; index >= 0; index-- {
		found, err := tx.Find(ctx, FeatureCollections.Flags, core.NewObject("tenantId", chain[index].Get("id")), nil)
		if err != nil {
			return nil, err
		}
		for _, flag := range found {
			key := jsString(flag.Get("key"))
			if flags.Has(key) {
				shadowed = append(shadowed, flag)
			} else {
				flags.Set(key, flag)
			}
		}
	}
	entries := core.NewObject()
	for _, realm := range chain {
		found, err := tx.Find(ctx, FeatureCollections.Targets, core.NewObject("tenantId", realm.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		for _, entry := range found {
			expiresAt := entry.Get("expiresAt")
			if isUndefined(expiresAt) || jsNumber(expiresAt) > float64(now) {
				flagID := jsString(entry.Get("flagId"))
				list, _ := entries.Get(flagID).([]any)
				entries.Set(flagID, append(append([]any{}, list...), entry))
			}
		}
	}
	list := make([]any, len(chain))
	for index, realm := range chain {
		list[index] = realm
	}
	return core.NewObject("chain", list, "flags", flags, "shadowed", shadowed, "entries", entries), nil
}

// MentionsFeatures (features.ts mentionsFeatures): whether any statement of the documents names the
// `tenant.features` context key in a condition.
func MentionsFeatures(documents []any) bool {
	return anyConditionNames(documents, FeatureContextKey)
}

// FeatureCollections is features.ts featureCollections.
var FeatureCollections = struct {
	Flags   string
	Targets string
}{"featureFlags", "featureTargets"}

// FeatureContextKey is features.ts featureContextKey.
const FeatureContextKey = "tenant.features"

// MaxFeatureFlagsPerTenant is features.ts maxFeatureFlagsPerTenant.
const MaxFeatureFlagsPerTenant = 200
