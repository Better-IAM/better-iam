package server

// Skeleton of packages/server/src/features.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// EnabledFeatureKeys (features.ts enabledFeatureKeys): The sorted keys of every flag (internal ones included) that
// is on for the tenant: the `tenant.features` context.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EnabledFeatureKeys(state *core.Object) (result []string, err error) {
	err = notImplemented("features.ts enabledFeatureKeys")
	return
}

// EvaluateFeatures (features.ts evaluateFeatures): Evaluates the flags that reach a tenant, sorted by key. `keys`
// restricts the result (unknown keys evaluate to `false` with reason `UNKNOWN`); internal flags are included only
// with `includeInternal`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EvaluateFeatures(state *core.Object, options *core.Object) (result []*core.Object, err error) {
	err = notImplemented("features.ts evaluateFeatures")
	return
}

// EvaluateFlag (features.ts evaluateFlag): One flag's value for `state.chain[0]`. Precedence: the kill switch; then,
// walking from the tenant up to (not including) the defining tenant, the nearest tenant with an override or a
// target, where a tenant's own override beats a target on the same tenant and a locked target silences overrides at
// and below its tenant; then the rollout; then the default.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EvaluateFlag(state *core.Object, flag *core.Object) (result *core.Object, err error) {
	err = notImplemented("features.ts evaluateFlag")
	return
}

// FeatureKey (features.ts featureKey): Validates a flag key: at most 64 characters matching `keyPattern`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func FeatureKey(value any) (result string, err error) {
	err = notImplemented("features.ts featureKey")
	return
}

// FeatureSettings (features.ts featureSettings): Applies a settings patch to `current` (defaults for a new flag) and
// validates the result. `null` clears `description` and `rolloutPercentage`; unknown fields are refused.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func FeatureSettings(input *core.Object, current *core.Object) (result *core.Object, err error) {
	err = notImplemented("features.ts featureSettings")
	return
}

// FeatureState (features.ts featureState): Reads the flags and pinned values along a tenant's ancestry (two lookups
// per tenant in the chain).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func FeatureState(ctx context.Context, tx core.IamStore, chain []*core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("features.ts featureState")
	return
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
