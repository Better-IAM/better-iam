package server

// Port of packages/server/src/access-policy.ts.

import (
	"math"

	"github.com/Better-IAM/better-iam/go/core"
)

// DefaultActivationMs is the default just-in-time activation length (one hour).
const DefaultActivationMs = 3_600_000

// MaxActivationMs is the longest activation (seven days).
const MaxActivationMs = 7 * 86400_000

// DefaultApprovalLifetimeMs is how long an activation request waits for approval by default (one day).
const DefaultApprovalLifetimeMs = 24 * 3_600_000

var accessPolicyKeys = []string{"maxActivationMs", "requireJustification", "requireMfa", "requireApproval", "approvalLifetimeMs"}

// TenantAccessPolicy validates a tenant access policy; unknown keys and non-boolean flags are refused, `false` flags
// are dropped. The result's members follow the TypeScript assignment order.
func TenantAccessPolicy(value any) (*core.Object, error) {
	input, err := Object(core.Normalize(value))
	if err != nil {
		return nil, err
	}
	policy := core.NewObject()
	for _, key := range input.Keys() {
		if !containsString(accessPolicyKeys, key) {
			return nil, invalidInput("Unknown access policy field " + key)
		}
	}
	if item := input.Get("maxActivationMs"); !isUndefined(item) {
		valid, err := Integer(item, "maxActivationMs", 60_000, MaxActivationMs)
		if err != nil {
			return nil, err
		}
		policy.Set("maxActivationMs", valid)
	}
	if item := input.Get("approvalLifetimeMs"); !isUndefined(item) {
		valid, err := Integer(item, "approvalLifetimeMs", 5*60_000, 30*86400_000)
		if err != nil {
			return nil, err
		}
		policy.Set("approvalLifetimeMs", valid)
	}
	for _, flag := range []string{"requireJustification", "requireMfa", "requireApproval"} {
		item := input.Get(flag)
		if isUndefined(item) {
			continue
		}
		if typeOf(item) != "boolean" {
			return nil, invalidInput(flag + " must be boolean")
		}
		if item == true {
			policy.Set(flag, true)
		}
	}
	return policy, nil
}

// ActivationRules govern activating one binding.
type ActivationRules struct {
	RequireJustification bool    `json:"requireJustification"`
	RequireMfa           bool    `json:"requireMfa"`
	RequireApproval      bool    `json:"requireApproval"`
	MaxActivationMs      float64 `json:"maxActivationMs"`
	ApprovalLifetimeMs   float64 `json:"approvalLifetimeMs"`
}

// ActivationRulesFor is activationRules: the binding's own settings tightened by the tenant's policy (nil: none).
func ActivationRulesFor(binding *core.Object, policy *core.Object) ActivationRules {
	bindingMax := numberOr(binding.Get("maxActivationMs"), DefaultActivationMs)
	rules := ActivationRules{
		RequireJustification: binding.Get("requireJustification") == true || policy.Get("requireJustification") == true,
		RequireMfa:           binding.Get("requireMfa") == true || policy.Get("requireMfa") == true,
		RequireApproval:      binding.Get("requireApproval") == true || policy.Get("requireApproval") == true,
		MaxActivationMs:      bindingMax,
		ApprovalLifetimeMs:   numberOr(policy.Get("approvalLifetimeMs"), DefaultApprovalLifetimeMs),
	}
	if limit := policy.Get("maxActivationMs"); !isUndefined(limit) {
		rules.MaxActivationMs = math.Min(bindingMax, jsNumber(limit))
	}
	return rules
}

// numberOr is `value ?? fallback` for number members.
func numberOr(value any, fallback float64) float64 {
	if nullish(value) {
		return fallback
	}
	return jsNumber(value)
}
