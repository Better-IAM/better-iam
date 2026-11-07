package server

// Port of packages/server/src/tenant-policy.ts. Both validators take a model value and return the validated policy
// as a *core.Object whose members are in the TypeScript assignment order, so stored tenant records are
// byte-identical to the ones a TypeScript server writes.

import (
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

var authPolicyKeys = map[string]bool{
	"requireMfa": true, "allowedMethods": true, "sessionLifetimeMs": true, "sessionIdleTimeoutMs": true,
	"maxAttempts": true, "minPasswordLength": true, "maxSessions": true, "allowImpersonation": true,
	"trustedDeviceDays": true, "passwordHistory": true, "passwordMaxAgeDays": true, "passwordMinClasses": true,
	"passwordRejectPersonalInfo": true, "notifyNewSignIn": true, "allowedIpRanges": true, "mfaEmailCodes": true,
	"requireMfaForOwners": true, "bindSessionsToIp": true,
}

const thirtyDays = 30 * 24 * 60 * 60_000

// TenantAuthPolicy validates a tenant authentication policy; every field is optional but must be well-formed.
func TenantAuthPolicy(value any) (*core.Object, error) {
	input, err := Object(core.Normalize(value))
	if err != nil {
		return nil, err
	}
	policy := core.NewObject()
	for _, key := range input.Keys() {
		if !authPolicyKeys[key] {
			return nil, invalidInput("Unknown authentication policy field " + key)
		}
	}
	flag := func(key string) error {
		item := input.Get(key)
		if isUndefined(item) {
			return nil
		}
		if typeOf(item) != "boolean" {
			return invalidInput(key + " must be a boolean")
		}
		policy.Set(key, item)
		return nil
	}
	number := func(key string, min, max float64) error {
		item := input.Get(key)
		if isUndefined(item) {
			return nil
		}
		valid, err := Integer(item, key, min, max)
		if err != nil {
			return err
		}
		policy.Set(key, valid)
		return nil
	}
	if err := flag("requireMfa"); err != nil {
		return nil, err
	}
	if methods := input.Get("allowedMethods"); !isUndefined(methods) {
		list, err := Strings(methods, "allowedMethods")
		if err != nil {
			return nil, err
		}
		list = unique(list)
		valid := len(list) > 0
		for _, method := range list {
			if !containsString(core.AuthMethods, method) {
				valid = false
			}
		}
		if !valid {
			return nil, invalidInput("allowedMethods must list one or more of " + strings.Join(core.AuthMethods, ", "))
		}
		policy.Set("allowedMethods", stringsOf(list))
	}
	if err := number("sessionLifetimeMs", 60_000, thirtyDays); err != nil {
		return nil, err
	}
	if err := number("sessionIdleTimeoutMs", 60_000, thirtyDays); err != nil {
		return nil, err
	}
	lifetime, hasLifetime := policy.Number("sessionLifetimeMs")
	idle, hasIdle := policy.Number("sessionIdleTimeoutMs")
	if hasLifetime && hasIdle && idle > lifetime {
		return nil, invalidInput("sessionIdleTimeoutMs cannot exceed sessionLifetimeMs")
	}
	if err := number("maxAttempts", 1, 100_000); err != nil {
		return nil, err
	}
	if err := number("minPasswordLength", 12, 128); err != nil {
		return nil, err
	}
	if err := number("maxSessions", 1, 100); err != nil {
		return nil, err
	}
	if err := flag("allowImpersonation"); err != nil {
		return nil, err
	}
	if err := number("trustedDeviceDays", 0, 365); err != nil {
		return nil, err
	}
	if err := number("passwordHistory", 1, 24); err != nil {
		return nil, err
	}
	if err := number("passwordMaxAgeDays", 1, 3650); err != nil {
		return nil, err
	}
	if err := number("passwordMinClasses", 2, 4); err != nil {
		return nil, err
	}
	if err := flag("passwordRejectPersonalInfo"); err != nil {
		return nil, err
	}
	if err := flag("notifyNewSignIn"); err != nil {
		return nil, err
	}
	if ranges := input.Get("allowedIpRanges"); !isUndefined(ranges) {
		list, err := Strings(ranges, "allowedIpRanges")
		if err != nil {
			return nil, err
		}
		list = unique(list)
		valid := len(list) > 0
		for _, item := range list {
			if !core.IsIPRange(item) {
				valid = false
			}
		}
		if !valid {
			return nil, invalidInput("allowedIpRanges must list one or more IPv4/IPv6 addresses or CIDR blocks")
		}
		policy.Set("allowedIpRanges", stringsOf(list))
	}
	for _, key := range []string{"mfaEmailCodes", "requireMfaForOwners", "bindSessionsToIp"} {
		if err := flag(key); err != nil {
			return nil, err
		}
	}
	return policy, nil
}

// TenantLimitKeys are the plan limits, in validation (and storage) order.
var TenantLimitKeys = []string{"identities", "serviceAccounts", "agents", "groups", "roles", "policies", "resources", "webhooks"}

// TenantLimits validates plan limits: known keys only, each a non-negative integer.
func TenantLimits(value any) (*core.Object, error) {
	input, err := Object(core.Normalize(value))
	if err != nil {
		return nil, err
	}
	limits := core.NewObject()
	for _, key := range input.Keys() {
		if !containsString(TenantLimitKeys, key) {
			return nil, invalidInput("Unknown limit " + key)
		}
	}
	for _, key := range TenantLimitKeys {
		if item := input.Get(key); !isUndefined(item) {
			valid, err := Integer(item, key, 0, 1_000_000_000)
			if err != nil {
				return nil, err
			}
			limits.Set(key, valid)
		}
	}
	return limits, nil
}
