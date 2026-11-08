package scim

// Port of packages/scim/src/validation.ts.

import (
	"context"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// hash is the lowercase hex SHA-256 of the UTF-8 value.
func hash(value string) string { return auth.HashToken(value) }

// object requires a JSON object.
func object(value any) (*core.Object, error) {
	o, ok := value.(*core.Object)
	if !ok || o == nil {
		return nil, core.NewIamError("invalidSyntax", "Expected a JSON object.")
	}
	return o, nil
}

// text requires a nonempty string of at most 512 characters and answers it trimmed; with optional, undefined answers
// nil.
func text(value any, field string, optional ...bool) (*string, error) {
	if len(optional) > 0 && optional[0] && core.IsUndefined(value) {
		return nil, nil
	}
	s, ok := value.(string)
	if !ok || core.JSTrim(s) == "" || utf16Len(s) > 512 {
		return nil, core.NewIamError("invalidValue", field+" must be a nonempty string of at most 512 characters.")
	}
	trimmed := core.JSTrim(s)
	return &trimmed, nil
}

// requiredText is text for a required value.
func requiredText(value any, field string) (string, error) {
	result, err := text(value, field)
	if err != nil {
		return "", err
	}
	return *result, nil
}

// fields rejects attributes outside allowed. Resource bodies pass through withoutIgnored (attributes.go) first, so
// what reaches this is an attribute no supported schema defines (or, with UnsupportedAttributes "reject", one this
// service does not store).
func fields(value *core.Object, allowed ...string) error {
	for _, key := range value.Keys() {
		if !containsString(allowed, key) {
			return core.NewIamError("mutability", "An unsupported or immutable attribute was supplied.")
		}
	}
	return nil
}

// boolean requires a boolean (`active`), answering fallback for undefined.
func boolean(value any, fallback bool) (bool, error) {
	if core.IsUndefined(value) {
		return fallback, nil
	}
	b, ok := value.(bool)
	if !ok {
		return false, core.NewIamError("invalidValue", "active must be a boolean.")
	}
	return b, nil
}

// activeTenant requires the tenant and its ancestors to be active.
func activeTenant(ctx context.Context, store core.IamStore, id string) error {
	active, err := core.TenantTreeActive(ctx, store, id)
	if err != nil {
		return err
	}
	if !active {
		return core.NewIamError("unauthorized", "Inactive tenant.", 401)
	}
	return nil
}
