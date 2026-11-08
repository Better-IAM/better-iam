package main

// Instance members whose Go signature or result differs from the TypeScript instance surface. The Go methods keep
// their Go shapes (their Go callers rely on them); the conformance bridge adapts the arguments and results of a call
// at these paths so the call answers exactly as the TypeScript member does.

import (
	"context"
	"reflect"

	"github.com/Better-IAM/better-iam/go/core"
)

// callShape adapts one member path: spread rewrites the TypeScript arguments into the Go parameters, result rewrites
// the Go result into the TypeScript one.
type callShape struct {
	spread func(args []any) []any
	result func(value any) any
}

// dispatchedShape: TypeScript `{ dispatched: n }`, Go the bare count.
func dispatchedShape(value any) any {
	if core.IsUndefined(value) {
		return value
	}
	return core.NewObject("dispatched", value)
}

// undefinedWhenNil: TypeScript `undefined` where Go returns a nil pointer (null on the wire).
func undefinedWhenNil(value any) any {
	if value == nil {
		return core.Undefined
	}
	if reflected := reflect.ValueOf(value); (reflected.Kind() == reflect.Pointer || reflected.Kind() == reflect.Map ||
		reflected.Kind() == reflect.Interface) && reflected.IsNil() {
		return core.Undefined
	}
	return value
}

// spreadTrustChange: TypeScript `(credential, { tenantId, providerId })`, Go `(credential, tenantID, providerID)`.
func spreadTrustChange(args []any) []any {
	if len(args) < 2 {
		return args
	}
	input, ok := args[1].(*core.Object)
	if !ok || input == nil {
		return args
	}
	spread := []any{args[0], input.Get("tenantId"), input.Get("providerId")}
	return append(spread, args[2:]...)
}

var callShapes = map[string]callShape{
	"dispatchAuditHooks":             {result: dispatchedShape},
	"events.dispatch":                {result: dispatchedShape},
	"hosts.resolve":                  {result: undefinedWhenNil},
	"ldap.tenantForBase":             {result: undefinedWhenNil},
	"ldap.resolveBindName":           {result: undefinedWhenNil},
	"protocolHost.assertTrustChange": {spread: spreadTrustChange},
}

// invokeMember calls fn, the member resolveMethod resolved for path, with the TypeScript arguments, adapting the
// members in callShapes.
func invokeMember(ctx context.Context, fn reflect.Value, path any, args []any, tx core.IamStore) (any, error) {
	text, _ := path.(string)
	shape, adapted := callShapes[text]
	if adapted && shape.spread != nil {
		args = shape.spread(args)
	}
	result, err := invoke(ctx, fn, args, tx)
	if err != nil {
		return nil, err
	}
	if adapted && shape.result != nil {
		result = shape.result(result)
	}
	return result, nil
}
