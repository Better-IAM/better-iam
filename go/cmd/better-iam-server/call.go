package main

// POST /__conformance/call and the `call` operations of store transactions: a dotted member path of the TypeScript
// instance (bootstrap, billing.closePeriod, auth.settleBookkeeping, api.roles.create) resolved on the Go instance by
// reflection, with the in-process arguments decoded into the Go parameter types.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

var memberPath = regexp.MustCompile(`^[A-Za-z][\w]*(\.[A-Za-z][\w]*){0,3}$`)

var reservedMembers = map[string]bool{"__proto__": true, "prototype": true, "constructor": true}

// topLevel are the instance members CONTROL.md lets a call name directly; the runtimes and auth, api are objects.
var topLevel = map[string]bool{
	"initialize": true, "bootstrap": true, "recoverRoot": true, "purgeDeleted": true, "pruneAudit": true,
	"archiveAudit": true, "sweepExpired": true, "selfCheck": true, "sendAccessDigest": true, "sendExpiryReminders": true,
	"reconcilePackages": true, "closeOverdueCertifications": true, "closeOverdueTeamReviews": true,
	"checkInvariants": true, "detectThreats": true, "flushAccessUsage": true, "dispatchAuditHooks": true,
	"rotateSecrets": true, "assertionKey": true, "assertionKeys": true, "authenticate": true, "require": true,
	"callPlugin": true, "authorize": true, "authorizeMany": true, "listAccessible": true, "planResources": true,
	"features": true, "inference": true, "a2a": true, "billing": true, "kms": true, "pki": true, "protection": true,
	"vault": true, "quotas": true, "privacy": true, "workflows": true, "compliance": true, "applications": true,
	"ssh": true, "verifiableCredentials": true, "ldap": true, "signals": true, "licenses": true, "guests": true,
	"clearances": true, "sessionTokens": true, "hosts": true, "events": true, "metrics": true, "auth": true, "api": true,
}

var initialisms = map[string]string{"Id": "ID", "Ids": "IDs", "Url": "URL", "Urls": "URLs", "Api": "API", "Json": "JSON", "Ip": "IP", "Uri": "URI", "Ips": "IPs"}
var initialismPattern = regexp.MustCompile(`(Ids|Id|Urls|Url|Api|Json|Ips|Ip|Uri)([A-Z0-9]|$)`)

// goName is the Go member name of a TypeScript member name.
func goName(name string) string {
	pascal := strings.ToUpper(name[:1]) + name[1:]
	return initialismPattern.ReplaceAllStringFunc(pascal, func(match string) string {
		for key, value := range initialisms {
			if strings.HasPrefix(match, key) && (len(match) == len(key) || match[len(key)] < 'a' || match[len(key)] > 'z') {
				return value + match[len(key):]
			}
		}
		return match
	})
}

func unknownMethod(path string) error {
	return core.NewIamError("NOT_FOUND", "Unknown method "+path, 404)
}

// member finds a field or method of value by its TypeScript name (exact Go name first, then case-insensitively).
func member(value reflect.Value, name string) (reflect.Value, bool) {
	if !value.IsValid() {
		return reflect.Value{}, false
	}
	for value.Kind() == reflect.Interface && !value.IsNil() {
		value = value.Elem()
	}
	candidates := []string{goName(name), strings.ToUpper(name[:1]) + name[1:]}
	for _, candidate := range candidates {
		if method := value.MethodByName(candidate); method.IsValid() {
			return method, true
		}
	}
	target := value
	if target.Kind() == reflect.Pointer {
		if target.IsNil() {
			return reflect.Value{}, false
		}
		target = target.Elem()
	}
	if target.Kind() == reflect.Struct {
		for _, candidate := range candidates {
			if field := target.FieldByName(candidate); field.IsValid() && field.CanInterface() {
				return field, true
			}
		}
	}
	// Case-insensitive fallbacks.
	lower := strings.ToLower(name)
	for index := 0; index < value.NumMethod(); index++ {
		if strings.ToLower(value.Type().Method(index).Name) == lower {
			return value.Method(index), true
		}
	}
	if target.Kind() == reflect.Struct {
		for index := 0; index < target.NumField(); index++ {
			field := target.Type().Field(index)
			if field.IsExported() && strings.ToLower(field.Name) == lower {
				return target.Field(index), true
			}
		}
	}
	return reflect.Value{}, false
}

// resolveMethod resolves a dotted member path to a callable on the instance.
func resolveMethod(iam *server.BetterIam, path any) (reflect.Value, error) {
	text, ok := path.(string)
	if !ok || !memberPath.MatchString(text) {
		return reflect.Value{}, core.NewIamError("INVALID_INPUT", "method must be a dotted member path", 400)
	}
	parts := strings.Split(text, ".")
	if !topLevel[parts[0]] {
		return reflect.Value{}, unknownMethod(text)
	}
	value := reflect.ValueOf(iam)
	for _, part := range parts {
		if reservedMembers[part] {
			return reflect.Value{}, unknownMethod(text)
		}
		next, found := member(value, part)
		if !found {
			return reflect.Value{}, unknownMethod(text)
		}
		value = next
	}
	for value.Kind() == reflect.Interface && !value.IsNil() {
		value = value.Elem()
	}
	if value.Kind() != reflect.Func || value.IsNil() {
		return reflect.Value{}, unknownMethod(text)
	}
	return value, nil
}

var (
	contextType    = reflect.TypeOf((*context.Context)(nil)).Elem()
	errorType      = reflect.TypeOf((*error)(nil)).Elem()
	objectType     = reflect.TypeOf((*core.Object)(nil))
	anyType        = reflect.TypeOf((*any)(nil)).Elem()
	credentialType = reflect.TypeOf(core.CredentialInput{})
	headerType     = reflect.TypeOf(http.Header{})
	identityInput  = reflect.TypeOf(auth.CreateIdentityInput{})
)

// isTransaction reports whether an argument stands for the transaction handle ({"$tx": true}).
func isTransaction(value any) bool {
	object, ok := value.(*core.Object)
	return ok && object != nil && object.Len() == 1 && object.Get("$tx") == true
}

// convertArgument converts a decoded model value into a Go parameter of type target.
func convertArgument(value any, target reflect.Type, tx core.IamStore) (reflect.Value, error) {
	if isTransaction(value) {
		if tx == nil || !reflect.TypeOf(tx).AssignableTo(target) {
			return reflect.Value{}, fmt.Errorf("a transaction handle is not a %s", target)
		}
		return reflect.ValueOf(tx), nil
	}
	if core.IsUndefined(value) {
		return reflect.Zero(target), nil
	}
	switch {
	case target == anyType:
		if value == nil {
			return reflect.Zero(target), nil
		}
		return reflect.ValueOf(value), nil
	case target == objectType:
		if value == nil {
			return reflect.Zero(target), nil
		}
		object, ok := value.(*core.Object)
		if !ok {
			return reflect.Value{}, fmt.Errorf("expected an object, got %T", value)
		}
		return reflect.ValueOf(object), nil
	case target == credentialType:
		credential := core.CredentialInput{}
		if object, ok := value.(*core.Object); ok && object != nil {
			if token, ok := object.Get("token").(string); ok {
				credential.Token = token
			}
			switch headers := object.Get("headers").(type) {
			case http.Header:
				credential.Headers = headers
			case *core.Object:
				credential.Headers = http.Header{}
				headers.Entries(func(key string, item any) bool {
					credential.Headers.Add(key, fmt.Sprint(item))
					return true
				})
			}
		}
		return reflect.ValueOf(credential), nil
	case target == headerType:
		if header, ok := value.(http.Header); ok {
			return reflect.ValueOf(header), nil
		}
	}
	// In[T] (API methods): the body as the model value.
	if target.Kind() == reflect.Struct && target.NumField() == 1 && target.Field(0).Name == "Body" && target.Field(0).Type == objectType {
		holder := reflect.New(target).Elem()
		object, _ := value.(*core.Object)
		if object == nil {
			object = core.NewObject()
		}
		holder.Field(0).Set(reflect.ValueOf(object))
		return holder, nil
	}
	if reflected := reflect.ValueOf(value); value != nil && reflected.Type().AssignableTo(target) {
		return reflected, nil
	}
	// Everything else through JSON (typed structs, numbers into ints, lists).
	data, err := json.Marshal(value)
	if err != nil {
		return reflect.Value{}, err
	}
	holder := reflect.New(target)
	if err := json.Unmarshal(data, holder.Interface()); err != nil {
		return reflect.Value{}, err
	}
	if target == identityInput {
		// A password member means a password was given (TypeScript `password` present, even empty).
		input := holder.Interface().(*auth.CreateIdentityInput)
		object, _ := value.(*core.Object)
		input.HasPassword = object != nil && object.Has("password")
		input.TenantID, input.Email, input.Name, input.Password = object.Get("tenantId"), object.Get("email"), object.Get("name"), object.Get("password")
	}
	return holder.Elem(), nil
}

// invoke calls fn with the decoded arguments (context injected, the transaction for {"$tx": true}) and returns its
// result as a Go value (undefined when it returns nothing).
func invoke(ctx context.Context, fn reflect.Value, args []any, tx core.IamStore) (any, error) {
	signature := fn.Type()
	values := []reflect.Value{}
	next := 0
	for index := 0; index < signature.NumIn(); index++ {
		parameter := signature.In(index)
		if signature.IsVariadic() && index == signature.NumIn()-1 {
			element := parameter.Elem()
			for ; next < len(args); next++ {
				converted, err := convertArgument(args[next], element, tx)
				if err != nil {
					return nil, core.NewIamError("INVALID_INPUT", err.Error(), 400)
				}
				values = append(values, converted)
			}
			break
		}
		if parameter == contextType {
			values = append(values, reflect.ValueOf(ctx))
			continue
		}
		var arg any = core.Undefined
		if next < len(args) {
			arg = args[next]
		}
		next++
		converted, err := convertArgument(arg, parameter, tx)
		if err != nil {
			return nil, core.NewIamError("INVALID_INPUT", err.Error(), 400)
		}
		values = append(values, converted)
	}
	results := fn.Call(values)
	var outputs []any
	for index, result := range results {
		if signature.Out(index) == errorType {
			if !result.IsNil() {
				return nil, result.Interface().(error)
			}
			continue
		}
		outputs = append(outputs, unwrapOut(result))
	}
	switch len(outputs) {
	case 0:
		return core.Undefined, nil
	case 1:
		return outputs[0], nil
	}
	return outputs, nil
}

// unwrapOut is an API method's Out[T].Value, or the value itself.
func unwrapOut(result reflect.Value) any {
	if result.Kind() == reflect.Struct && result.NumField() == 1 && result.Type().Field(0).Name == "Value" && strings.HasPrefix(result.Type().Name(), "Out[") {
		return result.Field(0).Interface()
	}
	return result.Interface()
}
