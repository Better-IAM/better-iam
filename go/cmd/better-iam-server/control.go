package main

// The script and store control endpoints (CONTROL.md "Script" and "Store").

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// scriptControl replaces (or appends to) the script, or reports the calls made so far.
func (a *app) scriptControl(body any) (any, error) {
	a.state.mu.Lock()
	defer a.state.mu.Unlock()
	if core.IsUndefined(body) {
		return core.NewObject("calls", append([]any{}, a.state.calls...)), nil
	}
	list, ok := bodyMember(body, "answers").([]any)
	if !ok {
		return nil, core.NewIamError("INVALID_INPUT", "answers must be an array", 400)
	}
	answers := make([]*answer, 0, len(list))
	for _, item := range list {
		object, _ := item.(*core.Object)
		if object == nil {
			object = core.NewObject()
		}
		entry := &answer{id: object.Get("id"), callback: jsonString(object.Get("callback")), args: object.Get("args"), async: object.Get("async") == true}
		if object.Has("error") {
			entry.hasError, entry.failure = true, object.Get("error")
		} else {
			entry.result = object.Get("result")
		}
		answers = append(answers, entry)
	}
	if bodyMember(body, "append") == true {
		var unused []*answer
		for _, item := range a.state.script {
			if !item.used {
				unused = append(unused, item)
			}
		}
		a.state.script = append(unused, answers...)
	} else {
		a.state.script = answers
		a.state.calls = nil
	}
	return core.NewObject("answers", float64(len(a.state.script))), nil
}

var isoInstant = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$`)

// timeless blanks out epoch-millisecond numbers, ISO-8601 instants and password hashes.
func timeless(value any) any {
	switch typed := value.(type) {
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = timeless(item)
		}
		return out
	case *core.Object:
		if typed == nil {
			return nil
		}
		out := core.NewObject()
		typed.Entries(func(key string, item any) bool {
			out.Set(key, timeless(item))
			return true
		})
		return out
	case float64:
		if typed >= 1e12 && typed < 1e13 {
			return 0.0
		}
	case string:
		if isoInstant.MatchString(typed) || strings.HasPrefix(typed, "$argon2") {
			return ""
		}
	}
	return value
}

// scriptError is a scripted callback's thrown error: an IamError ({iam: true}) or a named plain error.
type scriptError struct {
	name    string
	message string
}

func (e *scriptError) Error() string { return e.message }
func (e *scriptError) Name() string  { return e.name }

func rethrow(failure any) error {
	object, _ := failure.(*core.Object)
	if object != nil && object.Get("iam") == true {
		status := 400
		if value, ok := object.Get("status").(float64); ok {
			status = int(value)
		}
		return core.NewIamError(jsonString(object.Get("code")), jsonString(object.Get("message")), status)
	}
	message := "Scripted callback failed"
	name := "Error"
	if object != nil {
		if text, ok := object.Get("message").(string); ok {
			message = text
		}
		if text, ok := object.Get("name").(string); ok {
			name = text
		}
	}
	return &scriptError{name: name, message: message}
}

// scripted is the callback standing in for the application callback at an option path.
func (a *app) scripted(name string) server.ScriptedCallback {
	return func(ctx context.Context, args ...any) (any, error) {
		encoded := encodeValue(append([]any{}, args...))
		a.state.mu.Lock()
		var chosen *answer
		for _, pass := range []func(item *answer) bool{
			func(item *answer) bool { return sameValue(item.args, encoded) },
			func(item *answer) bool { return sameValue(timeless(item.args), timeless(encoded)) },
			func(item *answer) bool { return true },
		} {
			for _, item := range a.state.script {
				if !item.used && item.callback == name && pass(item) {
					chosen = item
					break
				}
			}
			if chosen != nil {
				break
			}
		}
		var used any
		if chosen != nil {
			used = chosen.id
			chosen.used = true
		}
		a.state.calls = append(a.state.calls, core.NewObject("callback", name, "args", encoded, "answer", used))
		a.state.mu.Unlock()
		if chosen == nil {
			return nil, &scriptError{name: "ConformanceScriptError", message: "No scripted answer for " + name}
		}
		if chosen.hasError {
			return nil, rethrow(chosen.failure)
		}
		return decodeValue(chosen.result), nil
	}
}

var storeMethods = map[string]bool{"get": true, "find": true, "findOrdered": true, "insert": true, "put": true, "delete": true, "collections": true, "describe": true}

// errRollback rolls a control transaction back.
var errRollback = errors.New("rollback")

func malformed(message string) error { return core.NewIamError("INVALID_INPUT", message, 400) }

// withResults replaces {"$result": [n, ...path]} with (a member of) what operation n returned.
func withResults(value any, earlier []any) (any, error) {
	switch typed := value.(type) {
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			replaced, err := withResults(item, earlier)
			if err != nil {
				return nil, err
			}
			out[index] = replaced
		}
		return out, nil
	case *core.Object:
		if typed == nil {
			return nil, nil
		}
		if reference, ok := typed.Get("$result").([]any); ok && typed.Len() == 1 {
			index, ok := reference[0].(float64)
			if len(reference) == 0 || !ok || index < 0 || int(index) >= len(earlier) || index != float64(int(index)) {
				return nil, malformed(fmt.Sprintf("$result names operation %v, which has not run", reference[0]))
			}
			node := earlier[int(index)]
			for _, part := range reference[1:] {
				node = memberOf(node, part)
			}
			return node, nil
		}
		out := core.NewObject()
		var failure error
		typed.Entries(func(key string, item any) bool {
			replaced, err := withResults(item, earlier)
			if err != nil {
				failure = err
				return false
			}
			out.Set(key, replaced)
			return true
		})
		return out, failure
	}
	return value, nil
}

// memberOf is node?.[part] over model values (and Go results through their model form).
func memberOf(node any, part any) any {
	if _, isModel := node.(*core.Object); !isModel {
		if _, isList := node.([]any); !isList && node != nil && !core.IsUndefined(node) {
			if model, err := server.ToModel(node); err == nil {
				node = model
			}
		}
	}
	switch typed := node.(type) {
	case *core.Object:
		if typed == nil {
			return core.Undefined
		}
		return typed.Get(fmt.Sprint(part))
	case []any:
		if index, ok := part.(float64); ok && int(index) >= 0 && int(index) < len(typed) {
			return typed[int(index)]
		}
	}
	return core.Undefined
}

func optionalInt(value any) *int {
	if number, ok := value.(float64); ok {
		converted := int(number)
		return &converted
	}
	return nil
}

func optionalFloat(value any) *float64 {
	if number, ok := value.(float64); ok {
		return &number
	}
	return nil
}

// storeOp runs one IamStore method (or, inside a transaction, a `call` of an instance member).
func (a *app) storeOp(ctx context.Context, current *instance, target core.IamStore, method string, rawArgs any, op *core.Object, earlier []any) (any, error) {
	decoded, err := withResults(decodeValue(rawArgs), earlier)
	if err != nil {
		return nil, err
	}
	args, _ := decoded.([]any)
	arg := func(index int) any {
		if index < len(args) {
			return args[index]
		}
		return core.Undefined
	}
	text := func(index int) string { return fmt.Sprint(arg(index)) }
	object := func(index int) *core.Object {
		value, _ := arg(index).(*core.Object)
		return value
	}
	if method == "call" && op != nil {
		fn, err := resolveMethod(current.iam, op.Get("path"))
		if err != nil {
			return nil, err
		}
		return invoke(ctx, fn, args, target)
	}
	if !storeMethods[method] {
		return nil, malformed("Unknown store method " + method)
	}
	switch method {
	case "get":
		record, err := target.Get(ctx, text(0), text(1))
		if err != nil || record == nil {
			return core.Undefined, err
		}
		return record, nil
	case "find":
		var options *core.FindOptions
		if value := object(2); value != nil {
			options = &core.FindOptions{Limit: optionalInt(value.Get("limit")), Offset: optionalInt(value.Get("offset"))}
			if after, ok := value.Get("after").(string); ok {
				options.After = &after
			}
		}
		return target.Find(ctx, text(0), object(1), options)
	case "findOrdered":
		order := core.OrderOptions{}
		if value := object(2); value != nil {
			order.Field = jsonString(value.Get("field"))
			order.Direction = jsonString(value.Get("direction"))
			order.From, order.To = optionalFloat(value.Get("from")), optionalFloat(value.Get("to"))
			order.Offset, order.Limit = optionalInt(value.Get("offset")), optionalInt(value.Get("limit"))
		}
		return core.FindOrdered(ctx, target, text(0), object(1), order, nil)
	case "insert":
		return target.Insert(ctx, text(0), object(1))
	case "put":
		return target.Put(ctx, text(0), object(1))
	case "delete":
		return core.Undefined, target.Delete(ctx, text(0), text(1))
	case "collections":
		lister, ok := target.(core.CollectionLister)
		if !ok {
			return nil, malformed("Unknown store method collections")
		}
		return lister.Collections(ctx)
	case "describe":
		describer, ok := target.(core.Describer)
		if !ok {
			return nil, malformed("Unknown store method describe")
		}
		return describer.Describe(ctx)
	}
	return nil, malformed("Unknown store method " + method)
}

func (a *app) storeControl(ctx context.Context, current *instance, body any) (any, error) {
	method := jsonString(bodyMember(body, "method"))
	if method != "transaction" {
		result, err := a.storeOp(ctx, current, current.store, method, bodyMember(body, "args"), nil, nil)
		if err != nil {
			return core.NewObject("error", errorShape(err)), nil
		}
		return core.NewObject("data", encodeValue(result)), nil
	}
	results := []any{}
	ops, _ := bodyMember(body, "ops").([]any)
	err := current.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		earlier := []any{}
		for _, item := range ops {
			op, _ := item.(*core.Object)
			if op == nil {
				op = core.NewObject()
			}
			value, err := a.storeOp(ctx, current, tx, jsonString(op.Get("method")), op.Get("args"), op, earlier)
			if err != nil {
				earlier = append(earlier, core.Undefined)
				results = append(results, core.NewObject("error", errorShape(err)))
				if op.Get("propagate") == true {
					return errRollback
				}
				continue
			}
			earlier = append(earlier, value)
			results = append(results, core.NewObject("data", encodeValue(value)))
		}
		if bodyMember(body, "rollback") == true {
			return errRollback
		}
		return nil
	})
	if errors.Is(err, errRollback) {
		return core.NewObject("data", core.NewObject("results", results, "rolledBack", true)), nil
	}
	if err != nil {
		return core.NewObject("error", errorShape(err), "data", core.NewObject("results", results, "rolledBack", true)), nil
	}
	return core.NewObject("data", core.NewObject("results", results, "rolledBack", false)), nil
}
