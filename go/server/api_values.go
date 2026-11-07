package server

// The values an API method receives and answers (Go-only support for the generated API surface; see go/PORTING.md).
//
// A TypeScript API method takes its body as `unknown`-ish input and validates it itself (text(), object(), ...), so
// the Go methods take the body as the JavaScript model value the router parsed (In.Body, a *core.Object) and validate
// it with the same helpers, in the same order, with the same messages. The generated request type T documents the
// shape and gives in-process callers a typed way in (InputOf) and implementers a typed way to read it (Typed).
//
// A TypeScript method answers whatever object it built (records as stored, members in the order the code builds
// them). Out carries that answer as a model value (*core.Object, []any, ...) so the JSON is byte-identical to the
// TypeScript server's, or as the generated output type T when that is more natural; Typed converts either into T for
// in-process callers.

import (
	"encoding/json"
	"reflect"

	"github.com/Better-IAM/better-iam/go/core"
)

// In is the body of an API call: the request's JSON object as a model value. T is the generated request type
// (go/apitypes) of the route.
type In[T any] struct {
	Body *core.Object
}

// Input wraps a model value (a request body) as an In.
func Input[T any](body *core.Object) In[T] {
	if body == nil {
		body = core.NewObject()
	}
	return In[T]{Body: body}
}

// InputOf converts a typed request into the model value the method validates (JSON round trip).
func InputOf[T any](value T) (In[T], error) {
	model, err := ToModel(value)
	if err != nil {
		return In[T]{}, err
	}
	object, ok := model.(*core.Object)
	if !ok {
		return In[T]{}, invalidInput("Input must be an object")
	}
	return In[T]{Body: object}, nil
}

// Get reads a member of the body (core.Undefined when absent).
func (in In[T]) Get(key string) any {
	if in.Body == nil {
		return core.Undefined
	}
	return in.Body.Get(key)
}

// Typed decodes the body into the generated request type. Use it only after validating the body the TypeScript
// way: Go's JSON decoding errors are not the TypeScript validation errors.
func (in In[T]) Typed() (T, error) {
	var typed T
	if in.Body == nil {
		return typed, nil
	}
	data, err := json.Marshal(in.Body)
	if err != nil {
		return typed, err
	}
	err = json.Unmarshal(data, &typed)
	return typed, err
}

// Out is the answer of an API call: Value is a model value (preferred: byte-identical JSON) or a T.
type Out[T any] struct {
	Value any
}

// Answer wraps an answer (a model value or a T).
func Answer[T any](value any) Out[T] { return Out[T]{Value: value} }

// Typed converts the answer into the generated output type (JSON round trip when it is a model value).
func (o Out[T]) Typed() (T, error) {
	var typed T
	if value, ok := o.Value.(T); ok {
		return value, nil
	}
	if o.Value == nil {
		return typed, nil
	}
	data, err := json.Marshal(o.Value)
	if err != nil {
		return typed, err
	}
	err = json.Unmarshal(data, &typed)
	return typed, err
}

// ToModel converts a Go value into the JavaScript model value its JSON describes: model values pass through, other
// values (typed structs, maps, slices) go through encoding/json and core.ParseJSON.
func ToModel(value any) (any, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case *core.Object, string, float64, bool, []any:
		return typed, nil
	case core.Decision:
		return core.NewObject("allowed", typed.Allowed, "reason", typed.Reason, "matched", stringsOf(nonNilStrings(typed.Matched))), nil
	}
	if core.IsUndefined(value) {
		return value, nil
	}
	if reflected := reflect.ValueOf(value); reflected.Kind() == reflect.Pointer && reflected.IsNil() {
		return nil, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return core.ParseJSON(data)
}

func nonNilStrings(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

// mustModel parses a JSON literal into a model value (the generated constants of modules that have no Go literal
// form).
func mustModel(text string) any {
	value, err := core.ParseJSON([]byte(text))
	if err != nil {
		panic(err)
	}
	return value
}

// mustObject parses a JSON object literal into a *core.Object.
func mustObject(text string) *core.Object {
	return mustModel(text).(*core.Object)
}
