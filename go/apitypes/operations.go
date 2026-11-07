package apitypes

import (
	"reflect"
	"sync"
)

// Operation describes one route: POST {basePath}/{Path} with a JSON body of type Input, answered with
// `{ "data": <Output> }`. The flags are those of spec/api/routes.json.
type Operation struct {
	// Path is the route below the basePath, such as "roles/create" or "authorize".
	Path string
	// OperationID is the OpenAPI operationId ("roles.create"); for the special routes it is the path.
	OperationID string
	// Group and Method name the API group and method; Group is empty for the special routes.
	Group  string
	Method string
	// Public routes ignore request credentials (routes.json credential "none").
	Public bool
	// Call is how the router calls the method: "credential, input", "input", "beginMfa" or "confirmMfa" (see
	// routes.json dispatch rules), or "request" for the special routes.
	Call string
	// TenantBound public routes take the organization of the request's host.
	TenantBound bool
	// SetsSessionCookie routes answer with a session the router sets as the session cookie (unless the request used a
	// bearer credential).
	SetsSessionCookie bool
	// ReadsDeviceCookie routes receive the trusted-device cookie as body.deviceToken when the body has none.
	ReadsDeviceCookie bool
	// Special marks authorize, authorizeMany and listAccessible, which call the operations directly.
	Special bool
	// Input and Output are the Go types of the request body and of the answer's data.
	Input  reflect.Type
	Output reflect.Type
}

// NewInput returns a pointer to a new zero Input value, ready for json.Unmarshal.
func (o *Operation) NewInput() any { return reflect.New(o.Input).Interface() }

// NewOutput returns a pointer to a new zero Output value, ready for json.Unmarshal.
func (o *Operation) NewOutput() any { return reflect.New(o.Output).Interface() }

// Op is an Operation with its Input and Output types attached, for typed clients:
//
//	func Call[In, Out any](ctx context.Context, op apitypes.Op[In, Out], input In) (Out, error)
type Op[In, Out any] struct{ *Operation }

// Operations lists every route: the RPC routes of routes.json in its order, then authorize, authorizeMany and
// listAccessible.
func Operations() []*Operation {
	out := make([]*Operation, len(operationTable))
	for index := range operationTable {
		out[index] = &operationTable[index]
	}
	return out
}

var operationIndex = sync.OnceValue(func() map[string]*Operation {
	index := make(map[string]*Operation, len(operationTable))
	for i := range operationTable {
		index[operationTable[i].Path] = &operationTable[i]
	}
	return index
})

// LookupOperation finds the route with that path below the basePath ("roles/create").
func LookupOperation(path string) (*Operation, bool) {
	op, ok := operationIndex()[path]
	return op, ok
}
