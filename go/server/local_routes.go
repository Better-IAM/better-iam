package server

// In-process access to the HTTP API's route table, for the better-iam CLI's localTransport
// (packages/cli/src/transport.ts): the same routes the HTTP handler serves, with the same credential rules, without
// an HTTP request around them.

import (
	"context"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// RouteAccess is one route of the HTTP API and whether it needs a credential ("public" or "token").
type RouteAccess struct {
	Route  string `json:"route"`
	Access string `json:"access"`
}

// IsPublicRoute reports whether a route needs no credential over HTTP (sign-in ceremonies, invitation acceptance,
// discovery).
func IsPublicRoute(path string) bool {
	group, method, _ := strings.Cut(path, "/")
	if group == "auth" {
		method, _, _ = strings.Cut(method, "/")
		return PublicAuthMethods.Has(method)
	}
	return PublicAPIMethods.Has(path)
}

// DispatchRoute calls one route of the HTTP API in process (`roles/create`, `auth/getSession`, `authorize`,
// `plugins/{id}/{path}`) with the credential, exactly as the HTTP router does once it has read the request body:
// only the routes it serves, public routes with the body alone, the others with the credential. Unknown routes fail
// with NOT_FOUND "Endpoint not found". There is no body-size limit here.
func (iam *BetterIam) DispatchRoute(ctx context.Context, credential core.CredentialInput, path string, body *core.Object) (any, error) {
	if body == nil {
		body = core.NewObject()
	}
	return iam.HTTP.dispatch(ctx, path, body, credential)
}

// Routes lists every route the HTTP API serves (the top-level authorization routes, the auth methods and every API
// group method), unsorted, with whether it needs a credential. Plugin endpoints are not listed.
func Routes() []RouteAccess {
	routes := []RouteAccess{
		{Route: "authorize", Access: "token"},
		{Route: "authorizeMany", Access: "token"},
		{Route: "listAccessible", Access: "token"},
	}
	for _, method := range PublicAuthMethods.items {
		routes = append(routes, RouteAccess{Route: "auth/" + method, Access: "public"})
	}
	for _, method := range AuthenticatedAuthMethods.items {
		routes = append(routes, RouteAccess{Route: "auth/" + method, Access: "token"})
	}
	for path := range rpcRoutes {
		group, _, _ := strings.Cut(path, "/")
		if group == "auth" || !RouteGroups.Has(group) {
			continue
		}
		access := "token"
		if PublicAPIMethods.Has(path) {
			access = "public"
		}
		routes = append(routes, RouteAccess{Route: path, Access: access})
	}
	return routes
}
