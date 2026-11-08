// Package chi is the chi integration of the Better IAM middleware: chi middlewares are net/http middlewares, so it is
// the net/http integration (middleware.Middleware) with route-parameter helpers for authorize guards.
//
//	iamChi := chi.New(iam, middleware.Options{LoginPath: "/login"})
//	router := chirouter.NewRouter()
//	router.Use(iamChi.Handler)
//	router.With(iamChi.Authorize("projects:read", middleware.AuthorizeSpec[*http.Request]{
//		Resource: chi.ResourceFromParam("project", "id"),
//	})).Get("/projects/{id}", handler)
package chi

import (
	"context"
	"net/http"

	chirouter "github.com/go-chi/chi/v5"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/middleware"
	"github.com/Better-IAM/better-iam/go/server"
)

// IamChi is the chi integration: `router.Use(iamChi.Handler)` serves the IAM API under the Serve prefixes and gives
// every other request its helpers (middleware.FromRequest); RequireSession and Authorize are `router.With` guards.
type IamChi struct {
	*middleware.Middleware
}

// New is the chi integration over a composed server.
func New(iam *server.BetterIam, options middleware.Options) *IamChi {
	return &IamChi{Middleware: middleware.New(iam, options)}
}

// NewWith is the chi integration over any IAM implementation.
func NewWith(source middleware.IAM, options middleware.Options) *IamChi {
	return &IamChi{Middleware: middleware.NewWith(source, options)}
}

// NewLazy is the chi integration over an IAM instance resolved on use.
func NewLazy(resolve func(ctx context.Context) (middleware.IAM, error), options middleware.Options) *IamChi {
	return &IamChi{Middleware: middleware.NewLazy(resolve, options)}
}

// TenantFromParam is an authorize TenantID callback reading the tenant from a route parameter.
func TenantFromParam(name string) func(r *http.Request, session *core.Object) (string, error) {
	return func(r *http.Request, _ *core.Object) (string, error) { return chirouter.URLParam(r, name), nil }
}

// ResourceFromParam is an authorize Resource callback naming a resource of resourceType by a route parameter.
func ResourceFromParam(resourceType, name string) func(r *http.Request, session *core.Object) (middleware.ResourceRef, error) {
	return func(r *http.Request, _ *core.Object) (middleware.ResourceRef, error) {
		return middleware.ResourceRef{Type: resourceType, ID: chirouter.URLParam(r, name)}, nil
	}
}
