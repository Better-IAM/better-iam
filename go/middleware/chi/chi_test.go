package chi_test

// The scenario of tests/middleware.test.ts against the chi integration.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	chirouter "github.com/go-chi/chi/v5"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/internal/middlewaretest"
	"github.com/Better-IAM/better-iam/go/internal/orgfixture"
	"github.com/Better-IAM/better-iam/go/middleware"
	"github.com/Better-IAM/better-iam/go/middleware/chi"
)

func ok(w http.ResponseWriter, _ *http.Request) {
	middlewaretest.WriteJSON(w, core.NewObject("ok", true))
}

func TestChiMountsTheAPIGuardsRoutesAndHandlesRefusals(t *testing.T) {
	f := orgfixture.New(t, nil)
	iamChi := chi.New(f.IAM, middleware.Options{LoginPath: "/login", StepUpPath: "/verify"})
	router := chirouter.NewRouter()
	router.Use(iamChi.Handler)
	route := func(fn func(ctx context.Context, iam *middleware.Helpers, r *http.Request) (any, error)) http.HandlerFunc {
		return iamChi.Wrap(func(w http.ResponseWriter, r *http.Request) error {
			value, err := fn(r.Context(), middleware.FromRequest(r), r)
			if err != nil {
				return err
			}
			middlewaretest.WriteJSON(w, value)
			return nil
		}).ServeHTTP
	}
	router.With(iamChi.RequireSession(nil)).Get("/me", route(func(ctx context.Context, iam *middleware.Helpers, _ *http.Request) (any, error) {
		return middlewaretest.Me(ctx, iam)
	}))
	router.With(iamChi.RequireSession(&middleware.StepUpRequirement{MFA: middleware.MfaRequired})).Get("/secure", ok)
	router.With(iamChi.RequireSession(nil)).Post("/danger", ok)
	router.With(iamChi.Authorize("iam:identities:update", middleware.AuthorizeSpec[*http.Request]{})).Get("/admin", ok)
	router.Post("/login", route(func(ctx context.Context, iam *middleware.Helpers, r *http.Request) (any, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		return middlewaretest.Login(ctx, iam, f.TenantID, body)
	}))
	router.Post("/logout", route(func(ctx context.Context, iam *middleware.Helpers, _ *http.Request) (any, error) {
		return middlewaretest.Logout(ctx, iam)
	}))
	router.Get("/thrower", route(func(ctx context.Context, iam *middleware.Helpers, _ *http.Request) (any, error) {
		return middlewaretest.Thrower(ctx, iam)
	}))
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	middlewaretest.Scenario(t, f, middlewaretest.Client(t, server.URL))
}

func TestChiAuthorizeCallbacksReadRouteParameters(t *testing.T) {
	f := orgfixture.New(t, nil)
	iamChi := chi.New(f.IAM, middleware.Options{})
	router := chirouter.NewRouter()
	router.Use(iamChi.Handler)
	router.With(iamChi.Authorize("iam:identities:update", middleware.AuthorizeSpec[*http.Request]{
		TenantID: chi.TenantFromParam("tenantId"),
		Resource: chi.ResourceFromParam("iam", "tenantId"),
	})).Get("/tenants/{tenantId}/admin", ok)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	call := middlewaretest.Client(t, server.URL)
	signIn := call("POST", "/api/iam/auth/signIn", middlewaretest.JSONHeaders(nil), core.MustStringify(core.NewObject(
		"tenantId", f.TenantID, "email", "owner@acme.test", "password", orgfixture.OwnerPassword,
	)))
	cookie := map[string]string{"cookie": middlewaretest.CookieOf(signIn)}
	if status := call("GET", "/tenants/"+f.TenantID+"/admin", cookie, "").StatusCode; status != 200 {
		t.Fatalf("own tenant: %d", status)
	}
	if status := call("GET", "/tenants/"+f.RootID+"/admin", cookie, "").StatusCode; status != 403 {
		t.Fatalf("other tenant: %d", status)
	}
}
