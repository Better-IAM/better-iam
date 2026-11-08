package echo_test

// The scenario of tests/middleware.test.ts against the echo integration.

import (
	"context"
	"io"
	"net/http/httptest"
	"testing"

	labstack "github.com/labstack/echo/v4"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/internal/middlewaretest"
	"github.com/Better-IAM/better-iam/go/internal/orgfixture"
	"github.com/Better-IAM/better-iam/go/middleware"
	"github.com/Better-IAM/better-iam/go/middleware/echo"
)

func ok(c labstack.Context) error { return c.JSONBlob(200, []byte(`{"ok":true}`)) }

func route(fn func(ctx context.Context, iam *middleware.Helpers, c labstack.Context) (any, error)) labstack.HandlerFunc {
	return func(c labstack.Context) error {
		value, err := fn(c.Request().Context(), echo.FromContext(c), c)
		if err != nil {
			return err
		}
		return c.JSONBlob(200, []byte(core.MustStringify(value)))
	}
}

func TestEchoMountsTheAPIGuardsRoutesAndHandlesRefusals(t *testing.T) {
	f := orgfixture.New(t, nil)
	iamEcho := echo.New(f.IAM, middleware.Options{LoginPath: "/login", StepUpPath: "/verify"})
	e := labstack.New()
	e.HideBanner = true
	e.HTTPErrorHandler = iamEcho.ErrorHandler(e.DefaultHTTPErrorHandler)
	e.Use(iamEcho.Middleware())
	e.GET("/me", route(func(ctx context.Context, iam *middleware.Helpers, _ labstack.Context) (any, error) {
		return middlewaretest.Me(ctx, iam)
	}), iamEcho.RequireSession(nil))
	e.GET("/secure", ok, iamEcho.RequireSession(&middleware.StepUpRequirement{MFA: middleware.MfaRequired}))
	e.POST("/danger", ok, iamEcho.RequireSession(nil))
	e.GET("/admin", ok, iamEcho.Authorize("iam:identities:update", middleware.AuthorizeSpec[labstack.Context]{}))
	e.POST("/login", route(func(ctx context.Context, iam *middleware.Helpers, c labstack.Context) (any, error) {
		body, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return nil, err
		}
		return middlewaretest.Login(ctx, iam, f.TenantID, body)
	}))
	e.POST("/logout", route(func(ctx context.Context, iam *middleware.Helpers, _ labstack.Context) (any, error) {
		return middlewaretest.Logout(ctx, iam)
	}))
	e.GET("/thrower", route(func(ctx context.Context, iam *middleware.Helpers, _ labstack.Context) (any, error) {
		return middlewaretest.Thrower(ctx, iam)
	}))
	httpServer := httptest.NewServer(e)
	t.Cleanup(httpServer.Close)
	middlewaretest.Scenario(t, f, middlewaretest.Client(t, httpServer.URL))
}

func TestEchoAuthorizeCallbacksReadRouteParameters(t *testing.T) {
	f := orgfixture.New(t, nil)
	iamEcho := echo.New(f.IAM, middleware.Options{})
	e := labstack.New()
	e.HTTPErrorHandler = iamEcho.ErrorHandler(nil)
	e.Use(iamEcho.Middleware())
	e.GET("/tenants/:tenantId/admin", ok, iamEcho.Authorize("iam:identities:update", middleware.AuthorizeSpec[labstack.Context]{
		TenantID: echo.TenantFromParam("tenantId"),
		Resource: echo.ResourceFromParam("iam", "tenantId"),
	}))
	httpServer := httptest.NewServer(e)
	t.Cleanup(httpServer.Close)
	call := middlewaretest.Client(t, httpServer.URL)
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
