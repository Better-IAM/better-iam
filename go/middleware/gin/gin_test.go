package gin_test

// The scenario of tests/middleware.test.ts against the gin integration.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	gingonic "github.com/gin-gonic/gin"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/internal/middlewaretest"
	"github.com/Better-IAM/better-iam/go/internal/orgfixture"
	"github.com/Better-IAM/better-iam/go/middleware"
	"github.com/Better-IAM/better-iam/go/middleware/gin"
	"github.com/Better-IAM/better-iam/go/server"
)

func init() { gingonic.SetMode(gingonic.TestMode) }

func ok(c *gingonic.Context) { c.Data(200, "application/json", []byte(`{"ok":true}`)) }

func route(fn func(ctx context.Context, iam *middleware.Helpers, c *gingonic.Context) (any, error)) gingonic.HandlerFunc {
	return func(c *gingonic.Context) {
		value, err := fn(c.Request.Context(), gin.FromContext(c), c)
		if err != nil {
			_ = c.Error(err)
			return
		}
		c.Data(200, "application/json", []byte(core.MustStringify(value)))
	}
}

func TestGinMountsTheAPIGuardsRoutesAndHandlesRefusals(t *testing.T) {
	f := orgfixture.New(t, nil)
	iamGin := gin.New(f.IAM, middleware.Options{LoginPath: "/login", StepUpPath: "/verify"})
	router := gingonic.New()
	router.Use(iamGin.ErrorHandler(), iamGin.Middleware())
	router.GET("/me", iamGin.RequireSession(nil), route(func(ctx context.Context, iam *middleware.Helpers, _ *gingonic.Context) (any, error) {
		return middlewaretest.Me(ctx, iam)
	}))
	router.GET("/secure", iamGin.RequireSession(&middleware.StepUpRequirement{MFA: middleware.MfaRequired}), ok)
	router.POST("/danger", iamGin.RequireSession(nil), ok)
	router.GET("/admin", iamGin.Authorize("iam:identities:update", middleware.AuthorizeSpec[*gingonic.Context]{}), ok)
	router.POST("/login", route(func(ctx context.Context, iam *middleware.Helpers, c *gingonic.Context) (any, error) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return nil, err
		}
		return middlewaretest.Login(ctx, iam, f.TenantID, body)
	}))
	router.POST("/logout", route(func(ctx context.Context, iam *middleware.Helpers, _ *gingonic.Context) (any, error) {
		return middlewaretest.Logout(ctx, iam)
	}))
	router.GET("/thrower", route(func(ctx context.Context, iam *middleware.Helpers, _ *gingonic.Context) (any, error) {
		return middlewaretest.Thrower(ctx, iam)
	}))
	httpServer := httptest.NewServer(router)
	t.Cleanup(httpServer.Close)
	middlewaretest.Scenario(t, f, middlewaretest.Client(t, httpServer.URL))
}

func TestGinAuthorizeCallbacksReadRouteParametersAndReachNodeMounts(t *testing.T) {
	f := orgfixture.New(t, nil)
	f.IAM.UseProtocol(server.ProtocolService{
		BasePath: "/node-proto",
		NodeHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, core.MustStringify(core.NewObject("served", r.URL.RequestURI())))
		}),
	})
	iamGin := gin.New(f.IAM, middleware.Options{Serve: []string{"/api/iam", "/node-proto"}})
	router := gingonic.New()
	router.Use(iamGin.Middleware())
	router.GET("/tenants/:tenantId/admin", iamGin.Authorize("iam:identities:update", middleware.AuthorizeSpec[*gingonic.Context]{
		TenantID: gin.TenantFromParam("tenantId"),
		Resource: gin.ResourceFromParam("iam", "tenantId"),
	}), ok)
	httpServer := httptest.NewServer(router)
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
	if served := middlewaretest.Body(t, call("GET", "/node-proto/metadata?x=1", nil, ""))["served"]; served != "/node-proto/metadata?x=1" {
		t.Fatalf("served %v", served)
	}
}
