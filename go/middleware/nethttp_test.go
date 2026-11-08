package middleware_test

// Ports of tests/middleware.test.ts (the Express, Hono and Fastify adapters run the same scenario; here the net/http
// integration, through the server's Node-style transport and through its fetch-style handler) and
// tests/middleware-plan.test.ts.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/internal/middlewaretest"
	"github.com/Better-IAM/better-iam/go/internal/orgfixture"
	"github.com/Better-IAM/better-iam/go/middleware"
	"github.com/Better-IAM/better-iam/go/server"
)

// routes mounts the scenario's routes on a ServeMux with the integration's guards.
func routes(f *orgfixture.Fixture, iamHTTP *middleware.Middleware) *http.ServeMux {
	mux := http.NewServeMux()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		middlewaretest.WriteJSON(w, core.NewObject("ok", true))
	})
	route := func(fn func(ctx context.Context, iam *middleware.Helpers, r *http.Request) (any, error)) http.Handler {
		return iamHTTP.Wrap(func(w http.ResponseWriter, r *http.Request) error {
			value, err := fn(r.Context(), middleware.FromRequest(r), r)
			if err != nil {
				return err
			}
			middlewaretest.WriteJSON(w, value)
			return nil
		})
	}
	mux.Handle("GET /me", iamHTTP.RequireSession(nil)(route(func(ctx context.Context, iam *middleware.Helpers, _ *http.Request) (any, error) {
		return middlewaretest.Me(ctx, iam)
	})))
	mux.Handle("GET /secure", iamHTTP.RequireSession(&middleware.StepUpRequirement{MFA: middleware.MfaRequired})(ok))
	mux.Handle("POST /danger", iamHTTP.RequireSession(nil)(ok))
	mux.Handle("GET /admin", iamHTTP.Authorize("iam:identities:update", middleware.AuthorizeSpec[*http.Request]{})(ok))
	mux.Handle("POST /login", route(func(ctx context.Context, iam *middleware.Helpers, r *http.Request) (any, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		return middlewaretest.Login(ctx, iam, f.TenantID, body)
	}))
	mux.Handle("POST /logout", route(func(ctx context.Context, iam *middleware.Helpers, _ *http.Request) (any, error) {
		return middlewaretest.Logout(ctx, iam)
	}))
	mux.Handle("GET /thrower", route(func(ctx context.Context, iam *middleware.Helpers, _ *http.Request) (any, error) {
		return middlewaretest.Thrower(ctx, iam)
	}))
	return mux
}

func listen(t *testing.T, handler http.Handler) middlewaretest.Fetch {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return middlewaretest.Client(t, server.URL)
}

func TestNetHTTPMountsTheAPIGuardsRoutesAndHandlesRefusals(t *testing.T) {
	f := orgfixture.New(t, nil)
	iamHTTP := middleware.New(f.IAM, middleware.Options{LoginPath: "/login", StepUpPath: "/verify"})
	middlewaretest.Scenario(t, f, listen(t, iamHTTP.Handler(routes(f, iamHTTP))))
}

// fetchOnly hides the server's Node-style transport, so the integration answers the API with the fetch-style
// handler (the Hono adapter's path, and the fallback of the Fastify adapter).
type fetchOnly struct {
	middleware.IAM
	middleware.EndpointProvider
	middleware.HostResolver
	middleware.ResourcePlanner
}

func TestNetHTTPAnswersTheAPIWithTheFetchHandlerWithoutANodeTransport(t *testing.T) {
	f := orgfixture.New(t, nil)
	adapted := middleware.Server(f.IAM)
	source := fetchOnly{IAM: adapted, EndpointProvider: adapted, HostResolver: adapted, ResourcePlanner: adapted}
	if _, node := any(source).(middleware.NodeHandler); node {
		t.Fatal("the source must not have a Node transport")
	}
	iamHTTP := middleware.NewWith(source, middleware.Options{LoginPath: "/login", StepUpPath: "/verify"})
	middlewaretest.Scenario(t, f, listen(t, iamHTTP.Handler(routes(f, iamHTTP))))
}

func TestNetHTTPServesTheAPIWhenMountedUnderAStrippedPrefix(t *testing.T) {
	f := orgfixture.New(t, nil)
	iamHTTP := middleware.New(f.IAM, middleware.Options{})
	mux := http.NewServeMux()
	// Mounted under a path, the router strips the prefix from r.URL; the integration routes on the original target.
	mux.Handle("/api/iam/", http.StripPrefix("/api/iam", iamHTTP.Handler(nil)))
	call := listen(t, mux)
	signIn := call("POST", "/api/iam/auth/signIn", middlewaretest.JSONHeaders(nil), core.MustStringify(core.NewObject(
		"tenantId", f.TenantID, "email", "owner@acme.test", "password", orgfixture.OwnerPassword,
	)))
	if signIn.StatusCode != 200 || middlewaretest.CookieOf(signIn) == "" {
		t.Fatalf("sign-in: %d", signIn.StatusCode)
	}
	session := call("POST", "/api/iam/auth/getSession", middlewaretest.JSONHeaders(map[string]string{"cookie": middlewaretest.CookieOf(signIn)}), "{}")
	data, _ := middlewaretest.Body(t, session)["data"].(map[string]any)
	identity, _ := data["identity"].(map[string]any)
	if identity["email"] != "owner@acme.test" {
		t.Fatalf("session: %v", data)
	}
}

func TestNetHTTPAuthorizeCallbacksReadRouteParameters(t *testing.T) {
	f := orgfixture.New(t, nil)
	var seen []string
	iamHTTP := middleware.New(f.IAM, middleware.Options{})
	mux := http.NewServeMux()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		middlewaretest.WriteJSON(w, core.NewObject("ok", true))
	})
	mux.Handle("GET /tenants/{tenantId}/admin", iamHTTP.Authorize("iam:identities:update", middleware.AuthorizeSpec[*http.Request]{
		TenantID: func(r *http.Request, _ *core.Object) (string, error) {
			seen = append(seen, "nethttp:"+r.PathValue("tenantId"))
			return r.PathValue("tenantId"), nil
		},
		Resource: func(r *http.Request, _ *core.Object) (middleware.ResourceRef, error) {
			return middleware.ResourceRef{Type: "iam", ID: r.PathValue("tenantId")}, nil
		},
	})(ok))
	call := listen(t, iamHTTP.Handler(mux))
	signIn := call("POST", "/api/iam/auth/signIn", middlewaretest.JSONHeaders(nil), core.MustStringify(core.NewObject(
		"tenantId", f.TenantID, "email", "owner@acme.test", "password", orgfixture.OwnerPassword,
	)))
	cookie := map[string]string{"cookie": middlewaretest.CookieOf(signIn)}
	if response := call("GET", "/tenants/"+f.TenantID+"/admin", cookie, ""); response.StatusCode != 200 {
		t.Fatalf("status %d", response.StatusCode)
	}
	// Another tenant's administration is refused.
	if response := call("GET", "/tenants/"+f.RootID+"/admin", cookie, ""); response.StatusCode != 403 {
		t.Fatalf("status %d", response.StatusCode)
	}
	if strings.Join(seen, ",") != "nethttp:"+f.TenantID+",nethttp:"+f.RootID {
		t.Fatalf("seen %v", seen)
	}
}

func TestNetHTTPReachesNodeOnlyProtocolMountsListedInServe(t *testing.T) {
	f := orgfixture.New(t, nil)
	f.IAM.UseProtocol(server.ProtocolService{
		BasePath: "/node-proto",
		NodeHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, core.MustStringify(core.NewObject("served", r.URL.RequestURI())))
		}),
	})
	iamHTTP := middleware.New(f.IAM, middleware.Options{Serve: []string{"/api/iam", "/node-proto"}})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /node-proto/x", func(w http.ResponseWriter, _ *http.Request) {
		middlewaretest.WriteJSON(w, core.NewObject("served", "by the app"))
	})
	call := listen(t, iamHTTP.Handler(mux))
	if served := middlewaretest.Body(t, call("GET", "/node-proto/metadata?x=1", nil, ""))["served"]; served != "/node-proto/metadata?x=1" {
		t.Fatalf("served %v", served)
	}
	if served := middlewaretest.Body(t, call("GET", "/node-proto/x", nil, ""))["served"]; served != "/node-proto/x" {
		t.Fatalf("served %v", served)
	}
	posted := call("POST", "/node-proto/metadata", map[string]string{"content-type": "application/json"}, `{"a":1}`)
	if served := middlewaretest.Body(t, posted)["served"]; served != "/node-proto/metadata" {
		t.Fatalf("served %v", served)
	}
}

func TestMiddlewarePlanPlansForTheRequestCredentialAndPlansNeverWhenSignedOut(t *testing.T) {
	f := orgfixture.New(t, nil)
	helpers := func(header http.Header) *middleware.Helpers {
		target := httptest.NewRequest("GET", "http://localhost:3000/documents", nil).URL
		return middleware.NewHelpers(func(context.Context) (middleware.IAM, error) { return middleware.Server(f.IAM), nil },
			middleware.RequestBinding{URL: target, Header: header}, middleware.HelperOptions{})
	}
	owner := helpers(http.Header{"Authorization": {"Bearer " + f.Owner.Token}})
	plan, err := owner.Plan(f.Ctx, middleware.PlanInput{Action: "documents:read", Type: "document"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Get("tenantId") != f.TenantID || plan.Get("kind") != "always" {
		t.Fatalf("owner plan: %s", core.MustStringify(plan))
	}
	anonymous := helpers(http.Header{})
	never, err := anonymous.Plan(f.Ctx, middleware.PlanInput{Action: "documents:read", Type: "document"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	_ = json.Unmarshal([]byte(core.MustStringify(never)), &decoded)
	if decoded["kind"] != "never" || decoded["filter"].(map[string]any)["kind"] != "false" {
		t.Fatalf("anonymous plan: %s", core.MustStringify(never))
	}
}
