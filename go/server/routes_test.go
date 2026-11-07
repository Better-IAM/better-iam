package server

// The route manifest test (spec/BUILDOUT.md "Parity verification" 1): the router answers exactly the routes of
// spec/api/routes.json, no missing and no extra ones, and every one of them reaches its method.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

type routeManifest struct {
	BasePath string `json:"basePath"`
	RPC      []struct {
		Path       string `json:"path"`
		Group      string `json:"group"`
		Method     string `json:"method"`
		Call       string `json:"call"`
		Credential string `json:"credential"`
		Tenant     bool   `json:"tenantBound"`
		Cookie     bool   `json:"setsSessionCookie"`
		Device     bool   `json:"readsDeviceCookie"`
	} `json:"rpc"`
	Special []struct {
		Path string `json:"path"`
	} `json:"special"`
	Sets map[string][]string `json:"sets"`
}

func loadRoutes(t *testing.T) routeManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "spec", "api", "routes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest routeManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestRouterAnswersExactlyTheManifest(t *testing.T) {
	manifest := loadRoutes(t)
	expected := map[string]bool{}
	for _, route := range manifest.RPC {
		expected[route.Path] = true
	}
	// The router's table, plus the two auth routes http.go dispatches itself.
	actual := map[string]bool{"auth/beginMfa": true, "auth/confirmMfa": true}
	for path := range rpcRoutes {
		actual[path] = true
	}
	var missing, extra []string
	for path := range expected {
		if !actual[path] {
			missing = append(missing, path)
		}
	}
	for path := range actual {
		if !expected[path] {
			extra = append(extra, path)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("router differs from routes.json: missing %v, extra %v", missing, extra)
	}
	// The sets the router decides with are the manifest's.
	sets := map[string]*orderedSet{
		"publicAuthMethods": PublicAuthMethods, "authenticatedAuthMethods": AuthenticatedAuthMethods,
		"routeGroups": RouteGroups, "publicApiMethods": PublicAPIMethods, "tenantBoundPublicMethods": tenantBoundPublicMethods,
		"sessionCookieRoutes": sessionCookieRoutes, "deviceTokenRoutes": deviceTokenRoutes,
	}
	for name, set := range sets {
		want := manifest.Sets[name]
		if strings.Join(set.Values(), ",") != strings.Join(want, ",") {
			t.Errorf("%s = %v, routes.json %v", name, set.Values(), want)
		}
	}
	// Every route's flags agree with the router: public routes, tenant pinning, cookies.
	for _, route := range manifest.RPC {
		public := PublicAPIMethods.Has(route.Path)
		if route.Group == "auth" {
			public = PublicAuthMethods.Has(route.Method)
		}
		if public != (route.Credential == "none") {
			t.Errorf("%s: public %v, routes.json credential %q", route.Path, public, route.Credential)
		}
		if bound := public && (route.Group == "auth" || tenantBoundPublicMethods.Has(route.Path)); bound != route.Tenant {
			t.Errorf("%s: tenant-bound %v, routes.json %v", route.Path, bound, route.Tenant)
		}
		if sessionCookieRoutes.Has(route.Path) != route.Cookie || deviceTokenRoutes.Has(route.Path) != route.Device {
			t.Errorf("%s: cookie flags differ", route.Path)
		}
		if op, ok := apitypes.LookupOperation(route.Path); !ok || op.Group != route.Group || op.Method != route.Method {
			t.Errorf("%s: no generated operation", route.Path)
		}
	}
	if len(manifest.Special) != 4 {
		t.Errorf("special routes: %d", len(manifest.Special))
	}
}

// TestEveryRouteReachesItsMethod posts to every route and checks the router dispatched it: whatever the method
// answers (a validation error, a refusal, NOT_IMPLEMENTED from a stub), it is never the router's "Endpoint not found".
func TestEveryRouteReachesItsMethod(t *testing.T) {
	const base = "http://localhost:3000"
	f := newIam(t, base, nil)
	manifest := loadRoutes(t)
	paths := []string{"authorize", "authorizeMany", "listAccessible"}
	for _, route := range manifest.RPC {
		paths = append(paths, route.Path)
	}
	for _, path := range paths {
		response := f.post(base, path, `{}`, map[string]string{"authorization": "Bearer not-a-real-token-but-long-enough-to-check"})
		if response.Status == 404 {
			if message := jsString(member(jsonBody(t, response).Get("error"), "message")); message == "Endpoint not found" {
				t.Errorf("%s: the router answered Endpoint not found", path)
			}
		}
		if response.Status == 500 {
			t.Errorf("%s: 500 %s", path, response.Body)
		}
	}
	// Plugin routes: an unknown plugin endpoint is the router's 404.
	if response := f.post(base, "plugins/none/action", `{"tenantId":"t"}`, nil); response.Status != 404 {
		t.Errorf("plugins/none/action: %d", response.Status)
	}
	// In-process: every group of the API struct is constructed.
	for _, route := range manifest.RPC {
		call := rpcRoutes[route.Path]
		if call == nil {
			continue
		}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("%s panicked: %v", route.Path, recovered)
				}
			}()
			_, _ = call(context.Background(), f.iam.API, core.CredentialInput{Headers: http.Header{}}, core.NewObject())
		}()
	}
}
