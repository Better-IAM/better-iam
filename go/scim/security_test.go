package scim

// Ports of tests/security-scim.test.ts (SCIM in both directions: an identity provider cannot undo an administrator's
// decisions or go past plan limits, its changes reach subscribers, and outbound provisioning never hands someone
// else's downstream account to a person who merely typed that address) and of the outbound SCIM target part of
// tests/security-outbound.test.ts.

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

func TestInboundNeverReEnablesSomeoneAnAdministratorDisabled(t *testing.T) {
	d := newDirectory(t, nil)
	created := d.create(obj("userName", "mallory@acme.test", "active", true))
	_, err := d.iam.API.Identities.SetStatus(d.ctx, d.owner, server.Input[apitypes.IdentitiesSetStatusInput](obj(
		"tenantId", d.tenantID, "identityId", d.identityID(created), "status", "disabled",
	)))
	requirePorted(t, err)
	if retitle := d.request("Users/"+created, "PATCH", patchOp(obj("op", "replace", "path", "title", "value", "Engineer"))); retitle.status != 200 {
		t.Fatalf("retitle: %d %s", retitle.status, show(retitle.body))
	}
	if d.identityOf(created).Get("status") != "disabled" {
		t.Fatal("re-enabled")
	}
	// The IdP's own deactivation and reactivation still round-trip.
	other := d.create(obj("userName", "olivia@acme.test", "active", true))
	if got := d.request("Users/"+other, "PATCH", patchOp(obj("op", "replace", "path", "active", "value", false))); got.status != 200 {
		t.Fatalf("off: %d", got.status)
	}
	if d.identityOf(other).Get("status") != "disabled" {
		t.Fatal("not disabled")
	}
	if got := d.request("Users/"+other, "PATCH", patchOp(obj("op", "replace", "path", "active", "value", true))); got.status != 200 {
		t.Fatalf("on: %d", got.status)
	}
	if d.identityOf(other).Get("status") != "active" {
		t.Fatal("not reactivated")
	}
}

func TestInboundKeepsToTheTenantPlanLimits(t *testing.T) {
	d := newDirectory(t, nil)
	members := len(find(t, d.store, "identities", obj("tenantId", d.tenantID, "kind", "user")))
	_, err := d.iam.API.Tenants.SetLimits(d.ctx, d.root, server.Input[apitypes.TenantsSetLimitsInput](obj(
		"tenantId", d.tenantID, "limits", obj("identities", members+1, "groups", 0),
	)))
	requirePorted(t, err)
	if got := d.request("Users", "POST", obj("userName", "one@acme.test")); got.status != 201 {
		t.Fatalf("one: %d %s", got.status, show(got.body))
	}
	if got := d.request("Users", "POST", obj("userName", "two@acme.test")); got.status != 409 {
		t.Fatalf("two: %d", got.status)
	}
	if got := d.request("Groups", "POST", obj("displayName", "Admins")); got.status != 409 {
		t.Fatalf("group: %d", got.status)
	}
}

func TestInboundFansItsAuditEventsOutToSubscribers(t *testing.T) {
	d := newDirectory(t, nil)
	var mu sync.Mutex
	var seen []string
	unsubscribe, err := d.iam.Events.Subscribe("iam:scim:*", func(_ context.Context, event *core.Object) error {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, jsString(event.Get("action")))
		return nil
	})
	requirePorted(t, err)
	defer unsubscribe()
	if got := d.request("Users", "POST", obj("userName", "sam@acme.test")); got.status != 201 {
		t.Fatalf("create: %d", got.status)
	}
	_, err = d.iam.Events.Dispatch(d.ctx)
	requirePorted(t, err)
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(strings.Join(seen, ","), "iam:scim:CreateUser") {
		t.Fatalf("seen: %v", seen)
	}
}

// endless is a request body that never ends.
type endless struct{ read int }

func (e *endless) Read(p []byte) (int, error) {
	for index := range p {
		p[index] = ' '
	}
	e.read += len(p)
	return len(p), nil
}

func TestInboundRefusesOversizedBodiesWithoutBufferingThem(t *testing.T) {
	d := newDirectory(t, nil)
	body := &endless{}
	request := httptest.NewRequest("POST", "https://iam.test"+d.connection.path+"/Users", io.NopCloser(body))
	request.Header.Set("content-type", "application/scim+json")
	response := decode(t, d.service.Handle(request))
	if response.status != 413 || response.get("scimType") != "tooLarge" {
		t.Fatalf("oversized: %d %s", response.status, show(response.body))
	}
	if body.read > 2*MaxPayloadSize {
		t.Fatalf("buffered %d bytes", body.read)
	}
}

var quotedFilter = regexp.MustCompile(`^(\w+) eq (".*")$`)

func TestOutboundAdoptsByEmailOnlyForAVerifiedAddressEscapingFilterValues(t *testing.T) {
	f := newOrgFixture(t)
	var mu sync.Mutex
	users := newOrderedRecords()
	users.set("victim-remote", obj("id", "victim-remote", "userName", "victim@acme.test", "active", true))
	var filters []string
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		send := func(status int, body any) {
			w.Header().Set("content-type", "application/scim+json")
			w.WriteHeader(status)
			if body != nil {
				_, _ = w.Write([]byte(show(core.Normalize(body))))
			}
		}
		parsed := func() *core.Object {
			value, _ := core.ParseJSON(raw)
			record, _ := value.(*core.Object)
			return record
		}
		if r.Method == "GET" && r.URL.Path == "/scim/Users" {
			filter := r.URL.Query().Get("filter")
			filters = append(filters, filter)
			match := quotedFilter.FindStringSubmatch(filter)
			wanted, _ := core.ParseJSONString(match[2])
			found := []any{}
			for _, user := range users.values() {
				if user.Get(match[1]) == wanted {
					found = append(found, user)
				}
			}
			send(200, obj("totalResults", len(found), "Resources", found))
			return
		}
		if r.Method == "POST" && r.URL.Path == "/scim/Users" {
			user := parsed().Spread(obj("id", hex.EncodeToString(randomBytes(4))))
			users.set(user.Get("id").(string), user)
			send(201, user)
			return
		}
		if r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/scim/Users/") {
			id := strings.TrimPrefix(r.URL.Path, "/scim/Users/")
			users.set(id, parsed())
			send(200, users.items[id])
			return
		}
		send(404, obj("detail", "not found"))
	}))
	t.Cleanup(downstream.Close)
	// Someone signs up with the victim's address plus a quote: unverified, and not the same address.
	insert(t, f.store, "identities", obj(
		"id", "impostor", "tenantId", f.tenantID, "name", "Impostor", "kind", "user", "email", `victim"@acme.test`,
		"emailVerified", false, "status", "active", "rootAdmin", false, "owner", false, "createdAt", wallClock(),
	))
	config := hostProvisioning(f.iam)
	config.EncryptionKey = newKey()
	config.AllowInsecureLocalhost = true
	provisioner := must(NewProvisioner(config))
	target := f.record(provisioner.CreateTarget(f.ctx, f.owner, TargetInput{
		TenantID: f.tenantID, Name: strPtr("App"), BaseURL: strPtr(downstream.URL + "/scim"), Token: strPtr(testDownstreamToken),
	}))
	_, err := provisioner.SyncTarget(f.ctx, f.owner, f.tenantID, target.Get("id").(string))
	requirePorted(t, err)
	mu.Lock()
	defer mu.Unlock()
	// The victim's downstream account is untouched and the impostor got an account of their own.
	victim := users.items["victim-remote"]
	if victim.Get("userName") != "victim@acme.test" || victim.Has("externalId") {
		t.Fatalf("victim: %s", show(victim))
	}
	joined := strings.Join(filters, "\n")
	if !strings.Contains(joined, `externalId eq "impostor"`) {
		t.Fatalf("filters: %v", filters)
	}
	for _, filter := range filters {
		if strings.HasPrefix(filter, "userName eq") && strings.Contains(filter, "victim") {
			t.Fatalf("looked up the victim's address: %s", filter)
		}
	}
}

func TestOutboundRefusesPrivateBaseURLsAndKeepsTheTokenFromFollowingABaseURLChange(t *testing.T) {
	store := newStore(t)
	insert(t, store, "tenants", obj("id", "a", "tenantId", "a", "name", "A", "type", "organization", "parentId", nil, "status", "active", "createdAt", wallClock()))
	insert(t, store, "identities", obj("id", "ada", "tenantId", "a", "name", "Ada", "kind", "user", "email", "ada@acme.test", "emailVerified", true, "status", "active", "rootAdmin", false, "owner", false, "createdAt", wallClock()))
	scim := must(NewProvisioner(ProvisioningConfig{
		Store: store, EncryptionKey: newKey(), AllowInsecureLocalhost: true,
		Authenticate: func(context.Context, core.CredentialInput) (string, error) { return "admin", nil },
		Authorize: func(_ context.Context, credential core.CredentialInput, _ string, _ core.ResourceRef) error {
			if credential.Token != "admin" {
				return core.NewIamError("ACCESS_DENIED", "Forbidden", 403)
			}
			return nil
		},
	}))
	for _, baseURL := range []string{"https://10.0.0.1:8443/scim", "https://[fd00::1]/scim"} {
		_, err := scim.CreateTarget(bg, admin, TargetInput{TenantID: "a", Name: strPtr("Internal"), BaseURL: strPtr(baseURL), Token: strPtr(testDownstreamToken)})
		expectCode(t, err, "INVALID_INPUT", 0)
	}
	var mu sync.Mutex
	var received []string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, r.Header.Get("authorization"))
		mu.Unlock()
		w.Header().Set("content-type", "application/scim+json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"totalResults":0,"Resources":[]}`))
	}))
	t.Cleanup(origin.Close)
	target := must(scim.CreateTarget(bg, admin, TargetInput{TenantID: "a", Name: strPtr("App"), BaseURL: strPtr("https://app.example.test/scim/v2"), Token: strPtr(testDownstreamToken)}))
	id := target.Get("id").(string)
	_, err := scim.UpdateTarget(bg, admin, TargetInput{TenantID: "a", TargetID: id, BaseURL: strPtr(origin.URL + "/scim")})
	expectCode(t, err, "INVALID_INPUT", 0)
	// Renaming keeps the token; a new URL with a new token is fine.
	must(scim.UpdateTarget(bg, admin, TargetInput{TenantID: "a", TargetID: id, Name: strPtr("Renamed")}))
	moved := must(scim.UpdateTarget(bg, admin, TargetInput{TenantID: "a", TargetID: id, BaseURL: strPtr(origin.URL + "/scim"), Token: strPtr("a-new-downstream-token")}))
	if moved.Get("baseUrl") != origin.URL+"/scim" {
		t.Fatalf("baseUrl: %v", moved.Get("baseUrl"))
	}
	must(scim.PreviewTarget(bg, admin, "a", id))
	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("no downstream lookups")
	}
	for _, value := range received {
		if value != "Bearer a-new-downstream-token" {
			t.Fatalf("authorization sent: %q", value)
		}
	}
}
