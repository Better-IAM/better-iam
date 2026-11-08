package scim

// Port of tests/scim-outbound.test.ts: outbound SCIM provisioning against a minimal in-memory SCIM service.

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

const testDownstreamToken = "downstream-provisioning-token"

// orderedRecords is a Map of records keyed by id (insertion order kept).
type orderedRecords struct {
	order []string
	items map[string]*core.Object
}

func newOrderedRecords() *orderedRecords { return &orderedRecords{items: map[string]*core.Object{}} }

func (r *orderedRecords) set(id string, record *core.Object) {
	if _, ok := r.items[id]; !ok {
		r.order = append(r.order, id)
	}
	r.items[id] = record
}

func (r *orderedRecords) remove(id string) {
	if _, ok := r.items[id]; !ok {
		return
	}
	delete(r.items, id)
	for index, item := range r.order {
		if item == id {
			r.order = append(r.order[:index], r.order[index+1:]...)
			break
		}
	}
}

func (r *orderedRecords) values() []*core.Object {
	out := make([]*core.Object, len(r.order))
	for index, id := range r.order {
		out[index] = r.items[id]
	}
	return out
}

// fakeScim is a minimal SCIM 2.0 service provider: users in memory, bearer auth, filter by one attribute.
type fakeScim struct {
	mu       sync.Mutex
	server   *httptest.Server
	users    *orderedRecords
	groups   *orderedRecords
	calls    []string
	failNext int
}

var filterPattern = regexp.MustCompile(`^(\w+) eq "(.*)"$`)
var groupPathPattern = regexp.MustCompile(`^/scim/v2/Groups(?:/([^/]+))?$`)
var userPathPattern = regexp.MustCompile(`^/scim/v2/Users/([^/]+)$`)

func newFakeScim(t *testing.T) *fakeScim {
	f := &fakeScim{users: newOrderedRecords(), groups: newOrderedRecords()}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		send := func(status int, body any) {
			w.Header().Set("content-type", "application/scim+json")
			w.WriteHeader(status)
			if body != nil {
				_, _ = w.Write([]byte(core.MustStringify(core.Normalize(body))))
			}
		}
		parse := func() *core.Object {
			value, _ := core.ParseJSON(raw)
			o, _ := value.(*core.Object)
			return o
		}
		if r.Header.Get("authorization") != "Bearer "+testDownstreamToken {
			send(401, obj("detail", "bad token"))
			return
		}
		if f.failNext != 0 {
			status := f.failNext
			f.failNext = 0
			send(status, obj("detail", "downstream refused"))
			return
		}
		search := func(records *orderedRecords) {
			match := filterPattern.FindStringSubmatch(r.URL.Query().Get("filter"))
			matches := []any{}
			for _, item := range records.values() {
				if match != nil && item.Get(match[1]) == match[2] {
					matches = append(matches, item)
				}
			}
			send(200, obj("totalResults", len(matches), "Resources", matches))
		}
		if group := groupPathPattern.FindStringSubmatch(r.URL.Path); group != nil {
			groupID := group[1]
			switch {
			case groupID == "" && r.Method == "GET":
				search(f.groups)
				return
			case groupID == "" && r.Method == "POST":
				item := parse().Spread(obj("id", randomUUID()))
				f.groups.set(item.Get("id").(string), item)
				send(201, item)
				return
			}
			if _, exists := f.groups.items[groupID]; groupID == "" || !exists {
				send(404, obj("detail", "no such group"))
				return
			}
			if r.Method == "PUT" {
				f.groups.set(groupID, parse().Spread(obj("id", groupID)))
				send(200, f.groups.items[groupID])
				return
			}
			if r.Method == "DELETE" {
				f.groups.remove(groupID)
				send(204, nil)
				return
			}
		}
		id := ""
		if match := userPathPattern.FindStringSubmatch(r.URL.Path); match != nil {
			id = match[1]
		}
		if r.URL.Path == "/scim/v2/Users" && r.Method == "GET" {
			search(f.users)
			return
		}
		if r.URL.Path == "/scim/v2/Users" && r.Method == "POST" {
			user := parse().Spread(obj("id", randomUUID()))
			f.users.set(user.Get("id").(string), user)
			send(201, user)
			return
		}
		if _, exists := f.users.items[id]; id != "" && !exists {
			send(404, obj("detail", "no such user"))
			return
		}
		switch {
		case id != "" && r.Method == "PUT":
			f.users.set(id, parse().Spread(obj("id", id)))
			send(200, f.users.items[id])
		case id != "" && r.Method == "PATCH":
			operations := parse().Get("Operations").([]any)
			f.users.set(id, f.users.items[id].Spread(member(operations[0], "value").(*core.Object)))
			send(200, f.users.items[id])
		case id != "" && r.Method == "DELETE":
			f.users.remove(id)
			send(204, nil)
		default:
			send(404, nil)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeScim) fail(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext = status
}

func (f *fakeScim) userCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.users.order)
}

func (f *fakeScim) byExternal() map[string]*core.Object {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]*core.Object{}
	for _, user := range f.users.values() {
		out[jsString(user.Get("externalId"))] = user
	}
	return out
}

func (f *fakeScim) writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, call := range f.calls {
		if !strings.HasPrefix(call, "GET") {
			count++
		}
	}
	return count
}

type outboundFixture struct {
	t          *testing.T
	store      core.IamStore
	downstream *fakeScim
	origin     string
	mu         sync.Mutex
	denied     []string
}

func newKey() string { return base64.StdEncoding.EncodeToString(randomBytes(32)) }

func newOutboundFixture(t *testing.T) *outboundFixture {
	t.Helper()
	store := newStore(t)
	insert(t, store, "tenants", obj("id", "a", "tenantId", "a", "name", "A", "type", "organization", "parentId", nil, "status", "active", "createdAt", wallClock()))
	for _, row := range [][3]string{{"ada", "active", "user"}, {"bob", "active", "user"}, {"cy", "disabled", "user"}, {"robot", "active", "service"}} {
		id, status, kind := row[0], row[1], row[2]
		identity := obj("id", id, "tenantId", "a", "name", strings.ToUpper(id), "kind", kind)
		if kind == "user" {
			identity.Set("email", id+"@acme.test")
		}
		identity.Assign(obj("emailVerified", true, "status", status, "rootAdmin", false, "owner", false, "createdAt", wallClock(), "attributes", obj("department", id+"-dept")))
		insert(t, store, "identities", identity)
	}
	insert(t, store, "groupMembers", obj("id", "m1", "tenantId", "a", "groupId", "engineering", "identityId", "ada"))
	downstream := newFakeScim(t)
	return &outboundFixture{t: t, store: store, downstream: downstream, origin: downstream.server.URL}
}

func (f *outboundFixture) provisioner() *Provisioner {
	f.t.Helper()
	return must(NewProvisioner(ProvisioningConfig{
		Store:                  f.store,
		EncryptionKey:          newKey(),
		AllowInsecureLocalhost: true,
		Authenticate:           func(context.Context, core.CredentialInput) (string, error) { return "admin", nil },
		Authorize: func(_ context.Context, credential core.CredentialInput, action string, _ core.ResourceRef) error {
			bearer := ""
			if credential.Headers != nil {
				bearer = credential.Headers.Get("authorization")
			}
			if credential.Token != "admin" && bearer != "Bearer admin" {
				f.mu.Lock()
				f.denied = append(f.denied, action)
				f.mu.Unlock()
				return core.NewIamError("ACCESS_DENIED", "Forbidden", 403)
			}
			return nil
		},
	}))
}

func strPtr(value string) *string { return &value }
func flag(value bool) *bool       { return &value }

func (f *outboundFixture) target(service *Provisioner, input TargetInput) *core.Object {
	f.t.Helper()
	input.TenantID = "a"
	if input.Token == nil {
		input.Token = strPtr(testDownstreamToken)
	}
	return must(service.CreateTarget(bg, admin, input))
}

func matches(t *testing.T, value *core.Object, pairs ...any) {
	t.Helper()
	expected := obj(pairs...)
	for _, key := range expected.Keys() {
		if show(value.Get(key)) != show(expected.Get(key)) {
			t.Fatalf("%s: expected %s, got %s (%s)", key, show(expected.Get(key)), show(value.Get(key)), show(value))
		}
	}
}

func TestKeepsDownstreamTokensUsableThroughAnEncryptionKeyRotation(t *testing.T) {
	f := newOutboundFixture(t)
	oldKey, newKeyValue := newKey(), newKey()
	makeProvisioner := func(encryptionKey string, previous ...string) *Provisioner {
		return must(NewProvisioner(ProvisioningConfig{
			Store: f.store, EncryptionKey: encryptionKey, PreviousEncryptionKeys: previous, AllowInsecureLocalhost: true,
			Authenticate: func(context.Context, core.CredentialInput) (string, error) { return "admin", nil },
			Authorize:    func(context.Context, core.CredentialInput, string, core.ResourceRef) error { return nil },
		}))
	}
	target := must(makeProvisioner(oldKey).CreateTarget(bg, admin, TargetInput{TenantID: "a", Name: strPtr("Acme Slack"), BaseURL: strPtr(f.origin + "/scim/v2/"), Token: strPtr(testDownstreamToken)}))
	id := target.Get("id").(string)
	// Rotating: the new key seals, the old one still opens.
	during := makeProvisioner(newKeyValue, oldKey)
	matches(t, must(during.SyncTarget(bg, admin, "a", id)), "created", 2, "failed", 0)
	sameJSON(t, must(during.RotateKeys(bg)), obj("resealed", 1, "current", 0, "unreadable", 0))
	sameJSON(t, must(during.RotateKeys(bg)), obj("resealed", 0, "current", 1, "unreadable", 0))
	// Afterwards the old key can go.
	matches(t, must(makeProvisioner(newKeyValue).SyncTarget(bg, admin, "a", id)), "failed", 0)
	sameJSON(t, must(makeProvisioner(newKey()).RotateKeys(bg)), obj("resealed", 0, "current", 0, "unreadable", 1))
	if _, err := NewProvisioner(ProvisioningConfig{Store: f.store, EncryptionKey: newKeyValue, PreviousEncryptionKeys: []string{"c2hvcnQ="}}); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("short previous key: %v", err)
	}
}

func TestProvisionsActiveMembersUpdatesChangesAndDeactivatesPeopleWhoLeave(t *testing.T) {
	f := newOutboundFixture(t)
	service := f.provisioner()
	target := f.target(service, TargetInput{Name: strPtr("Acme Slack"), BaseURL: strPtr(f.origin + "/scim/v2/"), AttributeMapping: obj("department", "department")})
	matches(t, target, "tenantId", "a", "name", "Acme Slack", "baseUrl", f.origin+"/scim/v2", "deprovision", "deactivate", "enabled", true, "provisioned", 0)
	if strings.Contains(show(target), testDownstreamToken) || strings.Contains(show(find(t, f.store, "provisioningTargets", nil)), testDownstreamToken) {
		t.Fatal("the downstream token leaked")
	}
	id := target.Get("id").(string)
	run := must(service.SyncTarget(bg, admin, "a", id))
	matches(t, run, "created", 2, "updated", 0, "deactivated", 0, "failed", 0)
	external := f.downstream.byExternal()
	var keys []string
	for key := range external {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "ada,bob" {
		t.Fatalf("downstream: %v", keys)
	}
	matches(t, external["ada"], "userName", "ada@acme.test", "displayName", "ADA", "active", true, EnterpriseSchema, obj("department", "ada-dept"))

	// A second run with no changes touches nothing downstream.
	before := len(f.downstream.calls)
	matches(t, must(service.SyncTarget(bg, admin, "a", id)), "created", 0, "updated", 0, "unchanged", 2)
	if len(f.downstream.calls) != before {
		t.Fatal("an unchanged run called downstream")
	}

	// A rename is pushed; a disabled member is deactivated, not deleted.
	put(t, f.store, "identities", get(t, f.store, "identities", "ada").Spread(obj("name", "Ada L.")))
	put(t, f.store, "identities", get(t, f.store, "identities", "bob").Spread(obj("status", "disabled")))
	matches(t, must(service.SyncTarget(bg, admin, "a", id)), "updated", 1, "deactivated", 1, "failed", 0)
	external = f.downstream.byExternal()
	matches(t, external["ada"], "displayName", "Ada L.")
	matches(t, external["bob"], "active", false)
	matches(t, must(service.GetTarget(bg, admin, "a", id)), "provisioned", 1)

	// Re-enabling reactivates the same downstream account.
	put(t, f.store, "identities", get(t, f.store, "identities", "bob").Spread(obj("status", "active")))
	matches(t, must(service.SyncTarget(bg, admin, "a", id)), "created", 0, "updated", 1)
	if f.downstream.userCount() != 2 {
		t.Fatal("a duplicate downstream account")
	}
	matches(t, f.downstream.byExternal()["bob"], "active", true)
	actions := map[string]bool{}
	for _, event := range find(t, f.store, "audit", obj("tenantId", "a")) {
		actions[jsString(event.Get("action"))] = true
	}
	if !actions["iam:scim:CreateTarget"] || !actions["iam:scim:SyncTarget"] {
		t.Fatalf("audit: %v", actions)
	}
}

func TestScopesToGroupsAdoptsExistingUsersDeletesWhenConfiguredAndRecordsFailures(t *testing.T) {
	f := newOutboundFixture(t)
	// A downstream account created by hand earlier is adopted by userName instead of duplicated.
	f.downstream.users.set("existing", obj("id", "existing", "userName", "ada@acme.test", "active", true))
	service := f.provisioner()
	target := f.target(service, TargetInput{Name: strPtr("Engineering tools"), BaseURL: strPtr(f.origin + "/scim/v2"), GroupIDs: []string{"engineering"}, Deprovision: strPtr("delete")})
	id := target.Get("id").(string)
	runs := must(service.SyncAll(bg, "a"))
	matches(t, runs.Get(id).(*core.Object), "created", 0, "updated", 1, "failed", 0)
	if f.downstream.userCount() != 1 {
		t.Fatal("duplicated")
	}
	matches(t, f.downstream.users.items["existing"], "externalId", "ada", "active", true)

	// Leaving the group deletes the downstream account in delete mode.
	ok(t, f.store.Transaction(bg, func(ctx context.Context, tx core.IamStore) error { return tx.Delete(ctx, "groupMembers", "m1") }))
	matches(t, must(service.SyncTarget(bg, admin, "a", id)), "deleted", 1)
	if f.downstream.userCount() != 0 || len(find(t, f.store, "provisioningLinks", obj("targetId", id))) != 0 {
		t.Fatal("not deleted")
	}

	// Downstream refusals are counted and reported without stopping the run.
	insert(t, f.store, "groupMembers", obj("id", "m2", "tenantId", "a", "groupId", "engineering", "identityId", "bob"))
	f.downstream.fail(500)
	run := must(service.SyncTarget(bg, admin, "a", id))
	if run.Get("failed") != 1.0 {
		t.Fatalf("failed: %s", show(run))
	}
	first := run.Get("errors").([]any)[0].(*core.Object)
	matches(t, first, "identityId", "bob", "status", 500)
	if !strings.Contains(first.Get("message").(string), "downstream refused") {
		t.Fatalf("message: %s", show(first))
	}
	matches(t, must(service.GetTarget(bg, admin, "a", id)).Get("lastRun").(*core.Object), "failed", 1)
	// The next run retries.
	matches(t, must(service.SyncTarget(bg, admin, "a", id)), "created", 1, "failed", 0)

	// A wrong token fails every call with 401 and is fixed by replacing the token.
	must(service.UpdateTarget(bg, admin, TargetInput{TenantID: "a", TargetID: id, Token: strPtr("wrong-token-value")}))
	put(t, f.store, "identities", get(t, f.store, "identities", "bob").Spread(obj("name", "Robert")))
	run = must(service.SyncTarget(bg, admin, "a", id))
	matches(t, run.Get("errors").([]any)[0].(*core.Object), "status", 401)
	must(service.UpdateTarget(bg, admin, TargetInput{TenantID: "a", TargetID: id, Token: strPtr(testDownstreamToken)}))
	matches(t, must(service.SyncTarget(bg, admin, "a", id)), "updated", 1, "failed", 0)
}

func TestPushesScopedGroupsWithTheirProvisionedMembers(t *testing.T) {
	f := newOutboundFixture(t)
	insert(t, f.store, "groups", obj("id", "engineering", "tenantId", "a", "name", "Engineering"), obj("id", "design", "tenantId", "a", "name", "Design"))
	// An existing downstream group with the same name is adopted.
	f.downstream.groups.set("g-existing", obj("id", "g-existing", "displayName", "Engineering", "members", list()))
	service := f.provisioner()
	target := f.target(service, TargetInput{Name: strPtr("With groups"), BaseURL: strPtr(f.origin + "/scim/v2"), GroupIDs: []string{"engineering", "design"}, PushGroups: flag(true)})
	if target.Get("pushGroups") != true {
		t.Fatal("pushGroups")
	}
	id := target.Get("id").(string)
	run := must(service.SyncTarget(bg, admin, "a", id))
	sameJSON(t, run.Get("groups"), obj("created", 1, "updated", 1, "deleted", 0, "unchanged", 0))
	remoteID := func(externalID string) any { return f.downstream.byExternal()[externalID].Get("id") }
	byName := func(name string) *core.Object {
		for _, item := range f.downstream.groups.values() {
			if item.Get("displayName") == name {
				return item
			}
		}
		t.Fatalf("no group %s", name)
		return nil
	}
	matches(t, byName("Engineering"), "id", "g-existing", "externalId", "engineering", "members", list(obj("value", remoteID("ada"))))
	matches(t, byName("Design"), "members", list())

	// Membership changes update the group; unchanged groups are left alone.
	insert(t, f.store, "groupMembers", obj("id", "m3", "tenantId", "a", "groupId", "design", "identityId", "bob"))
	run = must(service.SyncTarget(bg, admin, "a", id))
	matches(t, run, "created", 1)
	matches(t, run.Get("groups").(*core.Object), "updated", 1, "unchanged", 1)
	matches(t, byName("Design"), "members", list(obj("value", remoteID("bob"))))

	// Groups that leave scope are deleted downstream; turning pushGroups off removes the rest.
	must(service.UpdateTarget(bg, admin, TargetInput{TenantID: "a", TargetID: id, GroupIDs: []string{"engineering"}}))
	run = must(service.SyncTarget(bg, admin, "a", id))
	matches(t, run.Get("groups").(*core.Object), "deleted", 1)
	if names := f.downstream.groups.values(); len(names) != 1 || names[0].Get("displayName") != "Engineering" {
		t.Fatalf("groups: %s", show(names))
	}
	must(service.UpdateTarget(bg, admin, TargetInput{TenantID: "a", TargetID: id, PushGroups: flag(false)}))
	run = must(service.SyncTarget(bg, admin, "a", id))
	matches(t, run.Get("groups").(*core.Object), "deleted", 1)
	if len(f.downstream.groups.order) != 0 {
		t.Fatal("groups left downstream")
	}
	_, err := service.UpdateTarget(bg, admin, TargetInput{TenantID: "a", TargetID: id, GroupIDs: []string{}, PushGroups: flag(true)})
	expectCode(t, err, "INVALID_INPUT", 0)
}

type recordingEvents struct {
	mu       sync.Mutex
	patterns [][]string
	handlers []func(ctx context.Context, event *core.Object) error
}

func (e *recordingEvents) Subscribe(pattern any, handler func(ctx context.Context, event *core.Object) error) (func(), error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.patterns = append(e.patterns, pattern.([]string))
	e.handlers = append(e.handlers, handler)
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.handlers = nil
	}, nil
}

func TestIgnoresLapsedMembershipsAndSyncsAfterAccessPackageChanges(t *testing.T) {
	f := newOutboundFixture(t)
	insert(t, f.store, "groups", obj("id", "engineering", "tenantId", "a", "name", "Engineering"))
	// Bob's temporary (or package) membership has already ended but not been purged yet.
	insert(t, f.store, "groupMembers", obj("id", "m-lapsed", "tenantId", "a", "groupId", "engineering", "identityId", "bob", "expiresAt", wallClock()-1000))
	service := f.provisioner()
	target := f.target(service, TargetInput{Name: strPtr("Scoped"), BaseURL: strPtr(f.origin + "/scim/v2"), GroupIDs: []string{"engineering"}, PushGroups: flag(true)})
	must(service.SyncTarget(bg, admin, "a", target.Get("id").(string)))
	users := f.downstream.users.values()
	if len(users) != 1 || users[0].Get("externalId") != "ada" {
		t.Fatalf("users: %s", show(users))
	}
	if members := f.downstream.groups.values()[0].Get("members").([]any); len(members) != 1 {
		t.Fatalf("members: %d", len(members))
	}
	events := &recordingEvents{}
	unsubscribe := must(service.Subscribe(events, SubscribeOptions{}))
	unsubscribe()
	joined := strings.Join(events.patterns[0], ",")
	if !strings.Contains(joined, "iam:packages:*") || !strings.Contains(joined, "package:*") {
		t.Fatalf("patterns: %s", joined)
	}
}

func TestPreviewsTheNextSyncWithoutWritingDownstream(t *testing.T) {
	f := newOutboundFixture(t)
	f.downstream.users.set("existing", obj("id", "existing", "userName", "bob@acme.test", "active", true))
	service := f.provisioner()
	target := f.target(service, TargetInput{Name: strPtr("Preview"), BaseURL: strPtr(f.origin + "/scim/v2")})
	id := target.Get("id").(string)
	plan := must(service.PreviewTarget(bg, admin, "a", id))
	matches(t, plan.Get("counts").(*core.Object), "create", 1, "adopt", 1, "unchanged", 0)
	changes := show(plan.Get("changes"))
	for _, want := range []string{`{"identityId":"ada","email":"ada@acme.test","action":"create"}`, `{"identityId":"bob","email":"bob@acme.test","action":"adopt"}`} {
		if !strings.Contains(changes, want) {
			t.Fatalf("changes %s lack %s", changes, want)
		}
	}
	if f.downstream.writes() != 0 || len(find(t, f.store, "provisioningLinks", nil)) != 0 {
		t.Fatal("the preview wrote")
	}
	if must(service.GetTarget(bg, admin, "a", id)).Has("lastRun") {
		t.Fatal("lastRun after a preview")
	}
	must(service.SyncTarget(bg, admin, "a", id))
	afterSync := f.downstream.writes()
	put(t, f.store, "identities", get(t, f.store, "identities", "ada").Spread(obj("name", "Ada L.")))
	put(t, f.store, "identities", get(t, f.store, "identities", "bob").Spread(obj("status", "disabled")))
	plan = must(service.PreviewTarget(bg, admin, "a", id))
	matches(t, plan.Get("counts").(*core.Object), "update", 1, "deactivate", 1, "create", 0)
	if f.downstream.writes() != afterSync {
		t.Fatal("the preview wrote")
	}
	_, err := service.PreviewTarget(bg, core.CredentialInput{Token: "member"}, "a", id)
	expectCode(t, err, "ACCESS_DENIED", 403)
}

func TestServesAJSONManagementAPIWithTheIamEnvelopeAndCSRFRule(t *testing.T) {
	f := newOutboundFixture(t)
	service := f.provisioner()
	call := func(route string, body any, headers map[string]string) answer {
		t.Helper()
		request := httptest.NewRequest("POST", "https://iam.test/scim/provisioning/"+route, jsonBody(body))
		request.Header.Set("content-type", "application/json")
		request.Header.Set("x-better-iam", "1")
		request.Header.Set("authorization", "Bearer admin")
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		return decode(t, service.Handle(request))
	}
	created := call("targets/create", obj("tenantId", "a", "name", "Over HTTP", "baseUrl", f.origin+"/scim/v2", "token", testDownstreamToken), nil)
	if created.status != 200 {
		t.Fatalf("create: %d %s", created.status, show(created.body))
	}
	id := created.get("data", "id").(string)
	if synced := call("targets/sync", obj("tenantId", "a", "targetId", id), nil); synced.get("data", "created") != 2.0 {
		t.Fatalf("sync: %s", show(synced.body))
	}
	listed := call("targets/list", obj("tenantId", "a"), nil).get("data").([]any)
	if len(listed) != 1 || member(listed[0], "id") != id || member(listed[0], "provisioned") != 2.0 {
		t.Fatalf("list: %s", show(listed))
	}
	// Missing CSRF header, wrong caller, unknown route, other paths.
	if got := call("targets/list", obj("tenantId", "a"), map[string]string{"x-better-iam": "0"}); got.status != 403 {
		t.Fatalf("csrf: %d", got.status)
	}
	forbidden := call("targets/list", obj("tenantId", "a"), map[string]string{"authorization": "Bearer member"})
	if forbidden.status != 403 {
		t.Fatalf("forbidden: %d", forbidden.status)
	}
	sameJSON(t, forbidden.body, obj("error", obj("code", "ACCESS_DENIED", "message", "Forbidden")))
	if got := call("targets/nope", obj(), nil); got.status != 404 {
		t.Fatalf("unknown route: %d", got.status)
	}
	if service.Handle(httptest.NewRequest("GET", "https://iam.test/elsewhere", nil)) != nil {
		t.Fatal("answered outside its base path")
	}
}

func TestSyncsFromIamEventsGuardsManagementAndValidatesInput(t *testing.T) {
	f := newOutboundFixture(t)
	service := f.provisioner()
	target := f.target(service, TargetInput{Name: strPtr("Events"), BaseURL: strPtr(f.origin + "/scim/v2")})
	id := target.Get("id").(string)
	events := &recordingEvents{}
	debounce := 10.0
	unsubscribe := must(service.Subscribe(events, SubscribeOptions{DebounceMs: &debounce}))
	handler := events.handlers[0]
	// Its own audit events never trigger a run; member changes do (debounced).
	ok(t, handler(bg, obj("tenantId", "a", "action", "iam:scim:SyncTarget")))
	time.Sleep(50 * time.Millisecond)
	if f.downstream.userCount() != 0 {
		t.Fatal("its own event triggered a run")
	}
	ok(t, handler(bg, obj("tenantId", "a", "action", "iam:identities:update")))
	ok(t, handler(bg, obj("tenantId", "a", "action", "iam:groups:update")))
	deadline := time.Now().Add(5 * time.Second)
	for f.downstream.userCount() != 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if f.downstream.userCount() != 2 {
		t.Fatal("the debounced sync did not run")
	}
	unsubscribe()
	if len(events.handlers) != 0 {
		t.Fatal("still subscribed")
	}

	_, err := service.SyncTarget(bg, core.CredentialInput{Token: "member"}, "a", id)
	expectCode(t, err, "ACCESS_DENIED", 403)
	if !strings.Contains(strings.Join(f.denied, ","), "iam:scim:targets:sync") {
		t.Fatalf("denied: %v", f.denied)
	}
	_, err = service.GetTarget(bg, admin, "b", id)
	expectCode(t, err, "NOT_FOUND", 404)
	for _, change := range []func(input *TargetInput){
		func(input *TargetInput) { input.BaseURL = strPtr("http://scim.example.test/v2") },
		func(input *TargetInput) { input.BaseURL = strPtr("not a url") },
		func(input *TargetInput) { input.Token = strPtr("short") },
		func(input *TargetInput) { input.Deprovision = strPtr("archive") },
		func(input *TargetInput) { input.AttributeMapping = obj("manager", "boss") },
		func(input *TargetInput) { input.Name = strPtr("") },
	} {
		input := TargetInput{TenantID: "a", Name: strPtr("X"), BaseURL: strPtr(f.origin + "/scim/v2"), Token: strPtr(testDownstreamToken)}
		change(&input)
		_, err := service.CreateTarget(bg, admin, input)
		expectCode(t, err, "INVALID_INPUT", 0)
	}

	// Disabling a target deprovisions everyone on the next run; deleting it leaves downstream accounts alone.
	must(service.UpdateTarget(bg, admin, TargetInput{TenantID: "a", TargetID: id, Enabled: flag(false)}))
	matches(t, must(service.SyncTarget(bg, admin, "a", id)), "deactivated", 2)
	ok(t, service.DeleteTarget(bg, admin, "a", id))
	if targets := must(service.ListTargets(bg, admin, "a")); len(targets) != 0 {
		t.Fatal("target listed after deletion")
	}
	if len(find(t, f.store, "provisioningLinks", nil)) != 0 || f.downstream.userCount() != 2 {
		t.Fatal("deletion state")
	}
	if _, err := NewProvisioner(ProvisioningConfig{Store: f.store, EncryptionKey: "short"}); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("short key: %v", err)
	}
}
