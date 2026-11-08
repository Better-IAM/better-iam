package scim

// Port of tests/scim-protocol.test.ts: SCIM protocol coverage.

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

type protocolFixture struct {
	t          *testing.T
	store      core.IamStore
	service    *Service
	connection connectionCredential
}

func newProtocolFixture(t *testing.T) *protocolFixture {
	t.Helper()
	store := newStore(t)
	insert(t, store, "tenants", obj("id", "a", "tenantId", "a", "name", "a", "type", "organization", "parentId", nil, "status", "active", "createdAt", wallClock()))
	service := must(NewService(Config{
		Store: store,
		Authenticate: func(_ context.Context, credential core.CredentialInput) (string, error) {
			if err := adminOnly(credential); err != nil {
				return "", err
			}
			return "administrator", nil
		},
		Authorize: func(_ context.Context, credential core.CredentialInput, _ string, _ core.ResourceRef) error {
			return adminOnly(credential)
		},
	}))
	connection := credentialOf(must(service.CreateConnection(bg, admin, CreateConnectionInput{TenantID: "a", Name: "A"})))
	return &protocolFixture{t: t, store: store, service: service, connection: connection}
}

func (f *protocolFixture) request(resource, method string, body any, headers map[string]string, token ...string) answer {
	f.t.Helper()
	connection := f.connection
	if len(token) > 0 {
		connection.token = token[0]
	}
	return scimCall(f.t, f.service, "https://iam.test", connection, resource, method, body, headers)
}

func (f *protocolFixture) create(user *core.Object) answer {
	f.t.Helper()
	created := f.request("Users", "POST", user, nil)
	if created.status != 201 {
		f.t.Fatalf("create: %d %s", created.status, show(created.body))
	}
	return created
}

func (f *protocolFixture) filter(expression string, extra ...string) answer {
	f.t.Helper()
	return f.request("Users?filter="+url.QueryEscape(expression)+strings.Join(extra, ""), "", nil, nil)
}

func (f *protocolFixture) patch(id string, operations []*core.Object, resourceType ...string) answer {
	f.t.Helper()
	kind := "Users"
	if len(resourceType) > 0 {
		kind = resourceType[0]
	}
	return f.request(kind+"/"+id, "PATCH", patchOp(operations...), nil)
}

func TestEvaluatesLogicalGroupedValuePathSubAttributeAndSchemaQualifiedFilters(t *testing.T) {
	f := newProtocolFixture(t)
	f.create(obj(
		"userName", "ada",
		"name", obj("givenName", "Ada", "familyName", "Lovelace"),
		"emails", list(obj("value", "ada@work.test", "type", "work", "primary", true), obj("value", "ada@home.test", "type", "home")),
		EnterpriseSchema, obj("department", "Research"),
	))
	f.create(obj(
		"userName", "grace",
		"active", false,
		"name", obj("givenName", "Grace", "familyName", "Hopper"),
		"emails", list(obj("value", "grace@home.test", "type", "home")),
		EnterpriseSchema, obj("department", "Navy"),
	))
	f.create(obj("userName", "linus"))
	for expression, want := range map[string]float64{
		`userName eq "ada" or userName eq "grace"`:                       2,
		`active eq true and not (userName sw "l")`:                       1,
		`emails[type eq "work" and value co "@work"]`:                    1,
		`emails.type eq "home"`:                                          2,
		`emails co "home.test"`:                                          2,
		`name.familyName sw "HOP"`:                                       1,
		EnterpriseSchema + `:department eq "research"`:                   1,
		`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "linus"`: 1,
		`emails pr`:       2,
		`not (emails pr)`: 1,
		`meta.lastModified gt "2000-01-01T00:00:00Z"`:                    3,
		`(userName eq "ada" or userName eq "grace") and active eq false`: 1,
	} {
		if got := f.filter(expression).get("totalResults"); got != want {
			t.Errorf("%s: %v, want %v", expression, got, want)
		}
	}
	// Malformed, unbounded or type-confused filters fail loudly instead of broadening the result.
	var many []string
	for i := 0; i < 70; i++ {
		many = append(many, `userName eq "`+core.NumberString(float64(i))+`"`)
	}
	for _, bad := range []string{`userName eq`, `userName xx "a"`, `(userName eq "a"`, `active gt true`, `userName co 5`, `urn:example:custom:attr eq "x"`, strings.Join(many, " or ")} {
		if got := f.filter(bad); got.status != 400 {
			t.Errorf("%s: %d", bad, got.status)
		}
	}
	if _, err := ParseScimFilter(`primary eq "true"`); err == nil {
		t.Fatal("primary requires a boolean")
	}
}

func userNames(resources any) []string {
	var names []string
	for _, item := range resources.([]any) {
		names = append(names, jsString(member(item, "userName")))
	}
	return names
}

func TestSortsProjectsAttributesAndServesPostSearch(t *testing.T) {
	f := newProtocolFixture(t)
	for _, userName := range []string{"bravo", "alpha", "charlie"} {
		f.create(obj("userName", userName, "name", obj("givenName", strings.ToUpper(userName))))
	}
	sorted := f.request("Users?sortBy=userName&sortOrder=descending", "", nil, nil)
	if got := strings.Join(userNames(sorted.get("Resources")), ","); got != "charlie,bravo,alpha" {
		t.Fatalf("sorted: %s", got)
	}
	projected := f.request("Users?sortBy=userName&attributes=userName,name.givenName&count=1", "", nil, nil)
	if projected.get("totalResults") != 3.0 {
		t.Fatalf("projected: %s", show(projected.body))
	}
	first := projected.get("Resources").([]any)[0].(*core.Object)
	keys := first.Keys()
	sort.Strings(keys)
	if strings.Join(keys, ",") != "id,name,schemas,userName" {
		t.Fatalf("keys: %v", keys)
	}
	sameJSON(t, first.Get("name"), obj("givenName", "ALPHA"))
	excluded := f.request("Users?excludedAttributes=meta,name,id", "", nil, nil)
	resource := excluded.get("Resources").([]any)[0].(*core.Object)
	if resource.Has("meta") || resource.Has("name") || !resource.Has("id") {
		t.Fatalf("excluded: %s", show(resource))
	}
	if got := f.request("Users?attributes=userName&excludedAttributes=name", "", nil, nil); got.status != 400 {
		t.Fatalf("both: %d", got.status)
	}
	if got := f.request("Users?sortOrder=sideways&sortBy=userName", "", nil, nil); got.status != 400 {
		t.Fatalf("sideways: %d", got.status)
	}
	searched := f.request("Users/.search", "POST", obj(
		"schemas", list(SearchSchema),
		"filter", `userName sw "b" or userName sw "c"`,
		"sortBy", "userName",
		"startIndex", 2,
		"count", 5,
		"attributes", list("userName"),
	), nil)
	if searched.status != 200 || searched.get("totalResults") != 2.0 || searched.get("startIndex") != 2.0 {
		t.Fatalf("search: %d %s", searched.status, show(searched.body))
	}
	page := searched.get("Resources").([]any)
	if len(page) != 1 || page[0].(*core.Object).Len() != 3 || member(page[0], "userName") != "charlie" {
		t.Fatalf("page: %s", show(page))
	}
	if got := f.request("Users/.search", "POST", obj("filter", "userName pr"), nil); got.status != 400 {
		t.Fatalf("no schema: %d", got.status)
	}
	if got := f.request("Users/.search", "", nil, nil); got.status != 405 {
		t.Fatalf("GET .search: %d", got.status)
	}
}

func TestAppliesValuePathSubAttributeAndExtensionPatchPaths(t *testing.T) {
	f := newProtocolFixture(t)
	user := f.create(obj(
		"userName", "patchy",
		"title", "Engineer",
		"emails", list(obj("value", "p@home.test", "type", "home")),
		EnterpriseSchema, obj("department", "Platform", "costCenter", "42"),
	))
	id := user.get("id").(string)
	// Seeding: add to a value path that matches nothing creates the entry with the filter's attribute.
	response := f.patch(id, []*core.Object{
		obj("op", "add", "path", `emails[type eq "work"].value`, "value", "p@work.test"),
		obj("op", "Replace", "path", "name.givenName", "value", "Pat"),
		obj("op", "replace", "path", EnterpriseSchema+":department", "value", "Security"),
		obj("op", "replace", "path", EnterpriseSchema+":manager.value", "value", "boss-id"),
		obj("op", "Replace", "path", "active", "value", "False"),
	})
	if response.status != 200 {
		t.Fatalf("patch: %d %s", response.status, show(response.body))
	}
	sameJSON(t, response.get("emails"), list(obj("value", "p@home.test", "type", "home"), obj("type", "work", "value", "p@work.test")))
	sameJSON(t, response.get("name"), obj("givenName", "Pat"))
	if response.get("active") != false || response.get("title") != "Engineer" {
		t.Fatalf("active/title: %s", show(response.body))
	}
	sameJSON(t, response.get(EnterpriseSchema), obj("department", "Security", "costCenter", "42", "manager", obj("value", "boss-id")))

	// Okta-style pathless replace with schema-qualified keys and a whole extension object.
	response = f.patch(id, []*core.Object{
		obj("op", "replace", "value", obj("active", true, EnterpriseSchema+":division", "R&D", EnterpriseSchema, obj("costCenter", "7"))),
		obj("op", "remove", "path", `emails[type eq "home"]`),
		obj("op", "replace", "path", `emails[type eq "work"].primary`, "value", "True"),
	})
	if response.status != 200 || response.get("active") != true {
		t.Fatalf("okta: %d %s", response.status, show(response.body))
	}
	sameJSON(t, response.get("emails"), list(obj("type", "work", "value", "p@work.test", "primary", true)))
	extension := response.get(EnterpriseSchema).(*core.Object)
	if extension.Get("division") != "R&D" || extension.Get("costCenter") != "7" || extension.Get("department") != "Security" {
		t.Fatalf("extension: %s", show(extension))
	}

	// Removing the last extension attribute drops the extension schema.
	response = f.patch(id, []*core.Object{obj("op", "remove", "path", EnterpriseSchema)})
	if response.object().Has(EnterpriseSchema) {
		t.Fatal("extension kept")
	}
	sameJSON(t, response.get("schemas"), list(UserSchema))

	// replace with an unmatched filter, required-attribute removal and immutable paths are rejected atomically.
	before := f.request("Users/"+id, "", nil, nil)
	for _, operations := range [][]*core.Object{
		{obj("op", "replace", "path", `emails[type eq "other"].value`, "value", "x@y.test")},
		{obj("op", "remove", "path", "userName")},
		{obj("op", "replace", "path", "meta.created", "value", "x")},
		{obj("op", "replace", "path", `name[givenName eq "x"]`, "value", obj())},
		{obj("op", "replace", "path", "displayName", "value", "Changed"), obj("op", "replace", "path", "id", "value", "x")},
	} {
		if rejected := f.patch(id, operations); rejected.status != 400 {
			t.Errorf("%s: %d", show(list(operations[0])), rejected.status)
		}
	}
	if after := f.request("Users/"+id, "", nil, nil); after.get("meta", "version") != before.get("meta", "version") {
		t.Fatal("a rejected PATCH changed the resource")
	}
}

func memberValues(members any) []string {
	var values []string
	for _, item := range members.([]any) {
		values = append(values, jsString(member(item, "value")))
	}
	return values
}

func TestRemovesListedGroupMembersAndFilteredMembersAndAnswersIfNoneMatch(t *testing.T) {
	f := newProtocolFixture(t)
	var users []string
	for _, userName := range []string{"m1", "m2", "m3"} {
		users = append(users, f.create(obj("userName", userName)).get("id").(string))
	}
	group := f.request("Groups", "POST", obj("displayName", "Team", "members", list(obj("value", users[0]), obj("value", users[1]), obj("value", users[2]))), nil)
	groupID := group.get("id").(string)
	response := f.patch(groupID, []*core.Object{obj("op", "remove", "path", "members", "value", list(obj("value", users[0])))}, "Groups")
	if got := strings.Join(memberValues(response.get("members")), ","); got != users[1]+","+users[2] {
		t.Fatalf("entra remove: %s", got)
	}
	response = f.patch(groupID, []*core.Object{obj("op", "remove", "path", `members[value eq "`+users[1]+`" or value eq "`+users[2]+`"]`)}, "Groups")
	if len(response.get("members").([]any)) != 0 || len(find(t, f.store, "groupMembers", nil)) != 0 {
		t.Fatalf("filtered remove: %s", show(response.body))
	}
	etag := response.header.Get("etag")
	if got := f.request("Groups/"+groupID, "", nil, map[string]string{"if-none-match": etag}); got.status != 304 {
		t.Fatalf("if-none-match: %d", got.status)
	}
	if got := f.request("Groups/"+groupID, "", nil, map[string]string{"if-none-match": `W/"0"`}); got.status != 200 {
		t.Fatalf("stale if-none-match: %d", got.status)
	}
	members := f.request("Groups?filter="+url.QueryEscape(`displayName eq "team"`)+"&attributes=displayName", "", nil, nil)
	sameJSON(t, members.get("Resources").([]any)[0], obj("schemas", list(GroupSchema), "id", groupID, "displayName", "Team"))
}

func TestProcessesBulkRequestsWithForwardReferencesIsolationAndFailOnErrors(t *testing.T) {
	f := newProtocolFixture(t)
	response := f.request("Bulk", "POST", obj(
		"schemas", list(BulkRequestSchema),
		"Operations", list(
			// The group references a user declared later in the request.
			obj("method", "POST", "bulkId", "g1", "path", "/Groups", "data", obj("displayName", "Bulk Group", "members", list(obj("value", "bulkId:u1")))),
			obj("method", "POST", "bulkId", "u1", "path", "/Users", "data", obj("userName", "bulk-one")),
			obj("method", "POST", "bulkId", "dup", "path", "/Users", "data", obj("userName", "bulk-one")),
			obj("method", "PATCH", "path", "/Users/bulkId:u1", "data", patchOp(obj("op", "replace", "path", "displayName", "value", "One"))),
			obj("method", "POST", "bulkId", "orphan", "path", "/Groups", "data", obj("displayName", "X", "members", list(obj("value", "bulkId:dup")))),
			obj("method", "POST", "bulkId", "ghost", "path", "/Groups", "data", obj("displayName", "Y", "members", list(obj("value", "bulkId:nope")))),
			obj("method", "DELETE", "path", "/Users/missing"),
		),
	), nil)
	if response.status != 200 {
		t.Fatalf("bulk: %d %s", response.status, show(response.body))
	}
	byBulkID := map[string]*core.Object{}
	byMethod := map[string]*core.Object{}
	for _, item := range response.get("Operations").([]any) {
		operation := item.(*core.Object)
		if bulkID, has := operation.Get("bulkId").(string); has {
			byBulkID[bulkID] = operation
		}
		byMethod[operation.Get("method").(string)] = operation
	}
	for bulkID, status := range map[string]string{"u1": "201", "g1": "201", "dup": "409", "orphan": "409", "ghost": "400"} {
		if got := byBulkID[bulkID].Get("status"); got != status {
			t.Errorf("%s: %v, want %s (%s)", bulkID, got, status, show(byBulkID[bulkID]))
		}
	}
	if byMethod["DELETE"].Get("status") != "404" || byMethod["PATCH"].Get("status") != "200" {
		t.Fatalf("delete/patch: %s", show(response.body))
	}
	groupPath := regexp.MustCompile(`^.*/Groups/`).ReplaceAllString(byBulkID["g1"].Get("location").(string), "Groups/")
	group := f.request(groupPath, "", nil, nil)
	location := strings.Split(byBulkID["u1"].Get("location").(string), "/")
	userID := location[len(location)-1]
	if got := strings.Join(memberValues(group.get("members")), ","); got != userID {
		t.Fatalf("group members: %s", got)
	}
	if got := f.request("Users/"+userID, "", nil, nil).get("displayName"); got != "One" {
		t.Fatalf("displayName: %v", got)
	}
	// Failed operations leave nothing behind.
	if count := len(find(t, f.store, "scimGroups", nil)); count != 1 {
		t.Fatalf("scimGroups: %d", count)
	}

	stopped := f.request("Bulk", "POST", obj(
		"schemas", list(BulkRequestSchema),
		"failOnErrors", 1,
		"Operations", list(
			obj("method", "POST", "bulkId", "bad", "path", "/Users", "data", obj("userName", "")),
			obj("method", "POST", "bulkId", "never", "path", "/Users", "data", obj("userName", "never")),
		),
	), nil)
	if len(stopped.get("Operations").([]any)) != 1 || f.filter(`userName eq "never"`).get("totalResults") != 0.0 {
		t.Fatalf("failOnErrors: %s", show(stopped.body))
	}

	cycle := f.request("Bulk", "POST", obj(
		"schemas", list(BulkRequestSchema),
		"Operations", list(
			obj("method", "POST", "bulkId", "x", "path", "/Groups", "data", obj("displayName", "X", "members", list(obj("value", "bulkId:y")))),
			obj("method", "POST", "bulkId", "y", "path", "/Groups", "data", obj("displayName", "Y", "members", list(obj("value", "bulkId:x")))),
		),
	), nil)
	var statuses []string
	for _, item := range cycle.get("Operations").([]any) {
		statuses = append(statuses, member(item, "status").(string))
	}
	if strings.Join(statuses, ",") != "409,409" {
		t.Fatalf("cycle: %v", statuses)
	}

	version := f.request("Bulk", "POST", obj(
		"schemas", list(BulkRequestSchema),
		"Operations", list(obj("method", "PUT", "path", "/Users/"+userID, "version", `W/"999"`, "data", obj("userName", "bulk-one"))),
	), nil)
	if got := member(version.get("Operations").([]any)[0], "status"); got != "412" {
		t.Fatalf("version: %v", got)
	}

	if got := f.request("Bulk", "POST", obj("schemas", list(BulkRequestSchema), "Operations", list()), nil); got.status != 400 {
		t.Fatalf("empty: %d", got.status)
	}
	var tooMany []any
	for i := 0; i < 101; i++ {
		tooMany = append(tooMany, obj("method", "DELETE", "path", "/Users/"+core.NumberString(float64(i))))
	}
	if got := f.request("Bulk", "POST", obj("schemas", list(BulkRequestSchema), "Operations", tooMany), nil); got.status != 413 {
		t.Fatalf("too many: %d", got.status)
	}
	if got := f.request("Bulk", "POST", obj("schemas", list(BulkRequestSchema), "Operations", list(obj("method", "DELETE", "path", "/Users/x"))), nil, "forged"); got.status != 401 {
		t.Fatalf("forged: %d", got.status)
	}
}

func TestListsConnectionsWithUsageAndRotatesTokensWithoutLosingProvisionedState(t *testing.T) {
	f := newProtocolFixture(t)
	f.create(obj("userName", "kept"))
	listed := must(f.service.ListConnections(bg, admin, "a"))
	if len(listed) != 1 {
		t.Fatalf("listed: %d", len(listed))
	}
	summary := listed[0]
	if summary.Get("id") != f.connection.id || summary.Get("name") != "A" || summary.Get("users") != 1.0 || summary.Get("groups") != 0.0 || summary.Get("revoked") != false {
		t.Fatalf("summary: %s", show(summary))
	}
	if _, isNumber := summary.Get("lastUsedAt").(float64); !isNumber {
		t.Fatal("lastUsedAt")
	}
	if strings.Contains(show(summary), f.connection.token) {
		t.Fatal("token listed")
	}
	if _, err := f.service.ListConnections(bg, core.CredentialInput{Token: "forged"}, "a"); err == nil || err.(*core.IamError).Status != 403 {
		t.Fatalf("forged: %v", err)
	}
	hour := 3600.0
	rotated := must(f.service.RotateToken(bg, admin, RotateTokenInput{TenantID: "a", ConnectionID: f.connection.id, ExpiresIn: &hour}))
	if rotated.Get("token") == f.connection.token {
		t.Fatal("token unchanged")
	}
	if got := f.request("Users", "", nil, nil); got.status != 401 {
		t.Fatalf("old token: %d", got.status)
	}
	if got := f.request("Users", "", nil, nil, rotated.Get("token").(string)); got.get("totalResults") != 1.0 {
		t.Fatalf("new token: %s", show(got.body))
	}
	if count := len(find(t, f.store, "audit", obj("action", "iam:scim:RotateToken"))); count != 1 {
		t.Fatalf("audit: %d", count)
	}
	ok(t, f.service.RevokeConnection(bg, admin, "a", f.connection.id))
	_, err := f.service.RotateToken(bg, admin, RotateTokenInput{TenantID: "a", ConnectionID: f.connection.id})
	expectCode(t, err, "CONFLICT", 409)
}
