package server

// License tests, after tests/licenses.test.ts, tests/licenses-lifecycle.test.ts and tests/licenses-hardening.test.ts:
// products (validation, platform and tenant scope, shadowing, retirement), pools and seats (seniority, capacity cuts,
// terms, the waiting list), group claims, bulk assignment, limits, settings, self-service, the reconcile and reclaim
// jobs, waiting-list email, batched group reconciliation, and `principal.licenses`. Organizations and people are seeded
// in the store (directoryFixture); the licenses and groups API groups are called through iam.API.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const licenseHour = 3_600_000

type licenseFixture struct {
	*directoryFixture
	t        *testing.T
	tenantID string
	owner    core.CredentialInput
	ownerID  string
	pro      *core.Object
	alice    *core.Object
	bob      *core.Object
	carol    *core.Object
	creds    map[string]core.CredentialInput
	names    map[string]string
}

// licCall invokes an API method with a body.
func licCall[I, O any](f *licenseFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, pairs ...any) (*core.Object, error) {
	out, err := method(f.ctx, credential, Input[I](body(pairs...)))
	if err != nil {
		return nil, err
	}
	object, _ := out.Value.(*core.Object)
	return object, nil
}

// licMust is licCall that fails the test on an error.
func licMust[I, O any](f *licenseFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, pairs ...any) *core.Object {
	f.t.Helper()
	object, err := licCall(f, method, credential, pairs...)
	if err != nil {
		f.t.Fatalf("unexpected error: %v", err)
	}
	return object
}

func licCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", code)
	}
	if known := iamError(t, err); known.Code != code {
		t.Fatalf("expected %s, got %s: %s", code, known.Code, known.Message)
	}
}

// licenseScenario is Acme with a product "pro" (featureKeys sso, exports) and three people.
func licenseScenario(t *testing.T, mutate func(options *BetterIamOptions)) *licenseFixture {
	t.Helper()
	f := &licenseFixture{directoryFixture: newDirectoryFixture(t, mutate), t: t, creds: map[string]core.CredentialInput{},
		names: map[string]string{}}
	f.tenantID, f.owner = f.organization("Acme", "owner@acme.test")
	f.ownerID = jsString(f.find("identities", core.NewObject("tenantId", f.tenantID, "owner", true))[0].Get("id"))
	f.pro = licMust(f, f.iam.API.Licenses.CreateProduct, f.owner, "tenantId", f.tenantID, "key", "pro", "name", "Pro",
		"description", "Everything in Pro", "featureKeys", items("sso", "exports"))
	f.alice = f.member("alice")
	f.bob = f.member("bob")
	f.carol = f.member("carol")
	return f
}

// member creates a person of Acme, remembering their name and credential.
func (f *licenseFixture) member(name string, members ...any) *core.Object {
	f.t.Helper()
	identity, credential := f.person(f.tenantID, name, members...)
	f.names[jsString(identity.Get("id"))] = name
	f.creds[name] = credential
	return identity
}

func licID(record *core.Object) string { return jsString(record.Get("id")) }

// assign moves the clock a second, then assigns the product (pro by default) to a person.
func (f *licenseFixture) assign(identityID string, productID ...string) (*core.Object, error) {
	f.advance(1000)
	product := licID(f.pro)
	if len(productID) > 0 {
		product = productID[0]
	}
	return licCall(f, f.iam.API.Licenses.Assign, f.owner, "tenantId", f.tenantID, "productId", product,
		"subjectType", "identity", "subjectId", identityID)
}

func (f *licenseFixture) mustAssign(identityID string, productID ...string) *core.Object {
	f.t.Helper()
	result, err := f.assign(identityID, productID...)
	if err != nil {
		f.t.Fatalf("assign: %v", err)
	}
	return result
}

// seats is the product's seats as "name status #position".
func (f *licenseFixture) seats(productID ...string) []string {
	f.t.Helper()
	product := licID(f.pro)
	if len(productID) > 0 {
		product = productID[0]
	}
	listed := licMust(f, f.iam.API.Licenses.ListSeats, f.owner, "tenantId", f.tenantID, "productId", product)
	out := []string{}
	for _, item := range listed.Get("seats").([]any) {
		seat := item.(*core.Object)
		text := jsString(seat.Get("identityName")) + " " + jsString(seat.Get("status"))
		if !isUndefined(seat.Get("position")) {
			text += " #" + jsString(seat.Get("position"))
		}
		out = append(out, text)
	}
	return out
}

// changes is seat changes as "name from->to".
func (f *licenseFixture) changes(list any) []string {
	out := []string{}
	items, _ := list.([]any)
	for _, item := range items {
		change := item.(*core.Object)
		out = append(out, f.names[jsString(change.Get("identityId"))]+" "+jsString(change.Get("from"))+"->"+jsString(change.Get("to")))
	}
	return out
}

// trail is the audit events of a tenant whose action starts with prefix, oldest first.
func (f *licenseFixture) trail(tenantID, prefix string) []*core.Object {
	f.t.Helper()
	events := []*core.Object{}
	for _, event := range f.find("audit", core.NewObject("tenantId", tenantID)) {
		if strings.HasPrefix(jsString(event.Get("action")), prefix) {
			events = append(events, event)
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		return jsNumber(coalesce(events[i].Get("sequence"), 0.0)) < jsNumber(coalesce(events[j].Get("sequence"), 0.0))
	})
	return events
}

func licStrings(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if stringify(stringsOf(got)) != stringify(stringsOf(want)) {
		t.Errorf("%s = %v, want %v", label, got, want)
	}
}

func licSorted(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func licActions(events []*core.Object) []string { return pluck(events, "action") }

// project seeds a project under Acme with an owner and returns its ID, owner credential and owner ID.
func (f *licenseFixture) project(name string) (string, core.CredentialInput, string) {
	f.t.Helper()
	tenantID, credential := f.organization(name, strings.ToLower(name)+"@acme.test", "parentId", f.tenantID, "type", "project")
	ownerID := jsString(f.find("identities", core.NewObject("tenantId", tenantID, "owner", true))[0].Get("id"))
	return tenantID, credential, ownerID
}

func TestLicenseProducts(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses := f.iam.API.Licenses
	expectJSON(t, "pro", f.pro, stringify(core.NewObject(
		"id", f.pro.Get("id"), "key", "pro", "name", "Pro", "description", "Everything in Pro",
		"featureKeys", items("exports", "sso"), "status", "active", "scope", "tenant", "definedBy", f.tenantID,
		"definedHere", true, "shadowed", false, "createdAt", f.pro.Get("createdAt"), "createdBy", f.ownerID,
		"updatedAt", f.pro.Get("createdAt"), "updatedBy", f.ownerID,
	)))
	create := func(pairs ...any) (*core.Object, error) {
		input := body("tenantId", f.tenantID, "key", "team", "name", "Team").Assign(body(pairs...))
		out, err := licenses.CreateProduct(f.ctx, f.owner, Input[apitypes.LicensesCreateProductInput](input))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	for _, key := range []any{"Pro", "-pro", "pro plan", "", strings.Repeat("x", 65), "pro/plan", 7.0} {
		_, err := create("key", key)
		licCode(t, err, "INVALID_INPUT")
	}
	many := make([]any, 51)
	for index := range many {
		many[index] = fmt.Sprintf("feature-%d", index)
	}
	for _, pairs := range [][]any{
		{"name", " "}, {"name", strings.Repeat("x", 101)}, {"description", strings.Repeat("x", 513)},
		{"featureKeys", items("Bad Key")}, {"featureKeys", "sso"}, {"featureKeys", many},
	} {
		_, err := create(pairs...)
		licCode(t, err, "INVALID_INPUT")
	}
	_, err := create("key", "pro")
	licCode(t, err, "CONFLICT")
	expectStatus(t, err, 409)
	team, err := create("key", "team.v2_b-1")
	if err != nil {
		t.Fatal(err)
	}
	if team.Get("key") != "team.v2_b-1" || stringify(team.Get("featureKeys")) != "[]" || team.Has("description") {
		t.Fatalf("team = %s", stringify(team))
	}

	// The key never changes; the name, description (null clears) and feature keys do.
	f.advance(1000)
	renamed := licMust(f, licenses.UpdateProduct, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro),
		"name", "Pro plan", "description", nil, "featureKeys", items("sso", "sso", "audit-log"))
	if renamed.Get("key") != "pro" || renamed.Get("name") != "Pro plan" || stringify(renamed.Get("featureKeys")) != `["audit-log","sso"]` ||
		renamed.Get("updatedAt") != f.now() || renamed.Get("createdAt") != f.pro.Get("createdAt") || renamed.Has("description") {
		t.Fatalf("renamed = %s", stringify(renamed))
	}
	_, err = licCall(f, licenses.UpdateProduct, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro))
	expectError(t, err, "INVALID_INPUT", "Nothing to update")
	_, err = licCall(f, licenses.UpdateProduct, f.owner, "tenantId", f.tenantID, "productId", "missing", "name", "x")
	licCode(t, err, "NOT_FOUND")
	_, err = licCall(f, licenses.UpdateProduct, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "featureKeys", items("Nope"))
	licCode(t, err, "INVALID_INPUT")
	got := licMust(f, licenses.GetProduct, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro))
	expectJSON(t, "getProduct", got, stringify(renamed))
	_, err = licCall(f, licenses.GetProduct, f.owner, "tenantId", f.tenantID, "productId", "missing")
	licCode(t, err, "NOT_FOUND")
	expectStatus(t, err, 404)

	listed := licMust(f, licenses.ListProducts, f.owner, "tenantId", f.tenantID)
	if listed.Get("tenantId") != f.tenantID {
		t.Fatalf("listed tenant = %v", listed.Get("tenantId"))
	}
	licStrings(t, "keys", pluck(answerListOf(listed, "products"), "key"), "pro", "team.v2_b-1")
	retired := licMust(f, licenses.ListProducts, f.owner, "tenantId", f.tenantID, "status", "retired")
	expectJSON(t, "retired", retired.Get("products"), "[]")
	_, err = licCall(f, licenses.ListProducts, f.owner, "tenantId", f.tenantID, "status", "gone")
	licCode(t, err, "INVALID_INPUT")

	events := f.trail(f.tenantID, "license:")
	licStrings(t, "actions", licActions(events), "license:product-create", "license:product-create", "license:product-update")
	if events[0].Get("actorId") != f.ownerID || events[0].Get("resourceId") != "licenses/products/"+licID(f.pro) {
		t.Fatalf("event = %s", stringify(events[0]))
	}
	expectJSON(t, "create metadata", events[0].Get("metadata"), stringify(core.NewObject("productId", f.pro.Get("id"),
		"key", "pro", "name", "Pro", "description", "Everything in Pro", "featureKeys", items("exports", "sso"), "status", "active")))
	metadata := events[2].Get("metadata").(*core.Object)
	before, after := metadata.Get("before").(*core.Object), metadata.Get("after").(*core.Object)
	if before.Get("name") != "Pro" || before.Get("description") != "Everything in Pro" || after.Get("name") != "Pro plan" ||
		after.Get("description") != nil || stringify(after.Get("featureKeys")) != `["audit-log","sso"]` {
		t.Fatalf("update metadata = %s", stringify(metadata))
	}
}

// answerListOf is the objects of a list member.
func answerListOf(object *core.Object, key string) []*core.Object {
	list, _ := object.Get(key).([]any)
	out := make([]*core.Object, len(list))
	for index, item := range list {
		out[index], _ = item.(*core.Object)
	}
	return out
}

func TestLicenseRecentAuthentication(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses := f.iam.API.Licenses
	f.advance(6 * 60_000)
	_, err := licCall(f, licenses.CreateProduct, f.owner, "tenantId", f.tenantID, "key", "team", "name", "Team")
	licCode(t, err, "RECENT_AUTH_REQUIRED")
	_, err = licCall(f, licenses.RetireProduct, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro))
	licCode(t, err, "RECENT_AUTH_REQUIRED")
	// Renaming does not.
	renamed := licMust(f, licenses.UpdateProduct, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "name", "Pro 2")
	if renamed.Get("name") != "Pro 2" {
		t.Fatalf("renamed = %s", stringify(renamed))
	}
	fresh := f.ownerSignIn(f.tenantID)
	if team := licMust(f, licenses.CreateProduct, fresh, "tenantId", f.tenantID, "key", "team", "name", "Team"); team.Get("key") != "team" {
		t.Fatalf("team = %s", stringify(team))
	}
	retired := licMust(f, licenses.RetireProduct, fresh, "tenantId", f.tenantID, "productId", licID(f.pro))
	if member(retired.Get("product"), "status") != "retired" {
		t.Fatalf("retired = %s", stringify(retired))
	}
}

func TestLicensePlatformAndTenantProducts(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses := f.iam.API.Licenses
	rootID := f.rootTenantID()
	suite := licMust(f, licenses.CreateProduct, f.rootCred, "tenantId", rootID, "key", "suite", "name", "Suite", "featureKeys", items("suite"))
	if suite.Get("scope") != "platform" || suite.Get("definedBy") != rootID || suite.Get("definedHere") != true {
		t.Fatalf("suite = %s", stringify(suite))
	}
	products := answerListOf(licMust(f, licenses.ListProducts, f.owner, "tenantId", f.tenantID), "products")
	if len(products) != 2 || products[0].Get("key") != "pro" || products[0].Get("definedHere") != true ||
		products[1].Get("key") != "suite" || products[1].Get("scope") != "platform" || products[1].Get("definedHere") != false ||
		products[1].Get("shadowed") != false || products[1].Get("definedBy") != rootID {
		t.Fatalf("products = %s", stringify(products))
	}
	if got := licMust(f, licenses.GetProduct, f.owner, "tenantId", f.tenantID, "productId", licID(suite)); got.Get("definedHere") != false {
		t.Fatalf("suite view = %s", stringify(got))
	}
	// Only root administrators define and change platform products; tenants never repeat their keys.
	_, err := licCall(f, licenses.CreateProduct, f.owner, "tenantId", rootID, "key", "mine", "name", "Mine")
	licCode(t, err, "ACCESS_DENIED")
	_, err = licCall(f, licenses.CreateProduct, f.owner, "tenantId", f.tenantID, "key", "suite", "name", "Suite copy")
	expectError(t, err, "CONFLICT", "A platform license product already uses this key")
	_, err = licCall(f, licenses.UpdateProduct, f.owner, "tenantId", f.tenantID, "productId", licID(suite), "name", "Mine now")
	licCode(t, err, "INVALID_INPUT")
	_, err = licCall(f, licenses.RetireProduct, f.owner, "tenantId", f.tenantID, "productId", licID(suite))
	licCode(t, err, "INVALID_INPUT")
	_, err = licCall(f, licenses.UpdateProduct, f.owner, "tenantId", rootID, "productId", licID(suite), "name", "Mine now")
	licCode(t, err, "ACCESS_DENIED")

	// A project sees Acme's products and the platform's, and may not repeat an enclosing key.
	apolloID, apollo, _ := f.project("Apollo")
	seen := answerListOf(licMust(f, licenses.ListProducts, apollo, "tenantId", apolloID), "products")
	if len(seen) != 2 || seen[0].Get("key") != "pro" || seen[0].Get("scope") != "tenant" || seen[0].Get("definedBy") != f.tenantID ||
		seen[1].Get("key") != "suite" || seen[1].Get("scope") != "platform" {
		t.Fatalf("project products = %s", stringify(seen))
	}
	_, err = licCall(f, licenses.CreateProduct, apollo, "tenantId", apolloID, "key", "pro", "name", "Pro copy")
	expectError(t, err, "CONFLICT", "An enclosing tenant already defines a license product with this key")
	addon := licMust(f, licenses.CreateProduct, apollo, "tenantId", apolloID, "key", "apollo-addon", "name", "Apollo add-on")
	licStrings(t, "acme keys", pluck(answerListOf(licMust(f, licenses.ListProducts, f.owner, "tenantId", f.tenantID), "products"), "key"), "pro", "suite")
	_, err = licCall(f, licenses.GetProduct, f.owner, "tenantId", f.tenantID, "productId", licID(addon))
	licCode(t, err, "NOT_FOUND")

	// The platform may later define a key a tenant already uses: the tenant's product is then shadowed.
	platformPro := licMust(f, licenses.CreateProduct, f.rootCred, "tenantId", rootID, "key", "pro", "name", "Platform Pro")
	listed := answerListOf(licMust(f, licenses.ListProducts, f.owner, "tenantId", f.tenantID), "products")
	pairs := []string{}
	for _, product := range listed {
		pairs = append(pairs, jsString(product.Get("id"))+" "+jsString(product.Get("shadowed")))
	}
	licStrings(t, "shadowing", pairs, licID(platformPro)+" false", licID(f.pro)+" true", licID(suite)+" false")
	if got := licMust(f, licenses.GetProduct, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro)); got.Get("shadowed") != true {
		t.Fatalf("pro view = %s", stringify(got))
	}
	// Seats of the shadowed product grant nothing: neither principal.licenses nor mine.
	licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 5.0)
	f.mustAssign(licID(f.alice))
	if keys := must(f.iam.Licenses.Products(f.ctx, licID(f.alice), f.tenantID)); len(keys) != 0 {
		t.Fatalf("shadowed products = %v", keys)
	}
	mine := licMust(f, licenses.Mine, f.creds["alice"], "tenantId", f.tenantID)
	expectJSON(t, "mine", mine.Get("licenses"), "[]")
}

func TestLicenseRetireProduct(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses := f.iam.API.Licenses
	rootID := f.rootTenantID()
	apolloID, apollo, apolloOwner := f.project("Apollo")
	f.names[apolloOwner] = "apollo"
	suite := licMust(f, licenses.CreateProduct, f.rootCred, "tenantId", rootID, "key", "suite", "name", "Suite", "featureKeys", items("suite"))
	acmePool := licMust(f, licenses.AddPool, f.rootCred, "tenantId", f.tenantID, "productId", licID(suite), "quantity", 2.0)
	licMust(f, licenses.AddPool, f.rootCred, "tenantId", apolloID, "productId", licID(suite), "quantity", 1.0)
	licMust(f, licenses.AssignMany, f.owner, "tenantId", f.tenantID, "productId", licID(suite), "identityIds", items(licID(f.alice), licID(f.bob)))
	held := licMust(f, licenses.Assign, apollo, "tenantId", apolloID, "productId", licID(suite), "subjectType", "identity", "subjectId", apolloOwner)
	licStrings(t, "apollo seat", f.changes(held.Get("seats")), "apollo none->active")

	retired := licMust(f, licenses.RetireProduct, f.rootCred, "tenantId", rootID, "productId", licID(suite))
	if member(retired.Get("product"), "status") != "retired" || member(retired.Get("product"), "key") != "suite" {
		t.Fatalf("retired = %s", stringify(retired))
	}
	where := []string{}
	for _, item := range retired.Get("seats").([]any) {
		change := item.(*core.Object)
		label := "apollo"
		if change.Get("tenantId") == f.tenantID {
			label = "acme"
		}
		where = append(where, label+" "+jsString(change.Get("to")))
	}
	licStrings(t, "released", licSorted(where), "acme none", "acme none", "apollo none")
	expectJSON(t, "acme seats", licMust(f, licenses.ListSeats, f.owner, "tenantId", f.tenantID).Get("seats"), "[]")

	// Retired is final: no seats, no new assignments or pool changes, and the key stays taken.
	_, err := licCall(f, licenses.RetireProduct, f.rootCred, "tenantId", rootID, "productId", licID(suite))
	licCode(t, err, "INVALID_TRANSITION")
	_, err = licCall(f, licenses.Assign, f.owner, "tenantId", f.tenantID, "productId", licID(suite), "subjectType", "identity", "subjectId", licID(f.carol))
	licCode(t, err, "INVALID_TRANSITION")
	_, err = licCall(f, licenses.AssignMany, f.owner, "tenantId", f.tenantID, "productId", licID(suite), "identityIds", items(licID(f.carol)))
	licCode(t, err, "INVALID_TRANSITION")
	_, err = licCall(f, licenses.AddPool, f.rootCred, "tenantId", f.tenantID, "productId", licID(suite), "quantity", 1.0)
	licCode(t, err, "INVALID_TRANSITION")
	poolID := jsString(member(acmePool.Get("pool"), "id"))
	_, err = licCall(f, licenses.UpdatePool, f.rootCred, "tenantId", f.tenantID, "poolId", poolID, "quantity", 5.0)
	licCode(t, err, "INVALID_TRANSITION")
	_, err = licCall(f, licenses.RemovePool, f.rootCred, "tenantId", f.tenantID, "poolId", poolID)
	licCode(t, err, "INVALID_TRANSITION")
	_, err = licCall(f, licenses.CreateProduct, f.rootCred, "tenantId", rootID, "key", "suite", "name", "Again")
	licCode(t, err, "CONFLICT")
	licStrings(t, "retired keys", pluck(answerListOf(licMust(f, licenses.ListProducts, f.owner, "tenantId", f.tenantID, "status", "retired"), "products"), "key"), "suite")
	var usage *core.Object
	for _, product := range answerListOf(licMust(f, licenses.Usage, f.owner, "tenantId", f.tenantID), "products") {
		if product.Get("key") == "suite" {
			usage = product
		}
	}
	if usage == nil || usage.Get("status") != "retired" || usage.Get("capacity") != 2.0 || usage.Get("active") != 0.0 ||
		usage.Get("waiting") != 0.0 || usage.Get("assignments") != 2.0 {
		t.Fatalf("usage = %s", stringify(usage))
	}
	// The safety net never brings seats back; unassigning still tidies up.
	must(f.iam.Licenses.Reconcile(f.ctx, nil))
	expectJSON(t, "acme seats", licMust(f, licenses.ListSeats, f.owner, "tenantId", f.tenantID).Get("seats"), "[]")
	unassigned := licMust(f, licenses.Unassign, f.owner, "tenantId", f.tenantID, "productId", licID(suite), "subjectType", "identity", "subjectId", licID(f.alice))
	expectJSON(t, "unassign", unassigned, `{"removed":true,"seats":[]}`)
	mine := licMust(f, licenses.Mine, f.creds["alice"], "tenantId", f.tenantID)
	if stringify(mine.Get("licenses")) != "[]" || stringify(mine.Get("featureKeys")) != "[]" || stringify(mine.Get("allFeatureKeys")) != "[]" {
		t.Fatalf("mine = %s", stringify(mine))
	}

	// Retirement is audited in the defining tenant, each release where the seat was.
	retire := f.trail(rootID, "license:product-retire")
	expectJSON(t, "retire metadata", retire[0].Get("metadata"), stringify(core.NewObject("productId", suite.Get("id"), "key", "suite",
		"releasedSeats", 3.0, "tenants", 2.0)))
	releases := f.trail(apolloID, "license:seat-release")
	if len(releases) != 1 || releases[0].Get("resourceId") != apolloOwner || member(releases[0].Get("metadata"), "reason") != "product-retired" {
		t.Fatalf("apollo releases = %s", stringify(releases))
	}
}

func TestLicenseSeniorityAndCapacity(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses := f.iam.API.Licenses
	first := f.mustAssign(licID(f.alice))
	expectJSON(t, "assignment", first.Get("assignment"), stringify(core.NewObject(
		"id", member(first.Get("assignment"), "id"), "tenantId", f.tenantID, "productId", f.pro.Get("id"), "productKey", "pro",
		"productName", "Pro", "subjectType", "identity", "subjectId", f.alice.Get("id"), "subjectName", "alice",
		"subjectEmail", "alice@acme.test", "assignedBy", f.ownerID, "assignedAt", f.now(),
	)))
	// No capacity yet: the claim waits.
	licStrings(t, "first", f.changes(first.Get("seats")), "alice none->waiting")
	initial := licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 2.0, "note", "Initial purchase")
	expectJSON(t, "pool", initial.Get("pool"), stringify(core.NewObject(
		"id", member(initial.Get("pool"), "id"), "tenantId", f.tenantID, "tenantName", "Acme", "productId", f.pro.Get("id"),
		"productKey", "pro", "productName", "Pro", "quantity", 2.0, "note", "Initial purchase", "source", "manual", "live", true,
		"createdAt", f.now(), "createdBy", f.ownerID,
	)))
	initialID := jsString(member(initial.Get("pool"), "id"))
	licStrings(t, "initial", f.changes(initial.Get("seats")), "alice waiting->active")
	licStrings(t, "bob", f.changes(f.mustAssign(licID(f.bob)).Get("seats")), "bob none->active")
	licStrings(t, "carol", f.changes(f.mustAssign(licID(f.carol)).Get("seats")), "carol none->waiting")
	licStrings(t, "seats", f.seats(), "alice active", "bob active", "carol waiting #1")
	expectJSON(t, "usage", licMust(f, licenses.Usage, f.owner, "tenantId", f.tenantID), stringify(core.NewObject(
		"tenantId", f.tenantID, "products", items(core.NewObject(
			"productId", f.pro.Get("id"), "key", "pro", "name", "Pro", "scope", "tenant", "status", "active", "capacity", 2.0,
			"active", 2.0, "waiting", 1.0, "available", 0.0, "pools", 1.0, "assignments", 3.0, "reclaimable", 0.0,
			"reclaimableThroughGroups", 0.0,
		)),
	)))

	// A capacity cut moves the newest active seat to the head of the waiting list; it is never an error.
	f.advance(1000)
	cut := licMust(f, licenses.UpdatePool, f.owner, "tenantId", f.tenantID, "poolId", initialID, "quantity", 1.0)
	if pool := cut.Get("pool").(*core.Object); pool.Get("quantity") != 1.0 || pool.Get("updatedAt") != f.now() || pool.Get("updatedBy") != f.ownerID {
		t.Fatalf("cut = %s", stringify(pool))
	}
	licStrings(t, "cut", f.changes(cut.Get("seats")), "bob active->waiting")
	licStrings(t, "seats", f.seats(), "alice active", "bob waiting #1", "carol waiting #2")
	waiting := licMust(f, licenses.ListSeats, f.owner, "tenantId", f.tenantID, "status", "waiting")
	if waiting.Get("total") != 2.0 {
		t.Fatalf("waiting = %s", stringify(waiting))
	}
	paged := licMust(f, licenses.ListSeats, f.owner, "tenantId", f.tenantID, "status", "waiting", "limit", 1.0, "offset", 1.0)
	if pagedSeats := answerListOf(paged, "seats"); paged.Get("total") != 2.0 || len(pagedSeats) != 1 || pagedSeats[0].Get("identityName") != "carol" || pagedSeats[0].Get("position") != 2.0 {
		t.Fatalf("paged = %s", stringify(paged))
	}
	expectJSON(t, "alice waiting", licMust(f, licenses.ListSeats, f.owner, "tenantId", f.tenantID, "identityId", licID(f.alice), "status", "waiting"), `{"seats":[],"total":0}`)
	for _, pairs := range [][]any{{"status", "gone"}, {"limit", 0.0}, {"limit", 1001.0}, {"offset", -1.0}} {
		_, err := licCall(f, licenses.ListSeats, f.owner, append([]any{"tenantId", f.tenantID}, pairs...)...)
		licCode(t, err, "INVALID_INPUT")
	}

	// A pool with an end: waiting people take its seats at once and keep them until the term ends.
	f.advance(1000)
	trial := licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 5.0, "endsAt", f.now()+licenseHour, "note", "Trial")
	if pool := trial.Get("pool").(*core.Object); pool.Get("endsAt") != f.now()+licenseHour || pool.Get("live") != true {
		t.Fatalf("trial = %s", stringify(pool))
	}
	trialID := jsString(member(trial.Get("pool"), "id"))
	licStrings(t, "trial", f.changes(trial.Get("seats")), "bob waiting->active", "carol waiting->active")
	licStrings(t, "notes", pluck(answerListOf(licMust(f, licenses.ListPools, f.owner, "tenantId", f.tenantID), "pools"), "note"), "Trial", "Initial purchase")
	f.advance(2 * licenseHour)
	expectJSON(t, "job", must(f.iam.Licenses.Reconcile(f.ctx, nil)), `{"tenants":1,"activated":0,"waiting":2,"released":0,"failedTenants":[]}`)
	licStrings(t, "seats", f.seats(), "alice active", "bob waiting #1", "carol waiting #2")
	expectJSON(t, "job again", must(f.iam.Licenses.Reconcile(f.ctx, core.NewObject("tenantId", f.tenantID))), `{"tenants":1,"activated":0,"waiting":0,"released":0,"failedTenants":[]}`)
	pools := licMust(f, licenses.ListPools, f.owner, "tenantId", f.tenantID)
	if pools.Get("total") != 1.0 || answerListOf(pools, "pools")[0].Get("note") != "Initial purchase" {
		t.Fatalf("pools = %s", stringify(pools))
	}
	everything := answerListOf(licMust(f, licenses.ListPools, f.owner, "tenantId", f.tenantID, "includeEnded", true), "pools")
	if len(everything) != 2 || everything[0].Get("note") != "Trial" || everything[0].Get("live") != false || everything[1].Get("live") != true {
		t.Fatalf("everything = %s", stringify(everything))
	}

	// An ended pool can be reopened (null clears the end) and removed.
	reopened := licMust(f, licenses.UpdatePool, f.owner, "tenantId", f.tenantID, "poolId", trialID, "endsAt", nil, "note", nil)
	if pool := reopened.Get("pool").(*core.Object); pool.Has("endsAt") || pool.Has("note") || pool.Get("live") != true {
		t.Fatalf("reopened = %s", stringify(pool))
	}
	licStrings(t, "reopened", f.changes(reopened.Get("seats")), "bob waiting->active", "carol waiting->active")
	removed := licMust(f, licenses.RemovePool, f.owner, "tenantId", f.tenantID, "poolId", trialID)
	if removed.Get("removed") != true {
		t.Fatalf("removed = %s", stringify(removed))
	}
	licStrings(t, "removed", f.changes(removed.Get("seats")), "bob active->waiting", "carol active->waiting")
	_, err := licCall(f, licenses.RemovePool, f.owner, "tenantId", f.tenantID, "poolId", trialID)
	licCode(t, err, "NOT_FOUND")

	// A pool that starts later adds nothing until it starts.
	later := licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 1.0, "startsAt", f.now()+licenseHour)
	if member(later.Get("pool"), "live") != false || stringify(later.Get("seats")) != "[]" {
		t.Fatalf("later = %s", stringify(later))
	}
	if usage := answerListOf(licMust(f, licenses.Usage, f.owner, "tenantId", f.tenantID), "products")[0]; usage.Get("capacity") != 1.0 || usage.Get("pools") != 1.0 {
		t.Fatalf("usage = %s", stringify(usage))
	}
	f.advance(2 * licenseHour)
	if job := must(f.iam.Licenses.Reconcile(f.ctx, nil)); job.Get("activated") != 1.0 {
		t.Fatalf("job = %s", stringify(job))
	}
	licStrings(t, "seats", f.seats(), "alice active", "bob active", "carol waiting #1")

	poolActions := []string{}
	for _, action := range licActions(f.trail(f.tenantID, "license:pool-")) {
		poolActions = append(poolActions, action)
	}
	licStrings(t, "pool actions", poolActions, "license:pool-add", "license:pool-update", "license:pool-add", "license:pool-update", "license:pool-remove", "license:pool-add")
	update := f.trail(f.tenantID, "license:pool-update")[0]
	updateMeta := update.Get("metadata").(*core.Object)
	if update.Get("resourceId") != "licenses/pools/"+initialID || member(updateMeta.Get("before"), "poolId") != initialID ||
		member(updateMeta.Get("before"), "quantity") != 2.0 || member(updateMeta.Get("before"), "productKey") != "pro" || member(updateMeta.Get("after"), "quantity") != 1.0 {
		t.Fatalf("pool update = %s", stringify(update))
	}
	scheduled := []string{}
	for _, event := range f.trail(f.tenantID, "license:seat-waiting") {
		if event.Get("actorId") == "deployment-operator" {
			scheduled = append(scheduled, jsString(event.Get("resourceId"))+" "+jsString(member(event.Get("metadata"), "reason")))
		}
	}
	licStrings(t, "scheduled", scheduled, licID(f.bob)+" schedule", licID(f.carol)+" schedule")
}

func TestLicenseSameMillisecondClaims(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses := f.iam.API.Licenses
	licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 1.0)
	// Assign in descending ID order without moving the clock, so identity order alone would reverse seniority.
	people := []string{licID(f.alice), licID(f.bob), licID(f.carol)}
	sort.Sort(sort.Reverse(sort.StringSlice(people)))
	assign := func(identityID string) *core.Object {
		return licMust(f, licenses.Assign, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "subjectType", "identity", "subjectId", identityID)
	}
	for index, want := range []string{"active", "waiting", "waiting"} {
		seats := answerListOf(assign(people[index]), "seats")
		if len(seats) != 1 || seats[0].Get("identityId") != people[index] || seats[0].Get("to") != want {
			t.Fatalf("assign %d = %s", index, stringify(seats))
		}
	}
	holders := func() []string {
		out := []string{}
		for _, seat := range answerListOf(licMust(f, licenses.ListSeats, f.owner, "tenantId", f.tenantID), "seats") {
			out = append(out, jsString(seat.Get("identityId"))+" "+jsString(seat.Get("status"))+" "+jsString(coalesce(seat.Get("position"), nil)))
		}
		return out
	}
	expected := []string{people[0] + " active null", people[2] + " waiting 1", people[1] + " waiting 2"}
	licStrings(t, "holders", holders(), expected...)
	// Later runs keep it that way, and the next free seat goes to the head of the waiting list.
	if job := must(f.iam.Licenses.Reconcile(f.ctx, nil)); job.Get("activated") != 0.0 || job.Get("waiting") != 0.0 {
		t.Fatalf("job = %s", stringify(job))
	}
	licStrings(t, "holders", holders(), expected...)
	more := answerListOf(licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 1.0), "seats")
	if len(more) != 1 || more[0].Get("identityId") != people[2] || more[0].Get("from") != "waiting" || more[0].Get("to") != "active" {
		t.Fatalf("more = %s", stringify(more))
	}
}

func TestLicensePoolValidation(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses := f.iam.API.Licenses
	add := func(pairs ...any) (*core.Object, error) {
		input := body("tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 1.0).Assign(body(pairs...))
		out, err := licenses.AddPool(f.ctx, f.owner, Input[apitypes.LicensesAddPoolInput](input))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	for _, quantity := range []any{0.0, -1.0, 1.5, 1_000_001.0, "3"} {
		_, err := add("quantity", quantity)
		licCode(t, err, "INVALID_INPUT")
	}
	for _, pairs := range [][]any{
		{"endsAt", f.now() - 1}, {"endsAt", f.now()}, {"startsAt", f.now() + 2*licenseHour, "endsAt", f.now() + licenseHour},
		{"startsAt", -5.0}, {"note", strings.Repeat("x", 513)},
	} {
		_, err := add(pairs...)
		licCode(t, err, "INVALID_INPUT")
	}
	_, err := add("subscriptionId", "missing")
	licCode(t, err, "NOT_FOUND")
	_, err = add("productId", "missing")
	licCode(t, err, "NOT_FOUND")
	if big, err := add("quantity", 1_000_000.0); err != nil || member(big.Get("pool"), "quantity") != 1_000_000.0 {
		t.Fatalf("big pool: %v %s", err, stringify(big))
	}
	later, err := add("startsAt", f.now()+licenseHour, "endsAt", f.now()+3*licenseHour)
	if err != nil {
		t.Fatal(err)
	}
	laterID := jsString(member(later.Get("pool"), "id"))
	_, err = licCall(f, licenses.UpdatePool, f.owner, "tenantId", f.tenantID, "poolId", laterID)
	expectError(t, err, "INVALID_INPUT", "Nothing to update")
	_, err = licCall(f, licenses.UpdatePool, f.owner, "tenantId", f.tenantID, "poolId", laterID, "endsAt", f.now()+licenseHour)
	licCode(t, err, "INVALID_INPUT")
	_, err = licCall(f, licenses.UpdatePool, f.owner, "tenantId", f.tenantID, "poolId", laterID, "quantity", 0.0)
	licCode(t, err, "INVALID_INPUT")
	_, err = licCall(f, licenses.UpdatePool, f.owner, "tenantId", f.tenantID, "poolId", "missing", "quantity", 2.0)
	licCode(t, err, "NOT_FOUND")
	_, err = licCall(f, licenses.ListPools, f.owner, "tenantId", f.tenantID, "limit", 0.0)
	licCode(t, err, "INVALID_INPUT")
	_, err = licCall(f, licenses.ListPools, f.owner, "tenantId", f.tenantID, "includeEnded", "yes")
	licCode(t, err, "INVALID_INPUT")
	// Ended pools are kept 400 days after their end as purchase history, then swept.
	ending, err := add("endsAt", f.now()+licenseHour)
	if err != nil {
		t.Fatal(err)
	}
	f.advance(licenseHour + 399*24*licenseHour)
	swept := must(f.iam.SweepExpired(f.ctx, nil))
	if member(swept.Get("deleted"), "licensePools") != core.Undefined {
		t.Fatalf("swept early = %s", stringify(swept))
	}
	f.advance(2 * 24 * licenseHour)
	swept = must(f.iam.SweepExpired(f.ctx, nil))
	if member(swept.Get("deleted"), "licensePools") != 2.0 {
		t.Fatalf("swept = %s", stringify(swept))
	}
	left := f.find("licensePools", core.NewObject("tenantId", f.tenantID))
	if len(left) != 1 || left[0].Get("id") == member(ending.Get("pool"), "id") {
		t.Fatalf("left = %s", stringify(left))
	}
}

func TestLicenseGroupAssignments(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses, groups := f.iam.API.Licenses, f.iam.API.Groups
	licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 10.0)
	design := licMust(f, groups.Create, f.owner, "tenantId", f.tenantID, "name", "Design")
	licMust(f, groups.AddMembers, f.owner, "tenantId", f.tenantID, "groupId", licID(design), "identityIds", items(licID(f.alice), licID(f.bob)))
	f.advance(1000)
	grouped := licMust(f, licenses.Assign, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "subjectType", "group", "subjectId", licID(design))
	assignment := grouped.Get("assignment").(*core.Object)
	if assignment.Get("subjectType") != "group" || assignment.Get("subjectId") != design.Get("id") || assignment.Get("subjectName") != "Design" || assignment.Has("subjectEmail") {
		t.Fatalf("assignment = %s", stringify(assignment))
	}
	licStrings(t, "grouped", licSorted(f.changes(grouped.Get("seats"))), "alice none->active", "bob none->active")
	// A direct assignment on top only adds a source.
	direct := f.mustAssign(licID(f.alice))
	expectJSON(t, "direct seats", direct.Get("seats"), "[]")
	aliceSeats := answerListOf(licMust(f, licenses.ListSeats, f.owner, "tenantId", f.tenantID, "identityId", licID(f.alice)), "seats")
	if len(aliceSeats) != 1 || aliceSeats[0].Get("identityName") != "alice" || aliceSeats[0].Get("identityEmail") != "alice@acme.test" ||
		aliceSeats[0].Get("identityKind") != "user" || aliceSeats[0].Get("status") != "active" || aliceSeats[0].Get("direct") != true ||
		stringify(aliceSeats[0].Get("groupIds")) != stringify(items(licID(design))) {
		t.Fatalf("alice seats = %s", stringify(aliceSeats))
	}

	// Membership changes move seats in the same transaction, whoever writes them.
	licMust(f, groups.AddMember, f.owner, "tenantId", f.tenantID, "groupId", licID(design), "identityId", licID(f.carol))
	licStrings(t, "seats", licSorted(f.seats()), "alice active", "bob active", "carol active")
	licMust(f, groups.RemoveMember, f.owner, "tenantId", f.tenantID, "groupId", licID(design), "identityId", licID(f.bob))
	licMust(f, groups.RemoveMember, f.owner, "tenantId", f.tenantID, "groupId", licID(design), "identityId", licID(f.alice))
	licStrings(t, "seats", f.seats(), "alice active", "carol active")
	if seat := answerListOf(licMust(f, licenses.ListSeats, f.owner, "tenantId", f.tenantID, "identityId", licID(f.alice)), "seats")[0]; seat.Get("direct") != true || stringify(seat.Get("groupIds")) != "[]" {
		t.Fatalf("alice seat = %s", stringify(seat))
	}
	releases := f.trail(f.tenantID, "license:seat-release")
	release := releases[len(releases)-1]
	expectJSON(t, "release metadata", release.Get("metadata"), stringify(core.NewObject("productId", f.pro.Get("id"), "productKey", "pro",
		"from", "active", "to", "none", "reason", "group-membership")))
	if release.Get("actorId") != f.ownerID || release.Get("resourceId") != f.bob.Get("id") {
		t.Fatalf("release = %s", stringify(release))
	}

	// A temporary membership ends by itself; the next reconcile releases the seat.
	erin := f.member("erin")
	licMust(f, groups.AddMember, f.owner, "tenantId", f.tenantID, "groupId", licID(design), "identityId", licID(erin), "expiresAt", f.now()+licenseHour)
	if !containsString(f.seats(), "erin active") {
		t.Fatalf("erin has no seat: %v", f.seats())
	}
	f.advance(2 * licenseHour)
	if job := must(f.iam.Licenses.Reconcile(f.ctx, nil)); job.Get("released") != 1.0 {
		t.Fatalf("job = %s", stringify(job))
	}
	licStrings(t, "seats", f.seats(), "alice active", "carol active")

	// Duplicates and unknown subjects are refused.
	_, err := f.assign(licID(f.alice))
	licCode(t, err, "CONFLICT")
	_, err = f.assign("missing")
	licCode(t, err, "NOT_FOUND")
	_, err = f.assign(licID(f.alice), "missing")
	licCode(t, err, "NOT_FOUND")
	_, err = licCall(f, licenses.Assign, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "subjectType", "group", "subjectId", "missing")
	licCode(t, err, "NOT_FOUND")
	_, err = licCall(f, licenses.Assign, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "subjectType", "team", "subjectId", licID(f.alice))
	licCode(t, err, "INVALID_INPUT")

	// Listing assignments: newest first, filtered and paged.
	all := licMust(f, licenses.ListAssignments, f.owner, "tenantId", f.tenantID)
	if all.Get("total") != 2.0 {
		t.Fatalf("all = %s", stringify(all))
	}
	licStrings(t, "subjects", pluck(answerListOf(all, "assignments"), "subjectName"), "alice", "Design")
	byGroup := answerListOf(licMust(f, licenses.ListAssignments, f.owner, "tenantId", f.tenantID, "subjectType", "group"), "assignments")
	if len(byGroup) != 1 || byGroup[0].Get("subjectId") != design.Get("id") {
		t.Fatalf("by group = %s", stringify(byGroup))
	}
	filtered := licMust(f, licenses.ListAssignments, f.owner, "tenantId", f.tenantID, "subjectId", licID(f.alice), "productId", licID(f.pro))
	if filtered.Get("total") != 1.0 || answerListOf(filtered, "assignments")[0].Get("id") != member(direct.Get("assignment"), "id") {
		t.Fatalf("filtered = %s", stringify(filtered))
	}
	paged := licMust(f, licenses.ListAssignments, f.owner, "tenantId", f.tenantID, "limit", 1.0, "offset", 1.0)
	if paged.Get("total") != 2.0 || answerListOf(paged, "assignments")[0].Get("subjectName") != "Design" {
		t.Fatalf("paged = %s", stringify(paged))
	}
	_, err = licCall(f, licenses.ListAssignments, f.owner, "tenantId", f.tenantID, "subjectType", "robot")
	licCode(t, err, "INVALID_INPUT")

	// Unassigning by product and subject, or by ID; seats a remaining assignment covers stay.
	ungrouped := licMust(f, licenses.Unassign, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "subjectType", "group", "subjectId", licID(design))
	licStrings(t, "ungrouped", f.changes(ungrouped.Get("seats")), "carol active->none")
	_, err = licCall(f, licenses.Unassign, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "subjectType", "group", "subjectId", licID(design))
	licCode(t, err, "NOT_FOUND")
	directID := member(direct.Get("assignment"), "id")
	licStrings(t, "by id", f.changes(licMust(f, licenses.Unassign, f.owner, "tenantId", f.tenantID, "assignmentId", directID).Get("seats")), "alice active->none")
	_, err = licCall(f, licenses.Unassign, f.owner, "tenantId", f.tenantID, "assignmentId", directID)
	licCode(t, err, "NOT_FOUND")
	_, err = licCall(f, licenses.Unassign, f.owner, "tenantId", f.tenantID)
	licCode(t, err, "INVALID_INPUT")
	licStrings(t, "seats", f.seats())
	unassigns := []string{}
	for _, event := range f.trail(f.tenantID, "license:unassign") {
		unassigns = append(unassigns, jsString(event.Get("resourceId"))+" "+jsString(member(event.Get("metadata"), "subjectType")))
	}
	licStrings(t, "unassigns", unassigns, licID(design)+" group", licID(f.alice)+" identity")
}

func TestLicenseAssignManyAndGroupDeletion(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses, groups := f.iam.API.Licenses, f.iam.API.Groups
	licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 3.0)
	f.mustAssign(licID(f.bob))
	dave := f.member("dave")
	f.advance(1000)
	many := licMust(f, licenses.AssignMany, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro),
		"identityIds", items(licID(f.bob), licID(dave), licID(dave), licID(f.carol)))
	expectJSON(t, "skipped", many.Get("skipped"), stringify(items(licID(f.bob))))
	licStrings(t, "assigned", pluck(answerListOf(many, "assigned"), "subjectName"), "dave", "carol")
	licStrings(t, "many", licSorted(f.changes(many.Get("seats"))), "carol none->active", "dave none->active")
	licStrings(t, "assign events", pluck(f.trail(f.tenantID, "license:assign"), "resourceId"), licID(f.bob), licID(dave), licID(f.carol))
	// Nothing new: no seat run, no error.
	again := licMust(f, licenses.AssignMany, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "identityIds", items(licID(f.bob)))
	expectJSON(t, "again", again, stringify(core.NewObject("assigned", []any{}, "skipped", items(licID(f.bob)), "seats", []any{})))
	tooMany := make([]any, 101)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("id-%d", index)
	}
	for _, identityIDs := range []any{[]any{}, "x", tooMany} {
		_, err := licCall(f, licenses.AssignMany, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "identityIds", identityIDs)
		licCode(t, err, "INVALID_INPUT")
	}
	// One unknown person rejects the whole batch.
	_, err := licCall(f, licenses.AssignMany, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "identityIds", items(licID(f.alice), "missing"))
	licCode(t, err, "NOT_FOUND")
	if listed := licMust(f, licenses.ListAssignments, f.owner, "tenantId", f.tenantID, "subjectId", licID(f.alice)); listed.Get("total") != 0.0 {
		t.Fatalf("alice assignments = %s", stringify(listed))
	}

	// Deleting a group deletes its license assignments; the seats they carried go.
	ops := licMust(f, groups.Create, f.owner, "tenantId", f.tenantID, "name", "Ops")
	licMust(f, groups.AddMember, f.owner, "tenantId", f.tenantID, "groupId", licID(ops), "identityId", licID(f.alice))
	licMust(f, groups.AddMember, f.owner, "tenantId", f.tenantID, "groupId", licID(ops), "identityId", licID(f.bob))
	f.advance(1000)
	grouped := licMust(f, licenses.Assign, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "subjectType", "group", "subjectId", licID(ops))
	licStrings(t, "grouped", f.changes(grouped.Get("seats")), "alice none->waiting")
	licMust(f, groups.Delete, f.owner, "tenantId", f.tenantID, "groupId", licID(ops))
	if listed := licMust(f, licenses.ListAssignments, f.owner, "tenantId", f.tenantID, "subjectType", "group"); listed.Get("total") != 0.0 {
		t.Fatalf("group assignments = %s", stringify(listed))
	}
	licStrings(t, "seats", licSorted(f.seats()), "bob active", "carol active", "dave active")
	releases := f.trail(f.tenantID, "license:seat-release")
	last := releases[len(releases)-1]
	if last.Get("resourceId") != f.alice.Get("id") || member(last.Get("metadata"), "from") != "waiting" || member(last.Get("metadata"), "reason") != "group-deleted" {
		t.Fatalf("release = %s", stringify(last))
	}
}

func TestLicenseLimits(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses := f.iam.API.Licenses
	now := f.now()
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		for index := 1; index < 200; index++ {
			if _, err := tx.Insert(ctx, "licenseProducts", core.NewObject("id", fmt.Sprintf("product-%d", index), "tenantId", f.tenantID,
				"uniqueKey", fmt.Sprintf("key:bulk-%d", index), "key", fmt.Sprintf("bulk-%d", index), "name", fmt.Sprintf("Bulk %d", index),
				"featureKeys", []any{}, "status", "active", "createdAt", now, "createdBy", f.ownerID, "updatedAt", now, "updatedBy", f.ownerID)); err != nil {
				return err
			}
		}
		for index := 0; index < 100; index++ {
			if _, err := tx.Insert(ctx, "licensePools", core.NewObject("id", fmt.Sprintf("pool-%d", index), "tenantId", f.tenantID,
				"productId", licID(f.pro), "quantity", 1.0, "source", "manual", "createdAt", now, "createdBy", f.ownerID)); err != nil {
				return err
			}
		}
		for index := 0; index < 10_000; index++ {
			if _, err := tx.Insert(ctx, "licenseAssignments", core.NewObject("id", fmt.Sprintf("assignment-%d", index), "tenantId", f.tenantID,
				"uniqueKey", fmt.Sprintf("%s:identity:ghost-%d", licID(f.pro), index), "productId", licID(f.pro), "subjectType", "identity",
				"subjectId", fmt.Sprintf("ghost-%d", index), "assignedBy", f.ownerID, "assignedAt", now)); err != nil {
				return err
			}
		}
		return nil
	})
	_, err := licCall(f, licenses.CreateProduct, f.owner, "tenantId", f.tenantID, "key", "one-more", "name", "One more")
	licCode(t, err, "LIMIT_EXCEEDED")
	expectStatus(t, err, 409)
	_, err = licCall(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 1.0)
	licCode(t, err, "LIMIT_EXCEEDED")
	_, err = f.assign(licID(f.alice))
	licCode(t, err, "LIMIT_EXCEEDED")
	_, err = licCall(f, licenses.AssignMany, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "identityIds", items(licID(f.alice)))
	licCode(t, err, "LIMIT_EXCEEDED")
	// Another product has room.
	if pool := licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", "product-1", "quantity", 1.0); member(pool.Get("pool"), "productKey") != "bulk-1" {
		t.Fatalf("pool = %s", stringify(pool))
	}
}

func TestLicenseSettings(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses := f.iam.API.Licenses
	expectJSON(t, "defaults", licMust(f, licenses.GetSettings, f.owner, "tenantId", f.tenantID), stringify(core.NewObject("tenantId", f.tenantID, "notifyWaiting", false)))
	expectJSON(t, "reclaim", licMust(f, licenses.Configure, f.owner, "tenantId", f.tenantID, "reclaimAfterDays", 30.0), stringify(core.NewObject(
		"tenantId", f.tenantID, "reclaimAfterDays", 30.0, "notifyWaiting", false, "updatedAt", f.now(), "updatedBy", f.ownerID)))
	if notify := licMust(f, licenses.Configure, f.owner, "tenantId", f.tenantID, "notifyWaiting", true); notify.Get("reclaimAfterDays") != 30.0 || notify.Get("notifyWaiting") != true {
		t.Fatalf("notify = %s", stringify(notify))
	}
	cleared := licMust(f, licenses.Configure, f.owner, "tenantId", f.tenantID, "reclaimAfterDays", nil)
	if cleared.Get("notifyWaiting") != true || cleared.Has("reclaimAfterDays") {
		t.Fatalf("cleared = %s", stringify(cleared))
	}
	expectJSON(t, "settings", licMust(f, licenses.GetSettings, f.owner, "tenantId", f.tenantID), stringify(cleared))
	for _, pairs := range [][]any{{}, {"reclaimAfterDays", 6.0}, {"reclaimAfterDays", 366.0}, {"reclaimAfterDays", 7.5}, {"reclaimAfterDays", "30"}, {"notifyWaiting", "yes"}} {
		_, err := licCall(f, licenses.Configure, f.owner, append([]any{"tenantId", f.tenantID}, pairs...)...)
		licCode(t, err, "INVALID_INPUT")
	}
	metadata := []any{}
	for _, event := range f.trail(f.tenantID, "license:settings") {
		metadata = append(metadata, event.Get("metadata"))
	}
	expectJSON(t, "settings trail", metadata, `[{"reclaimAfterDays":30,"notifyWaiting":false,"previousReclaimAfterDays":null,"previousNotifyWaiting":false},`+
		`{"reclaimAfterDays":30,"notifyWaiting":true,"previousReclaimAfterDays":30,"previousNotifyWaiting":false},`+
		`{"reclaimAfterDays":null,"notifyWaiting":true,"previousReclaimAfterDays":30,"previousNotifyWaiting":true}]`)
}

func TestLicenseMineAndRuntime(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses := f.iam.API.Licenses
	team := licMust(f, licenses.CreateProduct, f.owner, "tenantId", f.tenantID, "key", "team", "name", "Team", "featureKeys", items("boards", "sso"))
	licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 1.0)
	licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(team), "quantity", 5.0)
	f.mustAssign(licID(f.alice))
	f.mustAssign(licID(f.alice), licID(team))
	f.mustAssign(licID(f.bob))
	expectJSON(t, "alice", licMust(f, licenses.Mine, f.creds["alice"], "tenantId", f.tenantID), stringify(core.NewObject(
		"tenantId", f.tenantID, "identityId", f.alice.Get("id"), "licenses", items(
			core.NewObject("productId", f.pro.Get("id"), "key", "pro", "name", "Pro", "description", "Everything in Pro", "status", "active",
				"featureKeys", items("exports", "sso"), "platform", false, "definedBy", f.tenantID),
			core.NewObject("productId", team.Get("id"), "key", "team", "name", "Team", "status", "active",
				"featureKeys", items("boards", "sso"), "platform", false, "definedBy", f.tenantID),
		),
		// Acme's own products: their feature keys are not the platform's entitlements.
		"featureKeys", []any{}, "allFeatureKeys", items("boards", "exports", "sso"),
	)))
	expectJSON(t, "bob", licMust(f, licenses.Mine, f.creds["bob"], "tenantId", f.tenantID), stringify(core.NewObject(
		"tenantId", f.tenantID, "identityId", f.bob.Get("id"), "licenses", items(
			core.NewObject("productId", f.pro.Get("id"), "key", "pro", "name", "Pro", "description", "Everything in Pro", "status", "waiting",
				"position", 1.0, "featureKeys", []any{}, "platform", false, "definedBy", f.tenantID),
		),
		"featureKeys", []any{}, "allFeatureKeys", []any{},
	)))
	expectJSON(t, "carol", licMust(f, licenses.Mine, f.creds["carol"], "tenantId", f.tenantID), stringify(core.NewObject(
		"tenantId", f.tenantID, "identityId", f.carol.Get("id"), "licenses", []any{}, "featureKeys", []any{}, "allFeatureKeys", []any{})))
	acme := core.NewObject("trustedTenantId", f.tenantID)
	licStrings(t, "trusted features", must(f.iam.Licenses.Features(f.ctx, licID(f.alice), f.tenantID, acme)), "boards", "exports", "sso")
	licStrings(t, "platform features", must(f.iam.Licenses.Features(f.ctx, licID(f.alice), f.tenantID, nil)))
	licStrings(t, "products", must(f.iam.Licenses.Products(f.ctx, licID(f.alice), f.tenantID)), "pro", "team")
	licStrings(t, "bob features", must(f.iam.Licenses.Features(f.ctx, licID(f.bob), f.tenantID, acme)))
	context := must(core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return LicenseContext(ctx, tx, f.tenantID, licID(f.alice), int64(f.now()))
	}))
	expectJSON(t, "principal.licenses", context, `{"principal.licenses":["pro","team"]}`)

	count := func() int { return len(f.find("audit", core.NewObject("tenantId", f.tenantID))) }
	before := count()
	licMust(f, licenses.Mine, f.creds["alice"], "tenantId", f.tenantID)
	if count() != before {
		t.Fatal("mine was audited")
	}
	// Only the caller's own tenant; administrators of other tenants see nothing of theirs here.
	_, err := licCall(f, licenses.Mine, f.creds["alice"], "tenantId", f.rootTenantID())
	licCode(t, err, "ACCESS_DENIED")
	_, err = licCall(f, licenses.Mine, core.CredentialInput{Token: "not-a-token"}, "tenantId", f.tenantID)
	licCode(t, err, "UNAUTHENTICATED")
	_, err = licCall(f, licenses.Mine, f.creds["alice"], "tenantId", "")
	licCode(t, err, "INVALID_INPUT")
	if root := licMust(f, licenses.Mine, f.rootCred, "tenantId", f.tenantID); stringify(root.Get("licenses")) != "[]" {
		t.Fatalf("root = %s", stringify(root))
	}
	if owner := licMust(f, licenses.Mine, f.owner, "tenantId", f.tenantID); owner.Get("identityId") != f.ownerID || stringify(owner.Get("licenses")) != "[]" {
		t.Fatalf("owner = %s", stringify(owner))
	}
}

func TestLicenseReclaim(t *testing.T) {
	const day = 86_400_000
	f := licenseScenario(t, nil)
	licenses, groups := f.iam.API.Licenses, f.iam.API.Groups
	licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 10.0)
	// Reclaim is off by default.
	expectJSON(t, "off", must(f.iam.Licenses.Reclaim(f.ctx, nil)), `{"tenants":0,"reclaimed":[],"failedTenants":[]}`)
	licMust(f, licenses.Configure, f.owner, "tenantId", f.tenantID, "reclaimAfterDays", 30.0)
	dave := f.member("dave")
	erin := f.member("erin")
	field := licMust(f, groups.Create, f.owner, "tenantId", f.tenantID, "name", "Field")
	licMust(f, groups.AddMember, f.owner, "tenantId", f.tenantID, "groupId", licID(field), "identityId", licID(erin))
	licMust(f, licenses.Assign, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "subjectType", "group", "subjectId", licID(field))
	licMust(f, licenses.AssignMany, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "identityIds", items(licID(f.alice), licID(f.bob), licID(dave)))
	// Day 2: dave is disabled (his seat goes). Day 20: alice signs in. Day 25: carol gets Pro.
	f.advance(2 * day)
	f.patch("identities", licID(dave), core.NewObject("status", "disabled"))
	must(ReconcileLicensesOf(f.ctx, f.iam.Context, f.tenantID, []string{licID(dave)}, nil))
	f.advance(18 * day)
	f.issue(f.record("identities", licID(f.alice)), false)
	f.advance(5 * day)
	admin := f.ownerSignIn(f.tenantID)
	licMust(f, licenses.Assign, admin, "tenantId", f.tenantID, "productId", licID(f.pro), "subjectType", "identity", "subjectId", licID(f.carol))
	f.advance(6 * day)
	current := f.ownerSignIn(f.tenantID)
	// Usage reports inactive active seats, including those held through groups.
	usage := answerListOf(licMust(f, licenses.Usage, current, "tenantId", f.tenantID), "products")[0]
	if usage.Get("active") != 4.0 || usage.Get("reclaimable") != 2.0 || usage.Get("reclaimableThroughGroups") != 1.0 || usage.Get("reclaimAfterDays") != core.Undefined {
		t.Fatalf("usage = %s", stringify(usage))
	}

	result := must(f.iam.Licenses.Reclaim(f.ctx, nil))
	if result.Get("tenants") != 1.0 || stringify(result.Get("failedTenants")) != "[]" {
		t.Fatalf("result = %s", stringify(result))
	}
	reclaimed := answerListOf(result, "reclaimed")
	licStrings(t, "reclaimed", licSorted(pluck(reclaimed, "identityId")), licSorted([]string{licID(f.bob), licID(dave)})...)
	for _, item := range reclaimed {
		if item.Get("identityId") == f.bob.Get("id") {
			expectJSON(t, "bob reclaimed", item, stringify(core.NewObject("tenantId", f.tenantID, "productId", f.pro.Get("id"), "productKey", "pro",
				"identityId", f.bob.Get("id"), "lastActivityAt", f.bob.Get("createdAt"))))
		}
	}
	held := map[string]*core.Object{}
	for _, seat := range answerListOf(licMust(f, licenses.ListSeats, current, "tenantId", f.tenantID), "seats") {
		held[jsString(seat.Get("identityId"))] = seat
	}
	keys := []string{}
	for key := range held {
		keys = append(keys, key)
	}
	licStrings(t, "holders", licSorted(keys), licSorted([]string{licID(f.alice), licID(f.carol), licID(erin)})...)
	// The pass records what it saw on each seat.
	if held[licID(f.alice)].Get("lastActivityAt") != f.now()-11*day || held[licID(erin)].Get("lastActivityAt") != erin.Get("createdAt") {
		t.Fatalf("activity = %s", stringify(held))
	}
	direct := pluck(answerListOf(licMust(f, licenses.ListAssignments, current, "tenantId", f.tenantID, "subjectType", "identity"), "assignments"), "subjectId")
	licStrings(t, "direct", licSorted(direct), licSorted([]string{licID(f.alice), licID(f.carol)})...)
	if usage := answerListOf(licMust(f, licenses.Usage, current, "tenantId", f.tenantID), "products")[0]; usage.Get("active") != 3.0 ||
		usage.Get("reclaimable") != 1.0 || usage.Get("reclaimableThroughGroups") != 1.0 {
		t.Fatalf("usage after = %s", stringify(usage))
	}
	reclaims := f.trail(f.tenantID, "license:reclaim")
	licStrings(t, "reclaim events", licSorted(pluck(reclaims, "resourceId")), licSorted([]string{licID(f.bob), licID(dave)})...)
	for _, event := range reclaims {
		if event.Get("resourceId") == f.bob.Get("id") {
			metadata := event.Get("metadata").(*core.Object)
			if event.Get("actorId") != "deployment-operator" || metadata.Get("productKey") != "pro" || metadata.Get("lastActivityAt") != f.bob.Get("createdAt") ||
				metadata.Get("reclaimAfterDays") != 30.0 {
				t.Fatalf("reclaim event = %s", stringify(event))
			}
		}
	}
	releases := f.trail(f.tenantID, "license:seat-release")
	if last := releases[len(releases)-1]; last.Get("resourceId") != f.bob.Get("id") || member(last.Get("metadata"), "reason") != "reclaim" {
		t.Fatalf("release = %s", stringify(last))
	}
	// A second pass finds nothing more; turning reclaim off stops it.
	if again := must(f.iam.Licenses.Reclaim(f.ctx, core.NewObject("tenantId", f.tenantID))); stringify(again.Get("reclaimed")) != "[]" {
		t.Fatalf("again = %s", stringify(again))
	}
	licMust(f, licenses.Configure, current, "tenantId", f.tenantID, "reclaimAfterDays", nil)
	expectJSON(t, "off for tenant", must(f.iam.Licenses.Reclaim(f.ctx, core.NewObject("tenantId", f.tenantID))), `{"tenants":0,"reclaimed":[],"failedTenants":[]}`)
	expectJSON(t, "off", must(f.iam.Licenses.Reclaim(f.ctx, nil)), `{"tenants":0,"reclaimed":[],"failedTenants":[]}`)
	missing := must(f.iam.Licenses.Reclaim(f.ctx, core.NewObject("tenantId", "missing")))
	failed := answerListOf(missing, "failedTenants")
	if missing.Get("tenants") != 0.0 || len(failed) != 1 || failed[0].Get("tenantId") != "missing" || failed[0].Get("code") != "NOT_FOUND" {
		t.Fatalf("missing = %s", stringify(missing))
	}
}

func TestLicenseIdentityLifecycle(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses := f.iam.API.Licenses
	licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 1.0)
	f.mustAssign(licID(f.alice))
	f.mustAssign(licID(f.bob))
	licStrings(t, "seats", f.seats(), "alice active", "bob waiting #1")
	// A disabled person claims no seat; the next in line moves up.
	f.patch("identities", licID(f.alice), core.NewObject("status", "disabled"))
	changed := must(ReconcileLicensesOf(f.ctx, f.iam.Context, f.tenantID, []string{licID(f.alice)}, nil))
	licStrings(t, "changed", licSorted(changed), licSorted([]string{licID(f.alice), licID(f.bob)})...)
	licStrings(t, "seats", f.seats(), "bob active")
	// An expired person neither.
	f.patch("identities", licID(f.bob), core.NewObject("expiresAt", f.now()+licenseHour))
	f.advance(2 * licenseHour)
	if job := must(f.iam.Licenses.Reconcile(f.ctx, nil)); job.Get("released") != 1.0 {
		t.Fatalf("job = %s", stringify(job))
	}
	licStrings(t, "seats", f.seats())
	// A deleted person's direct assignments and seats go (releaseLicensesOf), and carol moves up.
	f.patch("identities", licID(f.alice), core.NewObject("status", "active"))
	must(ReconcileLicensesOf(f.ctx, f.iam.Context, f.tenantID, []string{licID(f.alice)}, nil))
	f.mustAssign(licID(f.carol))
	licStrings(t, "seats", f.seats(), "alice active", "carol waiting #1")
	var changes []*core.Object
	aliceRecord := f.record("identities", licID(f.alice))
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		var err error
		changes, err = ReleaseLicensesOf(ctx, f.iam.Context, tx, aliceRecord, "deployment-operator")
		return err
	})
	licStrings(t, "release", f.changes(licenseChanges(changes)), "alice active->none", "carol waiting->active")
	if listed := licMust(f, licenses.ListAssignments, f.owner, "tenantId", f.tenantID, "subjectId", licID(f.alice)); listed.Get("total") != 0.0 {
		t.Fatalf("alice assignments = %s", stringify(listed))
	}
	releases := f.trail(f.tenantID, "license:seat-release")
	if last := releases[len(releases)-1]; last.Get("actorId") != "deployment-operator" || member(last.Get("metadata"), "reason") != "identity-deleted" {
		t.Fatalf("release = %s", stringify(last))
	}
	// Without identities nothing runs.
	if none := must(ReconcileLicensesOf(f.ctx, f.iam.Context, f.tenantID, nil, nil)); len(none) != 0 {
		t.Fatalf("none = %v", none)
	}
}

func TestLicenseWaitingListEmail(t *testing.T) {
	var mu sync.Mutex
	sent := []*core.Object{}
	f := licenseScenario(t, func(options *BetterIamOptions) {
		options.Authentication.SendEmail = func(ctx context.Context, message auth.DeliveryMessage) error {
			mu.Lock()
			defer mu.Unlock()
			sent = append(sent, core.NewObject("to", message.To, "template", message.Template, "payload", message.Payload))
			return nil
		}
	})
	licenses := f.iam.API.Licenses
	dispatch := func() []string {
		must(f.iam.Auth.DispatchOutbox(f.ctx, 100))
		mu.Lock()
		defer mu.Unlock()
		out := []string{}
		for _, message := range sent {
			if strings.HasPrefix(jsString(message.Get("template")), "license-") {
				out = append(out, jsString(message.Get("to"))+" "+jsString(message.Get("template")))
			}
		}
		sent = sent[:0]
		return out
	}
	dispatch()
	// Off by default.
	f.mustAssign(licID(f.alice))
	licStrings(t, "off", dispatch())
	licMust(f, licenses.Configure, f.owner, "tenantId", f.tenantID, "notifyWaiting", true)
	f.mustAssign(licID(f.bob))
	licStrings(t, "waiting", dispatch(), "bob@acme.test license-waiting")
	licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 5.0)
	licStrings(t, "activated", licSorted(dispatch()), "alice@acme.test license-activated", "bob@acme.test license-activated")
}

func TestBatchGroupLicensesDefersReconciliation(t *testing.T) {
	f := licenseScenario(t, nil)
	licenses, groups := f.iam.API.Licenses, f.iam.API.Groups
	licMust(f, licenses.AddPool, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "quantity", 1.0)
	crew := licMust(f, groups.Create, f.owner, "tenantId", f.tenantID, "name", "Crew")
	licMust(f, licenses.Assign, f.owner, "tenantId", f.tenantID, "productId", licID(f.pro), "subjectType", "group", "subjectId", licID(crew))
	server := f.iam.Context
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		_, err := BatchGroupLicenses(ctx, server, tx, func(ctx context.Context) (any, error) {
			for _, person := range []*core.Object{f.carol, f.alice, f.bob} {
				if _, err := tx.Insert(ctx, "groupMembers", core.NewObject("id", ID(), "tenantId", f.tenantID, "groupId", licID(crew),
					"identityId", licID(person), "createdAt", f.now())); err != nil {
					return nil, err
				}
				// Inside the batch only noted; nested batches join it.
				changes, err := BatchGroupLicenses(ctx, server, tx, func(ctx context.Context) (any, error) {
					return ReconcileGroupLicenses(ctx, server, tx, f.tenantID, licID(crew), "deployment-operator")
				})
				if err != nil {
					return nil, err
				}
				if len(changes.([]*core.Object)) != 0 {
					t.Errorf("reconciled inside the batch: %v", changes)
				}
			}
			seats, err := tx.Find(ctx, LicenseCollections.Seats, core.NewObject("tenantId", f.tenantID), nil)
			if len(seats) != 0 {
				t.Errorf("seats inside the batch: %d", len(seats))
			}
			return nil, err
		})
		return err
	})
	// People who claim a seat in the same batch rank by identity ID among themselves.
	people := []string{licID(f.alice), licID(f.bob), licID(f.carol)}
	sort.Strings(people)
	holders := []string{}
	for _, seat := range answerListOf(licMust(f, licenses.ListSeats, f.owner, "tenantId", f.tenantID), "seats") {
		holders = append(holders, jsString(seat.Get("identityId"))+" "+jsString(seat.Get("status")))
	}
	licStrings(t, "holders", holders, people[0]+" active", people[1]+" waiting", people[2]+" waiting")
	if held := must(GroupsHoldLicenses(f.ctx, f.iam.Store, f.tenantID, []string{licID(crew), licID(crew)})); !held {
		t.Fatal("the group holds licenses")
	}
	if held := must(GroupsHoldLicenses(f.ctx, f.iam.Store, f.tenantID, []string{"other"})); held {
		t.Fatal("an unlicensed group holds none")
	}
}

func TestLicenseKeysAndHelpers(t *testing.T) {
	for _, key := range []string{"pro", "team.v2_b-1", "0day"} {
		if got, err := LicenseKey(key); err != nil || got != key {
			t.Fatalf("LicenseKey(%q) = %q, %v", key, got, err)
		}
	}
	_, err := LicenseKey("Pro")
	expectError(t, err, "INVALID_INPUT", "License keys are 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter or digit")
	_, err = LicenseKey(7.0)
	expectError(t, err, "INVALID_INPUT", "Invalid key")
	pools := []*core.Object{
		core.NewObject("quantity", 2.0),
		core.NewObject("quantity", 3.0, "startsAt", 100.0),
		core.NewObject("quantity", 5.0, "endsAt", 100.0),
	}
	if capacity := must(LicenseCapacity(pools, 50)); capacity != 7 {
		t.Fatalf("capacity at 50 = %v", capacity)
	}
	if capacity := must(LicenseCapacity(pools, 100)); capacity != 5 {
		t.Fatalf("capacity at 100 = %v", capacity)
	}
	if live := must(LiveLicensePool(pools[2], 99)); !live {
		t.Fatal("pool ending at 100 is live at 99")
	}
	if !MentionsLicenses([]any{nil, core.NewObject("statements", items(core.NewObject("condition", core.NewObject("ForAnyValue:StringEquals",
		core.NewObject("principal.licenses", "pro")))))}) {
		t.Fatal("mentions principal.licenses")
	}
	if MentionsLicenses([]any{core.NewObject("statements", []any{})}) {
		t.Fatal("no mention")
	}
}
