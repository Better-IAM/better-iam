package server

// Port of tests/applications.test.ts: the application catalog, the "My apps" launcher, the provider gate and
// assignment hygiene. The organization fixture (tests/support/organization.ts) is rebuilt here from records where the
// TypeScript fixture goes through API groups other units port (tenants.create, identities.create, groups, roles,
// bindings, packages): the records are the ones those groups write, so the applications code under test reads what it
// reads in TypeScript.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const appsDay = int64(86_400_000)

// appsOrg is tests/support/organization.ts organizationFixture: a bootstrapped platform with one organization
// ("Acme") whose owner is set up, a controllable clock, and sessions that last seven days.
type appsOrg struct {
	t                *testing.T
	ctx              context.Context
	iam              *BetterIam
	clock            *atomic.Int64
	rootTenantID     string
	rootID           string
	tenantID         string
	ownerID          string
	ownerAuthorityID string
	owner            core.CredentialInput
}

// newAppsOrg composes the server; mutate adjusts the options before construction.
func newAppsOrg(t *testing.T, mutate func(options *BetterIamOptions)) *appsOrg {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(1_767_225_600_000)
	week := int64(7 * 86_400_000)
	now := func() int64 { return clock.Load() }
	options := &BetterIamOptions{
		Database: newStore(t), Secret: "organization-fixture-secret-with-32-characters", BaseURL: "http://localhost:3000",
		WallClock:      now,
		Authentication: &auth.Options{Now: now, SessionLifetimeMs: &week, SessionIdleTimeoutMs: &week},
	}
	if mutate != nil {
		mutate(options)
	}
	iam, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iam.Close)
	f := &appsOrg{t: t, ctx: context.Background(), iam: iam, clock: clock}
	if err := iam.Initialize(f.ctx); err != nil {
		t.Fatal(err)
	}
	root, err := iam.Bootstrap(f.ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password"))
	if err != nil {
		t.Fatal(err)
	}
	f.rootTenantID = jsString(member(root.Get("tenant"), "id"))
	f.rootID = jsString(member(root.Get("identity"), "id"))
	// tenants.create with activation: the tenant, its grant authority under root's, the owner, and the owner setup.
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		authorities, err := tx.Find(ctx, "grantAuthorities", core.NewObject("tenantId", f.rootTenantID, "identityId", f.rootID), nil)
		if err != nil {
			return err
		}
		if len(authorities) == 0 {
			return errors.New("root has no grant authority")
		}
		f.tenantID = ID()
		realm := core.NewObject("id", f.tenantID, "tenantId", f.tenantID, "name", "Acme", "type", "organization",
			"parentId", f.rootTenantID, "status", "active", "createdAt", float64(now()))
		if _, err := tx.Insert(ctx, "tenants", realm); err != nil {
			return err
		}
		authority, err := tx.Insert(ctx, "grantAuthorities", core.NewObject("id", ID(), "tenantId", f.tenantID,
			"identityId", "pending", "parentAuthorityId", authorities[0].Get("id"), "ceiling", All(), "revoked", false))
		if err != nil {
			return err
		}
		owner, err := iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{TenantID: f.tenantID, Email: "owner@acme.test",
			Name: "Owner", Password: "a strong tenant owner password", HasPassword: true, Owner: true, EmailVerified: true})
		if err != nil {
			return err
		}
		f.ownerID = jsString(owner.Get("id"))
		f.ownerAuthorityID = jsString(authority.Get("id"))
		return iam.Context.OwnerSetup(ctx, tx, realm, owner, authority)
	})
	f.owner = f.ownerSignIn()
	return f
}

func (f *appsOrg) now() int64             { return f.clock.Load() }
func (f *appsOrg) advance(ms int64)       { f.clock.Add(ms) }
func (f *appsOrg) server() *ServerContext { return f.iam.Context }

func (f *appsOrg) tx(fn func(ctx context.Context, tx core.IamStore) error) {
	f.t.Helper()
	if err := f.iam.Store.Transaction(f.ctx, fn); err != nil {
		f.t.Fatal(err)
	}
}

func (f *appsOrg) insert(collection string, record *core.Object) *core.Object {
	f.t.Helper()
	var stored *core.Object
	f.tx(func(ctx context.Context, tx core.IamStore) (err error) {
		stored, err = tx.Insert(ctx, collection, record)
		return err
	})
	return stored
}

func (f *appsOrg) get(collection, id string) *core.Object {
	f.t.Helper()
	record, err := f.iam.Store.Get(f.ctx, collection, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return record
}

func (f *appsOrg) find(collection string, filter *core.Object) []*core.Object {
	f.t.Helper()
	records, err := f.iam.Store.Find(f.ctx, collection, filter, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return records
}

// signIn signs a person of the organization in with their password ("a strong {name} password").
func (f *appsOrg) signIn(email, password string) core.CredentialInput {
	f.t.Helper()
	result, err := f.iam.API.Auth.SignIn(f.ctx, Input[apitypes.AuthSignInInput](core.NewObject("tenantId", f.tenantID, "email", email, "password", password)))
	if err != nil {
		f.t.Fatal(err)
	}
	model, err := ToModel(result.Value)
	if err != nil {
		f.t.Fatal(err)
	}
	token, ok := member(model, "token").(string)
	if !ok {
		f.t.Fatalf("sign-in of %s answered no token: %v", email, model)
	}
	return core.CredentialInput{Token: token}
}

// ownerSignIn is a fresh owner session, recently authenticated.
func (f *appsOrg) ownerSignIn() core.CredentialInput {
	return f.signIn("owner@acme.test", "a strong tenant owner password")
}

// token signs `{name}@acme.test` in.
func (f *appsOrg) token(name string) core.CredentialInput {
	return f.signIn(name+"@acme.test", "a strong "+name+" password")
}

// memberIdentity creates the person `{name}@acme.test` with a password (identities.create as the owner).
func (f *appsOrg) memberIdentity(name string) *core.Object {
	f.t.Helper()
	var identity *core.Object
	f.tx(func(ctx context.Context, tx core.IamStore) (err error) {
		identity, err = f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{TenantID: f.tenantID, Email: name + "@acme.test",
			Name: name, Password: "a strong " + name + " password", HasPassword: true})
		return err
	})
	return identity
}

// group is the record groups.create writes.
func (f *appsOrg) group(name string) *core.Object {
	return f.insert("groups", core.NewObject("id", ID(), "tenantId", f.tenantID, "name", name, "createdAt", float64(f.now())))
}

// addMember is the record groups.addMember writes.
func (f *appsOrg) addMember(groupID, identityID any) {
	f.insert("groupMembers", core.NewObject("id", ID(), "tenantId", f.tenantID, "uniqueKey", jsString(groupID)+":"+jsString(identityID),
		"groupId", groupID, "identityId", identityID, "addedAt", float64(f.now())))
}

// role binds a role with one policy document to an identity, under the owner's grant authority (roles.create and
// bindings.create as the owner).
func (f *appsOrg) role(name string, document *core.Object, identityID any) {
	policy := f.insert("policies", core.NewObject("id", ID(), "tenantId", f.tenantID, "name", name, "document", document,
		"version", 1.0, "authorityId", f.ownerAuthorityID))
	role := f.insert("roles", core.NewObject("id", ID(), "tenantId", f.tenantID, "name", name,
		"policyIds", []any{policy.Get("id")}, "authorityId", f.ownerAuthorityID))
	f.insert("bindings", core.NewObject("id", ID(), "tenantId", f.tenantID, "subjectType", "identity", "subjectId", identityID,
		"roleId", role.Get("id"), "authorityId", f.ownerAuthorityID))
}

// appsValue is the answer of an API method as a model value.
func appsValue(t *testing.T, value any, err error) any {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	model, err := ToModel(value)
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func appsObject(t *testing.T, value any, err error) *core.Object {
	t.Helper()
	object, ok := appsValue(t, value, err).(*core.Object)
	if !ok {
		t.Fatalf("not an object: %v", value)
	}
	return object
}

func appsList(t *testing.T, value any, err error) []*core.Object {
	t.Helper()
	items, _ := appsValue(t, value, err).([]any)
	list := make([]*core.Object, len(items))
	for index, item := range items {
		list[index], _ = item.(*core.Object)
	}
	return list
}

func appsCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got no error", code)
	}
	if known := iamError(t, err); known.Code != code {
		t.Fatalf("expected %s, got %s %q", code, known.Code, known.Message)
	}
}

// expectAppsJSON compares a model value's JSON with the expected text.
func expectAppsJSON(t *testing.T, value any, want string) {
	t.Helper()
	text, _, err := core.Stringify(value)
	if err != nil {
		t.Fatal(err)
	}
	if text != want {
		t.Fatalf("got %s, want %s", text, want)
	}
}

// appsScenario is the scenario() of applications.test.ts: the organization, an Engineering group with alice, and bob.
type appsScenario struct {
	*appsOrg
	apps        *ApplicationsAPI
	engineering *core.Object
	alice, bob  *core.Object
}

func newAppsScenario(t *testing.T) *appsScenario {
	f := newAppsOrg(t, nil)
	s := &appsScenario{appsOrg: f, apps: f.iam.API.Applications}
	s.engineering = f.group("Engineering")
	s.alice = f.memberIdentity("alice")
	s.bob = f.memberIdentity("bob")
	f.addMember(s.engineering.Get("id"), s.alice.Get("id"))
	return s
}

func (s *appsScenario) create(credential core.CredentialInput, body *core.Object) (*core.Object, error) {
	out, err := s.apps.Create(s.ctx, credential, Input[apitypes.ApplicationsCreateInput](body.Spread(core.NewObject("tenantId", s.tenantID))))
	if err != nil {
		return nil, err
	}
	return appsObject(s.t, out.Value, nil), nil
}

func (s *appsScenario) mustCreate(body *core.Object) *core.Object {
	s.t.Helper()
	return must(s.create(s.owner, body))
}

func (s *appsScenario) assign(credential core.CredentialInput, body *core.Object) error {
	_, err := s.apps.Assign(s.ctx, credential, Input[apitypes.ApplicationsAssignInput](body.Spread(core.NewObject("tenantId", s.tenantID))))
	return err
}

func (s *appsScenario) mustAssign(body *core.Object) {
	s.t.Helper()
	if err := s.assign(s.owner, body); err != nil {
		s.t.Fatal(err)
	}
}

func (s *appsScenario) update(credential core.CredentialInput, body *core.Object) (*core.Object, error) {
	out, err := s.apps.Update(s.ctx, credential, Input[apitypes.ApplicationsUpdateInput](body.Spread(core.NewObject("tenantId", s.tenantID))))
	if err != nil {
		return nil, err
	}
	return appsObject(s.t, out.Value, nil), nil
}

func (s *appsScenario) mine(credential core.CredentialInput) []*core.Object {
	s.t.Helper()
	out, err := s.apps.Mine(s.ctx, credential, Input[apitypes.ApplicationsMineInput](core.NewObject("tenantId", s.tenantID)))
	return appsList(s.t, out.Value, err)
}

// names is `{key}:{via}` of the caller's launcher, sorted.
func (s *appsScenario) names(credential core.CredentialInput) string {
	s.t.Helper()
	result := []string{}
	for _, app := range s.mine(credential) {
		via := "undefined"
		if value, ok := app.Get("via").(string); ok {
			via = value
		}
		result = append(result, jsString(app.Get("key"))+":"+via)
	}
	sort.Strings(result)
	return strings.Join(result, ",")
}

func (s *appsScenario) allowed(body *core.Object) *core.Object {
	s.t.Helper()
	return must(s.iam.Applications.Allowed(s.ctx, body.Spread(core.NewObject("tenantId", s.tenantID))))
}

func TestApplicationsLauncherShowsAssignedAppsAndRecordsLaunches(t *testing.T) {
	s := newAppsScenario(t)
	wiki := s.mustCreate(core.NewObject("key", "wiki", "name", "Wiki", "launchUrl", "https://wiki.acme.test/login",
		"visibility", "everyone", "category", "Knowledge"))
	ci := s.mustCreate(core.NewObject("key", "ci", "name", "CI", "launchUrl", "https://ci.acme.test"))
	payroll := s.mustCreate(core.NewObject("key", "payroll", "name", "Payroll", "launchUrl", "https://payroll.acme.test"))
	s.mustAssign(core.NewObject("appId", ci.Get("id"), "subjectType", "group", "subjectId", s.engineering.Get("id")))
	s.mustAssign(core.NewObject("appId", payroll.Get("id"), "subjectType", "identity", "subjectId", s.bob.Get("id"),
		"expiresAt", float64(s.now()+5*appsDay)))
	alice := s.token("alice")
	bob := s.token("bob")
	if got := s.names(alice); got != "ci:group,wiki:everyone" {
		t.Fatalf("alice's apps: %s", got)
	}
	if got := s.names(bob); got != "payroll:direct,wiki:everyone" {
		t.Fatalf("bob's apps: %s", got)
	}
	// Launching needs the app; launches are counted.
	launched, err := s.apps.Launch(s.ctx, alice, Input[apitypes.ApplicationsLaunchInput](core.NewObject("tenantId", s.tenantID, "appId", ci.Get("id"))))
	expectAppsJSON(t, appsValue(t, launched.Value, err), `{"url":"https://ci.acme.test/"}`)
	_, err = s.apps.Launch(s.ctx, alice, Input[apitypes.ApplicationsLaunchInput](core.NewObject("tenantId", s.tenantID, "appId", payroll.Get("id"))))
	appsCode(t, err, "ACCESS_DENIED")
	mine := s.mine(alice)
	if mine[0].Get("key") != "ci" || jsNumber(mine[0].Get("lastLaunchedAt")) != float64(s.now()) {
		t.Fatalf("first launcher entry: %v", mine[0])
	}
	launches := s.find("appLaunches", core.NewObject("tenantId", s.tenantID))
	if len(launches) != 1 || jsNumber(launches[0].Get("count")) != 1 || launches[0].Get("uniqueKey") != jsString(ci.Get("id"))+":"+jsString(s.alice.Get("id")) {
		t.Fatalf("launches: %v", launches)
	}
	// Assignments end.
	s.advance(6 * appsDay)
	later := s.token("bob")
	if got := s.names(later); got != "wiki:everyone" {
		t.Fatalf("bob's apps after the assignment ended: %s", got)
	}
	// Disabled apps disappear.
	owner := s.ownerSignIn()
	if _, err := s.update(owner, core.NewObject("appId", wiki.Get("id"), "enabled", false)); err != nil {
		t.Fatal(err)
	}
	if got := s.names(later); got != "" {
		t.Fatalf("apps after disabling: %s", got)
	}
	// Every change is audited.
	actions := map[string]int{}
	for _, event := range s.find("audit", core.NewObject("tenantId", s.tenantID)) {
		actions[jsString(event.Get("action"))]++
	}
	if actions["app:create"] != 3 || actions["app:assign"] != 2 || actions["app:launch"] != 1 || actions["app:update"] != 1 {
		t.Fatalf("audit actions: %v", actions)
	}
}

func TestApplicationsOfferAccessRequestsThroughARequestablePackage(t *testing.T) {
	s := newAppsScenario(t)
	pkg := s.insert("accessPackages", core.NewObject("id", ID(), "tenantId", s.tenantID, "name", "Engineering tools",
		"roleIds", []any{}, "groupIds", []any{s.engineering.Get("id")}, "requestable", true))
	ci := s.mustCreate(core.NewObject("key", "ci", "name", "CI", "launchUrl", "https://ci.acme.test", "requestPackageId", pkg.Get("id")))
	s.mustAssign(core.NewObject("appId", ci.Get("id"), "subjectType", "group", "subjectId", s.engineering.Get("id")))
	bob := s.token("bob")
	mine := s.mine(bob)
	if len(mine) != 1 || mine[0].Get("key") != "ci" || mine[0].Get("requestPackageId") != pkg.Get("id") || !isUndefined(mine[0].Get("via")) {
		t.Fatalf("bob's launcher: %v", mine)
	}
	_, err := s.create(s.owner, core.NewObject("key", "other", "name", "Other", "launchUrl", "http://insecure.example.test"))
	appsCode(t, err, "INVALID_INPUT")
	// A package that is not requestable cannot be named.
	closed := s.insert("accessPackages", core.NewObject("id", ID(), "tenantId", s.tenantID, "name", "Closed",
		"roleIds", []any{}, "groupIds", []any{}, "requestable", false))
	_, err = s.create(s.owner, core.NewObject("key", "closed", "name", "Closed", "launchUrl", "https://closed.acme.test", "requestPackageId", closed.Get("id")))
	expectError(t, err, "INVALID_INPUT", "requestPackageId must name a package members may request")
}

func TestApplicationsCheckAssignmentsAndReportUnusedOnes(t *testing.T) {
	s := newAppsScenario(t)
	crm := s.mustCreate(core.NewObject("key", "crm", "name", "CRM", "launchUrl", "https://crm.acme.test"))
	s.mustAssign(core.NewObject("appId", crm.Get("id"), "subjectType", "identity", "subjectId", s.alice.Get("id")))
	if got := s.allowed(core.NewObject("identityId", s.alice.Get("id"), "appId", crm.Get("id"))); got.Get("allowed") != true || got.Get("governed") != true {
		t.Fatalf("alice: %v", got)
	}
	if got := s.allowed(core.NewObject("identityId", s.bob.Get("id"), "appId", crm.Get("id"))); got.Get("allowed") != false {
		t.Fatalf("bob: %v", got)
	}
	expectAppsJSON(t, s.allowed(core.NewObject("identityId", s.bob.Get("id"), "oauthClientId", "not-in-catalog")), `{"allowed":true,"governed":false}`)
	_, err := s.iam.Applications.Allowed(s.ctx, core.NewObject("tenantId", s.tenantID, "identityId", s.bob.Get("id")))
	expectError(t, err, "INVALID_INPUT", "Name exactly one of appId or oauthClientId")
	s.advance(100 * appsDay)
	owner := s.ownerSignIn()
	usageOut, err := s.apps.Usage(s.ctx, owner, Input[apitypes.ApplicationsUsageInput](core.NewObject("tenantId", s.tenantID, "unusedDays", 90.0)))
	usage := appsList(t, usageOut.Value, err)
	if usage[0].Get("key") != "crm" || jsNumber(usage[0].Get("people")) != 1 || jsNumber(usage[0].Get("launchedLast30Days")) != 0 {
		t.Fatalf("usage: %v", usage[0])
	}
	unused, _ := usage[0].Get("unused").([]any)
	if len(unused) != 1 || member(unused[0], "identityId") != s.alice.Get("id") || member(unused[0], "name") != "alice@acme.test" {
		t.Fatalf("unused: %v", unused)
	}
	removed, err := s.apps.RemoveUnused(s.ctx, owner, Input[apitypes.ApplicationsRemoveUnusedInput](core.NewObject("tenantId", s.tenantID,
		"appId", crm.Get("id"), "unusedDays", 90.0)))
	expectAppsJSON(t, appsValue(t, removed.Value, err), `{"removed":1}`)
	listed, err := s.apps.ListAssignments(s.ctx, owner, Input[apitypes.ApplicationsListAssignmentsInput](core.NewObject("tenantId", s.tenantID, "appId", crm.Get("id"))))
	if got := appsList(t, listed.Value, err); len(got) != 0 {
		t.Fatalf("assignments left: %v", got)
	}
	var reason any
	for _, event := range s.find("audit", core.NewObject("tenantId", s.tenantID)) {
		if event.Get("action") == "app:unassign" {
			reason = member(event.Get("metadata"), "reason")
		}
	}
	if reason != "unused 90 days" {
		t.Fatalf("unassign reason %v", reason)
	}
	// Members cannot manage the catalog.
	alice := s.token("alice")
	// Expired people have no apps even before the worker disables them.
	if err := s.assign(owner, core.NewObject("appId", crm.Get("id"), "subjectType", "identity", "subjectId", s.bob.Get("id"))); err != nil {
		t.Fatal(err)
	}
	s.tx(func(ctx context.Context, tx core.IamStore) error {
		bob, err := tx.Get(ctx, "identities", jsString(s.bob.Get("id")))
		if err != nil {
			return err
		}
		_, err = tx.Put(ctx, "identities", bob.Spread(core.NewObject("expiresAt", float64(s.now()+60_000))))
		return err
	})
	s.advance(120_000)
	if got := s.allowed(core.NewObject("identityId", s.bob.Get("id"), "appId", crm.Get("id"))); got.Get("allowed") != false {
		t.Fatalf("expired bob: %v", got)
	}
	err = s.assign(alice, core.NewObject("appId", crm.Get("id"), "subjectType", "identity", "subjectId", s.alice.Get("id")))
	appsCode(t, err, "ACCESS_DENIED")
	// The check API answers the same question, under iam:applications:read.
	checked, err := s.apps.Check(s.ctx, owner, Input[apitypes.ApplicationsCheckInput](core.NewObject("tenantId", s.tenantID,
		"identityId", s.alice.Get("id"), "appId", crm.Get("id"))))
	expectAppsJSON(t, appsValue(t, checked.Value, err), `{"allowed":false,"governed":true,"appId":"`+jsString(crm.Get("id"))+`"}`)
	_, err = s.apps.Check(s.ctx, alice, Input[apitypes.ApplicationsCheckInput](core.NewObject("tenantId", s.tenantID,
		"identityId", s.alice.Get("id"), "appId", crm.Get("id"))))
	appsCode(t, err, "ACCESS_DENIED")
}

func TestApplicationsKeepTheCatalogHonest(t *testing.T) {
	s := newAppsScenario(t)
	_, err := s.create(s.owner, core.NewObject("key", "x", "name", "X"))
	expectError(t, err, "INVALID_INPUT", "launchUrl is required")
	_, err = s.create(s.owner, core.NewObject("key", "Bad Key", "name", "X", "launchUrl", "https://x.acme.test"))
	expectError(t, err, "INVALID_INPUT", "App keys use lowercase letters, digits, dots, underscores or hyphens")
	carol := s.memberIdentity("carol")
	wiki := s.mustCreate(core.NewObject("key", "wiki", "name", "Wiki", "launchUrl", "https://wiki.acme.test", "ownerIds", []any{carol.Get("id")}))
	expectAppsJSON(t, wiki.Get("ownerIds"), `["`+jsString(carol.Get("id"))+`"]`)
	_, err = s.create(s.owner, core.NewObject("key", "wiki", "name", "Wiki again", "launchUrl", "https://wiki.acme.test"))
	expectError(t, err, "CONFLICT", "An app with this key exists")
	_, err = s.update(s.owner, core.NewObject("appId", wiki.Get("id"), "key", "renamed"))
	expectError(t, err, "INVALID_INPUT", "An app key cannot change")
	// A deleted owner never blocks disabling the app, and leaves the owner list (identities.delete releases them).
	s.tx(func(ctx context.Context, tx core.IamStore) error {
		if err := ReleaseAppRecordsOf(ctx, tx, carol); err != nil {
			return err
		}
		return tx.Delete(ctx, "identities", jsString(carol.Get("id")))
	})
	disabled := must(s.update(s.owner, core.NewObject("appId", wiki.Get("id"), "enabled", false)))
	if disabled.Get("enabled") != false {
		t.Fatalf("disabled: %v", disabled)
	}
	expectAppsJSON(t, disabled.Get("ownerIds"), `[]`)
	must(s.update(s.owner, core.NewObject("appId", wiki.Get("id"), "enabled", true)))
	// Group assignments go with the group (groups.delete releases them).
	temp := s.group("Temp")
	s.mustAssign(core.NewObject("appId", wiki.Get("id"), "subjectType", "group", "subjectId", temp.Get("id")))
	s.mustAssign(core.NewObject("appId", wiki.Get("id"), "subjectType", "identity", "subjectId", s.alice.Get("id")))
	s.tx(func(ctx context.Context, tx core.IamStore) error {
		if err := ReleaseGroupApps(ctx, tx, s.tenantID, jsString(temp.Get("id"))); err != nil {
			return err
		}
		return tx.Delete(ctx, "groups", jsString(temp.Get("id")))
	})
	listed, err := s.apps.ListAssignments(s.ctx, s.owner, Input[apitypes.ApplicationsListAssignmentsInput](core.NewObject("tenantId", s.tenantID)))
	assignments := appsList(t, listed.Value, err)
	if len(assignments) != 1 || assignments[0].Get("subjectType") != "identity" || assignments[0].Get("subjectName") != "alice@acme.test" {
		t.Fatalf("assignments: %v", assignments)
	}
	// A per-app administrator (assign on this app only) sees no addresses and can remove single assignments.
	s.role("Wiki admin", obj(t, `{"version":1,"statements":[`+
		`{"effect":"allow","actions":["iam:applications:assign","iam:applications:read"],"resources":["iam/`+jsString(wiki.Get("id"))+`"]},`+
		`{"effect":"allow","actions":["iam:applications:read"],"resources":["iam/`+s.tenantID+`"]}]}`), s.bob.Get("id"))
	bob := s.token("bob")
	seenOut, err := s.apps.ListAssignments(s.ctx, bob, Input[apitypes.ApplicationsListAssignmentsInput](core.NewObject("tenantId", s.tenantID, "appId", wiki.Get("id"))))
	seen := appsList(t, seenOut.Value, err)
	if len(seen) != 1 || !isUndefined(seen[0].Get("subjectName")) {
		t.Fatalf("seen by the app admin: %v", seen)
	}
	usageOut, err := s.apps.Usage(s.ctx, bob, Input[apitypes.ApplicationsUsageInput](core.NewObject("tenantId", s.tenantID)))
	for _, item := range member(appsList(t, usageOut.Value, err)[0], "unused").([]any) {
		if !isUndefined(member(item, "name")) {
			t.Fatalf("the app admin sees a name: %v", item)
		}
	}
	_, err = s.apps.Create(s.ctx, bob, Input[apitypes.ApplicationsCreateInput](core.NewObject("tenantId", s.tenantID, "key", "mine",
		"name", "Mine", "launchUrl", "https://mine.acme.test")))
	appsCode(t, err, "ACCESS_DENIED")
	removed, err := s.apps.Unassign(s.ctx, bob, Input[apitypes.ApplicationsUnassignInput](core.NewObject("tenantId", s.tenantID, "assignmentId", seen[0].Get("id"))))
	expectAppsJSON(t, appsValue(t, removed.Value, err), `{"removed":true}`)
	_, err = s.apps.Unassign(s.ctx, s.owner, Input[apitypes.ApplicationsUnassignInput](core.NewObject("tenantId", s.tenantID, "assignmentId", seen[0].Get("id"))))
	appsCode(t, err, "NOT_FOUND")
	// Launches are refused while an administrator views as the person.
	must(s.update(s.owner, core.NewObject("appId", wiki.Get("id"), "visibility", "everyone")))
	s.tx(func(ctx context.Context, tx core.IamStore) error {
		tenant, err := tx.Get(ctx, "tenants", s.tenantID)
		if err != nil {
			return err
		}
		_, err = tx.Put(ctx, "tenants", tenant.Spread(core.NewObject("authPolicy", core.NewObject("allowImpersonation", true))))
		return err
	})
	actor, err := s.iam.Auth.Authenticate(s.ctx, s.ownerSignIn())
	if err != nil {
		t.Fatal(err)
	}
	var viewing *core.Object
	s.tx(func(ctx context.Context, tx core.IamStore) (err error) {
		target, err := tx.Get(ctx, "identities", jsString(s.alice.Get("id")))
		if err != nil {
			return err
		}
		viewing, err = s.iam.Auth.IssueImpersonationSession(ctx, tx, actor, target, 15*60_000)
		return err
	})
	_, err = s.apps.Launch(s.ctx, core.CredentialInput{Token: jsString(viewing.Get("token"))},
		Input[apitypes.ApplicationsLaunchInput](core.NewObject("tenantId", s.tenantID, "appId", wiki.Get("id"))))
	appsCode(t, err, "IMPERSONATION_RESTRICTED")
	// The launcher is for people signed in to their organization.
	_, err = s.apps.Mine(s.ctx, s.owner, Input[apitypes.ApplicationsMineInput](core.NewObject("tenantId", s.rootTenantID)))
	expectError(t, err, "ACCESS_DENIED", "The launcher is for people signed in to their organization")
}

func TestApplicationsGovernOAuthClients(t *testing.T) {
	s := newAppsScenario(t)
	// A client of the organization, as the OAuth provider registers it.
	clientID := "crm-client"
	s.insert("oauthClients", core.NewObject("id", "crm-client-row", "tenantId", s.tenantID, "clientId", clientID, "revoked", false))
	crm := s.mustCreate(core.NewObject("key", "crm", "name", "CRM", "launchUrl", "https://crm.acme.test", "oauthClientId", clientID))
	if crm.Get("kind") != "oidc" || crm.Get("oauthClientId") != clientID {
		t.Fatalf("crm: %v", crm)
	}
	_, err := s.create(s.owner, core.NewObject("key", "crm2", "name", "CRM again", "launchUrl", "https://crm.acme.test",
		"oauthClientId", clientID, "visibility", "everyone"))
	expectError(t, err, "CONFLICT", "App crm already governs this OAuth client")
	_, err = s.create(s.owner, core.NewObject("key", "crm3", "name", "CRM elsewhere", "launchUrl", "https://crm.acme.test",
		"oauthClientId", "no-such-client"))
	expectError(t, err, "INVALID_INPUT", "oauthClientId must name an OAuth client of this organization")
	s.mustAssign(core.NewObject("appId", crm.Get("id"), "subjectType", "identity", "subjectId", s.alice.Get("id")))
	host := s.iam.ProtocolHost.(*ProtocolHost)
	gate := func(identityID any, clientID string) bool {
		t.Helper()
		return must(host.ClientAllowed(s.ctx, jsString(identityID), s.tenantID, clientID))
	}
	if !gate(s.alice.Get("id"), clientID) || gate(s.bob.Get("id"), clientID) || !gate(s.bob.Get("id"), "some-other-client") {
		t.Fatal("the provider gate answered wrongly")
	}
	// Disabling keeps refusing; releasing the client is explicit.
	must(s.update(s.owner, core.NewObject("appId", crm.Get("id"), "enabled", false)))
	if gate(s.alice.Get("id"), clientID) {
		t.Fatal("a disabled app still admits alice")
	}
	_, err = s.apps.Delete(s.ctx, s.owner, Input[apitypes.ApplicationsDeleteInput](core.NewObject("tenantId", s.tenantID, "appId", crm.Get("id"))))
	expectError(t, err, "CONFLICT", "CRM decides who may sign in to OAuth client crm-client; without it everyone of the organization may. Pass releaseClient: true to confirm.")
	_, err = s.update(s.owner, core.NewObject("appId", crm.Get("id"), "oauthClientId", ""))
	appsCode(t, err, "CONFLICT")
	deleted, err := s.apps.Delete(s.ctx, s.owner, Input[apitypes.ApplicationsDeleteInput](core.NewObject("tenantId", s.tenantID,
		"appId", crm.Get("id"), "releaseClient", true)))
	expectAppsJSON(t, appsValue(t, deleted.Value, err), `{"deleted":true}`)
	if !gate(s.bob.Get("id"), clientID) {
		t.Fatal("a released client is still governed")
	}
	if left := s.find("appAssignments", core.NewObject("tenantId", s.tenantID)); len(left) != 0 {
		t.Fatalf("assignments outlived their app: %v", left)
	}
}

func TestApplicationsListCountsLiveAssignmentsAndRecentLaunches(t *testing.T) {
	s := newAppsScenario(t)
	beta := s.mustCreate(core.NewObject("key", "beta", "name", "Beta", "launchUrl", "https://beta.acme.test", "visibility", "everyone",
		"description", "  The beta  ", "logoUrl", "http://localhost:4000/logo.png"))
	if beta.Get("description") != "The beta" || beta.Get("logoUrl") != "http://localhost:4000/logo.png" {
		t.Fatalf("beta: %v", beta)
	}
	alpha := s.mustCreate(core.NewObject("key", "alpha", "name", "Alpha", "launchUrl", "https://alpha.acme.test"))
	s.mustAssign(core.NewObject("appId", alpha.Get("id"), "subjectType", "identity", "subjectId", s.alice.Get("id"),
		"expiresAt", float64(s.now()+appsDay)))
	s.mustAssign(core.NewObject("appId", alpha.Get("id"), "subjectType", "group", "subjectId", s.engineering.Get("id")))
	alice := s.token("alice")
	if _, err := s.apps.Launch(s.ctx, alice, Input[apitypes.ApplicationsLaunchInput](core.NewObject("tenantId", s.tenantID, "appId", beta.Get("id")))); err != nil {
		t.Fatal(err)
	}
	listOut, err := s.apps.List(s.ctx, s.owner, Input[apitypes.ApplicationsListInput](core.NewObject("tenantId", s.tenantID)))
	list := appsList(t, listOut.Value, err)
	if len(list) != 2 || list[0].Get("key") != "alpha" || jsNumber(list[0].Get("assignments")) != 2 ||
		list[1].Get("key") != "beta" || jsNumber(list[1].Get("launchedLast30Days")) != 1 {
		t.Fatalf("list: %v", list)
	}
	// The direct assignment ended; the group one stays; beta's launch is older than 30 days.
	s.advance(31 * appsDay)
	listOut, err = s.apps.List(s.ctx, s.ownerSignIn(), Input[apitypes.ApplicationsListInput](core.NewObject("tenantId", s.tenantID)))
	list = appsList(t, listOut.Value, err)
	if jsNumber(list[0].Get("assignments")) != 1 || jsNumber(list[1].Get("launchedLast30Days")) != 0 {
		t.Fatalf("list later: %v", list)
	}
	// Plain http is refused for apps outside the local machine, and credentials in URLs always.
	_, err = s.create(s.ownerSignIn(), core.NewObject("key", "creds", "name", "Creds", "launchUrl", "https://user:pass@x.acme.test"))
	expectError(t, err, "INVALID_INPUT", "launchUrl cannot carry credentials")
	_, err = s.create(s.ownerSignIn(), core.NewObject("key", "rel", "name", "Rel", "launchUrl", "/relative"))
	expectError(t, err, "INVALID_INPUT", "launchUrl must be an absolute URL")
	_, err = s.create(s.ownerSignIn(), core.NewObject("key", "vis", "name", "Vis", "launchUrl", "https://vis.acme.test", "visibility", "some"))
	expectError(t, err, "INVALID_INPUT", "visibility must be 'everyone' or 'assigned'")
}

func TestApplicationURLRules(t *testing.T) {
	for _, item := range []struct {
		base  string
		local bool
	}{{"http://localhost:3000", true}, {"http://127.0.0.1", true}, {"http://[::1]:8080", true}, {"https://iam.example.com", false}, {"", false}, {"not a url", false}} {
		if got, _ := LocalDeployment(item.base); got != item.local {
			t.Errorf("LocalDeployment(%q) = %v", item.base, got)
		}
	}
	if got, err := AppURL("https://Wiki.Example.test", "launchUrl", false); err != nil || got != "https://wiki.example.test/" {
		t.Errorf("AppURL normalizes: %q %v", got, err)
	}
	if _, err := AppURL("http://localhost:4000", "launchUrl", false); err == nil {
		t.Error("http on the local machine needs a local deployment")
	}
	if got, err := AppURL("http://localhost:4000/x", "logoUrl", true); err != nil || got != "http://localhost:4000/x" {
		t.Errorf("AppURL local: %q %v", got, err)
	}
	_, err := AppURL("http://example.test", "logoUrl", true)
	expectError(t, err, "INVALID_INPUT", "logoUrl must use https")
	if _, err := AppKey("a" + strings.Repeat("b", 64)); err == nil {
		t.Error("a 65-character key was accepted")
	}
	if key, err := AppKey("my-app.v2_x"); err != nil || key != "my-app.v2_x" {
		t.Errorf("AppKey: %q %v", key, err)
	}
}
