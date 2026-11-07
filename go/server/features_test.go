package server

// Port of tests/feature-flags.test.ts: platform and tenant feature flags, precedence (kill switch, targets, overrides,
// locks, rollouts, defaults), the `tenant.features` policy context key, access rules and the audit trail. The
// organization fixture seeds its tenants and owners directly (the tenants API is ported separately) and drives the
// features API, `iam.features` and the HTTP transport.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// flagFixtureStart is the fixture's starting clock: 2026-01-01T13:00:00Z.
const flagFixtureStart = 1_767_272_400_000

// flagFixture is a bootstrapped platform with one organization ("Acme") and its owner, after
// tests/support/organization.ts organizationFixture: the clock is controllable and sessions last seven days.
type flagFixture struct {
	*iamFixture
	clock       *atomic.Int64
	rootID      string
	tenantID    string
	rootCred    core.CredentialInput
	ownerCred   core.CredentialInput
	ownerID     string
	authorityID string
}

func newFlagFixture(t *testing.T, mutate func(options *BetterIamOptions)) *flagFixture {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(flagFixtureStart)
	week := int64(7 * 86400000)
	base := newIam(t, "http://localhost:3000", func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}}
		options.ResolveResource = func(ctx context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			return &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID, Attributes: core.NewObject()}, nil
		}
		options.WallClock = clock.Load
		options.Authentication = &auth.Options{Now: clock.Load, SessionLifetimeMs: &week, SessionIdleTimeoutMs: &week}
		if mutate != nil {
			mutate(options)
		}
	})
	f := &flagFixture{iamFixture: base, clock: clock, rootID: base.rootTenantID()}
	f.rootCred = f.signInID(jsString(member(base.root.Get("identity"), "id")), true)
	f.tenantID = f.createTenant("Acme", "organization", f.rootID)
	f.ownerCred, f.ownerID, f.authorityID = f.addOwner(f.tenantID, "owner@acme.test", "Owner")
	return f
}

func (f *flagFixture) now() float64     { return float64(f.clock.Load()) }
func (f *flagFixture) advance(ms int64) { f.clock.Add(ms) }

func (f *flagFixture) transact(fn func(ctx context.Context, tx core.IamStore) error) {
	f.t.Helper()
	if err := f.iam.Store.Transaction(context.Background(), fn); err != nil {
		f.t.Fatal(err)
	}
}

// createTenant inserts an active tenant below parentID and returns its id.
func (f *flagFixture) createTenant(name, kind, parentID string) string {
	f.t.Helper()
	id := ID()
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, "tenants", core.NewObject("id", id, "tenantId", id, "name", name, "type", kind,
			"parentId", parentID, "status", "active", "createdAt", f.now()))
		return err
	})
	return id
}

// addOwner creates the tenant's owner with the owner role (as accepting the owner invitation does) and signs in.
func (f *flagFixture) addOwner(tenantID, email, name string) (core.CredentialInput, string, string) {
	f.t.Helper()
	var ownerID, authorityID string
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		realm, err := tx.Get(ctx, "tenants", tenantID)
		if err != nil {
			return err
		}
		identity, err := f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{TenantID: tenantID, Email: email, Name: name,
			Password: "a strong " + name + " password", HasPassword: true, Owner: true, EmailVerified: true})
		if err != nil {
			return err
		}
		authority, err := tx.Insert(ctx, "grantAuthorities", core.NewObject("id", ID(), "tenantId", tenantID,
			"identityId", identity.Get("id"), "ceiling", All(), "revoked", false))
		if err != nil {
			return err
		}
		ownerID, authorityID = jsString(identity.Get("id")), jsString(authority.Get("id"))
		return f.iam.Context.OwnerSetup(ctx, tx, realm, identity, authority)
	})
	return f.signInID(ownerID, false), ownerID, authorityID
}

// member creates a person in the organization without any grants.
func (f *flagFixture) member(name string) *core.Object {
	f.t.Helper()
	var identity *core.Object
	f.transact(func(ctx context.Context, tx core.IamStore) (err error) {
		identity, err = f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{TenantID: f.tenantID,
			Email: name + "@acme.test", Name: name, Password: "a strong " + name + " password", HasPassword: true, EmailVerified: true})
		return err
	})
	return identity
}

// signInID issues a session for an identity and returns its credential.
func (f *flagFixture) signInID(identityID string, mfa bool) core.CredentialInput {
	f.t.Helper()
	var token string
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		identity, err := tx.Get(ctx, "identities", identityID)
		if err != nil {
			return err
		}
		issued, err := f.iam.Auth.IssueSession(ctx, tx, identity, auth.IssueSessionOptions{Mfa: mfa, Method: "password"})
		if err != nil {
			return err
		}
		token = jsString(issued.Get("token"))
		return nil
	})
	return core.CredentialInput{Token: token}
}

// project creates a project under Acme with its own owner.
func (f *flagFixture) project(name string) (string, core.CredentialInput) {
	f.t.Helper()
	id := f.createTenant(name, "project", f.tenantID)
	credential, _, _ := f.addOwner(id, strings.ToLower(name)+"@acme.test", name+" owner")
	return id, credential
}

// auditActions lists the audit events whose action starts with prefix.
func (f *flagFixture) auditEvents(tenantID, prefix string) []*core.Object {
	f.t.Helper()
	events, err := f.iam.Store.Find(context.Background(), "audit", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []*core.Object
	for _, event := range events {
		if strings.HasPrefix(jsString(event.Get("action")), prefix) {
			out = append(out, event)
		}
	}
	return out
}

// body is a request body from a JSON template.
func (f *flagFixture) body(format string, args ...any) *core.Object {
	f.t.Helper()
	return obj(f.t, fmt.Sprintf(format, args...))
}

// answer fails the test on an error and returns the answer.
func flagAnswer[T any](t *testing.T, out Out[T], err error) any {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return out.Value
}

// asObject is the answer as an object.
func asObject(t *testing.T, value any) *core.Object {
	t.Helper()
	object, ok := value.(*core.Object)
	if !ok {
		t.Fatalf("expected an object, got %T %v", value, value)
	}
	return object
}

// asList is the answer as a list of objects.
func asList(t *testing.T, value any) []*core.Object {
	t.Helper()
	var out []*core.Object
	switch list := value.(type) {
	case []any:
		for _, item := range list {
			out = append(out, asObject(t, item))
		}
	case []*core.Object:
		out = list
	default:
		t.Fatalf("expected a list, got %T %v", value, value)
	}
	return out
}

// toJSON is JSON.stringify for comparisons.
func toJSON(t *testing.T, value any) string {
	t.Helper()
	text, _, err := core.Stringify(value)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// subsetMatches is toMatchObject: every member of expected is in actual with a matching value (arrays match
// element by element).
func subsetMatches(expected, actual any) bool {
	switch want := expected.(type) {
	case *core.Object:
		have, ok := actual.(*core.Object)
		if !ok || have == nil {
			return false
		}
		matched := true
		want.Entries(func(key string, value any) bool {
			got, present := have.Lookup(key)
			if !present || !subsetMatches(value, got) {
				matched = false
			}
			return matched
		})
		return matched
	case []any:
		have, ok := actual.([]any)
		if !ok || len(have) != len(want) {
			return false
		}
		for index := range want {
			if !subsetMatches(want[index], have[index]) {
				return false
			}
		}
		return true
	default:
		return core.Normalize(expected) == core.Normalize(actual)
	}
}

// expectMatch is expect(actual).toMatchObject(JSON).
func expectMatch(t *testing.T, actual any, expected string) {
	t.Helper()
	if !subsetMatches(parse(t, expected), actual) {
		t.Errorf("expected %s to match %s", toJSON(t, actual), expected)
	}
}

func (f *flagFixture) createFlag(credential core.CredentialInput, input *core.Object) (any, error) {
	out, err := f.iam.API.Features.Create(context.Background(), credential, Input[apitypes.FeaturesCreateInput](input))
	return out.Value, err
}

func (f *flagFixture) updateFlag(credential core.CredentialInput, input *core.Object) (any, error) {
	out, err := f.iam.API.Features.Update(context.Background(), credential, Input[apitypes.FeaturesUpdateInput](input))
	return out.Value, err
}

func (f *flagFixture) setTarget(credential core.CredentialInput, input *core.Object) (any, error) {
	out, err := f.iam.API.Features.SetTarget(context.Background(), credential, Input[apitypes.FeaturesSetTargetInput](input))
	return out.Value, err
}

func (f *flagFixture) setOverride(credential core.CredentialInput, input *core.Object) (any, error) {
	out, err := f.iam.API.Features.SetOverride(context.Background(), credential, Input[apitypes.FeaturesSetOverrideInput](input))
	return out.Value, err
}

func (f *flagFixture) listFlags(credential core.CredentialInput, tenantID string) (*core.Object, error) {
	out, err := f.iam.API.Features.List(context.Background(), credential, Input[apitypes.FeaturesListInput](core.NewObject("tenantId", tenantID)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *flagFixture) evaluateAPI(credential core.CredentialInput, input *core.Object) (any, error) {
	out, err := f.iam.API.Features.Evaluate(context.Background(), credential, Input[apitypes.FeaturesEvaluateInput](input))
	return out.Value, err
}

func (f *flagFixture) listTargets(credential core.CredentialInput, tenantID, key string) []*core.Object {
	f.t.Helper()
	out, err := f.iam.API.Features.ListTargets(context.Background(), credential, Input[apitypes.FeaturesListTargetsInput](core.NewObject("tenantId", tenantID, "key", key)))
	return asList(f.t, flagAnswer(f.t, out, err))
}

// must fails the test on an error.
func (f *flagFixture) must(value any, err error) any {
	f.t.Helper()
	if err != nil {
		f.t.Fatalf("unexpected error: %v", err)
	}
	return value
}

func (f *flagFixture) isEnabled(tenantID, key string) bool {
	f.t.Helper()
	enabled, err := f.iam.Features.IsEnabled(context.Background(), tenantID, key)
	if err != nil {
		f.t.Fatal(err)
	}
	return enabled
}

// evaluateOne is `(await iam.features.evaluate(tenantId, { keys: [key] }))[0]`.
func (f *flagFixture) evaluateOne(tenantID, key string) *core.Object {
	f.t.Helper()
	evaluations, err := f.iam.Features.Evaluate(context.Background(), tenantID, core.NewObject("keys", []any{key}))
	if err != nil {
		f.t.Fatal(err)
	}
	if len(evaluations) != 1 {
		f.t.Fatalf("expected one evaluation, got %d", len(evaluations))
	}
	return evaluations[0]
}

func TestFeaturesPlatformFlagsResolveDefaultsOverridesTargetsLocksAndKillSwitch(t *testing.T) {
	f := newFlagFixture(t, nil)
	created := f.must(f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"new-billing","description":"The new billing pages","tenantOverridable":true}`, f.rootID)))
	expectMatch(t, created, `{"key":"new-billing","scope":"platform","defaultValue":false,"tenantOverridable":true,"killSwitch":false,"internal":false}`)
	if f.isEnabled(f.tenantID, "new-billing") {
		t.Error("the flag is off by default")
	}
	expectMatch(t, f.evaluateOne(f.tenantID, "new-billing"), `{"reason":"DEFAULT","overridable":true,"locked":false}`)

	// The organization turns it on for itself.
	chosen := f.must(f.setOverride(f.ownerCred, f.body(`{"tenantId":%q,"key":"new-billing","value":true}`, f.tenantID)))
	expectMatch(t, chosen, fmt.Sprintf(`{"value":true,"reason":"OVERRIDE","decidedBy":%q}`, f.tenantID))
	evaluated := f.must(f.evaluateAPI(f.ownerCred, core.NewObject("tenantId", f.tenantID)))
	if got, want := toJSON(t, evaluated), fmt.Sprintf(`{"tenantId":%q,"flags":{"new-billing":true}}`, f.tenantID); got != want {
		t.Errorf("evaluate: %s, want %s", got, want)
	}

	// An unlocked platform target on the same tenant does not beat the tenant's own choice...
	f.must(f.setTarget(f.rootCred, f.body(`{"tenantId":%q,"key":"new-billing","targetTenantId":%q,"value":false}`, f.rootID, f.tenantID)))
	if !f.isEnabled(f.tenantID, "new-billing") {
		t.Error("an unlocked target beat the tenant's override")
	}
	// ...a locked one does, and refuses new overrides until it is lifted.
	f.must(f.setTarget(f.rootCred, f.body(`{"tenantId":%q,"key":"new-billing","targetTenantId":%q,"value":false,"locked":true,"note":"Invoice migration pending"}`, f.rootID, f.tenantID)))
	expectMatch(t, f.evaluateOne(f.tenantID, "new-billing"), `{"value":false,"reason":"TARGET","locked":true,"overridable":false}`)
	_, err := f.setOverride(f.ownerCred, f.body(`{"tenantId":%q,"key":"new-billing","value":true}`, f.tenantID))
	expectCode(t, err, "FEATURE_LOCKED")
	listed := f.must(f.listFlags(f.ownerCred, f.tenantID)).(*core.Object)
	flags := asList(t, listed.Get("flags"))
	if len(flags) != 1 {
		t.Fatalf("listed flags: %s", toJSON(t, listed))
	}
	expectMatch(t, flags[0], fmt.Sprintf(`{"key":"new-billing","scope":"platform","definedBy":%q,"override":{"value":true},"target":{"value":false,"locked":true}}`, f.rootID))
	// Tenants see neither the platform's settings nor its note.
	if flags[0].Has("definition") {
		t.Error("a tenant saw the platform flag's definition")
	}
	if strings.Contains(toJSON(t, listed), "Invoice migration") {
		t.Error("a tenant saw the target's note")
	}

	f.must(f.setTarget(f.rootCred, f.body(`{"tenantId":%q,"key":"new-billing","targetTenantId":%q,"value":null}`, f.rootID, f.tenantID)))
	if !f.isEnabled(f.tenantID, "new-billing") {
		t.Error("removing the target did not restore the override")
	}

	// The kill switch wins over everything, and lifting it restores the previous state.
	f.must(f.updateFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"new-billing","killSwitch":true}`, f.rootID)))
	expectMatch(t, f.evaluateOne(f.tenantID, "new-billing"), `{"value":false,"reason":"KILL_SWITCH"}`)
	f.must(f.updateFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"new-billing","killSwitch":false}`, f.rootID)))
	if !f.isEnabled(f.tenantID, "new-billing") {
		t.Error("lifting the kill switch did not restore the override")
	}

	// Flags that do not allow overrides refuse them; withdrawing a choice is always allowed.
	f.must(f.updateFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"new-billing","tenantOverridable":false}`, f.rootID)))
	if f.isEnabled(f.tenantID, "new-billing") {
		t.Error("an override applied to a flag that no longer allows them")
	}
	_, err = f.setOverride(f.ownerCred, f.body(`{"tenantId":%q,"key":"new-billing","value":true}`, f.tenantID))
	expectCode(t, err, "FEATURE_LOCKED")
	f.must(f.setOverride(f.ownerCred, f.body(`{"tenantId":%q,"key":"new-billing","value":null}`, f.tenantID)))

	// Unknown keys are off.
	if f.isEnabled(f.tenantID, "nothing-here") {
		t.Error("an unknown key is on")
	}
	unknown := f.must(f.evaluateAPI(f.ownerCred, f.body(`{"tenantId":%q,"keys":["nothing-here"]}`, f.tenantID)))
	if got, want := toJSON(t, unknown), fmt.Sprintf(`{"tenantId":%q,"flags":{"nothing-here":false}}`, f.tenantID); got != want {
		t.Errorf("evaluate unknown: %s, want %s", got, want)
	}
}

func TestFeaturesValidateKeysAndSettings(t *testing.T) {
	f := newFlagFixture(t, nil)
	for _, key := range []string{"Bad", "1st", "a--b", "trailing-", strings.Repeat("x", 65), "__proto__"} {
		_, err := f.createFlag(f.rootCred, core.NewObject("tenantId", f.rootID, "key", key))
		expectCode(t, err, "INVALID_INPUT")
	}
	_, err := f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"on-with-rollout","defaultValue":true,"rolloutPercentage":10}`, f.rootID))
	expectCode(t, err, "INVALID_INPUT")
	_, err = f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"hidden","internal":true,"tenantOverridable":true}`, f.rootID))
	expectCode(t, err, "INVALID_INPUT")
	_, err = f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"extra","colour":"blue"}`, f.rootID))
	expectCode(t, err, "INVALID_INPUT")
	f.must(f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"reports.v2"}`, f.rootID)))
	_, err = f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"reports.v2"}`, f.rootID))
	expectCode(t, err, "CONFLICT")
	_, err = f.updateFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"missing"}`, f.rootID))
	expectCode(t, err, "NOT_FOUND")
	// A target must sit below the defining tenant.
	_, err = f.setTarget(f.rootCred, f.body(`{"tenantId":%q,"key":"reports.v2","targetTenantId":%q,"value":true}`, f.rootID, f.rootID))
	expectCode(t, err, "INVALID_INPUT")
}

func TestFeaturesTenantFlagsReachTheSubtreeAndAncestorsOwnTheirKeys(t *testing.T) {
	f := newFlagFixture(t, nil)
	apolloID, apollo := f.project("Apollo")
	created := f.must(f.createFlag(f.ownerCred, f.body(`{"tenantId":%q,"key":"beta-reports","tenantOverridable":true}`, f.tenantID)))
	expectMatch(t, created, fmt.Sprintf(`{"scope":"tenant","tenantId":%q}`, f.tenantID))
	f.must(f.setTarget(f.ownerCred, f.body(`{"tenantId":%q,"key":"beta-reports","targetTenantId":%q,"value":true}`, f.tenantID, apolloID)))
	if !f.isEnabled(apolloID, "beta-reports") || f.isEnabled(f.tenantID, "beta-reports") {
		t.Error("the target applies to the project only")
	}
	// The flag never reaches the platform tenant.
	if f.isEnabled(f.rootID, "beta-reports") {
		t.Error("an organization's flag reached the platform tenant")
	}
	// An organization cannot target outside its subtree or itself.
	for _, target := range []string{f.rootID, f.tenantID} {
		_, err := f.setTarget(f.ownerCred, f.body(`{"tenantId":%q,"key":"beta-reports","targetTenantId":%q,"value":true}`, f.tenantID, target))
		expectCode(t, err, "INVALID_INPUT")
	}

	// The project sees the organization's flag and its target, and may override it.
	listed := f.must(f.listFlags(apollo, apolloID)).(*core.Object)
	expectMatch(t, asList(t, listed.Get("flags"))[0], fmt.Sprintf(`{"key":"beta-reports","scope":"tenant","definedBy":%q,"target":{"value":true,"locked":false},"evaluation":{"value":true,"reason":"TARGET","decidedBy":%q}}`, f.tenantID, apolloID))
	opted := f.must(f.setOverride(apollo, f.body(`{"tenantId":%q,"key":"beta-reports","value":false}`, apolloID)))
	expectMatch(t, opted, `{"value":false,"reason":"OVERRIDE"}`)
	// The defining tenant changes its own flag through update, not an override.
	_, err := f.setOverride(f.ownerCred, f.body(`{"tenantId":%q,"key":"beta-reports","value":true}`, f.tenantID))
	expectCode(t, err, "INVALID_INPUT")
	var entries []string
	for _, entry := range f.listTargets(f.ownerCred, f.tenantID, "beta-reports") {
		entries = append(entries, fmt.Sprintf("%v %v %v %v", entry.Get("source"), entry.Get("tenantName"), entry.Get("value"), entry.Get("active")))
	}
	sort.Strings(entries)
	if got := strings.Join(entries, "; "); got != "override Apollo false true; target Apollo true true" {
		t.Errorf("targets: %s", got)
	}

	// Keys an ancestor defines cannot be defined again below it...
	f.must(f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"sso"}`, f.rootID)))
	_, err = f.createFlag(f.ownerCred, f.body(`{"tenantId":%q,"key":"sso"}`, f.tenantID))
	expectCode(t, err, "CONFLICT")
	_, err = f.createFlag(apollo, f.body(`{"tenantId":%q,"key":"beta-reports"}`, apolloID))
	expectCode(t, err, "CONFLICT")
	// ...and a platform flag created later shadows a tenant's flag of the same key: tenants cannot switch a
	// platform-gated feature on for themselves.
	f.must(f.createFlag(f.ownerCred, f.body(`{"tenantId":%q,"key":"audit-export","defaultValue":true}`, f.tenantID)))
	if !f.isEnabled(f.tenantID, "audit-export") {
		t.Error("the tenant's own flag is on by default")
	}
	f.must(f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"audit-export"}`, f.rootID)))
	if f.isEnabled(f.tenantID, "audit-export") {
		t.Error("a tenant flag beat the platform flag of the same key")
	}
	shadowed := f.must(f.listFlags(f.ownerCred, f.tenantID)).(*core.Object)
	var keys []string
	for _, entry := range asList(t, shadowed.Get("shadowed")) {
		keys = append(keys, jsString(entry.Get("key")))
	}
	if strings.Join(keys, ",") != "audit-export" {
		t.Errorf("shadowed: %v", keys)
	}
	var found *core.Object
	for _, entry := range asList(t, shadowed.Get("flags")) {
		if entry.Get("key") == "audit-export" {
			found = entry
		}
	}
	expectMatch(t, found, fmt.Sprintf(`{"scope":"platform","definedBy":%q}`, f.rootID))
}

func TestFeaturesOrganizationOverridesPlatformFlagForItsProjects(t *testing.T) {
	f := newFlagFixture(t, nil)
	apolloID, apollo := f.project("Apollo")
	f.must(f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"new-editor","tenantOverridable":true}`, f.rootID)))
	f.must(f.setOverride(f.ownerCred, f.body(`{"tenantId":%q,"key":"new-editor","value":true}`, f.tenantID)))
	expectMatch(t, f.evaluateOne(apolloID, "new-editor"), fmt.Sprintf(`{"value":true,"reason":"OVERRIDE","decidedBy":%q}`, f.tenantID))
	// A platform target on the project is closer than the organization's choice.
	f.must(f.setTarget(f.rootCred, f.body(`{"tenantId":%q,"key":"new-editor","targetTenantId":%q,"value":false}`, f.rootID, apolloID)))
	if f.isEnabled(apolloID, "new-editor") {
		t.Error("the organization's override beat the closer target")
	}
	// A lock on the organization silences overrides in its whole subtree but not the platform's own closer target.
	f.must(f.setTarget(f.rootCred, f.body(`{"tenantId":%q,"key":"new-editor","targetTenantId":%q,"value":true,"locked":true}`, f.rootID, f.tenantID)))
	_, err := f.setOverride(apollo, f.body(`{"tenantId":%q,"key":"new-editor","value":true}`, apolloID))
	expectCode(t, err, "FEATURE_LOCKED")
	if f.isEnabled(apolloID, "new-editor") {
		t.Error("the lock above beat the closer target")
	}
	f.must(f.setTarget(f.rootCred, f.body(`{"tenantId":%q,"key":"new-editor","targetTenantId":%q,"value":null}`, f.rootID, apolloID)))
	expectMatch(t, f.evaluateOne(apolloID, "new-editor"), fmt.Sprintf(`{"value":true,"reason":"TARGET","decidedBy":%q,"locked":true}`, f.tenantID))
}

func TestFeaturesRolloutsBucketWholeOrganizationsStably(t *testing.T) {
	f := newFlagFixture(t, nil)
	apolloID, _ := f.project("Apollo")
	f.must(f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"fast-search","rolloutPercentage":0}`, f.rootID)))
	bucket := RolloutBucket("fast-search", f.tenantID)
	if bucket < 0 || bucket >= 100 || RolloutBucket("fast-search", f.tenantID) != bucket {
		t.Fatalf("bucket %v", bucket)
	}
	previous := false
	for _, percentage := range []float64{0, 10, 25, 50, 75, 100} {
		f.must(f.updateFlag(f.rootCred, core.NewObject("tenantId", f.rootID, "key", "fast-search", "rolloutPercentage", percentage)))
		organization := f.evaluateOne(f.tenantID, "fast-search")
		child := f.evaluateOne(apolloID, "fast-search")
		if organization.Get("reason") != "ROLLOUT" || organization.Get("value") != (bucket < percentage) {
			t.Errorf("%v%%: %s", percentage, toJSON(t, organization))
		}
		// A project lands on the same side as its organization.
		if child.Get("value") != organization.Get("value") {
			t.Errorf("%v%%: the project disagrees with its organization", percentage)
		}
		if previous && organization.Get("value") != true {
			t.Errorf("%v%%: raising the percentage removed the organization", percentage)
		}
		previous = organization.Get("value") == true
	}
	if !previous {
		t.Error("100% leaves the organization out")
	}
	// Clearing the rollout falls back to the default.
	f.must(f.updateFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"fast-search","rolloutPercentage":null}`, f.rootID)))
	expectMatch(t, f.evaluateOne(f.tenantID, "fast-search"), `{"value":false,"reason":"DEFAULT"}`)
}

func TestFeaturesExposedToPoliciesAsTenantFeatures(t *testing.T) {
	f := newFlagFixture(t, func(options *BetterIamOptions) {
		// An application claiming the flag must not satisfy the condition.
		options.ResolveContext = func(context.Context, *Principal) (*core.Object, error) {
			return core.NewObject("tenant.features", []any{"exports"}), nil
		}
	})
	alice := f.member("alice")
	statement := obj(t, `{"effect":"allow","actions":["documents:read"],"resources":["*"],"conditions":{"ArrayContains":{"tenant.features":"exports"}}}`)
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		if _, err := tx.Insert(ctx, "policies", core.NewObject("id", "policy-exporter", "tenantId", f.tenantID, "name", "Exporter",
			"document", core.NewObject("version", 1.0, "statements", []any{statement}), "version", 1.0, "authorityId", f.authorityID)); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "roles", core.NewObject("id", "role-exporter", "tenantId", f.tenantID, "name", "Exporter",
			"policyIds", []any{"policy-exporter"}, "authorityId", f.authorityID)); err != nil {
			return err
		}
		_, err := tx.Insert(ctx, "bindings", core.NewObject("id", "binding-exporter", "tenantId", f.tenantID, "subjectType", "identity",
			"subjectId", alice.Get("id"), "roleId", "role-exporter", "authorityId", f.authorityID))
		return err
	})
	aliceCred := f.signInID(jsString(alice.Get("id")), false)
	canRead := func() bool {
		t.Helper()
		decision, err := f.iam.Authorize(context.Background(), AuthorizationRequest{Credential: aliceCred, TenantID: f.tenantID,
			Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "d1"}})
		if err != nil {
			t.Fatal(err)
		}
		return decision.Allowed
	}
	if canRead() {
		t.Error("allowed before the flag exists")
	}
	f.must(f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"exports"}`, f.rootID)))
	if canRead() {
		t.Error("allowed while the flag is off")
	}
	f.must(f.setTarget(f.rootCred, f.body(`{"tenantId":%q,"key":"exports","targetTenantId":%q,"value":true}`, f.rootID, f.tenantID)))
	if !canRead() {
		t.Error("denied while the flag is on")
	}
	f.must(f.updateFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"exports","killSwitch":true}`, f.rootID)))
	if canRead() {
		t.Error("allowed after the kill switch")
	}
}

func TestFeaturesContextKeyIsKnownToPolicyLint(t *testing.T) {
	document := obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"],"conditions":{"ArrayContains":{"tenant.features":"exports"}}}]}`)
	if !MentionsFeatures([]any{document}) || MentionsFeatures([]any{obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["*"],"resources":["*"]}]}`)}) {
		t.Error("mentionsFeatures")
	}
	linted, err := LintPolicy(document, nil)
	if err != nil {
		if known := iamError(t, err); known.Code == "NOT_IMPLEMENTED" {
			// policy-lint.ts is ported by another unit.
			t.Skip(known.Message)
		}
		t.Fatal(err)
	}
	if got := toJSON(t, linted); got != `{"valid":true,"warnings":[]}` {
		t.Errorf("lint: %s", got)
	}
}

func TestFeaturesAccessMembersEvaluateAdministratorsManageInternalFlagsHidden(t *testing.T) {
	f := newFlagFixture(t, nil)
	alice := f.signInID(jsString(f.member("alice").Get("id")), false)
	f.must(f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"public-beta","defaultValue":true}`, f.rootID)))
	f.must(f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"ops-hold","internal":true,"defaultValue":true}`, f.rootID)))
	evaluated := f.must(f.evaluateAPI(alice, core.NewObject("tenantId", f.tenantID)))
	if got, want := toJSON(t, evaluated), fmt.Sprintf(`{"tenantId":%q,"flags":{"public-beta":true}}`, f.tenantID); got != want {
		t.Errorf("member evaluate: %s", got)
	}
	hidden := f.must(f.evaluateAPI(alice, f.body(`{"tenantId":%q,"keys":["ops-hold"]}`, f.tenantID)))
	if got, want := toJSON(t, hidden), fmt.Sprintf(`{"tenantId":%q,"flags":{"ops-hold":false}}`, f.tenantID); got != want {
		t.Errorf("internal evaluate: %s", got)
	}
	// Trusted server code sees internal flags.
	values, err := f.iam.Features.Values(context.Background(), f.tenantID)
	if err != nil || toJSON(t, values) != `{"ops-hold":true,"public-beta":true}` {
		t.Errorf("values: %v %v", values, err)
	}
	_, err = f.evaluateAPI(alice, core.NewObject("tenantId", f.rootID))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = f.listFlags(alice, f.tenantID)
	expectCode(t, err, "ACCESS_DENIED")
	_, err = f.createFlag(alice, f.body(`{"tenantId":%q,"key":"mine"}`, f.tenantID))
	expectCode(t, err, "ACCESS_DENIED")
	// Owners do not see the platform's internal flags; root administrators do.
	ownerView := f.must(f.listFlags(f.ownerCred, f.tenantID)).(*core.Object)
	var ownerKeys []string
	for _, entry := range asList(t, ownerView.Get("flags")) {
		ownerKeys = append(ownerKeys, jsString(entry.Get("key")))
	}
	if strings.Join(ownerKeys, ",") != "public-beta" {
		t.Errorf("owner view: %v", ownerKeys)
	}
	rootView := f.must(f.listFlags(f.rootCred, f.tenantID)).(*core.Object)
	var rootKeys []string
	for _, entry := range asList(t, rootView.Get("flags")) {
		rootKeys = append(rootKeys, fmt.Sprintf("%v:%v", entry.Get("key"), member(entry.Get("definition"), "internal")))
	}
	if strings.Join(rootKeys, ",") != "ops-hold:true,public-beta:false" {
		t.Errorf("root view: %v", rootKeys)
	}
	_, err = f.setOverride(f.ownerCred, f.body(`{"tenantId":%q,"key":"ops-hold","value":false}`, f.tenantID))
	expectCode(t, err, "NOT_FOUND")

	// Over HTTP with a bearer token.
	response := f.post("http://localhost:3000", "features/evaluate", fmt.Sprintf(`{"tenantId":%q}`, f.tenantID),
		map[string]string{"authorization": "Bearer " + alice.Token})
	if response.Status != 200 {
		t.Fatalf("HTTP evaluate: %d %s", response.Status, response.Body)
	}
	if got, want := toJSON(t, jsonBody(t, response).Get("data")), fmt.Sprintf(`{"tenantId":%q,"flags":{"public-beta":true}}`, f.tenantID); got != want {
		t.Errorf("HTTP evaluate: %s", got)
	}
}

func TestFeaturesTargetsLapseDeleteCleansUpAndChangesAreAudited(t *testing.T) {
	f := newFlagFixture(t, nil)
	f.must(f.createFlag(f.rootCred, f.body(`{"tenantId":%q,"key":"trial-seats"}`, f.rootID)))
	expiresAt := f.now() + 3_600_000
	f.must(f.setTarget(f.rootCred, core.NewObject("tenantId", f.rootID, "key", "trial-seats", "targetTenantId", f.tenantID, "value", true, "expiresAt", expiresAt)))
	expectMatch(t, f.evaluateOne(f.tenantID, "trial-seats"), fmt.Sprintf(`{"value":true,"reason":"TARGET","expiresAt":%s}`, core.NumberString(expiresAt)))
	_, err := f.setTarget(f.rootCred, core.NewObject("tenantId", f.rootID, "key", "trial-seats", "targetTenantId", f.tenantID, "value", true, "expiresAt", f.now()-1))
	expectCode(t, err, "INVALID_INPUT")
	f.advance(2 * 3_600_000)
	if f.isEnabled(f.tenantID, "trial-seats") {
		t.Error("a lapsed target still applies")
	}
	lapsed := f.listTargets(f.rootCred, f.rootID, "trial-seats")
	if len(lapsed) == 0 {
		t.Fatal("no targets listed")
	}
	expectMatch(t, lapsed[0], `{"tenantName":"Acme","active":false}`)

	deleted, err := f.iam.API.Features.Delete(context.Background(), f.rootCred, Input[apitypes.FeaturesDeleteInput](f.body(`{"tenantId":%q,"key":"trial-seats"}`, f.rootID)))
	if got := toJSON(t, flagAnswer(t, deleted, err)); got != `{"success":true,"removedTargets":1}` {
		t.Errorf("delete: %s", got)
	}
	expectMatch(t, f.evaluateOne(f.tenantID, "trial-seats"), `{"value":false,"reason":"UNKNOWN"}`)
	trail := f.auditEvents(f.rootID, "feature:")
	var actions []string
	var target *core.Object
	for _, event := range trail {
		actions = append(actions, jsString(event.Get("action")))
		if event.Get("action") == "feature:target" {
			target = event
		}
	}
	sort.Strings(actions)
	if strings.Join(actions, ",") != "feature:create,feature:delete,feature:target" {
		t.Errorf("audit trail: %v", actions)
	}
	if target == nil {
		t.Fatal("no feature:target event")
	}
	expectMatch(t, target.Get("metadata"), fmt.Sprintf(`{"key":"trial-seats","targetTenantId":%q,"value":true}`, f.tenantID))
}
