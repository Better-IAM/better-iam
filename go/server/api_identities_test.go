package server

// Ports of the TypeScript tests of api/identities.ts and api/service-accounts.ts: tests/credential-hygiene.test.ts,
// tests/key-scopes-and-expiring-bindings.test.ts (API key scopes), tests/administration.test.ts (service accounts and
// identity deletion), tests/data-export.test.ts, tests/federation-import-gaps.test.ts (provider links),
// tests/impersonation.test.ts and tests/impersonation-limits.test.ts (account control), tests/manager.test.ts and
// tests/identity-expiry.test.ts. The fixtures run in the bootstrapped root tenant and seed the roles, bindings and
// groups other API groups would write (those groups are ported separately). Steps that reach a stub of another unit
// skip with the stub's name; the afterIdentityChange reconciliation (package automation) runs after the commit, so
// its stub is tolerated where the mutation itself is under test.

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const idDay = 86_400_000.0

type identitiesFixture struct {
	*iamFixture
	ctx      context.Context
	clock    *atomic.Int64
	tenantID string
	owner    *core.Object
	ownerID  string
	// rootIdentity is the bootstrapped root administrator.
	rootIdentity *core.Object
	authority    string
	mu           sync.Mutex
	mail         []auth.DeliveryMessage
}

func newIdentitiesFixture(t *testing.T, mutate func(options *BetterIamOptions)) *identitiesFixture {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(1_767_225_600_000)
	f := &identitiesFixture{ctx: context.Background(), clock: clock}
	base := newIam(t, "http://localhost:3000", func(options *BetterIamOptions) {
		options.WallClock = func() int64 { return clock.Load() }
		options.Authentication = &auth.Options{
			Now: func() int64 { return clock.Load() },
			SendEmail: func(ctx context.Context, message auth.DeliveryMessage) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.mail = append(f.mail, message)
				return nil
			},
		}
		options.Permissions = &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}}
		options.ResolveResource = func(ctx context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			return &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID, Attributes: core.NewObject()}, nil
		}
		if mutate != nil {
			mutate(options)
		}
	})
	f.iamFixture = base
	f.tenantID = base.rootTenantID()
	// The root administrator signs in with MFA only, so the tenant's owner in these tests is a second person: the
	// owner role and an unlimited authority under the root's, as an owner invitation leaves them. The root account
	// stays a root administrator (rootSignIn) but is no longer counted as an owner.
	root, _ := base.root.Get("identity").(*core.Object)
	rootID := jsString(root.Get("id"))
	rootAuthorities, err := base.iam.Store.Find(f.ctx, "grantAuthorities", core.NewObject("tenantId", f.tenantID, "identityId", rootID), nil)
	if err != nil || len(rootAuthorities) == 0 {
		t.Fatalf("root authority: %v", err)
	}
	f.rootIdentity = root
	owner := base.createIdentity("owner@example.test", "Owner", "a strong owner password")
	f.ownerID = jsString(owner.Get("id"))
	f.authority = "authority-owner"
	ownerRole := f.find("roles", core.NewObject("tenantId", f.tenantID, "uniqueKey", "system:owner"))[0]
	f.seed("grantAuthorities", core.NewObject("id", f.authority, "tenantId", f.tenantID, "identityId", f.ownerID, "ceiling", All(),
		"parentAuthorityId", rootAuthorities[0].Get("id"), "revoked", false))
	f.seed("bindings", core.NewObject("id", "binding-owner", "tenantId", f.tenantID, "subjectType", "identity", "subjectId", f.ownerID,
		"roleId", ownerRole.Get("id"), "authorityId", f.authority))
	f.seed("identities", owner.Spread(core.NewObject("owner", true)), f.get("identities", rootID).Spread(core.NewObject("owner", false)))
	f.owner = f.get("identities", f.ownerID)
	return f
}

func (f *identitiesFixture) now() float64     { return float64(f.clock.Load()) }
func (f *identitiesFixture) advance(ms int64) { f.clock.Add(ms) }

// signIn issues a user session for an identity: { token, session }.
func (f *identitiesFixture) signIn(identity *core.Object, mfa bool) (core.CredentialInput, *core.Object) {
	f.t.Helper()
	issued, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.IssueSession(ctx, tx, identity, auth.IssueSessionOptions{Mfa: mfa, Method: "password"})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	session, _ := issued.Get("session").(*core.Object)
	return core.CredentialInput{Token: jsString(issued.Get("token"))}, session
}

// ownerSignIn is a fresh owner session without MFA (an owner of the tenant, not a root principal).
func (f *identitiesFixture) ownerSignIn() core.CredentialInput {
	credential, _ := f.signIn(f.owner, false)
	return credential
}

// rootSignIn is a fresh root principal session (MFA).
func (f *identitiesFixture) rootSignIn() core.CredentialInput {
	credential, _ := f.signIn(f.rootIdentity, true)
	return credential
}

func (f *identitiesFixture) seed(collection string, records ...*core.Object) {
	f.t.Helper()
	err := f.iam.Store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		for _, record := range records {
			existing, err := tx.Get(ctx, collection, jsString(record.Get("id")))
			if err != nil {
				return err
			}
			if existing == nil {
				_, err = tx.Insert(ctx, collection, record)
			} else {
				_, err = tx.Put(ctx, collection, record)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *identitiesFixture) get(collection, id string) *core.Object {
	f.t.Helper()
	record, err := f.iam.Store.Get(f.ctx, collection, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return record
}

func (f *identitiesFixture) find(collection string, filter *core.Object) []*core.Object {
	f.t.Helper()
	records, err := f.iam.Store.Find(f.ctx, collection, filter, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return records
}

// member creates a person in the tenant (auth primitive).
func (f *identitiesFixture) member(name string) *core.Object {
	return f.createIdentity(name+"@example.test", name, "a strong "+name+" password")
}

// grant binds a role allowing actions on every resource to a subject under the owner's authority.
func (f *identitiesFixture) grant(id, subjectType, subjectID string, actions ...string) {
	f.seed("roles", core.NewObject("id", "role-"+id, "tenantId", f.tenantID, "name", "R "+id,
		"document", core.NewObject("version", 1.0, "statements", []any{core.NewObject("effect", "allow", "actions", stringsOf(actions), "resources", []any{"*"})}),
		"authorityId", f.authority))
	f.seed("bindings", core.NewObject("id", "binding-"+id, "tenantId", f.tenantID, "subjectType", subjectType, "subjectId", subjectID, "roleId", "role-"+id, "authorityId", f.authority))
}

// serviceAccount creates a service account through the API (its afterIdentityChange stub tolerated).
func (f *identitiesFixture) serviceAccount(credential core.CredentialInput, name string) *core.Object {
	f.t.Helper()
	_, err := f.iam.API.ServiceAccounts.Create(f.ctx, credential, Input[apitypes.ServiceAccountsCreateInput](core.NewObject("tenantId", f.tenantID, "name", name)))
	idAfterChange(f.t, err)
	for _, account := range f.find("identities", core.NewObject("tenantId", f.tenantID, "kind", "service")) {
		if account.Get("name") == name {
			return account
		}
	}
	f.t.Fatalf("service account %s not created", name)
	return nil
}

func (f *identitiesFixture) authorizeToken(token, action string) (core.Decision, error) {
	return f.iam.Authorize(f.ctx, AuthorizationRequest{
		Credential: core.CredentialInput{Token: token}, TenantID: f.tenantID, Action: action,
		Resource: ResourceTarget{Type: "documents", ID: "a"},
	})
}

func (f *identitiesFixture) auditActions() []string {
	var actions []string
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		actions = append(actions, jsString(event.Get("action")))
	}
	return actions
}

// stubbed reports a NOT_IMPLEMENTED error (a stub of a unit not ported yet).
func idStubbed(err error) (string, bool) {
	if iamErr, ok := asIamError(err); ok && iamErr.Code == "NOT_IMPLEMENTED" {
		return iamErr.Message, true
	}
	return "", false
}

// idSkipOnStub skips the rest of the test when a step reached another unit's stub.
func idSkipOnStub(t *testing.T, err error) {
	t.Helper()
	if message, ok := idStubbed(err); ok {
		t.Skip("blocked by a stub of another unit: " + message)
	}
}

// afterChange accepts a mutation whose only failure is the package-automation reconciliation stub that runs after
// the commit; any other error fails the test.
func idAfterChange(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if message, ok := idStubbed(err); ok && strings.Contains(message, "afterIdentityChange") {
		return
	}
	t.Fatalf("unexpected error: %v", err)
}

func idExpectCode(t *testing.T, err error, code string) {
	t.Helper()
	if message, ok := idStubbed(err); ok && code != "NOT_IMPLEMENTED" {
		t.Skip("blocked by a stub of another unit: " + message)
	}
	iamErr, ok := asIamError(err)
	if !ok || iamErr.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func idObject(t *testing.T, value any) *core.Object {
	t.Helper()
	object, ok := value.(*core.Object)
	if !ok {
		t.Fatalf("not an object: %#v", value)
	}
	return object
}

func idList(t *testing.T, value any) []*core.Object {
	t.Helper()
	list, ok := value.([]any)
	if !ok {
		t.Fatalf("not a list: %#v", value)
	}
	objects := make([]*core.Object, len(list))
	for index, item := range list {
		objects[index] = idObject(t, item)
	}
	return objects
}

func idMembers(list []*core.Object, key string) []string {
	out := make([]string, len(list))
	for index, item := range list {
		out[index] = jsString(item.Get(key))
	}
	return out
}

func idJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCredentialsHygiene(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	tenantID := f.tenantID
	owner, ownerSession := f.signIn(f.owner, false)
	account := f.serviceAccount(owner, "ci")
	accountID := jsString(account.Get("id"))
	api := f.iam.API.Credentials
	create := func(credential core.CredentialInput, members ...any) (*core.Object, error) {
		body := core.NewObject("tenantId", tenantID, "identityId", accountID)
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		out, err := api.Create(f.ctx, credential, Input[apitypes.CredentialsCreateInput](body))
		if err != nil {
			return nil, err
		}
		return idObject(t, out.Value), nil
	}
	list := func(credential core.CredentialInput, members ...any) []*core.Object {
		body := core.NewObject("tenantId", tenantID)
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		out, err := api.List(f.ctx, credential, Input[apitypes.CredentialsListInput](body))
		if err != nil {
			t.Fatal(err)
		}
		return idList(t, out.Value)
	}
	getKey := func(credential core.CredentialInput, id any) (*core.Object, error) {
		out, err := api.Get(f.ctx, credential, Input[apitypes.CredentialsGetInput](core.NewObject("tenantId", tenantID, "credentialId", id)))
		if err != nil {
			return nil, err
		}
		return idObject(t, out.Value), nil
	}
	update := func(credential core.CredentialInput, members ...any) (*core.Object, error) {
		body := core.NewObject("tenantId", tenantID)
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		out, err := api.Update(f.ctx, credential, Input[apitypes.CredentialsUpdateInput](body))
		if err != nil {
			return nil, err
		}
		return idObject(t, out.Value), nil
	}

	_, err := create(owner, "name", strings.Repeat("x", 129))
	idExpectCode(t, err, "INVALID_INPUT")
	issued, err := create(owner, "name", "deploy", "description", "GitHub Actions")
	if err != nil {
		t.Fatal(err)
	}
	if issued.Get("name") != "deploy" || !strings.HasPrefix(jsString(issued.Get("token")), "biam_key_") {
		t.Fatalf("issued: %v", idJSON(t, issued))
	}
	credentialID := issued.Get("credentialId")
	listed := list(owner)
	if len(listed) != 1 || listed[0].Get("id") != credentialID || listed[0].Get("identityId") != accountID ||
		listed[0].Get("description") != "GitHub Actions" || listed[0].Get("expired") != false || listed[0].Has("lastUsedAt") {
		t.Fatalf("listed: %s", idJSON(t, listed))
	}
	if strings.Contains(idJSON(t, listed), "tokenHash") {
		t.Fatal("token hash leaked")
	}
	token := jsString(issued.Get("token"))
	use := func() error {
		_, err := f.authorizeToken(token, "documents:read")
		return err
	}
	if err := use(); err != nil {
		t.Fatal(err)
	}
	// Use within a minute of creation is not written back (write throttling).
	if summary, _ := getKey(owner, credentialID); summary.Has("lastUsedAt") {
		t.Fatalf("throttled use recorded: %s", idJSON(t, summary))
	}
	f.advance(61_000)
	if err := use(); err != nil {
		t.Fatal(err)
	}
	if summary, _ := getKey(owner, credentialID); summary.Get("lastUsedAt") != f.now() {
		t.Fatalf("lastUsedAt: %s", idJSON(t, summary))
	}
	// Only API keys are credentials.
	_, err = getKey(owner, ownerSession.Get("id"))
	idExpectCode(t, err, "INVALID_CREDENTIAL")
	// Hygiene report: keys that have not been used for a day.
	if _, err := create(owner, "name", "stale"); err != nil {
		t.Fatal(err)
	}
	f.advance(int64(idDay))
	fresh := f.ownerSignIn()
	names := idMembers(list(fresh, "unusedForMs", idDay), "name")
	if strings.Join(names, ",") != "stale,deploy" {
		t.Fatalf("unused: %v", names)
	}
	if err := use(); err != nil {
		t.Fatal(err)
	}
	if names := idMembers(list(fresh, "unusedForMs", idDay), "name"); strings.Join(names, ",") != "stale" {
		t.Fatalf("unused after use: %v", names)
	}
	if names := idMembers(list(fresh, "identityId", accountID), "name"); strings.Join(names, ",") != "stale,deploy" {
		t.Fatalf("newest first: %v", names)
	}
	// Relabeling needs no recent authentication; moving the expiry does, and only into the next year.
	owner = f.ownerSignIn()
	f.advance(6 * 60_000)
	fresh = f.ownerSignIn()
	relabeled, err := update(owner, "credentialId", credentialID, "name", "deploy-prod", "description", nil)
	if err != nil {
		t.Fatal(err)
	}
	if relabeled.Get("name") != "deploy-prod" || relabeled.Has("description") {
		t.Fatalf("relabeled: %s", idJSON(t, relabeled))
	}
	_, err = update(owner, "credentialId", credentialID, "expiresAt", f.now()+3_600_000)
	idExpectCode(t, err, "RECENT_AUTH_REQUIRED")
	_, err = update(fresh, "credentialId", credentialID, "expiresAt", f.now()-1)
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = update(fresh, "credentialId", credentialID, "expiresAt", f.now()+400*idDay)
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = update(fresh, "credentialId", credentialID)
	idExpectCode(t, err, "INVALID_INPUT")
	shortened, err := update(fresh, "credentialId", credentialID, "expiresAt", f.now()+3_600_000)
	if err != nil {
		t.Fatal(err)
	}
	if shortened.Get("expiresAt") != f.now()+3_600_000 {
		t.Fatalf("shortened: %s", idJSON(t, shortened))
	}
	f.advance(3_600_001)
	idExpectCode(t, use(), "UNAUTHENTICATED")
	if summary, _ := getKey(fresh, credentialID); summary.Get("expired") != true {
		t.Fatalf("expired: %s", idJSON(t, summary))
	}
	// Rotation keeps the label and expiry but starts the usage history over.
	admin := f.ownerSignIn()
	var stale *core.Object
	for _, key := range list(admin) {
		if key.Get("name") == "stale" {
			stale = key
		}
	}
	rotatedOut, err := api.Rotate(f.ctx, admin, Input[apitypes.CredentialsRotateInput](core.NewObject("tenantId", tenantID, "credentialId", stale.Get("id"))))
	if err != nil {
		t.Fatal(err)
	}
	rotated := idObject(t, rotatedOut.Value)
	if rotated.Get("name") != "stale" {
		t.Fatalf("rotated: %s", idJSON(t, rotated))
	}
	replacement, err := getKey(admin, rotated.Get("credentialId"))
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Get("name") != "stale" || replacement.Get("expiresAt") != stale.Get("expiresAt") || replacement.Has("lastUsedAt") {
		t.Fatalf("replacement: %s", idJSON(t, replacement))
	}
	if ids := idMembers(list(admin), "id"); strings.Join(ids, ",") != jsString(rotated.Get("credentialId"))+","+jsString(credentialID) {
		t.Fatalf("after rotation: %v", ids)
	}
	// Revocation deletes the key at once; other sessions are refused.
	_, err = api.Revoke(f.ctx, admin, Input[apitypes.CredentialsRevokeInput](core.NewObject("tenantId", tenantID, "credentialId", ownerSession.Get("id"))))
	idExpectCode(t, err, "INVALID_CREDENTIAL")
	revoked, err := api.Revoke(f.ctx, admin, Input[apitypes.CredentialsRevokeInput](core.NewObject("tenantId", tenantID, "credentialId", rotated.Get("credentialId"))))
	if err != nil || idJSON(t, revoked.Value) != `{"revoked":true}` {
		t.Fatalf("revoke: %v %v", revoked.Value, err)
	}
	if len(list(admin)) != 1 {
		t.Fatal("revoked key still listed")
	}
}

func TestCredentialsScopes(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	tenantID := f.tenantID
	owner := f.ownerSignIn()
	account := f.serviceAccount(owner, "ci")
	accountID := jsString(account.Get("id"))
	f.grant("editor", "identity", accountID, "documents:read", "documents:write")
	create := func(credential core.CredentialInput, members ...any) (*core.Object, error) {
		body := core.NewObject("tenantId", tenantID, "identityId", accountID)
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		out, err := f.iam.API.Credentials.Create(f.ctx, credential, Input[apitypes.CredentialsCreateInput](body))
		if err != nil {
			return nil, err
		}
		return idObject(t, out.Value), nil
	}
	_, err := create(owner, "scopes", []any{"documents:read"}, "policy", obj(t, `{"version":1,"statements":[]}`))
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = create(owner, "scopes", []any{})
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = create(owner, "scopes", []any{"nope:read"})
	idExpectCode(t, err, "INVALID_ACTION")
	key, err := create(owner, "name", "reader", "scopes", []any{"documents:read", "documents:read"})
	if err != nil {
		t.Fatal(err)
	}
	can := func(token, action string) bool {
		decision, err := f.authorizeToken(token, action)
		if err != nil {
			t.Fatal(err)
		}
		return decision.Allowed
	}
	token := jsString(key.Get("token"))
	if !can(token, "documents:read") || can(token, "documents:write") {
		t.Fatal("scopes do not bound the key")
	}
	summaryOut, err := f.iam.API.Credentials.Get(f.ctx, owner, Input[apitypes.CredentialsGetInput](core.NewObject("tenantId", tenantID, "credentialId", key.Get("credentialId"))))
	if err != nil {
		t.Fatal(err)
	}
	summary := idObject(t, summaryOut.Value)
	if idJSON(t, summary.Get("scopes")) != `["documents:read"]` || jsString(member(member(summary.Get("policy"), "statements").([]any)[0], "sid")) != "KeyScopes" {
		t.Fatalf("summary: %s", idJSON(t, summary))
	}
	custom, err := create(owner, "policy", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:*"],"resources":["documents/a"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	customOut, _ := f.iam.API.Credentials.Get(f.ctx, owner, Input[apitypes.CredentialsGetInput](core.NewObject("tenantId", tenantID, "credentialId", custom.Get("credentialId"))))
	if idObject(t, customOut.Value).Has("scopes") {
		t.Fatal("custom policy reported as scopes")
	}
	// A key never mints a broader key: a scoped caller key passes its scopes on and refuses broader ones.
	f.grant("issuer", "identity", accountID, "iam:credentials:create", "iam:credentials:read")
	f.seed("grantAuthorities", core.NewObject("id", "authority-ci", "tenantId", tenantID, "identityId", accountID, "ceiling", All(), "parentAuthorityId", f.authority, "revoked", false))
	issuer, err := create(owner, "name", "issuer", "scopes", []any{"documents:*", "iam:credentials:*"})
	if err != nil {
		t.Fatal(err)
	}
	keyCredential := core.CredentialInput{Token: jsString(issuer.Get("token"))}
	_, err = create(keyCredential, "scopes", []any{"documents:read", "iam:*"})
	idExpectCode(t, err, "ACCESS_DENIED")
	narrower, err := create(keyCredential, "scopes", []any{"documents:read"})
	if err != nil {
		t.Fatal(err)
	}
	inherited, err := create(keyCredential)
	if err != nil {
		t.Fatal(err)
	}
	stored := f.get("sessions", jsString(inherited.Get("credentialId")))
	if scopes, ok := policyScopes(stored.Get("policy")); !ok || idJSON(t, scopes) != `["documents:*","iam:credentials:*"]` {
		t.Fatalf("inherited policy: %s", idJSON(t, stored.Get("policy")))
	}
	if !can(jsString(narrower.Get("token")), "documents:read") {
		t.Fatal("narrower key cannot read")
	}
	// Rotation through a key is bounded the same way.
	_, err = f.iam.API.Credentials.Rotate(f.ctx, keyCredential, Input[apitypes.CredentialsRotateInput](core.NewObject("tenantId", tenantID, "credentialId", custom.Get("credentialId"))))
	idExpectCode(t, err, "ACCESS_DENIED")
}

func TestScopeCoverage(t *testing.T) {
	cases := []struct {
		outer, inner string
		covered      bool
	}{
		{"documents:read", "documents:read", true},
		{"documents:*", "documents:read", true},
		{"documents:*", "documents:re*", true},
		{"documents:r*", "documents:*", false},
		{"*", "iam:*", true},
		{"documents:read", "documents:*", false},
		{"docs:${x}*", "docs:a*", false},
		{"documents:?ead", "documents:read", true},
	}
	for _, c := range cases {
		if got := scopeCovers(c.outer, c.inner); got != c.covered {
			t.Errorf("scopeCovers(%q, %q) = %v", c.outer, c.inner, got)
		}
	}
	scoped := ScopesPolicy([]string{"documents:*"})
	if !withinKeyPolicy(scoped, ScopesPolicy([]string{"documents:read"})) || withinKeyPolicy(scoped, ScopesPolicy([]string{"iam:read"})) ||
		withinKeyPolicy(scoped, core.Undefined) || !withinKeyPolicy(All(), All()) || withinKeyPolicy(All(), scoped) {
		t.Error("withinKeyPolicy")
	}
	summary, _ := CredentialSummary(core.NewObject("id", "k", "identityId", "svc", "createdAt", 10.0, "expiresAt", 20.0, "lastSeenAt", 10.0, "name", "n", "policy", scoped), 20)
	if idJSON(t, summary) != `{"id":"k","identityId":"svc","createdAt":10,"expiresAt":20,"expired":true,"policy":{"version":1,"statements":[{"sid":"KeyScopes","effect":"allow","actions":["documents:*"],"resources":["*"]}]},"name":"n","scopes":["documents:*"]}` {
		t.Errorf("summary: %s", idJSON(t, summary))
	}
}

func TestServiceAccountsLifecycle(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	tenantID := f.tenantID
	owner := f.ownerSignIn()
	sa := f.iam.API.ServiceAccounts
	_, err := sa.Create(f.ctx, owner, Input[apitypes.ServiceAccountsCreateInput](core.NewObject("tenantId", tenantID, "name", "CI", "description", "Build pipeline")))
	idAfterChange(t, err)
	accounts := f.find("identities", core.NewObject("tenantId", tenantID, "kind", "service"))
	if len(accounts) != 1 || accounts[0].Get("description") != "Build pipeline" || accounts[0].Get("status") != "active" {
		t.Fatalf("created: %s", idJSON(t, accounts))
	}
	accountID := jsString(accounts[0].Get("id"))
	listed, err := sa.List(f.ctx, owner, Input[apitypes.ServiceAccountsListInput](core.NewObject("tenantId", tenantID)))
	if err != nil || strings.Join(idMembers(idList(t, listed.Value), "id"), ",") != accountID {
		t.Fatalf("list: %v %v", listed.Value, err)
	}
	people, err := f.iam.API.Identities.List(f.ctx, owner, Input[apitypes.IdentitiesListInput](core.NewObject("tenantId", tenantID, "kind", "service")))
	if err != nil || strings.Join(idMembers(idList(t, people.Value), "id"), ",") != accountID {
		t.Fatalf("identities.list kind service: %v %v", people.Value, err)
	}
	_, err = sa.Get(f.ctx, owner, Input[apitypes.ServiceAccountsGetInput](core.NewObject("tenantId", tenantID, "identityId", f.ownerID)))
	idExpectCode(t, err, "NOT_FOUND")
	_, err = sa.Update(f.ctx, owner, Input[apitypes.ServiceAccountsUpdateInput](core.NewObject("tenantId", tenantID, "identityId", accountID, "name", "CI runner")))
	idAfterChange(t, err)
	if f.get("identities", accountID).Get("name") != "CI runner" {
		t.Fatal("rename not stored")
	}
	_, err = sa.Update(f.ctx, owner, Input[apitypes.ServiceAccountsUpdateInput](core.NewObject("tenantId", tenantID, "identityId", accountID)))
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = sa.Update(f.ctx, owner, Input[apitypes.ServiceAccountsUpdateInput](core.NewObject("tenantId", tenantID, "identityId", accountID, "expiresAt", f.now()+idDay)))
	idAfterChange(t, err)
	if f.get("identities", accountID).Get("expiresAt") != f.now()+idDay {
		t.Fatal("expiry not stored")
	}
	_, err = sa.Update(f.ctx, owner, Input[apitypes.ServiceAccountsUpdateInput](core.NewObject("tenantId", tenantID, "identityId", accountID, "expiresAt", nil)))
	idAfterChange(t, err)
	if f.get("identities", accountID).Has("expiresAt") {
		t.Fatal("expiry not cleared")
	}
	key, err := f.iam.API.Credentials.Create(f.ctx, owner, Input[apitypes.CredentialsCreateInput](core.NewObject("tenantId", tenantID, "identityId", accountID, "expiresInSeconds", 3600.0)))
	if err != nil {
		t.Fatal(err)
	}
	token := jsString(idObject(t, key.Value).Get("token"))
	if decision, err := f.authorizeToken(token, "documents:read"); err != nil || decision.Allowed {
		t.Fatalf("ungranted key: %+v %v", decision, err)
	}
	_, err = sa.SetStatus(f.ctx, owner, Input[apitypes.ServiceAccountsSetStatusInput](core.NewObject("tenantId", tenantID, "identityId", accountID, "status", "paused")))
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = sa.SetStatus(f.ctx, owner, Input[apitypes.ServiceAccountsSetStatusInput](core.NewObject("tenantId", tenantID, "identityId", accountID, "status", "disabled")))
	idSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.authorizeToken(token, "documents:read"); err == nil {
		t.Fatal("disabled account key still works")
	}
	if keys := f.find("sessions", core.NewObject("identityId", accountID)); len(keys) != 0 {
		t.Fatal("keys survive disabling")
	}
	_, err = f.iam.API.Credentials.Create(f.ctx, owner, Input[apitypes.CredentialsCreateInput](core.NewObject("tenantId", tenantID, "identityId", accountID)))
	idExpectCode(t, err, "INVALID_IDENTITY")
	if _, err := sa.SetStatus(f.ctx, owner, Input[apitypes.ServiceAccountsSetStatusInput](core.NewObject("tenantId", tenantID, "identityId", accountID, "status", "active"))); err != nil {
		t.Fatal(err)
	}
	removed, err := sa.Delete(f.ctx, owner, Input[apitypes.ServiceAccountsDeleteInput](core.NewObject("tenantId", tenantID, "identityId", accountID)))
	idSkipOnStub(t, err)
	if err != nil || idObject(t, removed.Value).Get("status") != "deleted" {
		t.Fatalf("delete: %v %v", removed.Value, err)
	}
	after, _ := sa.List(f.ctx, owner, Input[apitypes.ServiceAccountsListInput](core.NewObject("tenantId", tenantID)))
	if len(idList(t, after.Value)) != 0 {
		t.Fatal("deleted account listed")
	}
	_, err = f.iam.API.Credentials.Create(f.ctx, owner, Input[apitypes.CredentialsCreateInput](core.NewObject("tenantId", tenantID, "identityId", accountID)))
	idExpectCode(t, err, "INVALID_IDENTITY")
}

func TestServiceAccountLimitAndExpiry(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	root := f.get("tenants", f.tenantID)
	f.seed("tenants", root.Spread(core.NewObject("limits", core.NewObject("serviceAccounts", 1.0))))
	f.serviceAccount(owner, "one")
	_, err := f.iam.API.ServiceAccounts.Create(f.ctx, owner, Input[apitypes.ServiceAccountsCreateInput](core.NewObject("tenantId", f.tenantID, "name", "two")))
	idExpectCode(t, err, "LIMIT_EXCEEDED")
	f.seed("tenants", root)
	_, err = f.iam.API.ServiceAccounts.Create(f.ctx, owner, Input[apitypes.ServiceAccountsCreateInput](core.NewObject("tenantId", f.tenantID, "name", "past", "expiresAt", f.now()-1)))
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = f.iam.API.ServiceAccounts.Create(f.ctx, owner, Input[apitypes.ServiceAccountsCreateInput](core.NewObject("tenantId", f.tenantID, "name", "temp", "expiresAt", f.now()+60_000)))
	idAfterChange(t, err)
	var temp *core.Object
	for _, account := range f.find("identities", core.NewObject("tenantId", f.tenantID, "kind", "service")) {
		if account.Get("name") == "temp" {
			temp = account
		}
	}
	if temp == nil || temp.Get("expiresAt") != f.now()+60_000 {
		t.Fatalf("temp: %v", temp)
	}
	f.advance(61_000)
	fresh := f.ownerSignIn()
	_, err = f.iam.API.Credentials.Create(f.ctx, fresh, Input[apitypes.CredentialsCreateInput](core.NewObject("tenantId", f.tenantID, "identityId", temp.Get("id"))))
	idExpectCode(t, err, "INVALID_IDENTITY")
}

func TestIdentitiesListAndGet(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	bob := f.member("bob")
	alice := f.member("alice")
	f.seed("identities", alice.Spread(core.NewObject("expiresAt", f.now()+idDay)))
	f.seed("identities", identity("gone", f.tenantID, "name", "Zed", "status", "deleted"))
	list := func(members ...any) []string {
		body := core.NewObject("tenantId", f.tenantID)
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		out, err := f.iam.API.Identities.List(f.ctx, owner, Input[apitypes.IdentitiesListInput](body))
		if err != nil {
			t.Fatal(err)
		}
		return idMembers(idList(t, out.Value), "name")
	}
	if names := strings.Join(list(), ","); names != "alice,bob,Owner,Root" {
		t.Fatalf("list: %s", names)
	}
	if names := strings.Join(list("includeDeleted", true), ","); names != "alice,bob,Owner,Root,Zed" {
		t.Fatalf("includeDeleted: %s", names)
	}
	if names := strings.Join(list("status", "deleted"), ","); names != "Zed" {
		t.Fatalf("status deleted: %s", names)
	}
	if names := strings.Join(list("query", "BOB@"), ","); names != "bob" {
		t.Fatalf("query: %s", names)
	}
	if names := strings.Join(list("expiresBefore", f.now()+2*idDay), ","); names != "alice" {
		t.Fatalf("expiresBefore: %s", names)
	}
	if names := strings.Join(list("limit", 1.0, "offset", 1.0), ","); names != "bob" {
		t.Fatalf("paging: %s", names)
	}
	if names := list("offset", 10.0); len(names) != 0 {
		t.Fatalf("offset past the end: %v", names)
	}
	for _, bad := range [][]any{{"kind", "robot"}, {"status", "gone"}, {"limit", 0.0}, {"offset", -1.0}, {"query", ""}} {
		body := core.NewObject("tenantId", f.tenantID, bad[0].(string), bad[1])
		_, err := f.iam.API.Identities.List(f.ctx, owner, Input[apitypes.IdentitiesListInput](body))
		idExpectCode(t, err, "INVALID_INPUT")
	}
	got, err := f.iam.API.Identities.Get(f.ctx, owner, Input[apitypes.IdentitiesGetInput](core.NewObject("tenantId", f.tenantID, "identityId", bob.Get("id"))))
	if err != nil || idObject(t, got.Value).Has("passwordHash") || idObject(t, got.Value).Get("email") != "bob@example.test" {
		t.Fatalf("get: %v %v", got.Value, err)
	}
	tombstone, err := f.iam.API.Identities.Get(f.ctx, owner, Input[apitypes.IdentitiesGetInput](core.NewObject("tenantId", f.tenantID, "identityId", "gone")))
	if err != nil || idObject(t, tombstone.Value).Get("status") != "deleted" {
		t.Fatalf("tombstone: %v %v", tombstone.Value, err)
	}
	_, err = f.iam.API.Identities.Get(f.ctx, owner, Input[apitypes.IdentitiesGetInput](core.NewObject("tenantId", f.tenantID, "identityId", "missing")))
	idExpectCode(t, err, "NOT_FOUND")
	// A member without iam:identities:read is refused.
	bobCredential, _ := f.signIn(bob, false)
	_, err = f.iam.API.Identities.List(f.ctx, bobCredential, Input[apitypes.IdentitiesListInput](core.NewObject("tenantId", f.tenantID)))
	idExpectCode(t, err, "ACCESS_DENIED")
}

func TestIdentitiesSessionsExportAndRevocation(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	first, _ := f.signIn(alice, false)
	f.advance(1000)
	second, _ := f.signIn(alice, false)
	f.seed("groups", core.NewObject("id", "team", "tenantId", f.tenantID, "name", "Team"))
	f.seed("groupMembers", core.NewObject("id", "m1", "tenantId", f.tenantID, "uniqueKey", "team:"+aliceID, "groupId", "team", "identityId", aliceID))
	f.grant("readers", "group", "team", "documents:read")
	f.seed("relationships", core.NewObject("id", "rel", "tenantId", f.tenantID, "type", "folder", "objectId", "plans", "relation", "viewer", "subjectType", "identity", "subjectId", aliceID))
	sessionsOut, err := f.iam.API.Identities.ListSessions(f.ctx, owner, Input[apitypes.IdentitiesListSessionsInput](core.NewObject("tenantId", f.tenantID, "identityId", aliceID)))
	if err != nil {
		t.Fatal(err)
	}
	sessions := idList(t, sessionsOut.Value)
	if len(sessions) != 2 || sessions[0].Has("tokenHash") || sessions[0].Has("uniqueKey") || sessions[0].Get("lastSeenAt").(float64) < sessions[1].Get("lastSeenAt").(float64) {
		t.Fatalf("listSessions: %s", idJSON(t, sessions))
	}
	// Alice has no permission to export herself.
	_, err = f.iam.API.Identities.Export(f.ctx, first, Input[apitypes.IdentitiesExportInput](core.NewObject("tenantId", f.tenantID, "identityId", aliceID)))
	idExpectCode(t, err, "ACCESS_DENIED")
	exportedOut, err := f.iam.API.Identities.Export(f.ctx, owner, Input[apitypes.IdentitiesExportInput](core.NewObject("tenantId", f.tenantID, "identityId", aliceID)))
	if err != nil {
		t.Fatal(err)
	}
	exported := idObject(t, exportedOut.Value)
	text := idJSON(t, exported)
	if strings.Contains(text, "passwordHash") || strings.Contains(text, "tokenHash") || strings.Contains(text, first.Token) {
		t.Fatalf("export leaks secrets: %s", text)
	}
	if idObject(t, exported.Get("identity")).Get("email") != "alice@example.test" || len(exported.Get("sessions").([]any)) != 2 ||
		idJSON(t, exported.Get("mfa")) != `{"enabled":false}` || idJSON(t, exported.Get("links")) != `[]` || idJSON(t, exported.Get("passkeys")) != `[]` {
		t.Fatalf("export: %s", text)
	}
	if groups := idMembers(idList(t, exported.Get("groups")), "name"); strings.Join(groups, ",") != "Team" {
		t.Fatalf("export groups: %v", groups)
	}
	bindings := idList(t, exported.Get("bindings"))
	if len(bindings) != 1 || idJSON(t, bindings[0].Get("via")) != `{"groupId":"team"}` {
		t.Fatalf("export bindings: %s", idJSON(t, bindings))
	}
	if relations := idMembers(idList(t, exported.Get("relationships")), "relation"); strings.Join(relations, ",") != "viewer" {
		t.Fatalf("export relationships: %v", relations)
	}
	if exported.Get("auditIncluded") != true || !strings.Contains(idJSON(t, exported.Get("audit")), "auth:session:create") {
		t.Fatalf("export audit: %s", idJSON(t, exported.Get("audit")))
	}
	var exportEvent *core.Object
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "identity:export")) {
		exportEvent = event
	}
	if exportEvent == nil || exportEvent.Get("resourceId") != aliceID || idJSON(t, exportEvent.Get("metadata")) != `{"kind":"user","auditIncluded":true}` {
		t.Fatalf("export audit event: %v", exportEvent)
	}
	// An exporter without audit permission receives everything except the trail.
	hr := f.member("hr")
	f.grant("hr", "identity", jsString(hr.Get("id")), "iam:identities:read")
	hrCredential, _ := f.signIn(hr, false)
	partialOut, err := f.iam.API.Identities.Export(f.ctx, hrCredential, Input[apitypes.IdentitiesExportInput](core.NewObject("tenantId", f.tenantID, "identityId", aliceID)))
	if err != nil {
		t.Fatal(err)
	}
	partial := idObject(t, partialOut.Value)
	if partial.Get("auditIncluded") != false || partial.Has("audit") && !isUndefined(partial.Get("audit")) || len(partial.Get("groups").([]any)) != 1 {
		t.Fatalf("partial export: %s", idJSON(t, partial))
	}
	// Recent authentication is required.
	f.advance(6 * 60_000)
	_, err = f.iam.API.Identities.Export(f.ctx, owner, Input[apitypes.IdentitiesExportInput](core.NewObject("tenantId", f.tenantID, "identityId", aliceID)))
	idExpectCode(t, err, "RECENT_AUTH_REQUIRED")
	owner = f.ownerSignIn()
	// Revoking sessions ends both of Alice's sessions without disabling her.
	revoked, err := f.iam.API.Identities.RevokeSessions(f.ctx, owner, Input[apitypes.IdentitiesRevokeSessionsInput](core.NewObject("tenantId", f.tenantID, "identityId", aliceID)))
	if err != nil || idJSON(t, revoked.Value) != `{"revoked":2}` {
		t.Fatalf("revokeSessions: %v %v", revoked.Value, err)
	}
	for _, credential := range []core.CredentialInput{first, second} {
		if _, err := f.iam.Authenticate(f.ctx, credential); err == nil {
			t.Fatal("revoked session still authenticates")
		}
	}
	if f.get("identities", aliceID).Get("status") != "active" {
		t.Fatal("revocation disabled the identity")
	}
	// A member cannot revoke an administrator's sessions without iam:identities:update.
	again, _ := f.signIn(alice, false)
	_, err = f.iam.API.Identities.RevokeSessions(f.ctx, again, Input[apitypes.IdentitiesRevokeSessionsInput](core.NewObject("tenantId", f.tenantID, "identityId", f.ownerID)))
	idExpectCode(t, err, "ACCESS_DENIED")
	// keepApiKeys keeps the API keys of a service account and ends everything else.
	account := f.serviceAccount(owner, "bot")
	accountID := jsString(account.Get("id"))
	if _, err := f.iam.API.Credentials.Create(f.ctx, owner, Input[apitypes.CredentialsCreateInput](core.NewObject("tenantId", f.tenantID, "identityId", accountID))); err != nil {
		t.Fatal(err)
	}
	_, err = f.iam.API.Identities.RevokeSessions(f.ctx, owner, Input[apitypes.IdentitiesRevokeSessionsInput](core.NewObject("tenantId", f.tenantID, "identityId", accountID, "keepApiKeys", "yes")))
	idExpectCode(t, err, "INVALID_INPUT")
	kept, err := f.iam.API.Identities.RevokeSessions(f.ctx, owner, Input[apitypes.IdentitiesRevokeSessionsInput](core.NewObject("tenantId", f.tenantID, "identityId", accountID, "keepApiKeys", true)))
	if err != nil || idJSON(t, kept.Value) != `{"revoked":0}` || len(f.find("sessions", core.NewObject("identityId", accountID))) != 1 {
		t.Fatalf("keepApiKeys: %v %v", kept.Value, err)
	}
	var metadata []string
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "identity:revoke-sessions")) {
		metadata = append(metadata, idJSON(t, event.Get("metadata")))
	}
	if strings.Join(metadata, ",") != `{"revoked":2,"keptApiKeys":false},{"revoked":0,"keptApiKeys":true}` &&
		strings.Join(metadata, ",") != `{"revoked":0,"keptApiKeys":true},{"revoked":2,"keptApiKeys":false}` {
		t.Fatalf("revoke audit: %v", metadata)
	}
}

func TestIdentitiesProviderLinks(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	bob := f.member("bob")
	bobID := jsString(bob.Get("id"))
	okta := func(subject string) *core.Object {
		return core.NewObject("tenantId", f.tenantID, "identityId", bobID, "providerId", "acme-okta", "issuer", "https://acme.okta.test", "subject", subject)
	}
	linkOut, err := f.iam.API.Identities.LinkProvider(f.ctx, owner, Input[apitypes.IdentitiesLinkProviderInput](okta("okta-bob")))
	if err != nil {
		t.Fatal(err)
	}
	link := idObject(t, linkOut.Value)
	if link.Get("identityId") != bobID || link.Get("subject") != "okta-bob" || link.Get("providerId") != "acme-okta" || jsString(link.Get("id")) == "" {
		t.Fatalf("link: %s", idJSON(t, link))
	}
	stored := f.get("externalIdentities", jsString(link.Get("id")))
	if stored.Get("uniqueKey") != `["acme-okta","https://acme.okta.test","okta-bob"]` {
		t.Fatalf("stored link: %s", idJSON(t, stored))
	}
	_, err = f.iam.API.Identities.LinkProvider(f.ctx, owner, Input[apitypes.IdentitiesLinkProviderInput](okta("okta-bob-2")))
	idExpectCode(t, err, "ACCOUNT_LINK_CONFLICT")
	other := f.member("carol")
	taken := okta("okta-bob")
	taken.Set("identityId", other.Get("id"))
	_, err = f.iam.API.Identities.LinkProvider(f.ctx, owner, Input[apitypes.IdentitiesLinkProviderInput](taken))
	idExpectCode(t, err, "ACCOUNT_LINK_CONFLICT")
	// A member administrator (identities:update) cannot link an IdP account to the owner's account.
	admin := f.member("admin")
	f.grant("member-admin", "identity", jsString(admin.Get("id")), "iam:identities:update", "iam:identities:read")
	adminCredential, _ := f.signIn(admin, false)
	attack := okta("okta-attacker")
	attack.Set("identityId", f.ownerID)
	_, err = f.iam.API.Identities.LinkProvider(f.ctx, adminCredential, Input[apitypes.IdentitiesLinkProviderInput](attack))
	idExpectCode(t, err, "ACCESS_DENIED")
	listed, err := f.iam.API.Identities.ListProviders(f.ctx, adminCredential, Input[apitypes.IdentitiesListProvidersInput](core.NewObject("tenantId", f.tenantID, "identityId", bobID)))
	if err != nil || len(idList(t, listed.Value)) != 1 {
		t.Fatalf("listProviders: %v %v", listed.Value, err)
	}
	removedOut, err := f.iam.API.Identities.UnlinkProvider(f.ctx, owner, Input[apitypes.IdentitiesUnlinkProviderInput](core.NewObject("tenantId", f.tenantID, "identityId", bobID, "linkId", link.Get("id"))))
	if err != nil || idObject(t, removedOut.Value).Get("id") != link.Get("id") {
		t.Fatalf("unlink: %v %v", removedOut.Value, err)
	}
	_, err = f.iam.API.Identities.UnlinkProvider(f.ctx, owner, Input[apitypes.IdentitiesUnlinkProviderInput](core.NewObject("tenantId", f.tenantID, "identityId", bobID, "linkId", link.Get("id"))))
	idExpectCode(t, err, "NOT_FOUND")
	actions := strings.Join(f.auditActions(), ",")
	if !strings.Contains(actions, "identity:link-provider") || !strings.Contains(actions, "identity:unlink-provider") {
		t.Fatalf("audit: %s", actions)
	}
	// Service accounts never sign in through external providers.
	account := f.serviceAccount(owner, "bot")
	robot := okta("okta-robot")
	robot.Set("identityId", account.Get("id"))
	_, err = f.iam.API.Identities.LinkProvider(f.ctx, owner, Input[apitypes.IdentitiesLinkProviderInput](robot))
	idExpectCode(t, err, "INVALID_INPUT")
}

func TestIdentitiesAccountControl(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	admin := f.member("admin")
	f.grant("member-admin", "identity", jsString(admin.Get("id")), "iam:identities:update", "iam:identities:read")
	adminCredential, _ := f.signIn(admin, false)
	// An ordinary administrator can neither send the owner a reset nor change the owner's address.
	_, err := f.iam.API.Identities.RequestPasswordReset(f.ctx, adminCredential, Input[apitypes.IdentitiesRequestPasswordResetInput](core.NewObject("tenantId", f.tenantID, "identityId", f.ownerID)))
	idExpectCode(t, err, "ACCESS_DENIED")
	_, err = f.iam.API.Identities.Update(f.ctx, adminCredential, Input[apitypes.IdentitiesUpdateInput](core.NewObject("tenantId", f.tenantID, "identityId", f.ownerID, "email", "attacker@example.test")))
	idExpectCode(t, err, "ACCESS_DENIED")
	denials := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "iam:identities:update", "outcome", "deny"))
	if len(denials) < 2 {
		t.Fatalf("refusals not audited as denials: %d", len(denials))
	}
	// For a member it works, and the reset email is queued.
	bob := f.member("bob")
	reset, err := f.iam.API.Identities.RequestPasswordReset(f.ctx, adminCredential, Input[apitypes.IdentitiesRequestPasswordResetInput](core.NewObject("tenantId", f.tenantID, "identityId", bob.Get("id"))))
	if err != nil || idJSON(t, reset.Value) != `{"queued":true,"email":"bob@example.test"}` {
		t.Fatalf("reset: %v %v", reset.Value, err)
	}
	// An email change revokes the sessions, marks the address unverified, and is audited.
	bobCredential, _ := f.signIn(bob, false)
	_, err = f.iam.API.Identities.Update(f.ctx, adminCredential, Input[apitypes.IdentitiesUpdateInput](core.NewObject("tenantId", f.tenantID, "identityId", bob.Get("id"), "email", "Robert@Example.test")))
	idAfterChange(t, err)
	stored := f.get("identities", jsString(bob.Get("id")))
	if stored.Get("email") != "robert@example.test" || stored.Get("uniqueKey") != "email:robert@example.test" || stored.Get("emailVerified") != false {
		t.Fatalf("email change: %s", idJSON(t, stored))
	}
	if _, err := f.iam.Authenticate(f.ctx, bobCredential); err == nil {
		t.Fatal("sessions survive an email change")
	}
	changes := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "identity:email-change"))
	if len(changes) != 1 || idJSON(t, changes[0].Get("metadata")) != `{"from":"bob@example.test","to":"robert@example.test"}` {
		t.Fatalf("email-change audit: %s", idJSON(t, changes))
	}
	carol := f.member("carol")
	_, err = f.iam.API.Identities.Update(f.ctx, adminCredential, Input[apitypes.IdentitiesUpdateInput](core.NewObject("tenantId", f.tenantID, "identityId", carol.Get("id"), "email", "robert@example.test")))
	idExpectCode(t, err, "IDENTITY_EXISTS")
	_, err = f.iam.API.Identities.Update(f.ctx, adminCredential, Input[apitypes.IdentitiesUpdateInput](core.NewObject("tenantId", f.tenantID, "identityId", carol.Get("id"))))
	idExpectCode(t, err, "INVALID_INPUT")
	// Your own attributes, manager and expiry are changed by another administrator.
	_, err = f.iam.API.Identities.Update(f.ctx, adminCredential, Input[apitypes.IdentitiesUpdateInput](core.NewObject("tenantId", f.tenantID, "identityId", admin.Get("id"), "managerId", carol.Get("id"))))
	idExpectCode(t, err, "ACCESS_DENIED")
	// The owner may change their own name freely.
	owner := f.ownerSignIn()
	_, err = f.iam.API.Identities.Update(f.ctx, owner, Input[apitypes.IdentitiesUpdateInput](core.NewObject("tenantId", f.tenantID, "identityId", f.ownerID, "name", "Root Owner")))
	idAfterChange(t, err)
	if f.get("identities", f.ownerID).Get("name") != "Root Owner" {
		t.Fatal("owner rename not stored")
	}
}

func TestIdentitiesManagers(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	ann := f.member("ann")
	bob := f.member("bob")
	cid := f.member("cid")
	update := func(id any, members ...any) error {
		body := core.NewObject("tenantId", f.tenantID, "identityId", id)
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		_, err := f.iam.API.Identities.Update(f.ctx, owner, Input[apitypes.IdentitiesUpdateInput](body))
		return err
	}
	idAfterChange(t, update(bob.Get("id"), "managerId", ann.Get("id")))
	idAfterChange(t, update(cid.Get("id"), "managerId", bob.Get("id")))
	idExpectCode(t, update(ann.Get("id"), "managerId", cid.Get("id")), "INVALID_INPUT")
	idExpectCode(t, update(ann.Get("id"), "managerId", ann.Get("id")), "INVALID_INPUT")
	idExpectCode(t, update(ann.Get("id"), "managerId", "nobody"), "NOT_FOUND")
	reports, err := f.iam.API.Identities.ListReports(f.ctx, owner, Input[apitypes.IdentitiesListReportsInput](core.NewObject("tenantId", f.tenantID, "identityId", ann.Get("id"))))
	if err != nil || strings.Join(idMembers(idList(t, reports.Value), "name"), ",") != "bob" {
		t.Fatalf("listReports: %v %v", reports.Value, err)
	}
	idAfterChange(t, update(cid.Get("id"), "managerId", nil))
	if f.get("identities", jsString(cid.Get("id"))).Has("managerId") {
		t.Fatal("manager not cleared")
	}
	// Owners: the last owner without an expiry keeps none.
	idExpectCode(t, update(f.ownerID, "expiresAt", f.now()+idDay), "LAST_OWNER")
	// Expiries in the past are refused.
	idExpectCode(t, update(bob.Get("id"), "expiresAt", f.now()-1), "INVALID_INPUT")
	idAfterChange(t, update(bob.Get("id"), "expiresAt", f.now()+idDay))
	if f.get("identities", jsString(bob.Get("id"))).Get("expiresAt") != f.now()+idDay {
		t.Fatal("expiry not stored")
	}
}

func TestIdentitiesOwnershipAndBoundaries(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	bob := f.member("bob")
	bobID := jsString(bob.Get("id"))
	setOwner := func(credential core.CredentialInput, id any, value any) (*core.Object, error) {
		out, err := f.iam.API.Identities.SetOwner(f.ctx, credential, Input[apitypes.IdentitiesSetOwnerInput](core.NewObject("tenantId", f.tenantID, "identityId", id, "owner", value)))
		if err != nil {
			return nil, err
		}
		return idObject(t, out.Value), nil
	}
	// A non-owner administrator cannot transfer ownership.
	admin := f.member("admin")
	f.grant("member-admin", "identity", jsString(admin.Get("id")), "iam:identities:update", "iam:identities:read")
	adminCredential, _ := f.signIn(admin, false)
	_, err := setOwner(adminCredential, bobID, true)
	idExpectCode(t, err, "ACCESS_DENIED")
	_, err = setOwner(owner, bobID, "yes")
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = setOwner(owner, f.ownerID, false)
	idExpectCode(t, err, "LAST_OWNER")
	promoted, err := setOwner(owner, bobID, true)
	if err != nil || promoted.Get("owner") != true {
		t.Fatalf("promote: %v %v", promoted, err)
	}
	ownerRole := f.find("roles", core.NewObject("tenantId", f.tenantID, "uniqueKey", "system:owner"))[0]
	bindings := f.find("bindings", core.NewObject("tenantId", f.tenantID, "subjectId", bobID, "roleId", ownerRole.Get("id")))
	if len(bindings) != 1 {
		t.Fatalf("owner binding: %d", len(bindings))
	}
	bobAuthority := f.get("grantAuthorities", jsString(bindings[0].Get("authorityId")))
	if bobAuthority.Get("identityId") != bobID || bobAuthority.Get("parentAuthorityId") != f.authority {
		t.Fatalf("owner authority: %s", idJSON(t, bobAuthority))
	}
	// Removing ownership passes the authority to the caller who stays an owner.
	demoted, err := setOwner(owner, bobID, false)
	if err != nil || demoted.Get("owner") != false {
		t.Fatalf("demote: %v %v", demoted, err)
	}
	if len(f.find("bindings", core.NewObject("tenantId", f.tenantID, "subjectId", bobID, "roleId", ownerRole.Get("id")))) != 0 {
		t.Fatal("owner binding survives")
	}
	if f.get("grantAuthorities", jsString(bobAuthority.Get("id"))).Get("identityId") != f.ownerID {
		t.Fatal("authority not passed to the remaining owner")
	}
	// Boundaries are platform controlled: only a root principal sets them, validated against the catalog.
	document := obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"]}]}`)
	setBoundary := func(credential core.CredentialInput, doc any) (*core.Object, error) {
		out, err := f.iam.API.Identities.SetBoundary(f.ctx, credential, Input[apitypes.IdentitiesSetBoundaryInput](core.NewObject("tenantId", f.tenantID, "identityId", bobID, "document", doc)))
		if err != nil {
			return nil, err
		}
		return idObject(t, out.Value), nil
	}
	_, err = setBoundary(owner, document)
	idExpectCode(t, err, "ACCESS_DENIED")
	root := f.rootSignIn()
	_, err = setBoundary(root, obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["nope:read"],"resources":["*"]}]}`))
	idExpectCode(t, err, "INVALID_ACTION")
	first, err := setBoundary(root, document)
	if err != nil || first.Get("uniqueKey") != bobID {
		t.Fatalf("boundary: %v %v", first, err)
	}
	second, err := setBoundary(root, obj(t, `{"version":1,"statements":[]}`))
	if err != nil || second.Get("id") != first.Get("id") {
		t.Fatalf("boundary replaced: %v %v", second, err)
	}
	if boundaries := f.find("principalBoundaries", core.NewObject("tenantId", f.tenantID, "identityId", bobID)); len(boundaries) != 1 {
		t.Fatalf("boundaries: %d", len(boundaries))
	}
}

func TestIdentitiesImpersonation(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	impersonate := func(credential core.CredentialInput, members ...any) (*core.Object, error) {
		body := core.NewObject("tenantId", f.tenantID, "identityId", aliceID, "reason", "Support ticket 42")
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		out, err := f.iam.API.Identities.Impersonate(f.ctx, credential, Input[apitypes.IdentitiesImpersonateInput](body))
		if err != nil {
			return nil, err
		}
		return idObject(t, out.Value), nil
	}
	// Off by default.
	_, err := impersonate(owner)
	idExpectCode(t, err, "FEATURE_DISABLED")
	root := f.get("tenants", f.tenantID)
	f.seed("tenants", root.Spread(core.NewObject("authPolicy", core.NewObject("allowImpersonation", true))))
	_, err = impersonate(owner, "durationMs", 1000.0)
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = impersonate(owner, "reason", "")
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = impersonate(owner, "identityId", f.ownerID)
	idExpectCode(t, err, "INVALID_INPUT")
	account := f.serviceAccount(owner, "bot")
	_, err = impersonate(owner, "identityId", account.Get("id"))
	idExpectCode(t, err, "INVALID_INPUT")
	second := f.member("second")
	f.seed("identities", f.get("identities", jsString(second.Get("id"))).Spread(core.NewObject("owner", true)))
	_, err = impersonate(owner, "identityId", second.Get("id"))
	idExpectCode(t, err, "ACCESS_DENIED")
	result, err := impersonate(owner, "durationMs", 600_000.0)
	if err != nil {
		t.Fatal(err)
	}
	session := idObject(t, result.Get("session"))
	if session.Has("tokenHash") || session.Get("impersonatorId") != f.ownerID || session.Get("identityId") != aliceID ||
		session.Get("expiresAt") != f.now()+600_000 || idObject(t, result.Get("identity")).Get("id") != aliceID {
		t.Fatalf("impersonation: %s", idJSON(t, result))
	}
	events := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "identity:impersonate"))
	if len(events) != 1 || idJSON(t, events[0].Get("metadata")) != idJSON(t, core.NewObject("reason", "Support ticket 42", "sessionId", session.Get("id"), "expiresAt", session.Get("expiresAt"))) {
		t.Fatalf("impersonation audit: %s", idJSON(t, events))
	}
	// The view-as session cannot impersonate again (it needs recent authentication).
	viewAs := core.CredentialInput{Token: jsString(result.Get("token"))}
	_, err = impersonate(viewAs)
	if err == nil {
		t.Fatal("impersonation from a view-as session")
	}
}

func TestIdentitiesInvitations(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	invite := func(members ...any) (*core.Object, error) {
		body := core.NewObject("tenantId", f.tenantID)
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		out, err := f.iam.API.Identities.Invite(f.ctx, owner, Input[apitypes.IdentitiesInviteInput](body))
		if err != nil {
			return nil, err
		}
		return idObject(t, out.Value), nil
	}
	_, err := invite("email", "root@example.test")
	idExpectCode(t, err, "IDENTITY_EXISTS")
	_, err = invite("email", "not-an-email")
	idExpectCode(t, err, "INVALID_INPUT")
	invited, err := invite("email", "New@Example.test", "name", "Newcomer")
	idSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if invited.Get("email") != "new@example.test" || idJSON(t, invited.Get("roleIds")) != `[]` ||
		invited.Get("expiresAt") != f.now()+f.iam.Context.Config.InvitationLifetimeMs {
		t.Fatalf("invite: %s", idJSON(t, invited))
	}
	listed, err := f.iam.API.Identities.ListInvitations(f.ctx, owner, Input[apitypes.IdentitiesListInvitationsInput](core.NewObject("tenantId", f.tenantID)))
	if err != nil || len(idList(t, listed.Value)) != 1 || strings.Contains(idJSON(t, listed.Value), "tokenHash") {
		t.Fatalf("listInvitations: %v %v", listed.Value, err)
	}
	outbox := f.find("outbox", core.NewObject("tenantId", f.tenantID, "template", "member-invitation"))
	if len(outbox) != 1 || outbox[0].Get("to") != "new@example.test" || !strings.Contains(idJSON(t, outbox[0].Get("payload")), "sealed") {
		t.Fatalf("outbox: %s", idJSON(t, outbox))
	}
	revoked, err := f.iam.API.Identities.RevokeInvitation(f.ctx, owner, Input[apitypes.IdentitiesRevokeInvitationInput](core.NewObject("tenantId", f.tenantID, "invitationId", invited.Get("invitationId"))))
	if err != nil || idObject(t, revoked.Value).Get("revoked") != true || idObject(t, revoked.Value).Has("tokenHash") {
		t.Fatalf("revoke: %v %v", revoked.Value, err)
	}
	_, err = f.iam.API.Identities.RevokeInvitation(f.ctx, owner, Input[apitypes.IdentitiesRevokeInvitationInput](core.NewObject("tenantId", f.tenantID, "invitationId", invited.Get("invitationId"))))
	idExpectCode(t, err, "CONFLICT")
	_, err = f.iam.API.Identities.ResendInvitation(f.ctx, owner, Input[apitypes.IdentitiesResendInvitationInput](core.NewObject("tenantId", f.tenantID, "invitationId", invited.Get("invitationId"))))
	idExpectCode(t, err, "CONFLICT")
}

func TestIdentitiesInvitationsNeedDelivery(t *testing.T) {
	f := newIdentitiesFixture(t, func(options *BetterIamOptions) { options.Authentication.SendEmail = nil })
	owner := f.ownerSignIn()
	_, err := f.iam.API.Identities.Invite(f.ctx, owner, Input[apitypes.IdentitiesInviteInput](core.NewObject("tenantId", f.tenantID, "email", "new@example.test")))
	idExpectCode(t, err, "DELIVERY_REQUIRED")
	_, err = f.iam.API.Identities.ResendInvitation(f.ctx, owner, Input[apitypes.IdentitiesResendInvitationInput](core.NewObject("tenantId", f.tenantID, "invitationId", "x")))
	idExpectCode(t, err, "DELIVERY_REQUIRED")
}

func TestIdentitiesRevokeInvitationsBy(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	f.seed("memberInvitations",
		core.NewObject("id", "open", "tenantId", f.tenantID, "email", "a@example.test", "inviterId", "inviter", "consumed", false),
		core.NewObject("id", "used", "tenantId", f.tenantID, "email", "b@example.test", "inviterId", "inviter", "consumed", true),
		core.NewObject("id", "other", "tenantId", f.tenantID, "email", "c@example.test", "inviterId", "someone", "consumed", false),
	)
	err := f.iam.Store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		return RevokeInvitationsBy(ctx, tx, "inviter")
	})
	idSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if f.get("memberInvitations", "open").Get("revoked") != true || f.get("memberInvitations", "used").Has("revoked") || f.get("memberInvitations", "other").Has("revoked") {
		t.Fatal("revokeInvitationsBy")
	}
}

func TestIdentitiesCreate(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	create := func(members ...any) error {
		body := core.NewObject("tenantId", f.tenantID)
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		_, err := f.iam.API.Identities.Create(f.ctx, owner, Input[apitypes.IdentitiesCreateInput](body))
		return err
	}
	idExpectCode(t, create("email", "x@example.test", "name", "X", "emailVerified", "yes"), "INVALID_INPUT")
	idExpectCode(t, create("email", "x@example.test", "name", "X", "expiresAt", f.now()-1), "INVALID_INPUT")
	idExpectCode(t, create("email", "x@example.test", "name", "X", "providers", []any{
		core.NewObject("providerId", "p", "issuer", "i", "subject", "a"), core.NewObject("providerId", "p", "issuer", "i", "subject", "b"),
	}), "INVALID_INPUT")
	idExpectCode(t, create("email", "root@example.test", "name", "Dup"), "IDENTITY_EXISTS")
	ann := f.member("ann")
	idAfterChange(t, create("email", "Dan@Example.test", "name", "Dan", "password", "a strong dan password", "emailVerified", true,
		"managerId", ann.Get("id"), "expiresAt", f.now()+idDay,
		"providers", []any{core.NewObject("providerId", "okta", "issuer", "https://okta.test", "subject", "dan")}))
	dan := f.find("identities", core.NewObject("tenantId", f.tenantID, "email", "dan@example.test"))
	if len(dan) != 1 || dan[0].Get("emailVerified") != true || dan[0].Get("managerId") != ann.Get("id") || dan[0].Get("expiresAt") != f.now()+idDay || !dan[0].Has("passwordHash") {
		t.Fatalf("created: %s", idJSON(t, dan))
	}
	links := f.find("externalIdentities", core.NewObject("tenantId", f.tenantID, "identityId", dan[0].Get("id")))
	if len(links) != 1 || links[0].Get("subject") != "dan" {
		t.Fatalf("pre-linked sign-in: %s", idJSON(t, links))
	}
	// The same external account cannot be linked to a second person.
	idExpectCode(t, create("email", "eve@example.test", "name", "Eve",
		"providers", []any{core.NewObject("providerId", "okta", "issuer", "https://okta.test", "subject", "dan")}), "ACCOUNT_LINK_CONFLICT")
	// A manager needs iam:identities:update besides iam:identities:create.
	hr := f.member("hr")
	f.grant("hr", "identity", jsString(hr.Get("id")), "iam:identities:create")
	hrCredential, _ := f.signIn(hr, false)
	_, err := f.iam.API.Identities.Create(f.ctx, hrCredential, Input[apitypes.IdentitiesCreateInput](core.NewObject("tenantId", f.tenantID, "email", "fay@example.test", "name", "Fay", "managerId", ann.Get("id"))))
	idExpectCode(t, err, "ACCESS_DENIED")
	_, err = f.iam.API.Identities.Create(f.ctx, hrCredential, Input[apitypes.IdentitiesCreateInput](core.NewObject("tenantId", f.tenantID, "email", "fay@example.test", "name", "Fay")))
	idAfterChange(t, err)
}

func TestIdentitiesCreateMany(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	createMany := func(items ...any) error {
		_, err := f.iam.API.Identities.CreateMany(f.ctx, owner, Input[apitypes.IdentitiesCreateManyInput](core.NewObject("tenantId", f.tenantID, "identities", items)))
		return err
	}
	idExpectCode(t, createMany(), "INVALID_INPUT")
	idExpectCode(t, createMany(core.NewObject("email", "bad", "name", "Bad")), "INVALID_INPUT")
	f.seed("roles", core.NewObject("id", "protected", "tenantId", f.tenantID, "name", "Guarded", "protected", true, "authorityId", f.authority))
	idExpectCode(t, createMany(core.NewObject("email", "a@example.test", "name", "A", "roleIds", []any{"protected"})), "PROTECTED_RESOURCE")
	f.seed("roles", core.NewObject("id", "reader", "tenantId", f.tenantID, "name", "Reader", "authorityId", f.authority,
		"document", core.NewObject("version", 1.0, "statements", []any{core.NewObject("effect", "allow", "actions", []any{"documents:read"}, "resources", []any{"*"})})))
	f.seed("groups", core.NewObject("id", "team", "tenantId", f.tenantID, "name", "Team"))
	err := createMany(
		core.NewObject("email", "a@example.test", "name", "A", "roleIds", []any{"reader", "reader"}, "groupIds", []any{"team"}, "expiresAt", f.now()+idDay),
		core.NewObject("email", "b@example.test", "name", "B", "emailVerified", true),
	)
	idSkipOnStub(t, idFilterAfterChange(err))
	idAfterChange(t, err)
	a := f.find("identities", core.NewObject("tenantId", f.tenantID, "email", "a@example.test"))[0]
	aID := jsString(a.Get("id"))
	bindings := f.find("bindings", core.NewObject("tenantId", f.tenantID, "subjectId", aID))
	if len(bindings) != 1 || bindings[0].Get("uniqueKey") != "identity:"+aID+":reader:"+jsString(bindings[0].Get("authorityId")) {
		t.Fatalf("bindings: %s", idJSON(t, bindings))
	}
	if members := f.find("groupMembers", core.NewObject("tenantId", f.tenantID, "identityId", aID)); len(members) != 1 || members[0].Get("uniqueKey") != "team:"+aID {
		t.Fatalf("memberships: %s", idJSON(t, members))
	}
	if a.Get("expiresAt") != f.now()+idDay {
		t.Fatal("expiry not stored")
	}
	b := f.find("identities", core.NewObject("tenantId", f.tenantID, "email", "b@example.test"))[0]
	if b.Get("emailVerified") != true {
		t.Fatal("emailVerified not stored")
	}
	// One failure rejects the whole batch.
	idExpectCode(t, createMany(core.NewObject("email", "c@example.test", "name", "C"), core.NewObject("email", "a@example.test", "name", "Again")), "IDENTITY_EXISTS")
	if len(f.find("identities", core.NewObject("tenantId", f.tenantID, "email", "c@example.test"))) != 0 {
		t.Fatal("partial batch committed")
	}
}

// idFilterAfterChange drops the tolerated afterIdentityChange stub error so idSkipOnStub only reacts to other stubs.
func idFilterAfterChange(err error) error {
	if message, ok := idStubbed(err); ok && strings.Contains(message, "afterIdentityChange") {
		return nil
	}
	return err
}

func TestIdentitiesGroupsAndBindings(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	f.seed("groups", core.NewObject("id", "team", "tenantId", f.tenantID, "name", "Team"), core.NewObject("id", "temp", "tenantId", f.tenantID, "name", "Temp"), core.NewObject("id", "old", "tenantId", f.tenantID, "name", "Old"))
	f.seed("groupMembers",
		core.NewObject("id", "m1", "tenantId", f.tenantID, "groupId", "team", "identityId", aliceID),
		core.NewObject("id", "m2", "tenantId", f.tenantID, "groupId", "temp", "identityId", aliceID, "expiresAt", f.now()+idDay),
		core.NewObject("id", "m3", "tenantId", f.tenantID, "groupId", "old", "identityId", aliceID, "expiresAt", f.now()-1),
	)
	f.grant("direct", "identity", aliceID, "documents:read")
	f.grant("team", "group", "team", "documents:write")
	groups, err := f.iam.API.Identities.ListGroups(f.ctx, owner, Input[apitypes.IdentitiesListGroupsInput](core.NewObject("tenantId", f.tenantID, "identityId", aliceID)))
	if err != nil {
		t.Fatal(err)
	}
	listed := idList(t, groups.Value)
	if strings.Join(idMembers(listed, "name"), ",") != "Team,Temp" || listed[0].Has("membershipExpiresAt") || listed[1].Get("membershipExpiresAt") != f.now()+idDay {
		t.Fatalf("listGroups: %s", idJSON(t, listed))
	}
	bindings, err := f.iam.API.Identities.ListBindings(f.ctx, owner, Input[apitypes.IdentitiesListBindingsInput](core.NewObject("tenantId", f.tenantID, "identityId", aliceID)))
	if err != nil {
		t.Fatal(err)
	}
	if roles := idMembers(idList(t, bindings.Value), "roleId"); len(roles) != 2 {
		t.Fatalf("listBindings: %v", roles)
	}
	_, err = f.iam.API.Identities.ListGroups(f.ctx, owner, Input[apitypes.IdentitiesListGroupsInput](core.NewObject("tenantId", f.tenantID, "identityId", "missing")))
	idExpectCode(t, err, "NOT_FOUND")
}

func TestIdentitiesStatusAndDeletion(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	setStatus := func(id any, status any) error {
		_, err := f.iam.API.Identities.SetStatus(f.ctx, owner, Input[apitypes.IdentitiesSetStatusInput](core.NewObject("tenantId", f.tenantID, "identityId", id, "status", status)))
		return err
	}
	idExpectCode(t, setStatus(aliceID, "paused"), "INVALID_INPUT")
	idExpectCode(t, setStatus(f.ownerID, "disabled"), "LAST_OWNER")
	agent := identity("agent-1", f.tenantID, "kind", "agent")
	f.seed("identities", agent)
	idExpectCode(t, setStatus("agent-1", "disabled"), "INVALID_INPUT")
	// Deleting yourself or the last owner is refused before anything else happens.
	_, err := f.iam.API.Identities.Delete(f.ctx, owner, Input[apitypes.IdentitiesDeleteInput](core.NewObject("tenantId", f.tenantID, "identityId", f.ownerID)))
	idExpectCode(t, err, "INVALID_INPUT")
	aliceCredential, _ := f.signIn(alice, false)
	err = setStatus(aliceID, "disabled")
	idSkipOnStub(t, idFilterAfterChange(err))
	idAfterChange(t, err)
	if f.get("identities", aliceID).Get("status") != "disabled" {
		t.Fatal("not disabled")
	}
	if _, err := f.iam.Authenticate(f.ctx, aliceCredential); err == nil {
		t.Fatal("disabled identity still authenticates")
	}
	f.seed("identities", f.get("identities", aliceID).Spread(core.NewObject("expiresAt", f.now()-1)))
	idExpectCode(t, setStatus(aliceID, "active"), "INVALID_TRANSITION")
	removed, err := f.iam.API.Identities.Delete(f.ctx, owner, Input[apitypes.IdentitiesDeleteInput](core.NewObject("tenantId", f.tenantID, "identityId", aliceID)))
	idSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	tombstone := idObject(t, removed.Value)
	if tombstone.Get("status") != "deleted" || tombstone.Has("email") || tombstone.Get("deletedEmail") != "alice@example.test" || tombstone.Has("passwordHash") ||
		tombstone.Get("uniqueKey") != "deleted:"+aliceID {
		t.Fatalf("tombstone: %s", idJSON(t, tombstone))
	}
	_, err = f.iam.API.Identities.Delete(f.ctx, owner, Input[apitypes.IdentitiesDeleteInput](core.NewObject("tenantId", f.tenantID, "identityId", aliceID)))
	idExpectCode(t, err, "CONFLICT")
}

func TestIdentitiesSameAttributes(t *testing.T) {
	if !sameAttributes(obj(t, `{"a":1,"b":[1,2]}`), obj(t, `{"b":[1,2],"a":1}`)) || sameAttributes(obj(t, `{"a":1}`), obj(t, `{"a":2}`)) ||
		!sameAttributes(core.Undefined, core.NewObject()) || sameAttributes(core.Undefined, obj(t, `{"a":null}`)) {
		t.Error("sameAttributes")
	}
}

func TestIdentitiesOffboarding(t *testing.T) {
	f := newIdentitiesFixture(t, nil)
	owner := f.ownerSignIn()
	alice := f.member("alice")
	bob := f.member("bob")
	carol := f.member("carol")
	aliceID, bobID, carolID := jsString(alice.Get("id")), jsString(bob.Get("id")), jsString(carol.Get("id"))
	f.seed("identities", f.get("identities", bobID).Spread(core.NewObject("managerId", aliceID)), f.get("identities", carolID).Spread(core.NewObject("managerId", bobID)))
	f.seed("resources", core.NewObject("id", "doc", "tenantId", f.tenantID, "type", "documents", "resourceId", "doc", "ownerId", bobID))
	f.seed("accessRequests", core.NewObject("id", "req", "tenantId", f.tenantID, "requesterId", bobID, "status", "pending", "roleIds", []any{}))
	f.seed("grantAuthorities", core.NewObject("id", "authority-bob", "tenantId", f.tenantID, "identityId", bobID, "ceiling", All(), "parentAuthorityId", f.authority, "revoked", false))
	offboard := func(id string, members ...any) (*core.Object, error) {
		body := core.NewObject("tenantId", f.tenantID, "identityId", id, "reason", "Left")
		for index := 0; index+1 < len(members); index += 2 {
			body.Set(members[index].(string), members[index+1])
		}
		out, err := f.iam.API.Identities.Offboard(f.ctx, owner, Input[apitypes.IdentitiesOffboardInput](body))
		if err != nil {
			return nil, err
		}
		return idObject(t, out.Value), nil
	}
	_, err := offboard(f.ownerID)
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = offboard(bobID, "successorId", bobID)
	idExpectCode(t, err, "INVALID_INPUT")
	_, err = offboard(bobID, "reason", "")
	idExpectCode(t, err, "INVALID_INPUT")
	offboarded, err := offboard(bobID, "successorId", aliceID)
	idSkipOnStub(t, idFilterAfterChange(err))
	idAfterChange(t, err)
	if offboarded == nil {
		t.Skip("offboarding result held back by the afterIdentityChange stub")
	}
	if offboarded.Get("reportsReassigned") != 1.0 || offboarded.Get("resourcesReassigned") != 1.0 || offboarded.Get("accessRequests") != 1.0 ||
		offboarded.Get("authorities") != 1.0 || idObject(t, offboarded.Get("identity")).Get("status") != "disabled" {
		t.Fatalf("offboard: %s", idJSON(t, offboarded))
	}
	if f.get("identities", carolID).Get("managerId") != aliceID || f.get("resources", "doc").Get("ownerId") != aliceID ||
		f.get("accessRequests", "req").Get("status") != "cancelled" || f.get("grantAuthorities", "authority-bob").Get("revoked") != true {
		t.Fatal("offboarding did not hand over")
	}
	events := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "identity:offboard"))
	if len(events) != 1 || member(events[0].Get("metadata"), "successorId") != aliceID || member(events[0].Get("metadata"), "reason") != "Left" {
		t.Fatalf("offboard audit: %s", idJSON(t, events))
	}
	second, err := offboard(aliceID)
	idAfterChange(t, err)
	if second.Get("reportsReassigned") != 2.0 || f.get("identities", carolID).Has("managerId") {
		t.Fatalf("second offboard: %s", idJSON(t, second))
	}
}
