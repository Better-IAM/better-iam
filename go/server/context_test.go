package server

// The record helpers of context.ts (the parts tests/access-windows.test.ts, tests/limits.test.ts,
// tests/owner-gates.test.ts and friends exercise through the API), access windows against the TypeScript
// insideWindow (testdata/windows.json), and secrets.ts (tests/secret-rotation.test.ts, service level).

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

func TestInsideWindowMatchesTypeScript(t *testing.T) {
	fixture := readFixture(t, "windows.json")
	cases, _ := fixture.Array("cases")
	failures := 0
	for _, item := range cases {
		window := member(item, "window").(*core.Object)
		at := member(item, "at").(float64)
		got, err := InsideWindow(window, at)
		if err != nil {
			t.Fatalf("%s: %v", core.MustStringify(window), err)
		}
		if got != member(item, "inside") {
			failures++
			if failures < 10 {
				t.Errorf("insideWindow(%s, %v) = %v, TypeScript says %v", core.MustStringify(window), at, got, member(item, "inside"))
			}
		}
	}
	if failures > 0 || len(cases) < 1000 {
		t.Fatalf("%d of %d differ", failures, len(cases))
	}
	_, err := InsideWindow(core.NewObject("from", "9:00", "to", "17:00", "timeZone", "UTC"), 0)
	expectError(t, err, "INVALID_INPUT", "Window times must be HH:MM")
	_, err = InsideWindow(core.NewObject("from", "09:00", "to", "17:00", "timeZone", "Mars/Olympus"), 0)
	if err == nil || errorName(err) != "RangeError" {
		t.Fatalf("unknown zone: %v", err)
	}
}

func TestAccessWindowValidation(t *testing.T) {
	k := newKernel(t, nil)
	for _, invalid := range []string{
		`{"from":"09:00","to":"17:00","timeZone":"Mars/Olympus"}`,
		`{"from":"9:00","to":"17:00","timeZone":"UTC"}`,
		`{"from":"09:00","to":"09:00","timeZone":"UTC"}`,
		`{"from":"09:00","to":"17:00","timeZone":"UTC","days":[7]}`,
		`{"from":"09:00","to":"17:00","timeZone":"UTC","days":[]}`,
		`{"from":"09:00","to":"17:00","timeZone":"Local"}`,
		`[]`,
	} {
		_, err := k.server.AccessWindow(parse(t, invalid))
		if err == nil || iamError(t, err).Code != "INVALID_INPUT" {
			t.Fatalf("%s: %v", invalid, err)
		}
	}
	_, err := k.server.AccessWindow(parse(t, `{"from":"09:00","to":"09:00","timeZone":"UTC"}`))
	expectError(t, err, "INVALID_INPUT", "Window must not be empty")
	_, err = k.server.AccessWindow(parse(t, `{"from":"09:00","to":"10:00","timeZone":"Nowhere/City"}`))
	expectError(t, err, "INVALID_INPUT", "Unknown window.timeZone")
	_, err = k.server.AccessWindow(parse(t, `{"from":"09:00","to":"10:00","timeZone":"UTC","days":[1,"2"]}`))
	expectError(t, err, "INVALID_INPUT", "Invalid window.days")
	window := must(k.server.AccessWindow(parse(t, `{"timeZone":"europe/berlin","days":[5,1,3,1],"to":"17:00","from":"09:00","extra":true}`)))
	if got := core.MustStringify(window); got != `{"from":"09:00","to":"17:00","timeZone":"europe/berlin","days":[1,3,5]}` {
		t.Fatal(got)
	}
	for _, zone := range []string{"UTC", "utc", "US/Eastern", "+01", "+0100", "-05:30", "Etc/GMT+5", "Europe/Kiev", "Europe/Kyiv"} {
		if _, err := LoadTimeZone(zone); err != nil {
			t.Fatalf("%s: %v", zone, err)
		}
	}
	for _, zone := range []string{"Local", "Z", "+24:00", "+1", "UTC+1", "Etc/GMT-15"} {
		if _, err := LoadTimeZone(zone); err == nil {
			t.Fatalf("%s accepted", zone)
		}
	}
	// WithinWindow: no window applies at all times.
	if inside := must(k.server.WithinWindow(core.NewObject())); !inside {
		t.Fatal("no window")
	}
}

func TestBindingAndMembershipTimes(t *testing.T) {
	k := newKernel(t, nil)
	now := float64(k.clock.Load())
	if !k.server.LiveBinding(core.NewObject()) || !k.server.LiveBinding(core.NewObject("startsAt", now, "expiresAt", now+1)) ||
		k.server.LiveBinding(core.NewObject("startsAt", now+1)) || k.server.LiveBinding(core.NewObject("expiresAt", now)) {
		t.Fatal("live binding")
	}
	if !k.server.ExpiredBinding(core.NewObject("expiresAt", now)) || k.server.ExpiredBinding(core.NewObject("startsAt", now+1)) {
		t.Fatal("expired binding")
	}
	if !k.server.LiveMembership(core.NewObject("expiresAt", now+1)) || k.server.LiveMembership(core.NewObject("expiresAt", now)) {
		t.Fatal("live membership")
	}
	if !k.server.IdentityExpired(core.NewObject("expiresAt", now)) || k.server.IdentityExpired(core.NewObject("expiresAt", "0")) {
		t.Fatal("identity expiry")
	}
	_, err := k.server.BindingStart(now - 60_001)
	expectError(t, err, "INVALID_INPUT", "startsAt must not be in the past")
	_, err = k.server.BindingStart(now + 10*365*86400000 + 1)
	expectError(t, err, "INVALID_INPUT", "startsAt must be within ten years")
	_, err = k.server.BindingStart("soon")
	expectError(t, err, "INVALID_INPUT", "Invalid startsAt")
	if got := must(k.server.BindingStart(now - 60_000)); got != now-60_000 {
		t.Fatal(got)
	}
	_, err = k.server.BindingExpiry(now)
	expectError(t, err, "INVALID_INPUT", "expiresAt must be in the future")
	_, err = k.server.BindingExpiry(now + 10*365*86400000 + 1)
	expectError(t, err, "INVALID_INPUT", "expiresAt must be within ten years")
}

func TestTenantHelpers(t *testing.T) {
	k := newKernel(t, nil)
	k.tenantTree()
	k.insert("tenants", core.NewObject("id", "loop-a", "tenantId", "loop-a", "name", "A", "type", "project", "parentId", "loop-b", "status", "active"),
		core.NewObject("id", "loop-b", "tenantId", "loop-b", "name", "B", "type", "project", "parentId", "loop-a", "status", "active"))
	_, err := k.server.Tenant(k.ctx, k.store, "missing")
	expectError(t, err, "NOT_FOUND", "Tenant not found")
	_, err = k.server.Tenant(k.ctx, k.store, core.Undefined)
	expectError(t, err, "INVALID_INPUT", "Invalid tenantId")
	project := must(k.server.Tenant(k.ctx, k.store, "project"))
	chain := must(k.server.Ancestry(k.ctx, k.store, project))
	if len(chain) != 3 || chain[2].Get("id") != "root" {
		t.Fatalf("ancestry %d", len(chain))
	}
	loop := must(k.server.Tenant(k.ctx, k.store, "loop-a"))
	_, err = k.server.Ancestry(k.ctx, k.store, loop)
	expectError(t, err, "INVALID_HIERARCHY", "Invalid tenant hierarchy")
	if ids := must(k.server.AncestorIDs(k.ctx, k.store, "project")); !reflect.DeepEqual(ids, []string{"project", "org", "root"}) {
		t.Fatal(ids)
	}
	if ids := must(k.server.AncestorIDs(k.ctx, k.store, "gone")); !reflect.DeepEqual(ids, []string{"gone"}) {
		t.Fatal(ids)
	}
	if ids := must(k.server.AncestorIDs(k.ctx, k.store, "loop-a")); !reflect.DeepEqual(ids, []string{"loop-a", "loop-b"}) {
		t.Fatal(ids)
	}
	k.insert("identities", identity("i1", "org"))
	_, err = k.server.Scoped(k.ctx, k.store, "identities", "i1", "root")
	expectError(t, err, "NOT_FOUND", "Resource not found")
	_, err = k.server.ServiceAccount(k.ctx, k.store, "i1", "org")
	expectError(t, err, "NOT_FOUND", "Service account not found")
	k.insert("identities", identity("i2", "org", "status", "deleted"))
	_, err = k.server.ActiveIdentity(k.ctx, k.store, "i2", "org")
	expectError(t, err, "NOT_FOUND", "Identity has been deleted")
	// Slugs are global aliases.
	if err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		alias, err := k.server.ClaimSlug(ctx, tx, "org", "Acme")
		if err != nil || alias != "acme" {
			t.Fatalf("%s %v", alias, err)
		}
		_, err = k.server.ClaimSlug(ctx, tx, "project", "acme")
		expectError(t, err, "SLUG_TAKEN", "This slug is already in use")
		_, err = k.server.ClaimSlug(ctx, tx, "project", "-bad")
		expectError(t, err, "INVALID_INPUT", "Slug must use 1-63 lowercase letters, digits, or hyphens")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if alias := must(k.store.Get(k.ctx, "tenantAliases", "acme")); alias.Get("createdAt") != float64(k.clock.Load()) {
		t.Fatal(core.MustStringify(alias))
	}
	// Plan limits.
	tenant := core.NewObject("id", "org", "limits", core.NewObject("groups", 2.0))
	count := func(n int) func(context.Context) (int, error) {
		return func(context.Context) (int, error) { return n, nil }
	}
	if err := k.server.EnforceLimit(k.ctx, k.store, tenant, "groups", count(1)); err != nil {
		t.Fatal(err)
	}
	err = k.server.EnforceLimit(k.ctx, k.store, tenant, "groups", count(2))
	expectError(t, err, "LIMIT_EXCEEDED", "This tenant has reached its group limit (2)")
	err = k.server.EnforceLimit(k.ctx, k.store, tenant, "groups", count(0), 3)
	expectError(t, err, "LIMIT_EXCEEDED", "This tenant has reached its group limit (2)")
	if err := k.server.EnforceLimit(k.ctx, k.store, tenant, "roles", count(100)); err != nil {
		t.Fatal(err)
	}
}

func TestOwnersAndAuthorities(t *testing.T) {
	k := newKernel(t, nil)
	k.tenantTree()
	rootAdmin := identity("root-admin", "root", "rootAdmin", true)
	owner := identity("owner", "org", "owner", true)
	member := identity("member", "org")
	k.insert("identities", rootAdmin, owner, member)
	rootPrincipal := principalOf(rootAdmin, session("s-root", "root-admin", "root", "user", "mfa", true))
	if !must(k.server.RootPrincipal(k.ctx, k.store, rootPrincipal)) {
		t.Fatal("root principal")
	}
	for _, other := range []*Principal{
		principalOf(rootAdmin, session("s1", "root-admin", "root", "user")),
		principalOf(rootAdmin, session("s2", "root-admin", "root", "api-key", "mfa", true)),
		principalOf(owner, session("s3", "owner", "org", "user", "mfa", true)),
	} {
		if must(k.server.RootPrincipal(k.ctx, k.store, other)) {
			t.Fatalf("%s is not root", jsString(other.Session.Get("id")))
		}
	}
	err := k.server.ProtectLastOwner(k.ctx, k.store, owner)
	expectError(t, err, "LAST_OWNER", "Cannot remove the final active owner")
	err = k.server.ProtectLastOwner(k.ctx, k.store, rootAdmin)
	expectError(t, err, "LAST_ROOT_ADMIN", "Cannot remove the final root administrator")
	if err := k.server.ProtectLastOwner(k.ctx, k.store, member); err != nil {
		t.Fatal(err)
	}
	// Authority chains: revoked or missing links end the chain.
	k.insert("grantAuthorities",
		core.NewObject("id", "a-parent", "tenantId", "org", "identityId", "owner", "ceiling", All(), "revoked", false),
		core.NewObject("id", "a-child", "tenantId", "org", "identityId", "member", "ceiling", All(), "revoked", false, "parentAuthorityId", "a-parent"),
		core.NewObject("id", "a-orphan", "tenantId", "org", "identityId", "member", "ceiling", All(), "revoked", false, "parentAuthorityId", "a-gone"),
		core.NewObject("id", "a-revoked", "tenantId", "org", "identityId", "member", "ceiling", All(), "revoked", true),
	)
	ceilings, ok, err := k.server.AuthorityChain(k.ctx, k.store, "a-child")
	if err != nil || !ok || len(ceilings) != 2 {
		t.Fatalf("chain %v %v %v", len(ceilings), ok, err)
	}
	if _, ok, _ := k.server.AuthorityChain(k.ctx, k.store, "a-orphan"); ok {
		t.Fatal("orphaned chain")
	}
	memberPrincipal := principalOf(member, session("s-member", "member", "org", "user"))
	authority := must(k.server.GrantingAuthority(k.ctx, k.store, memberPrincipal, "org", ""))
	if authority.Get("id") != "a-child" {
		t.Fatal(authority.Get("id"))
	}
	_, err = k.server.GrantingAuthority(k.ctx, k.store, memberPrincipal, "org", "a-parent")
	expectError(t, err, "ACCESS_DENIED", "Cannot use another administrator’s grant authority")
	_, err = k.server.GrantingAuthority(k.ctx, k.store, memberPrincipal, "org", "a-revoked")
	expectError(t, err, "ACCESS_DENIED", "Cannot use another administrator’s grant authority")
	_, err = k.server.GrantingAuthority(k.ctx, k.store, principalOf(owner, session("s-imp", "owner", "org", "user", "impersonatorId", "root-admin")), "org", "")
	expectError(t, err, "IMPERSONATION_RESTRICTED", "Access cannot be granted while impersonating")
	_, err = k.server.GrantingAuthority(k.ctx, k.store, principalOf(identity("nobody", "org"), session("s-n", "nobody", "org", "user")), "org", "")
	expectError(t, err, "GRANT_AUTHORITY_REQUIRED", "An active delegated grant authority is required")
	var rootAuthority *core.Object
	if err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		rootAuthority, err = k.server.GrantingAuthority(ctx, tx, rootPrincipal, "org", "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if rootAuthority.Get("rootIssued") != true || core.MustStringify(rootAuthority.Get("ceiling")) != core.MustStringify(All()) {
		t.Fatal(core.MustStringify(rootAuthority))
	}
	again := must(k.server.GrantingAuthority(k.ctx, k.store, rootPrincipal, "org", ""))
	if again.Get("id") != rootAuthority.Get("id") {
		t.Fatal("root authority reused")
	}
	if usable := must(k.server.GrantingAuthority(k.ctx, k.store, rootPrincipal, "org", "a-parent")); usable.Get("id") != "a-parent" {
		t.Fatal("root uses any live authority")
	}
	// Grant-bearing records are edited by their authority or root only.
	err = k.server.CanEditGrantResource(k.ctx, k.store, memberPrincipal, core.NewObject("tenantId", "org"))
	expectError(t, err, "PROTECTED_RESOURCE", "This resource is controlled by a superior authority")
	if err := k.server.CanEditGrantResource(k.ctx, k.store, memberPrincipal, core.NewObject("tenantId", "org", "authorityId", "a-child")); err != nil {
		t.Fatal(err)
	}
	if err := k.server.CanEditGrantResource(k.ctx, k.store, rootPrincipal, core.NewObject("tenantId", "org")); err != nil {
		t.Fatal(err)
	}
	// Owner setup creates the protected Owner policy, role and binding.
	org := must(k.server.Tenant(k.ctx, k.store, "org"))
	pending := core.NewObject("id", "a-owner", "tenantId", "org", "identityId", "pending", "ceiling", All(), "revoked", false)
	k.insert("grantAuthorities", pending)
	if err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		return k.server.OwnerSetup(ctx, tx, org, owner, pending)
	}); err != nil {
		t.Fatal(err)
	}
	roles := must(k.store.Find(k.ctx, "roles", core.NewObject("tenantId", "org", "uniqueKey", "system:owner"), nil))
	policies := must(k.store.Find(k.ctx, "policies", core.NewObject("tenantId", "org", "uniqueKey", "system:owner"), nil))
	bindings := must(k.store.Find(k.ctx, "bindings", core.NewObject("tenantId", "org", "subjectId", "owner"), nil))
	stored := must(k.store.Get(k.ctx, "grantAuthorities", "a-owner"))
	if len(roles) != 1 || roles[0].Get("protected") != true || len(policies) != 1 || len(bindings) != 1 ||
		bindings[0].Get("roleId") != roles[0].Get("id") || bindings[0].Get("authorityId") != "a-owner" || stored.Get("identityId") != "owner" ||
		core.MustStringify(roles[0].Get("policyIds")) != `["`+jsString(policies[0].Get("id"))+`"]` {
		t.Fatal("owner setup")
	}
	if !strings.Contains(core.MustStringify(policies[0]), `"document":{"version":1,"statements":[{"effect":"allow","actions":["*"],"resources":["*"]}]},"version":1`) {
		t.Fatal(core.MustStringify(policies[0]))
	}
}

func TestRevokeAllEndsDirectAndAssumedSessions(t *testing.T) {
	k := newKernel(t, nil)
	k.tenantTree()
	k.insert("identities", identity("alice", "org"))
	k.insert("sessions",
		session("direct", "alice", "org", "user"),
		session("assumed", "role-identity", "project", "role", "originalIdentityId", "alice"),
		session("other", "bob", "org", "user"),
	)
	if err := k.tx(func(ctx context.Context, tx core.IamStore) error { return k.server.RevokeAll(ctx, tx, "alice") }); err != nil {
		t.Fatal(err)
	}
	left := must(k.store.Find(k.ctx, "sessions", nil, nil))
	if len(left) != 1 || left[0].Get("id") != "other" {
		t.Fatalf("%d sessions left", len(left))
	}
}

func TestRotateSecretsReSealsEveryField(t *testing.T) {
	const previous = "previous-deployment-secret-with-32-characters"
	k := newKernel(t, func(options *BetterIamOptions) { options.PreviousSecrets = []string{previous} })
	seal := func(secret, value, context string) string { return auth.EncryptSecret(value, secret, context) }
	k.insert("authMfa", core.NewObject("id", "m1", "tenantId", "org", "identityId", "alice", "encryptedSecret", seal(previous, "totp", "mfa:alice")),
		core.NewObject("id", "m2", "tenantId", "org", "identityId", "bob", "encryptedSecret", seal(testSecret, "totp", "mfa:bob")),
		core.NewObject("id", "m3", "tenantId", "org", "identityId", "carol", "encryptedSecret", seal("gone-secret-with-at-least-32-characters!", "x", "mfa:carol")))
	k.insert("webhooks", core.NewObject("id", "w1", "tenantId", "org", "secretSealed", seal(previous, "whsec", "webhook:w1")))
	k.insert("outbox",
		core.NewObject("id", "o1", "tenantId", "org", "kind", "email", "payload", core.NewObject("sealed", seal(previous, "{}", "outbox:o1"))),
		core.NewObject("id", "o2", "tenantId", "org", "kind", "email", "deliveredAt", 1.0, "payload", core.NewObject("sealed", seal(previous, "{}", "outbox:o2"))))
	k.insert("kmsKeyVersions", core.NewObject("id", "k1", "tenantId", "org", "keyId", "key", "version", 2.0, "wrapper", "secret", "materialSealed", seal(previous, "m", "kms-key:key:2")),
		core.NewObject("id", "k2", "tenantId", "org", "keyId", "key", "version", 3.0, "wrapper", "kms", "materialSealed", seal(previous, "m", "kms-key:key:3")))
	k.insert("vaultVersions", core.NewObject("id", "v1", "tenantId", "org", "secretId", "s", "version", 1.0, "sealed", seal(previous, "v", "vault:org:s:1")),
		core.NewObject("id", "v2", "tenantId", "org", "secretId", "s", "version", 2.0, "kmsKeyId", "key", "sealed", "kms-ciphertext"))
	k.insert("signalSources", core.NewObject("id", "src", "tenantId", "org", "poll", core.NewObject("url", "https://x", "tokenSealed", seal(previous, "t", "signal-poll:src"))))
	for collection, context := range map[string]string{"inferenceProviders": "inference-provider:", "sshAuthorities": "ssh-authority:", "vcIssuerKeys": "vc-issuer-key:"} {
		k.insert(collection, core.NewObject("id", "x1", "tenantId", "org", "keySealed", seal(previous, "key", context+"x1")))
	}
	k.insert("vaultLeases", core.NewObject("id", "l1", "tenantId", "org", "handleSealed", seal(previous, "h", "vault-lease:l1")))

	_, err := RotateSecrets(k.ctx, k.server, SecretRotationOptions{BatchSize: float(0)})
	expectError(t, err, "INVALID_INPUT", "batchSize must be an integer between 1 and 2000")
	_, err = RotateSecrets(k.ctx, k.server, SecretRotationOptions{Limit: float(1.5)})
	expectError(t, err, "INVALID_INPUT", "limit must be a positive integer")

	dry := must(RotateSecrets(k.ctx, k.server, SecretRotationOptions{DryRun: true, BatchSize: float(1)}))
	want := `{"resealed":{"authMfa":1,"webhooks":1,"outbox":1,"inferenceProviders":1,"kmsKeyVersions":1,"vaultVersions":1,"vaultLeases":1,"sshAuthorities":1,"vcIssuerKeys":1,"signalSources":1},"unreadable":{"authMfa":1},"current":1,"complete":true,"done":false}`
	if got := core.MustStringify(core.Normalize(dry)); got != want {
		t.Fatalf("dry run:\n got %s\nwant %s", got, want)
	}
	sample := must(RotateSecrets(k.ctx, k.server, SecretRotationOptions{DryRun: true, Limit: float(1)}))
	if sample.Complete || sample.Done {
		t.Fatalf("a limited sample is incomplete: %+v", sample)
	}
	rotated := must(RotateSecrets(k.ctx, k.server, SecretRotationOptions{}))
	if rotated.Resealed.Len() != 10 || !rotated.Done {
		t.Fatalf("rotation %s", core.MustStringify(core.Normalize(rotated)))
	}
	after := must(RotateSecrets(k.ctx, k.server, SecretRotationOptions{DryRun: true}))
	if after.Resealed.Len() != 0 || after.Current != 11 || !after.Done {
		t.Fatalf("after %s", core.MustStringify(core.Normalize(after)))
	}
	webhook := must(k.store.Get(k.ctx, "webhooks", "w1"))
	if value := must(auth.DecryptSecret(jsString(webhook.Get("secretSealed")), []string{testSecret}, "webhook:w1")); value != "whsec" {
		t.Fatal(value)
	}
	source := must(k.store.Get(k.ctx, "signalSources", "src"))
	if member(source.Get("poll"), "url") != "https://x" {
		t.Fatal("nested write keeps the other members")
	}
	delivered := must(k.store.Get(k.ctx, "outbox", "o2"))
	if _, ok := auth.OpenSecret(jsString(member(delivered.Get("payload"), "sealed")), []string{testSecret}, "outbox:o2"); ok {
		t.Fatal("delivered outbox messages are not re-sealed")
	}
}
