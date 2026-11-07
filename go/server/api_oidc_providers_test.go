package server

// Port of tests/oidc-providers.test.ts and tests/oidc-provider-update-sessions.test.ts: OIDC provider management
// (`oidcProviders.*`) with permissions and recent authentication, the feature gate, issuer, key and URL validation, the
// per-tenant issuer uniqueness, editing only under the creator's grant authority, the refusal to delete a provider that
// live trusts still use, and the sessions an update ends.
//
// Providers are created through `oidcProviders.create`, whose validation is web-identity.ts's (another unit), and
// sessions end through temporary-credentials.ts's deleteTemporarySessions (another unit). Steps that reach those
// skip while they are stubs (appsPorted); the steps that do not are exercised with providers, trusts and roles seeded
// as records, the way the TypeScript test seeds its feature-off provider.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	oidcIssuer   = "https://token.actions.example.test"
	oidcAudience = "https://acme.example"
)

// appsPorted skips the rest of a test when a step reached another unit's NOT_IMPLEMENTED stub.
func appsPorted(t *testing.T, err error) {
	t.Helper()
	var known *core.IamError
	if errors.As(err, &known) && known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
}

// oidcTestKey is a public RS256 JWK (tests/support/jwt-keys.ts generateTestKey(...).publicJwk).
func oidcTestKey(t *testing.T, kid string) *core.Object {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
	return core.NewObject("kty", "RSA", "kid", kid, "alg", "RS256", "use", "sig",
		"n", encode(key.N.Bytes()), "e", encode(big.NewInt(int64(key.E)).Bytes()))
}

// oidcFixture is the organization with sts.webIdentity configured (enabled unless the options say otherwise).
func oidcFixture(t *testing.T, webIdentity *StsWebIdentityOptions) *appsOrg {
	return newAppsOrg(t, func(options *BetterIamOptions) {
		if webIdentity != nil {
			options.Sts = &StsOptions{WebIdentity: webIdentity}
		}
	})
}

func oidcEnabled(members func(options *StsWebIdentityOptions)) *StsWebIdentityOptions {
	options := &StsWebIdentityOptions{Enabled: flag(true)}
	if members != nil {
		members(options)
	}
	return options
}

func oidcInput(f *appsOrg, key *core.Object, extra *core.Object) *core.Object {
	input := core.NewObject("tenantId", f.tenantID, "name", "GitHub Actions", "issuer", oidcIssuer,
		"audiences", []any{oidcAudience}, "jwks", core.NewObject("keys", []any{key}))
	if extra != nil {
		extra.Entries(func(name string, value any) bool {
			if isUndefined(value) {
				input.Delete(name)
			} else {
				input.Set(name, value)
			}
			return true
		})
	}
	return input
}

func (f *appsOrg) oidcCreate(credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	out, err := f.iam.API.OidcProviders.Create(f.ctx, credential, Input[apitypes.OidcProvidersCreateInput](input))
	if err != nil {
		return nil, err
	}
	return appsObject(f.t, out.Value, nil), nil
}

func (f *appsOrg) oidcUpdate(credential core.CredentialInput, providerID any, fields *core.Object) (*core.Object, error) {
	out, err := f.iam.API.OidcProviders.Update(f.ctx, credential, Input[apitypes.OidcProvidersUpdateInput](
		core.NewObject("tenantId", f.tenantID, "providerId", providerID).Assign(fields)))
	if err != nil {
		return nil, err
	}
	return appsObject(f.t, out.Value, nil), nil
}

func (f *appsOrg) oidcTarget(providerID any) *core.Object {
	return core.NewObject("tenantId", f.tenantID, "providerId", providerID)
}

func (f *appsOrg) oidcGet(credential core.CredentialInput, providerID any) (*core.Object, error) {
	out, err := f.iam.API.OidcProviders.Get(f.ctx, credential, Input[apitypes.OidcProvidersGetInput](f.oidcTarget(providerID)))
	if err != nil {
		return nil, err
	}
	return appsObject(f.t, out.Value, nil), nil
}

func (f *appsOrg) oidcList(credential core.CredentialInput) ([]*core.Object, error) {
	out, err := f.iam.API.OidcProviders.List(f.ctx, credential, Input[apitypes.OidcProvidersListInput](core.NewObject("tenantId", f.tenantID)))
	if err != nil {
		return nil, err
	}
	return appsList(f.t, out.Value, nil), nil
}

func (f *appsOrg) oidcDelete(credential core.CredentialInput, providerID any) (*core.Object, error) {
	out, err := f.iam.API.OidcProviders.Delete(f.ctx, credential, Input[apitypes.OidcProvidersDeleteInput](f.oidcTarget(providerID)))
	if err != nil {
		return nil, err
	}
	return appsObject(f.t, out.Value, nil), nil
}

func (f *appsOrg) oidcRevokeSessions(credential core.CredentialInput, providerID any, before any) (*core.Object, error) {
	input := f.oidcTarget(providerID)
	if !isUndefined(before) {
		input.Set("before", before)
	}
	out, err := f.iam.API.OidcProviders.RevokeSessions(f.ctx, credential, Input[apitypes.OidcProvidersRevokeSessionsInput](input))
	if err != nil {
		return nil, err
	}
	return appsObject(f.t, out.Value, nil), nil
}

// seedProvider is a provider registered while the feature was on, as the TypeScript test seeds it.
func (f *appsOrg) seedProvider(key *core.Object, issuer string, authorityID any) *core.Object {
	now := float64(f.now())
	provider := core.NewObject("id", ID(), "tenantId", f.tenantID, "uniqueKey", "issuer:"+issuer, "name", "GitHub Actions",
		"issuer", issuer, "audiences", []any{oidcAudience}, "jwks", core.NewObject("keys", []any{key}), "algorithms", []any{"RS256"},
		"maxTokenLifetimeSeconds", 3600.0, "clockToleranceSeconds", 30.0, "replayProtection", "single-use", "enabled", true,
		"authorityId", authorityID, "createdAt", now, "createdBy", f.ownerID, "updatedAt", now)
	if isUndefined(authorityID) {
		provider.Delete("authorityId")
	}
	return f.insert("oidcProviders", provider)
}

// seedTrust is a web trust through the provider, as trust.create writes it.
func (f *appsOrg) seedTrust(providerID any) *core.Object {
	now := float64(f.now())
	return f.insert("trusts", core.NewObject("id", ID(), "tenantId", f.tenantID, "kind", "web-identity", "sourceTenantId", f.tenantID,
		"sourceIdentityId", ID(), "roleId", ID(), "requireMfa", false, "revoked", false, "providerId", providerID,
		"conditions", obj(f.t, `{"StringEquals":{"token.sub":"repo:acme/app:ref:refs/heads/main"}}`),
		"authorityId", f.ownerAuthorityID, "createdAt", now, "updatedAt", now))
}

// seedSession is a live web-identity session through the trust.
func (f *appsOrg) seedSession(trust, provider *core.Object) string {
	now := float64(f.now())
	tokenHash := "hash-" + ID()
	id := ID()
	f.insert("sessions", core.NewObject("id", id, "tenantId", f.tenantID, "identityId", trust.Get("sourceIdentityId"),
		"originalIdentityId", trust.Get("sourceIdentityId"), "roleId", trust.Get("roleId"), "trustId", trust.Get("id"), "kind", "role",
		"tokenHash", tokenHash, "createdAt", now, "lastSeenAt", now, "authenticatedAt", now, "expiresAt", now+900_000, "mfa", false,
		"credentialAuthorityId", f.ownerAuthorityID,
		"webIdentity", core.NewObject("providerId", provider.Get("id"), "issuer", provider.Get("issuer"), "subject", "repo:acme/app"),
		"uniqueKey", tokenHash))
	return id
}

// administrator is a member holding the given IAM permissions through a role, optionally with a delegated grant
// authority (authorities.create as the owner).
func (f *appsOrg) administrator(name string, permissions []string, authority bool) (identity *core.Object, credential core.CredentialInput, authorityID string) {
	identity = f.memberIdentity(name)
	actions := make([]any, len(permissions))
	for index, permission := range permissions {
		actions[index] = permission
	}
	f.role(name+" role", core.NewObject("version", 1.0, "statements", []any{
		core.NewObject("effect", "allow", "actions", actions, "resources", []any{"*"}),
	}), identity.Get("id"))
	if authority {
		created := f.insert("grantAuthorities", core.NewObject("id", ID(), "tenantId", f.tenantID, "identityId", identity.Get("id"),
			"parentAuthorityId", f.ownerAuthorityID, "ceiling", All(), "revoked", false))
		authorityID = jsString(created.Get("id"))
	}
	return identity, f.token(name), authorityID
}

// rootCredential is a root administrator session with MFA (the fixture's rootCredential).
func (f *appsOrg) rootCredential() core.CredentialInput {
	f.t.Helper()
	var issued *core.Object
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		root, err := tx.Get(ctx, "identities", f.rootID)
		if err != nil {
			return err
		}
		issued, err = f.iam.Auth.IssueSession(ctx, tx, root, auth.IssueSessionOptions{Mfa: true})
		return err
	})
	return core.CredentialInput{Token: jsString(issued.Get("token"))}
}

func oidcSortedKeys(object *core.Object) string {
	keys := object.Keys()
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func TestOidcProvidersCreateReadUpdateDelete(t *testing.T) {
	f := oidcFixture(t, oidcEnabled(nil))
	key := oidcTestKey(t, "rsa-1")
	created, err := f.oidcCreate(f.owner, oidcInput(f, key, nil))
	appsPorted(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if got := oidcSortedKeys(created); got != "algorithms,audiences,authorityId,clockToleranceSeconds,createdAt,createdBy,enabled,id,issuer,jwks,maxTokenLifetimeSeconds,name,replayProtection,tenantId,updatedAt" {
		t.Fatalf("public members: %s", got)
	}
	expectJSON(t, created.Get("algorithms"), `["RS256","ES256"]`)
	if created.Get("maxTokenLifetimeSeconds") != 3600.0 || created.Get("clockToleranceSeconds") != 30.0 ||
		created.Get("replayProtection") != "single-use" || created.Get("enabled") != true || created.Get("createdBy") != f.ownerID ||
		jsNumber(created.Get("createdAt")) != float64(f.now()) {
		t.Fatalf("created: %v", created)
	}
	stored := f.get("oidcProviders", jsString(created.Get("id")))
	if stored.Get("uniqueKey") != "issuer:"+oidcIssuer {
		t.Fatalf("uniqueKey %v", stored.Get("uniqueKey"))
	}
	if authority := f.get("grantAuthorities", jsString(created.Get("authorityId"))); authority.Get("identityId") != f.ownerID {
		t.Fatalf("authority %v", authority)
	}
	got := f.mustPorted(f.oidcGet(f.owner, created.Get("id")))
	expectJSON(t, got, core.MustStringify(created))
	f.advance(1000)
	updated, err := f.oidcUpdate(f.owner, created.Get("id"), core.NewObject("name", "GitHub",
		"audiences", []any{oidcAudience, "sts.amazonaws.com"}, "jwks", nil, "jwksUri", "https://token.actions.example.test/.well-known/jwks",
		"algorithms", []any{"RS256"}, "maxTokenLifetimeSeconds", 600.0, "clockToleranceSeconds", 5.0, "replayProtection", "off"))
	appsPorted(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Get("name") != "GitHub" || updated.Get("jwksUri") != "https://token.actions.example.test/.well-known/jwks" ||
		!isUndefined(updated.Get("jwks")) || jsNumber(updated.Get("updatedAt")) != float64(f.now()) {
		t.Fatalf("updated: %v", updated)
	}
	_, err = f.oidcUpdate(f.owner, created.Get("id"), core.NewObject("name", "GitHub"))
	expectError(t, err, "INVALID_INPUT", "The update changes nothing")
	_, err = f.oidcUpdate(f.owner, created.Get("id"), core.NewObject("issuer", "https://other.example.test"))
	appsCode(t, err, "INVALID_INPUT")
	_, err = f.oidcUpdate(f.owner, created.Get("id"), core.NewObject("jwks", core.NewObject("keys", []any{key})))
	expectError(t, err, "INVALID_INPUT", "Give jwks or jwksUri, not both")
	deleted, err := f.oidcDelete(f.owner, created.Get("id"))
	appsPorted(t, err)
	expectJSON(t, appsValue(t, deleted, err), `{"deleted":true}`)
	_, err = f.oidcGet(f.owner, created.Get("id"))
	appsCode(t, err, "NOT_FOUND")
}

func TestOidcProvidersReadAndManageUnderThePermissionsAndRecentAuthentication(t *testing.T) {
	// The feature is off: reads, deletion and session revocation keep working, which is what this test exercises.
	f := oidcFixture(t, nil)
	key := oidcTestKey(t, "rsa-1")
	_, reader, _ := f.administrator("reader", []string{"iam:oidc-providers:read"}, false)
	_, nobody, _ := f.administrator("nobody", []string{"iam:trust:read"}, false)
	provider := f.seedProvider(key, oidcIssuer, f.ownerAuthorityID)
	public := ToPublicOidcProvider(provider)
	expectJSON(t, f.mustPorted(f.oidcGet(reader, provider.Get("id"))), core.MustStringify(public))
	if got := oidcSortedKeys(public); got != "algorithms,audiences,authorityId,clockToleranceSeconds,createdAt,createdBy,enabled,id,issuer,jwks,maxTokenLifetimeSeconds,name,replayProtection,tenantId,updatedAt" {
		t.Fatalf("public members: %s", got)
	}
	_, err := f.oidcList(nobody)
	appsCode(t, err, "ACCESS_DENIED")
	_, err = f.oidcDelete(reader, provider.Get("id"))
	appsCode(t, err, "ACCESS_DENIED")
	_, err = f.oidcRevokeSessions(reader, provider.Get("id"), core.Undefined)
	appsCode(t, err, "ACCESS_DENIED")
	// Past the five-minute window the owner's session may still read, but not change anything.
	f.advance(6 * 60_000)
	if got := f.mustPorted(f.oidcGet(f.owner, provider.Get("id"))); got.Get("id") != provider.Get("id") {
		t.Fatalf("get: %v", got)
	}
	_, err = f.oidcDelete(f.owner, provider.Get("id"))
	appsCode(t, err, "RECENT_AUTH_REQUIRED")
	_, err = f.oidcRevokeSessions(f.owner, provider.Get("id"), core.Undefined)
	appsCode(t, err, "RECENT_AUTH_REQUIRED")
	_, err = f.oidcUpdate(f.owner, provider.Get("id"), core.NewObject("enabled", false))
	appsCode(t, err, "RECENT_AUTH_REQUIRED")
	fresh := f.ownerSignIn()
	// Revoking sessions moves the watermark (no later than now + 1), keeps updatedAt, and is audited.
	_, err = f.oidcRevokeSessions(fresh, provider.Get("id"), float64(f.now()+2))
	expectError(t, err, "INVALID_INPUT", "before must be a time no later than now")
	revoked := f.mustPorted(f.oidcRevokeSessions(fresh, provider.Get("id"), core.Undefined))
	expectJSON(t, revoked, `{"providerId":"`+jsString(provider.Get("id"))+`","sessionsRevokedBefore":`+core.NumberString(float64(f.now()+1))+`,"revoked":0}`)
	stored := f.get("oidcProviders", jsString(provider.Get("id")))
	if jsNumber(stored.Get("sessionsRevokedBefore")) != float64(f.now()+1) || stored.Get("updatedAt") != provider.Get("updatedAt") {
		t.Fatalf("stored after revokeSessions: %v", stored)
	}
	var audited *core.Object
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if event.Get("action") == "role:sessions-revoked" {
			audited = event
		}
	}
	if audited == nil || audited.Get("resourceId") != provider.Get("id") || jsNumber(member(audited.Get("metadata"), "revoked")) != 0 {
		t.Fatalf("audit: %v", audited)
	}
	// An earlier watermark never moves it back.
	again := f.mustPorted(f.oidcRevokeSessions(fresh, provider.Get("id"), float64(f.now()-1000)))
	if jsNumber(again.Get("sessionsRevokedBefore")) != float64(f.now()+1) {
		t.Fatalf("watermark moved back: %v", again)
	}
	expectJSON(t, appsValue(t, f.mustPorted(f.oidcDelete(fresh, provider.Get("id"))), nil), `{"deleted":true}`)
}

func TestOidcProvidersAreGatedByTheFeatureExceptReadsDisablingAndDeletion(t *testing.T) {
	f := oidcFixture(t, nil)
	key := oidcTestKey(t, "rsa-1")
	_, err := f.oidcCreate(f.owner, oidcInput(f, key, nil))
	if known := iamError(t, err); known.Code != "FEATURE_DISABLED" || known.Status != 403 || known.Message != "Web identity federation is not enabled" {
		t.Fatalf("create with the feature off: %v", known)
	}
	provider := f.seedProvider(key, oidcIssuer, f.ownerAuthorityID)
	_, err = f.oidcUpdate(f.owner, provider.Get("id"), core.NewObject("name", "Renamed"))
	appsCode(t, err, "FEATURE_DISABLED")
	_, err = f.oidcUpdate(f.owner, provider.Get("id"), core.NewObject("enabled", true, "name", "x"))
	appsCode(t, err, "FEATURE_DISABLED")
	trust := f.seedTrust(provider.Get("id"))
	// Deletion waits for the trust to be revoked, which also works with the feature off.
	_, err = f.oidcDelete(f.owner, provider.Get("id"))
	expectError(t, err, "CONFLICT", "Revoke the trusts that use this provider first")
	list := must(f.oidcList(f.owner))
	if len(list) != 1 || list[0].Get("id") != provider.Get("id") {
		t.Fatalf("list: %v", list)
	}
	// The kill switch keeps working, and ends the provider's sessions for good.
	session := f.seedSession(trust, provider)
	disabled, err := f.oidcUpdate(f.owner, provider.Get("id"), core.NewObject("enabled", false))
	appsPorted(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Get("enabled") != false || jsNumber(disabled.Get("sessionsRevokedBefore")) != float64(f.now()+1) {
		t.Fatalf("disabled: %v", disabled)
	}
	if f.get("sessions", session) != nil {
		t.Fatal("the provider's session outlived the kill switch")
	}
}

func TestOidcProvidersDisableWithoutTrustsAndRefuseEmptyUpdates(t *testing.T) {
	f := oidcFixture(t, nil)
	provider := f.seedProvider(oidcTestKey(t, "rsa-1"), oidcIssuer, f.ownerAuthorityID)
	f.advance(1000)
	disabled := f.mustPorted(f.oidcUpdate(f.owner, provider.Get("id"), core.NewObject("enabled", false)))
	if disabled.Get("enabled") != false || jsNumber(disabled.Get("sessionsRevokedBefore")) != float64(f.now()+1) ||
		jsNumber(disabled.Get("updatedAt")) != float64(f.now()) {
		t.Fatalf("disabled: %v", disabled)
	}
	_, err := f.oidcUpdate(f.owner, provider.Get("id"), core.NewObject("enabled", false))
	expectError(t, err, "INVALID_INPUT", "The update changes nothing")
	_, err = f.oidcUpdate(f.owner, provider.Get("id"), core.NewObject("enabled", true))
	appsCode(t, err, "FEATURE_DISABLED")
	_, err = f.oidcUpdate(f.owner, provider.Get("id"), core.NewObject("enabled", false, "issuer", "https://other.example.test"))
	expectError(t, err, "INVALID_INPUT", "The issuer of a provider cannot change")
	_, err = f.oidcUpdate(f.owner, nil, core.NewObject("enabled", false))
	appsCode(t, err, "INVALID_INPUT")
}

func TestOidcProvidersLetOnlyTheCreatorsAuthorityOrRootEdit(t *testing.T) {
	f := oidcFixture(t, nil)
	permissions := []string{"iam:oidc-providers:create", "iam:oidc-providers:read", "iam:oidc-providers:update", "iam:oidc-providers:delete"}
	_, admin, adminAuthority := f.administrator("admin", permissions, true)
	key := oidcTestKey(t, "rsa-1")
	mine := f.seedProvider(key, oidcIssuer, adminAuthority)
	owners := f.seedProvider(key, "https://gitlab.example.test", f.ownerAuthorityID)
	// Neither can edit or delete the other's provider.
	_, err := f.oidcUpdate(f.owner, mine.Get("id"), core.NewObject("enabled", false))
	appsCode(t, err, "ACCESS_DENIED")
	_, err = f.oidcDelete(admin, owners.Get("id"))
	appsCode(t, err, "ACCESS_DENIED")
	// A provider without an authority is controlled by a superior authority.
	orphan := f.seedProvider(key, "https://orphan.example.test", core.Undefined)
	_, err = f.oidcUpdate(f.owner, orphan.Get("id"), core.NewObject("enabled", false))
	expectError(t, err, "PROTECTED_RESOURCE", "This resource is controlled by a superior authority")
	// The creator and root may.
	if got := f.mustPorted(f.oidcUpdate(admin, mine.Get("id"), core.NewObject("enabled", false))); got.Get("enabled") != false {
		t.Fatalf("admin's update: %v", got)
	}
	if got := f.mustPorted(f.oidcUpdate(f.rootCredential(), orphan.Get("id"), core.NewObject("enabled", false))); got.Get("enabled") != false {
		t.Fatalf("root's update: %v", got)
	}
}

func TestOidcProvidersCreateUnderADelegatedAuthorityOnly(t *testing.T) {
	f := oidcFixture(t, oidcEnabled(nil))
	permissions := []string{"iam:oidc-providers:create", "iam:oidc-providers:read", "iam:oidc-providers:update", "iam:oidc-providers:delete"}
	_, admin, _ := f.administrator("admin", permissions, true)
	_, unauthorized, _ := f.administrator("helper", permissions, false)
	key := oidcTestKey(t, "rsa-1")
	_, err := f.oidcCreate(unauthorized, oidcInput(f, key, nil))
	appsPorted(t, err)
	appsCode(t, err, "GRANT_AUTHORITY_REQUIRED")
	mine := f.mustPorted(f.oidcCreate(admin, oidcInput(f, key, nil)))
	owners := f.mustPorted(f.oidcCreate(f.owner, oidcInput(f, key, core.NewObject("issuer", "https://gitlab.example.test"))))
	if mine.Get("authorityId") == owners.Get("authorityId") {
		t.Fatal("both providers carry one authority")
	}
}

func TestOidcProvidersValidateTheirInput(t *testing.T) {
	f := oidcFixture(t, oidcEnabled(nil))
	key := oidcTestKey(t, "rsa-1")
	selfIssuer := f.iam.Endpoint.Origin + f.iam.Endpoint.BasePath
	invalid := []*core.Object{
		core.NewObject("jwks", core.NewObject("keys", []any{})),
		core.NewObject("jwks", core.NewObject("keys", []any{key.Spread(core.NewObject("d", "secret"))})),
		core.NewObject("jwks", core.Undefined, "jwksUri", "http://keys.example.test/jwks"),
		core.NewObject("jwks", core.Undefined, "jwksUri", "https://keys.example.test:8443/jwks"),
		core.NewObject("jwks", core.Undefined, "jwksUri", "https://user:pass@keys.example.test/jwks"),
		core.NewObject("jwks", core.Undefined, "jwksUri", "https://10.0.0.1/jwks"),
		core.NewObject("jwksUri", "https://keys.example.test/jwks"),
		core.NewObject("issuer", "http://token.actions.example.test"),
		core.NewObject("issuer", "not a url"),
		core.NewObject("issuer", "https://token.actions.example.test?tenant=1"),
		core.NewObject("issuer", "https://token.actions.example.test#fragment"),
		core.NewObject("issuer", "https://"+strings.Repeat("a", 510)+".test"),
		core.NewObject("issuer", selfIssuer),
		core.NewObject("issuer", selfIssuer+"/"),
		core.NewObject("audiences", []any{}),
		core.NewObject("audiences", []any{strings.Repeat("x", 257)}),
		core.NewObject("algorithms", []any{"HS256"}),
		core.NewObject("algorithms", []any{"none"}),
		core.NewObject("algorithms", []any{}),
		core.NewObject("maxTokenLifetimeSeconds", 59.0),
		core.NewObject("maxTokenLifetimeSeconds", 86401.0),
		core.NewObject("clockToleranceSeconds", 121.0),
		core.NewObject("clockToleranceSeconds", -1.0),
		core.NewObject("replayProtection", "sometimes"),
		core.NewObject("enabled", "yes"),
		core.NewObject("name", ""),
	}
	for _, extra := range invalid {
		_, err := f.oidcCreate(f.owner, oidcInput(f, key, extra))
		appsPorted(t, err)
		appsCode(t, err, "INVALID_INPUT")
	}
	if left := f.find("oidcProviders", core.NewObject("tenantId", f.tenantID)); len(left) != 0 {
		t.Fatalf("providers stored: %v", left)
	}
	// One provider per issuer in a tenant; another issuer is fine, with keys found by discovery.
	f.mustPorted(f.oidcCreate(f.owner, oidcInput(f, key, nil)))
	_, err := f.oidcCreate(f.owner, oidcInput(f, key, core.NewObject("name", "Again")))
	expectError(t, err, "CONFLICT", "A provider for this issuer already exists")
	discovered := f.mustPorted(f.oidcCreate(f.owner, oidcInput(f, key, core.NewObject("issuer", "https://gitlab.example.test", "jwks", core.Undefined))))
	if !isUndefined(discovered.Get("jwks")) || !isUndefined(discovered.Get("jwksUri")) {
		t.Fatalf("discovered: %v", discovered)
	}
	// Loopback http issuers only with the development switch.
	dev := oidcFixture(t, oidcEnabled(func(options *StsWebIdentityOptions) { options.AllowInsecureLocalhost = flag(true) }))
	created := dev.mustPorted(dev.oidcCreate(dev.owner, oidcInput(dev, key, core.NewObject("issuer", "http://127.0.0.1:8080/idp"))))
	if created.Get("issuer") != "http://127.0.0.1:8080/idp" {
		t.Fatalf("dev issuer: %v", created.Get("issuer"))
	}
}

func TestOidcProvidersEnforceAllowedIssuers(t *testing.T) {
	f := oidcFixture(t, oidcEnabled(func(options *StsWebIdentityOptions) { options.AllowedIssuers = []string{oidcIssuer} }))
	key := oidcTestKey(t, "rsa-1")
	_, err := f.oidcCreate(f.owner, oidcInput(f, key, core.NewObject("issuer", "https://gitlab.example.test")))
	appsPorted(t, err)
	expectError(t, err, "INVALID_INPUT", "The issuer is not in sts.webIdentity.allowedIssuers")
	if got := f.mustPorted(f.oidcCreate(f.owner, oidcInput(f, key, nil))); got.Get("issuer") != oidcIssuer {
		t.Fatalf("issuer: %v", got.Get("issuer"))
	}
}

func TestOidcProvidersEndSessionsWhenKeysOrClaimRulesChangeNotOnARename(t *testing.T) {
	f := oidcFixture(t, oidcEnabled(nil))
	provider := f.seedProvider(oidcTestKey(t, "rsa-1"), oidcIssuer, f.ownerAuthorityID)
	trust := f.seedTrust(provider.Get("id"))
	alive := func(id string) bool { return f.get("sessions", id) != nil }
	update := func(fields *core.Object) *core.Object {
		t.Helper()
		updated, err := f.oidcUpdate(f.owner, provider.Get("id"), fields)
		appsPorted(t, err)
		if err != nil {
			t.Fatal(err)
		}
		return updated
	}
	// A rename and the replay switch keep live sessions.
	kept := f.seedSession(trust, provider)
	for _, fields := range []*core.Object{core.NewObject("name", "GitHub"), core.NewObject("replayProtection", "off")} {
		if got := update(fields); !isUndefined(got.Get("sessionsRevokedBefore")) {
			t.Fatalf("a %v update moved the watermark", fields)
		}
	}
	if !alive(kept) {
		t.Fatal("a rename ended a session")
	}
	// The kill switch ends them for good: re-enabling the provider moves no watermark.
	f.advance(1000)
	killed := f.seedSession(trust, provider)
	disabled := update(core.NewObject("enabled", false))
	if jsNumber(disabled.Get("sessionsRevokedBefore")) != float64(f.now()+1) || alive(killed) || alive(kept) {
		t.Fatalf("disabled: %v", disabled)
	}
	f.advance(1000)
	enabled := update(core.NewObject("enabled", true))
	if enabled.Get("sessionsRevokedBefore") != disabled.Get("sessionsRevokedBefore") || enabled.Get("enabled") != true {
		t.Fatalf("enabled: %v", enabled)
	}
	watermark := jsNumber(disabled.Get("sessionsRevokedBefore"))
	for _, fields := range []*core.Object{
		core.NewObject("audiences", []any{oidcAudience, "sts.amazonaws.com"}),
		core.NewObject("algorithms", []any{"RS256", "ES256", "EdDSA"}),
		core.NewObject("maxTokenLifetimeSeconds", 600.0),
		core.NewObject("clockToleranceSeconds", 5.0),
		core.NewObject("jwks", core.NewObject("keys", []any{oidcTestKey(t, "rsa-2")})),
		core.NewObject("jwks", nil, "jwksUri", "https://token.actions.example.test/.well-known/jwks"),
		core.NewObject("jwksUri", "https://keys.example.test/jwks"),
	} {
		f.advance(1000)
		older := f.seedSession(trust, provider)
		updated := update(fields)
		if got := jsNumber(updated.Get("sessionsRevokedBefore")); got != float64(f.now()+1) || got <= watermark || alive(older) {
			t.Fatalf("%v: %v", fields, updated)
		}
		watermark = jsNumber(updated.Get("sessionsRevokedBefore"))
	}
}

func TestOidcIssuerKeyHashesLongIssuers(t *testing.T) {
	if got := oidcIssuerKey("https://idp.example.test"); got != "issuer:https://idp.example.test" {
		t.Fatalf("short issuer key %q", got)
	}
	long := "https://" + strings.Repeat("a", 510) + ".test"
	if got := oidcIssuerKey(long); got != "issuer#sha256:"+Hash(long) {
		t.Fatalf("long issuer key %q", got)
	}
}

// mustPorted returns the record, skipping the test when the call reached another unit's stub and failing it on any
// other error.
func (f *appsOrg) mustPorted(record *core.Object, err error) *core.Object {
	f.t.Helper()
	appsPorted(f.t, err)
	if err != nil {
		f.t.Fatal(err)
	}
	return record
}
