package server

// Trust management, linked accounts and root administrators, after tests/trust-management.test.ts,
// tests/administration.test.ts (trusts and root administrators), tests/revoke-older-sessions.test.ts (trust
// revokeSessions), tests/web-identity.test.ts (trust evaluateWebIdentity) and tests/server.test.ts (linked accounts).
// Organizations, roles, service accounts and web-identity trusts are seeded in the store (roles.create, roles.assume,
// serviceAccounts.create and oidcProviders.create are ported by other units); steps that reach a stub of another unit
// end the test with a skip.

import (
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// trustSkipOnStub ends the test with a skip when err is another unit's NOT_IMPLEMENTED stub.
func trustSkipOnStub(t *testing.T, err error) {
	t.Helper()
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
		t.Skip("blocked by a stub of another unit: " + known.Message)
	}
}

// trustExpectCode is expectCode that skips when the step reached another unit's stub.
func trustExpectCode(t *testing.T, err error, code string) {
	t.Helper()
	trustSkipOnStub(t, err)
	expectCode(t, err, code)
}

var trustReadDocuments = core.NewObject("version", 1.0, "statements", items(allow(items("documents:read"), items("*"))))

type trustOrg struct {
	*directoryFixture
	tenantID string
	owner    core.CredentialInput
	ownerID  string
}

func newTrustOrg(t *testing.T, mutate func(options *BetterIamOptions)) *trustOrg {
	t.Helper()
	f := newDirectoryFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}}
		if mutate != nil {
			mutate(options)
		}
	})
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	owners := f.find("identities", core.NewObject("tenantId", tenantID, "owner", true))
	return &trustOrg{directoryFixture: f, tenantID: tenantID, owner: owner, ownerID: jsString(owners[0].Get("id"))}
}

func (f *trustOrg) rootID() string { return jsString(member(f.root.Get("identity"), "id")) }

func (f *trustOrg) readerRole() string {
	return f.role(f.tenantID, "Reader "+ID()[:8], allow(items("documents:read"), items("*")))
}

func (f *trustOrg) createTrust(credential core.CredentialInput, pairs ...any) (*core.Object, error) {
	out, err := f.iam.API.Trust.Create(f.ctx, credential, Input[apitypes.TrustCreateInput](body(pairs...)))
	object, _ := out.Value.(*core.Object)
	return object, err
}

func (f *trustOrg) updateTrust(credential core.CredentialInput, trustID string, pairs ...any) (*core.Object, error) {
	members := append([]any{"tenantId", f.tenantID, "trustId", trustID}, pairs...)
	out, err := f.iam.API.Trust.Update(f.ctx, credential, Input[apitypes.TrustUpdateInput](body(members...)))
	object, _ := out.Value.(*core.Object)
	return object, err
}

// ownerTrust is a reader role and a same-tenant trust (no MFA) from the owner to it.
func (f *trustOrg) ownerTrust(pairs ...any) (string, *core.Object) {
	f.t.Helper()
	roleID := f.readerRole()
	members := append([]any{"tenantId", f.tenantID, "sourceTenantId", f.tenantID, "sourceIdentityId", f.ownerID,
		"roleId", roleID, "requireMfa", false}, pairs...)
	trust, err := f.createTrust(f.rootCred, members...)
	if err != nil {
		f.t.Fatal(err)
	}
	return roleID, trust
}

// seedWebTrust seeds a web-identity trust record backed by a new service account, as trust.create stores it.
func (f *trustOrg) seedWebTrust(roleID string, pairs ...any) *core.Object {
	f.t.Helper()
	accountID := ID()
	f.seed("identities", core.NewObject("id", accountID, "tenantId", f.tenantID, "kind", "service",
		"name", "workload-"+accountID[:8], "status", "active", "emailVerified", false, "rootAdmin", false, "owner", false,
		"createdAt", f.now()))
	now := f.now()
	trust := core.NewObject(
		"id", ID(), "tenantId", f.tenantID, "kind", "web-identity", "sourceTenantId", f.tenantID,
		"sourceIdentityId", accountID, "roleId", roleID, "requireMfa", false, "revoked", false, "ceiling", All(),
		"passSourceAttributes", true, "providerId", ID(),
		"conditions", core.NewObject("StringEquals", core.NewObject("token.sub", "repo:acme/app:ref:refs/heads/main")),
		"createdAt", now, "createdBy", f.ownerID, "updatedAt", now,
	)
	for index := 0; index+1 < len(pairs); index += 2 {
		trust.Set(pairs[index].(string), pairs[index+1])
	}
	f.seed("trusts", trust)
	return trust
}

func definedKeys(object *core.Object) []string {
	var keys []string
	for _, key := range object.Keys() {
		if !isUndefined(object.Get(key)) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func TestTrustCreateReturnsPublicTrustWithIdentityDefaults(t *testing.T) {
	f := newTrustOrg(t, nil)
	roleID := f.readerRole()
	created, err := f.createTrust(f.rootCred, "tenantId", f.tenantID, "sourceTenantId", f.tenantID,
		"sourceIdentityId", f.ownerID, "roleId", roleID, "externalId", "contract-7")
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{"allowedTagKeys", "ceiling", "createdAt", "createdBy", "id", "kind", "passSourceAttributes", "requireMfa",
		"requiresExternalId", "revoked", "roleId", "sourceIdentityId", "sourceIdentityMode", "sourceTenantId", "tenantId", "updatedAt"}
	if got := strings.Join(definedKeys(created), ","); got != strings.Join(keys, ",") {
		t.Fatalf("keys = %s", got)
	}
	expected := core.NewObject(
		"id", created.Get("id"), "tenantId", f.tenantID, "kind", "identity", "sourceTenantId", f.tenantID,
		"sourceIdentityId", f.ownerID, "roleId", roleID, "requireMfa", true, "requiresExternalId", true, "revoked", false,
		"ceiling", All(), "passSourceAttributes", true, "allowedTagKeys", []any{}, "sourceIdentityMode", "forbidden",
		"createdAt", f.now(), "createdBy", f.rootID(), "updatedAt", f.now(),
	)
	if stringify(created) != stringify(expected) {
		t.Fatalf("created = %s\nwant      %s", stringify(created), stringify(expected))
	}
	stored := f.record("trusts", jsString(created.Get("id")))
	if stored.Get("externalIdHash") != Hash("contract-7") {
		t.Fatalf("externalIdHash = %v", stored.Get("externalIdHash"))
	}
	listed := answerList(f.iam.API.Trust.List(f.ctx, f.owner, Input[apitypes.TrustListInput](body("tenantId", f.tenantID))))
	if len(listed) != 1 || stringify(listed[0]) != stringify(created) {
		t.Fatalf("listed = %s", stringify(listed))
	}
	text := stringify(listed)
	if strings.Contains(text, "externalIdHash") || strings.Contains(text, jsString(stored.Get("externalIdHash"))) {
		t.Fatalf("list leaks the external ID hash: %s", text)
	}
}

func TestTrustCreateKeepsSourceAttributesOutOfCrossTenantTrusts(t *testing.T) {
	f := newTrustOrg(t, nil)
	roleID := f.readerRole()
	base := []any{"tenantId", f.tenantID, "sourceTenantId", f.rootTenantID(), "sourceIdentityId", f.rootID(), "roleId", roleID}
	closed, err := f.createTrust(f.rootCred, base...)
	if err != nil {
		t.Fatal(err)
	}
	if closed.Get("passSourceAttributes") != false || closed.Get("requiresExternalId") != false {
		t.Fatalf("closed = %s", stringify(closed))
	}
	open, err := f.createTrust(f.rootCred, append(base, "passSourceAttributes", true)...)
	if err != nil {
		t.Fatal(err)
	}
	if open.Get("passSourceAttributes") != true {
		t.Fatalf("open = %s", stringify(open))
	}
}

func TestTrustCreateValidatesTheKnobs(t *testing.T) {
	f := newTrustOrg(t, func(options *BetterIamOptions) {
		options.Sts = &StsOptions{MaxRoleSessionSeconds: float(7200)}
	})
	roleID := f.readerRole()
	base := []any{"tenantId", f.tenantID, "sourceTenantId", f.tenantID, "sourceIdentityId", f.ownerID, "roleId", roleID}
	invalid := [][]any{
		{"maxSessionSeconds", 59.0},
		{"maxSessionSeconds", 7201.0},
		{"maxSessionSeconds", 900.5},
		{"maxSessionSeconds", "900"},
		{"sourceIdentityMode", "sometimes"},
		{"passSourceAttributes", "yes"},
		{"requireMfa", "no"},
		{"description", strings.Repeat("x", 513)},
		{"description", ""},
		{"externalId", 42.0},
		{"kind", "saml"},
		{"providerId", "provider"},
		{"conditions", core.NewObject()},
	}
	for _, extra := range invalid {
		_, err := f.createTrust(f.rootCred, append(append([]any{}, base...), extra...)...)
		expectCode(t, err, "INVALID_INPUT")
	}
	_, err := f.createTrust(f.rootCred, append(append([]any{}, base...), "maxSessionSeconds", 59.0)...)
	expectError(t, err, "INVALID_INPUT", "maxSessionSeconds must be an integer from 60 to 7200")
	_, err = f.createTrust(f.rootCred, append(append([]any{}, base...), "providerId", "provider")...)
	expectError(t, err, "INVALID_INPUT", "providerId applies only to web-identity trusts")
	// Web-identity trusts are gated by sts.webIdentity (off in this fixture); the gate is checked first.
	_, err = f.createTrust(f.rootCred, append(append([]any{}, base...), "kind", "web-identity")...)
	expectError(t, err, "FEATURE_DISABLED", "Web identity federation is not enabled")
	expectStatus(t, err, 403)
	configured, err := f.createTrust(f.rootCred, append(append([]any{}, base...), "kind", "identity", "maxSessionSeconds", 7200.0,
		"sourceIdentityMode", "required", "passSourceAttributes", false,
		"description", "Break-glass access for the on-call engineer")...)
	if err != nil {
		t.Fatal(err)
	}
	if configured.Get("maxSessionSeconds") != 7200.0 || configured.Get("sourceIdentityMode") != "required" ||
		configured.Get("passSourceAttributes") != false || configured.Get("description") != "Break-glass access for the on-call engineer" {
		t.Fatalf("configured = %s", stringify(configured))
	}
	// Identity trusts stay platform-controlled.
	_, err = f.createTrust(f.ownerSignIn(f.tenantID), base...)
	expectCode(t, err, "ACCESS_DENIED")
	// Protected roles cannot be assumed; a source identity of another tenant than named is NOT_FOUND.
	protected := f.readerRole()
	f.patch("roles", protected, core.NewObject("protected", true))
	_, err = f.createTrust(f.rootCred, "tenantId", f.tenantID, "sourceTenantId", f.tenantID, "sourceIdentityId", f.ownerID, "roleId", protected)
	expectError(t, err, "PROTECTED_RESOURCE", "Cannot assume protected owner roles")
	_, err = f.createTrust(f.rootCred, "tenantId", f.tenantID, "sourceTenantId", f.rootTenantID(), "sourceIdentityId", f.ownerID, "roleId", roleID)
	expectCode(t, err, "NOT_FOUND")
}

func TestTrustCreateValidatesTagKeys(t *testing.T) {
	f := newTrustOrg(t, nil)
	roleID := f.readerRole()
	base := []any{"tenantId", f.tenantID, "sourceTenantId", f.tenantID, "sourceIdentityId", f.ownerID, "roleId", roleID}
	for _, keys := range []any{"team", items("team", "Team"), items("*", "team"), items("bad-key")} {
		_, err := f.createTrust(f.rootCred, append(append([]any{}, base...), "allowedTagKeys", keys)...)
		trustExpectCode(t, err, "INVALID_INPUT")
	}
	tagged, err := f.createTrust(f.rootCred, append(append([]any{}, base...), "allowedTagKeys", items("team", "env"))...)
	trustSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if stringify(tagged.Get("allowedTagKeys")) != `["team","env"]` {
		t.Fatalf("tagged = %s", stringify(tagged))
	}
}

func TestTrustUpdateBumpsTheWatermarkOnlyWhenTheTrustTightens(t *testing.T) {
	f := newTrustOrg(t, nil)
	_, trust := f.ownerTrust()
	trustID := jsString(trust.Get("id"))
	f.advance(1000)
	// Loosening or relabelling keeps live sessions.
	for _, fields := range [][]any{
		{"description", "Support access"},
		{"passSourceAttributes", false},
		{"requireMfa", false, "description", "Support access for tickets"},
		{"ceiling", trustReadDocuments},
	} {
		updated, err := f.updateTrust(f.rootCred, trustID, fields...)
		if err != nil {
			t.Fatalf("%v: %v", fields, err)
		}
		if !isUndefined(updated.Get("sessionsRevokedBefore")) || updated.Get("updatedAt") != f.now() {
			t.Fatalf("updated = %s", stringify(updated))
		}
	}
	// A lower session cap ends the sessions issued under the higher one.
	capped, err := f.updateTrust(f.rootCred, trustID, "maxSessionSeconds", 1800.0)
	if err != nil {
		t.Fatal(err)
	}
	if capped.Get("maxSessionSeconds") != 1800.0 || capped.Get("sessionsRevokedBefore") != f.now()+1 {
		t.Fatalf("capped = %s", stringify(capped))
	}
	f.advance(1000)
	// Raising it again (or clearing it back to the 3600 s default) does not.
	raised, err := f.updateTrust(f.rootCred, trustID, "maxSessionSeconds", nil)
	if err != nil {
		t.Fatal(err)
	}
	if raised.Has("maxSessionSeconds") || raised.Get("sessionsRevokedBefore") != capped.Get("sessionsRevokedBefore") {
		t.Fatalf("raised = %s", stringify(raised))
	}
	// The source identity mode bumps it.
	moded, err := f.updateTrust(f.rootCred, trustID, "sourceIdentityMode", "optional")
	if err != nil {
		t.Fatal(err)
	}
	if moded.Get("sessionsRevokedBefore") != f.now()+1 {
		t.Fatalf("moded = %s", stringify(moded))
	}
	f.advance(1000)
	cleared, err := f.updateTrust(f.rootCred, trustID, "description", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Has("description") || cleared.Get("sessionsRevokedBefore") != moded.Get("sessionsRevokedBefore") || cleared.Has("externalIdHash") {
		t.Fatalf("cleared = %s", stringify(cleared))
	}
}

func TestTrustUpdateComparesTagKeysAsSets(t *testing.T) {
	f := newTrustOrg(t, nil)
	_, trust := f.ownerTrust()
	trustID := jsString(trust.Get("id"))
	// Seeded as trust.create stores allowedTagKeys: ['team', 'env'].
	f.patch("trusts", trustID, core.NewObject("allowedTagKeys", items("team", "env")))
	f.advance(1000)
	// Clearing the tag keys (null) narrows what the trust admits.
	cleared, err := f.updateTrust(f.rootCred, trustID, "allowedTagKeys", nil, "description", "No tags")
	if err != nil {
		t.Fatal(err)
	}
	if stringify(cleared.Get("allowedTagKeys")) != "[]" || cleared.Get("sessionsRevokedBefore") != f.now()+1 {
		t.Fatalf("cleared = %s", stringify(cleared))
	}
	// A malformed stored list reads as no keys.
	f.patch("trusts", trustID, core.NewObject("allowedTagKeys", "*"))
	f.advance(1000)
	relabelled, err := f.updateTrust(f.rootCred, trustID, "allowedTagKeys", nil)
	if err != nil {
		t.Fatal(err)
	}
	if relabelled.Get("sessionsRevokedBefore") != cleared.Get("sessionsRevokedBefore") {
		t.Fatalf("relabelled = %s", stringify(relabelled))
	}
	f.patch("trusts", trustID, core.NewObject("allowedTagKeys", items("env", "team")))
	_, err = f.updateTrust(f.rootCred, trustID, "allowedTagKeys", items("team", "env"))
	trustExpectCode(t, err, "INVALID_INPUT")
}

func TestTrustUpdateRefusesNonRootNoOpsForeignFieldsRevokedAndStale(t *testing.T) {
	f := newTrustOrg(t, nil)
	_, trust := f.ownerTrust("description", "Support")
	trustID := jsString(trust.Get("id"))
	// The owner holds iam:trust:update but identity trusts are platform-controlled; the refusal is audited.
	_, err := f.updateTrust(f.ownerSignIn(f.tenantID), trustID, "description", "Mine")
	expectError(t, err, "ACCESS_DENIED", "Only a root administrator can manage identity trusts")
	denials := 0
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if event.Get("action") == "iam:trust:update" && event.Get("outcome") == "deny" {
			denials++
		}
	}
	if denials != 1 {
		t.Fatalf("denials = %d", denials)
	}
	for _, fields := range []struct {
		pairs   []any
		message string
	}{
		{nil, "The update changes nothing"},
		{[]any{"description", "Support"}, "The update changes nothing"},
		{[]any{"requireMfa", false}, "The update changes nothing"},
		{[]any{"maxSessionSeconds", 3601.0}, "maxSessionSeconds must be an integer from 60 to 3600"},
		{[]any{"maxSessionSeconds", 30.0}, "maxSessionSeconds must be an integer from 60 to 3600"},
		{[]any{"sourceIdentityMode", "maybe"}, "sourceIdentityMode must be 'forbidden', 'optional' or 'required'"},
		{[]any{"conditions", core.NewObject("StringEquals", core.NewObject("token.sub", "repo:acme/app"))}, "conditions applies only to web-identity trusts"},
		{[]any{"tagClaims", core.NewObject("team", "token.team")}, "tagClaims applies only to web-identity trusts"},
		{[]any{"sourceIdentityClaim", "token.actor"}, "sourceIdentityClaim applies only to web-identity trusts"},
		{[]any{"requireMfa", "yes"}, "requireMfa must be a boolean"},
	} {
		_, err := f.updateTrust(f.rootCred, trustID, fields.pairs...)
		expectError(t, err, "INVALID_INPUT", fields.message)
	}
	_, err = f.updateTrust(f.rootCred, ID(), "description", "x")
	expectCode(t, err, "NOT_FOUND")
	f.patch("trusts", trustID, core.NewObject("revoked", true))
	_, err = f.updateTrust(f.rootCred, trustID, "description", "Again")
	expectError(t, err, "CONFLICT", "The trust is revoked")
	expectStatus(t, err, 409)
	f.advance(6 * 60_000)
	_, err = f.updateTrust(f.rootCred, trustID, "description", "Late")
	expectCode(t, err, "RECENT_AUTH_REQUIRED")
}

func TestTrustUpdateManagesWebIdentityTrustsThroughTheCreatorAuthority(t *testing.T) {
	f := newTrustOrg(t, func(options *BetterIamOptions) {
		options.Sts = &StsOptions{WebIdentity: &StsWebIdentityOptions{Enabled: flag(true)}}
	})
	roleID := f.readerRole()
	mine := f.seedWebTrust(roleID, "authorityId", f.authorities[f.tenantID])
	owner := f.ownerSignIn(f.tenantID)
	mineID := jsString(mine.Get("id"))
	for _, fields := range []struct {
		pairs   []any
		message string
	}{
		{[]any{"requireMfa", true}, "requireMfa applies only to identity trusts"},
		{[]any{"allowedTagKeys", items("team")}, "allowedTagKeys applies only to identity trusts"},
		{[]any{"sourceIdentityMode", "optional"}, "sourceIdentityMode applies only to identity trusts"},
		{[]any{"tagClaims", core.NewObject("bad-key", "token.team")}, "Tag keys must start with a letter and use at most 64 letters, digits or underscores"},
		{[]any{"tagClaims", "team"}, "tagClaims must map session tag keys to token.<claim> names"},
	} {
		_, err := f.updateTrust(owner, mineID, fields.pairs...)
		expectError(t, err, "INVALID_INPUT", fields.message)
	}
	// The creator's authority edits the trust (no root needed); relabelling keeps sessions.
	described, err := f.updateTrust(owner, mineID, "description", "CI deploys")
	if err != nil {
		t.Fatal(err)
	}
	if described.Get("kind") != "web-identity" || described.Get("description") != "CI deploys" || described.Has("sessionsRevokedBefore") {
		t.Fatalf("described = %s", stringify(described))
	}
	// Clearing a claim mapping revokes older sessions.
	f.patch("trusts", mineID, core.NewObject("tagClaims", core.NewObject("repo", "token.repository")))
	f.advance(1000)
	unmapped, err := f.updateTrust(owner, mineID, "tagClaims", nil)
	if err != nil {
		t.Fatal(err)
	}
	if unmapped.Has("tagClaims") || unmapped.Get("sessionsRevokedBefore") != f.now()+1 {
		t.Fatalf("unmapped = %s", stringify(unmapped))
	}
	// A trust issued under another administrator's authority is out of the owner's reach.
	rootAuthority := ID()
	f.seed("grantAuthorities", core.NewObject("id", rootAuthority, "tenantId", f.tenantID, "identityId", f.rootID(),
		"rootIssued", true, "ceiling", All(), "revoked", false))
	foreign := f.seedWebTrust(roleID, "authorityId", rootAuthority)
	_, err = f.updateTrust(owner, jsString(foreign.Get("id")), "description", "Mine now")
	expectCode(t, err, "ACCESS_DENIED")
	_, err = f.iam.API.Trust.Revoke(f.ctx, owner, Input[apitypes.TrustRevokeInput](body("tenantId", f.tenantID, "trustId", foreign.Get("id"))))
	expectCode(t, err, "ACCESS_DENIED")
	// A web-identity trust without a valid service account control is refused before any field is read.
	f.patch("trusts", mineID, core.NewObject("sourceIdentityId", "missing-account"))
	member, memberCredential := f.person(f.tenantID, "maya")
	_ = member
	_, err = f.updateTrust(memberCredential, mineID, "description", "Hers")
	expectCode(t, err, "ACCESS_DENIED")
	// Claim names are checked by web-identity.ts.
	f.patch("trusts", mineID, core.NewObject("sourceIdentityId", mine.Get("sourceIdentityId")))
	_, err = f.updateTrust(owner, mineID, "sourceIdentityClaim", "actor")
	trustExpectCode(t, err, "INVALID_INPUT")
	_, err = f.updateTrust(owner, mineID, "conditions", core.NewObject("StringLike", core.NewObject("token.sub", "*")))
	trustExpectCode(t, err, "WEAK_TRUST_CONDITIONS")
	revoked, err := f.iam.API.Trust.Revoke(f.ctx, owner, Input[apitypes.TrustRevokeInput](body("tenantId", f.tenantID, "trustId", mineID)))
	trustSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if record := revoked.Value.(*core.Object); record.Get("kind") != "web-identity" || record.Get("revoked") != true {
		t.Fatalf("revoked = %s", stringify(record))
	}
}

func TestTrustUpdateIsUnavailableForWebIdentityTrustsWhileTheFeatureIsOff(t *testing.T) {
	f := newTrustOrg(t, nil)
	roleID := f.readerRole()
	web := f.seedWebTrust(roleID, "authorityId", f.authorities[f.tenantID])
	_, err := f.updateTrust(f.rootCred, jsString(web.Get("id")), "description", "x")
	expectError(t, err, "FEATURE_DISABLED", "Web identity federation is not enabled")
	expectStatus(t, err, 403)
}

func TestTrustUpdateBoundsMaxSessionSecondsByTheDeploymentCeiling(t *testing.T) {
	f := newTrustOrg(t, func(options *BetterIamOptions) {
		options.Sts = &StsOptions{MaxRoleSessionSeconds: float(7200)}
	})
	_, trust := f.ownerTrust()
	trustID := jsString(trust.Get("id"))
	updated, err := f.updateTrust(f.rootCred, trustID, "maxSessionSeconds", 7200.0)
	if err != nil {
		t.Fatal(err)
	}
	// Raising the cap above the legacy 3600 s default is a loosening: no watermark.
	if updated.Get("maxSessionSeconds") != 7200.0 || updated.Has("sessionsRevokedBefore") {
		t.Fatalf("updated = %s", stringify(updated))
	}
	_, err = f.updateTrust(f.rootCred, trustID, "maxSessionSeconds", 7201.0)
	expectError(t, err, "INVALID_INPUT", "maxSessionSeconds must be an integer from 60 to 7200")
}

func TestTrustListAndRevoke(t *testing.T) {
	f := newTrustOrg(t, nil)
	beta, betaOwner := f.organization("Beta", "owner@beta.test")
	roleID := f.role(beta, "Auditor", allow(items("documents:read"), items("*")))
	trust, err := f.createTrust(f.rootCred, "tenantId", beta, "sourceTenantId", f.tenantID, "sourceIdentityId", f.ownerID,
		"roleId", roleID, "externalId", "contract-7")
	if err != nil {
		t.Fatal(err)
	}
	list := func(credential core.CredentialInput, pairs ...any) ([]*core.Object, error) {
		out, err := f.iam.API.Trust.List(f.ctx, credential, Input[apitypes.TrustListInput](body(append([]any{"tenantId", beta}, pairs...)...)))
		if err != nil {
			return nil, err
		}
		listed, _ := out.Value.([]any)
		objects := make([]*core.Object, len(listed))
		for index, item := range listed {
			objects[index] = item.(*core.Object)
		}
		return objects, nil
	}
	listed, err := list(betaOwner)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Get("id") != trust.Get("id") || listed[0].Get("roleId") != roleID ||
		listed[0].Get("sourceTenantId") != f.tenantID || listed[0].Get("requiresExternalId") != true || listed[0].Has("externalIdHash") {
		t.Fatalf("listed = %s", stringify(listed))
	}
	_, err = list(f.owner)
	expectCode(t, err, "ACCESS_DENIED")
	// Revoked trusts are listed only on request.
	f.patch("trusts", jsString(trust.Get("id")), core.NewObject("revoked", true))
	if listed, err = list(betaOwner); err != nil || len(listed) != 0 {
		t.Fatalf("listed = %s, %v", stringify(listed), err)
	}
	if listed, err = list(betaOwner, "includeRevoked", true); err != nil || len(listed) != 1 || listed[0].Get("revoked") != true {
		t.Fatalf("listed = %s, %v", stringify(listed), err)
	}
	// Identity trusts are revoked by root only; the trust's live role sessions are deleted.
	f.patch("trusts", jsString(trust.Get("id")), core.NewObject("revoked", false))
	_, err = f.iam.API.Trust.Revoke(f.ctx, betaOwner, Input[apitypes.TrustRevokeInput](body("tenantId", beta, "trustId", trust.Get("id"))))
	expectError(t, err, "ACCESS_DENIED", "Only a root administrator can manage identity trusts")
	revoked, err := f.iam.API.Trust.Revoke(f.ctx, f.rootCred, Input[apitypes.TrustRevokeInput](body("tenantId", beta, "trustId", trust.Get("id"))))
	trustSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if record := revoked.Value.(*core.Object); record.Get("revoked") != true || record.Get("updatedAt") != f.now() {
		t.Fatalf("revoked = %s", stringify(record))
	}
}

func TestTrustRevokeSessionsPreReadsTheTrust(t *testing.T) {
	f := newTrustOrg(t, nil)
	roleID, trust := f.ownerTrust()
	revoke := func(credential core.CredentialInput, pairs ...any) (Out[apitypes.TrustRevokeSessionsOutput], error) {
		return f.iam.API.Trust.RevokeSessions(f.ctx, credential, Input[apitypes.TrustRevokeSessionsInput](body(append([]any{"tenantId", f.tenantID}, pairs...)...)))
	}
	// Anonymous callers cannot probe trust ids.
	_, err := revoke(core.CredentialInput{Token: "nope"}, "trustId", ID())
	expectCode(t, err, "UNAUTHENTICATED")
	_, err = revoke(f.owner, "trustId", ID())
	expectError(t, err, "NOT_FOUND", "Resource not found")
	_, err = revoke(f.owner, "trustId", 42.0)
	expectError(t, err, "INVALID_INPUT", "Invalid trustId")
	// Delegated like roles.revokeSessions: a member without iam:roles:revoke-sessions is refused.
	_, memberCredential := f.person(f.tenantID, "maya")
	_, err = revoke(memberCredential, "trustId", trust.Get("id"))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = revoke(f.owner, "trustId", trust.Get("id"), "before", f.now()+2)
	expectError(t, err, "INVALID_INPUT", "before must be a time no later than now")
	result, err := revoke(f.owner, "trustId", trust.Get("id"))
	trustSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	answer := result.Value.(*core.Object)
	if answer.Get("trustId") != trust.Get("id") || answer.Get("sessionsRevokedBefore") != f.now()+1 || answer.Get("revoked") != 0.0 {
		t.Fatalf("answer = %s", stringify(answer))
	}
	if f.record("trusts", jsString(trust.Get("id"))).Get("sessionsRevokedBefore") != f.now()+1 {
		t.Fatal("watermark not stored")
	}
	found := false
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if event.Get("action") == "role:sessions-revoked" && event.Get("resourceId") == trust.Get("id") {
			found = stringify(event.Get("metadata")) == stringify(core.NewObject("sessionsRevokedBefore", f.now()+1, "revoked", 0.0))
		}
	}
	if !found {
		t.Fatalf("no role:sessions-revoked event for role %s", roleID)
	}
}

func TestTrustEvaluateWebIdentity(t *testing.T) {
	off := newTrustOrg(t, nil)
	_, err := off.iam.API.Trust.EvaluateWebIdentity(off.ctx, off.owner, Input[apitypes.TrustEvaluateWebIdentityInput](body(
		"tenantId", off.tenantID, "trustId", ID(), "webIdentityToken", "a.b.c")))
	expectError(t, err, "FEATURE_DISABLED", "Web identity federation is not enabled")

	f := newTrustOrg(t, func(options *BetterIamOptions) {
		options.Sts = &StsOptions{WebIdentity: &StsWebIdentityOptions{Enabled: flag(true)}}
	})
	roleID := f.readerRole()
	web := f.seedWebTrust(roleID, "authorityId", f.authorities[f.tenantID])
	providerID := jsString(web.Get("providerId"))
	f.seed("oidcProviders", core.NewObject("id", providerID, "tenantId", f.tenantID,
		"uniqueKey", "issuer:https://token.example.test/"+providerID, "name", "CI", "issuer", "https://token.example.test/"+providerID,
		"audiences", items("sts.example.test"), "algorithms", items("RS256"), "maxTokenLifetimeSeconds", 3600.0,
		"clockToleranceSeconds", 30.0, "replayProtection", "single-use", "enabled", true,
		"authorityId", f.authorities[f.tenantID], "createdAt", f.now(), "createdBy", f.ownerID, "updatedAt", f.now()))
	evaluate := func(credential core.CredentialInput, pairs ...any) (Out[apitypes.TrustEvaluateWebIdentityOutput], error) {
		return f.iam.API.Trust.EvaluateWebIdentity(f.ctx, credential, Input[apitypes.TrustEvaluateWebIdentityInput](body(append([]any{"tenantId", f.tenantID}, pairs...)...)))
	}
	_, err = evaluate(f.owner, "trustId", web.Get("id"), "webIdentityToken", strings.Repeat("a", 8193))
	expectError(t, err, "INVALID_INPUT", "webIdentityToken must be a compact JWT of at most 8192 characters")
	_, err = evaluate(f.owner, "trustId", web.Get("id"), "webIdentityToken", 42.0)
	expectCode(t, err, "INVALID_INPUT")
	// A value that is not a compact JWS never reaches the verifier.
	malformed, err := evaluate(f.owner, "trustId", web.Get("id"), "webIdentityToken", "not a token")
	if err != nil {
		t.Fatal(err)
	}
	if stringify(malformed.Value) != `{"verified":false,"reason":"malformed"}` {
		t.Fatalf("malformed = %s", stringify(malformed.Value))
	}
	// Authorized on the trust before it is read.
	_, memberCredential := f.person(f.tenantID, "maya")
	_, err = evaluate(memberCredential, "trustId", web.Get("id"), "webIdentityToken", "not a token")
	expectCode(t, err, "ACCESS_DENIED")
	_, err = evaluate(f.owner, "trustId", ID(), "webIdentityToken", "not a token")
	expectCode(t, err, "NOT_FOUND")
	_, identityTrust := f.ownerTrust()
	_, err = evaluate(f.owner, "trustId", identityTrust.Get("id"), "webIdentityToken", "not a token")
	expectError(t, err, "INVALID_INPUT", "Only web-identity trusts evaluate web identity tokens")
	_, err = evaluate(f.owner, "trustId", web.Get("id"), "webIdentityToken", "aaa.bbb.ccc")
	trustSkipOnStub(t, err)
}

func TestTrustCreateWebIdentityTrust(t *testing.T) {
	f := newTrustOrg(t, func(options *BetterIamOptions) {
		options.Sts = &StsOptions{WebIdentity: &StsWebIdentityOptions{Enabled: flag(true)}}
	})
	roleID := f.readerRole()
	base := []any{"tenantId", f.tenantID, "kind", "web-identity", "providerId", ID(), "serviceAccountId", ID(), "roleId", roleID}
	for _, field := range []string{"sourceTenantId", "sourceIdentityId", "requireMfa", "externalId", "allowedTagKeys", "sourceIdentityMode"} {
		_, err := f.createTrust(f.owner, append(append([]any{}, base...), field, "x")...)
		expectError(t, err, "INVALID_INPUT", field+" applies only to identity trusts")
	}
	_, err := f.createTrust(f.owner, "tenantId", f.tenantID, "kind", "web-identity", "serviceAccountId", ID(), "roleId", roleID)
	expectError(t, err, "INVALID_INPUT", "Invalid providerId")
	_, err = f.createTrust(f.owner, "tenantId", f.tenantID, "kind", "web-identity", "providerId", ID(), "roleId", roleID)
	expectError(t, err, "INVALID_INPUT", "Invalid serviceAccountId")
	_, err = f.createTrust(f.owner, append(append([]any{}, base...),
		"conditions", core.NewObject("StringEquals", core.NewObject("token.sub", "repo:acme/app:ref:refs/heads/main")))...)
	trustSkipOnStub(t, err)
	expectCode(t, err, "NOT_FOUND")
}

func TestRootAdministrators(t *testing.T) {
	f := newTrustOrg(t, nil)
	rootTenant := f.rootTenantID()
	second, _ := f.person(rootTenant, "second")
	set := func(credential core.CredentialInput, pairs ...any) (Out[apitypes.RootSetAdministratorOutput], error) {
		return f.iam.API.Root.SetAdministrator(f.ctx, credential, Input[apitypes.RootSetAdministratorInput](body(pairs...)))
	}
	listAdmins := func(credential core.CredentialInput, tenantID string) (Out[apitypes.RootListAdministratorsOutput], error) {
		return f.iam.API.Root.ListAdministrators(f.ctx, credential, Input[apitypes.RootListAdministratorsInput](body("tenantId", tenantID)))
	}
	granted := answerObject(set(f.rootCred, "tenantId", rootTenant, "identityId", second.Get("id"), "enabled", true))
	if granted.Get("rootAdmin") != true || granted.Has("passwordHash") {
		t.Fatalf("granted = %s", stringify(granted))
	}
	var emails []string
	for _, item := range answerList(listAdmins(f.rootCred, rootTenant)) {
		emails = append(emails, jsString(item.Get("email")))
	}
	sort.Strings(emails)
	if strings.Join(emails, ",") != "root@example.test,second@acme.test" {
		t.Fatalf("administrators = %v", emails)
	}
	_, err := listAdmins(f.owner, f.tenantID)
	expectCode(t, err, "ACCESS_DENIED")
	_, err = listAdmins(f.rootCred, f.tenantID)
	expectError(t, err, "INVALID_INPUT", "Root administrators belong to the root tenant")
	_, err = set(f.rootCred, "tenantId", f.tenantID, "identityId", f.ownerID, "enabled", true)
	expectError(t, err, "INVALID_INPUT", "Root administrator must belong to root")
	_, err = set(f.rootCred, "tenantId", rootTenant, "identityId", second.Get("id"), "enabled", "yes")
	expectError(t, err, "INVALID_INPUT", "Root administrator must belong to root")
	service := ID()
	f.seed("identities", core.NewObject("id", service, "tenantId", rootTenant, "kind", "service", "name", "bot",
		"status", "active", "emailVerified", false, "rootAdmin", false, "owner", false, "createdAt", f.now()))
	_, err = set(f.rootCred, "tenantId", rootTenant, "identityId", service, "enabled", true)
	expectError(t, err, "INVALID_INPUT", "Root administrators must be users")
	_, err = set(f.rootCred, "tenantId", rootTenant, "identityId", ID(), "enabled", true)
	expectCode(t, err, "NOT_FOUND")
	revoked := answerObject(set(f.rootCred, "tenantId", rootTenant, "identityId", second.Get("id"), "enabled", false))
	if revoked.Get("rootAdmin") != false {
		t.Fatalf("revoked = %s", stringify(revoked))
	}
	f.advance(6 * 60_000)
	_, err = set(f.rootCred, "tenantId", rootTenant, "identityId", second.Get("id"), "enabled", true)
	expectCode(t, err, "RECENT_AUTH_REQUIRED")
}

func TestLinksListAndRevoke(t *testing.T) {
	f := newTrustOrg(t, nil)
	beta, betaOwner := f.organization("Beta", "owner@beta.test", "slug", "beta")
	betaID := jsString(f.find("identities", core.NewObject("tenantId", beta, "owner", true))[0].Get("id"))
	linkID := ID()
	f.seed("identityLinks", core.NewObject("id", linkID, "tenantId", f.tenantID, "uniqueKey", f.ownerID+":"+betaID,
		"leftId", f.ownerID, "rightId", betaID, "revoked", false, "createdAt", f.now()))
	linked := answerList(f.iam.API.Links.List(f.ctx, f.owner, Input[apitypes.LinksListInput](nil)))
	expected := core.NewObject("id", linkID, "identityId", betaID, "email", "owner@beta.test", "name", "Owner", "status", "active",
		"tenantId", beta, "tenantName", "Beta", "tenantSlug", "beta", "tenantStatus", "active")
	if len(linked) != 1 || stringify(linked[0]) != stringify(expected) {
		t.Fatalf("linked = %s", stringify(linked))
	}
	fromBeta := answerList(f.iam.API.Links.List(f.ctx, betaOwner, Input[apitypes.LinksListInput](nil)))
	if len(fromBeta) != 1 || fromBeta[0].Get("identityId") != f.ownerID || strings.Contains(stringify(fromBeta), "tenantSlug") {
		t.Fatalf("fromBeta = %s", stringify(fromBeta))
	}
	revoke := func(credential core.CredentialInput, id any) (Out[apitypes.LinksRevokeOutput], error) {
		return f.iam.API.Links.Revoke(f.ctx, credential, Input[apitypes.LinksRevokeInput](body("linkId", id)))
	}
	_, outsider := f.person(f.tenantID, "maya")
	_, err := revoke(outsider, linkID)
	expectError(t, err, "NOT_FOUND", "Link not found")
	_, err = revoke(f.owner, ID())
	expectError(t, err, "NOT_FOUND", "Link not found")
	if result := answerObject(revoke(f.owner, linkID)); stringify(result) != `{"revoked":true}` {
		t.Fatalf("revoke = %s", stringify(result))
	}
	if f.record("identityLinks", linkID).Get("revoked") != true {
		t.Fatal("link not revoked")
	}
	unlinked := false
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if event.Get("action") == "identity:unlink" && event.Get("resourceId") == linkID && event.Get("actorId") == f.ownerID {
			unlinked = true
		}
	}
	if !unlinked {
		t.Fatal("no identity:unlink event")
	}
	if remaining := answerList(f.iam.API.Links.List(f.ctx, f.owner, Input[apitypes.LinksListInput](nil))); len(remaining) != 0 {
		t.Fatalf("remaining = %s", stringify(remaining))
	}
	f.advance(6 * 60_000)
	_, err = revoke(f.ownerSignIn(f.tenantID), linkID)
	if err != nil {
		t.Fatalf("fresh session: %v", err)
	}
	_, err = revoke(f.owner, linkID)
	expectCode(t, err, "RECENT_AUTH_REQUIRED")
}

func TestLinksCreateAndSwitchUseTheFlows(t *testing.T) {
	f := newTrustOrg(t, nil)
	_, betaOwner := f.organization("Beta", "owner@beta.test")
	_, err := f.iam.API.Links.Create(f.ctx, f.owner, Input[apitypes.LinksCreateInput](body("targetCredential", core.NewObject("token", betaOwner.Token))))
	trustSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
}
