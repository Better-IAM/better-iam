package auth

// Ports of tests/session-limits.test.ts and the authentication part of tests/identity-expiry.test.ts, plus the
// tenant session cap (authPolicy.maxSessions) and impersonation lifetime rules of the service.

import (
	"context"
	"math"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func TestGetSessionReportsTheLimitsInForce(t *testing.T) {
	lifetime, idle := int64(10*60_000), int64(4*60_000)
	f := newInsightFixture(t, 0)
	options := f.auth.Options()
	options.SessionLifetimeMs, options.SessionIdleTimeoutMs = &lifetime, &idle
	f.auth = must[*Service](t)(New(options))
	signed := must[*core.Object](t)(f.signInAs(ownerPassword, nil))
	value := str(signed, "token")
	expiresAt := numOr(child(signed, "session"), "expiresAt", 0)
	limits := func() *core.Object {
		return child(must[*core.Object](t)(f.auth.GetSession(f.ctx, token(value))), "limits")
	}
	now := float64(f.now())
	if got := core.MustStringify(limits()); got != core.MustStringify(core.NewObject("lifetimeMs", 600000.0, "idleTimeoutMs", 240000.0, "idleExpiresAt", now+240000, "now", now)) {
		t.Errorf("limits %s", got)
	}
	if expiresAt != now+600000 {
		t.Error("expiresAt")
	}
	f.update("tenants", "root", func(tenant *core.Object) { tenant.Set("authPolicy", core.NewObject("sessionIdleTimeoutMs", 120000.0)) })
	f.advance(60_000)
	shortened := must[*core.Object](t)(f.auth.GetSession(f.ctx, token(value)))
	if numOr(child(shortened, "limits"), "idleTimeoutMs", 0) != 120000 || numOr(child(shortened, "limits"), "idleExpiresAt", 0) != float64(f.now()+120000) ||
		numOr(child(shortened, "session"), "lastSeenAt", 0) != float64(f.now()) {
		t.Errorf("shortened %s", core.MustStringify(shortened))
	}
	for expiresAt-float64(f.now()) > 120000 {
		f.advance(90_000)
		if got := numOr(limits(), "idleExpiresAt", 0); got != math.Min(float64(f.now()+120000), expiresAt) {
			t.Fatalf("idleExpiresAt %v", got)
		}
	}
	ending := limits()
	if numOr(ending, "idleExpiresAt", 0) != expiresAt || numOr(ending, "idleExpiresAt", 0) >= float64(f.now()+120000) {
		t.Error("idle expiry passes the absolute end")
	}
	f.advance(120000 + 1)
	_, err := f.auth.GetSession(f.ctx, token(value))
	expectCode(t, err, "UNAUTHENTICATED")
}

func TestExpiredIdentitiesAreRefusedEverywhere(t *testing.T) {
	f := orgFixture(t)
	alice := f.member("alice")
	f.update("identities", str(alice, "id"), func(o *core.Object) { o.Set("expiresAt", float64(f.now()+2*day)) })
	login := session(t, f.memberSignIn("alice"))
	must[*Principal](t)(f.auth.Authenticate(f.ctx, token(login)))
	f.advance(2*day + 1)
	_, err := f.auth.Authenticate(f.ctx, token(login))
	expectCode(t, err, "UNAUTHENTICATED")
	_, err = f.signInFrom(f.ctx, "alice")
	expectCode(t, err, "INVALID_CREDENTIALS")
	_, err = f.auth.SignIn(f.ctx, core.NewObject("tenantId", "org", "email", "alice@acme.test", "password", "wrong password here"))
	expectCode(t, err, "INVALID_CREDENTIALS")
	f.auth.SettleBookkeeping()
	if ledger := f.get("authSignIns", str(alice, "id")); numOr(ledger, "failedAttempts", 0) != 0 {
		t.Error("an expired identity recorded failures")
	}
	f.update("identities", str(alice, "id"), func(o *core.Object) { o.Delete("expiresAt") })
	session(t, f.memberSignIn("alice"))
}

func TestTenantSessionCapEndsTheOldestSessions(t *testing.T) {
	f := orgFixture(t)
	f.member("alice")
	f.setOrgPolicy(core.NewObject("maxSessions", 2.0))
	var tokens []string
	for index := 0; index < 3; index++ {
		tokens = append(tokens, session(t, f.memberSignIn("alice")))
		f.advance(1_000)
	}
	_, err := f.auth.Authenticate(f.ctx, token(tokens[0]))
	expectCode(t, err, "UNAUTHENTICATED")
	for _, value := range tokens[1:] {
		must[*Principal](t)(f.auth.Authenticate(f.ctx, token(value)))
	}
}

func TestImpersonationSessionsFollowTheirSource(t *testing.T) {
	f := orgFixture(t)
	alice := f.member("alice")
	f.member("owner")
	actor := must[*Principal](t)(f.auth.Authenticate(f.ctx, token(session(t, f.memberSignIn("owner")))))
	issue := func() (*core.Object, error) {
		return core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			return f.auth.IssueImpersonationSession(ctx, tx, actor, alice, 60*60_000)
		})
	}
	_, err := issue()
	expectCode(t, err, "FEATURE_DISABLED")
	f.setOrgPolicy(core.NewObject("allowImpersonation", true))
	viewAs := must[*core.Object](t)(issue())
	principal := must[*Principal](t)(f.auth.Authenticate(f.ctx, token(str(viewAs, "token"))))
	if str(principal.Identity, "id") != str(alice, "id") || numOr(principal.Session, "expiresAt", 0) > numOr(actor.Session, "expiresAt", 0) {
		t.Fatalf("view-as %s", core.MustStringify(principal.Session))
	}
	expectCode(t, f.auth.RequireRecent(principal), "IMPERSONATION_RESTRICTED")
	_, err = f.auth.Reauthenticate(f.ctx, token(str(viewAs, "token")), core.NewObject("password", "a strong alice password"))
	expectCode(t, err, "IMPERSONATION_RESTRICTED")
	nested := &Principal{Identity: principal.Identity, Session: principal.Session}
	_, err = core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.auth.IssueImpersonationSession(ctx, tx, nested, alice, 60_000)
	})
	expectCode(t, err, "IMPERSONATION_RESTRICTED")
	// Ending the administrator's session ends the view-as with it.
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		return f.auth.EndSession(ctx, tx, str(actor.Session, "id"))
	})
	_, err = f.auth.Authenticate(f.ctx, token(str(viewAs, "token")))
	expectCode(t, err, "UNAUTHENTICATED")
	// A view-as also ends once the tenant stops allowing impersonation.
	actor = must[*Principal](t)(f.auth.Authenticate(f.ctx, token(session(t, f.memberSignIn("owner")))))
	viewAs = must[*core.Object](t)(issue())
	f.setOrgPolicy(core.NewObject())
	_, err = f.auth.Authenticate(f.ctx, token(str(viewAs, "token")))
	if iam := expectCode(t, err, "UNAUTHENTICATED"); iam.Message != "Impersonation has ended" {
		t.Errorf("message %s", iam.Message)
	}
	// The removal inside the refusing transaction rolls back with it, as in the TypeScript service: the row stays,
	// and every later use is refused the same way.
	_, err = f.auth.Authenticate(f.ctx, token(str(viewAs, "token")))
	expectCode(t, err, "UNAUTHENTICATED")
}
