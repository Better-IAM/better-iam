package auth

// Port of tests/auth-session-hygiene.test.ts (the authentication service part: role sessions, API keys and the
// session-kind helpers are created and tested by the server port).

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

var userTokenPattern = regexp.MustCompile(`^biam_ses_[A-Za-z0-9_-]{49}$`)

func noSecretFields(t *testing.T, value any) {
	t.Helper()
	text := core.MustStringify(value)
	if strings.Contains(text, "tokenHash") || strings.Contains(text, "uniqueKey") {
		t.Errorf("secret-derived fields in %s", text)
	}
}

func (f *fixture) storedSession(token string) *core.Object {
	f.t.Helper()
	rows := f.find("sessions", core.NewObject("tokenHash", HashToken(token)))
	if len(rows) != 1 {
		f.t.Fatalf("%d sessions for the token", len(rows))
	}
	return rows[0]
}

func TestSignInResultsNeverCarrySecretDerivedFields(t *testing.T) {
	f := orgFixture(t)
	f.member("alice")
	signedIn := f.memberSignIn("alice")
	if !strings.HasPrefix(str(child(signedIn, "session"), "id"), "ses_") {
		t.Error("session id prefix")
	}
	noSecretFields(t, signedIn)
	bob := f.enrolled("bob")
	verified := must[*core.Object](t)(f.auth.VerifyMfa(f.ctx, core.NewObject("tenantId", "org", "challenge", bob.challenge(), "code", bob.code())))
	if !isTrue(child(verified, "session"), "mfa") {
		t.Error("mfa")
	}
	noSecretFields(t, verified)
}

func TestUserTokensArePrefixedAndChecksummed(t *testing.T) {
	f := orgFixture(t)
	f.member("alice")
	value := session(t, f.memberSignIn("alice"))
	if !userTokenPattern.MatchString(value) || len(value) != 58 {
		t.Fatalf("token %q", value)
	}
	if kind, ok := ParseCredentialToken(value); !ok || kind != "ses" {
		t.Error("parse")
	}
	if principal := must[*Principal](t)(f.auth.Authenticate(f.ctx, token(value))); str(principal.Session, "kind") != "user" {
		t.Error("kind")
	}
	for _, kind := range []string{"ses", "key", "rol", "sts", "dlg"} {
		generated := must[string](t)(NewCredentialToken(kind))
		if !regexp.MustCompile(`^biam_` + kind + `_[A-Za-z0-9_-]{49}$`).MatchString(generated) {
			t.Errorf("%s token %q", kind, generated)
		}
		if parsed, ok := ParseCredentialToken(generated); !ok || parsed != kind {
			t.Errorf("%s does not parse", kind)
		}
	}
	key := must[string](t)(NewCredentialToken("key"))
	for _, bad := range []string{key[:len(key)-1], key + "A", strings.Replace(key, "biam_key_", "biam_xyz_", 1), "biam_ses_" + key[9:52], ""} {
		if _, ok := ParseCredentialToken(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

// countingStore counts the storage calls made through it.
type countingStore struct {
	core.IamStore
	calls atomic.Int32
}

func (s *countingStore) Find(ctx context.Context, collection string, filter *core.Object, options *core.FindOptions) ([]*core.Object, error) {
	s.calls.Add(1)
	return s.IamStore.Find(ctx, collection, filter, options)
}

func (s *countingStore) Transaction(ctx context.Context, fn core.TxFunc) error {
	s.calls.Add(1)
	return s.IamStore.Transaction(ctx, fn)
}

func TestBadChecksumIsRefusedBeforeReadingStorage(t *testing.T) {
	f := orgFixture(t)
	f.member("alice")
	value := session(t, f.memberSignIn("alice"))
	at := len(value) - 6
	replacement := "A"
	if value[at] == 'A' {
		replacement = "B"
	}
	flipped := value[:at] + replacement + value[at+1:]
	if _, ok := ParseCredentialToken(flipped); ok {
		t.Fatal("the flipped token parses")
	}
	counting := &countingStore{IamStore: f.store}
	options := f.auth.Options()
	options.Store = counting
	service := must[*Service](t)(New(options))
	for _, input := range []core.CredentialInput{
		{Token: flipped},
		{Headers: http.Header{"Authorization": {"Bearer " + flipped}}},
		{Headers: http.Header{"Cookie": {"better-iam.session=" + flipped}}},
	} {
		_, err := service.Authenticate(f.ctx, input)
		if expectCode(t, err, "UNAUTHENTICATED").Status != 401 {
			t.Error("status")
		}
	}
	if counting.calls.Load() != 0 {
		t.Fatalf("%d storage calls for a bad checksum", counting.calls.Load())
	}
	must[*Principal](t)(service.Authenticate(f.ctx, token(value)))
	if counting.calls.Load() == 0 {
		t.Fatal("the genuine token was not looked up")
	}
}

func TestLegacyUnprefixedTokensWorkUntilTheyExpire(t *testing.T) {
	f := orgFixture(t)
	owner := f.member("owner")
	legacy := "legacy_user_token-" + strings.Repeat("x", 43-len("legacy_user_token-"))
	now := float64(f.now())
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, "sessions", core.NewObject("id", "ses_legacy_row", "tenantId", "org", "identityId", owner.Get("id"), "kind", "user",
			"tokenHash", HashToken(legacy), "uniqueKey", HashToken(legacy), "createdAt", now, "lastSeenAt", now, "expiresAt", now+float64(day),
			"authenticatedAt", now, "mfa", false))
		return err
	})
	if principal := must[*Principal](t)(f.auth.Authenticate(f.ctx, token(legacy))); str(principal.Session, "id") != "ses_legacy_row" {
		t.Error("legacy session")
	}
	f.advance(day)
	_, err := f.auth.Authenticate(f.ctx, token(legacy))
	expectCode(t, err, "UNAUTHENTICATED")
}

func TestRequireRecentRefusesTemporaryCredentials(t *testing.T) {
	f := orgFixture(t)
	f.member("alice")
	user := must[*Principal](t)(f.auth.Authenticate(f.ctx, token(session(t, f.memberSignIn("alice")))))
	if err := f.auth.RequireRecent(user); err != nil {
		t.Fatal(err)
	}
	derived := func(change func(*core.Object)) *Principal {
		copy := user.Session.Clone()
		change(copy)
		return &Principal{Identity: user.Identity, Session: copy}
	}
	for _, principal := range []*Principal{
		derived(func(s *core.Object) { s.Set("kind", "role") }),
		derived(func(s *core.Object) { s.Set("kind", "session-token") }),
		derived(func(s *core.Object) { s.Set("kind", "future-kind") }),
		derived(func(s *core.Object) { s.Set("sourceSessionId", "ses_source") }),
	} {
		err := expectCode(t, f.auth.RequireRecent(principal), "RECENT_AUTH_REQUIRED")
		if principal.Session.Get("kind") == "role" && (err.Status != 403 || err.Message != "Temporary credentials cannot perform this operation; use a signed-in session") {
			t.Errorf("role refusal %+v", err)
		}
	}
	if err := f.auth.RequireRecent(derived(func(s *core.Object) { s.Set("kind", "api-key") })); err != nil {
		t.Errorf("api-key: %v", err)
	}
	expectCode(t, f.auth.RequireRecent(derived(func(s *core.Object) {
		s.Set("kind", "role")
		s.Set("impersonatorId", "usr_admin")
	})), "IMPERSONATION_RESTRICTED")
	f.advance(5*60_000 + 1)
	expectCode(t, f.auth.RequireRecent(user), "RECENT_AUTH_REQUIRED")
}

func TestVerifyStepUpCodeAcceptsAFirstHandCodeOnce(t *testing.T) {
	f := orgFixture(t)
	carol := f.enrolled("carol")
	stepUp := func(identityID, code string) (*core.Object, error) {
		return core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			current, err := tx.Get(ctx, "identities", identityID)
			if err != nil {
				return nil, err
			}
			return f.auth.VerifyStepUpCode(ctx, tx, current, code)
		})
	}
	code := carol.code()
	if result := must[*core.Object](t)(stepUp(carol.id, code)); numOr(result, "verifiedAt", 0) != float64(f.now()) {
		t.Errorf("verifiedAt %s", core.MustStringify(result))
	}
	_, err := stepUp(carol.id, code)
	if expectCode(t, err, "INVALID_MFA").Status != 401 {
		t.Error("status")
	}
	f.advance(90_000)
	_, err = stepUp(carol.id, wrongCode(carol.code()))
	expectCode(t, err, "INVALID_MFA")
	_, err = stepUp(carol.id, "abcdef")
	expectCode(t, err, "INVALID_MFA")
	steps := 0
	for _, event := range f.find("audit", core.NewObject("tenantId", "org", "actorId", carol.id)) {
		if str(event, "action") == "auth:mfa:step-up" {
			steps++
		}
	}
	if steps != 1 {
		t.Errorf("%d step-up events", steps)
	}
	dave := f.member("dave")
	_, err = stepUp(str(dave, "id"), "123456")
	if expectCode(t, err, "MFA_NOT_ENROLLED").Status != 403 {
		t.Error("status")
	}
	// A service identity is never enrolled, even with a planted authenticator record.
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		record, err := tx.Get(ctx, "authMfa", carol.id)
		if err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "identities", core.NewObject("id", "svc_robot", "tenantId", "org", "kind", "service", "name", "robot",
			"status", "active", "emailVerified", false, "rootAdmin", false, "owner", false, "createdAt", float64(f.now()))); err != nil {
			return err
		}
		_, err = tx.Insert(ctx, "authMfa", record.Spread(core.NewObject("id", "svc_robot", "lastUsedStep", -1.0)))
		return err
	})
	f.advance(30_000)
	fresh := carol.code()
	_, err = stepUp("svc_robot", fresh)
	expectCode(t, err, "MFA_NOT_ENROLLED")
	if numOr(f.get("authMfa", "svc_robot"), "lastUsedStep", 0) != -1 {
		t.Error("the refusal consumed the planted record")
	}
	must[*core.Object](t)(stepUp(carol.id, fresh))
}

func TestLimitAttemptBudgets(t *testing.T) {
	f := orgFixture(t)
	two, twelve, one := int64(2), int64(12), int64(1)
	if err := f.auth.LimitAttempt(f.ctx, "org", "web-identity:trust-1", LimitAttemptOptions{Limit: &two}); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.LimitAttempt(f.ctx, "org", "web-identity:trust-1", LimitAttemptOptions{Limit: &two}); err != nil {
		t.Fatal(err)
	}
	err := f.auth.LimitAttempt(f.ctx, "org", "web-identity:trust-1", LimitAttemptOptions{Limit: &two})
	var limited *RateLimitedError
	if !asError(err, &limited) || limited.Status != 429 || limited.RetryAfterMs <= 0 {
		t.Fatalf("refusal %v", err)
	}
	if err := f.auth.LimitAttempt(f.ctx, "org", "web-identity:trust-2", LimitAttemptOptions{Limit: &two}); err != nil {
		t.Fatal(err)
	}
	if err := f.auth.LimitAttempt(f.ctx, "org", "step-up:someone", LimitAttemptOptions{Tier: "sensitive"}); err != nil {
		t.Fatal(err)
	}
	f.setOrgPolicy(core.NewObject("maxAttempts", 1.0))
	if err := f.auth.LimitAttempt(f.ctx, "org", "sign-in:capped", LimitAttemptOptions{}); err != nil {
		t.Fatal(err)
	}
	expectCode(t, f.auth.LimitAttempt(f.ctx, "org", "sign-in:capped", LimitAttemptOptions{}), "RATE_LIMITED")
	for attempt := 0; attempt < 12; attempt++ {
		if err := f.auth.LimitAttempt(f.ctx, "org", "web-identity:busy", LimitAttemptOptions{Limit: &twelve}); err != nil {
			t.Fatal(err)
		}
	}
	expectCode(t, f.auth.LimitAttempt(f.ctx, "org", "web-identity:busy", LimitAttemptOptions{Limit: &twelve}), "RATE_LIMITED")
	f.setOrgPolicy(core.NewObject("maxAttempts", 100.0))
	if err := f.auth.LimitAttempt(f.ctx, "org", "web-identity:strict", LimitAttemptOptions{Limit: &one}); err != nil {
		t.Fatal(err)
	}
	expectCode(t, f.auth.LimitAttempt(f.ctx, "org", "web-identity:strict", LimitAttemptOptions{Limit: &one}), "RATE_LIMITED")
	zero := int64(0)
	expectCode(t, f.auth.LimitAttempt(f.ctx, "org", "x", LimitAttemptOptions{Limit: &zero}), "INVALID_INPUT")
}

func TestMfaAuthenticatedAtIsRecordedForFirstHandFactorsOnly(t *testing.T) {
	f := orgFixture(t)
	root := f.identity("root", true, "root@example.test")
	credential := MfaCredential{TenantID: "root", Challenge: challengeOf(t, f.signIn("root", "root@example.test", testPassword))}
	enrollment := must[*core.Object](t)(f.auth.BeginMfa(f.ctx, credential))
	rootResult := must[*core.Object](t)(f.auth.ConfirmMfa(f.ctx, ConfirmMfaInput{Credential: credential, Code: f.totp(str(enrollment, "secret"))}))
	rootRow := f.storedSession(str(rootResult, "token"))
	if !isTrue(rootRow, "mfa") || !core.StrictEquals(rootRow.Get("mfaAuthenticatedAt"), rootRow.Get("createdAt")) {
		t.Errorf("root session %s", core.MustStringify(rootRow))
	}
	alice := f.member("alice")
	passwordRow := f.storedSession(session(t, f.memberSignIn("alice")))
	if passwordRow.Has("mfaAuthenticatedAt") {
		t.Error("a password session has an MFA time")
	}
	bob := f.enrolled("bob")
	verified := must[*core.Object](t)(f.auth.VerifyMfa(f.ctx, core.NewObject("tenantId", "org", "challenge", bob.challenge(), "code", bob.code(), "rememberDevice", true)))
	if numOr(f.storedSession(str(verified, "token")), "mfaAuthenticatedAt", 0) != float64(f.now()) {
		t.Error("verified MFA time")
	}
	f.advance(60_000)
	remembered := must[*core.Object](t)(f.auth.SignIn(f.ctx, core.NewObject("tenantId", "org", "email", "bob@acme.test", "password", "a strong bob password",
		"deviceToken", verified.Get("deviceToken"))))
	deviceRow := f.storedSession(session(t, remembered))
	if !isTrue(deviceRow, "mfa") || !deviceRow.Has("trustedDeviceId") || deviceRow.Has("mfaAuthenticatedAt") {
		t.Errorf("device session %s", core.MustStringify(deviceRow))
	}
	// Impersonation inherits the actor's MFA flag, never a factor time.
	f.setOrgPolicy(core.NewObject("allowImpersonation", true))
	owner := f.member("owner")
	actor := must[*Principal](t)(f.auth.Authenticate(f.ctx, token(session(t, f.memberSignIn("owner")))))
	viewAs := must[*core.Object](t)(core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.auth.IssueImpersonationSession(ctx, tx, actor, alice, 60*60_000)
	}))
	if !userTokenPattern.MatchString(str(viewAs, "token")) {
		t.Error("impersonation token shape")
	}
	impersonation := f.storedSession(str(viewAs, "token"))
	if str(impersonation, "impersonatorId") != str(owner, "id") || impersonation.Has("mfaAuthenticatedAt") || str(impersonation, "method") != "impersonation" {
		t.Errorf("impersonation %s", core.MustStringify(impersonation))
	}
	noSecretFields(t, viewAs.Get("session"))
	_ = root
}
