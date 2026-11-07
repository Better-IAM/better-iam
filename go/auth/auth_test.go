package auth

// Port of tests/auth.test.ts.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// --- tenant authentication and session revocation ------------------------------------------------------------------

func TestKeepsIdenticalEmailsSeparateAcrossTenants(t *testing.T) {
	f := newFixture(t)
	first := f.identity("org", false, "")
	second := f.identity("sibling", false, "")
	login := session(t, f.signIn("org", "SAME@example.com", testPassword))
	principal := must[*Principal](t)(f.auth.Authenticate(f.ctx, core.CredentialInput{Token: login, Headers: http.Header{"X-Tenant-Id": {"sibling"}}}))
	if str(principal.Identity, "id") != str(first, "id") || str(principal.Identity, "id") == str(second, "id") || str(principal.Identity, "tenantId") != "org" {
		t.Fatalf("authenticated %s", core.MustStringify(principal.Identity))
	}
	current := must[*core.Object](t)(f.auth.GetSession(f.ctx, token(login)))
	if child(current, "identity").Has("passwordHash") {
		t.Error("getSession exposes passwordHash")
	}
	sessions := must[[]*core.Object](t)(f.auth.ListSessions(f.ctx, token(login)))
	if sessions[0].Has("tokenHash") || !isTrue(sessions[0], "current") {
		t.Error("listSessions exposes tokenHash or misses current")
	}
	if !strings.HasPrefix(str(f.get("identities", str(first, "id")), "passwordHash"), "$argon2id$") {
		t.Error("password hash is not argon2id")
	}
}

func TestChecksAncestorStatusAndSessionExpiry(t *testing.T) {
	f := newFixture(t)
	f.identity("project", false, "")
	login := session(t, f.signIn("project", "same@example.com", testPassword))
	f.update("tenants", "org", func(o *core.Object) { o.Set("status", "suspended") })
	_, err := f.auth.Authenticate(f.ctx, token(login))
	expectCode(t, err, "TENANT_UNAVAILABLE")
	f.update("tenants", "org", func(o *core.Object) { o.Set("status", "active") })
	f.advance(8 * 24 * 60 * 60_000)
	_, err = f.auth.Authenticate(f.ctx, token(login))
	expectCode(t, err, "UNAUTHENTICATED")
}

func TestHostPrefixedCookiesAndIdleChecksOnSessionIDs(t *testing.T) {
	f := newFixture(t)
	f.identity("org", false, "")
	result := f.signIn("org", "same@example.com", testPassword)
	login := session(t, result)
	sessionID := str(child(result, "session"), "id")
	_, err := f.auth.Authenticate(f.ctx, core.CredentialInput{Headers: http.Header{"Cookie": {"better-iam.session=" + login}}})
	expectCode(t, err, "UNAUTHENTICATED")
	principal := must[*Principal](t)(f.auth.Authenticate(f.ctx, core.CredentialInput{Headers: http.Header{"Cookie": {"__Host-better-iam.session=" + login}}}))
	if str(principal.Session, "id") != sessionID {
		t.Fatal("cookie resolved another session")
	}
	f.advance(23 * 60 * 60_000)
	validated := must[*Principal](t)(f.auth.ValidateSessionID(f.ctx, sessionID))
	if numOr(validated.Session, "lastSeenAt", 0) != float64(f.now()) {
		t.Error("validateSessionId did not touch lastSeenAt")
	}
	f.advance(24 * 60 * 60_000)
	_, err = f.auth.ValidateSessionID(f.ctx, sessionID)
	expectCode(t, err, "UNAUTHENTICATED")
	_, err = f.auth.Authenticate(f.ctx, token(login))
	expectCode(t, err, "UNAUTHENTICATED")
}

func TestPersistsFailedLoginRateLimits(t *testing.T) {
	f := newFixture(t)
	attempt := func() error {
		_, err := f.auth.SignIn(f.ctx, core.NewObject("tenantId", "org", "email", "unknown@example.com", "password", testPassword))
		return err
	}
	for index := 0; index < 10; index++ {
		expectCode(t, attempt(), "INVALID_CREDENTIALS")
	}
	limited := expectCode(t, attempt(), "RATE_LIMITED")
	var rateLimited *RateLimitedError
	if !asError(attempt(), &rateLimited) || rateLimited.RetryAfterMs != 15*60_000 || limited.Status != 429 {
		t.Error("RATE_LIMITED does not carry retryAfterMs")
	}
	f.advance(16 * 60_000)
	expectCode(t, attempt(), "INVALID_CREDENTIALS")
}

func TestSignUpRequiresVerificationAndConsumesItOnce(t *testing.T) {
	f := newFixture(t)
	result := must[*core.Object](t)(f.auth.SignUp(f.ctx, core.NewObject("tenantId", "org", "email", "new@example.com", "name", "New", "password", testPassword)))
	if !isTrue(result, "verificationRequired") || child(result, "identity").Has("passwordHash") {
		t.Fatalf("signUp result %s", core.MustStringify(result))
	}
	_, err := f.auth.SignIn(f.ctx, core.NewObject("tenantId", "org", "email", "new@example.com", "password", testPassword))
	expectCode(t, err, "EMAIL_UNVERIFIED")
	if stored := core.MustStringify(f.find("outbox", nil)); strings.Contains(stored, `"token":`) {
		t.Error("outbox payload is not sealed")
	}
	if dispatched := f.dispatch(); dispatched != (DispatchResult{Delivered: 1}) {
		t.Fatalf("dispatch %+v", dispatched)
	}
	verification := f.messages()[0].Payload["token"]
	_, err = f.auth.VerifyEmail(f.ctx, core.NewObject("tenantId", "sibling", "token", verification))
	expectCode(t, err, "INVALID_CHALLENGE")
	if ok := parallel(2, func() error {
		_, err := f.auth.VerifyEmail(f.ctx, core.NewObject("tenantId", "org", "token", verification))
		return err
	}); ok != 1 {
		t.Fatalf("%d verifications succeeded", ok)
	}
	session(t, f.signIn("org", "new@example.com", testPassword))
	if payload := child(f.find("outbox", nil)[0], "payload"); payload.Len() != 0 {
		t.Error("delivered payload kept")
	}
	_, err = f.auth.SignUp(f.ctx, core.NewObject("tenantId", "root", "email", "bad@example.com", "name", "Bad", "password", testPassword))
	expectCode(t, err, "FORBIDDEN")
}

func TestPasswordChangesRevokeSessionsAndRequireRecentAuthentication(t *testing.T) {
	f := newFixture(t)
	f.identity("org", false, "")
	login := session(t, f.signIn("org", "same@example.com", testPassword))
	f.advance(6 * 60_000)
	change := core.NewObject("currentPassword", testPassword, "password", "replacement-password")
	_, err := f.auth.ChangePassword(f.ctx, token(login), change)
	expectCode(t, err, "RECENT_AUTH_REQUIRED")
	fresh := session(t, must[*core.Object](t)(f.auth.Reauthenticate(f.ctx, token(login), core.NewObject("password", testPassword))))
	must[*core.Object](t)(f.auth.ChangePassword(f.ctx, token(fresh), change))
	_, err = f.auth.Authenticate(f.ctx, token(login))
	expectCode(t, err, "UNAUTHENTICATED")
	_, err = f.auth.Authenticate(f.ctx, token(fresh))
	expectCode(t, err, "UNAUTHENTICATED")
	session(t, f.signIn("org", "same@example.com", "replacement-password"))
}

// --- MFA enrollment, challenges, and account recovery ----------------------------------------------------------------

func TestRootMfaEnrollmentReplayAndRecovery(t *testing.T) {
	f := newFixture(t)
	root := f.identity("root", true, "")
	login := f.signIn("root", "same@example.com", testPassword)
	if !isTrue(login, "mfaRequired") || !isTrue(login, "enrollmentRequired") {
		t.Fatalf("login %s", core.MustStringify(login))
	}
	_, err := f.auth.Authenticate(f.ctx, token(str(login, "challenge")))
	expectCode(t, err, "UNAUTHENTICATED")
	credential := MfaCredential{TenantID: "root", Challenge: str(login, "challenge")}
	enrollment := must[*core.Object](t)(f.auth.BeginMfa(f.ctx, credential))
	if strings.Contains(core.MustStringify(f.get("authMfa", str(root, "id"))), str(enrollment, "secret")) {
		t.Error("the TOTP secret is stored in the clear")
	}
	verified := must[*core.Object](t)(f.auth.ConfirmMfa(f.ctx, ConfirmMfaInput{Credential: credential, Code: f.totp(str(enrollment, "secret"))}))
	if codes, _ := verified.Get("recoveryCodes").([]any); len(codes) != 10 {
		t.Fatalf("recovery codes %v", verified.Get("recoveryCodes"))
	}
	if principal := must[*Principal](t)(f.auth.Authenticate(f.ctx, token(str(verified, "token")))); !isTrue(principal.Session, "mfa") {
		t.Error("enrollment session is not MFA")
	}
	next := challengeOf(t, f.signIn("root", "same@example.com", testPassword))
	_, err = f.auth.BeginMfa(f.ctx, MfaCredential{TenantID: "root", Challenge: next})
	expectCode(t, err, "MFA_REQUIRED")
	verify := func() error {
		_, err := f.auth.VerifyMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", next, "code", f.totp(str(enrollment, "secret"))))
		return err
	}
	expectCode(t, verify(), "INVALID_MFA")
	f.advance(30_000)
	if err := verify(); err != nil {
		t.Fatal(err)
	}
	expectCode(t, verify(), "INVALID_CHALLENGE")
	must[*core.Object](t)(f.auth.RequestPasswordReset(f.ctx, core.NewObject("tenantId", "root", "email", "same@example.com")))
	f.dispatch()
	reset := f.lastMessage("password-reset").Payload["token"]
	must[*core.Object](t)(f.auth.ResetPassword(f.ctx, core.NewObject("tenantId", "root", "token", reset, "password", "replacement-password")))
	_, err = f.auth.Authenticate(f.ctx, token(str(verified, "token")))
	expectCode(t, err, "UNAUTHENTICATED")
	after := f.signIn("root", "same@example.com", "replacement-password")
	if !isTrue(after, "mfaRequired") || flag(after, "enrollmentRequired") {
		t.Fatalf("after reset %s", core.MustStringify(after))
	}
}

func TestRecoveryCodesWorkOnceAcrossSimultaneousChallenges(t *testing.T) {
	f := newFixture(t)
	f.identity("org", false, "")
	login := session(t, f.signIn("org", "same@example.com", testPassword))
	enrollment := must[*core.Object](t)(f.auth.BeginMfa(f.ctx, MfaCredential{Credentials: &core.CredentialInput{Token: login}}))
	enabled := must[*core.Object](t)(f.auth.ConfirmMfa(f.ctx, ConfirmMfaInput{
		Credential: MfaCredential{Credentials: &core.CredentialInput{Token: login}}, Code: f.totp(str(enrollment, "secret")),
	}))
	code := enabled.Get("recoveryCodes").([]any)[0].(string)
	challenges := []string{
		challengeOf(t, f.signIn("org", "same@example.com", testPassword)),
		challengeOf(t, f.signIn("org", "same@example.com", testPassword)),
	}
	var next int32
	ok := parallel(2, func() error {
		index := int(atomicAdd(&next) - 1)
		_, err := f.auth.RecoverMfa(f.ctx, core.NewObject("tenantId", "org", "challenge", challenges[index], "code", code))
		return err
	})
	if ok != 1 {
		t.Fatalf("%d recoveries succeeded", ok)
	}
	if strings.Contains(core.MustStringify(f.find("authMfa", nil)), code) {
		t.Error("recovery code stored in the clear")
	}
}

func TestRotatesRecoveryCodesAndProhibitsDisablingRootMfa(t *testing.T) {
	f := newFixture(t)
	f.identity("root", true, "")
	credential := MfaCredential{TenantID: "root", Challenge: challengeOf(t, f.signIn("root", "same@example.com", testPassword))}
	enrollment := must[*core.Object](t)(f.auth.BeginMfa(f.ctx, credential))
	enabled := must[*core.Object](t)(f.auth.ConfirmMfa(f.ctx, ConfirmMfaInput{Credential: credential, Code: f.totp(str(enrollment, "secret"))}))
	rotated := must[*core.Object](t)(f.auth.RegenerateRecoveryCodes(f.ctx, token(str(enabled, "token"))))
	codes := rotated.Get("recoveryCodes").([]any)
	old := enabled.Get("recoveryCodes").([]any)[0]
	if len(codes) != 10 {
		t.Fatal("rotation did not issue 10 codes")
	}
	for _, code := range codes {
		if code == old {
			t.Fatal("rotation kept an old code")
		}
	}
	_, err := f.auth.DisableMfa(f.ctx, token(str(enabled, "token")))
	expectCode(t, err, "MFA_REQUIRED")
	again := challengeOf(t, f.signIn("root", "same@example.com", testPassword))
	_, err = f.auth.RecoverMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", again, "code", old))
	expectCode(t, err, "INVALID_MFA")
	must[*core.Object](t)(f.auth.RecoverMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", again, "code", codes[0])))
}

// --- passwordless and delivery ---------------------------------------------------------------------------------------

func TestEncryptedOutboxAndPasswordlessCodesOnce(t *testing.T) {
	f := newFixture(t)
	f.identity("org", false, "")
	must[*core.Object](t)(f.auth.StartPasswordless(f.ctx, core.NewObject("tenantId", "org", "destination", "same@example.com", "channel", "email", "kind", "code")))
	sealed := core.MustStringify(f.find("outbox", nil))
	f.dispatch()
	code := f.messages()[0].Payload["token"]
	if strings.Contains(sealed, `"`+code+`"`) {
		t.Error("the code is visible in the outbox")
	}
	finish := func(tenantID, destination string) error {
		_, err := f.auth.FinishPasswordless(f.ctx, core.NewObject("tenantId", tenantID, "destination", destination, "token", code))
		return err
	}
	expectCode(t, finish("sibling", "same@example.com"), "INVALID_CHALLENGE")
	expectCode(t, finish("org", "other@example.com"), "INVALID_CHALLENGE")
	if ok := parallel(2, func() error { return finish("org", "same@example.com") }); ok != 1 {
		t.Fatalf("%d finishes succeeded", ok)
	}
	if dispatched := f.dispatch(); dispatched != (DispatchResult{}) {
		t.Fatalf("dispatch %+v", dispatched)
	}
}

func TestSmsLoginRequiresVerifiedPhone(t *testing.T) {
	f := newFixture(t)
	f.identity("org", false, "")
	login := session(t, f.signIn("org", "same@example.com", testPassword))
	start := core.NewObject("tenantId", "org", "destination", "+15551234567", "channel", "sms", "kind", "code")
	must[*core.Object](t)(f.auth.StartPasswordless(f.ctx, start))
	f.dispatch()
	if len(f.messages()) != 0 {
		t.Fatal("an unverified phone received a code")
	}
	must[*core.Object](t)(f.auth.StartPhoneVerification(f.ctx, token(login), core.NewObject("phone", "+15551234567")))
	f.dispatch()
	must[*core.Object](t)(f.auth.ConfirmPhoneVerification(f.ctx, token(login), core.NewObject("phone", "+15551234567", "code", f.messages()[0].Payload["token"])))
	must[*core.Object](t)(f.auth.StartPasswordless(f.ctx, start))
	f.dispatch()
	result := must[*core.Object](t)(f.auth.FinishPasswordless(f.ctx, core.NewObject("tenantId", "org", "destination", "+15551234567", "token", f.messages()[1].Payload["token"])))
	session(t, result)
}

func TestSealedValuesAndFeatureConfiguration(t *testing.T) {
	sealed := EncryptSecret("private value", testSecret, "tenant:a")
	if value, err := DecryptSecret(sealed, []string{testSecret}, "tenant:a"); err != nil || value != "private value" {
		t.Fatal("round trip failed")
	}
	if _, err := DecryptSecret(sealed, []string{testSecret}, "tenant:b"); err == nil {
		t.Fatal("another context opened the value")
	}
	store := newStore(t)
	defer store.Close(context.Background())
	if _, err := New(Options{Store: store, Secret: testSecret, BaseURL: "https://iam.example.com", SignUpEnabled: true}); err == nil || !strings.Contains(err.Error(), "sendEmail") {
		t.Errorf("signUpEnabled without sendEmail: %v", err)
	}
	if _, err := New(Options{Store: store, Secret: testSecret, BaseURL: "https://iam.example.com", PasswordlessSms: true}); err == nil || !strings.Contains(err.Error(), "sendSms") {
		t.Errorf("passwordlessSms without sendSms: %v", err)
	}
}

// --- passkeys ----------------------------------------------------------------------------------------------------------

func TestPasskeysRegisterAndAuthenticateRejectingWrongTenantOriginAndReplay(t *testing.T) {
	f := newFixture(t)
	user := f.identity("org", false, "")
	login := session(t, f.signIn("org", "same@example.com", testPassword))
	registration := must[*core.Object](t)(f.auth.BeginPasskeyRegistration(f.ctx, token(login)))
	authenticator := newVirtualAuthenticator("iam.example.com", "https://iam.example.com")
	must[*core.Object](t)(f.auth.FinishPasskeyRegistration(f.ctx, token(login), core.NewObject(
		"challengeId", registration.Get("challengeId"),
		"response", authenticator.register(str(child(registration, "options"), "challenge")),
	)))
	authentication := must[*core.Object](t)(f.auth.BeginPasskeyAuthentication(f.ctx, core.NewObject("tenantId", "org", "email", "same@example.com")))
	challenge := str(child(authentication, "options"), "challenge")
	finish := func(tenantID string, response *core.Object) (*core.Object, error) {
		return f.auth.FinishPasskeyAuthentication(f.ctx, core.NewObject("tenantId", tenantID, "challengeId", authentication.Get("challengeId"), "response", response))
	}
	_, err := finish("sibling", authenticator.assert(challenge, str(user, "id")))
	expectCode(t, err, "INVALID_CHALLENGE")
	if _, err := finish("org", authenticator.assert(challenge, str(user, "id"), "https://attacker.example")); err == nil {
		t.Fatal("an assertion from another origin was accepted")
	}
	authenticated := must[*core.Object](t)(finish("org", authenticator.assert(challenge, str(user, "id"))))
	if principal := must[*Principal](t)(f.auth.Authenticate(f.ctx, token(str(authenticated, "token")))); !isTrue(principal.Session, "mfa") {
		t.Error("a passkey session must satisfy MFA")
	}
	_, err = finish("org", authenticator.assert(challenge, str(user, "id")))
	expectCode(t, err, "INVALID_CHALLENGE")
	keys := must[[]*core.Object](t)(f.auth.ListPasskeys(f.ctx, token(str(authenticated, "token"))))
	if len(keys) != 1 || keys[0].Has("publicKey") || str(keys[0], "name") != "This device" {
		t.Fatalf("passkeys %s", core.MustStringify(keys))
	}
	must[*core.Object](t)(f.auth.DeletePasskey(f.ctx, token(str(authenticated, "token")), core.NewObject("id", keys[0].Get("id"))))
	_, err = f.auth.Authenticate(f.ctx, token(str(authenticated, "token")))
	expectCode(t, err, "UNAUTHENTICATED")
}
