package auth

// Ports of tests/passkey-discovery.test.ts, tests/passkey-mfa.test.ts and tests/passkey-metadata.test.ts (the
// authentication service part; the HTTP rename call belongs to the server port).

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const passkeyOrigin = "https://iam.example.com"

func passkeyFixture(t *testing.T, configure ...func(*Options)) *fixture {
	return newFixture(t, append([]func(*Options){func(o *Options) {
		o.Passkeys = &PasskeyOptions{RPID: "iam.example.com", RPName: "IAM"}
		o.SignUpEnabled, o.PasswordlessEmail, o.PasswordlessSms = false, false, false
	}}, configure...)...)
}

func (f *fixture) person(name string) *core.Object {
	f.t.Helper()
	var created *core.Object
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		created, err = f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "root", Email: name + "@example.test", Name: name,
			Password: "a strong " + name + " password", HasPassword: true, EmailVerified: true})
		return err
	})
	return created
}

func (f *fixture) personSignIn(name string) *core.Object {
	return must[*core.Object](f.t)(f.auth.SignIn(f.ctx, core.NewObject("tenantId", "root", "email", name+"@example.test", "password", "a strong "+name+" password")))
}

func (f *fixture) registerPasskey(credentials core.CredentialInput, authenticator *virtualAuthenticator, name any) *core.Object {
	f.t.Helper()
	registration := must[*core.Object](f.t)(f.auth.BeginPasskeyRegistration(f.ctx, credentials))
	input := core.NewObject("challengeId", registration.Get("challengeId"), "response", authenticator.register(str(child(registration, "options"), "challenge")))
	if name != nil {
		input.Set("name", name)
	}
	return must[*core.Object](f.t)(f.auth.FinishPasskeyRegistration(f.ctx, credentials, input))
}

func (f *fixture) finishPasskey(challengeID any, response *core.Object) (*core.Object, error) {
	return f.auth.FinishPasskeyAuthentication(f.ctx, core.NewObject("tenantId", "root", "challengeId", challengeID, "response", response))
}

func TestPasskeyDiscoveryFindsTheAccountFromTheCredential(t *testing.T) {
	three := int64(3)
	f := passkeyFixture(t, func(o *Options) { o.RateLimits = &RateLimitOptions{Attempts: &three} })
	type registered struct {
		identity      *core.Object
		authenticator *virtualAuthenticator
	}
	enroll := func(name string) registered {
		identity := f.person(name)
		credentials := token(session(t, f.personSignIn(name)))
		authenticator := newVirtualAuthenticator("iam.example.com", passkeyOrigin)
		f.registerPasskey(credentials, authenticator, name+"'s key")
		return registered{identity, authenticator}
	}
	alice, bob := enroll("alice"), enroll("bob")
	discovery := must[*core.Object](t)(f.auth.BeginPasskeyAuthentication(f.ctx, core.NewObject("tenantId", "root")))
	options := child(discovery, "options")
	if options.Has("allowCredentials") || str(options, "userVerification") != "required" {
		t.Fatalf("discovery options %s", core.MustStringify(options))
	}
	signedIn := must[*core.Object](t)(f.finishPasskey(discovery.Get("challengeId"), alice.authenticator.assert(str(options, "challenge"), str(alice.identity, "id"))))
	if s := child(signedIn, "session"); str(s, "identityId") != str(alice.identity, "id") || str(s, "method") != "passkey" || !isTrue(s, "mfa") {
		t.Fatalf("session %s", core.MustStringify(s))
	}
	_, err := f.finishPasskey(discovery.Get("challengeId"), bob.authenticator.assert(str(options, "challenge"), str(bob.identity, "id")))
	expectCode(t, err, "INVALID_CHALLENGE")
	again := must[*core.Object](t)(f.auth.BeginPasskeyAuthentication(f.ctx, core.NewObject("tenantId", "root")))
	_, err = f.finishPasskey(again.Get("challengeId"), bob.authenticator.assert(str(child(again, "options"), "challenge"), str(alice.identity, "id")))
	expectCode(t, err, "INVALID_PASSKEY")
	stranger := newVirtualAuthenticator("iam.example.com", passkeyOrigin)
	third := must[*core.Object](t)(f.auth.BeginPasskeyAuthentication(f.ctx, core.NewObject("tenantId", "root")))
	_, err = f.finishPasskey(third.Get("challengeId"), stranger.assert(str(child(third, "options"), "challenge"), str(alice.identity, "id")))
	expectCode(t, err, "INVALID_PASSKEY")
	for index := 0; index < 27; index++ {
		must[*core.Object](t)(f.auth.BeginPasskeyAuthentication(f.ctx, core.NewObject("tenantId", "root")))
	}
	_, err = f.auth.BeginPasskeyAuthentication(f.ctx, core.NewObject("tenantId", "root"))
	expectCode(t, err, "RATE_LIMITED")
	named := must[*core.Object](t)(f.auth.BeginPasskeyAuthentication(f.ctx, core.NewObject("tenantId", "root", "email", "bob@example.test")))
	allowed := child(named, "options").Get("allowCredentials").([]any)
	if len(allowed) != 1 || str(allowed[0].(*core.Object), "id") != bob.authenticator.id() {
		t.Fatalf("allowCredentials %s", core.MustStringify(allowed))
	}
	bobSession := must[*core.Object](t)(f.finishPasskey(named.Get("challengeId"), bob.authenticator.assert(str(child(named, "options"), "challenge"), str(bob.identity, "id"))))
	if str(child(bobSession, "session"), "identityId") != str(bob.identity, "id") {
		t.Error("bob signed in as someone else")
	}
	f.update("identities", str(alice.identity, "id"), func(o *core.Object) { o.Set("status", "disabled") })
	elsewhere := f.auth.WithClient(f.ctx, &core.SessionClientInfo{IP: "203.0.113.9"})
	blocked := must[*core.Object](t)(f.auth.BeginPasskeyAuthentication(elsewhere, core.NewObject("tenantId", "root")))
	_, err = f.finishPasskey(blocked.Get("challengeId"), alice.authenticator.assert(str(child(blocked, "options"), "challenge"), str(alice.identity, "id")))
	expectCode(t, err, "UNAUTHENTICATED")
}

func TestPasskeyAsTheSecondFactor(t *testing.T) {
	f := passkeyFixture(t)
	alice := f.person("alice")
	authenticator := newVirtualAuthenticator("iam.example.com", passkeyOrigin)
	f.registerPasskey(token(session(t, f.personSignIn("alice"))), authenticator, nil)
	f.update("tenants", "root", func(o *core.Object) { o.Set("authPolicy", core.NewObject("requireMfa", true)) })
	challenge := f.personSignIn("alice")
	if flag(challenge, "enrollmentRequired") || flag(challenge, "authenticatorEnrolled") || !isTrue(challenge, "passkeyAvailable") {
		t.Fatalf("challenge %s", core.MustStringify(challenge))
	}
	login := challengeOf(t, challenge)
	_, err := f.auth.BeginMfa(f.ctx, MfaCredential{TenantID: "root", Challenge: login})
	expectCode(t, err, "MFA_REQUIRED")
	_, err = f.auth.ConfirmMfa(f.ctx, ConfirmMfaInput{Credential: MfaCredential{TenantID: "root", Challenge: login}, Code: "123456"})
	expectCode(t, err, "MFA_REQUIRED")
	begun := must[*core.Object](t)(f.auth.BeginPasskeyMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", login)))
	options := child(begun, "options")
	if allowed := options.Get("allowCredentials").([]any); len(allowed) != 1 || str(allowed[0].(*core.Object), "id") != authenticator.id() {
		t.Fatalf("allowCredentials %s", core.MustStringify(allowed))
	}
	finish := func(tenantID string, response *core.Object, remember bool) (*core.Object, error) {
		return f.auth.FinishPasskeyMfa(f.ctx, core.NewObject("tenantId", tenantID, "challengeId", begun.Get("challengeId"), "response", response, "rememberDevice", remember))
	}
	_, err = finish("root", authenticator.assert(str(options, "challenge"), str(alice, "id"), "https://attacker.example"), false)
	expectCode(t, err, "INVALID_PASSKEY")
	_, err = finish("elsewhere", authenticator.assert(str(options, "challenge"), str(alice, "id")), false)
	expectCode(t, err, "INVALID_CHALLENGE")
	result := must[*core.Object](t)(finish("root", authenticator.assert(str(options, "challenge"), str(alice, "id")), true))
	if s := child(result, "session"); !isTrue(s, "mfa") || str(s, "method") != "password" || !result.Has("deviceToken") {
		t.Fatalf("result %s", core.MustStringify(result))
	}
	if current := must[*core.Object](t)(f.auth.GetSession(f.ctx, token(str(result, "token")))); str(child(current, "identity"), "id") != str(alice, "id") {
		t.Error("getSession")
	}
	_, err = finish("root", authenticator.assert(str(options, "challenge"), str(alice, "id")), false)
	expectCode(t, err, "INVALID_CHALLENGE")
	_, err = f.auth.BeginPasskeyMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", login))
	expectCode(t, err, "INVALID_CHALLENGE")
	keys := must[[]*core.Object](t)(f.auth.ListPasskeys(f.ctx, token(str(result, "token"))))
	must[*core.Object](t)(f.auth.DeletePasskey(f.ctx, token(str(result, "token")), core.NewObject("id", keys[0].Get("id"))))
	bare := f.personSignIn("alice")
	if bare.Has("passkeyAvailable") {
		t.Error("a passkey is offered without one")
	}
	_, err = f.auth.BeginPasskeyMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", challengeOf(t, bare)))
	expectCode(t, err, "FEATURE_DISABLED")
}

func TestPasskeyMfaRefusesAnExpiredSignInChallenge(t *testing.T) {
	f := passkeyFixture(t)
	alice := f.person("alice")
	authenticator := newVirtualAuthenticator("iam.example.com", passkeyOrigin)
	f.registerPasskey(token(session(t, f.personSignIn("alice"))), authenticator, nil)
	f.update("tenants", "root", func(o *core.Object) { o.Set("authPolicy", core.NewObject("requireMfa", true)) })
	login := challengeOf(t, f.personSignIn("alice"))
	f.advance(4 * 60_000)
	begun := must[*core.Object](t)(f.auth.BeginPasskeyMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", login)))
	f.advance(2 * 60_000)
	_, err := f.auth.FinishPasskeyMfa(f.ctx, core.NewObject("tenantId", "root", "challengeId", begun.Get("challengeId"),
		"response", authenticator.assert(str(child(begun, "options"), "challenge"), str(alice, "id"))))
	expectCode(t, err, "INVALID_CHALLENGE")
}

func TestPasskeyNamesAndUsage(t *testing.T) {
	f := passkeyFixture(t)
	alice := f.person("alice")
	f.identity("root", true, "root@example.test")
	credentials := token(session(t, f.personSignIn("alice")))
	laptopKey := newVirtualAuthenticator("iam.example.com", passkeyOrigin)
	laptop := f.registerPasskey(credentials, laptopKey, "Work laptop")
	if str(laptop, "name") != "Work laptop" {
		t.Fatal(core.MustStringify(laptop))
	}
	f.advance(60_000)
	unnamed := f.registerPasskey(credentials, newVirtualAuthenticator("iam.example.com", passkeyOrigin), nil)
	if str(unnamed, "name") != "This device" {
		t.Fatal(core.MustStringify(unnamed))
	}
	listed := must[[]*core.Object](t)(f.auth.ListPasskeys(f.ctx, credentials))
	if str(listed[0], "name") != "This device" || str(listed[1], "name") != "Work laptop" {
		t.Fatalf("listed %s", core.MustStringify(listed))
	}
	second := listed[1]
	if str(second, "id") != str(laptop, "id") || numOr(second, "createdAt", 0) != float64(f.now()-60_000) || str(second, "deviceType") != "singleDevice" ||
		flag(second, "backedUp") || core.MustStringify(second.Get("transports")) != `["internal"]` || second.Has("lastUsedAt") {
		t.Fatalf("listed[1] %s", core.MustStringify(second))
	}
	if strings.Contains(core.MustStringify(listed), "publicKey") {
		t.Error("publicKey exposed")
	}
	f.advance(60_000)
	begun := must[*core.Object](t)(f.auth.BeginPasskeyAuthentication(f.ctx, core.NewObject("tenantId", "root", "email", "alice@example.test")))
	signedIn := must[*core.Object](t)(f.finishPasskey(begun.Get("challengeId"), laptopKey.assert(str(child(begun, "options"), "challenge"), str(alice, "id"))))
	if str(child(signedIn, "session"), "method") != "passkey" {
		t.Error("method")
	}
	for _, key := range must[[]*core.Object](t)(f.auth.ListPasskeys(f.ctx, credentials)) {
		used, ok := num(key, "lastUsedAt")
		if str(key, "id") == str(laptop, "id") && (!ok || used != float64(f.now())) {
			t.Error("lastUsedAt not stamped")
		}
		if str(key, "id") == str(unnamed, "id") && ok {
			t.Error("an unused key has lastUsedAt")
		}
	}
	f.advance(10 * 60_000)
	renamed := must[*core.Object](t)(f.auth.RenamePasskey(f.ctx, credentials, core.NewObject("id", laptop.Get("id"), "name", "  YubiKey 5C  ")))
	if str(renamed, "name") != "YubiKey 5C" {
		t.Errorf("renamed %s", core.MustStringify(renamed))
	}
	_, err := f.auth.RenamePasskey(f.ctx, credentials, core.NewObject("id", laptop.Get("id"), "name", "   "))
	expectCode(t, err, "INVALID_INPUT")
	_, err = f.auth.RenamePasskey(f.ctx, credentials, core.NewObject("id", laptop.Get("id"), "name", strings.Repeat("x", 65)))
	expectCode(t, err, "INVALID_INPUT")
	_, err = f.auth.RenamePasskey(f.ctx, credentials, core.NewObject("id", "pk_missing", "name", "Nope"))
	expectCode(t, err, "NOT_FOUND")
	events := map[string]bool{}
	for _, event := range f.find("audit", core.NewObject("tenantId", "root", "actorId", alice.Get("id"))) {
		events[str(event, "action")+"|"+str(child(event, "metadata"), "name")] = true
	}
	for _, expected := range []string{"auth:passkey:create|Work laptop", "auth:passkey:create|This device", "auth:passkey:rename|YubiKey 5C"} {
		if !events[expected] {
			t.Errorf("missing %s in %v", expected, events)
		}
	}
	stored := f.get("authPasskeys", str(laptop, "id"))
	if str(stored, "uniqueKey") != laptopKey.id() || str(stored, "credentialId") != laptopKey.id() || numOr(stored, "counter", -1) != 1 {
		t.Errorf("stored passkey %s", core.MustStringify(stored))
	}
}
