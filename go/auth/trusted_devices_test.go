package auth

// Port of tests/trusted-devices.test.ts (the authentication service part; the HTTP cookie handling belongs to the
// server port). Tenant policy changes are written to the tenant record as tenants.setAuthPolicy does.

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const day = int64(24 * 60 * 60_000)

type deviceFixture struct {
	*fixture
	secret string
}

func newDeviceFixture(t *testing.T, configure ...func(*Options)) *deviceFixture {
	f := orgFixture(t, append([]func(*Options){func(o *Options) {
		week, idle := 7*day, day
		o.SessionLifetimeMs, o.SessionIdleTimeoutMs = &week, &idle
	}}, configure...)...)
	f.member("alice")
	first := session(t, f.memberSignIn("alice"))
	credential := MfaCredential{Credentials: &core.CredentialInput{Token: first}}
	enrollment := must[*core.Object](t)(f.auth.BeginMfa(f.ctx, credential))
	must[*core.Object](t)(f.auth.ConfirmMfa(f.ctx, ConfirmMfaInput{Credential: credential, Code: f.totp(str(enrollment, "secret"))}))
	return &deviceFixture{fixture: f, secret: str(enrollment, "secret")}
}

func (f *deviceFixture) signInWith(deviceToken string) *core.Object {
	input := core.NewObject("tenantId", "org", "email", "alice@acme.test", "password", "a strong alice password")
	if deviceToken != "" {
		input.Set("deviceToken", deviceToken)
	}
	return must[*core.Object](f.t)(f.auth.SignIn(f.ctx, input))
}

func (f *deviceFixture) verify(challenge string, remember bool) *core.Object {
	f.advance(30_000) // a fresh TOTP step
	return must[*core.Object](f.t)(f.auth.VerifyMfa(f.ctx, core.NewObject("tenantId", "org", "challenge", challenge, "code", f.totp(f.secret), "rememberDevice", remember)))
}

func (f *deviceFixture) setPolicy(policy any) {
	f.update("tenants", "org", func(tenant *core.Object) {
		if policy == nil {
			tenant.Delete("authPolicy")
			return
		}
		tenant.Set("authPolicy", policy)
	})
}

func TestTrustedDevicesSkipMfaWithinThePolicyWindow(t *testing.T) {
	f := newDeviceFixture(t)
	// Root administrators are never remembered.
	root := f.identity("root", true, "root@example.test")
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		device, err := f.auth.RememberDevice(ctx, tx, root)
		if device != nil {
			t.Error("a root administrator was remembered")
		}
		return err
	})
	remembered := f.verify(challengeOf(t, f.signInWith("")), true)
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{32,}$`).MatchString(str(remembered, "deviceToken")) {
		t.Fatalf("device token %q", str(remembered, "deviceToken"))
	}
	if numOr(remembered, "deviceExpiresAt", 0) != float64(f.now()+30*day) {
		t.Error("deviceExpiresAt")
	}
	if child(remembered, "session").Has("trustedDeviceId") || !isTrue(child(remembered, "session"), "mfa") {
		t.Error("the verifying session is first-hand MFA")
	}
	deviceToken := str(remembered, "deviceToken")
	quick := f.signInWith(deviceToken)
	quickToken := session(t, quick)
	if !isTrue(child(quick, "session"), "mfa") || str(child(quick, "session"), "method") != "password" {
		t.Errorf("quick session %s", core.MustStringify(quick))
	}
	devices := must[[]*core.Object](t)(f.auth.ListTrustedDevices(f.ctx, token(quickToken)))
	if len(devices) != 1 || str(child(quick, "session"), "trustedDeviceId") != str(devices[0], "id") || numOr(devices[0], "lastUsedAt", 0) != float64(f.now()) {
		t.Fatalf("devices %s", core.MustStringify(devices))
	}
	if strings.Contains(core.MustStringify(devices), "tokenHash") {
		t.Error("tokenHash exposed")
	}
	if child(quick, "session").Has("mfaAuthenticatedAt") {
		t.Error("a remembered device is not a first-hand factor")
	}
	for _, candidate := range []string{"nonsense", deviceToken + "x", strings.Repeat("a", 40)} {
		challengeOf(t, f.signInWith(candidate))
	}
	f.setPolicy(core.NewObject("trustedDeviceDays", 7.0))
	again := f.verify(challengeOf(t, f.signInWith(strings.Repeat("x", 40))), true)
	if numOr(again, "deviceExpiresAt", 0) != float64(f.now()+7*day) {
		t.Error("the tenant window applies")
	}
	if got := must[[]*core.Object](t)(f.auth.ListTrustedDevices(f.ctx, token(str(again, "token")))); len(got) != 2 {
		t.Fatalf("%d devices", len(got))
	}
	f.setPolicy(core.NewObject("trustedDeviceDays", 0.0))
	challengeOf(t, f.signInWith(deviceToken))
	if disabled := f.verify(challengeOf(t, f.signInWith("")), true); disabled.Has("deviceToken") {
		t.Error("a disabled policy remembered the device")
	}
	f.setPolicy(nil)
	f.advance(8 * day)
	challengeOf(t, f.signInWith(str(again, "deviceToken")))
	still := f.signInWith(deviceToken)
	stillToken := session(t, still)
	if got := must[[]*core.Object](t)(f.auth.ListTrustedDevices(f.ctx, token(stillToken))); len(got) != 1 {
		t.Fatalf("%d live devices", len(got))
	}
	f.advance(6 * 60_000)
	device := must[[]*core.Object](t)(f.auth.ListTrustedDevices(f.ctx, token(stillToken)))[0]
	_, err := f.auth.RevokeTrustedDevice(f.ctx, token(stillToken), core.NewObject("deviceId", device.Get("id")))
	expectCode(t, err, "RECENT_AUTH_REQUIRED")
	fresh := session(t, f.signInWith(deviceToken))
	must[*core.Object](t)(f.auth.RevokeTrustedDevice(f.ctx, token(fresh), core.NewObject("deviceId", device.Get("id"))))
	challengeOf(t, f.signInWith(deviceToken))
	before := f.verify(challengeOf(t, f.signInWith("")), true)
	if !before.Has("deviceToken") {
		t.Fatal("no device token")
	}
	must[*core.Object](t)(f.auth.ChangePassword(f.ctx, token(str(before, "token")), core.NewObject("currentPassword", "a strong alice password", "password", "a brand new alice password!")))
	after := must[*core.Object](t)(f.auth.SignIn(f.ctx, core.NewObject("tenantId", "org", "email", "alice@acme.test", "password", "a brand new alice password!", "deviceToken", before.Get("deviceToken"))))
	challengeOf(t, after)
	actions := map[string]bool{}
	for _, event := range f.find("audit", core.NewObject("tenantId", "org")) {
		actions[str(event, "action")] = true
	}
	if !actions["auth:device:trust"] || !actions["auth:device:revoke"] {
		t.Errorf("trail %v", actions)
	}
}

func TestTrustedDevicesCanBeDisabledForTheDeployment(t *testing.T) {
	zero := int64(0)
	f := newDeviceFixture(t, func(o *Options) { o.TrustedDeviceLifetimeMs = &zero })
	if result := f.verify(challengeOf(t, f.signInWith("")), true); result.Has("deviceToken") {
		t.Error("a disabled deployment remembered the device")
	}
	store := newStore(t)
	defer store.Close(context.Background())
	second := int64(1000)
	_, err := New(Options{Store: store, Secret: "trusted-devices-test-secret-with-32-chars!!", BaseURL: "http://localhost:3000", TrustedDeviceLifetimeMs: &second})
	if err == nil || !strings.Contains(err.Error(), "Trusted device lifetime") {
		t.Errorf("a one-second lifetime: %v", err)
	}
}
