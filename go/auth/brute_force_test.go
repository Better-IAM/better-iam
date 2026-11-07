package auth

// Port of tests/brute-force.test.ts.

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

type bruteFixture struct {
	*fixture
	owner, bob *core.Object
}

func newBruteFixture(t *testing.T, ipAttempts int64, failedSignInAlerts int64) *bruteFixture {
	f := orgFixture(t, func(o *Options) {
		ten, window := int64(10), int64(90_000)
		o.RateLimits = &RateLimitOptions{Attempts: &ten, SensitiveAttempts: &ten, WindowMs: &window, IPAttempts: &ipAttempts}
		o.FailedSignInAlerts = failedSignInAlerts
	})
	b := &bruteFixture{fixture: f}
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		if b.owner, err = f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "root", Email: "owner@example.test", Name: "Owner",
			Password: ownerPassword, HasPassword: true, EmailVerified: true}); err != nil {
			return err
		}
		b.bob, err = f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "root", Email: "bob@example.test", Name: "Bob",
			Password: ownerPassword, HasPassword: true})
		return err
	})
	return b
}

func (f *bruteFixture) attempt(email, password, ip string) (*core.Object, error) {
	ctx := f.ctx
	if ip != "" {
		ctx = f.auth.WithClient(ctx, &core.SessionClientInfo{IP: ip, UserAgent: "curl/8"})
	}
	return f.auth.SignIn(ctx, core.NewObject("tenantId", "root", "email", email, "password", password))
}

func (f *bruteFixture) alerts() []DeliveryMessage {
	var out []DeliveryMessage
	for _, message := range f.messages() {
		if message.Template == "sign-in-failures" {
			out = append(out, message)
		}
	}
	return out
}

func TestPerIPAttemptCapsAcrossAccountsAndFlows(t *testing.T) {
	f := newBruteFixture(t, 3, 0)
	sprayer := "198.51.100.9"
	for _, email := range []string{"owner@example.test", "bob@example.test", "nobody@example.test"} {
		_, err := f.attempt(email, "wrong", sprayer)
		expectCode(t, err, "INVALID_CREDENTIALS")
	}
	_, err := f.attempt("carol@example.test", "wrong", sprayer)
	var limited *RateLimitedError
	if !asError(err, &limited) || limited.Status != 429 || limited.RetryAfterMs != 90_000 {
		t.Fatalf("refusal %v", err)
	}
	_, err = f.auth.RequestPasswordReset(f.auth.WithClient(f.ctx, &core.SessionClientInfo{IP: sprayer}), core.NewObject("tenantId", "root", "email", "owner@example.test"))
	expectCode(t, err, "RATE_LIMITED")
	f.auth.SettleBookkeeping()
	failures := 0
	for _, event := range f.find("audit", core.NewObject("tenantId", "root", "actorId", f.owner.Get("id"))) {
		if str(event, "action") == "auth:signin:fail" {
			failures++
		}
	}
	if failures != 1 {
		t.Fatalf("%d failures for the owner", failures)
	}
	_, err = f.attempt("owner@example.test", "wrong", "203.0.113.7")
	expectCode(t, err, "INVALID_CREDENTIALS")
	_, err = f.attempt("owner@example.test", "wrong", "")
	expectCode(t, err, "INVALID_CREDENTIALS")
	session(t, must[*core.Object](t)(f.attempt("owner@example.test", ownerPassword, "203.0.113.7")))
	must[*core.Object](t)(f.auth.ResetRateLimits(f.ctx, f.owner))
	_, err = f.attempt("owner@example.test", ownerPassword, sprayer)
	expectCode(t, err, "RATE_LIMITED")
	store := newStore(t)
	defer store.Close(context.Background())
	negative := int64(-1)
	_, err = New(Options{Store: store, Secret: testSecret, BaseURL: "http://localhost:3000", RateLimits: &RateLimitOptions{IPAttempts: &negative}})
	if err == nil || !strings.Contains(err.Error(), "ipAttempts") {
		t.Errorf("ipAttempts -1: %v", err)
	}
}

func TestFailedSignInAlertsOncePerStreak(t *testing.T) {
	f := newBruteFixture(t, 0, 2)
	guesser := "198.51.100.9"
	fail := func(email, password string) {
		t.Helper()
		_, err := f.attempt(email, password, guesser)
		expectCode(t, err, "INVALID_CREDENTIALS")
		f.auth.SettleBookkeeping()
		f.dispatch()
	}
	fail("owner@example.test", "wrong")
	if len(f.alerts()) != 0 {
		t.Fatal("alerted early")
	}
	fail("owner@example.test", "wrong again")
	alerts := f.alerts()
	if len(alerts) != 1 || alerts[0].To != "owner@example.test" || alerts[0].Payload["attempts"] != "2" || alerts[0].Payload["ip"] != guesser ||
		alerts[0].Payload["userAgent"] != "curl/8" || !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`).MatchString(alerts[0].Payload["time"]) {
		t.Fatalf("alerts %+v", alerts)
	}
	fail("owner@example.test", "and again")
	if len(f.alerts()) != 1 {
		t.Fatal("alerted twice in one streak")
	}
	signedIn := must[*core.Object](t)(f.attempt("owner@example.test", ownerPassword, "203.0.113.7"))
	if numOr(child(child(signedIn, "session"), "previousSignIn"), "failedAttempts", 0) != 3 {
		t.Error("previousSignIn")
	}
	fail("owner@example.test", "x")
	fail("owner@example.test", "y")
	if len(f.alerts()) != 2 {
		t.Fatal("a new streak did not alert")
	}
	for _, password := range []string{"x", "y", "z"} {
		fail("bob@example.test", password)
	}
	for _, alert := range f.alerts() {
		if alert.To == "bob@example.test" {
			t.Error("an unverified address was alerted")
		}
	}
	store := newStore(t)
	defer store.Close(context.Background())
	if _, err := New(Options{Store: store, Secret: testSecret, BaseURL: "http://localhost:3000", FailedSignInAlerts: 3}); err == nil ||
		!strings.Contains(err.Error(), "failedSignInAlerts requires sendEmail") {
		t.Errorf("without sendEmail: %v", err)
	}
	if _, err := New(Options{Store: store, Secret: testSecret, BaseURL: "http://localhost:3000", FailedSignInAlerts: 5_000,
		SendEmail: func(context.Context, DeliveryMessage) error { return nil }}); err == nil || !strings.Contains(err.Error(), "failedSignInAlerts") {
		t.Errorf("5000: %v", err)
	}
}
