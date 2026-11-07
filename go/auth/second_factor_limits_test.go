package auth

// Port of tests/second-factor-limits.test.ts. The server fixture's administrator unlock (identities.unlock) is the
// auth service's ResetRateLimits underneath, which these tests call directly.

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// orgFixture mirrors tests/support/organization.ts as far as authentication goes: http://localhost:3000, sessions of
// seven days, an email inbox, and people `{name}@acme.test` with the password `a strong {name} password`.
func orgFixture(t *testing.T, configure ...func(*Options)) *fixture {
	week := int64(7 * 86400000)
	return newFixture(t, append([]func(*Options){func(o *Options) {
		o.BaseURL = "http://localhost:3000"
		o.SignUpEnabled = false
		o.PasswordlessEmail, o.PasswordlessSms, o.SendSms = false, false, nil
		o.Passkeys = nil
		o.SessionLifetimeMs, o.SessionIdleTimeoutMs = &week, &week
	}}, configure...)...)
}

func (f *fixture) member(name string) *core.Object {
	f.t.Helper()
	var created *core.Object
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		created, err = f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{
			TenantID: "org", Email: name + "@acme.test", Name: name, Password: "a strong " + name + " password", HasPassword: true,
		})
		return err
	})
	return created
}

func (f *fixture) memberSignIn(name string) *core.Object {
	f.t.Helper()
	result, err := f.auth.SignIn(f.ctx, core.NewObject("tenantId", "org", "email", name+"@acme.test", "password", "a strong "+name+" password"))
	if err != nil {
		f.t.Fatal(err)
	}
	return result
}

// wrongCode is a six-digit code that is not the current one (nor, all but certainly, a neighbouring step's).
func wrongCode(right string) string {
	n, _ := strconv.Atoi(right)
	code := strconv.Itoa((n + 500_000) % 1_000_000)
	for len(code) < 6 {
		code = "0" + code
	}
	return code
}

type enrolledPerson struct {
	id            string
	recoveryCodes []any
	code          func() string
	challenge     func() string
}

func (f *fixture) enrolled(name string) enrolledPerson {
	f.t.Helper()
	identity := f.member(name)
	first := session(f.t, f.memberSignIn(name))
	credential := MfaCredential{Credentials: &core.CredentialInput{Token: first}}
	enrollment := must[*core.Object](f.t)(f.auth.BeginMfa(f.ctx, credential))
	secret := str(enrollment, "secret")
	confirmed := must[*core.Object](f.t)(f.auth.ConfirmMfa(f.ctx, ConfirmMfaInput{Credential: credential, Code: f.totp(secret)}))
	// Past the time step the enrollment used, so the current code is fresh.
	f.advance(31_000)
	return enrolledPerson{
		id:            str(identity, "id"),
		recoveryCodes: confirmed.Get("recoveryCodes").([]any),
		code:          func() string { return f.totp(secret) },
		challenge:     func() string { return challengeOf(f.t, f.memberSignIn(name)) },
	}
}

func TestSecondFactorCodeGuessesAreLimitedPerPerson(t *testing.T) {
	f := orgFixture(t)
	alice := f.enrolled("alice")
	verify := func(challenge, code string) (*core.Object, error) {
		return f.auth.VerifyMfa(f.ctx, core.NewObject("tenantId", "org", "challenge", challenge, "code", code))
	}
	first := alice.challenge()
	for attempt := 0; attempt < 3; attempt++ {
		_, err := verify(first, wrongCode(alice.code()))
		expectCode(t, err, "INVALID_MFA")
	}
	second := alice.challenge()
	for attempt := 0; attempt < 2; attempt++ {
		_, err := verify(second, wrongCode(alice.code()))
		expectCode(t, err, "INVALID_MFA")
	}
	third := alice.challenge()
	_, err := verify(third, wrongCode(alice.code()))
	if expectCode(t, err, "RATE_LIMITED").Status != 429 {
		t.Error("RATE_LIMITED is not 429")
	}
	_, err = verify(third, alice.code())
	expectCode(t, err, "RATE_LIMITED")
	bob := f.enrolled("bob")
	_, err = verify(bob.challenge(), wrongCode(bob.code()))
	expectCode(t, err, "INVALID_MFA")
	unlocked := must[*core.Object](t)(f.auth.ResetRateLimits(f.ctx, f.get("identities", alice.id)))
	if !isTrue(unlocked, "supported") {
		t.Fatal("the store limiter must support resets")
	}
	result := must[*core.Object](t)(verify(third, alice.code()))
	if !isTrue(child(result, "session"), "mfa") {
		t.Error("session is not MFA")
	}
}

func TestRecoveryCodeGuessesAreLimitedPerPerson(t *testing.T) {
	f := orgFixture(t)
	alice := f.enrolled("alice")
	recover := func(challenge, code string) error {
		_, err := f.auth.RecoverMfa(f.ctx, core.NewObject("tenantId", "org", "challenge", challenge, "code", code))
		return err
	}
	first := alice.challenge()
	for attempt := 0; attempt < 3; attempt++ {
		expectCode(t, recover(first, "not-a-recovery-code-"+strconv.Itoa(attempt)), "INVALID_MFA")
	}
	second := alice.challenge()
	for attempt := 0; attempt < 2; attempt++ {
		expectCode(t, recover(second, "still-not-one-"+strconv.Itoa(attempt)), "INVALID_MFA")
	}
	third := alice.challenge()
	expectCode(t, recover(third, alice.recoveryCodes[0].(string)), "RATE_LIMITED")
	// Wrong authenticator codes have their own allowance.
	_, err := f.auth.VerifyMfa(f.ctx, core.NewObject("tenantId", "org", "challenge", third, "code", wrongCode(alice.code())))
	expectCode(t, err, "INVALID_MFA")
}

func TestEmailedMfaCodesAreCappedPerPerson(t *testing.T) {
	f := orgFixture(t, func(o *Options) { o.MfaEmailCodes = true })
	f.update("tenants", "org", func(tenant *core.Object) { tenant.Set("authPolicy", core.NewObject("requireMfa", true)) })
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "org", Email: "carol@acme.test", Name: "Carol",
			Password: "a strong carol password", HasPassword: true, EmailVerified: true})
		return err
	})
	challenge := func() string {
		result := f.memberSignIn("carol")
		if !isTrue(result, "emailCodeAvailable") {
			t.Fatalf("expected an emailed-code challenge: %s", core.MustStringify(result))
		}
		return challengeOf(t, result)
	}
	request := func(token string) error {
		_, err := f.auth.RequestMfaCode(f.ctx, core.NewObject("tenantId", "org", "challenge", token))
		return err
	}
	first := challenge()
	for attempt := 0; attempt < 3; attempt++ {
		if err := request(first); err != nil {
			t.Fatal(err)
		}
	}
	second := challenge()
	for attempt := 0; attempt < 2; attempt++ {
		if err := request(second); err != nil {
			t.Fatal(err)
		}
	}
	expectCode(t, request(challenge()), "RATE_LIMITED")
	f.dispatch()
	count := 0
	for _, message := range f.messages() {
		if message.Template == "mfa-code" && message.To == "carol@acme.test" {
			count++
		}
	}
	if count != 5 {
		t.Fatalf("%d codes delivered", count)
	}
}

func TestPasskeySecondFactorStartsAreLimitedPerPerson(t *testing.T) {
	f := orgFixture(t, func(o *Options) { o.Passkeys = &PasskeyOptions{RPID: "localhost"} })
	alice := f.enrolled("alice")
	begin := func(challenge string) error {
		_, err := f.auth.BeginPasskeyMfa(f.ctx, core.NewObject("tenantId", "org", "challenge", challenge))
		return err
	}
	first := alice.challenge()
	for attempt := 0; attempt < 3; attempt++ {
		expectCode(t, begin(first), "FEATURE_DISABLED")
	}
	second := alice.challenge()
	for attempt := 0; attempt < 2; attempt++ {
		expectCode(t, begin(second), "FEATURE_DISABLED")
	}
	expectCode(t, begin(alice.challenge()), "RATE_LIMITED")
}

func TestWrongPasswordIsAnsweredBeforeTheFailureIsRecorded(t *testing.T) {
	store := newStore(t)
	gate := make(chan struct{})
	service := must[*Service](t)(New(Options{
		Store:   store,
		Secret:  "bookkeeping-test-secret-with-32-characters",
		BaseURL: "http://localhost:3000",
		// Holds the failure record's transaction open until the test lets it finish.
		OnAudit: func(_ context.Context, _ core.IamStore, event *core.Object) error {
			if str(event, "action") == "auth:signin:fail" {
				<-gate
			}
			return nil
		},
	}))
	ctx := context.Background()
	if err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, "tenants", core.NewObject("id", "org", "tenantId", "org", "name", "org", "parentId", nil, "type", "root",
			"status", "active", "createdAt", float64(time.Now().UnixMilli())))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	alice := must[*core.Object](t)(core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return service.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "org", Email: "alice@example.test", Name: "Alice",
			Password: "a strong alice password", HasPassword: true})
	}))
	outcome := make(chan string, 1)
	go func() {
		_, err := service.SignIn(ctx, core.NewObject("tenantId", "org", "email", "alice@example.test", "password", "not the password"))
		if err == nil {
			outcome <- "signed in"
			return
		}
		outcome <- err.(*core.IamError).Code
	}()
	select {
	case result := <-outcome:
		close(gate)
		if result != "INVALID_CREDENTIALS" {
			t.Fatalf("outcome %s", result)
		}
	case <-time.After(2 * time.Second):
		close(gate)
		t.Fatal("the refusal waited for the failure record")
	}
	service.SettleBookkeeping()
	ledger, err := store.Get(ctx, "authSignIns", str(alice, "id"))
	if err != nil || numOr(ledger, "failedAttempts", 0) != 1 {
		t.Fatalf("ledger %s (%v)", core.MustStringify(ledger), err)
	}
	_ = store.Close(ctx)
}

func TestWrongPasswordsForReauthenticateAndChangePasswordAreRecorded(t *testing.T) {
	f := orgFixture(t)
	alice := f.member("alice")
	laptop := f.auth.WithClient(f.ctx, &core.SessionClientInfo{IP: "203.0.113.7", UserAgent: "laptop"})
	result := must[*core.Object](t)(f.auth.SignIn(laptop, core.NewObject("tenantId", "org", "email", "alice@acme.test", "password", "a strong alice password")))
	credential := token(session(t, result))
	guesser := f.auth.WithClient(f.ctx, &core.SessionClientInfo{IP: "198.51.100.9", UserAgent: "curl/8"})
	for _, password := range []string{"guess one", "guess two"} {
		_, err := f.auth.Reauthenticate(guesser, credential, core.NewObject("password", password))
		expectCode(t, err, "INVALID_CREDENTIALS")
	}
	_, err := f.auth.ChangePassword(guesser, credential, core.NewObject("currentPassword", "guess three", "password", "a brand new alice password"))
	expectCode(t, err, "INVALID_CREDENTIALS")
	f.auth.SettleBookkeeping()
	ledger := f.get("authSignIns", str(alice, "id"))
	if numOr(ledger, "failedAttempts", 0) != 3 || core.MustStringify(ledger.Get("lastFailedClient")) != `{"ip":"198.51.100.9","userAgent":"curl/8"}` {
		t.Fatalf("ledger %s", core.MustStringify(ledger))
	}
	failures := 0
	for _, event := range f.find("audit", core.NewObject("tenantId", "org", "actorId", alice.Get("id"))) {
		if str(event, "action") == "auth:signin:fail" {
			failures++
			if metadata := core.MustStringify(event.Get("metadata")); metadata != `{"reason":"password","ip":"198.51.100.9","userAgent":"curl/8"}` {
				t.Errorf("metadata %s", metadata)
			}
		}
	}
	if failures != 3 {
		t.Fatalf("%d failure events", failures)
	}
	again := must[*core.Object](t)(f.auth.Reauthenticate(f.ctx, credential, core.NewObject("password", "a strong alice password")))
	session(t, again)
	if numOr(child(child(again, "session"), "previousSignIn"), "failedAttempts", 0) != 3 {
		t.Errorf("previousSignIn %s", core.MustStringify(child(again, "session")))
	}
}

func TestMemoryRateLimiterIsBounded(t *testing.T) {
	if _, err := CreateMemoryRateLimiter(MemoryRateLimiterOptions{MaxKeys: new(int64)}); err == nil {
		t.Fatal("maxKeys 0 accepted")
	}
	two := int64(2)
	limiter := must[RateLimiter](t)(CreateMemoryRateLimiter(MemoryRateLimiterOptions{MaxKeys: &two}))
	consume := func(key string, now int64, window ...int64) bool {
		windowMs := int64(1_000)
		if len(window) > 0 {
			windowMs = window[0]
		}
		permitted, _ := limiter.Consume(context.Background(), RateLimitInput{Key: key, TenantID: "t", Limit: 1, WindowMs: windowMs, Now: now})
		return permitted
	}
	for index, check := range []struct {
		got, want bool
	}{
		{consume("a", 0), true}, {consume("a", 0), false}, {consume("b", 0, 10_000), true},
		{consume("c", 5_000), true}, {consume("b", 5_000), false},
		{consume("d", 5_000), true}, {consume("c", 5_000), false}, {consume("b", 5_000), true},
	} {
		if check.got != check.want {
			t.Errorf("step %d: %v, expected %v", index, check.got, check.want)
		}
	}
}

func TestMemoryRateLimiterStaysCheapWhenFlooded(t *testing.T) {
	limiter := must[RateLimiter](t)(CreateMemoryRateLimiter(MemoryRateLimiterOptions{}))
	started := time.Now()
	for index := 0; index < 120_000; index++ {
		_, _ = limiter.Consume(context.Background(), RateLimitInput{Key: "k" + strconv.Itoa(index), TenantID: "t", Limit: 5, WindowMs: 60_000, Now: 0})
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("flood took %v", elapsed)
	}
	if permitted, _ := limiter.Consume(context.Background(), RateLimitInput{Key: "k0", TenantID: "t", Limit: 1, WindowMs: 60_000, Now: 0}); !permitted {
		t.Error("the oldest counter was not dropped")
	}
}

func TestStoreRateLimiterSweepsExpiredCounters(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	limiter := CreateStoreRateLimiter(store)
	ctx := context.Background()
	day := int64(24 * 60 * 60_000)
	for index := 0; index < 30; index++ {
		tenant := "org"
		if index%3 == 0 {
			tenant = "ghost-" + strconv.Itoa(index)
		}
		if _, err := limiter.Consume(ctx, RateLimitInput{Key: "key-" + strconv.Itoa(index), TenantID: tenant, Limit: 5, WindowMs: 60_000, Now: 1_000 + int64(index)}); err != nil {
			t.Fatal(err)
		}
	}
	limiter.(*storeRateLimiter).settle()
	if rows, _ := store.Find(ctx, "authRateLimits", nil, nil); len(rows) != 30 {
		t.Fatalf("%d counters", len(rows))
	}
	if permitted, _ := limiter.Consume(ctx, RateLimitInput{Key: "fresh", TenantID: "org", Limit: 5, WindowMs: 60_000, Now: 2 * day}); !permitted {
		t.Fatal("fresh attempt refused")
	}
	limiter.(*storeRateLimiter).settle()
	rows, _ := store.Find(ctx, "authRateLimits", nil, nil)
	if len(rows) != 1 || str(rows[0], "id") != "fresh" {
		t.Fatalf("after the sweep: %s", core.MustStringify(rows))
	}
	for attempt := 1; attempt < 5; attempt++ {
		_, _ = limiter.Consume(ctx, RateLimitInput{Key: "fresh", TenantID: "org", Limit: 5, WindowMs: 60_000, Now: 2 * day})
	}
	if permitted, _ := limiter.Consume(ctx, RateLimitInput{Key: "fresh", TenantID: "org", Limit: 5, WindowMs: 60_000, Now: 2 * day}); permitted {
		t.Fatal("a live counter did not keep counting")
	}
	limiter.(*storeRateLimiter).settle()
}
