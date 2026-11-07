package auth

// Port of tests/sign-in-insight.test.ts.

import (
	"context"
	"sort"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const ownerPassword = "a strong tenant owner password"

type insightFixture struct {
	*fixture
	owner *core.Object
}

func newInsightFixture(t *testing.T, attempts int64) *insightFixture {
	f := orgFixture(t, func(o *Options) {
		o.SendEmail = nil
		if attempts > 0 {
			o.RateLimits = &RateLimitOptions{Attempts: &attempts}
		}
	})
	var owner *core.Object
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		owner, err = f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "root", Email: "owner@example.test", Name: "Owner",
			Password: ownerPassword, HasPassword: true, EmailVerified: true})
		return err
	})
	return &insightFixture{fixture: f, owner: owner}
}

func (f *insightFixture) signInAs(password string, client *core.SessionClientInfo) (*core.Object, error) {
	return f.auth.SignIn(f.auth.WithClient(f.ctx, client), core.NewObject("tenantId", "root", "email", "owner@example.test", "password", password))
}

func (f *insightFixture) ledger() *core.Object { return f.get("authSignIns", str(f.owner, "id")) }

func (f *insightFixture) failures() []*core.Object {
	var out []*core.Object
	for _, event := range f.find("audit", core.NewObject("tenantId", "root", "actorId", f.owner.Get("id"))) {
		if str(event, "action") == "auth:signin:fail" {
			out = append(out, event)
		}
	}
	sort.Slice(out, func(i, j int) bool { return numOr(out[i], "sequence", 0) < numOr(out[j], "sequence", 0) })
	return out
}

func TestSignInLedgerCountsFailuresAndStampsThePreviousSignIn(t *testing.T) {
	f := newInsightFixture(t, 0)
	laptop := &core.SessionClientInfo{UserAgent: "Mozilla/5.0 (Macintosh)", IP: "203.0.113.7"}
	guesser := &core.SessionClientInfo{UserAgent: "curl/8", IP: "198.51.100.9"}
	_, err := f.signInAs("not the password", guesser)
	expectCode(t, err, "INVALID_CREDENTIALS")
	f.advance(1_000)
	_, err = f.signInAs("still wrong", guesser)
	expectCode(t, err, "INVALID_CREDENTIALS")
	secondFailureAt := float64(f.now())
	f.auth.SettleBookkeeping()
	ledger := f.ledger()
	guesserJSON := `{"ip":"198.51.100.9","userAgent":"curl/8"}`
	if numOr(ledger, "failedAttempts", 0) != 2 || numOr(ledger, "lastFailedAt", 0) != secondFailureAt ||
		core.MustStringify(ledger.Get("lastFailedClient")) != guesserJSON || ledger.Has("lastAt") {
		t.Fatalf("ledger %s", core.MustStringify(ledger))
	}
	if len(f.failures()) != 2 {
		t.Fatal("failure events")
	}
	f.advance(1_000)
	first := must[*core.Object](t)(f.signInAs(ownerPassword, laptop))
	firstSession := child(first, "session")
	if got := core.MustStringify(firstSession.Get("previousSignIn")); got != `{"failedAttempts":2,"lastFailedAt":`+core.NumberString(secondFailureAt)+`,"lastFailedClient":`+guesserJSON+`}` {
		t.Errorf("previousSignIn %s", got)
	}
	expected := core.NewObject("id", f.owner.Get("id"), "tenantId", "root", "identityId", f.owner.Get("id"), "lastAt", firstSession.Get("createdAt"),
		"failedAttempts", 0.0, "lastClient", core.NewObject("ip", "203.0.113.7", "userAgent", "Mozilla/5.0 (Macintosh)"))
	if core.MustStringify(f.ledger()) != core.MustStringify(expected) {
		t.Errorf("ledger %s, expected %s", core.MustStringify(f.ledger()), core.MustStringify(expected))
	}
	f.advance(60_000)
	second := must[*core.Object](t)(f.signInAs(ownerPassword, laptop))
	previous := core.MustStringify(child(second, "session").Get("previousSignIn"))
	if previous != `{"failedAttempts":0,"lastAt":`+core.NumberString(numOr(firstSession, "createdAt", 0))+`,"lastClient":{"ip":"203.0.113.7","userAgent":"Mozilla/5.0 (Macintosh)"}}` {
		t.Errorf("second previousSignIn %s", previous)
	}
	current := must[*core.Object](t)(f.auth.GetSession(f.ctx, token(str(second, "token"))))
	if core.MustStringify(child(current, "session").Get("previousSignIn")) != previous {
		t.Error("getSession previousSignIn")
	}
	events := must[[]*core.Object](t)(f.auth.ListSecurityEvents(f.ctx, token(str(second, "token")), core.NewObject("limit", 20.0)))
	var failed, created []*core.Object
	for _, event := range events {
		switch str(event, "action") {
		case "auth:signin:fail":
			failed = append(failed, event)
		case "auth:session:create":
			created = append(created, event)
		}
	}
	if len(failed) != 2 || core.MustStringify(failed[0].Get("metadata")) != `{"reason":"password","ip":"198.51.100.9","userAgent":"curl/8"}` {
		t.Errorf("failed %s", core.MustStringify(failed))
	}
	if core.MustStringify(created[0].Get("metadata")) != `{"method":"password","ip":"203.0.113.7","userAgent":"Mozilla/5.0 (Macintosh)"}` {
		t.Errorf("created %s", core.MustStringify(created[0]))
	}
	chain := f.find("audit", core.NewObject("tenantId", "root"))
	sort.Slice(chain, func(i, j int) bool { return numOr(chain[i], "sequence", 0) < numOr(chain[j], "sequence", 0) })
	if result := core.VerifyAuditChain(chain, core.VerifyAuditChainOptions{}); !result.Valid || result.Checked != len(chain) {
		t.Errorf("audit chain %+v", result)
	}
}

func TestSignInLedgerIgnoresUnknownAddressesRefusedAttemptsAndDisabledAccounts(t *testing.T) {
	f := newInsightFixture(t, 3)
	_, err := f.auth.SignIn(f.ctx, core.NewObject("tenantId", "root", "email", "nobody@example.test", "password", "whatever"))
	expectCode(t, err, "INVALID_CREDENTIALS")
	f.auth.SettleBookkeeping()
	if len(f.failures()) != 0 || len(f.find("authSignIns", core.NewObject("tenantId", "root"))) != 0 {
		t.Fatal("an unknown address left records")
	}
	for attempt := 0; attempt < 3; attempt++ {
		_, err := f.signInAs("wrong", nil)
		expectCode(t, err, "INVALID_CREDENTIALS")
	}
	_, err = f.signInAs("wrong", nil)
	expectCode(t, err, "RATE_LIMITED")
	f.auth.SettleBookkeeping()
	if len(f.failures()) != 3 || numOr(f.ledger(), "failedAttempts", 0) != 3 || f.ledger().Has("lastFailedClient") {
		t.Fatalf("ledger %s", core.MustStringify(f.ledger()))
	}
	f.update("identities", str(f.owner, "id"), func(o *core.Object) { o.Set("status", "disabled") })
	must[*core.Object](t)(f.auth.ResetRateLimits(f.ctx, f.get("identities", str(f.owner, "id"))))
	_, err = f.signInAs(ownerPassword, nil)
	expectCode(t, err, "INVALID_CREDENTIALS")
	_, err = f.signInAs("wrong", nil)
	expectCode(t, err, "INVALID_CREDENTIALS")
	f.auth.SettleBookkeeping()
	if len(f.failures()) != 3 || numOr(f.ledger(), "failedAttempts", 0) != 3 {
		t.Fatal("a disabled account recorded failures")
	}
}

func TestSignInLedgerCountsWrongSecondFactors(t *testing.T) {
	f := newInsightFixture(t, 0)
	first := must[*core.Object](t)(f.signInAs(ownerPassword, nil))
	credential := MfaCredential{Credentials: &core.CredentialInput{Token: str(first, "token")}}
	enrollment := must[*core.Object](t)(f.auth.BeginMfa(f.ctx, credential))
	enrolled := must[*core.Object](t)(f.auth.ConfirmMfa(f.ctx, ConfirmMfaInput{Credential: credential, Code: f.totp(str(enrollment, "secret"))}))
	previous := child(child(enrolled, "session"), "previousSignIn")
	if numOr(previous, "failedAttempts", -1) != 0 || !core.StrictEquals(previous.Get("lastAt"), child(first, "session").Get("createdAt")) {
		t.Errorf("enrolled previousSignIn %s", core.MustStringify(previous))
	}
	f.advance(31_000)
	challenge := challengeOf(t, must[*core.Object](t)(f.signInAs(ownerPassword, &core.SessionClientInfo{IP: "198.51.100.9"})))
	right := f.totp(str(enrollment, "secret"))
	wrong := wrongCode(right)
	_, err := f.auth.VerifyMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", challenge, "code", wrong))
	expectCode(t, err, "INVALID_MFA")
	_, err = f.auth.RecoverMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", challenge, "code", "not-a-recovery-code"))
	expectCode(t, err, "INVALID_MFA")
	f.auth.SettleBookkeeping()
	failures := f.failures()
	if len(failures) != 2 || str(child(failures[0], "metadata"), "reason") != "mfa" || str(child(failures[1], "metadata"), "reason") != "recovery-code" {
		t.Fatalf("failures %s", core.MustStringify(failures))
	}
	_, err = f.auth.VerifyMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "code", right))
	expectCode(t, err, "INVALID_CHALLENGE")
	f.auth.SettleBookkeeping()
	if len(f.failures()) != 2 {
		t.Fatal("an invalid challenge counted")
	}
	result := must[*core.Object](t)(f.auth.VerifyMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", challenge, "code", right)))
	previous = child(child(result, "session"), "previousSignIn")
	if numOr(previous, "failedAttempts", 0) != 2 || !core.StrictEquals(previous.Get("lastAt"), child(enrolled, "session").Get("createdAt")) ||
		numOr(previous, "lastFailedAt", 0) != float64(f.now()) {
		t.Errorf("previousSignIn %s", core.MustStringify(previous))
	}
	if ledger := f.ledger(); numOr(ledger, "failedAttempts", -1) != 0 || !core.StrictEquals(ledger.Get("lastAt"), child(result, "session").Get("createdAt")) {
		t.Errorf("ledger %s", core.MustStringify(ledger))
	}
}
