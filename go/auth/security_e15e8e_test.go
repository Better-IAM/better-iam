package auth

// Port of tests/security-e15e8e-auth.test.ts.

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func TestSecurityNoticesNeverQuoteTheUserAgent(t *testing.T) {
	phishing := "Mozilla/5.0 ACTION REQUIRED: your account is locked, restore access at https://evil.example/verify"
	for _, template := range []string{"new-sign-in", "sign-in-failures"} {
		rendered := must[*RenderedMessage](t)(RenderDeliveryMessage(TemplateMessage{Template: template, To: "a@example.test",
			Payload: map[string]string{"userAgent": phishing, "ip": "203.0.113.7", "attempts": "5", "method": "password"}}, TemplateOptions{}))
		for _, part := range []string{rendered.Text, rendered.HTML} {
			if strings.Contains(part, "evil.example") || strings.Contains(part, "ACTION REQUIRED") || !strings.Contains(part, "an unrecognized browser or app · 203.0.113.7") {
				t.Errorf("%s: %s", template, part)
			}
		}
	}
	if got := DescribeUserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Safari/604.1"); got != "Safari on iOS" {
		t.Error(got)
	}
}

func TestSubjectsStayOnOneLine(t *testing.T) {
	rendered := must[*RenderedMessage](t)(RenderDeliveryMessage(TemplateMessage{Template: "team-join-request", To: "maintainer@example.test",
		Payload: map[string]string{"requesterName": "Bob\r\nBcc: victim@example.test", "teamName": "Ops X", "teamId": "t1"}}, TemplateOptions{}))
	if regexp.MustCompile("[\r\n  ]").MatchString(rendered.Subject) {
		t.Errorf("subject %q", rendered.Subject)
	}
}

func TestDisplayNamesLoseControlCharactersAtSignUp(t *testing.T) {
	f := orgFixture(t, func(o *Options) { o.SignUpEnabled = true })
	created := must[*core.Object](t)(f.auth.SignUp(f.ctx, core.NewObject("tenantId", "org", "email", "mallory@acme.test",
		"name", "Mallory\r\nBcc: victim@example.test", "password", "a strong mallory password")))
	if name := str(child(created, "identity"), "name"); name != "Mallory  Bcc: victim@example.test" {
		t.Errorf("name %q", name)
	}
}

func TestOnlyTheNewestPasswordlessCodeStaysValid(t *testing.T) {
	f := orgFixture(t, func(o *Options) { o.PasswordlessEmail = true })
	f.member("alice")
	start := func(kind string) string {
		must[*core.Object](t)(f.auth.StartPasswordless(f.ctx, core.NewObject("tenantId", "org", "destination", "alice@acme.test", "channel", "email", "kind", kind)))
		f.dispatch()
		messages := f.messages()
		return messages[len(messages)-1].Payload["token"]
	}
	first := start("code")
	link := start("magic-link")
	second := start("code")
	finish := func(value string) (*core.Object, error) {
		return f.auth.FinishPasswordless(f.ctx, core.NewObject("tenantId", "org", "destination", "alice@acme.test", "token", value))
	}
	for _, stale := range []string{first, link} {
		if stale != second {
			_, err := finish(stale)
			expectCode(t, err, "INVALID_CHALLENGE")
		}
	}
	session(t, must[*core.Object](t)(finish(second)))
}

func TestFirstEmailedSignInDropsAnUnprovenPassword(t *testing.T) {
	f := orgFixture(t, func(o *Options) { o.PasswordlessEmail, o.SignUpEnabled = true, true })
	must[*core.Object](t)(f.auth.SignUp(f.ctx, core.NewObject("tenantId", "org", "email", "victim@acme.test", "name", "Victim", "password", "attacker chosen password")))
	_, err := f.auth.SignIn(f.ctx, core.NewObject("tenantId", "org", "email", "victim@acme.test", "password", "attacker chosen password"))
	expectCode(t, err, "EMAIL_UNVERIFIED")
	must[*core.Object](t)(f.auth.StartPasswordless(f.ctx, core.NewObject("tenantId", "org", "destination", "victim@acme.test", "channel", "email", "kind", "magic-link")))
	f.dispatch()
	link := f.lastMessage("magic-link").Payload["token"]
	session(t, must[*core.Object](t)(f.auth.FinishPasswordless(f.ctx, core.NewObject("tenantId", "org", "destination", "victim@acme.test", "token", link))))
	_, err = f.auth.SignIn(f.ctx, core.NewObject("tenantId", "org", "email", "victim@acme.test", "password", "attacker chosen password"))
	expectCode(t, err, "INVALID_CREDENTIALS")
	actions := map[string]bool{}
	for _, event := range f.find("audit", core.NewObject("tenantId", "org")) {
		actions[str(event, "action")] = true
	}
	if !actions["auth:password:clear"] {
		t.Error("the cleared password is not audited")
	}
}

func TestFirstEmailedSignInLeavesAdministratorAccountsAlone(t *testing.T) {
	no := false
	f := orgFixture(t, func(o *Options) { o.PasswordlessEmail, o.RequireEmailVerification = true, &no })
	f.member("carol")
	earlier := session(t, f.memberSignIn("carol"))
	must[*core.Object](t)(f.auth.StartPasswordless(f.ctx, core.NewObject("tenantId", "org", "destination", "carol@acme.test", "channel", "email", "kind", "code")))
	f.dispatch()
	code := f.lastMessage("code").Payload["token"]
	must[*core.Object](t)(f.auth.FinishPasswordless(f.ctx, core.NewObject("tenantId", "org", "destination", "carol@acme.test", "token", code)))
	if principal := must[*Principal](t)(f.auth.Authenticate(f.ctx, token(earlier))); str(principal.Identity, "email") != "carol@acme.test" {
		t.Error("earlier session")
	}
	session(t, f.memberSignIn("carol"))
}

func TestMailedLinksAreBoundToTheirAddress(t *testing.T) {
	f := orgFixture(t)
	alice := f.member("alice")
	f.tx(func(ctx context.Context, tx core.IamStore) error { return f.auth.IssuePasswordReset(ctx, tx, alice) })
	f.dispatch()
	reset := f.lastMessage("password-reset").Payload["token"]
	f.update("identities", str(alice, "id"), func(o *core.Object) { o.Set("email", "alice.new@acme.test") })
	_, err := f.auth.ResetPassword(f.ctx, core.NewObject("tenantId", "org", "token", reset, "password", "a brand new alice password"))
	if expectCode(t, err, "INVALID_CHALLENGE").Message != "Email has changed" {
		t.Error("message")
	}
}

func TestPasskeyStartsAnswerAlikeForUnknownAddresses(t *testing.T) {
	f := orgFixture(t, func(o *Options) { o.Passkeys = &PasskeyOptions{RPID: "localhost", RPName: "IAM"} })
	f.member("alice")
	begin := func(email string) *core.Object {
		return must[*core.Object](t)(f.auth.BeginPasskeyAuthentication(f.ctx, core.NewObject("tenantId", "org", "email", email)))
	}
	known, unknown := begin("alice@acme.test"), begin("nobody@acme.test")
	for _, answer := range []*core.Object{known, unknown} {
		if allowed, _ := child(answer, "options").Get("allowCredentials").([]any); len(allowed) != 1 || str(answer, "challengeId") == "" {
			t.Errorf("answer %s", core.MustStringify(answer))
		}
	}
	if core.MustStringify(child(begin("nobody@acme.test"), "options").Get("allowCredentials")) != core.MustStringify(child(unknown, "options").Get("allowCredentials")) {
		t.Error("the decoy is not stable")
	}
}

func TestReauthenticationRefusesAnExpiredPassword(t *testing.T) {
	f := orgFixture(t)
	f.setOrgPolicy(core.NewObject("passwordMaxAgeDays", 30.0))
	f.member("alice")
	f.advance(29 * day)
	first := session(t, f.memberSignIn("alice"))
	renewed := session(t, must[*core.Object](t)(f.auth.Reauthenticate(f.ctx, token(first), core.NewObject("password", "a strong alice password"))))
	f.advance(2 * day)
	_, err := f.auth.Reauthenticate(f.ctx, token(renewed), core.NewObject("password", "wrong password!!"))
	expectCode(t, err, "INVALID_CREDENTIALS")
	_, err = f.auth.Reauthenticate(f.ctx, token(renewed), core.NewObject("password", "a strong alice password"))
	expectCode(t, err, "PASSWORD_EXPIRED")
}
