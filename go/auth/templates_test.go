package auth

// Port of tests/templates.test.ts (testdata/differential.json additionally replays 840 renders recorded from the
// TypeScript renderer).

import (
	"net/url"
	"strings"
	"testing"
)

func testLinks() *TemplateLinks {
	return &TemplateLinks{
		Invitation: func(i InvitationLinkInput) string {
			return "https://app.example/join?kind=" + i.Kind + "&tenant=" + i.TenantID + "&token=" + i.Token
		},
		PasswordReset: func(i TokenLinkInput) string {
			return "https://app.example/reset?tenant=" + i.TenantID + "&token=" + i.Token
		},
		VerifyEmail: func(i TokenLinkInput) string { return "https://app.example/verify?token=" + i.Token },
		EmailChange: func(i TokenLinkInput) string { return "https://app.example/email?token=" + i.Token },
		MagicLink: func(i MagicLinkInput) string {
			return "https://app.example/magic?token=" + i.Token + "&to=" + url.QueryEscape(i.Destination)
		},
	}
}

func render(t *testing.T, message TemplateMessage, options TemplateOptions) *RenderedMessage {
	t.Helper()
	rendered, err := RenderDeliveryMessage(message, options)
	if err != nil || rendered == nil {
		t.Fatalf("%s: %v", message.Template, err)
	}
	return rendered
}

func contains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("%q does not contain %q", haystack, needle)
	}
}

func TestTemplatesRenderEveryBuiltInWithLinksAndEscaping(t *testing.T) {
	app := "Acme Cloud"
	invitation := render(t, TemplateMessage{Template: "member-invitation", To: "alice@example.test", Payload: map[string]string{
		"token": "tok", "tenantId": "t1", "tenantName": "Acme <script>alert(1)</script>", "inviterName": `Owner "O"`,
	}}, TemplateOptions{AppName: &app, Links: testLinks()})
	if invitation.Subject != "Join Acme <script>alert(1)</script> on Acme Cloud" {
		t.Error(invitation.Subject)
	}
	contains(t, invitation.Text, `Owner "O" invited you to join Acme <script>alert(1)</script>.`)
	contains(t, invitation.Text, "Accept invitation: https://app.example/join?kind=member&tenant=t1&token=tok")
	if strings.Contains(invitation.HTML, "<script>") {
		t.Error("unescaped HTML")
	}
	contains(t, invitation.HTML, "&lt;script&gt;")
	contains(t, invitation.HTML, `href="https://app.example/join?kind=member&amp;tenant=t1&amp;token=tok"`)
	owner := render(t, TemplateMessage{Template: "owner-invitation", To: "o@example.test", Payload: map[string]string{"token": "tok", "tenantId": "t1", "tenantName": "Acme"}},
		TemplateOptions{Links: testLinks()})
	if owner.Subject != "Set up Acme on Better IAM" {
		t.Error(owner.Subject)
	}
	contains(t, owner.Text, "kind=owner")
	reset := render(t, TemplateMessage{Template: "password-reset", To: "a@example.test", Payload: map[string]string{"token": "r1", "tenantId": "t1"}},
		TemplateOptions{Links: testLinks()})
	if reset.Subject != "Reset your Better IAM password" {
		t.Error(reset.Subject)
	}
	contains(t, reset.Text, "https://app.example/reset?tenant=t1&token=r1")
	contains(t, reset.HTML, "Choose a new password")
	for template, needle := range map[string]string{
		"verify-email": "https://app.example/verify?token=v1", "email-change": "https://app.example/email?token=v1",
		"magic-link": "https://app.example/magic?token=v1&to=a%40example.test",
	} {
		rendered := render(t, TemplateMessage{Template: template, To: "a@example.test", Payload: map[string]string{"token": "v1", "tenantId": "t1"}},
			TemplateOptions{Links: testLinks()})
		contains(t, rendered.Text, needle)
		contains(t, rendered.HTML, strings.ReplaceAll(needle, "&", "&amp;"))
	}
	code := render(t, TemplateMessage{Template: "code", To: "+15550001", Payload: map[string]string{"token": "123456"}}, TemplateOptions{})
	contains(t, code.Text, "Enter this code to sign in: 123456")
	mfa := render(t, TemplateMessage{Template: "mfa-code", To: "a@example.test", Payload: map[string]string{"code": "654321"}}, TemplateOptions{})
	if mfa.Subject != "Your Better IAM verification code" {
		t.Error(mfa.Subject)
	}
	contains(t, mfa.Text, "654321")
	alert := render(t, TemplateMessage{Template: "new-sign-in", To: "a@example.test", Payload: map[string]string{
		"method": "password", "time": "2026-09-22T00:00:00.000Z",
		"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
		"ip":        "203.0.113.7",
	}}, TemplateOptions{})
	if alert.Subject != "New sign-in to Better IAM" {
		t.Error(alert.Subject)
	}
	contains(t, alert.Text, "Chrome on Windows · 203.0.113.7")
	contains(t, alert.Text, "Method: password.")
	failures := render(t, TemplateMessage{Template: "sign-in-failures", To: "a@example.test", Payload: map[string]string{
		"attempts": "5", "time": "2026-09-22T00:00:00.000Z", "ip": "198.51.100.9",
	}}, TemplateOptions{})
	if failures.Subject != "Failed sign-in attempts on your Better IAM account" {
		t.Error(failures.Subject)
	}
	contains(t, failures.Text, "5 attempts to sign in to your account have failed")
	contains(t, failures.Text, "the latest from 198.51.100.9")
	contains(t, failures.HTML, "Nobody has got in")
	if strings.Contains(failures.HTML, "href=") {
		t.Error("a link without an account builder")
	}
	account := &TemplateLinks{Account: func(i TenantLinkInput) string { return "https://app.example.test/" + i.TenantID + "/account" }}
	linked := render(t, TemplateMessage{Template: "new-sign-in", To: "a@example.test", TenantID: "tenant-1",
		Payload: map[string]string{"method": "password", "time": "2026-09-22T00:00:00.000Z"}}, TemplateOptions{Links: account})
	contains(t, linked.Text, "Review your account: https://app.example.test/tenant-1/account")
	contains(t, linked.HTML, `href="https://app.example.test/tenant-1/account"`)
	linkedFailures := render(t, TemplateMessage{Template: "sign-in-failures", To: "a@example.test", TenantID: "tenant-1",
		Payload: map[string]string{"attempts": "5", "time": "2026-09-22T00:00:00.000Z"}}, TemplateOptions{Links: account})
	contains(t, linkedFailures.HTML, `href="https://app.example.test/tenant-1/account"`)
}

func TestTemplatesFallBackToRawTokensAndIgnoreUnknownTemplates(t *testing.T) {
	reset := render(t, TemplateMessage{Template: "password-reset", To: "a@example.test", Payload: map[string]string{"token": "raw-token"}}, TemplateOptions{})
	contains(t, reset.Text, "Code: raw-token")
	contains(t, reset.HTML, "<code>raw-token</code>")
	if strings.Contains(reset.HTML, "href=") {
		t.Error("a link without builders")
	}
	if rendered, err := RenderDeliveryMessage(TemplateMessage{Template: "not-a-template", To: "a@example.test", Payload: map[string]string{}}, TemplateOptions{}); rendered != nil || err != nil {
		t.Error("an unknown template rendered")
	}
}

func TestTemplatesRenderCertificationReviews(t *testing.T) {
	app := "Acme IAM"
	links := &TemplateLinks{
		Certification: func(i CertificationLinkInput) string {
			return "https://app.example/" + i.TenantID + "/certifications/" + i.CampaignID
		},
		Account: func(i TenantLinkInput) string { return "https://app.example/" + i.TenantID + "/account" },
	}
	review := render(t, TemplateMessage{Template: "certification-review", To: "manager@example.test", TenantID: "tenant-1", Payload: map[string]string{
		"campaignId": "campaign-1", "campaignName": "Q3 <review>", "items": "3", "dueAt": "2026-10-01T00:00:00.000Z",
	}}, TemplateOptions{AppName: &app, Links: links})
	if review.Subject != "Review access: Q3 <review>" {
		t.Error(review.Subject)
	}
	contains(t, review.Text, "review 3 access items in Q3 <review>")
	contains(t, review.Text, "Please decide by 2026-10-01T00:00:00.000Z.")
	contains(t, review.Text, "Review access: https://app.example/tenant-1/certifications/campaign-1")
	contains(t, review.HTML, "Q3 &lt;review&gt;")
	reminder := render(t, TemplateMessage{Template: "certification-reminder", To: "manager@example.test", TenantID: "tenant-1",
		Payload: map[string]string{"campaignId": "campaign-1", "campaignName": "Q3", "pending": "1"}},
		TemplateOptions{Links: &TemplateLinks{Account: links.Account}})
	if reminder.Subject != "Reminder: Q3 is waiting for you" {
		t.Error(reminder.Subject)
	}
	contains(t, reminder.Text, "1 access item still needs your decision in Q3.")
	contains(t, reminder.Text, "Review access: https://app.example/tenant-1/account")
	bare := render(t, TemplateMessage{Template: "certification-review", To: "manager@example.test", Payload: map[string]string{"campaignName": "Q3", "items": "2"}}, TemplateOptions{})
	if strings.Contains(bare.HTML, "href=") {
		t.Error("bare review has a link")
	}
}
