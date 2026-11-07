package auth

// Port of tests/security-activity.test.ts.

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func newActivityFixture(t *testing.T, notifications bool) *insightFixture {
	f := orgFixture(t, func(o *Options) { o.SignInNotifications = notifications })
	var owner *core.Object
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		if _, err := f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "root", Email: "root@example.test", Name: "Root",
			Password: "a strong root test password", HasPassword: true, EmailVerified: true, RootAdmin: true}); err != nil {
			return err
		}
		var err error
		owner, err = f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "root", Email: "owner@example.test", Name: "Owner",
			Password: ownerPassword, HasPassword: true, EmailVerified: true})
		return err
	})
	return &insightFixture{fixture: f, owner: owner}
}

func (f *insightFixture) newSignInAlerts() []DeliveryMessage {
	f.dispatch()
	var out []DeliveryMessage
	for _, message := range f.messages() {
		if message.Template == "new-sign-in" {
			out = append(out, message)
		}
	}
	return out
}

func TestNewSignInAlertsForUnfamiliarClientsAndTheOwnTrail(t *testing.T) {
	f := newActivityFixture(t, true)
	session(t, must[*core.Object](t)(f.signInAs(ownerPassword, nil)))
	if len(f.newSignInAlerts()) != 0 {
		t.Fatal("a session without client details alerted")
	}
	laptop := &core.SessionClientInfo{UserAgent: "Mozilla/5.0 (Macintosh)", IP: "203.0.113.7", Label: "Laptop"}
	first := must[*core.Object](t)(f.signInAs(ownerPassword, laptop))
	alerts := f.newSignInAlerts()
	if len(alerts) != 1 {
		t.Fatalf("%d alerts", len(alerts))
	}
	payload := alerts[0].Payload
	if alerts[0].To != "owner@example.test" || payload["sessionId"] != str(child(first, "session"), "id") || payload["method"] != "password" ||
		payload["userAgent"] != laptop.UserAgent || payload["ip"] != laptop.IP || payload["label"] != "Laptop" {
		t.Fatalf("alert %+v", alerts[0])
	}
	must[*core.Object](t)(f.signInAs(ownerPassword, laptop))
	if len(f.newSignInAlerts()) != 1 {
		t.Fatal("a known client alerted")
	}
	must[*core.Object](t)(f.signInAs(ownerPassword, &core.SessionClientInfo{UserAgent: "Mozilla/5.0 (iPhone)", IP: "198.51.100.2"}))
	if len(f.newSignInAlerts()) != 2 {
		t.Fatal("a new phone did not alert")
	}
	f.update("tenants", "root", func(tenant *core.Object) { tenant.Set("authPolicy", core.NewObject("notifyNewSignIn", false)) })
	must[*core.Object](t)(f.signInAs(ownerPassword, &core.SessionClientInfo{UserAgent: "curl/8", IP: "192.0.2.9"}))
	if len(f.newSignInAlerts()) != 2 {
		t.Fatal("the tenant could not switch alerts off")
	}
	events := must[[]*core.Object](t)(f.auth.ListSecurityEvents(f.ctx, token(str(first, "token")), core.NewObject("limit", 10.0)))
	if len(events) < 5 {
		t.Fatalf("%d events", len(events))
	}
	actions := map[string]bool{}
	for _, event := range events {
		if !strings.HasPrefix(str(event, "action"), "auth:") {
			t.Errorf("non-auth event %s", str(event, "action"))
		}
		actions[str(event, "action")] = true
	}
	if !actions["auth:session:create"] || !actions["auth:identity:create"] {
		t.Errorf("actions %v", actions)
	}
	if numOr(events[0], "timestamp", 0) < numOr(events[len(events)-1], "timestamp", 0) {
		t.Error("not newest first")
	}
	if strings.Contains(core.MustStringify(events), "actorId") {
		t.Error("actorId exposed")
	}
	_, err := f.auth.ListSecurityEvents(f.ctx, token(str(first, "token")), core.NewObject("limit", 0.0))
	expectCode(t, err, "INVALID_INPUT")
	ids := map[string]bool{}
	for _, event := range events {
		ids[str(event, "id")] = true
	}
	for _, event := range f.find("audit", core.NewObject("tenantId", "root")) {
		if str(event, "actorId") != str(f.owner, "id") && ids[str(event, "id")] {
			t.Error("another person's event leaked into the trail")
		}
	}
}

func TestNewSignInAlertsStaySilentWhenOff(t *testing.T) {
	f := newActivityFixture(t, false)
	must[*core.Object](t)(f.signInAs(ownerPassword, &core.SessionClientInfo{UserAgent: "Mozilla/5.0 (Macintosh)", IP: "203.0.113.7"}))
	if len(f.newSignInAlerts()) != 0 {
		t.Fatal("alerted with notifications off")
	}
	f.update("tenants", "root", func(tenant *core.Object) { tenant.Set("authPolicy", core.NewObject("notifyNewSignIn", true)) })
	must[*core.Object](t)(f.signInAs(ownerPassword, &core.SessionClientInfo{UserAgent: "Mozilla/5.0 (Windows)", IP: "203.0.113.8"}))
	if len(f.newSignInAlerts()) != 1 {
		t.Fatal("a tenant could not opt in")
	}
}
