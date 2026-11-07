package auth

// The outbox delivery rules (tests/events.test.ts covers them through webhooks; tests/auth.test.ts through mail):
// sealed payloads, claims, exponential backoff, abandonment, and the delivered/failed record shapes.

import (
	"context"
	"errors"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func TestOutboxRetriesWithBackoffAndAbandons(t *testing.T) {
	three := int64(3)
	f := orgFixture(t, func(o *Options) {
		o.MaxDeliveryAttempts = &three
		o.DeliverWebhook = func(_ context.Context, _ DeliveryMessage) error { return errors.New("endpoint down") }
	})
	reference := "evt_1"
	var webhookID, emailID string
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		if webhookID, err = f.auth.EnqueueDelivery(ctx, tx, EnqueueInput{TenantID: "org", Kind: "webhook", To: "hook_1", Template: "webhook",
			Payload: core.NewObject("url", "https://hooks.example.test", "body", "{}"), Reference: &reference}); err != nil {
			return err
		}
		emailID, err = f.auth.EnqueueDelivery(ctx, tx, EnqueueInput{TenantID: "org", Kind: "email", To: "a@acme.test", Template: "code",
			Payload: core.NewObject("token", "123456")})
		return err
	})
	queued := f.get("outbox", webhookID)
	if str(queued, "reference") != "evt_1" || numOr(queued, "attempts", -1) != 0 || child(queued, "payload").Len() != 1 || str(child(queued, "payload"), "sealed") == "" {
		t.Fatalf("queued %s", core.MustStringify(queued))
	}
	opened, err := DecryptSecret(str(child(queued, "payload"), "sealed"), []string{testSecret}, "outbox:"+webhookID)
	if err != nil || opened != `{"url":"https://hooks.example.test","body":"{}"}` {
		t.Fatalf("sealed payload %q %v", opened, err)
	}
	if result := f.dispatch(); result != (DispatchResult{Delivered: 1, Failed: 1}) {
		t.Fatalf("first run %+v", result)
	}
	delivered := f.get("outbox", emailID)
	if child(delivered, "payload").Len() != 0 || numOr(delivered, "deliveredAt", 0) != float64(f.now()) || numOr(delivered, "leaseUntil", -1) != 0 || delivered.Has("lastError") {
		t.Errorf("delivered %s", core.MustStringify(delivered))
	}
	if message := f.lastMessage("code"); message.ID != emailID || message.Payload["token"] != "123456" || message.TenantID != "org" {
		t.Errorf("message %+v", message)
	}
	if result := f.dispatch(); result != (DispatchResult{}) {
		t.Fatalf("leased message retried at once: %+v", result)
	}
	failing := f.get("outbox", webhookID)
	if str(failing, "lastError") != "Error: endpoint down" || numOr(failing, "leaseUntil", 0) != float64(f.now()+30_000) || numOr(failing, "attempts", 0) != 1 {
		t.Errorf("after one failure %s", core.MustStringify(failing))
	}
	f.advance(31_000)
	if result := f.dispatch(); result != (DispatchResult{Failed: 1}) {
		t.Fatalf("second run %+v", result)
	}
	if numOr(f.get("outbox", webhookID), "leaseUntil", 0) != float64(f.now()+60_000) {
		t.Error("the backoff does not double")
	}
	f.advance(61_000)
	if result := f.dispatch(); result != (DispatchResult{Failed: 1, Abandoned: 1}) {
		t.Fatalf("third run %+v", result)
	}
	abandoned := f.get("outbox", webhookID)
	if child(abandoned, "payload").Len() != 0 || numOr(abandoned, "failedAt", 0) != float64(f.now()) || numOr(abandoned, "attempts", 0) != 3 ||
		str(abandoned, "lastError") != "Error: endpoint down" || numOr(abandoned, "leaseUntil", -1) != 0 {
		t.Errorf("abandoned %s", core.MustStringify(abandoned))
	}
	f.advance(10 * 60_000)
	if result := f.dispatch(); result != (DispatchResult{}) {
		t.Fatalf("an abandoned message was retried: %+v", result)
	}
	for _, limit := range []int{-1, 1001} {
		_, err := f.auth.DispatchOutbox(f.ctx, limit)
		expectCode(t, err, "INVALID_INPUT")
	}
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := f.auth.EnqueueDelivery(ctx, tx, EnqueueInput{TenantID: "org", Kind: "sms", To: "+15551234567", Template: "code", Payload: core.NewObject()})
		if expectCode(t, err, "FEATURE_DISABLED").Message != "sms delivery is not configured" {
			t.Error("message")
		}
		return nil
	})
}

func TestOutboxErrorNamesAndPayloadValues(t *testing.T) {
	if got := errorText(core.NewIamError("X", "boom")); got != "IamError: boom" {
		t.Error(got)
	}
	if got := errorText(&SafeFetchError{Reason: "url", Message: "nope"}); got != "SafeFetchError: nope" {
		t.Error(got)
	}
	long := errorText(errors.New(string(make([]byte, 300))))
	if core.UTF16Len(long) != 256 {
		t.Errorf("lastError is %d long", core.UTF16Len(long))
	}
	values := payloadStrings(core.NewObject("a", "x", "b", 5.0, "c", true, "d", nil, "e", []any{1.0, "y"}))
	if values["a"] != "x" || values["b"] != "5" || values["c"] != "true" || values["d"] != "null" || values["e"] != "1,y" {
		t.Errorf("payload %v", values)
	}
}
