package server

// spec/vectors/webhooks.json, and the service-level behavior of tests/events.test.ts (subscription matching, subtree
// scope, chained audit recording, post-commit dispatch, signing, the guarded HTTP transport and its failures). The
// API-level parts of events.test.ts (the webhooks API group) belong to the API port.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

func TestWebhookVectors(t *testing.T) {
	file := spectest.Load(t, "webhooks")
	ran := 0
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			switch {
			case strings.HasPrefix(c.Name, "webhookBody"):
				event, _ := c.Input.Object("event")
				body := WebhookBody(event)
				want, _ := c.Output.(*core.Object)
				if got := core.MustStringify(body); got != jsString(want.Get("json")) {
					t.Fatalf("json:\n got %s\nwant %s", got, jsString(want.Get("json")))
				}
				if !spectest.Equal(body, want.Get("body")) {
					t.Fatalf("body %s", spectest.Show(body))
				}
			case strings.HasPrefix(c.Name, "deliver"):
				k := newKernel(t, nil)
				hookID := jsString(c.Input.Get("hookId"))
				hook := core.NewObject("id", hookID, "tenantId", "tnt_01", "url", "https://hooks.example.com/iam", "active", true,
					"secretSealed", auth.EncryptSecret(jsString(c.Input.Get("webhookSecret")), testSecret, "webhook:"+hookID))
				k.clock.Store(int64(c.Input.Get("now").(float64)))
				message := auth.DeliveryMessage{ID: jsString(c.Input.Get("messageId")), TenantID: "tnt_01", To: hookID,
					Template: jsString(c.Input.Get("event")), Payload: map[string]string{"url": "https://hooks.example.com/iam", "body": jsString(c.Input.Get("body"))}}
				delivery := must(k.server.Events.SignedWebhookDelivery(message, hook))
				got := core.NewObject("id", delivery.ID, "tenantId", delivery.TenantID, "webhookId", delivery.WebhookID, "url", delivery.URL,
					"event", delivery.Event, "body", delivery.Body, "headers", delivery.Headers)
				if core.MustStringify(got) != core.MustStringify(c.Output) {
					t.Fatalf("delivery:\n got %s\nwant %s", core.MustStringify(got), core.MustStringify(c.Output))
				}
				if !VerifyWebhookSignature(VerifyWebhookInput{Secret: jsString(c.Input.Get("webhookSecret")), Timestamp: delivery.Headers.Get("x-better-iam-timestamp"),
					Body: delivery.Body, Signature: jsString(delivery.Headers.Get("x-better-iam-signature")), Now: float(c.Input.Get("now").(float64))}) {
					t.Fatal("the delivery's own signature does not verify")
				}
			case strings.HasPrefix(c.Name, "verify"):
				input := VerifyWebhookInput{Secret: jsString(c.Input.Get("secret")), Timestamp: c.Input.Get("timestamp"),
					Body: jsString(c.Input.Get("body")), Signature: jsString(c.Input.Get("signature"))}
				if now, ok := c.Input.Get("now").(float64); ok {
					input.Now = &now
				}
				if tolerance, ok := c.Input.Get("toleranceSeconds").(float64); ok {
					input.ToleranceSeconds = &tolerance
				}
				spectest.Check(t, c, VerifyWebhookSignature(input))
			default:
				t.Fatalf("unknown case %s", c.Name)
			}
		})
		ran++
	}
	if ran != 16 {
		t.Fatalf("ran %d cases", ran)
	}
}

// eventKernel is a kernel with a tenant tree and webhook subscriptions; webhook deliveries are captured.
type eventKernel struct {
	*kernel
	mu         sync.Mutex
	deliveries []WebhookDelivery
	events     []*core.Object
	fail       error
}

func newEventKernel(t *testing.T, mutate func(options *BetterIamOptions)) *eventKernel {
	k := &eventKernel{}
	k.kernel = newKernel(t, func(options *BetterIamOptions) {
		options.Events = &EventOptions{
			DeliverWebhook: func(ctx context.Context, delivery WebhookDelivery) error {
				k.mu.Lock()
				defer k.mu.Unlock()
				if k.fail != nil {
					return k.fail
				}
				k.deliveries = append(k.deliveries, delivery)
				return nil
			},
			OnEvent: func(ctx context.Context, event *core.Object) error {
				k.mu.Lock()
				defer k.mu.Unlock()
				k.events = append(k.events, event)
				return nil
			},
		}
		if mutate != nil {
			mutate(options)
		}
	})
	k.tenantTree()
	return k
}

func (k *eventKernel) hook(id, tenantID string, members ...any) {
	k.t.Helper()
	secret, sealed := k.server.Events.SealedWebhookSecret(id)
	if !strings.HasPrefix(secret, "whsec_") {
		k.t.Fatal(secret)
	}
	record := core.NewObject("id", id, "tenantId", tenantID, "url", "https://hooks.example.com/"+id, "events", []any{"*"},
		"active", true, "scope", "tenant", "secretSealed", sealed, "createdAt", 1.0, "updatedAt", 1.0, "createdBy", "admin")
	for index := 0; index+1 < len(members); index += 2 {
		record.Set(members[index].(string), members[index+1])
	}
	k.insert("webhooks", record)
}

func (k *eventKernel) audit(principal *Principal, action, tenantID, resourceID, outcome string) {
	k.t.Helper()
	if err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		return k.server.Events.Audit(ctx, tx, principal, action, tenantID, resourceID, outcome, false, nil)
	}); err != nil {
		k.t.Fatal(err)
	}
}

func (k *eventKernel) deliver() []WebhookDelivery {
	k.t.Helper()
	if _, err := k.server.Auth.DispatchOutbox(k.ctx, 100); err != nil {
		k.t.Fatal(err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	delivered := k.deliveries
	k.deliveries = nil
	return delivered
}

func TestWebhookFanOutMatchesSubscriptions(t *testing.T) {
	k := newEventKernel(t, nil)
	admin := principalOf(identity("admin", "org"), session("ses-admin", "admin", "org", "user", "originalIdentityId", "root-admin", "impersonatorId", "support"))
	k.hook("all", "org")
	k.hook("groups", "org", "events", []any{"iam:groups:*"})
	k.hook("denials", "org", "outcomes", []any{"deny"})
	k.hook("engineering", "org", "resources", []any{"grp_eng*"})
	k.hook("subtree", "root", "scope", "subtree")
	k.hook("rootOnly", "root")
	k.hook("paused", "org", "active", false)
	k.audit(admin, "iam:groups:create", "org", "grp_eng", "allow")
	delivered := k.deliver()
	got := map[string]WebhookDelivery{}
	for _, delivery := range delivered {
		got[delivery.WebhookID] = delivery
	}
	for _, id := range []string{"all", "groups", "engineering", "subtree"} {
		if _, ok := got[id]; !ok {
			t.Fatalf("%s did not receive the event (got %v)", id, keys(got))
		}
	}
	if len(got) != 4 {
		t.Fatalf("unexpected receivers %v", keys(got))
	}
	delivery := got["subtree"]
	if delivery.TenantID != "root" || delivery.Event != "iam:groups:create" || delivery.URL != "https://hooks.example.com/subtree" {
		t.Fatalf("%+v", delivery)
	}
	body := must(core.ParseJSONString(delivery.Body)).(*core.Object)
	if body.Get("type") != "iam:groups:create" || body.Get("originalActorId") != "root-admin" || body.Get("impersonatorId") != "support" ||
		member(body.Get("sessionContext"), "sessionId") != "ses-admin" || body.Get("sequence") != 1.0 || !isUndefined(body.Get("previousHash")) {
		t.Fatalf("body %s", delivery.Body)
	}
	// The signature verifies with the subscription's secret.
	record := must(k.store.Get(k.ctx, "webhooks", "subtree"))
	secret := must(auth.DecryptSecret(jsString(record.Get("secretSealed")), []string{testSecret}, "webhook:subtree"))
	now := float64(k.clock.Load())
	if !VerifyWebhookSignature(VerifyWebhookInput{Secret: secret, Timestamp: delivery.Headers.Get("x-better-iam-timestamp"), Body: delivery.Body,
		Signature: jsString(delivery.Headers.Get("x-better-iam-signature")), Now: &now}) {
		t.Fatal("signature does not verify")
	}
	// A denial reaches the outcome-filtered subscription; another tenant's event does not reach tenant hooks.
	k.audit(admin, "iam:roles:delete", "org", "role_1", "deny")
	receivers := map[string]bool{}
	for _, delivery := range k.deliver() {
		receivers[delivery.WebhookID] = true
	}
	if !receivers["denials"] || !receivers["all"] || receivers["groups"] || receivers["engineering"] || !receivers["subtree"] {
		t.Fatalf("receivers %v", receivers)
	}
	k.audit(admin, "iam:roles:delete", "project", "role_2", "allow")
	receivers = map[string]bool{}
	for _, delivery := range k.deliver() {
		receivers[delivery.WebhookID] = true
	}
	if len(receivers) != 1 || !receivers["subtree"] {
		t.Fatalf("project event receivers %v", receivers)
	}
}

func keys[T any](m map[string]T) []string { return sortedKeys(m) }

func TestAuditRecordingChainsAndDispatches(t *testing.T) {
	var subscribed []string
	pluginSeen := 0
	k := newEventKernel(t, func(options *BetterIamOptions) {
		options.Plugins = []*core.IamPlugin{{ID: "audit-plugin", AfterAudit: func(ctx context.Context, event *core.Object) error {
			pluginSeen++
			return nil
		}}}
	})
	unsubscribe := must(k.server.Events.Subscribe([]string{"iam:groups:*", "auth:*"}, func(ctx context.Context, event *core.Object) error {
		subscribed = append(subscribed, jsString(event.Get("action")))
		return nil
	}))
	actor := principalOf(identity("admin", "org"), session("ses-1", "admin", "org", "role", "roleId", "role-1", "trustId", "trust-1",
		"webIdentity", core.NewObject("providerId", "p1", "issuer", "https://idp", "subject", strings.Repeat("s", 300)), "format", "jwt"))
	k.audit(actor, "iam:groups:create", "org", "grp_1", "allow")
	k.audit(actor, "iam:roles:create", "org", "role_2", "allow")
	if err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		return k.server.Events.Audit(ctx, tx, actor, "iam:groups:delete", "org", "grp_1", "deny", true, core.NewObject("reason", "refused"))
	}); err != nil {
		t.Fatal(err)
	}
	events := must(k.store.Find(k.ctx, "audit", core.NewObject("tenantId", "org"), nil))
	if len(events) != 3 {
		t.Fatalf("%d events", len(events))
	}
	verification := core.VerifyAuditChain(sortBySequence(events), core.VerifyAuditChainOptions{})
	if !verification.Valid {
		t.Fatalf("chain %+v", verification)
	}
	first := sortBySequence(events)[0]
	context := first.Get("sessionContext").(*core.Object)
	if core.MustStringify(context) != `{"sessionId":"ses-1","kind":"role","roleId":"role-1","trustId":"trust-1","webIdentityProviderId":"p1","webIdentitySubject":"`+strings.Repeat("s", 256)+`","format":"jwt"}` {
		t.Fatalf("session context %s", core.MustStringify(context))
	}
	if first.Has("originalActorId") || first.Get("rootOverride") != false || first.Get("timestamp") != float64(k.clock.Load()) {
		t.Fatalf("event %s", core.MustStringify(first))
	}
	dispatched := must(k.server.Events.Dispatch(k.ctx))
	if dispatched != 3 || pluginSeen != 3 || len(k.events) != 3 || strings.Join(sortedCopy(subscribed), ",") != "iam:groups:create,iam:groups:delete" {
		t.Fatalf("dispatched %d plugin %d events %d subscribed %v", dispatched, pluginSeen, len(k.events), subscribed)
	}
	hooks := must(k.store.Find(k.ctx, "auditHooks", core.NewObject("delivered", true), nil))
	if len(hooks) != 3 || hooks[0].Get("deliveredAt") != float64(k.clock.Load()) {
		t.Fatalf("hooks %d", len(hooks))
	}
	if again := must(k.server.Events.Dispatch(k.ctx)); again != 0 {
		t.Fatalf("redispatched %d", again)
	}
	unsubscribe()
	k.audit(actor, "iam:groups:update", "org", "grp_1", "allow")
	must(k.server.Events.Dispatch(k.ctx))
	if len(subscribed) != 2 {
		t.Fatal("unsubscribed handler ran")
	}
	if _, err := k.server.Events.Subscribe("", nil); err == nil {
		t.Fatal("empty pattern")
	}
}

func sortBySequence(events []*core.Object) []*core.Object {
	out := append([]*core.Object(nil), events...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && jsNumber(out[j].Get("sequence")) < jsNumber(out[j-1].Get("sequence")); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func TestNoDispatchRowsWithoutListeners(t *testing.T) {
	k := newKernel(t, nil)
	k.tenantTree()
	actor := principalOf(identity("admin", "org"), session("simulation", "admin", "org", "user"))
	if err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		return k.server.Events.Audit(ctx, tx, actor, "iam:groups:create", "org", "g", "allow", false, nil)
	}); err != nil {
		t.Fatal(err)
	}
	if rows := must(k.store.Find(k.ctx, "auditHooks", nil, nil)); len(rows) != 0 {
		t.Fatalf("%d dispatch rows", len(rows))
	}
	events := must(k.store.Find(k.ctx, "audit", nil, nil))
	if events[0].Has("sessionContext") {
		t.Fatal("simulated principals record no session context")
	}
}

func TestWebhookDeliveryDropsRemovedAndPausedSubscriptionsAndRotatesSecrets(t *testing.T) {
	k := newEventKernel(t, func(options *BetterIamOptions) {
		options.PreviousSecrets = []string{"previous-secret-with-at-least-32-characters"}
	})
	message := auth.DeliveryMessage{ID: "m1", TenantID: "org", To: "gone", Template: "iam:groups:create", Payload: map[string]string{"url": "x", "body": "{}"}}
	if err := k.server.Events.DeliverWebhookMessage(k.ctx, message); err != nil {
		t.Fatal(err)
	}
	k.insert("webhooks", core.NewObject("id", "old", "tenantId", "org", "url", "https://hooks.example.com/old", "events", []any{"*"},
		"active", true, "scope", "tenant", "secretSealed", auth.EncryptSecret("whsec_old", "previous-secret-with-at-least-32-characters", "webhook:old")))
	message.To = "old"
	if err := k.server.Events.DeliverWebhookMessage(k.ctx, message); err != nil {
		t.Fatal(err)
	}
	if len(k.deliveries) != 1 || k.deliveries[0].WebhookID != "old" {
		t.Fatalf("%+v", k.deliveries)
	}
	message.Payload = map[string]string{"url": "x"}
	err := k.server.Events.DeliverWebhookMessage(k.ctx, message)
	expectError(t, err, "INVALID_SEALED_VALUE", "Webhook payload is incomplete")
	k.hook("paused", "org", "active", false)
	message.To = "paused"
	message.Payload = map[string]string{"url": "x", "body": "{}"}
	if err := k.server.Events.DeliverWebhookMessage(k.ctx, message); err != nil || len(k.deliveries) != 1 {
		t.Fatalf("paused: %v %d", err, len(k.deliveries))
	}
}

func TestBuiltInWebhookTransport(t *testing.T) {
	var mu sync.Mutex
	var received []*http.Request
	var bodies []string
	status := http.StatusNoContent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, r)
		bodies = append(bodies, string(body))
		code := status
		mu.Unlock()
		switch r.URL.Path {
		case "/slow":
			time.Sleep(1500 * time.Millisecond)
		case "/redirect":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(code)
	}))
	defer server.Close()
	base := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	k := newKernel(t, func(options *BetterIamOptions) { options.Events = &EventOptions{WebhookTimeoutMs: float(1000)} })
	k.tenantTree()
	for _, path := range []string{"ok", "slow", "redirect", "closed"} {
		url := base + "/" + path
		if path == "closed" {
			url = "http://localhost:1/closed"
		}
		_, sealed := k.server.Events.SealedWebhookSecret(path)
		k.insert("webhooks", core.NewObject("id", path, "tenantId", "org", "url", url, "events", []any{"*"}, "active", true,
			"scope", "tenant", "secretSealed", sealed))
	}
	message := func(to string) auth.DeliveryMessage {
		return auth.DeliveryMessage{ID: "m-" + to, TenantID: "org", To: to, Template: "iam:groups:create", Payload: map[string]string{"url": "x", "body": `{"id":"evt"}`}}
	}
	if err := k.server.Events.DeliverWebhookMessage(k.ctx, message("ok")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	request := received[0]
	if request.Method != "POST" || bodies[0] != `{"id":"evt"}` || request.Header.Get("content-type") != "application/json" ||
		request.Header.Get("user-agent") != "better-iam-webhooks/1" || request.Header.Get("x-better-iam-delivery") != "m-ok" ||
		!strings.HasPrefix(request.Header.Get("x-better-iam-signature"), "v1=") {
		t.Fatalf("request %+v", request.Header)
	}
	status = http.StatusInternalServerError
	mu.Unlock()
	err := k.server.Events.DeliverWebhookMessage(k.ctx, message("ok"))
	expectError(t, err, "WEBHOOK_REJECTED", "Webhook endpoint responded with status 500")
	if iamError(t, err).Status != 502 {
		t.Fatal("status 502")
	}
	err = k.server.Events.DeliverWebhookMessage(k.ctx, message("slow"))
	expectError(t, err, "WEBHOOK_UNREACHABLE", "Webhook endpoint did not answer in time")
	err = k.server.Events.DeliverWebhookMessage(k.ctx, message("redirect"))
	expectError(t, err, "WEBHOOK_UNREACHABLE", "Webhook endpoint could not be reached")
	err = k.server.Events.DeliverWebhookMessage(k.ctx, message("closed"))
	expectError(t, err, "WEBHOOK_UNREACHABLE", "Webhook endpoint could not be reached")
}

func TestWebhookURLAndEventValidation(t *testing.T) {
	development := newKernel(t, nil)
	production := newKernel(t, func(options *BetterIamOptions) { options.BaseURL = "https://iam.example.com" })
	privateAllowed := newKernel(t, func(options *BetterIamOptions) {
		options.BaseURL = "https://iam.example.com"
		options.Events = &EventOptions{AllowPrivateNetworks: flag(true)}
	})
	if got := must(production.server.Events.WebhookURL("https://Hooks.Example.com:8443/iam")); got != "https://hooks.example.com:8443/iam" {
		t.Fatal(got)
	}
	if got := must(development.server.Events.WebhookURL("http://localhost:4000/hook")); got != "http://localhost:4000/hook" {
		t.Fatal(got)
	}
	for _, c := range []struct {
		events  *EventService
		url     any
		message string
	}{
		{production.server.Events, "hooks.example.com/iam", "Webhook URL must be absolute"},
		{production.server.Events, "https://user:pass@hooks.example.com/", "Webhook URLs cannot carry credentials or fragments"},
		{production.server.Events, "https://hooks.example.com/#frag", "Webhook URLs cannot carry credentials or fragments"},
		{production.server.Events, "http://hooks.example.com/", "Webhook URLs must use HTTPS"},
		{production.server.Events, "http://localhost:4000/hook", "Webhook URLs must use HTTPS"},
		{production.server.Events, "https://10.0.0.5/hook", "Webhook URLs must point at a public address (see events.allowPrivateNetworks)"},
		{production.server.Events, "https://169.254.169.254/latest", "Webhook URLs must point at a public address (see events.allowPrivateNetworks)"},
		{production.server.Events, 5.0, "Invalid url"},
	} {
		_, err := c.events.WebhookURL(c.url)
		expectError(t, err, "INVALID_INPUT", c.message)
	}
	if _, err := privateAllowed.server.Events.WebhookURL("https://10.0.0.5/hook"); err != nil {
		t.Fatal(err)
	}
	events := production.server.Events
	if got := must(events.WebhookEvents(parse(t, `["iam:groups:*","iam:groups:*","auth:sign-in"]`))); strings.Join(got, ",") != "iam:groups:*,auth:sign-in" {
		t.Fatal(got)
	}
	for _, bad := range []string{`[]`, `["bad pattern"]`, `["` + strings.Repeat("a", 129) + `"]`} {
		_, err := events.WebhookEvents(parse(t, bad))
		expectError(t, err, "INVALID_INPUT", "events must contain 1-50 event name patterns")
	}
	many := make([]any, 51)
	for index := range many {
		many[index] = "e" + core.NumberString(float64(index))
	}
	_, err := events.WebhookEvents(many)
	expectError(t, err, "INVALID_INPUT", "events must contain 1-50 event name patterns")
	if publicHook := PublicWebhook(core.NewObject("id", "h", "secretSealed", "x", "url", "u")); publicHook.Has("secretSealed") {
		t.Fatal("public webhook leaks the secret")
	}
	if !errors.Is(nil, nil) {
		t.Fatal()
	}
}

func sortedCopy(items []string) []string {
	out := append([]string(nil), items...)
	sortStrings(out)
	return out
}
