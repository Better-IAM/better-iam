package server

// Webhook subscriptions and the audit API, after tests/events.test.ts, tests/bulk-and-redelivery.test.ts, and
// tests/audit-chain.test.ts. Audit events are produced with the domains API (identities and groups are ported
// separately).

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

type webhookFixture struct {
	*directoryFixture
	tenantID   string
	owner      core.CredentialInput
	mu         sync.Mutex
	deliveries []WebhookDelivery
	reject     bool
}

func newWebhookFixture(t *testing.T) *webhookFixture {
	t.Helper()
	w := &webhookFixture{}
	w.directoryFixture = newDirectoryFixture(t, func(options *BetterIamOptions) {
		attempts := int64(3)
		options.Authentication.MaxDeliveryAttempts = &attempts
		options.Events = &EventOptions{DeliverWebhook: func(ctx context.Context, delivery WebhookDelivery) error {
			w.mu.Lock()
			defer w.mu.Unlock()
			if w.reject {
				return errors.New("endpoint down")
			}
			w.deliveries = append(w.deliveries, delivery)
			return nil
		}}
	})
	w.tenantID, w.owner = w.organization("Acme", "owner@acme.test")
	return w
}

func (w *webhookFixture) setReject(reject bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reject = reject
}

func (w *webhookFixture) last() WebhookDelivery {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.deliveries[len(w.deliveries)-1]
}

func (w *webhookFixture) dispatch() string {
	w.t.Helper()
	result, err := w.iam.Auth.DispatchOutbox(w.ctx, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	return stringify(must(ToModel(result)))
}

// claim adds a domain to Acme: an audited iam:domains:create event.
func (w *webhookFixture) claim(domain string) {
	w.t.Helper()
	answer(w.iam.API.Domains.Add(w.ctx, w.owner, Input[apitypes.DomainsAddInput](body("tenantId", w.tenantID, "domain", domain))))
}

func (w *webhookFixture) create(credential core.CredentialInput, pairs ...any) (Out[apitypes.WebhooksCreateOutput], error) {
	return w.iam.API.Webhooks.Create(w.ctx, credential, Input[apitypes.WebhooksCreateInput](body(append([]any{"tenantId", w.tenantID}, pairs...)...)))
}

func (w *webhookFixture) hookInput(webhookID any, pairs ...any) *core.Object {
	return body(append([]any{"tenantId", w.tenantID, "webhookId", webhookID}, pairs...)...)
}

func (w *webhookFixture) signed(delivery WebhookDelivery, secret string) bool {
	now := w.now()
	return VerifyWebhookSignature(VerifyWebhookInput{Secret: secret, Timestamp: delivery.Headers.Get("x-better-iam-timestamp"),
		Body: delivery.Body, Signature: jsString(delivery.Headers.Get("x-better-iam-signature")), Now: &now})
}

func TestWebhooksDeliverSignedEventsAndExposeHistory(t *testing.T) {
	w := newWebhookFixture(t)
	webhooks := w.iam.API.Webhooks
	for _, refused := range []struct {
		input   []any
		code    string
		message string
	}{
		{[]any{"url", "http://hooks.example.test/iam", "events", items("*")}, "INVALID_INPUT", "Webhook URLs must use HTTPS"},
		{[]any{"url", "https://user:pw@hooks.example.test/iam", "events", items("*")}, "INVALID_INPUT", "Webhook URLs cannot carry credentials or fragments"},
		{[]any{"url", "https://hooks.example.test/iam", "events", items("bad pattern")}, "INVALID_INPUT", "events must contain 1-50 event name patterns"},
		{[]any{"url", "https://hooks.example.test/iam", "events", items("*"), "scope", "subtree"}, "ACCESS_DENIED", "Subtree subscriptions are platform controlled"},
		{[]any{"url", "https://hooks.example.test/iam", "events", items("*"), "scope", "world"}, "INVALID_INPUT", "scope must be tenant or subtree"},
		{[]any{"url", "https://hooks.example.test/iam", "events", items("*"), "outcomes", items("maybe")}, "INVALID_INPUT", "outcomes must list allow, deny, or both"},
		{[]any{"url", "https://hooks.example.test/iam", "events", items("*"), "outcomes", items()}, "INVALID_INPUT", "outcomes must list allow, deny, or both"},
		{[]any{"url", "https://hooks.example.test/iam", "events", items("*"), "resources", items(strings.Repeat("a", 257))}, "INVALID_INPUT", "Invalid resources"},
		{[]any{"url", "https://hooks.example.test/iam", "events", items("*"), "description", ""}, "INVALID_INPUT", "Invalid description"},
	} {
		_, err := w.create(w.owner, refused.input...)
		expectError(t, err, refused.code, refused.message)
	}
	created := answerObject(w.create(w.owner, "url", "https://hooks.example.test/iam", "events", items("iam:domains:*", "iam:domains:*"),
		"description", "SIEM", "outcomes", items("allow", "allow"), "resources", items("domains/*")))
	secret := jsString(created.Get("secret"))
	webhook := created.Get("webhook").(*core.Object)
	webhookID := jsString(webhook.Get("id"))
	if !strings.HasPrefix(secret, "whsec_") || webhook.Has("secretSealed") || webhook.Get("active") != true || webhook.Get("scope") != "tenant" ||
		stringify(webhook.Get("events")) != `["iam:domains:*"]` || stringify(webhook.Get("outcomes")) != `["allow"]` ||
		stringify(webhook.Keys()) != `["id","tenantId","url","events","active","scope","createdAt","updatedAt","createdBy","description","outcomes","resources"]` {
		t.Fatalf("created = %s", stringify(created))
	}
	listed := answerList(webhooks.List(w.ctx, w.owner, Input[apitypes.WebhooksListInput](body("tenantId", w.tenantID))))
	if got := pluck(listed, "id"); len(got) != 1 || got[0] != webhookID || listed[0].Has("secretSealed") {
		t.Fatalf("list = %s", stringify(listed))
	}
	if stored := w.record("webhooks", webhookID); !stored.Has("secretSealed") || strings.Contains(stringify(stored), secret) {
		t.Fatal("the stored subscription carries the plain secret or no sealed one")
	}

	w.claim("acme.example")
	if got := w.dispatch(); got != `{"delivered":1,"failed":0,"abandoned":0}` {
		t.Fatalf("dispatch = %s", got)
	}
	first := w.last()
	if first.Event != "iam:domains:create" || first.WebhookID != webhookID || first.URL != "https://hooks.example.test/iam" || first.TenantID != w.tenantID {
		t.Fatalf("first delivery = %+v", first)
	}
	sent := must(core.ParseJSONString(first.Body)).(*core.Object)
	if sent.Get("type") != "iam:domains:create" || sent.Get("resourceId") != "domains/acme.example" || sent.Get("outcome") != "allow" {
		t.Fatalf("body = %s", first.Body)
	}
	if !w.signed(first, secret) || w.signed(first, "whsec_wrong") {
		t.Fatal("signature check")
	}

	// Failures back off, retry, and are abandoned after the configured attempts; history never carries payloads.
	w.setReject(true)
	w.advance(1000)
	w.claim("second.example")
	if got := w.dispatch(); got != `{"delivered":0,"failed":1,"abandoned":0}` {
		t.Fatalf("first failure = %s", got)
	}
	w.advance(31_000)
	if got := w.dispatch(); got != `{"delivered":0,"failed":1,"abandoned":0}` {
		t.Fatalf("second failure = %s", got)
	}
	w.advance(61_000)
	if got := w.dispatch(); got != `{"delivered":0,"failed":1,"abandoned":1}` {
		t.Fatalf("abandoned = %s", got)
	}
	history := answerList(webhooks.ListDeliveries(w.ctx, w.owner, Input[apitypes.WebhooksListDeliveriesInput](w.hookInput(webhookID))))
	if len(history) != 2 || history[0].Get("status") != "failed" || history[1].Get("status") != "delivered" ||
		history[0].Get("attempts") != 3.0 || history[1].Get("attempts") != 1.0 {
		t.Fatalf("history = %s", stringify(history))
	}
	failed := history[0]
	if !strings.Contains(jsString(failed.Get("lastError")), "endpoint down") || failed.Has("payload") || failed.Get("event") != "iam:domains:create" {
		t.Fatalf("failed delivery = %s", stringify(failed))
	}
	if _, ok := failed.Get("failedAt").(float64); !ok {
		t.Fatalf("failedAt = %v", failed.Get("failedAt"))
	}
	if _, ok := failed.Get("eventId").(string); !ok {
		t.Fatalf("eventId = %v", failed.Get("eventId"))
	}
	if stringify(obj(t, stringify(failed)).Keys()) != `["id","event","eventId","createdAt","attempts","failedAt","lastError","status"]` {
		t.Fatalf("history members %v", failed.Keys())
	}
	if newest := answerList(webhooks.ListDeliveries(w.ctx, w.owner, Input[apitypes.WebhooksListDeliveriesInput](w.hookInput(webhookID, "limit", 1.0)))); len(newest) != 1 || newest[0].Get("id") != failed.Get("id") {
		t.Fatalf("limited history = %s", stringify(newest))
	}

	// Redelivery rebuilds the event from its audit record.
	w.setReject(false)
	redeliver := func(deliveryID any) (Out[apitypes.WebhooksRedeliverOutput], error) {
		return webhooks.Redeliver(w.ctx, w.owner, Input[apitypes.WebhooksRedeliverInput](w.hookInput(webhookID, "deliveryId", deliveryID)))
	}
	queued := answerObject(redeliver(failed.Get("id")))
	if queued.Get("eventId") != failed.Get("eventId") {
		t.Fatalf("redeliver = %s", stringify(queued))
	}
	if got := w.dispatch(); got != `{"delivered":1,"failed":0,"abandoned":0}` {
		t.Fatalf("redelivery = %s", got)
	}
	replayed := w.last()
	replayedBody := must(core.ParseJSONString(replayed.Body)).(*core.Object)
	if replayed.ID != queued.Get("deliveryId") || replayedBody.Get("id") != failed.Get("eventId") || replayedBody.Get("type") != "iam:domains:create" ||
		replayedBody.Get("resourceId") != "domains/second.example" {
		t.Fatalf("replayed = %+v", replayed)
	}
	_, err := redeliver("out_missing")
	expectError(t, err, "NOT_FOUND", "Delivery not found")

	// Rotation signs later deliveries with the new secret; ping verifies an endpoint and cannot be rebuilt.
	rotated := answerObject(webhooks.RotateSecret(w.ctx, w.owner, Input[apitypes.WebhooksRotateSecretInput](w.hookInput(webhookID))))
	if rotated.Get("secret") == secret || member(rotated.Get("webhook"), "secretSealed") != core.Undefined {
		t.Fatalf("rotated = %s", stringify(rotated))
	}
	ping := answerObject(webhooks.Ping(w.ctx, w.owner, Input[apitypes.WebhooksPingInput](w.hookInput(webhookID))))
	w.dispatch()
	pinged := w.last()
	if pinged.Event != "webhook:ping" || pinged.ID != ping.Get("deliveryId") || !w.signed(pinged, jsString(rotated.Get("secret"))) || w.signed(pinged, secret) {
		t.Fatalf("ping delivery = %+v", pinged)
	}
	pingBody := must(core.ParseJSONString(pinged.Body)).(*core.Object)
	if stringify(pingBody.Keys()) != `["id","type","tenantId","actorId","resourceId","outcome","timestamp"]` || pingBody.Get("resourceId") != webhookID {
		t.Fatalf("ping body = %s", pinged.Body)
	}
	_, err = redeliver(ping.Get("deliveryId"))
	expectError(t, err, "INVALID_TRANSITION", "This delivery cannot be rebuilt")

	// Updates: nothing to change, type checks, clearing members, pausing.
	update := func(pairs ...any) (Out[apitypes.WebhooksUpdateOutput], error) {
		return webhooks.Update(w.ctx, w.owner, Input[apitypes.WebhooksUpdateInput](w.hookInput(webhookID, pairs...)))
	}
	_, err = update()
	expectError(t, err, "INVALID_INPUT", "Nothing to update")
	_, err = update("active", "no")
	expectError(t, err, "INVALID_INPUT", "active must be boolean")
	paused := answerObject(update("active", false, "events", items("*"), "description", nil, "outcomes", nil, "resources", nil))
	if paused.Get("active") != false || paused.Has("description") || paused.Has("outcomes") || paused.Has("resources") ||
		stringify(paused.Get("events")) != `["*"]` {
		t.Fatalf("paused = %s", stringify(paused))
	}
	_, err = webhooks.Ping(w.ctx, w.owner, Input[apitypes.WebhooksPingInput](w.hookInput(webhookID)))
	expectError(t, err, "INVALID_TRANSITION", "Webhook is paused")
	_, err = redeliver(failed.Get("id"))
	expectError(t, err, "INVALID_TRANSITION", "Webhook is paused")
	w.claim("paused.example")
	if got := w.dispatch(); got != `{"delivered":0,"failed":0,"abandoned":0}` {
		t.Fatalf("paused dispatch = %s", got)
	}
	answer(update("active", true))

	// A member without iam:webhooks:* is refused; another tenant's subscription is not found.
	_, memberCredential := w.person(w.tenantID, "member")
	_, err = webhooks.Get(w.ctx, memberCredential, Input[apitypes.WebhooksGetInput](w.hookInput(webhookID)))
	expectCode(t, err, "ACCESS_DENIED")
	other, otherOwner := w.organization("Other", "owner@other.test")
	_, err = webhooks.Get(w.ctx, otherOwner, Input[apitypes.WebhooksGetInput](body("tenantId", other, "webhookId", webhookID)))
	expectError(t, err, "NOT_FOUND", "Resource not found")
	if got := answerObject(webhooks.Get(w.ctx, w.owner, Input[apitypes.WebhooksGetInput](w.hookInput(webhookID)))); got.Has("secretSealed") || got.Get("id") != webhookID {
		t.Fatalf("get = %s", stringify(got))
	}

	// Deleting the subscription clears its queue.
	w.claim("queued.example")
	if result := answerObject(webhooks.Delete(w.ctx, w.owner, Input[apitypes.WebhooksDeleteInput](w.hookInput(webhookID)))); stringify(result) != `{"deleted":true}` {
		t.Fatalf("delete = %s", stringify(result))
	}
	remaining := w.find("outbox", body("tenantId", w.tenantID, "kind", "webhook", "to", webhookID))
	if len(remaining) == 0 {
		t.Fatal("delivery history was removed")
	}
	for _, message := range remaining {
		if !truthy(message.Get("deliveredAt")) && !truthy(message.Get("failedAt")) {
			t.Fatalf("a pending delivery survived: %s", stringify(message))
		}
	}
	if got := w.dispatch(); got != `{"delivered":0,"failed":0,"abandoned":0}` {
		t.Fatalf("after delete = %s", got)
	}
}

func TestWebhooksSubtreeSubscriptionsAndLimits(t *testing.T) {
	w := newWebhookFixture(t)
	webhooks := w.iam.API.Webhooks
	// Root subscribes a platform endpoint to the organization's subtree; the organization cannot touch it.
	platform := answerObject(w.create(w.rootCred, "url", "https://siem.example.test/all", "events", items("*"), "scope", "subtree"))
	hook := platform.Get("webhook").(*core.Object)
	if hook.Get("scope") != "subtree" {
		t.Fatalf("platform = %s", stringify(platform))
	}
	for name, call := range map[string]func() error{
		"update": func() error {
			_, err := webhooks.Update(w.ctx, w.owner, Input[apitypes.WebhooksUpdateInput](w.hookInput(hook.Get("id"), "active", false)))
			return err
		},
		"rotateSecret": func() error {
			_, err := webhooks.RotateSecret(w.ctx, w.owner, Input[apitypes.WebhooksRotateSecretInput](w.hookInput(hook.Get("id"))))
			return err
		},
		"ping": func() error {
			_, err := webhooks.Ping(w.ctx, w.owner, Input[apitypes.WebhooksPingInput](w.hookInput(hook.Get("id"))))
			return err
		},
		"delete": func() error {
			_, err := webhooks.Delete(w.ctx, w.owner, Input[apitypes.WebhooksDeleteInput](w.hookInput(hook.Get("id"))))
			return err
		},
	} {
		if err := call(); err == nil || iamError(t, err).Message != "Subtree subscriptions are platform controlled" {
			t.Fatalf("%s by the organization: %v", name, err)
		}
	}
	// Reading it stays an ordinary read.
	answer(webhooks.Get(w.ctx, w.owner, Input[apitypes.WebhooksGetInput](w.hookInput(hook.Get("id")))))
	answer(webhooks.Update(w.ctx, w.rootCred, Input[apitypes.WebhooksUpdateInput](w.hookInput(hook.Get("id"), "url", "https://siem.example.test/v2"))))

	// The tenant's plan limit applies.
	w.patch("tenants", w.tenantID, body("limits", body("webhooks", 1.0)))
	_, err := w.create(w.owner, "url", "https://hooks.example.test/iam", "events", items("*"))
	expectError(t, err, "LIMIT_EXCEEDED", "This tenant has reached its webhook limit (1)")
}

func TestAuditChainVerifyExportAndList(t *testing.T) {
	w := newWebhookFixture(t)
	audit := w.iam.API.Audit
	w.claim("one.example")
	w.claim("two.example")
	w.claim("three.example")
	_, memberCredential := w.person(w.tenantID, "member")
	_, err := w.iam.API.Domains.List(w.ctx, memberCredential, Input[apitypes.DomainsListInput](body("tenantId", w.tenantID)))
	expectCode(t, err, "ACCESS_DENIED")
	events := w.find("audit", body("tenantId", w.tenantID))
	events = sortBySequence(events)
	if len(events) < 5 {
		t.Fatalf("audit events = %d", len(events))
	}
	for index, event := range events {
		if event.Get("sequence") != float64(index+1) {
			t.Fatalf("sequence %d = %v", index, event.Get("sequence"))
		}
		previous := any(core.AuditGenesis)
		if index > 0 {
			previous = events[index-1].Get("hash")
		}
		if event.Get("previousHash") != previous {
			t.Fatalf("event %d is not linked", index+1)
		}
	}
	count := float64(len(events))
	lastHash := events[len(events)-1].Get("hash")
	tenant := func(pairs ...any) *core.Object { return body(append([]any{"tenantId", w.tenantID}, pairs...)...) }
	verified := answerObject(audit.Verify(w.ctx, w.owner, Input[apitypes.AuditVerifyInput](tenant())))
	if verified.Get("valid") != true || verified.Get("checked") != count || verified.Get("unchained") != 0.0 || verified.Get("first") != 1.0 ||
		verified.Get("last") != count || verified.Get("lastHash") != lastHash || member(verified.Get("head"), "sequence") != count ||
		member(verified.Get("head"), "hash") != lastHash {
		t.Fatalf("verify = %s", stringify(verified))
	}
	if stringify(verified.Keys()) != `["valid","checked","unchained","first","last","lastHash","head"]` {
		t.Fatalf("verify members %v", verified.Keys())
	}
	window := answerObject(audit.Verify(w.ctx, w.owner, Input[apitypes.AuditVerifyInput](tenant("fromSequence", 3.0, "toSequence", 5.0))))
	if window.Get("valid") != true || window.Get("checked") != 3.0 || window.Get("first") != 3.0 || window.Get("last") != 5.0 {
		t.Fatalf("window = %s", stringify(window))
	}
	_, err = audit.Verify(w.ctx, w.owner, Input[apitypes.AuditVerifyInput](tenant("fromSequence", 0.0)))
	expectError(t, err, "INVALID_INPUT", "Invalid fromSequence")

	exported := answerObject(audit.Export(w.ctx, w.owner, Input[apitypes.AuditExportInput](tenant("limit", 4.0))))
	if exported.Get("format") != "jsonl" || exported.Get("count") != 4.0 || exported.Get("firstSequence") != 1.0 || exported.Get("lastSequence") != 4.0 ||
		exported.Get("nextSequence") != 5.0 {
		t.Fatalf("export = %s", stringify(exported))
	}
	lines := parseLines(t, jsString(exported.Get("body")))
	if got := pluck(lines, "sequence"); stringify(got) != `["1","2","3","4"]` {
		t.Fatalf("exported sequences = %v", got)
	}
	if result := core.VerifyAuditChain(lines, core.VerifyAuditChainOptions{}); !result.Valid || result.Checked != 4 {
		t.Fatalf("offline verification = %+v", result)
	}
	rest := answerObject(audit.Export(w.ctx, w.owner, Input[apitypes.AuditExportInput](tenant("fromSequence", exported.Get("nextSequence")))))
	if rest.Has("nextSequence") && rest.Get("nextSequence") != core.Undefined {
		t.Fatalf("rest has a next page: %s", stringify(rest))
	}
	if strings.Contains(stringify(rest), `"nextSequence"`) {
		t.Fatalf("nextSequence serialized: %s", stringify(rest))
	}
	restLines := parseLines(t, jsString(rest.Get("body")))
	// The verify and export reads above were audited too, so the second page is longer than the snapshot.
	if len(restLines) <= len(events)-4 {
		t.Fatalf("rest lines = %d", len(restLines))
	}
	linked := jsString(lines[3].Get("hash"))
	if result := core.VerifyAuditChain(restLines, core.VerifyAuditChainOptions{PreviousHash: &linked}); !result.Valid || *result.First != 5 {
		t.Fatalf("second page = %+v", result)
	}

	// Tampering with a stored event is detected; so is a rewritten head.
	target := events[2]
	tampered := target.Spread(body("outcome", map[bool]string{true: "allow", false: "deny"}[target.Get("outcome") == "deny"]))
	w.seed("audit", tampered)
	broken := answerObject(audit.Verify(w.ctx, w.owner, Input[apitypes.AuditVerifyInput](tenant())))
	if broken.Get("valid") != false || stringify(broken.Get("failure")) != `{"sequence":3,"id":"`+jsString(target.Get("id"))+`","reason":"hash-mismatch"}` {
		t.Fatalf("tampered = %s", stringify(broken))
	}
	w.seed("audit", target)
	head := w.record("auditChains", w.tenantID)
	w.seed("auditChains", head.Spread(body("hash", strings.Repeat("a", 64))))
	broken = answerObject(audit.Verify(w.ctx, w.owner, Input[apitypes.AuditVerifyInput](tenant())))
	if broken.Get("valid") != false || member(broken.Get("failure"), "reason") != "head-mismatch" {
		t.Fatalf("rewritten head = %s", stringify(broken))
	}
	// A window is verified against its own links, not the head.
	if window := answerObject(audit.Verify(w.ctx, w.owner, Input[apitypes.AuditVerifyInput](tenant("toSequence", 4.0)))); window.Get("valid") != true {
		t.Fatalf("window with a rewritten head = %s", stringify(window))
	}
	w.seed("auditChains", head)

	// Searching: newest first, exact and glob actions, outcomes, actors, time ranges, paging.
	list := func(pairs ...any) []*core.Object {
		t.Helper()
		return answerList(audit.List(w.ctx, w.owner, Input[apitypes.AuditListInput](tenant(pairs...))))
	}
	all := list()
	for index := 1; index < len(all); index++ {
		if jsNumber(all[index].Get("timestamp")) > jsNumber(all[index-1].Get("timestamp")) {
			t.Fatal("audit list is not newest first")
		}
	}
	if got := list("action", "iam:domains:create"); len(got) != 3 {
		t.Fatalf("exact action = %d", len(got))
	}
	globbed := list("action", "iam:domains:*")
	if len(globbed) != 4 {
		t.Fatalf("glob action = %d (%v)", len(globbed), pluck(globbed, "action"))
	}
	denied := list("outcome", "deny")
	if len(denied) != 1 || denied[0].Get("action") != "iam:domains:read" {
		t.Fatalf("denials = %s", stringify(denied))
	}
	if got := list("resourceId", "domains/two.example"); len(got) != 1 {
		t.Fatalf("by resource = %d", len(got))
	}
	ownerID := jsString(w.find("identities", body("tenantId", w.tenantID, "owner", true))[0].Get("id"))
	for _, event := range list("actorId", ownerID) {
		if event.Get("actorId") != ownerID {
			t.Fatalf("actor filter leaked %s", stringify(event))
		}
	}
	// Every read is audited too: with the clock moved on, the audit of the previous call is the newest event.
	w.advance(1)
	before := list("limit", 3.0)
	w.advance(1)
	if got := list("limit", 2.0, "offset", 1.0); len(got) != 2 || got[0].Get("id") != before[0].Get("id") || got[1].Get("id") != before[1].Get("id") {
		t.Fatalf("paged = %v, before = %v", pluck(got, "id"), pluck(before, "id"))
	}
	if got := list("from", w.now()+1); len(got) != 0 {
		t.Fatalf("future range = %d", len(got))
	}
	if got := list("to", w.now()); len(got) < len(all) {
		t.Fatalf("bounded range = %d of %d", len(got), len(all))
	}
	_, err = audit.List(w.ctx, w.owner, Input[apitypes.AuditListInput](tenant("outcome", "maybe")))
	expectError(t, err, "INVALID_INPUT", "outcome must be allow or deny")
	_, err = audit.List(w.ctx, w.owner, Input[apitypes.AuditListInput](tenant("limit", 1001.0)))
	expectError(t, err, "INVALID_INPUT", "Invalid limit")

	// Audit reads need iam:audit:read.
	_, err = audit.Export(w.ctx, memberCredential, Input[apitypes.AuditExportInput](tenant()))
	expectCode(t, err, "ACCESS_DENIED")
}

func parseLines(t *testing.T, text string) []*core.Object {
	t.Helper()
	var events []*core.Object
	for _, line := range strings.Split(text, "\n") {
		events = append(events, obj(t, line))
	}
	return events
}
