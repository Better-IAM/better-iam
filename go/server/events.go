package server

// Port of packages/server/src/events.ts: chained audit recording, in-transaction fan-out (post-commit dispatch rows
// and webhook outbox deliveries), webhook signing and the built-in transport, post-commit dispatch, subscriptions,
// and webhook URL / event validation.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

var webhookEventPattern = regexp.MustCompile(`^[a-zA-Z0-9:*?_.-]{1,128}$`)
var signatureHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// VerifyWebhookInput is what VerifyWebhookSignature checks.
type VerifyWebhookInput struct {
	Secret string
	// Timestamp is the X-Better-IAM-Timestamp header value (a string or a number).
	Timestamp any
	Body      string
	// Signature is the X-Better-IAM-Signature header value.
	Signature string
	// ToleranceSeconds defaults to 300.
	ToleranceSeconds *float64
	// Now defaults to the current time (epoch milliseconds).
	Now *float64
}

func hmacSHA256(key, message string) []byte {
	mac := hmac.New(sha256.New, utf8Bytes(key))
	mac.Write(utf8Bytes(message))
	return mac.Sum(nil)
}

// VerifyWebhookSignature verifies a webhook signature produced by Better IAM.
func VerifyWebhookSignature(input VerifyWebhookInput) bool {
	timestamp := jsNumber(core.Normalize(input.Timestamp))
	if math.IsNaN(timestamp) || math.IsInf(timestamp, 0) {
		return false
	}
	tolerance := 300.0
	if input.ToleranceSeconds != nil {
		tolerance = *input.ToleranceSeconds
	}
	now := float64(time.Now().UnixMilli())
	if input.Now != nil {
		now = *input.Now
	}
	if math.Abs(math.Floor(now/1000)-timestamp) > tolerance {
		return false
	}
	expected := hmacSHA256(input.Secret, core.NumberString(timestamp)+"."+input.Body)
	provided := ""
	for _, part := range strings.Split(input.Signature, ",") {
		if trimmed := core.JSTrim(part); strings.HasPrefix(trimmed, "v1=") {
			provided = trimmed[3:]
			break
		}
	}
	if provided == "" || !signatureHex.MatchString(provided) {
		return false
	}
	decoded, _ := hex.DecodeString(provided)
	return hmac.Equal(expected, decoded)
}

// WebhookBody is the JSON body of a webhook delivery for an audit event, members in the documented order.
func WebhookBody(event *core.Object) *core.Object {
	body := core.NewObject(
		"id", event.Get("id"),
		"type", event.Get("action"),
		"tenantId", event.Get("tenantId"),
		"actorId", event.Get("actorId"),
		"resourceId", event.Get("resourceId"),
		"outcome", event.Get("outcome"),
		"timestamp", event.Get("timestamp"),
	)
	if value := event.Get("originalActorId"); truthy(value) {
		body.Set("originalActorId", value)
	}
	if value := event.Get("impersonatorId"); truthy(value) {
		body.Set("impersonatorId", value)
	}
	if truthy(event.Get("rootOverride")) {
		body.Set("rootOverride", true)
	}
	if value := event.Get("metadata"); truthy(value) {
		body.Set("metadata", value)
	}
	if value := event.Get("sessionContext"); truthy(value) {
		if object, ok := value.(*core.Object); ok {
			body.Set("sessionContext", object.Spread())
		} else {
			body.Set("sessionContext", value)
		}
	}
	if value, ok := event.Get("sequence").(float64); ok {
		body.Set("sequence", value)
	}
	if value, ok := event.Get("hash").(string); ok {
		body.Set("hash", value)
	}
	return body
}

// PublicWebhook strips the sealed signing secret from a subscription.
func PublicWebhook(hook *core.Object) *core.Object {
	safe := hook.Spread()
	safe.Delete("secretSealed")
	return safe
}

// EventService records audit events and fans them out (createEvents).
type EventService struct {
	ctx          *ServerContext
	addressRules auth.SafeFetchAddressOptions
	fetch        *auth.GuardedFetch
}

// CreateEvents builds the event service.
func CreateEvents(ctx *ServerContext) *EventService {
	rules := auth.SafeFetchAddressOptions{
		AnyPort:                true,
		AllowPrivateNetworks:   ctx.Options.Events != nil && ctx.Options.Events.AllowPrivateNetworks != nil && *ctx.Options.Events.AllowPrivateNetworks,
		AllowInsecureLocalhost: ctx.Config.BaseURL.Protocol != "https:",
	}
	return &EventService{ctx: ctx, addressRules: rules, fetch: auth.CreateGuardedFetch(auth.GuardedFetchOptions{SafeFetchAddressOptions: rules})}
}

func (s *EventService) needsDispatch() bool {
	for _, plugin := range s.ctx.Plugins {
		if plugin.AfterAudit != nil {
			return true
		}
	}
	return (s.ctx.Options.Events != nil && s.ctx.Options.Events.OnEvent != nil) || s.ctx.Subscribers.Size() > 0
}

func matchesAny(patterns any, value string) bool {
	list, _ := patterns.([]any)
	for _, pattern := range list {
		if text, ok := pattern.(string); ok && core.MatchPattern(text, value, nil) {
			return true
		}
	}
	return false
}

// FanOut queues post-commit dispatch and webhook deliveries inside the recording transaction.
func (s *EventService) FanOut(ctx context.Context, tx core.IamStore, event *core.Object) error {
	if s.needsDispatch() {
		if _, err := tx.Insert(ctx, "auditHooks", core.NewObject(
			"id", event.Get("id"), "tenantId", event.Get("tenantId"), "event", event, "delivered", false,
		)); err != nil {
			return err
		}
	}
	hooks, err := tx.Find(ctx, "webhooks", core.NewObject("active", true), nil)
	if err != nil || len(hooks) == 0 {
		return err
	}
	var ancestors []string
	ancestorsRead := false
	body := core.MustStringify(WebhookBody(event))
	action := jsString(event.Get("action"))
	resourceID := jsString(event.Get("resourceId"))
	for _, hook := range hooks {
		if !matchesAny(hook.Get("events"), action) {
			continue
		}
		if outcomes := hook.Get("outcomes"); truthy(outcomes) {
			list, _ := outcomes.([]any)
			found := false
			for _, outcome := range list {
				if outcome == event.Get("outcome") {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		if resources := hook.Get("resources"); truthy(resources) && !matchesAny(resources, resourceID) {
			continue
		}
		hookTenant := jsString(hook.Get("tenantId"))
		if hook.Get("tenantId") != event.Get("tenantId") {
			if hook.Get("scope") != "subtree" {
				continue
			}
			if !ancestorsRead {
				if ancestors, err = s.ctx.AncestorIDs(ctx, tx, jsString(event.Get("tenantId"))); err != nil {
					return err
				}
				ancestorsRead = true
			}
			if !containsString(ancestors, hookTenant) {
				continue
			}
		}
		reference := jsString(event.Get("id"))
		if _, err := s.ctx.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
			TenantID:  hookTenant,
			Kind:      "webhook",
			To:        jsString(hook.Get("id")),
			Template:  action,
			Payload:   core.NewObject("url", hook.Get("url"), "body", body),
			Reference: &reference,
		}); err != nil {
			return err
		}
	}
	return nil
}

// RecordAudit records an audit event at the end of its tenant's chain and fans it out. Every audit insert in the
// server goes through here.
func (s *EventService) RecordAudit(ctx context.Context, tx core.IamStore, event *core.Object) error {
	chained, err := core.AppendAuditEvent(ctx, tx, event)
	if err != nil {
		return err
	}
	return s.FanOut(ctx, tx, chained)
}

// Audit records an audit event attributed to the acting principal, with the session context of its credential.
// metadata is nil when absent.
func (s *EventService) Audit(ctx context.Context, tx core.IamStore, principal *Principal, action, tenantID, resourceID, outcome string, rootOverride bool, metadata *core.Object) error {
	event := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"actorId", principal.Identity.Get("id"),
		"originalActorId", principal.Session.Get("originalIdentityId"),
		"action", action,
		"resourceId", resourceID,
		"outcome", outcome,
		"rootOverride", rootOverride,
		"timestamp", float64(s.ctx.Wall()),
	)
	if metadata != nil {
		event.Set("metadata", metadata)
	}
	if impersonator := principal.Session.Get("impersonatorId"); truthy(impersonator) {
		event.Set("impersonatorId", impersonator)
	}
	// Which credential acted (and the role, trust and names behind a temporary one); covered by the hash chain.
	if sessionContext := AuditSessionContext(principal.Session); sessionContext != nil {
		event.Set("sessionContext", sessionContext)
	}
	// Hooks are dispatched separately so external code cannot interrupt a committed mutation.
	return s.RecordAudit(ctx, tx, event)
}

// SignedWebhookDelivery builds the signed delivery for an outbox message and its subscription: the stored body
// signed with the subscription's current secret at the injected clock's second.
func (s *EventService) SignedWebhookDelivery(message auth.DeliveryMessage, hook *core.Object) (*WebhookDelivery, error) {
	body, ok := message.Payload["body"]
	if !ok {
		return nil, core.NewIamError("INVALID_SEALED_VALUE", "Webhook payload is incomplete")
	}
	hookID := jsString(hook.Get("id"))
	sealed, _ := hook.Get("secretSealed").(string)
	secret, err := auth.DecryptSecret(sealed, append([]string{s.ctx.Options.Secret}, s.ctx.Options.PreviousSecrets...), "webhook:"+hookID)
	if err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(int64(math.Floor(float64(s.ctx.Now())/1000)), 10)
	signature := hex.EncodeToString(hmacSHA256(secret, timestamp+"."+body))
	return &WebhookDelivery{
		ID:        message.ID,
		TenantID:  message.TenantID,
		WebhookID: hookID,
		URL:       jsString(hook.Get("url")),
		Event:     message.Template,
		Body:      body,
		Headers: core.NewObject(
			"content-type", "application/json",
			"user-agent", "better-iam-webhooks/1",
			"x-better-iam-event", message.Template,
			"x-better-iam-delivery", message.ID,
			"x-better-iam-webhook", hookID,
			"x-better-iam-timestamp", timestamp,
			"x-better-iam-signature", "v1="+signature,
		),
	}, nil
}

// DeliverWebhookMessage is the built-in webhook transport: signs the stored body with the subscription's current
// secret and POSTs it (or hands it to events.deliverWebhook).
func (s *EventService) DeliverWebhookMessage(ctx context.Context, message auth.DeliveryMessage) error {
	hook, err := s.ctx.Store.Get(ctx, "webhooks", message.To)
	if err != nil {
		return err
	}
	// A removed or paused subscription drops its pending deliveries instead of failing forever.
	if hook == nil || !truthy(hook.Get("active")) {
		return nil
	}
	delivery, err := s.SignedWebhookDelivery(message, hook)
	if err != nil {
		return err
	}
	if s.ctx.Options.Events != nil && s.ctx.Options.Events.DeliverWebhook != nil {
		return s.ctx.Options.Events.DeliverWebhook(ctx, *delivery)
	}
	// Tenant administrators choose the URL: the guarded transport refuses private and reserved addresses at
	// connect time and never follows redirects.
	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(s.ctx.Config.WebhookTimeoutMs)*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, delivery.URL, strings.NewReader(delivery.Body))
	if err != nil {
		return core.NewIamError("WEBHOOK_UNREACHABLE", "Webhook endpoint could not be reached", 502)
	}
	request.Header = delivery.HTTPHeader()
	response, err := s.fetch.DoRedirectError(request)
	if err != nil {
		// One message for every connection failure, so delivery history cannot map networks or ports.
		if errors.Is(err, context.DeadlineExceeded) && requestCtx.Err() != nil && ctx.Err() == nil {
			return core.NewIamError("WEBHOOK_UNREACHABLE", "Webhook endpoint did not answer in time", 502)
		}
		return core.NewIamError("WEBHOOK_UNREACHABLE", "Webhook endpoint could not be reached", 502)
	}
	// The response body is never read; release the connection.
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return core.NewIamError("WEBHOOK_REJECTED", "Webhook endpoint responded with status "+strconv.Itoa(response.StatusCode), 502)
	}
	return nil
}

// Dispatch is the post-commit dispatch of queued events to plugins, the configured callback, and in-process
// subscribers.
func (s *EventService) Dispatch(ctx context.Context) (dispatched int, err error) {
	rows, err := s.ctx.Store.Find(ctx, "auditHooks", core.NewObject("delivered", false), nil)
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		event, _ := row.Get("event").(*core.Object)
		for _, plugin := range s.ctx.Plugins {
			if plugin.AfterAudit != nil {
				if err := plugin.AfterAudit(ctx, event); err != nil {
					return dispatched, err
				}
			}
		}
		if s.ctx.Options.Events != nil && s.ctx.Options.Events.OnEvent != nil {
			if err := s.ctx.Options.Events.OnEvent(ctx, event); err != nil {
				return dispatched, err
			}
		}
		action := jsString(member(event, "action"))
		for _, subscriber := range s.ctx.Subscribers.snapshot() {
			matched := false
			for _, pattern := range subscriber.Patterns {
				if core.MatchPattern(pattern, action, nil) {
					matched = true
					break
				}
			}
			if matched {
				if err := subscriber.Handler(ctx, event); err != nil {
					return dispatched, err
				}
			}
		}
		// Re-read: another dispatcher may have delivered the row and a retention sweep deleted it.
		rowID := jsString(row.Get("id"))
		if err := s.ctx.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			current, err := tx.Get(ctx, "auditHooks", rowID)
			if err != nil {
				return err
			}
			if current != nil && !truthy(current.Get("delivered")) {
				_, err = tx.Put(ctx, "auditHooks", current.Spread(core.NewObject("delivered", true, "deliveredAt", float64(s.ctx.Now()))))
			}
			return err
		}); err != nil {
			return dispatched, err
		}
		dispatched++
	}
	return dispatched, nil
}

// Subscribe subscribes an in-process handler to audit events whose action matches any pattern (a string or
// []string). It returns the unsubscribe function.
func (s *EventService) Subscribe(pattern any, handler func(ctx context.Context, event *core.Object) error) (func(), error) {
	var items []any
	switch value := pattern.(type) {
	case []string:
		items = stringsOf(value)
	case []any:
		items = value
	default:
		items = []any{value}
	}
	patterns := make([]string, len(items))
	for index, item := range items {
		text, err := Text(item, "event pattern", 128)
		if err != nil {
			return nil, err
		}
		patterns[index] = text
	}
	subscriber := &EventSubscriber{Patterns: patterns, Handler: handler}
	s.ctx.Subscribers.add(subscriber)
	return func() { s.ctx.Subscribers.remove(subscriber) }, nil
}

// WebhookURL validates a webhook endpoint URL and returns its serialization.
func (s *EventService) WebhookURL(value any) (string, error) {
	raw, err := Text(value, "url", 2048)
	if err != nil {
		return "", err
	}
	u, err := auth.ParseFetchURL(raw)
	if err != nil {
		return "", invalidInput("Webhook URL must be absolute")
	}
	if urlUsername(u) != "" || urlPassword(u) != "" || u.Fragment != "" {
		return "", invalidInput("Webhook URLs cannot carry credentials or fragments")
	}
	loopback := u.Hostname == "localhost" || u.Hostname == "127.0.0.1" || u.Hostname == "[::1]"
	if u.Protocol != "https:" && !(u.Protocol == "http:" && loopback && s.ctx.Config.BaseURL.Protocol != "https:") {
		return "", invalidInput("Webhook URLs must use HTTPS")
	}
	// IP literals are judged now; hostnames are judged again by the transport each time it connects.
	if _, err := auth.CheckFetchURL(u.Href, s.addressRules); err != nil {
		return "", invalidInput("Webhook URLs must point at a public address (see events.allowPrivateNetworks)")
	}
	return u.Href, nil
}

// WebhookEvents validates 1-50 event name patterns and removes duplicates.
func (s *EventService) WebhookEvents(value any) ([]string, error) {
	patterns, err := Strings(value, "events")
	if err != nil {
		return nil, err
	}
	invalid := len(patterns) == 0 || len(patterns) > 50
	for _, pattern := range patterns {
		if !webhookEventPattern.MatchString(pattern) {
			invalid = true
		}
	}
	if invalid {
		return nil, invalidInput("events must contain 1-50 event name patterns")
	}
	return unique(patterns), nil
}

// SealedWebhookSecret is a new signing secret for a subscription and its sealed form.
func (s *EventService) SealedWebhookSecret(hookID string) (secret, sealed string) {
	secret = "whsec_" + Token()
	return secret, auth.EncryptSecret(secret, s.ctx.Options.Secret, "webhook:"+hookID)
}
