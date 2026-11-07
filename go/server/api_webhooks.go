package server

// Port of packages/server/src/api/webhooks.ts: the `webhooks` API group (signed audit-event subscriptions and their
// delivery history) and the `audit` API group (searching, verifying, and exporting the tenant's audit hash chain).

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// DeliveryStatus is delivered, failed or pending.
type DeliveryStatus = string

// webhookOutcomes is webhooks.ts outcomes: allow, deny, or both, without duplicates.
func webhookOutcomes(value any) ([]string, error) {
	listed, err := Strings(value, "outcomes")
	if err != nil {
		return nil, err
	}
	items := unique(listed)
	invalid := len(items) == 0
	for _, item := range items {
		if item != "allow" && item != "deny" {
			invalid = true
		}
	}
	if invalid {
		return nil, invalidInput("outcomes must list allow, deny, or both")
	}
	return items, nil
}

// webhookResourcePatterns is webhooks.ts resourcePatterns: 1-20 resource patterns of at most 256 characters.
func webhookResourcePatterns(value any) ([]string, error) {
	listed, err := Strings(value, "resources")
	if err != nil {
		return nil, err
	}
	items := unique(listed)
	invalid := len(items) == 0 || len(items) > 20
	for _, item := range items {
		if utf16Len(item) > 256 {
			invalid = true
		}
	}
	if invalid {
		return nil, invalidInput("resources must contain 1-20 patterns")
	}
	return items, nil
}

// WebhooksAPI is the `webhooks` API group (packages/server/src/api/webhooks.ts createWebhooksApi): every method runs through the
// operation envelope; the router maps POST {basePath}/webhooks/{method} onto it.
type WebhooksAPI struct {
	server *ServerContext
}

// CreateWebhooksAPI builds the `webhooks` API group.
func CreateWebhooksAPI(server *ServerContext) *WebhooksAPI {
	return &WebhooksAPI{server: server}
}

func subtreePlatformControlled() *core.IamError {
	return core.NewIamError("ACCESS_DENIED", "Subtree subscriptions are platform controlled", 403)
}

// subscription reads a subscription of the tenant. A subtree subscription receives every descendant organization's
// events, so it stays root's after creation too: retargeting it, taking its secret, removing it, or making it deliver
// needs a root principal, not just iam:webhooks:update or iam:webhooks:delete in the tenant that holds it.
func (api *WebhooksAPI) subscription(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, webhookID any) (*core.Object, error) {
	hook, err := api.server.Scoped(ctx, tx, "webhooks", webhookID, tenantID)
	if err != nil {
		return nil, err
	}
	if hook.Get("scope") == "subtree" {
		root, err := api.server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		if !root {
			return nil, subtreePlatformControlled()
		}
	}
	return hook, nil
}

// recordList is a list of stored records as a model array.
func recordList(records []*core.Object) []any {
	list := make([]any, len(records))
	for index, record := range records {
		list[index] = record
	}
	return list
}

// Create is POST {basePath}/webhooks/create. Subscribes an HTTPS endpoint to the tenant's audit events and returns the signing secret, which is shown only once.
func (api *WebhooksAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksCreateInput]) (Out[apitypes.WebhooksCreateOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:webhooks:create", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		scope := coalesce(input.Get("scope"), "tenant")
		if scope != "tenant" && scope != "subtree" {
			return nil, invalidInput("scope must be tenant or subtree")
		}
		if scope == "subtree" {
			root, err := server.RootPrincipal(ctx, tx, principal)
			if err != nil {
				return nil, err
			}
			if !root {
				return nil, subtreePlatformControlled()
			}
		}
		hooks, err := tx.Find(ctx, "webhooks", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		existing := len(hooks)
		if existing >= 50 {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "At most 50 webhooks per tenant", 409)
		}
		if err := server.EnforceLimit(ctx, tx, call.Tenant, "webhooks", func(context.Context) (int, error) { return existing, nil }); err != nil {
			return nil, err
		}
		hookID := ID()
		secret, sealed := server.Events.SealedWebhookSecret(hookID)
		url, err := server.Events.WebhookURL(input.Get("url"))
		if err != nil {
			return nil, err
		}
		events, err := server.Events.WebhookEvents(input.Get("events"))
		if err != nil {
			return nil, err
		}
		hook := core.NewObject(
			"id", hookID,
			"tenantId", tenantID,
			"url", url,
			"events", stringsOf(events),
			"active", true,
			"scope", scope,
			"secretSealed", sealed,
			"createdAt", float64(server.Now()),
			"updatedAt", float64(server.Now()),
			"createdBy", principal.Identity.Get("id"),
		)
		if description := input.Get("description"); !isUndefined(description) {
			text, err := Text(description, "description", 512)
			if err != nil {
				return nil, err
			}
			hook.Set("description", text)
		}
		if value := input.Get("outcomes"); !isUndefined(value) {
			outcomes, err := webhookOutcomes(value)
			if err != nil {
				return nil, err
			}
			hook.Set("outcomes", stringsOf(outcomes))
		}
		if value := input.Get("resources"); !isUndefined(value) {
			resources, err := webhookResourcePatterns(value)
			if err != nil {
				return nil, err
			}
			hook.Set("resources", stringsOf(resources))
		}
		stored, err := tx.Insert(ctx, "webhooks", hook)
		if err != nil {
			return nil, err
		}
		return core.NewObject("webhook", PublicWebhook(stored), "secret", secret), nil
	}, false)
	return Out[apitypes.WebhooksCreateOutput]{Value: result}, err
}

// Delete is POST {basePath}/webhooks/delete. Deletes a subscription and discards the deliveries still waiting to be sent.
func (api *WebhooksAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksDeleteInput]) (Out[apitypes.WebhooksDeleteOutput], error) {
	server := api.server
	tenantID, webhookID := input.Get("tenantId"), input.Get("webhookId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:webhooks:delete", jsString(webhookID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		if _, err := api.subscription(ctx, tx, call.Principal, jsString(tenantID), webhookID); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "webhooks", jsString(webhookID)); err != nil {
			return nil, err
		}
		messages, err := tx.Find(ctx, "outbox", core.NewObject("tenantId", tenantID, "kind", "webhook", "to", webhookID), nil)
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if !truthy(message.Get("deliveredAt")) && !truthy(message.Get("failedAt")) {
				if err := tx.Delete(ctx, "outbox", jsString(message.Get("id"))); err != nil {
					return nil, err
				}
			}
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.WebhooksDeleteOutput]{Value: result}, err
}

// Get is POST {basePath}/webhooks/get. Returns one subscription without its secret.
func (api *WebhooksAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksGetInput]) (Out[apitypes.WebhooksGetOutput], error) {
	server := api.server
	tenantID, webhookID := input.Get("tenantId"), input.Get("webhookId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:webhooks:read", jsString(webhookID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		hook, err := server.Scoped(ctx, call.Tx, "webhooks", webhookID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		return PublicWebhook(hook), nil
	}, false)
	return Out[apitypes.WebhooksGetOutput]{Value: result}, err
}

// List is POST {basePath}/webhooks/list. Lists every subscription of the tenant, without secrets.
func (api *WebhooksAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksListInput]) (Out[apitypes.WebhooksListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:webhooks:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		hooks, err := call.Tx.Find(ctx, "webhooks", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		list := make([]any, len(hooks))
		for index, hook := range hooks {
			list[index] = PublicWebhook(hook)
		}
		return list, nil
	}, false)
	return Out[apitypes.WebhooksListOutput]{Value: result}, err
}

// ListDeliveries is POST {basePath}/webhooks/listDeliveries. Returns the delivery history of one subscription, newest first, with status, attempt count, and the last error.
// Payloads are never returned.
func (api *WebhooksAPI) ListDeliveries(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksListDeliveriesInput]) (Out[apitypes.WebhooksListDeliveriesOutput], error) {
	server := api.server
	tenantID, webhookID := input.Get("tenantId"), input.Get("webhookId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:webhooks:read", jsString(webhookID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		if _, err := server.Scoped(ctx, tx, "webhooks", webhookID, jsString(tenantID)); err != nil {
			return nil, err
		}
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000)
		if err != nil {
			return nil, err
		}
		messages, err := tx.Find(ctx, "outbox", core.NewObject("tenantId", tenantID, "kind", "webhook", "to", webhookID), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(messages, func(i, j int) bool {
			a, b := messages[i], messages[j]
			if difference := jsNumber(b.Get("createdAt")) - jsNumber(a.Get("createdAt")); difference != 0 && difference == difference {
				return difference < 0
			}
			return compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0
		})
		if len(messages) > int(limit) {
			messages = messages[:int(limit)]
		}
		list := make([]any, len(messages))
		for index, message := range messages {
			status := "pending"
			if truthy(message.Get("deliveredAt")) {
				status = "delivered"
			} else if truthy(message.Get("failedAt")) {
				status = "failed"
			}
			list[index] = core.NewObject(
				"id", message.Get("id"),
				"event", message.Get("template"),
				"eventId", message.Get("reference"),
				"createdAt", message.Get("createdAt"),
				"attempts", message.Get("attempts"),
				"deliveredAt", message.Get("deliveredAt"),
				"failedAt", message.Get("failedAt"),
				"lastError", message.Get("lastError"),
				"status", status,
			)
		}
		return list, nil
	}, false)
	return Out[apitypes.WebhooksListDeliveriesOutput]{Value: result}, err
}

// Ping is POST {basePath}/webhooks/ping. Queues a synthetic webhook:ping delivery so you can check an endpoint and its signature verification end to end.
func (api *WebhooksAPI) Ping(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksPingInput]) (Out[apitypes.WebhooksPingOutput], error) {
	server := api.server
	tenantID, webhookID := input.Get("tenantId"), input.Get("webhookId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:webhooks:update", jsString(webhookID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		hook, err := api.subscription(ctx, tx, principal, jsString(tenantID), webhookID)
		if err != nil {
			return nil, err
		}
		if !truthy(hook.Get("active")) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Webhook is paused")
		}
		event := core.NewObject(
			"id", ID(),
			"type", "webhook:ping",
			"tenantId", hook.Get("tenantId"),
			"actorId", principal.Identity.Get("id"),
			"resourceId", hook.Get("id"),
			"outcome", "allow",
			"timestamp", float64(server.Now()),
		)
		body, _, err := core.Stringify(event)
		if err != nil {
			return nil, err
		}
		deliveryID, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
			TenantID: jsString(hook.Get("tenantId")),
			Kind:     "webhook",
			To:       jsString(hook.Get("id")),
			Template: "webhook:ping",
			Payload:  core.NewObject("url", hook.Get("url"), "body", body),
		})
		if err != nil {
			return nil, err
		}
		return core.NewObject("deliveryId", deliveryID), nil
	}, false)
	return Out[apitypes.WebhooksPingOutput]{Value: result}, err
}

// Redeliver is POST {basePath}/webhooks/redeliver. Queues the event behind an earlier delivery again, rebuilt from the audit log and signed with the current secret.
func (api *WebhooksAPI) Redeliver(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksRedeliverInput]) (Out[apitypes.WebhooksRedeliverOutput], error) {
	server := api.server
	tenantID, webhookID := input.Get("tenantId"), input.Get("webhookId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:webhooks:update", jsString(webhookID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		hook, err := api.subscription(ctx, tx, call.Principal, jsString(tenantID), webhookID)
		if err != nil {
			return nil, err
		}
		if !truthy(hook.Get("active")) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Webhook is paused")
		}
		deliveryID, err := Text(input.Get("deliveryId"), "deliveryId")
		if err != nil {
			return nil, err
		}
		message, err := tx.Get(ctx, "outbox", deliveryID)
		if err != nil {
			return nil, err
		}
		if message == nil || message.Get("tenantId") != tenantID || message.Get("kind") != "webhook" || message.Get("to") != hook.Get("id") {
			return nil, core.NewIamError("NOT_FOUND", "Delivery not found", 404)
		}
		if !truthy(message.Get("reference")) {
			return nil, core.NewIamError("INVALID_TRANSITION", "This delivery cannot be rebuilt")
		}
		event, err := tx.Get(ctx, "audit", jsString(message.Get("reference")))
		if err != nil {
			return nil, err
		}
		if event == nil {
			return nil, core.NewIamError("NOT_FOUND", "The delivered event no longer exists", 404)
		}
		body, _, err := core.Stringify(WebhookBody(event))
		if err != nil {
			return nil, err
		}
		reference := jsString(event.Get("id"))
		queued, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
			TenantID:  jsString(hook.Get("tenantId")),
			Kind:      "webhook",
			To:        jsString(hook.Get("id")),
			Template:  jsString(event.Get("action")),
			Payload:   core.NewObject("url", hook.Get("url"), "body", body),
			Reference: &reference,
		})
		if err != nil {
			return nil, err
		}
		return core.NewObject("deliveryId", queued, "eventId", event.Get("id")), nil
	}, false)
	return Out[apitypes.WebhooksRedeliverOutput]{Value: result}, err
}

// RotateSecret is POST {basePath}/webhooks/rotateSecret. Replaces a subscription's signing secret and returns the new one, which is shown only once.
// Deliveries claimed after this point are signed with it.
func (api *WebhooksAPI) RotateSecret(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksRotateSecretInput]) (Out[apitypes.WebhooksRotateSecretOutput], error) {
	server := api.server
	tenantID, webhookID := input.Get("tenantId"), input.Get("webhookId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:webhooks:update", jsString(webhookID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		hook, err := api.subscription(ctx, tx, call.Principal, jsString(tenantID), webhookID)
		if err != nil {
			return nil, err
		}
		secret, sealed := server.Events.SealedWebhookSecret(jsString(hook.Get("id")))
		stored, err := tx.Put(ctx, "webhooks", hook.Spread(core.NewObject("secretSealed", sealed, "updatedAt", float64(server.Now()))))
		if err != nil {
			return nil, err
		}
		return core.NewObject("webhook", PublicWebhook(stored), "secret", secret), nil
	}, false)
	return Out[apitypes.WebhooksRotateSecretOutput]{Value: result}, err
}

// Update is POST {basePath}/webhooks/update. Changes a subscription's URL, event patterns, filters, description, or active flag.
func (api *WebhooksAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksUpdateInput]) (Out[apitypes.WebhooksUpdateOutput], error) {
	server := api.server
	tenantID, webhookID := input.Get("tenantId"), input.Get("webhookId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:webhooks:update", jsString(webhookID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		hook, err := api.subscription(ctx, tx, call.Principal, jsString(tenantID), webhookID)
		if err != nil {
			return nil, err
		}
		url, events, description := input.Get("url"), input.Get("events"), input.Get("description")
		active, outcomes, resources := input.Get("active"), input.Get("outcomes"), input.Get("resources")
		if isUndefined(url) && isUndefined(events) && isUndefined(description) && isUndefined(active) && isUndefined(outcomes) && isUndefined(resources) {
			return nil, invalidInput("Nothing to update")
		}
		next := hook.Spread(core.NewObject("updatedAt", float64(server.Now())))
		if !isUndefined(url) {
			value, err := server.Events.WebhookURL(url)
			if err != nil {
				return nil, err
			}
			next.Set("url", value)
		}
		if !isUndefined(events) {
			value, err := server.Events.WebhookEvents(events)
			if err != nil {
				return nil, err
			}
			next.Set("events", stringsOf(value))
		}
		if description == nil {
			next.Delete("description")
		} else if !isUndefined(description) {
			value, err := Text(description, "description", 512)
			if err != nil {
				return nil, err
			}
			next.Set("description", value)
		}
		if outcomes == nil {
			next.Delete("outcomes")
		} else if !isUndefined(outcomes) {
			value, err := webhookOutcomes(outcomes)
			if err != nil {
				return nil, err
			}
			next.Set("outcomes", stringsOf(value))
		}
		if resources == nil {
			next.Delete("resources")
		} else if !isUndefined(resources) {
			value, err := webhookResourcePatterns(resources)
			if err != nil {
				return nil, err
			}
			next.Set("resources", stringsOf(value))
		}
		if !isUndefined(active) {
			flag, ok := active.(bool)
			if !ok {
				return nil, invalidInput("active must be boolean")
			}
			next.Set("active", flag)
		}
		stored, err := tx.Put(ctx, "webhooks", next)
		if err != nil {
			return nil, err
		}
		return PublicWebhook(stored), nil
	}, false)
	return Out[apitypes.WebhooksUpdateOutput]{Value: result}, err
}

// AuditAPI is the `audit` API group (packages/server/src/api/webhooks.ts createAuditApi): every method runs through the
// operation envelope; the router maps POST {basePath}/audit/{method} onto it.
type AuditAPI struct {
	server *ServerContext
}

// CreateAuditAPI builds the `audit` API group.
func CreateAuditAPI(server *ServerContext) *AuditAPI {
	return &AuditAPI{server: server}
}

// optionalInteger is `value !== undefined ? integer(value, name, min, max) : undefined`.
func optionalInteger(value any, name string, min, max float64) (*float64, error) {
	if isUndefined(value) {
		return nil, nil
	}
	number, err := Integer(value, name, min, max)
	if err != nil {
		return nil, err
	}
	return &number, nil
}

func intPointer(value float64) *int {
	number := int(value)
	return &number
}

// Export is POST {basePath}/audit/export. Returns a page of the tenant's audit events in chain order as JSON Lines, ready to archive.
// The events carry `sequence`, `previousHash`, and `hash`, so an archive can be verified later (the last line's hash
// links the next export).
func (api *AuditAPI) Export(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuditExportInput]) (Out[apitypes.AuditExportOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:audit:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		from := 1.0
		if value := input.Get("fromSequence"); !isUndefined(value) {
			number, err := Integer(value, "fromSequence", 1, maxSafeInteger)
			if err != nil {
				return nil, err
			}
			from = number
		}
		limit, err := Integer(coalesce(input.Get("limit"), 1000.0), "limit", 1, 10000)
		if err != nil {
			return nil, err
		}
		// One event past the page tells whether more follow.
		events, err := core.FindOrdered(ctx, tx, "audit", core.NewObject("tenantId", tenantID), core.OrderOptions{
			Field: "sequence", From: &from, Limit: intPointer(limit + 1),
		}, nil)
		if err != nil {
			return nil, err
		}
		page := events
		if len(page) > int(limit) {
			page = page[:int(limit)]
		}
		head, err := tx.Get(ctx, "auditChains", jsString(tenantID))
		if err != nil {
			return nil, err
		}
		lines := make([]string, len(page))
		for index, event := range page {
			line, _, err := core.Stringify(event)
			if err != nil {
				return nil, err
			}
			lines[index] = line
		}
		var first, last, next any = core.Undefined, core.Undefined, core.Undefined
		if len(page) > 0 {
			first = page[0].Get("sequence")
			last = page[len(page)-1].Get("sequence")
		}
		if len(events) > int(limit) {
			next = jsNumber(page[len(page)-1].Get("sequence")) + 1
		}
		var chainHead any
		if head != nil {
			chainHead = core.NewObject("sequence", head.Get("sequence"), "hash", head.Get("hash"))
		}
		return core.NewObject(
			"format", "jsonl",
			"count", len(page),
			"body", strings.Join(lines, "\n"),
			"firstSequence", first,
			"lastSequence", last,
			"nextSequence", next,
			"head", chainHead,
		), nil
	}, false)
	return Out[apitypes.AuditExportOutput]{Value: result}, err
}

var auditGlob = regexp.MustCompile(`[*?]`)

// List is POST {basePath}/audit/list. Searches the tenant's audit events, newest first, by actor, action, resource, outcome, and time range.
// action accepts a glob pattern; from/to bound the timestamp; actorId, resourceId, and outcome match exactly.
func (api *AuditAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuditListInput]) (Out[apitypes.AuditListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:audit:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000)
		if err != nil {
			return nil, err
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1000000)
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", tenantID)
		if value := input.Get("actorId"); !isUndefined(value) {
			actorID, err := Text(value, "actorId")
			if err != nil {
				return nil, err
			}
			filter.Set("actorId", actorID)
		}
		if value := input.Get("resourceId"); !isUndefined(value) {
			resourceID, err := Text(value, "resourceId", 2048)
			if err != nil {
				return nil, err
			}
			filter.Set("resourceId", resourceID)
		}
		if outcome := input.Get("outcome"); !isUndefined(outcome) {
			if outcome != "allow" && outcome != "deny" {
				return nil, invalidInput("outcome must be allow or deny")
			}
			filter.Set("outcome", outcome)
		}
		from, err := optionalInteger(input.Get("from"), "from", 0, maxSafeInteger)
		if err != nil {
			return nil, err
		}
		to, err := optionalInteger(input.Get("to"), "to", 0, maxSafeInteger)
		if err != nil {
			return nil, err
		}
		action, hasAction := "", false
		if value := input.Get("action"); !isUndefined(value) {
			if action, err = Text(value, "action", 128); err != nil {
				return nil, err
			}
			hasAction = true
		}
		// An action without wildcards is an exact filter the database can use; a glob is applied while reading the
		// log newest first in pages, so the whole log is never loaded.
		glob := hasAction && auditGlob.MatchString(action)
		if hasAction && !glob {
			filter.Set("action", action)
		}
		var where func(*core.Object) bool
		if glob {
			where = func(event *core.Object) bool { return core.MatchPattern(action, jsString(event.Get("action")), nil) }
		}
		events, err := core.FindOrdered(ctx, call.Tx, "audit", filter, core.OrderOptions{
			Field: "timestamp", Direction: "desc", From: from, To: to, Offset: intPointer(offset), Limit: intPointer(limit),
		}, where)
		if err != nil {
			return nil, err
		}
		return recordList(events), nil
	}, false)
	return Out[apitypes.AuditListOutput]{Value: result}, err
}

// Verify is POST {basePath}/audit/verify. Checks the tenant's audit hash chain and reports whether any stored event was altered, reordered, or removed.
// It checks contiguous sequences, linked hashes, recomputable event hashes, and a chain head that matches the last
// event. `fromSequence`/`toSequence` verify a window against its own links.
func (api *AuditAPI) Verify(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuditVerifyInput]) (Out[apitypes.AuditVerifyOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:audit:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		from, err := optionalInteger(input.Get("fromSequence"), "fromSequence", 1, maxSafeInteger)
		if err != nil {
			return nil, err
		}
		to, err := optionalInteger(input.Get("toSequence"), "toSequence", 1, maxSafeInteger)
		if err != nil {
			return nil, err
		}
		head, err := tx.Get(ctx, "auditChains", jsString(tenantID))
		if err != nil {
			return nil, err
		}
		stored, err := tx.Find(ctx, "audit", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		events := make([]*core.Object, 0, len(stored))
		for _, event := range stored {
			sequence, chained := event.Get("sequence").(float64)
			if !chained || ((from == nil || sequence >= *from) && (to == nil || sequence <= *to)) {
				events = append(events, event)
			}
		}
		partial := from != nil || to != nil
		options := core.VerifyAuditChainOptions{}
		if !partial && head != nil {
			options.Head = &core.AuditChainHeadRef{Sequence: jsNumber(head.Get("sequence")), Hash: jsString(head.Get("hash"))}
		}
		verification, err := ToModel(core.VerifyAuditChain(events, options))
		if err != nil {
			return nil, err
		}
		answer, _ := verification.(*core.Object)
		if answer == nil {
			answer = core.NewObject()
		}
		if head != nil {
			answer.Set("head", core.NewObject("sequence", head.Get("sequence"), "hash", head.Get("hash"), "updatedAt", head.Get("updatedAt")))
		} else {
			answer.Set("head", nil)
		}
		return answer, nil
	}, false)
	return Out[apitypes.AuditVerifyOutput]{Value: result}, err
}
