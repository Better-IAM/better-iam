package auth

// Port of packages/auth/src/outbox.ts: sealed, at-least-once deliveries (email, SMS, webhooks).

import (
	"context"
	"errors"
	"math"
	"sort"

	"github.com/Better-IAM/better-iam/go/core"
)

// OutboxContext is what the outbox needs from the auth service.
type OutboxContext struct {
	Store core.IamStore
	// Secret seals new payloads.
	Secret string
	// Secrets open payloads: the current secret, then previous ones during a rotation (defaults to Secret).
	Secrets []string
	Now     func() int64
	// MaxAttempts abandons a message after this many failed attempts.
	MaxAttempts int64
	// Deliverer returns the callback for a message kind, or nil when that kind is not configured.
	Deliverer func(kind string) Deliverer
}

// DispatchResult counts one dispatch run.
type DispatchResult struct {
	Delivered int `json:"delivered"`
	Failed    int `json:"failed"`
	Abandoned int `json:"abandoned"`
}

// EnqueueInput is one delivery to queue. Payload is an object of strings, sealed as JSON in its key order.
type EnqueueInput struct {
	TenantID  string
	Kind      string
	To        string
	Template  string
	Payload   *core.Object
	Reference *string
}

// EnqueueDelivery enqueues a sealed delivery in the caller's transaction and returns the message ID.
func EnqueueDelivery(ctx context.Context, outbox *OutboxContext, tx core.IamStore, input EnqueueInput) (string, error) {
	if outbox.Deliverer(input.Kind) == nil {
		return "", core.NewIamError("FEATURE_DISABLED", input.Kind+" delivery is not configured")
	}
	id := NewID("out")
	payload := input.Payload
	if payload == nil {
		payload = core.NewObject()
	}
	plain, _, err := core.Stringify(payload)
	if err != nil {
		return "", err
	}
	message := core.NewObject(
		"id", id,
		"tenantId", input.TenantID,
		"kind", input.Kind,
		"to", input.To,
		"template", input.Template,
		"payload", core.NewObject("sealed", EncryptSecret(plain, outbox.Secret, "outbox:"+id)),
		"createdAt", float64(outbox.Now()),
		"attempts", 0.0,
	)
	if input.Reference != nil {
		message.Set("reference", *input.Reference)
	}
	if _, err := tx.Insert(ctx, "outbox", message); err != nil {
		return "", err
	}
	return id, nil
}

func leased(message *core.Object, now int64) bool {
	leaseUntil, ok := num(message, "leaseUntil")
	return ok && leaseUntil > float64(now)
}

// errorText is `${error.name}: ${error.message}` (or String(error)), at most 256 UTF-16 code units.
func errorText(err error) string {
	var iam *core.IamError
	var syntax *core.SyntaxError
	name := "Error"
	if errors.As(err, &iam) {
		name = "IamError"
	} else if errors.As(err, &syntax) {
		name = "SyntaxError"
	} else if named, ok := err.(interface{ Name() string }); ok {
		name = named.Name()
	}
	return sliceUTF16(name+": "+err.Error(), 0, 256)
}

// payloadStrings decodes an opened payload (a JSON object of strings) into a map; other values read as
// String(value), as template code would see them interpolated.
func payloadStrings(value any) map[string]string {
	out := map[string]string{}
	object, ok := value.(*core.Object)
	if !ok {
		return out
	}
	object.Entries(func(key string, item any) bool {
		if core.IsUndefined(item) {
			return true
		}
		out[key] = jsString(item)
		return true
	})
	return out
}

// DispatchOutbox delivers at least once. Callbacks must deduplicate by message ID. A failed attempt is retried with
// exponential backoff (30 seconds doubling to one hour) until MaxAttempts, then abandoned with failedAt set.
func DispatchOutbox(ctx context.Context, outbox *OutboxContext, limit int) (DispatchResult, error) {
	result := DispatchResult{}
	if limit < 1 || limit > 1000 {
		return result, core.NewIamError("INVALID_INPUT", "limit must be between 1 and 1000")
	}
	now := outbox.Now()
	all, err := outbox.Store.Find(ctx, "outbox", nil, nil)
	if err != nil {
		return result, err
	}
	var pending []*core.Object
	for _, message := range all {
		if !flag(message, "deliveredAt") && !flag(message, "failedAt") && !leased(message, now) {
			pending = append(pending, message)
		}
	}
	sort.SliceStable(pending, func(i, j int) bool {
		a, b := numOr(pending[i], "createdAt", math.NaN()), numOr(pending[j], "createdAt", math.NaN())
		if d := a - b; d != 0 && !math.IsNaN(d) {
			return d < 0
		}
		return str(pending[i], "id") < str(pending[j], "id")
	})
	if len(pending) > limit {
		pending = pending[:limit]
	}
	secrets := outbox.Secrets
	if secrets == nil {
		secrets = []string{outbox.Secret}
	}
	for _, candidate := range pending {
		lease := NewID("lease")
		// Claiming is its own transaction so two workers never deliver the same message.
		claimed, err := core.Transact(ctx, outbox.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			message, err := tx.Get(ctx, "outbox", str(candidate, "id"))
			if err != nil || message == nil {
				return nil, err
			}
			if flag(message, "deliveredAt") || flag(message, "failedAt") || leased(message, outbox.Now()) {
				return nil, nil
			}
			message.Set("lease", lease)
			message.Set("leaseUntil", float64(outbox.Now()+60_000))
			message.Set("attempts", numOr(message, "attempts", math.NaN())+1)
			if _, err := tx.Put(ctx, "outbox", message); err != nil {
				return nil, err
			}
			return message, nil
		})
		if err != nil {
			return result, err
		}
		if claimed == nil {
			continue
		}
		id := str(claimed, "id")
		deliveryErr := func() error {
			callback := outbox.Deliverer(str(claimed, "kind"))
			if callback == nil {
				return core.NewIamError("FEATURE_DISABLED", "Delivery callback unavailable")
			}
			sealed := str(child(claimed, "payload"), "sealed")
			if sealed == "" {
				return core.NewIamError("INVALID_SEALED_VALUE", "Outbox payload is not sealed")
			}
			plain, err := DecryptSecret(sealed, secrets, "outbox:"+id)
			if err != nil {
				return err
			}
			parsed, err := core.ParseJSONString(plain)
			if err != nil {
				return err
			}
			return callback(ctx, DeliveryMessage{
				ID:       id,
				TenantID: str(claimed, "tenantId"),
				To:       str(claimed, "to"),
				Template: str(claimed, "template"),
				Payload:  payloadStrings(parsed),
			})
		}()
		if deliveryErr == nil {
			err := outbox.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
				message, err := tx.Get(ctx, "outbox", id)
				if err != nil {
					return err
				}
				if message != nil && core.StrictEquals(message.Get("lease"), lease) {
					next := message.Spread(core.NewObject("payload", core.NewObject(), "deliveredAt", float64(outbox.Now()), "leaseUntil", 0.0, "lastError", core.Undefined))
					_, err = tx.Put(ctx, "outbox", next)
				}
				return err
			})
			if err != nil {
				return result, err
			}
			result.Delivered++
			continue
		}
		result.Failed++
		lastError := errorText(deliveryErr)
		attempts := numOr(claimed, "attempts", math.NaN())
		exhausted := attempts >= float64(outbox.MaxAttempts)
		if exhausted {
			result.Abandoned++
		}
		backoff := math.Min(30_000*math.Pow(2, math.Max(0, attempts-1)), 60*60_000)
		err = outbox.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			message, err := tx.Get(ctx, "outbox", id)
			if err != nil {
				return err
			}
			if message == nil || !core.StrictEquals(message.Get("lease"), lease) {
				return nil
			}
			var next *core.Object
			if exhausted {
				next = message.Spread(core.NewObject("payload", core.NewObject(), "failedAt", float64(outbox.Now()), "leaseUntil", 0.0, "lastError", lastError))
			} else {
				next = message.Spread(core.NewObject("leaseUntil", float64(outbox.Now())+backoff, "lastError", lastError))
			}
			_, err = tx.Put(ctx, "outbox", next)
			return err
		})
		if err != nil {
			return result, err
		}
	}
	return result, nil
}
