package server

// Port of packages/server/src/guarded.ts: the authorization envelope for resources the platform itself owns and
// describes with attributes (KMS keys, certificate authorities): the operation envelope of operations.ts, except that
// the decision sees the resource's attributes (resource.{name}), a module may add a fallback allow path (KMS
// grants), and one call may need several decisions (every name on a certificate). Sessions that view as someone else
// are refused outright.

import (
	"context"
	"errors"

	"github.com/Better-IAM/better-iam/go/core"
)

// GuardTarget is a guarded resource: the audited resource (without the `iam/` prefix: `kms/{keyId}`) and the
// attributes presented to policies as resource.{name}.
type GuardTarget struct {
	ResourceID string
	Attributes *core.Object
}

// Target makes GuardTarget a Guarded value.
func (t GuardTarget) Target() GuardTarget { return t }

// Guarded is a module's target type: anything that names its GuardTarget.
type Guarded interface {
	Target() GuardTarget
}

// GuardCall is what a guarded call's body receives.
type GuardCall struct {
	Tx        core.IamStore
	Principal *Principal
	Tenant    *core.Object
	// Metadata is added to the call's audit event.
	Metadata *core.Object
	// Allowed evaluates another action or target for the caller by policy alone (no fallback).
	Allowed func(ctx context.Context, action string, target GuardTarget) (bool, error)
}

// GuardOptions configure a guard.
type GuardOptions[T Guarded] struct {
	// Fallback is a second way to allow a call no policy decides: consulted only when the policy decision's reason
	// is NO_APPLICABLE_GRANT. Returns audit metadata naming what allowed the call, or nil.
	Fallback func(ctx context.Context, tx core.IamStore, principal *Principal, action string, target T) (*core.Object, error)
	// Describe is the audit metadata every allowed call of a target starts with.
	Describe func(target T) *core.Object
	// RecordedFailures are error codes thrown after authorization that are recorded as a denied call (with reason).
	RecordedFailures map[string]string
	// HookResult is what plugin afterOperation hooks see of a result (strip plaintexts and tokens).
	HookResult func(value any) any
}

// GuardDecision is a decision, with the fallback's audit note when the fallback allowed it.
type GuardDecision struct {
	core.Decision
	Note *core.Object
}

// GuardAction is the action of a guarded call: a fixed name, or one computed from the located target.
type GuardAction[T Guarded] struct {
	Name string
	Of   func(target T) string
}

// Guard is createGuard's result.
type Guard[T Guarded] struct {
	ctx        *ServerContext
	collection string
	options    GuardOptions[T]
}

// CreateGuard builds a guard; collection is the tenant-wide resource (`kms`, `pki`) where refusals before any
// lookup are recorded.
func CreateGuard[T Guarded](ctx *ServerContext, collection string, options GuardOptions[T]) *Guard[T] {
	return &Guard[T]{ctx: ctx, collection: collection, options: options}
}

func (g *Guard[T]) describe(target T) *core.Object {
	if g.options.Describe == nil {
		return nil
	}
	return g.options.Describe(target)
}

// Decide decides one action on a target. located is the module target when the fallback may be consulted (nil
// otherwise); cache holds prepared decisions by action across the several decisions of one call.
func (g *Guard[T]) Decide(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, action string, target GuardTarget, located *T, cache map[string]*PreparedDecision) (GuardDecision, error) {
	if truthy(principal.Session.Get("impersonatorId")) {
		return GuardDecision{Decision: core.Decision{Allowed: false, Reason: "IMPERSONATION_RESTRICTED", Matched: []string{}}}, nil
	}
	prepared := cache[action]
	if prepared == nil {
		var err error
		if prepared, err = g.ctx.Decisions.PrepareDecision(ctx, tx, principal, tenant, action); err != nil {
			return GuardDecision{}, err
		}
		if cache != nil {
			cache[action] = prepared
		}
	}
	decision, err := DecideOn(prepared, ResolvedResource{TenantID: jsString(tenant.Get("id")), Type: "iam", ID: target.ResourceID, Attributes: target.Attributes}, action)
	if err != nil {
		return GuardDecision{}, err
	}
	if decision.Allowed || located == nil || g.options.Fallback == nil || decision.Reason != "NO_APPLICABLE_GRANT" {
		return GuardDecision{Decision: decision}, nil
	}
	note, err := g.options.Fallback(ctx, tx, principal, action, *located)
	if err != nil {
		return GuardDecision{}, err
	}
	if note != nil {
		return GuardDecision{Decision: core.Decision{Allowed: true, Reason: "FALLBACK", Matched: []string{}}, Note: note}, nil
	}
	return GuardDecision{Decision: decision}, nil
}

// corePrincipal is the principal as the plugin hook type (typed core views).
func corePrincipal(principal *Principal) *core.AuthenticatedPrincipal {
	var identity core.Identity
	var session core.Session
	_ = core.FromRecord(principal.Identity, &identity)
	_ = core.FromRecord(principal.Session, &session)
	return &core.AuthenticatedPrincipal{Identity: &identity, Session: &session, DeviceProof: principal.DeviceProof}
}

type guardOutcome struct {
	denied       bool
	value        any
	rootOverride bool
}

// Run authenticates, locates the target, decides, runs, and audits. A denial commits only its audit record; a
// refusal inside the call (OperationDenied) or a recorded failure after authorization is audited as deny once the
// call's own transaction has rolled back.
func (g *Guard[T]) Run(ctx context.Context, credential core.CredentialInput, tenantID string, action GuardAction[T],
	locate func(ctx context.Context, tx core.IamStore, principal *Principal) (T, error),
	fn func(ctx context.Context, call GuardCall, target T) (any, error)) (any, error) {
	label := action.Name
	if action.Of != nil {
		label = "iam:call"
	}
	server := g.ctx
	return Span(server.Observe, "operation", label, tenantID, func() (any, error) {
		authenticated, err := server.Principals.Authenticate(ctx, credential)
		if err != nil {
			return nil, err
		}
		var actor *Principal
		resolvedAction := label
		resourceID := ""
		outcome, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (guardOutcome, error) {
			principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
			if err != nil {
				return guardOutcome{}, err
			}
			tenantText, err := Text(tenantID, "tenantId")
			if err != nil {
				return guardOutcome{}, err
			}
			tenant, err := server.Tenant(ctx, tx, tenantText)
			if err != nil {
				return guardOutcome{}, err
			}
			tenantKey := jsString(tenant.Get("id"))
			// Callers from another tenant (and "view as" sessions) are refused before anything is looked up, so they
			// learn nothing about which resources exist.
			impersonating := truthy(principal.Session.Get("impersonatorId"))
			outsider := false
			if !impersonating && principal.Session.Get("tenantId") != tenant.Get("id") {
				root, err := server.RootPrincipal(ctx, tx, principal)
				if err != nil {
					return guardOutcome{}, err
				}
				outsider = !root
			}
			if impersonating || outsider {
				resourceID = g.collection
				reason := "tenant"
				if impersonating {
					reason = "impersonation"
				}
				if err := server.Events.Audit(ctx, tx, principal, label, tenantKey, g.collection, "deny", false, core.NewObject("reason", reason)); err != nil {
					return guardOutcome{}, err
				}
				return guardOutcome{denied: true}, nil
			}
			located, err := locate(ctx, tx, principal)
			if err != nil {
				return guardOutcome{}, err
			}
			if action.Of != nil {
				resolvedAction = action.Of(located)
			} else {
				resolvedAction = action.Name
			}
			target := located.Target()
			resourceID = target.ResourceID
			prepared := map[string]*PreparedDecision{}
			decision, err := g.Decide(ctx, tx, principal, tenant, resolvedAction, target, &located, prepared)
			if err != nil {
				return guardOutcome{}, err
			}
			if !decision.Allowed {
				// A refusal names what was asked for (a profile, a purpose) as an allowed call would.
				refused := core.NewObject()
				if described := g.describe(located); described != nil {
					refused.Assign(described)
				}
				if decision.Reason == "IMPERSONATION_RESTRICTED" {
					refused.Set("reason", "impersonation")
				}
				var metadata *core.Object
				if refused.Len() > 0 {
					metadata = refused
				}
				if err := server.Events.Audit(ctx, tx, principal, resolvedAction, tenantKey, target.ResourceID, "deny", false, metadata); err != nil {
					return guardOutcome{}, err
				}
				return guardOutcome{denied: true}, nil
			}
			// A call a delegation holds back uses up the person's one confirmation (rolled back if the call fails).
			if err := UseConfirmation(ctx, tx, principal, resolvedAction, "iam", target.ResourceID, server.Now()); err != nil {
				return guardOutcome{}, err
			}
			actor = principal
			hook := core.OperationHookInput{Store: tx, Principal: corePrincipal(principal), TenantID: tenantKey, Action: resolvedAction, ResourceID: target.ResourceID}
			for _, plugin := range server.Plugins {
				if plugin.Hooks != nil && plugin.Hooks.BeforeOperation != nil {
					if err := plugin.Hooks.BeforeOperation(ctx, hook); err != nil {
						return guardOutcome{}, err
					}
				}
			}
			metadata := core.NewObject()
			if described := g.describe(located); described != nil {
				metadata.Assign(described)
			}
			if decision.Note != nil {
				metadata.Assign(decision.Note)
			}
			value, err := fn(ctx, GuardCall{
				Tx: tx, Principal: principal, Tenant: tenant, Metadata: metadata,
				Allowed: func(ctx context.Context, other string, otherTarget GuardTarget) (bool, error) {
					result, err := g.Decide(ctx, tx, principal, tenant, other, otherTarget, nil, prepared)
					return result.Allowed, err
				},
			}, located)
			if err != nil {
				return guardOutcome{}, err
			}
			result := value
			if g.options.HookResult != nil {
				result = g.options.HookResult(value)
			}
			for _, plugin := range server.Plugins {
				if plugin.Hooks != nil && plugin.Hooks.AfterOperation != nil {
					after := hook
					after.Result = result
					if err := plugin.Hooks.AfterOperation(ctx, after); err != nil {
						return guardOutcome{}, err
					}
				}
			}
			var audited *core.Object
			if metadata.Len() > 0 {
				audited = metadata
			}
			rootOverride := decision.Reason == "ROOT_OVERRIDE"
			if err := server.Events.Audit(ctx, tx, principal, resolvedAction, tenantKey, target.ResourceID, "allow", rootOverride, audited); err != nil {
				return guardOutcome{}, err
			}
			return guardOutcome{value: value, rootOverride: rootOverride}, nil
		})
		if err == nil && outcome.denied {
			err = core.NewIamError("ACCESS_DENIED", "Access denied", 403)
		}
		if err != nil {
			reason := ""
			var refused *OperationDenied
			var known *core.IamError
			if errors.As(err, &refused) {
				reason = "refused"
			} else if errors.As(err, &known) && g.options.RecordedFailures != nil {
				reason = g.options.RecordedFailures[known.Code]
			}
			// actor is set only once the call was authorized.
			if actor != nil && reason != "" {
				// Bookkeeping never masks the failure.
				_ = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
					return server.Events.Audit(ctx, tx, actor, resolvedAction, tenantID, resourceID, "deny", false, core.NewObject("reason", reason))
				})
			}
			return nil, err
		}
		if !truthy(authenticated.Session.Get("impersonatorId")) && !outcome.rootOverride && server.Usage != nil {
			server.Usage.Record(tenantID, jsString(authenticated.Identity.Get("id")), resolvedAction)
		}
		return outcome.value, nil
	}, nil, nil)
}

// VisibleItem is one listed item and the target it is decided on.
type VisibleItem[I any] struct {
	Item   I
	Target GuardTarget
}

// GuardVisible is the guard's list page helper (visible): the items whose targets the caller may perform action on,
// decided per target (policies only) with one prepared decision. Refuses (and audits) callers the tenant refuses
// outright; otherwise audits one allowed event on resourceID with the number listed.
func GuardVisible[T Guarded, I any](ctx context.Context, g *Guard[T], credential core.CredentialInput, tenantID, action, resourceID string,
	load func(ctx context.Context, tx core.IamStore, tenant *core.Object) ([]VisibleItem[I], error)) ([]I, error) {
	server := g.ctx
	return Span(server.Observe, "operation", action, tenantID, func() ([]I, error) {
		authenticated, err := server.Principals.Authenticate(ctx, credential)
		if err != nil {
			return nil, err
		}
		type visibleOutcome struct {
			denied bool
			items  []I
		}
		outcome, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (visibleOutcome, error) {
			principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
			if err != nil {
				return visibleOutcome{}, err
			}
			tenantText, err := Text(tenantID, "tenantId")
			if err != nil {
				return visibleOutcome{}, err
			}
			tenant, err := server.Tenant(ctx, tx, tenantText)
			if err != nil {
				return visibleOutcome{}, err
			}
			tenantKey := jsString(tenant.Get("id"))
			refuse := func() (visibleOutcome, error) {
				if err := server.Events.Audit(ctx, tx, principal, action, tenantKey, resourceID, "deny", false, nil); err != nil {
					return visibleOutcome{}, err
				}
				return visibleOutcome{denied: true}, nil
			}
			if truthy(principal.Session.Get("impersonatorId")) {
				return refuse()
			}
			prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, tenant, action)
			if err != nil {
				return visibleOutcome{}, err
			}
			if prepared.Fixed != nil && !prepared.Fixed.Allowed {
				return refuse()
			}
			loaded, err := load(ctx, tx, tenant)
			if err != nil {
				return visibleOutcome{}, err
			}
			items := []I{}
			for _, entry := range loaded {
				decision, err := DecideOn(prepared, ResolvedResource{TenantID: tenantKey, Type: "iam", ID: entry.Target.ResourceID, Attributes: entry.Target.Attributes}, action)
				if err != nil {
					return visibleOutcome{}, err
				}
				if decision.Allowed {
					items = append(items, entry.Item)
				}
			}
			if err := server.Events.Audit(ctx, tx, principal, action, tenantKey, resourceID, "allow", IsRootOverride(prepared), core.NewObject("listed", float64(len(items)))); err != nil {
				return visibleOutcome{}, err
			}
			return visibleOutcome{items: items}, nil
		})
		if err != nil {
			return nil, err
		}
		if outcome.denied {
			return nil, core.NewIamError("ACCESS_DENIED", "Access denied", 403)
		}
		return outcome.items, nil
	}, nil, nil)
}
