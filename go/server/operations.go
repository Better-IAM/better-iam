package server

// Port of packages/server/src/operations.ts: the transactional authorization envelope of every provisioning call
// (authenticate, re-validate the principal, authorize `action` on `iam/{resourceId}`, run the mutation, append one
// audit event), the authorization queries (authorize, authorizeMany, listAccessible) and plugin endpoints.

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// MutationContext is what an operation's mutation receives.
type MutationContext struct {
	Tx        core.IamStore
	Principal *Principal
	Tenant    *core.Object
}

// BatchResult is one answered check of authorizeMany.
type BatchResult struct {
	AuthorizationCheck
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// batchResults is `{ results }` as the TypeScript answer: action, resource, allowed, reason.
func batchResults(results []BatchResult) *core.Object {
	list := make([]any, len(results))
	for index, result := range results {
		list[index] = core.NewObject(
			"action", result.Action,
			"resource", core.NewObject("type", result.Resource.Type, "id", result.Resource.ID),
			"allowed", result.Allowed, "reason", result.Reason,
		)
	}
	return core.NewObject("results", list)
}

// AccessibleResources is the answer of listAccessible.
type AccessibleResources struct {
	Resources []*core.Object `json:"resources"`
	Total     int            `json:"total"`
}

// Model is `{ resources, total }` as the TypeScript answer.
func (a *AccessibleResources) Model() *core.Object {
	list := make([]any, len(a.Resources))
	for index, resource := range a.Resources {
		list[index] = resource
	}
	return core.NewObject("resources", list, "total", float64(a.Total))
}

// PluginCall is the input of callPlugin.
type PluginCall struct {
	PluginID string
	Path     string
	TenantID string
	Input    any
}

// OperationService is operations.ts OperationService.
type OperationService interface {
	// Operation is the transactional envelope of every provisioning call (see Operate for the typed form). A
	// denial commits only its audit record.
	Operation(ctx context.Context, credential core.CredentialInput, tenantID any, action, resourceID string, fn func(ctx context.Context, call MutationContext) (any, error), rootOnly bool) (any, error)
	// RecordedDecision is a decision that records denials and root overrides, with matched statements stripped.
	RecordedDecision(ctx context.Context, tx core.IamStore, current *Principal, request AuthorizationRequest) (core.Decision, error)
	Authorize(ctx context.Context, request AuthorizationRequest) (core.Decision, error)
	// AuthorizeMany evaluates up to 50 checks for one tenant in a single transaction (advisory UI state).
	AuthorizeMany(ctx context.Context, request BatchAuthorizationRequest) ([]BatchResult, error)
	// EvaluateMany is AuthorizeMany without the observability span.
	EvaluateMany(ctx context.Context, request BatchAuthorizationRequest) ([]BatchResult, error)
	// ListAccessible is the reverse query for list pages: the registered resources of one managed type the caller
	// may perform an action on.
	ListAccessible(ctx context.Context, request AccessibleResourcesRequest) (*AccessibleResources, error)
	// QueryAccessible is ListAccessible without the observability span.
	QueryAccessible(ctx context.Context, request AccessibleResourcesRequest) (*AccessibleResources, error)
	RequireAccess(ctx context.Context, request AuthorizationRequest) error
	// CallPlugin dispatches a plugin endpoint through the same envelope as built-in operations.
	CallPlugin(ctx context.Context, credential core.CredentialInput, call PluginCall) (any, error)
}

// Operate is OperationService.Operation with a typed result.
func Operate[T any](ctx context.Context, operations OperationService, credential core.CredentialInput, tenantID any, action, resourceID string, fn func(ctx context.Context, call MutationContext) (T, error), rootOnly bool) (T, error) {
	var zero T
	value, err := operations.Operation(ctx, credential, tenantID, action, resourceID, func(ctx context.Context, call MutationContext) (any, error) {
		return fn(ctx, call)
	}, rootOnly)
	if err != nil {
		return zero, err
	}
	typed, _ := value.(T)
	return typed, nil
}

// OperationDenied is thrown by a mutation to refuse an operation its permission alone does not cover (a protected
// target, for example). The mutation rolls back like any failure, and the operation then records the refusal as a
// deny audit event. It surfaces as ACCESS_DENIED (403) and unwraps to the IamError.
type OperationDenied struct {
	*core.IamError
}

func (e *OperationDenied) Unwrap() error { return e.IamError }

// NewOperationDenied builds the refusal; the message defaults to "Access denied".
func NewOperationDenied(message ...string) *OperationDenied {
	text := "Access denied"
	if len(message) > 0 {
		text = message[0]
	}
	return &OperationDenied{IamError: core.NewIamError("ACCESS_DENIED", text, 403)}
}

type operations struct {
	server *ServerContext
}

// CreateOperations builds the operation service (createOperations).
func CreateOperations(server *ServerContext) OperationService {
	return &operations{server: server}
}

func accessDenied() *core.IamError { return core.NewIamError("ACCESS_DENIED", "Access denied", 403) }

// auditRefusal records a refused decision. A principal of another tenant is refused before anything of the target
// is read, and so is its record: it goes to the caller's own tenant, naming the target. A clearance refusal is marked
// { mandatory: 'clearance' }.
func (o *operations) auditRefusal(ctx context.Context, tx core.IamStore, principal *Principal, action, tenantID, resourceID string, decision core.Decision) error {
	events := o.server.Events
	switch decision.Reason {
	case "TENANT_MISMATCH":
		return events.Audit(ctx, tx, principal, action, jsString(principal.Session.Get("tenantId")), resourceID, "deny", false, core.NewObject("targetTenantId", tenantID))
	case "CLEARANCE_REQUIRED":
		return events.Audit(ctx, tx, principal, action, tenantID, resourceID, "deny", false, core.NewObject("mandatory", "clearance"))
	}
	return events.Audit(ctx, tx, principal, action, tenantID, resourceID, "deny", false, nil)
}

type operationOutcome struct {
	denied       bool
	value        any
	rootOverride bool
}

func (o *operations) Operation(ctx context.Context, credential core.CredentialInput, rawTenantID any, action, resourceID string, fn func(ctx context.Context, call MutationContext) (any, error), rootOnly bool) (any, error) {
	server := o.server
	// The tenant ID is validated where TypeScript validates it: by ctx.tenant inside the transaction.
	tenantID, _ := rawTenantID.(string)
	return Span(server.Observe, "operation", action, tenantID, func() (any, error) {
		authenticated, err := server.Principals.Authenticate(ctx, credential)
		if err != nil {
			return nil, err
		}
		outcome, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (operationOutcome, error) {
			principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
			if err != nil {
				return operationOutcome{}, err
			}
			target, err := server.Tenant(ctx, tx, rawTenantID)
			if err != nil {
				return operationOutcome{}, err
			}
			decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
				TenantID: tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: resourceID},
			}, true)
			if err != nil {
				return operationOutcome{}, err
			}
			refused := !decision.Allowed
			if !refused && rootOnly {
				root, err := server.RootPrincipal(ctx, tx, principal)
				if err != nil {
					return operationOutcome{}, err
				}
				refused = !root
			}
			if refused {
				if err := o.auditRefusal(ctx, tx, principal, action, tenantID, resourceID, decision); err != nil {
					return operationOutcome{}, err
				}
				return operationOutcome{denied: true}, nil
			}
			// An operation a delegation holds back uses up the person's confirmation (rolled back if it fails).
			if err := UseConfirmation(ctx, tx, principal, action, "iam", resourceID, server.Now()); err != nil {
				return operationOutcome{}, err
			}
			hook := core.OperationHookInput{Store: tx, Principal: corePrincipal(principal), TenantID: tenantID, Action: action, ResourceID: resourceID}
			for _, plugin := range server.Plugins {
				if plugin.Hooks != nil && plugin.Hooks.BeforeOperation != nil {
					if err := plugin.Hooks.BeforeOperation(ctx, hook); err != nil {
						return operationOutcome{}, err
					}
				}
			}
			separation, err := SodSnapshot(ctx, server, tx, tenantID, action)
			if err != nil {
				return operationOutcome{}, err
			}
			guardrails, err := InvariantSnapshot(ctx, server, tx, tenantID, action)
			if err != nil {
				return operationOutcome{}, err
			}
			value, err := fn(ctx, MutationContext{Tx: tx, Principal: principal, Tenant: target})
			if err != nil {
				return operationOutcome{}, err
			}
			if err := SodVerify(ctx, server, tx, tenantID, separation, nil); err != nil {
				return operationOutcome{}, err
			}
			if err := InvariantVerify(ctx, server, tx, tenantID, guardrails); err != nil {
				return operationOutcome{}, err
			}
			for _, plugin := range server.Plugins {
				if plugin.Hooks != nil && plugin.Hooks.AfterOperation != nil {
					after := hook
					after.Result = value
					if err := plugin.Hooks.AfterOperation(ctx, after); err != nil {
						return operationOutcome{}, err
					}
				}
			}
			rootOverride := decision.Reason == "ROOT_OVERRIDE"
			if err := server.Events.Audit(ctx, tx, principal, action, tenantID, resourceID, "allow", rootOverride, nil); err != nil {
				return operationOutcome{}, err
			}
			return operationOutcome{value: value, rootOverride: rootOverride}, nil
		})
		if err != nil {
			// A mutation that refuses with OperationDenied is rolled back like any failure; the refusal is then
			// recorded in its own transaction as a deny event. Bookkeeping never masks the refusal.
			var denied *OperationDenied
			if errors.As(err, &denied) {
				_ = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
					return server.Events.Audit(ctx, tx, authenticated, action, tenantID, resourceID, "deny", false, nil)
				})
			}
			return nil, err
		}
		if outcome.denied {
			return nil, accessDenied()
		}
		// Access usage: what the person used through their grants, not a root override or impersonation. Recorded
		// after the commit.
		if !truthy(authenticated.Session.Get("impersonatorId")) && !outcome.rootOverride {
			server.Usage.Record(tenantID, jsString(authenticated.Identity.Get("id")), action)
		}
		return outcome.value, nil
	}, nil, nil)
}

func (o *operations) RecordedDecision(ctx context.Context, tx core.IamStore, current *Principal, request AuthorizationRequest) (core.Decision, error) {
	server := o.server
	decision, err := server.Decisions.Decide(ctx, tx, current, request, false)
	if err != nil {
		return core.Decision{}, err
	}
	if decision.Allowed && decision.Reason != "ROOT_OVERRIDE" && !truthy(current.Session.Get("impersonatorId")) {
		server.Usage.Record(request.TenantID, jsString(current.Identity.Get("id")), request.Action)
	}
	if !decision.Allowed {
		if err := o.auditRefusal(ctx, tx, current, request.Action, request.TenantID, request.Resource.ID, decision); err != nil {
			return core.Decision{}, err
		}
	} else if decision.Reason == "ROOT_OVERRIDE" {
		if err := server.Events.Audit(ctx, tx, current, request.Action, request.TenantID, request.Resource.ID, "allow", true, nil); err != nil {
			return core.Decision{}, err
		}
	}
	reason := "ACCESS_DENIED"
	if decision.Allowed {
		reason = decision.Reason
	}
	return core.Decision{Allowed: decision.Allowed, Reason: reason, Matched: []string{}}, nil
}

func spanName(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func (o *operations) Authorize(ctx context.Context, request AuthorizationRequest) (core.Decision, error) {
	server := o.server
	return Span(server.Observe, "authorize", spanName(request.Action, "invalid"), request.TenantID, func() (core.Decision, error) {
		principal, err := server.Principals.Authenticate(ctx, request.Credential)
		if err != nil {
			return core.Decision{}, err
		}
		return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (core.Decision, error) {
			current, err := server.Principals.CurrentPrincipal(ctx, tx, principal)
			if err != nil {
				return core.Decision{}, err
			}
			decision, err := o.RecordedDecision(ctx, tx, current, request)
			if err != nil {
				return core.Decision{}, err
			}
			// A person's confirmation of an agent's held-back action opens one call: this check is that call and uses
			// it up. Batch and listing checks never do.
			if decision.Allowed {
				if err := UseConfirmation(ctx, tx, current, request.Action, request.Resource.Type, request.Resource.ID, server.Now()); err != nil {
					return core.Decision{}, err
				}
			}
			return decision, nil
		})
	}, func(decision core.Decision) SpanResult {
		outcome := "denied"
		if decision.Allowed {
			outcome = "ok"
		}
		return SpanResult{Outcome: outcome, Code: decision.Reason}
	}, nil)
}

func (o *operations) AuthorizeMany(ctx context.Context, request BatchAuthorizationRequest) ([]BatchResult, error) {
	return Span(o.server.Observe, "authorizeMany", "authorizeMany", request.TenantID, func() ([]BatchResult, error) {
		return o.EvaluateMany(ctx, request)
	}, nil, nil)
}

// checksValue is the checks as a model value (the request's own, or the typed ones).
func checksValue(request BatchAuthorizationRequest) any {
	if request.ChecksValue != nil {
		return request.ChecksValue
	}
	if request.Checks == nil {
		return core.Undefined
	}
	list := make([]any, len(request.Checks))
	for index, check := range request.Checks {
		list[index] = core.NewObject("action", check.Action, "resource", core.NewObject("type", check.Resource.Type, "id", check.Resource.ID))
	}
	return list
}

func (o *operations) EvaluateMany(ctx context.Context, request BatchAuthorizationRequest) ([]BatchResult, error) {
	server := o.server
	tenantID, err := Text(request.TenantID, "tenantId")
	if err != nil {
		return nil, err
	}
	list, isList := checksValue(request).([]any)
	if !isList || len(list) == 0 || len(list) > 50 {
		return nil, invalidInput("Provide 1-50 authorization checks")
	}
	checks := make([]AuthorizationCheck, len(list))
	for index, check := range list {
		item, err := Object(check)
		if err != nil {
			return nil, err
		}
		resource, err := Object(item.Get("resource"))
		if err != nil {
			return nil, err
		}
		action, err := Text(item.Get("action"), "action")
		if err != nil {
			return nil, err
		}
		resourceType, err := Text(resource.Get("type"), "resource type")
		if err != nil {
			return nil, err
		}
		resourceID, err := Text(resource.Get("id"), "resource id")
		if err != nil {
			return nil, err
		}
		checks[index] = AuthorizationCheck{Action: action, Resource: ResourceTarget{Type: resourceType, ID: resourceID}}
	}
	principal, err := server.Principals.Authenticate(ctx, request.Credential)
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]BatchResult, error) {
		current, err := server.Principals.CurrentPrincipal(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		results := []BatchResult{}
		for _, check := range checks {
			decision, err := o.RecordedDecision(ctx, tx, current, AuthorizationRequest{TenantID: tenantID, Action: check.Action, Resource: check.Resource})
			if err != nil {
				return nil, err
			}
			results = append(results, BatchResult{AuthorizationCheck: check, Allowed: decision.Allowed, Reason: decision.Reason})
		}
		return results, nil
	})
}

func (o *operations) ListAccessible(ctx context.Context, request AccessibleResourcesRequest) (*AccessibleResources, error) {
	return Span(o.server.Observe, "listAccessible", spanName(request.Action, "invalid"), request.TenantID, func() (*AccessibleResources, error) {
		return o.QueryAccessible(ctx, request)
	}, nil, nil)
}

// pageValue is a limit or offset as the request gave it, the default for none.
func pageValue(value any, typed *float64, fallback float64) any {
	if value == nil && typed != nil {
		value = *typed
	}
	if nullish(value) {
		return fallback
	}
	return value
}

func (o *operations) QueryAccessible(ctx context.Context, request AccessibleResourcesRequest) (*AccessibleResources, error) {
	server := o.server
	tenantID, err := Text(request.TenantID, "tenantId")
	if err != nil {
		return nil, err
	}
	action, err := Text(request.Action, "action")
	if err != nil {
		return nil, err
	}
	resourceType, err := Text(request.Type, "resource type", 64)
	if err != nil {
		return nil, err
	}
	limit, err := Integer(pageValue(request.LimitValue, request.Limit, 100), "limit", 1, 1000)
	if err != nil {
		return nil, err
	}
	offset, err := Integer(pageValue(request.OffsetValue, request.Offset, 0), "offset", 0, 1000000)
	if err != nil {
		return nil, err
	}
	principal, err := server.Principals.Authenticate(ctx, request.Credential)
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*AccessibleResources, error) {
		current, err := server.Principals.CurrentPrincipal(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		target, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		targetID := jsString(target.Get("id"))
		known, err := server.Catalog.KnownAction(ctx, tx, targetID, action)
		if err != nil {
			return nil, err
		}
		if !known {
			return nil, core.NewIamError("INVALID_ACTION", "Unknown action "+action)
		}
		definition, err := server.Catalog.ManagedDefinition(ctx, tx, targetID, resourceType)
		if err != nil {
			return nil, err
		}
		if ShadowsApplicationType(definition, resourceType, action, true, server.Options.ResolveResource != nil) {
			return nil, core.NewIamError("INVALID_RESOURCE_TYPE", "This resource type is resolved by the application, not registered with IAM")
		}
		prepared, err := server.Decisions.PrepareDecision(ctx, tx, current, target, action)
		if err != nil {
			return nil, err
		}
		// An impersonation session lists only what the administrator behind it could reach too.
		actor, err := ImpersonatingActor(ctx, tx, current)
		if err != nil {
			return nil, err
		}
		var own *PreparedDecision
		if actor != nil {
			if own, err = server.Decisions.PrepareDecision(ctx, tx, actor, target, action); err != nil {
				return nil, err
			}
		}
		// Security clearances: every registration's effective label, read once for the type.
		var labels map[string]*core.Object
		if server.Config.Clearances != nil {
			if labels, err = LabelsForType(ctx, tx, targetID, definition.Name); err != nil {
				return nil, err
			}
		}
		resolved := func(item *core.Object) ResolvedResource {
			resource := ResolvedManaged(item)
			if labels != nil {
				resource.HasClassification = true
				if label, found := labels[jsString(item.Get("resourceId"))]; found && label != nil {
					resource.Classification = label
				}
			}
			return resource
		}
		allows := func(evaluator *PreparedDecision, item *core.Object) (bool, error) {
			decision, err := DecideOn(evaluator, resolved(item), "")
			return decision.Allowed, err
		}
		records, err := tx.Find(ctx, "resources", core.NewObject("tenantId", targetID, "type", definition.Name), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(records, func(i, j int) bool {
			return compareUTF16(jsString(records[i].Get("uniqueKey")), jsString(records[j].Get("uniqueKey"))) < 0
		})
		accessible := []*core.Object{}
		for _, item := range records {
			allowed, err := allows(prepared, item)
			if err != nil {
				return nil, err
			}
			if allowed && own != nil {
				if allowed, err = allows(own, item); err != nil {
					return nil, err
				}
			}
			if allowed {
				accessible = append(accessible, item)
			}
		}
		// Listing what one may act on is using the action (not for root overrides or impersonation).
		if len(accessible) > 0 && !truthy(current.Session.Get("impersonatorId")) && !IsRootOverride(prepared) {
			server.Usage.Record(targetID, jsString(current.Identity.Get("id")), action)
		}
		start := min(int(offset), len(accessible))
		end := min(start+int(limit), len(accessible))
		return &AccessibleResources{Resources: accessible[start:end], Total: len(accessible)}, nil
	})
}

func (o *operations) RequireAccess(ctx context.Context, request AuthorizationRequest) error {
	decision, err := o.Authorize(ctx, request)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return accessDenied()
	}
	return nil
}

func (o *operations) CallPlugin(ctx context.Context, credential core.CredentialInput, call PluginCall) (any, error) {
	server := o.server
	pluginID, err := Text(call.PluginID, "pluginId")
	if err != nil {
		return nil, err
	}
	path, err := Text(call.Path, "path")
	if err != nil {
		return nil, err
	}
	path = strings.TrimPrefix(path, "/")
	tenantID, err := Text(call.TenantID, "tenantId")
	if err != nil {
		return nil, err
	}
	endpoint := pluginEndpoint(server.Plugins, pluginID, path)
	if endpoint == nil {
		return nil, endpointNotFound()
	}
	input := call.Input
	if nullish(input) {
		input = core.NewObject()
	}
	raw, err := Object(input)
	if err != nil {
		return nil, err
	}
	if raw.Has("tenantId") && raw.Get("tenantId") != tenantID {
		return nil, invalidInput("Plugin input tenant does not match request scope")
	}
	checked, err := endpoint.Validate(raw.Spread(core.NewObject("tenantId", tenantID)))
	if err != nil {
		return nil, err
	}
	validated, err := Object(checked)
	if err != nil {
		return nil, err
	}
	if validated.Has("tenantId") && validated.Get("tenantId") != tenantID {
		return nil, invalidInput("Plugin validation changed tenant scope")
	}
	// Per-record endpoints are authorized on the record they name, tenant-wide ones on the tenant.
	resourceID := tenantID
	if endpoint.Resource != nil {
		if resourceID, err = Text(endpoint.Resource(validated), "plugin resource", 512); err != nil {
			return nil, err
		}
	}
	return server.Operations.Operation(ctx, credential, tenantID, endpoint.Action, resourceID, func(ctx context.Context, mutation MutationContext) (any, error) {
		return endpoint.Handler(ctx, core.PluginEndpointContext{
			Store: mutation.Tx, Principal: corePrincipal(mutation.Principal), TenantID: tenantID,
			Deliver: func(ctx context.Context, delivery core.PluginDelivery) (string, error) {
				payload := core.NewObject()
				keys := make([]string, 0, len(delivery.Payload))
				for key := range delivery.Payload {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					payload.Set(key, delivery.Payload[key])
				}
				return server.Auth.EnqueueDelivery(ctx, mutation.Tx, auth.EnqueueInput{
					TenantID: tenantID, Kind: delivery.Kind, To: delivery.To, Template: delivery.Template, Payload: payload,
				})
			},
		}, validated)
	}, false)
}
