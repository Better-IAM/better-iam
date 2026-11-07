package server

// Port of packages/server/src/api/filters.ts: data filtering. Which resources of a type a principal may perform an
// action on, as a filter for the application's own queries (core.PlanResources), mirroring decisions.decide for
// every resource of the type.

import (
	"context"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// FiltersAPI is the `filters` API group (createFiltersApi).
type FiltersAPI struct {
	server *ServerContext
}

// CreateFiltersAPI builds the `filters` API group.
func CreateFiltersAPI(server *ServerContext) *FiltersAPI {
	return &FiltersAPI{server: server}
}

// planTarget validates the action and resource type of a plan request.
func planTarget(input *core.Object) (action, resourceType string, err error) {
	if action, err = Text(input.Get("action"), "action"); err != nil {
		return
	}
	if resourceType, err = Text(input.Get("type"), "type", 64); err != nil {
		return
	}
	if !ResourceTypeName.MatchString(resourceType) || InternalResourceTypes.Has(resourceType) {
		return "", "", invalidInput("Plans cover application and managed resource types")
	}
	// Platform administration (`iam:*`) resolves its own resources; plan application actions only.
	if strings.HasPrefix(action, "iam:") {
		return "", "", invalidInput("Plans cover application actions, not iam:* administration")
	}
	return action, resourceType, nil
}

// planModel is `{ tenantId, action, type, ...plan }`.
func planModel(tenantID, action, resourceType string, plan core.ResourcePlan) *core.Object {
	return core.NewObject("tenantId", tenantID, "action", action, "type", resourceType, "kind", plan.Kind, "filter", plan.Filter.ToValue())
}

// principalPlan is the plan for one principal.
func principalPlan(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, realm *core.Object, action, resourceType string) (core.ResourcePlan, error) {
	realmID := jsString(realm.Get("id"))
	known, err := server.Catalog.KnownAction(ctx, tx, realmID, action)
	if err != nil {
		return core.ResourcePlan{}, err
	}
	if !known {
		return core.FixedPlan(false), nil
	}
	prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, realm, action)
	if err != nil {
		return core.ResourcePlan{}, err
	}
	if prepared.Fixed != nil {
		return core.FixedPlan(prepared.Fixed.Allowed), nil
	}
	inputs := prepared.Inputs
	if inputs == nil {
		return core.FixedPlan(false), nil
	}
	// Mandatory access control: the resources the session may read at all, AND-ed with what the policies allow.
	var mandatory *core.ResourceFilter
	if inputs.Mandatory != nil {
		value, err := inputs.Mandatory.Filter(ctx, resourceType, action)
		if err != nil {
			return core.ResourcePlan{}, err
		}
		filter, err := core.FilterFromValue(value)
		if err != nil {
			return core.ResourcePlan{}, err
		}
		mandatory = &filter
	}
	if IsRootOverride(prepared) {
		if mandatory != nil {
			return core.IntersectPlans(core.FixedPlan(true), core.ResourcePlan{Kind: "conditional", Filter: *mandatory}), nil
		}
		return core.FixedPlan(true), nil
	}
	if inputs.Confirm != nil && inputs.Confirm(action, resourceType, "\u0000plan") != nil {
		return core.FixedPlan(false), nil
	}
	request := core.PlanInput{
		Action: action, ResourceType: resourceType, TenantID: realmID, Context: inputs.Context,
		Denies: inputs.Denies, Boundaries: inputs.Boundaries, Mandatory: mandatory,
	}
	// A label's keys are derived per resource, not read from the row: conditions on them cannot be planned.
	if server.Config.Clearances != nil {
		request.DerivedResourceKeys = ResourceServerKeys.Keys()
	}
	for _, path := range inputs.Paths {
		request.Paths = append(request.Paths, core.PlanPath{Grants: path.Grants, Boundaries: path.Boundaries})
	}
	// [...inputs.held]: insertion order of the relationship tuples.
	for _, key := range heldOrder(inputs) {
		slash := strings.Index(key, "/")
		request.Relations = append(request.Relations, core.PlanRelation{Type: key[:slash], ID: key[slash+1:], Relations: append([]string(nil), inputs.Held[key]...)})
	}
	return core.PlanResources(request)
}

// heldOrder is the keys of the held relations in the order they were first held.
func heldOrder(inputs *DecisionInputs) []string {
	if inputs.HeldOrder != nil || len(inputs.Held) == 0 {
		return inputs.HeldOrder
	}
	keys := make([]string, 0, len(inputs.Held))
	for key := range inputs.Held {
		keys = append(keys, key)
	}
	sortStable(keys, compareUTF16)
	return keys
}

// callerPlan is the caller's plan; a "view as" session gets only what the administrator behind it could reach too.
func callerPlan(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, realm *core.Object, action, resourceType string) (core.ResourcePlan, error) {
	own, err := principalPlan(ctx, server, tx, principal, realm, action, resourceType)
	if err != nil {
		return core.ResourcePlan{}, err
	}
	actor, err := ImpersonatingActor(ctx, tx, principal)
	if err != nil || actor == nil {
		return own, err
	}
	theirs, err := principalPlan(ctx, server, tx, actor, realm, action, resourceType)
	if err != nil {
		return core.ResourcePlan{}, err
	}
	return core.IntersectPlans(own, theirs), nil
}

// Plan is POST {basePath}/filters/plan: the caller's plan for action on resources of type (`always`, `never`, or
// `conditional` with a filter over `id` and the resource's attributes). Not audited.
func (api *FiltersAPI) Plan(ctx context.Context, credential core.CredentialInput, input In[apitypes.FiltersPlanInput]) (Out[apitypes.FiltersPlanOutput], error) {
	server := api.server
	body := input.Body
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.FiltersPlanOutput]{}, err
	}
	action, resourceType, err := planTarget(body)
	if err != nil {
		return Out[apitypes.FiltersPlanOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.FiltersPlanOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		realm, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		plan, err := callerPlan(ctx, server, tx, principal, realm, action, resourceType)
		if err != nil {
			return nil, err
		}
		return planModel(jsString(realm.Get("id")), action, resourceType, plan), nil
	})
	return Out[apitypes.FiltersPlanOutput]{Value: result}, err
}

// PlanFor is POST {basePath}/filters/planFor: an administrator's preview of another identity's plan, as
// policies.simulate does for one decision. Requires iam:policies:simulate on the identity; audited as that action.
func (api *FiltersAPI) PlanFor(ctx context.Context, credential core.CredentialInput, input In[apitypes.FiltersPlanForInput]) (Out[apitypes.FiltersPlanForOutput], error) {
	server := api.server
	body := input.Body
	action, resourceType, err := planTarget(body)
	if err != nil {
		return Out[apitypes.FiltersPlanForOutput]{}, err
	}
	identityID, err := Text(body.Get("identityId"), "identityId")
	if err != nil {
		return Out[apitypes.FiltersPlanForOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, jsString(body.Get("tenantId")), "iam:policies:simulate", identityID,
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			realmID := jsString(call.Tenant.Get("id"))
			identity, err := server.Scoped(ctx, call.Tx, "identities", body.Get("identityId"), realmID)
			if err != nil {
				return nil, err
			}
			if identity.Get("status") == "deleted" {
				return nil, core.NewIamError("NOT_FOUND", "Identity not found", 404)
			}
			principal := server.Decisions.SimulatedPrincipal(identity, body.Get("assumeMfa") == true)
			plan, err := principalPlan(ctx, server, call.Tx, principal, call.Tenant, action, resourceType)
			if err != nil {
				return nil, err
			}
			return planModel(realmID, action, resourceType, plan), nil
		}, false)
	return Out[apitypes.FiltersPlanForOutput]{Value: result}, err
}

// PlanResourcesRequest is a plan request for the caller: the credential and which resources, as Authorize takes them.
type PlanResourcesRequest struct {
	Credential core.CredentialInput `json:"-"`
	TenantID   string               `json:"tenantId"`
	Action     string               `json:"action"`
	Type       string               `json:"type"`
}

// CreatePlanRuntime is `iam.planResources`: the caller's plan in process, taking the credential in the request like
// Authorize.
func CreatePlanRuntime(server *ServerContext) func(ctx context.Context, request PlanResourcesRequest) (*core.Object, error) {
	api := CreateFiltersAPI(server)
	return func(ctx context.Context, request PlanResourcesRequest) (*core.Object, error) {
		// A fixed span name: actions are caller-controlled and would otherwise mint unbounded metric series.
		return Span(server.Observe, "listAccessible", "planResources", request.TenantID, func() (*core.Object, error) {
			out, err := api.Plan(ctx, request.Credential, Input[apitypes.FiltersPlanInput](core.NewObject(
				"tenantId", request.TenantID, "action", request.Action, "type", request.Type,
			)))
			if err != nil {
				return nil, err
			}
			result, _ := out.Value.(*core.Object)
			return result, nil
		}, nil, nil)
	}
}
