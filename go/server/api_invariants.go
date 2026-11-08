package server

// Port of packages/server/src/api/invariants.ts: access invariants (guardrails), assertions about who may or must
// never perform an action on a resource, checked by `run` and, in `enforce` mode, around every operation that changes
// access. Reading needs `iam:invariants:read`; changing them needs `iam:invariants:manage`.

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// maxInvariants is the per-tenant invariant limit.
const maxInvariants = 100

// InvariantsAPI is the `invariants` API group (packages/server/src/api/invariants.ts createInvariantsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/invariants/{method} onto it.
type InvariantsAPI struct {
	server *ServerContext
}

// CreateInvariantsAPI builds the `invariants` API group.
func CreateInvariantsAPI(server *ServerContext) *InvariantsAPI {
	return &InvariantsAPI{server: server}
}

const invariantSubjectShape = "subject must be exactly one of identityId, groupId, attribute, or everyone"

// validInvariantSubject validates an invariant's subject (api/invariants.ts validSubject).
func validInvariantSubject(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, value any) (*core.Object, error) {
	subject, err := Object(value)
	if err != nil {
		return nil, err
	}
	if subject.Len() != 1 {
		return nil, invalidInput(invariantSubjectShape)
	}
	if raw := subject.Get("identityId"); !isUndefined(raw) {
		identityID, err := Text(raw, "subject.identityId")
		if err != nil {
			return nil, err
		}
		if _, err := server.Scoped(ctx, tx, "identities", identityID, tenantID); err != nil {
			return nil, err
		}
		return core.NewObject("identityId", identityID), nil
	}
	if raw := subject.Get("groupId"); !isUndefined(raw) {
		groupID, err := Text(raw, "subject.groupId")
		if err != nil {
			return nil, err
		}
		if _, err := server.Scoped(ctx, tx, "groups", groupID, tenantID); err != nil {
			return nil, err
		}
		return core.NewObject("groupId", groupID), nil
	}
	if raw := subject.Get("everyone"); !isUndefined(raw) {
		if raw != true {
			return nil, invalidInput("subject.everyone must be true")
		}
		return core.NewObject("everyone", true), nil
	}
	if raw := subject.Get("attribute"); !isUndefined(raw) {
		attribute, err := Object(raw)
		if err != nil {
			return nil, err
		}
		name, err := Text(attribute.Get("name"), "subject.attribute.name")
		if err != nil {
			return nil, err
		}
		kind := server.Catalog.IdentityAttributes.Get(name)
		if !truthy(kind) {
			return nil, invalidInput("Unknown identity attribute " + name)
		}
		if typeOf(attribute.Get("value")) != jsString(kind) {
			return nil, invalidInput("subject.attribute.value must be a " + jsString(kind))
		}
		return core.NewObject("attribute", core.NewObject("name", name, "value", attribute.Get("value"))), nil
	}
	return nil, invalidInput(invariantSubjectShape)
}

// SaveInvariant (api/invariants.ts saveInvariant): Creates (without `previous`) or updates an invariant after
// validating it like the API does; shared by the `invariants` API and configuration apply. `actorId` is recorded as
// the creator.
func SaveInvariant(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, input *core.Object, actorID string, previous *core.Object) (*core.Object, error) {
	fields, err := buildInvariant(ctx, server, tx, tenantID, input, previous)
	if err != nil {
		return nil, err
	}
	all, err := tx.Find(ctx, "accessInvariants", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	clash := []*core.Object{}
	for _, invariant := range all {
		if previous == nil || invariant.Get("id") != previous.Get("id") {
			clash = append(clash, invariant)
		}
	}
	for _, invariant := range clash {
		if invariant.Get("uniqueKey") == fields.Get("uniqueKey") {
			return nil, core.NewIamError("CONFLICT", "An invariant with this name exists", 409)
		}
	}
	if previous != nil {
		kept := previous.Spread()
		kept.Delete("description")
		return tx.Put(ctx, "accessInvariants", kept.Assign(fields))
	}
	if len(clash) >= maxInvariants {
		return nil, core.NewIamError("LIMIT_EXCEEDED", "At most 100 invariants", 409)
	}
	return tx.Insert(ctx, "accessInvariants", fields.Spread(core.NewObject(
		"id", ID(), "createdBy", actorID, "createdAt", fields.Get("updatedAt"),
	)))
}

// invariantField is `input[key] ?? previous?.[key]`.
func invariantField(input, previous *core.Object, key string) any {
	return coalesce(member(input, key), member(previous, key))
}

// buildInvariant derives the stored fields from input (api/invariants.ts build).
func buildInvariant(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, input, previous *core.Object) (*core.Object, error) {
	rawName, err := Text(invariantField(input, previous, "name"), "name", 100)
	if err != nil {
		return nil, err
	}
	name := core.JSTrim(rawName)
	if name == "" {
		return nil, invalidInput("name is required")
	}
	action, err := Text(invariantField(input, previous, "action"), "action")
	if err != nil {
		return nil, err
	}
	known, err := server.Catalog.KnownAction(ctx, tx, tenantID, action)
	if err != nil {
		return nil, err
	}
	if !known {
		return nil, core.NewIamError("INVALID_ACTION", "Unknown action "+action)
	}
	rawResource, err := Object(invariantField(input, previous, "resource"))
	if err != nil {
		return nil, err
	}
	resourceType, err := Text(rawResource.Get("type"), "resource type")
	if err != nil {
		return nil, err
	}
	resourceID, err := Text(rawResource.Get("id"), "resource id")
	if err != nil {
		return nil, err
	}
	// The resource must resolve now; an invariant over a resource that does not exist would never evaluate.
	if _, err := server.Decisions.Resolve(ctx, tx, core.ResourceRef{TenantID: tenantID, Type: resourceType, ID: resourceID}, true, "", nil); err != nil {
		return nil, err
	}
	expect := invariantField(input, previous, "expect")
	if expect != "allow" && expect != "deny" {
		return nil, invalidInput("expect must be allow or deny")
	}
	mode := coalesce(invariantField(input, previous, "mode"), "monitor")
	if mode != "enforce" && mode != "monitor" {
		return nil, invalidInput("mode must be enforce or monitor")
	}
	assumeMfa := coalesce(invariantField(input, previous, "assumeMfa"), true)
	if _, ok := assumeMfa.(bool); !ok {
		return nil, invalidInput("assumeMfa must be a boolean")
	}
	var description any = core.Undefined
	switch raw := member(input, "description"); {
	case isUndefined(raw):
		description = member(previous, "description")
	case raw == "":
	default:
		text, err := Text(raw, "description", 500)
		if err != nil {
			return nil, err
		}
		description = text
	}
	fields := core.NewObject("tenantId", tenantID, "uniqueKey", "name:"+core.JSLower(name), "name", name)
	if truthy(description) {
		fields.Set("description", description)
	}
	subject, err := validInvariantSubject(ctx, server, tx, tenantID, invariantField(input, previous, "subject"))
	if err != nil {
		return nil, err
	}
	fields.Set("subject", subject)
	fields.Set("action", action)
	fields.Set("resource", core.NewObject("type", resourceType, "id", resourceID))
	fields.Set("expect", expect)
	fields.Set("mode", mode)
	fields.Set("assumeMfa", assumeMfa)
	fields.Set("updatedAt", server.Now())
	return fields, nil
}

// invariantsByName sorts invariants by name (`a.name.localeCompare(b.name)`).
func invariantsByName(invariants []*core.Object) []*core.Object {
	sortStable(invariants, func(a, b *core.Object) int {
		return localeCompare(jsString(a.Get("name")), jsString(b.Get("name")))
	})
	return invariants
}

// invariantWithResult is `{ invariant, result }` after evaluating the saved invariant.
func invariantWithResult(ctx context.Context, server *ServerContext, tx core.IamStore, tenant, invariant *core.Object) (*core.Object, error) {
	results, err := EvaluateInvariants(ctx, server, tx, tenant, []*core.Object{invariant}, nil)
	if err != nil {
		return nil, err
	}
	return core.NewObject("invariant", invariant, "result", results[0]), nil
}

// Create is POST {basePath}/invariants/create. Stores an invariant (default mode `monitor`) and returns it with its
// current result.
func (api *InvariantsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.InvariantsCreateInput]) (Out[apitypes.InvariantsCreateOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:invariants:manage", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		invariant, err := SaveInvariant(ctx, server, call.Tx, jsString(call.Tenant.Get("id")), input.Body, jsString(call.Principal.Identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		return invariantWithResult(ctx, server, call.Tx, call.Tenant, invariant)
	}, false)
	return Out[apitypes.InvariantsCreateOutput]{Value: result}, err
}

// Delete is POST {basePath}/invariants/delete. Deletes an invariant, ending its monitoring and enforcement.
func (api *InvariantsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.InvariantsDeleteInput]) (Out[apitypes.InvariantsDeleteOutput], error) {
	server := api.server
	invariantID, err := Text(input.Get("invariantId"), "invariantId")
	if err != nil {
		return Out[apitypes.InvariantsDeleteOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:invariants:manage", invariantID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		invariant, err := server.Scoped(ctx, call.Tx, "accessInvariants", input.Get("invariantId"), jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		if err := call.Tx.Delete(ctx, "accessInvariants", jsString(invariant.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.InvariantsDeleteOutput]{Value: result}, err
}

// List is POST {basePath}/invariants/list. Lists the tenant's invariants by name, with the outcome of the last scheduled check.
func (api *InvariantsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.InvariantsListInput]) (Out[apitypes.InvariantsListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:invariants:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		invariants, err := call.Tx.Find(ctx, "accessInvariants", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		list := []any{}
		for _, invariant := range invariantsByName(invariants) {
			list = append(list, invariant)
		}
		return list, nil
	}, false)
	return Out[apitypes.InvariantsListOutput]{Value: result}, err
}

// Run is POST {basePath}/invariants/run. Evaluates every invariant, or one, against the current configuration and reports which pass.
func (api *InvariantsAPI) Run(ctx context.Context, credential core.CredentialInput, input In[apitypes.InvariantsRunInput]) (Out[apitypes.InvariantsRunOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	rawInvariantID := input.Get("invariantId")
	resourceID := jsString(tenantID)
	if !isUndefined(rawInvariantID) {
		text, err := Text(rawInvariantID, "invariantId")
		if err != nil {
			return Out[apitypes.InvariantsRunOutput]{}, err
		}
		resourceID = text
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:invariants:read", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		realmID := jsString(call.Tenant.Get("id"))
		var invariants []*core.Object
		if isUndefined(rawInvariantID) {
			found, err := call.Tx.Find(ctx, "accessInvariants", core.NewObject("tenantId", realmID), nil)
			if err != nil {
				return nil, err
			}
			invariants = invariantsByName(found)
		} else {
			invariant, err := server.Scoped(ctx, call.Tx, "accessInvariants", rawInvariantID, realmID)
			if err != nil {
				return nil, err
			}
			invariants = []*core.Object{invariant}
		}
		results, err := EvaluateInvariants(ctx, server, call.Tx, call.Tenant, invariants, nil)
		if err != nil {
			return nil, err
		}
		passed, failed, errorCount := 0, 0, 0
		list := make([]any, len(results))
		for index, result := range results {
			list[index] = result
			switch {
			case truthy(result.Get("error")):
				errorCount++
			case result.Get("passed") == true:
				passed++
			default:
				failed++
			}
		}
		return core.NewObject(
			"generatedAt", server.Now(),
			"summary", core.NewObject("passed", passed, "failed", failed, "errors", errorCount),
			"results", list,
		), nil
	}, false)
	return Out[apitypes.InvariantsRunOutput]{Value: result}, err
}

// Update is POST {basePath}/invariants/update. Changes any field of an invariant and returns it with its new result.
// Switching to `enforce` is allowed even while the invariant is broken.
func (api *InvariantsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.InvariantsUpdateInput]) (Out[apitypes.InvariantsUpdateOutput], error) {
	server := api.server
	invariantID, err := Text(input.Get("invariantId"), "invariantId")
	if err != nil {
		return Out[apitypes.InvariantsUpdateOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:invariants:manage", invariantID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		realmID := jsString(call.Tenant.Get("id"))
		previous, err := server.Scoped(ctx, call.Tx, "accessInvariants", input.Get("invariantId"), realmID)
		if err != nil {
			return nil, err
		}
		invariant, err := SaveInvariant(ctx, server, call.Tx, realmID, input.Body, jsString(call.Principal.Identity.Get("id")), previous)
		if err != nil {
			return nil, err
		}
		return invariantWithResult(ctx, server, call.Tx, call.Tenant, invariant)
	}, false)
	return Out[apitypes.InvariantsUpdateOutput]{Value: result}, err
}
