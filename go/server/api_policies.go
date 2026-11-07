package server

// Port of packages/server/src/api/policies.ts: the `policies` API group (versioned policy documents, document tests,
// simulations and access reviews) and the policy helpers configuration sync shares.

import (
	"context"
	"errors"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// PoliciesAPI is the `policies` API group (packages/server/src/api/policies.ts createPoliciesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/policies/{method} onto it.
type PoliciesAPI struct {
	server *ServerContext
}

// CreatePoliciesAPI builds the `policies` API group.
func CreatePoliciesAPI(server *ServerContext) *PoliciesAPI {
	return &PoliciesAPI{server: server}
}

// Create is POST {basePath}/policies/create. Stores a new policy document at version 1 under your grant authority.
func (api *PoliciesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesCreateInput]) (Out[apitypes.PoliciesCreateOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:policies:create", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return CreatePolicy(ctx, api.server, call.Tx, call.Principal, call.Tenant, input.Body)
	}, false)
	return Out[apitypes.PoliciesCreateOutput]{Value: result}, err
}

// Delete is POST {basePath}/policies/delete. Deletes a policy that no role attaches.
func (api *PoliciesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesDeleteInput]) (Out[apitypes.PoliciesDeleteOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:policies:delete", jsString(input.Get("policyId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		policy, err := api.server.Scoped(ctx, call.Tx, "policies", input.Get("policyId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if err := DeletePolicy(ctx, api.server, call.Tx, call.Principal, policy); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.PoliciesDeleteOutput]{Value: result}, err
}

// reviewResource resolves the resource reference of an access review (`{ type, id }`): reviews accept platform
// resources (`iam/...`) as well as catalog resources.
func reviewResource(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, value any) (*ResolvedResource, error) {
	reference, err := Object(value)
	if err != nil {
		return nil, err
	}
	resourceType, err := Text(reference.Get("type"), "resource type")
	if err != nil {
		return nil, err
	}
	resourceID, err := Text(reference.Get("id"), "resource id")
	if err != nil {
		return nil, err
	}
	return server.Decisions.Resolve(ctx, tx, core.ResourceRef{TenantID: tenantID, Type: resourceType, ID: resourceID}, true, "", nil)
}

// EffectiveActions is POST {basePath}/policies/effectiveActions. Access review: which catalog actions (or the given
// `actions`) an identity could perform on one resource. Grants are loaded once and evaluated per action. Advisory,
// like `simulate`.
func (api *PoliciesAPI) EffectiveActions(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesEffectiveActionsInput]) (Out[apitypes.PoliciesEffectiveActionsOutput], error) {
	server := api.server
	catalog := server.Catalog
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:policies:simulate", jsString(input.Get("identityId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, call.Tenant
		tenantKey := jsString(tenant.Get("id"))
		identity, err := server.Scoped(ctx, tx, "identities", input.Get("identityId"), tenantKey)
		if err != nil {
			return nil, err
		}
		resource, err := reviewResource(ctx, server, tx, tenantKey, input.Get("resource"))
		if err != nil {
			return nil, err
		}
		var candidates []string
		if value := input.Get("actions"); !isUndefined(value) {
			listed, err := Strings(value, "actions")
			if err != nil {
				return nil, err
			}
			candidates = unique(listed)
			if len(candidates) > 200 {
				return nil, invalidInput("Review at most 200 actions at once")
			}
			for _, action := range candidates {
				known, err := catalog.KnownAction(ctx, tx, tenantKey, action)
				if err != nil {
					return nil, err
				}
				if !known {
					return nil, core.NewIamError("INVALID_ACTION", "Unknown action "+action)
				}
			}
		} else {
			tenantActions, err := tx.Find(ctx, "actions", core.NewObject("tenantId", tenantKey), nil)
			if err != nil {
				return nil, err
			}
			candidates = append([]string(nil), catalog.Actions.Values()...)
			for _, item := range tenantActions {
				candidates = append(candidates, jsString(item.Get("name")))
			}
		}
		sortStable(candidates, compareUTF16)
		principal := server.Decisions.SimulatedPrincipal(identity, input.Get("assumeMfa") == true)
		first := "*"
		if len(candidates) > 0 {
			first = candidates[0]
		}
		prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, tenant, first)
		if err != nil {
			return nil, err
		}
		results := []any{}
		allowed := []any{}
		for _, action := range candidates {
			decision, err := DecideOn(prepared, *resource, action)
			if err != nil {
				return nil, err
			}
			results = append(results, core.NewObject("action", action, "allowed", decision.Allowed, "reason", decision.Reason))
			if decision.Allowed {
				allowed = append(allowed, action)
			}
		}
		return core.NewObject("allowed", allowed, "results", results), nil
	}, false)
	return Out[apitypes.PoliciesEffectiveActionsOutput]{Value: result}, err
}

// Get is POST {basePath}/policies/get. Returns one policy with its current document and version.
func (api *PoliciesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesGetInput]) (Out[apitypes.PoliciesGetOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:policies:read", jsString(input.Get("policyId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return api.server.Scoped(ctx, call.Tx, "policies", input.Get("policyId"), jsString(tenantID))
	}, false)
	return Out[apitypes.PoliciesGetOutput]{Value: result}, err
}

// List is POST {basePath}/policies/list. Lists every policy in the tenant at its current version, including the
// protected Owner policy.
func (api *PoliciesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesListInput]) (Out[apitypes.PoliciesListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:policies:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		policies, err := call.Tx.Find(ctx, "policies", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		return objectsOf(policies), nil
	}, false)
	return Out[apitypes.PoliciesListOutput]{Value: result}, err
}

// ListVersions is POST {basePath}/policies/listVersions. Returns a policy's full history, oldest first, ending with
// the current version.
func (api *PoliciesAPI) ListVersions(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesListVersionsInput]) (Out[apitypes.PoliciesListVersionsOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:policies:read", jsString(input.Get("policyId")), func(ctx context.Context, call MutationContext) ([]any, error) {
		policy, err := api.server.Scoped(ctx, call.Tx, "policies", input.Get("policyId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		archived, err := call.Tx.Find(ctx, "policyVersions", core.NewObject("tenantId", tenantID, "policyId", policy.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		versions := make([]*core.Object, 0, len(archived)+1)
		for _, version := range archived {
			entry := version.Spread()
			entry.Delete("uniqueKey")
			versions = append(versions, entry)
		}
		versions = append(versions, policy)
		sortStable(versions, func(a, b *core.Object) int {
			difference := jsNumber(a.Get("version")) - jsNumber(b.Get("version"))
			switch {
			case difference < 0:
				return -1
			case difference > 0:
				return 1
			}
			return 0
		})
		return objectsOf(versions), nil
	}, false)
	return Out[apitypes.PoliciesListVersionsOutput]{Value: result}, err
}

// archivePolicyVersion keeps the current version of a policy in its history (`policyVersions`).
func archivePolicyVersion(ctx context.Context, tx core.IamStore, policy *core.Object) error {
	_, err := tx.Insert(ctx, "policyVersions", policy.Spread(core.NewObject(
		"id", ID(), "policyId", policy.Get("id"),
		"uniqueKey", jsString(policy.Get("id"))+":"+jsString(policy.Get("version")),
	)))
	return err
}

// RestoreVersion is POST {basePath}/policies/restoreVersion. Rolls a policy back to an earlier document as a new
// version; the old document is re-validated against the catalog.
func (api *PoliciesAPI) RestoreVersion(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesRestoreVersionInput]) (Out[apitypes.PoliciesRestoreVersionOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:policies:update", jsString(input.Get("policyId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		policy, err := server.Scoped(ctx, tx, "policies", input.Get("policyId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if _, err := server.GrantingAuthority(ctx, tx, principal, jsString(tenantID), ""); err != nil {
			return nil, err
		}
		if err := server.CanEditGrantResource(ctx, tx, principal, policy); err != nil {
			return nil, err
		}
		if policy.Get("uniqueKey") == "system:owner" {
			return nil, core.NewIamError("PROTECTED_RESOURCE", "Owner policy is protected", 403)
		}
		current := jsNumber(policy.Get("version"))
		version, err := Integer(input.Get("version"), "version", 1, current)
		if err != nil {
			return nil, err
		}
		if version == current {
			return nil, invalidInput("That version is already current")
		}
		found, err := tx.Find(ctx, "policyVersions", core.NewObject(
			"tenantId", tenantID, "uniqueKey", jsString(policy.Get("id"))+":"+core.NumberString(version),
		), nil)
		if err != nil {
			return nil, err
		}
		if len(found) == 0 {
			return nil, core.NewIamError("NOT_FOUND", "Policy version not found", 404)
		}
		archived := found[0]
		if err := server.Catalog.Validate(ctx, tx, jsString(tenantID), archived.Get("document")); err != nil {
			return nil, err
		}
		if err := assertPolicyDeniesKept(ctx, server, tx, principal, policy, archived.Get("document")); err != nil {
			return nil, err
		}
		if err := archivePolicyVersion(ctx, tx, policy); err != nil {
			return nil, err
		}
		return tx.Put(ctx, "policies", policy.Spread(core.NewObject("document", archived.Get("document"), "version", current+1)))
	}, false)
	return Out[apitypes.PoliciesRestoreVersionOutput]{Value: result}, err
}

// Simulate is POST {basePath}/policies/simulate. Administrator-only explanation of a decision for any identity; it
// creates no session and grants nothing. `assumeMfa` simulates an MFA session.
func (api *PoliciesAPI) Simulate(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesSimulateInput]) (Out[apitypes.PoliciesSimulateOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:policies:simulate", jsString(input.Get("identityId")), func(ctx context.Context, call MutationContext) (any, error) {
		tx := call.Tx
		identity, err := server.Scoped(ctx, tx, "identities", input.Get("identityId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		// The request as TypeScript reads it: decide validates the action and the resource members itself (a
		// non-string becomes the empty text, which fails the same way).
		action, _ := input.Get("action").(string)
		resource := input.Get("resource")
		resourceType, _ := member(resource, "type").(string)
		resourceID, _ := member(resource, "id").(string)
		decision, err := server.Decisions.Decide(ctx, tx, server.Decisions.SimulatedPrincipal(identity, input.Get("assumeMfa") == true), AuthorizationRequest{
			TenantID: jsString(tenantID), Action: action, Resource: ResourceTarget{Type: resourceType, ID: resourceID},
		}, false)
		if err != nil {
			// Reading the type of a missing resource is a TypeError in TypeScript, at the point the resource is
			// first read (after the refusals that do not depend on it).
			var known *core.IamError
			if nullish(resource) && errors.As(err, &known) && known.Code == "INVALID_INPUT" && known.Message == "Invalid resource type" {
				return nil, &core.TypeError{Message: "Cannot read properties of " + jsString(resource) + " (reading 'type')"}
			}
			return nil, err
		}
		return ToModel(decision)
	}, false)
	return Out[apitypes.PoliciesSimulateOutput]{Value: result}, err
}

// Test is POST {basePath}/policies/test. Evaluates a candidate document (not stored) against an action, a resource
// string, and a caller-supplied context, for policy editors. Requires iam:policies:simulate. The document is
// validated against the catalog first.
func (api *PoliciesAPI) Test(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesTestInput]) (Out[apitypes.PoliciesTestOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:policies:simulate", jsString(tenantID), func(ctx context.Context, call MutationContext) (any, error) {
		tx, tenant := call.Tx, call.Tenant
		tenantKey := jsString(tenant.Get("id"))
		document := input.Get("document")
		if err := server.Catalog.Validate(ctx, tx, tenantKey, document); err != nil {
			return nil, err
		}
		supplied, err := Object(coalesce(input.Get("context"), core.NewObject()))
		if err != nil {
			return nil, err
		}
		callerContext := supplied.Spread()
		if callerContext.Len() > 200 {
			return nil, invalidInput("context may hold at most 200 keys")
		}
		now := isoString(float64(server.Now()))
		action, err := Text(input.Get("action"), "action")
		if err != nil {
			return nil, err
		}
		resource, err := Text(input.Get("resource"), "resource", 2048)
		if err != nil {
			return nil, err
		}
		// Defaults for the always-present server keys, as a synthetic session issued now would carry them; the
		// caller's context overrides any of them.
		evaluation := core.NewObject(
			"resource.tenantId", tenant.Get("id"),
			"principal.tenantId", tenant.Get("id"),
			"principal.sessionId", "simulation",
			"principal.tokenIssueTime", now,
			"principal.authTime", now,
			"principal.sessionTagKeys", []any{},
			"principal.delegated", false,
			// Threat detection keys as for a person nothing was detected about (threats.ts).
			"principal.riskLevel", "none",
			"principal.riskScore", 0.0,
			// No license seats (licenses.ts), as for a person nothing was assigned to.
			"principal.licenses", []any{},
			// A member rather than a guest (guests.ts).
			"principal.guest", false,
			// Device posture keys as for a request without a verified device (devices.ts).
			"request.deviceAssurance", "none",
			"request.deviceManaged", false,
			"request.deviceCompliant", false,
		)
		// With security clearances (clearances.ts): an uncleared person and an unlabeled resource. A document test
		// never applies mandatory access control itself.
		if server.Config.Clearances != nil {
			evaluation.Assign(core.NewObject(
				"principal.clearanceRank", -1.0,
				"principal.clearanceStatus", "none",
				"principal.clearanceCompartments", []any{},
				"principal.clearanceCitizenship", []any{},
				"resource.classificationRank", -1.0,
				"resource.compartments", []any{},
				"resource.noforn", false,
				"resource.releasableTo", []any{},
			))
		}
		evaluation.Set("request.time", now)
		// The tenant's feature flags as they are now, read only when the document names them.
		if MentionsFeatures([]any{document}) {
			chain, err := server.Ancestry(ctx, tx, tenant)
			if err != nil {
				return nil, err
			}
			state, err := FeatureState(ctx, tx, chain, server.Now())
			if err != nil {
				return nil, err
			}
			keys, err := EnabledFeatureKeys(state)
			if err != nil {
				return nil, err
			}
			evaluation.Set(FeatureContextKey, stringsOf(keys))
		}
		evaluation.Assign(callerContext)
		decision, err := core.EvaluatePolicy(core.EvaluationInput{Action: action, Resource: resource, Context: evaluation, Grants: []any{document}})
		if err != nil {
			return nil, err
		}
		return ToModel(decision)
	}, false)
	return Out[apitypes.PoliciesTestOutput]{Value: result}, err
}

// Update is POST {basePath}/policies/update. Optimistic concurrency: the caller supplies the version it read; previous
// versions are retained.
func (api *PoliciesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesUpdateInput]) (Out[apitypes.PoliciesUpdateOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:policies:update", jsString(input.Get("policyId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return UpdatePolicy(ctx, api.server, call.Tx, call.Principal, input.Body)
	}, false)
	return Out[apitypes.PoliciesUpdateOutput]{Value: result}, err
}

// WhoCan is POST {basePath}/policies/whoCan. Access review: every active identity of the tenant that could perform
// `action` on `resource`, with the reason. Root administrators are not listed: their override applies everywhere
// (except, with security clearances, to labeled resources above their own clearance). Advisory, like `simulate`.
func (api *PoliciesAPI) WhoCan(ctx context.Context, credential core.CredentialInput, input In[apitypes.PoliciesWhoCanInput]) (Out[apitypes.PoliciesWhoCanOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:policies:simulate", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, call.Tenant
		tenantKey := jsString(tenant.Get("id"))
		action, err := Text(input.Get("action"), "action")
		if err != nil {
			return nil, err
		}
		known, err := server.Catalog.KnownAction(ctx, tx, tenantKey, action)
		if err != nil {
			return nil, err
		}
		if !known {
			return nil, core.NewIamError("INVALID_ACTION", "Unknown action "+action)
		}
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000)
		if err != nil {
			return nil, err
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1000000)
		if err != nil {
			return nil, err
		}
		kind := input.Get("kind")
		if !isUndefined(kind) && kind != "user" && kind != "service" {
			return nil, invalidInput("kind must be user or service")
		}
		resource, err := reviewResource(ctx, server, tx, tenantKey, input.Get("resource"))
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", tenant.Get("id"), "status", "active")
		if !isUndefined(kind) {
			filter.Set("kind", kind)
		}
		identities, err := tx.Find(ctx, "identities", filter, nil)
		if err != nil {
			return nil, err
		}
		sortStable(identities, ByID)
		matches := []any{}
		for _, identity := range identities {
			principal := server.Decisions.SimulatedPrincipal(identity, input.Get("assumeMfa") == true)
			prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, tenant, action)
			if err != nil {
				return nil, err
			}
			decision, err := DecideOn(prepared, *resource, "")
			if err != nil {
				return nil, err
			}
			if decision.Allowed {
				matches = append(matches, core.NewObject("identityId", identity.Get("id"), "name", identity.Get("name"),
					"email", identity.Get("email"), "kind", identity.Get("kind"), "reason", decision.Reason))
			}
		}
		total := len(matches)
		start := min(int(offset), total)
		end := min(int(offset)+int(limit), total)
		return core.NewObject("identities", append([]any{}, matches[start:end]...), "total", float64(total)), nil
	}, false)
	return Out[apitypes.PoliciesWhoCanOutput]{Value: result}, err
}

// CreatePolicy (api/policies.ts createPolicy): Creates a policy under the caller's grant authority; shared by
// `policies.create` and configuration sync.
func CreatePolicy(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	tenantID := jsString(input.Get("tenantId"))
	if err := server.Catalog.Validate(ctx, tx, tenantID, input.Get("document")); err != nil {
		return nil, err
	}
	authority, err := server.GrantingAuthority(ctx, tx, principal, tenantID, "")
	if err != nil {
		return nil, err
	}
	if err := server.EnforceLimit(ctx, tx, tenant, "policies", func(ctx context.Context) (int, error) {
		policies, err := tx.Find(ctx, "policies", core.NewObject("tenantId", tenantID), nil)
		return len(policies), err
	}); err != nil {
		return nil, err
	}
	name, err := Text(input.Get("name"), "name")
	if err != nil {
		return nil, err
	}
	policy := core.NewObject("id", ID(), "tenantId", tenantID, "name", name)
	policy.SetRaw("document", input.Get("document"))
	policy.Set("version", 1.0)
	policy.Set("authorityId", authority.Get("id"))
	if value := input.Get("description"); !isUndefined(value) {
		description, err := Text(value, "description", 512)
		if err != nil {
			return nil, err
		}
		policy.Set("description", description)
	}
	return tx.Insert(ctx, "policies", policy)
}

// UpdatePolicy (api/policies.ts updatePolicy): Updates a policy as a new version (optimistic concurrency on
// `version`); the previous version is retained.
func UpdatePolicy(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	tenantID := jsString(input.Get("tenantId"))
	document := input.Get("document")
	if !isUndefined(document) {
		if err := server.Catalog.Validate(ctx, tx, tenantID, document); err != nil {
			return nil, err
		}
	}
	if _, err := server.GrantingAuthority(ctx, tx, principal, tenantID, ""); err != nil {
		return nil, err
	}
	policy, err := server.Scoped(ctx, tx, "policies", input.Get("policyId"), tenantID)
	if err != nil {
		return nil, err
	}
	if err := server.CanEditGrantResource(ctx, tx, principal, policy); err != nil {
		return nil, err
	}
	if policy.Get("uniqueKey") == "system:owner" {
		return nil, core.NewIamError("PROTECTED_RESOURCE", "Owner policy is protected", 403)
	}
	if !core.StrictEquals(policy.Get("version"), core.Normalize(input.Get("version"))) {
		return nil, core.NewIamError("VERSION_CONFLICT", "Policy version changed", 409)
	}
	if isUndefined(document) && isUndefined(input.Get("name")) && isUndefined(input.Get("description")) {
		return nil, invalidInput("Nothing to update")
	}
	if !isUndefined(document) {
		if err := assertPolicyDeniesKept(ctx, server, tx, principal, policy, document); err != nil {
			return nil, err
		}
	}
	if err := archivePolicyVersion(ctx, tx, policy); err != nil {
		return nil, err
	}
	next := policy.Spread()
	next.SetRaw("document", coalesce(document, policy.Get("document")))
	next.Set("version", jsNumber(policy.Get("version"))+1)
	if value := input.Get("name"); !isUndefined(value) {
		name, err := Text(value, "name")
		if err != nil {
			return nil, err
		}
		next.Set("name", name)
	}
	if value := input.Get("description"); !isUndefined(value) {
		description, err := Text(value, "description", 512)
		if err != nil {
			return nil, err
		}
		next.Set("description", description)
	}
	return tx.Put(ctx, "policies", next)
}

// assertPolicyDeniesKept: a policy another authority attached to a role (or whose role it inherits or bound) carries
// denies that authority relies on: its editor may not remove or change one (roles.ts assertDeniesKept).
func assertPolicyDeniesKept(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, policy *core.Object, document any) error {
	return AssertDeniesKept(ctx, server, tx, principal,
		statementList(DocumentDenyStatements(policy.Get("document"))),
		statementList(DocumentDenyStatements(document)),
		func(ctx context.Context) (bool, error) {
			roles, err := tx.Find(ctx, "roles", core.NewObject("tenantId", policy.Get("tenantId")), nil)
			if err != nil {
				return false, err
			}
			var attaching []string
			for _, role := range roles {
				if policyIDs, ok := role.Get("policyIds").([]any); ok && includesValue(policyIDs, policy.Get("id")) {
					attaching = append(attaching, jsString(role.Get("id")))
				}
			}
			return ReliedOnByOthers(ctx, tx, jsString(policy.Get("tenantId")), policy.Get("authorityId"), attaching)
		})
}

// DeletePolicy (api/policies.ts deletePolicy): Deletes a policy that no role still attaches; the Owner policy is
// protected.
func DeletePolicy(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, policy *core.Object) (err error) {
	if err := server.CanEditGrantResource(ctx, tx, principal, policy); err != nil {
		return err
	}
	if policy.Get("uniqueKey") == "system:owner" {
		return core.NewIamError("PROTECTED_RESOURCE", "Owner policy is protected", 403)
	}
	roles, err := tx.Find(ctx, "roles", core.NewObject("tenantId", policy.Get("tenantId")), nil)
	if err != nil {
		return err
	}
	for _, role := range roles {
		if policyIDs, ok := role.Get("policyIds").([]any); ok && includesValue(policyIDs, policy.Get("id")) {
			return core.NewIamError("RESOURCE_IN_USE", "Detach policy before deletion", 409)
		}
	}
	return tx.Delete(ctx, "policies", jsString(policy.Get("id")))
}
