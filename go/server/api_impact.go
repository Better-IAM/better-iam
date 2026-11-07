package server

// Port of packages/server/src/api/impact.ts: change impact preview. Before editing a role or policy (or deleting a
// role), see who would gain or lose which actions on which resources. The change is applied exactly as the real call
// would apply it (same validation and the same edit rights) inside a transaction that is always rolled back, and
// every holder's decisions are compared before and after, so inheritance, authority ceilings, boundaries,
// conditions, and eligibility all count.

import (
	"context"
	"errors"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ImpactAPI is the `impact` API group (packages/server/src/api/impact.ts createImpactApi): every method runs through the
// operation envelope; the router maps POST {basePath}/impact/{method} onto it.
type ImpactAPI struct {
	server *ServerContext
}

// CreateImpactAPI builds the `impact` API group.
func CreateImpactAPI(server *ServerContext) *ImpactAPI {
	return &ImpactAPI{server: server}
}

const (
	impactMaxHolders   = 200
	impactMaxResources = 10
)

// impactRollback rolls the simulation transaction back while carrying its result out.
type impactRollback struct {
	result *core.Object
}

func (r *impactRollback) Error() string { return "rollback" }

// compareInvariants is the invariants whose violations grew (broken) or disappeared (fixed) between two
// evaluations; without `detailed`, only how many.
func impactCompareInvariants(before, after []*core.Object, detailed bool) *core.Object {
	previous := map[string]*core.Object{}
	for _, result := range before {
		previous[jsString(member(result.Get("invariant"), "id"))] = result
	}
	broken := []any{}
	fixed := []any{}
	for _, result := range after {
		invariant := result.Get("invariant")
		id, name, mode := member(invariant, "id"), member(invariant, "name"), member(invariant, "mode")
		earlier := previous[jsString(id)]
		known := newOrderedSet()
		if earlier != nil {
			violations, _ := earlier.Get("violations").([]any)
			for _, violation := range violations {
				known.Add(jsString(member(member(violation, "identity"), "id")))
			}
		}
		added := []any{}
		violations, _ := result.Get("violations").([]any)
		for _, violation := range violations {
			if !known.Has(jsString(member(member(violation, "identity"), "id"))) {
				added = append(added, violation)
			}
		}
		if len(added) > 0 {
			broken = append(broken, core.NewObject("id", id, "name", name, "mode", mode, "violations", added))
		} else if truthy(result.Get("passed")) && earlier != nil && !truthy(earlier.Get("passed")) && !truthy(earlier.Get("error")) {
			fixed = append(fixed, core.NewObject("id", id, "name", name, "mode", mode))
		}
	}
	answer := core.NewObject("detailed", detailed, "brokenCount", len(broken), "fixedCount", len(fixed))
	if detailed {
		return answer.Set("broken", broken).Set("fixed", fixed)
	}
	return answer.Set("broken", []any{}).Set("fixed", []any{})
}

// inheritors is every role whose grants include `roleIds` (the roles themselves and their inheritors,
// transitively).
func impactInheritors(roles []*core.Object, roleIDs *orderedSet) *orderedSet {
	affected := newOrderedSet(roleIDs.Values()...)
	grew := true
	for grew {
		grew = false
		for _, role := range roles {
			id := jsString(role.Get("id"))
			if affected.Has(id) {
				continue
			}
			for _, parent := range stringList(role.Get("inherits")) {
				if affected.Has(parent) {
					affected.Add(id)
					grew = true
					break
				}
			}
		}
	}
	return affected
}

func (api *ImpactAPI) holders(ctx context.Context, tx core.IamStore, tenantID string, roleIDs *orderedSet) ([]*core.Object, error) {
	server := api.server
	bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	ids := newOrderedSet()
	groups := newOrderedSet()
	for _, binding := range bindings {
		roleID, ok := binding.Get("roleId").(string)
		if !ok || !roleIDs.Has(roleID) || server.ExpiredBinding(binding) {
			continue
		}
		if binding.Get("subjectType") == "identity" {
			ids.Add(jsString(binding.Get("subjectId")))
		} else {
			groups.Add(jsString(binding.Get("subjectId")))
		}
	}
	if groups.Len() > 0 {
		members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, member := range members {
			if groupID, ok := member.Get("groupId").(string); ok && groups.Has(groupID) && server.LiveMembership(member) {
				ids.Add(jsString(member.Get("identityId")))
			}
		}
	}
	people := []*core.Object{}
	for _, identityID := range miningSorted(ids.Values()) {
		identity, err := tx.Get(ctx, "identities", identityID)
		if err != nil {
			return nil, err
		}
		if identity != nil && identity.Get("tenantId") == tenantID && identity.Get("status") == "active" {
			people = append(people, identity)
		}
	}
	return people, nil
}

// allowed is the allowed actions per identity and resource, as `identityId -> resource -> Set(action)`.
func (api *ImpactAPI) allowed(ctx context.Context, tx core.IamStore, tenant *core.Object, people []*core.Object, resources []*ResolvedResource, actions []string, assumeMfa bool) (map[string]map[string]*orderedSet, error) {
	decisions := api.server.Decisions
	result := map[string]map[string]*orderedSet{}
	for _, identity := range people {
		principal := decisions.SimulatedPrincipal(identity, assumeMfa)
		prepared, err := decisions.PrepareDecision(ctx, tx, principal, tenant, actions[0])
		if err != nil {
			return nil, err
		}
		byResource := map[string]*orderedSet{}
		for _, resource := range resources {
			set := newOrderedSet()
			for _, action := range actions {
				decision, err := DecideOn(prepared, *resource, action)
				if err != nil {
					return nil, err
				}
				if decision.Allowed {
					set.Add(action)
				}
			}
			byResource[resource.Type+"/"+resource.ID] = set
		}
		result[jsString(identity.Get("id"))] = byResource
	}
	return result, nil
}

func (api *ImpactAPI) apply(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, change *core.Object) error {
	server := api.server
	// The caller must hold the permission the real call needs, not only the edit rights the helpers check.
	if role := change.Get("role"); truthy(role) {
		if err := Allow(ctx, server, tx, principal, tenantID, "iam:roles:update", jsString(member(role, "roleId")), "update this role"); err != nil {
			return err
		}
		update, _ := role.(*core.Object)
		_, err := UpdateRole(ctx, server, tx, principal, update.Spread(core.NewObject("tenantId", tenantID)))
		return err
	}
	if change := change.Get("policy"); truthy(change) {
		policy, err := server.Scoped(ctx, tx, "policies", member(change, "policyId"), tenantID)
		if err != nil {
			return err
		}
		if err := Allow(ctx, server, tx, principal, tenantID, "iam:policies:update", jsString(policy.Get("id")), "update this policy"); err != nil {
			return err
		}
		_, err = UpdatePolicy(ctx, server, tx, principal, core.NewObject(
			"tenantId", tenantID, "policyId", policy.Get("id"), "version", policy.Get("version"), "document", member(change, "document"),
		))
		return err
	}
	role, err := server.Scoped(ctx, tx, "roles", change.Get("deleteRole"), tenantID)
	if err != nil {
		return err
	}
	if err := Allow(ctx, server, tx, principal, tenantID, "iam:roles:delete", jsString(role.Get("id")), "delete this role"); err != nil {
		return err
	}
	return DeleteRole(ctx, server, tx, principal, role)
}

// impactAuthorization is what the authorized (and audited) preview operation hands the simulation.
type impactAuthorization struct {
	principal        *Principal
	invariantDetails bool
}

// Preview is POST {basePath}/impact/preview. Previews a role update (`change.role`, as `roles.update` takes it), a
// policy document change (`change.policy`), or a role deletion (`change.deleteRole`) against 1-10 `resources`. For
// every holder of the affected roles (at most 200), reports the actions gained and lost per resource; `actions` (at
// most 200) narrows the comparison, which otherwise covers every known action. `assumeMfa` evaluates holders as if
// MFA-verified. Nothing is saved. Requires iam:policies:simulate, plus the rights the change itself needs; which
// invariants break or pass is detailed only for callers allowed iam:invariants:read (others see counts).
func (api *ImpactAPI) Preview(ctx context.Context, credential core.CredentialInput, input In[apitypes.ImpactPreviewInput]) (Out[apitypes.ImpactPreviewOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.ImpactPreviewOutput], error) {
		return Out[apitypes.ImpactPreviewOutput]{}, err
	}
	change, err := Object(input.Get("change"))
	if err != nil {
		return fail(err)
	}
	kinds := 0
	for _, key := range []string{"role", "policy", "deleteRole"} {
		if !isUndefined(change.Get(key)) {
			kinds++
		}
	}
	if kinds != 1 {
		return fail(invalidInput("Provide exactly one of role, policy, or deleteRole"))
	}
	if role := change.Get("role"); truthy(role) {
		reference, err := Object(role)
		if err != nil {
			return fail(err)
		}
		if _, err := Text(reference.Get("roleId"), "roleId"); err != nil {
			return fail(err)
		}
	}
	if policy := change.Get("policy"); truthy(policy) {
		reference, err := Object(policy)
		if err != nil {
			return fail(err)
		}
		if _, err := Text(reference.Get("policyId"), "policyId"); err != nil {
			return fail(err)
		}
		if _, err := Object(member(policy, "document")); err != nil {
			return fail(err)
		}
	}
	if deleteRole := change.Get("deleteRole"); !isUndefined(deleteRole) {
		if _, err := Text(deleteRole, "deleteRole"); err != nil {
			return fail(err)
		}
	}
	items, ok := input.Get("resources").([]any)
	if !ok || len(items) == 0 || len(items) > impactMaxResources {
		return fail(invalidInput("Provide 1-" + jsString(float64(impactMaxResources)) + " resources"))
	}
	references := make([]core.ResourceRef, len(items))
	for index, item := range items {
		reference, err := Object(item)
		if err != nil {
			return fail(err)
		}
		resourceType, err := Text(reference.Get("type"), "resource type")
		if err != nil {
			return fail(err)
		}
		resourceID, err := Text(reference.Get("id"), "resource id")
		if err != nil {
			return fail(err)
		}
		references[index] = core.ResourceRef{Type: resourceType, ID: resourceID}
	}
	var requested []string
	if raw := input.Get("actions"); !isUndefined(raw) {
		list, err := Strings(raw, "actions")
		if err != nil {
			return fail(err)
		}
		requested = unique(list)
		if len(requested) == 0 || len(requested) > 200 {
			return fail(invalidInput("Compare 1-200 actions"))
		}
	}
	assumeMfa := input.Get("assumeMfa") == true
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	// Authorize (and audit) the preview itself; the simulation runs in its own transaction below.
	authorization, err := Operate(ctx, server.Operations, credential, tenantID, "iam:policies:simulate", tenantID, func(ctx context.Context, call MutationContext) (*impactAuthorization, error) {
		// The change rights below are checked for the session holder alone, so "view as" cannot borrow them.
		if truthy(call.Principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Change previews are not available while impersonating", 403)
		}
		// Invariant names, modes and violators are for those who may read invariants, decided before the change
		// is simulated so the change cannot grant the right to see them.
		invariants, err := server.Decisions.Decide(ctx, call.Tx, call.Principal, AuthorizationRequest{
			TenantID: tenantID, Action: "iam:invariants:read", Resource: ResourceTarget{Type: "iam", ID: tenantID},
		}, true)
		if err != nil {
			return nil, err
		}
		return &impactAuthorization{principal: call.Principal, invariantDetails: invariants.Allowed}, nil
	}, false)
	if err != nil {
		return fail(err)
	}
	principal := authorization.principal
	err = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		roles, err := tx.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return err
		}
		changed := newOrderedSet()
		if role := change.Get("role"); truthy(role) {
			changed.Add(jsString(member(role, "roleId")))
		}
		if deleteRole := change.Get("deleteRole"); truthy(deleteRole) {
			changed.Add(jsString(deleteRole))
		}
		if policy := change.Get("policy"); truthy(policy) {
			policyID := member(policy, "policyId")
			for _, role := range roles {
				for _, attached := range stringList(role.Get("policyIds")) {
					if attached == policyID {
						changed.Add(jsString(role.Get("id")))
						break
					}
				}
			}
		}
		affected := impactInheritors(roles, changed)
		everyone, err := api.holders(ctx, tx, tenantID, affected)
		if err != nil {
			return err
		}
		people := everyone
		if len(people) > impactMaxHolders {
			people = people[:impactMaxHolders]
		}
		resources := make([]*ResolvedResource, 0, len(references))
		for _, reference := range references {
			resolved, err := server.Decisions.Resolve(ctx, tx, core.ResourceRef{TenantID: tenantID, Type: reference.Type, ID: reference.ID}, true, "", nil)
			if err != nil {
				return err
			}
			resources = append(resources, resolved)
		}
		actions := requested
		if actions != nil {
			for _, action := range actions {
				known, err := server.Catalog.KnownAction(ctx, tx, tenantID, action)
				if err != nil {
					return err
				}
				if !known {
					return core.NewIamError("INVALID_ACTION", "Unknown action "+action)
				}
			}
		} else if actions, err = miningKnownActions(ctx, server, tx, tenantID); err != nil {
			return err
		}
		actions = miningSorted(actions)
		before, err := api.allowed(ctx, tx, tenant, people, resources, actions, assumeMfa)
		if err != nil {
			return err
		}
		guardrails, err := tx.Find(ctx, "accessInvariants", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return err
		}
		invariantsBefore, err := EvaluateInvariants(ctx, server, tx, tenant, guardrails, nil)
		if err != nil {
			return err
		}
		if err := api.apply(ctx, tx, principal, tenantID, change); err != nil {
			return err
		}
		after, err := api.allowed(ctx, tx, tenant, people, resources, actions, assumeMfa)
		if err != nil {
			return err
		}
		invariantsAfter, err := EvaluateInvariants(ctx, server, tx, tenant, guardrails, nil)
		if err != nil {
			return err
		}
		identities := []any{}
		gainedTotal, lostTotal := 0, 0
		for _, identity := range people {
			changes := []any{}
			for _, resource := range resources {
				key := resource.Type + "/" + resource.ID
				was := before[jsString(identity.Get("id"))][key]
				now := after[jsString(identity.Get("id"))][key]
				gained := []string{}
				for _, action := range now.Values() {
					if !was.Has(action) {
						gained = append(gained, action)
					}
				}
				lost := []string{}
				for _, action := range was.Values() {
					if !now.Has(action) {
						lost = append(lost, action)
					}
				}
				if len(gained) == 0 && len(lost) == 0 {
					continue
				}
				gainedTotal += len(gained)
				lostTotal += len(lost)
				changes = append(changes, core.NewObject("resource", key, "gained", stringsOf(gained), "lost", stringsOf(lost)))
			}
			if len(changes) > 0 {
				identities = append(identities, core.NewObject(
					"identity", core.NewObject("id", identity.Get("id"), "name", analysisLabel(identity)),
					"changes", changes,
				))
			}
		}
		roleByID := map[string]*core.Object{}
		for _, role := range roles {
			roleByID[jsString(role.Get("id"))] = role
		}
		type namedRole struct{ id, name string }
		named := make([]namedRole, 0, affected.Len())
		for _, roleID := range affected.Values() {
			name := roleID
			if role := roleByID[roleID]; role != nil {
				name = jsString(coalesce(role.Get("name"), roleID))
			}
			named = append(named, namedRole{id: roleID, name: name})
		}
		sort.SliceStable(named, func(i, j int) bool { return localeCompare(named[i].name, named[j].name) < 0 })
		roleList := make([]any, len(named))
		for index, role := range named {
			roleList[index] = core.NewObject("id", role.id, "name", role.name)
		}
		return &impactRollback{result: core.NewObject(
			"roles", roleList,
			"evaluated", len(people),
			"truncated", len(everyone) > len(people),
			"identities", identities,
			"gainedTotal", gainedTotal,
			"lostTotal", lostTotal,
			"invariants", impactCompareInvariants(invariantsBefore, invariantsAfter, authorization.invariantDetails),
		)}
	})
	var rollback *impactRollback
	if errors.As(err, &rollback) {
		return Out[apitypes.ImpactPreviewOutput]{Value: rollback.result}, nil
	}
	if err != nil {
		return fail(err)
	}
	return fail(core.NewIamError("INTERNAL_ERROR", "Impact preview did not complete", 500))
}
