package server

// Port of packages/server/src/api/access-paths.ts: self-service access paths. When a person is denied, the ways they
// could become allowed on their own (step up to MFA, accept pending terms of use, activate one of their eligible
// just-in-time bindings, or request a requestable access package), each confirmed by applying it inside a
// transaction that is always rolled back and re-running the ordinary decision. Needs only an ordinary session of the
// tenant; activation and package options are listed only when the caller may use them (`iam:bindings:activate`,
// `iam:packages:request`).

import (
	"context"
	"errors"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// AccessPathsAPI is the `accessPaths` API group (packages/server/src/api/access-paths.ts createAccessPathsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/accessPaths/{method} onto it.
type AccessPathsAPI struct {
	server *ServerContext
}

// CreateAccessPathsAPI builds the `accessPaths` API group.
func CreateAccessPathsAPI(server *ServerContext) *AccessPathsAPI {
	return &AccessPathsAPI{server: server}
}

// accessPathsMaxCandidates bounds the eligible bindings and packages simulated.
const accessPathsMaxCandidates = 50

// accessPathsRollback rolls the simulation transaction back while carrying its result out.
type accessPathsRollback struct {
	result *core.Object
}

func (r *accessPathsRollback) Error() string { return "rollback" }

func (api *AccessPathsAPI) allowed(ctx context.Context, tx core.IamStore, principal *Principal, tenantID, action string, resource ResourceTarget) (core.Decision, error) {
	return api.server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{TenantID: tenantID, Action: action, Resource: resource}, strings.HasPrefix(action, "iam:"))
}

func (api *AccessPathsAPI) may(ctx context.Context, tx core.IamStore, principal *Principal, tenantID, action, resourceID string) (bool, error) {
	decision, err := api.server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{TenantID: tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: resourceID}}, true)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

func (api *AccessPathsAPI) paths(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, action string, resource ResourceTarget) (*core.Object, error) {
	server := api.server
	tenantID := jsString(tenant.Get("id"))
	identityID := jsString(principal.Identity.Get("id"))
	now := server.Now()
	check := func(who *Principal) (bool, error) {
		decision, err := api.allowed(ctx, tx, who, tenantID, action, resource)
		if err != nil {
			return false, err
		}
		return decision.Allowed, nil
	}
	base, err := api.allowed(ctx, tx, principal, tenantID, action, resource)
	if err != nil {
		return nil, err
	}
	if base.Allowed {
		return core.NewObject("allowed", true, "reason", base.Reason, "paths", []any{}), nil
	}
	// Mandatory access control (security clearances): nothing a person can do on their own lifts a clearance refusal,
	// and naming a way would reveal that the resource is labeled above them.
	if base.Reason == "CLEARANCE_REQUIRED" {
		return core.NewObject("allowed", false, "reason", "ACCESS_DENIED", "paths", []any{}), nil
	}
	found := []any{}

	// A second factor.
	if !truthy(principal.Session.Get("mfa")) {
		stepped := *principal
		stepped.Session = principal.Session.Spread(core.NewObject("mfa", true))
		helps, err := check(&stepped)
		if err != nil {
			return nil, err
		}
		if helps {
			found = append(found, core.NewObject("kind", "mfa"))
		}
	}

	// Required terms of use not yet accepted (simulated as accepted, then removed again).
	agreements, err := tx.Find(ctx, "agreements", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	if len(agreements) > 0 && principal.Identity.Get("kind") == "user" {
		accepted, err := tx.Find(ctx, "agreementAcceptances", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		acceptances := map[string]*core.Object{}
		for _, acceptance := range accepted {
			acceptances[jsString(acceptance.Get("agreementId"))] = acceptance
		}
		var owed []*core.Object
		for _, agreement := range agreements {
			if truthy(agreement.Get("required")) && !AcceptanceCurrent(agreement, acceptances[jsString(agreement.Get("id"))], now) {
				owed = append(owed, agreement)
			}
		}
		if len(owed) > 0 {
			type written struct {
				id       string
				previous *core.Object
			}
			var writes []written
			for _, agreement := range owed {
				acceptanceID := jsString(agreement.Get("id")) + ":" + identityID
				previous := acceptances[jsString(agreement.Get("id"))]
				record := core.NewObject(
					"id", acceptanceID, "tenantId", tenantID, "agreementId", agreement.Get("id"), "identityId", identityID,
					"version", agreement.Get("version"), "acceptedAt", float64(now),
				)
				if previous != nil {
					_, err = tx.Put(ctx, "agreementAcceptances", record)
				} else {
					_, err = tx.Insert(ctx, "agreementAcceptances", record)
				}
				if err != nil {
					return nil, err
				}
				writes = append(writes, written{id: acceptanceID, previous: previous})
			}
			helps, err := check(principal)
			if err != nil {
				return nil, err
			}
			if helps {
				list := make([]any, len(owed))
				for index, agreement := range owed {
					list[index] = core.NewObject("id", agreement.Get("id"), "name", agreement.Get("name"), "version", agreement.Get("version"))
				}
				found = append(found, core.NewObject("kind", "accept-agreements", "agreements", list))
			}
			for _, entry := range writes {
				if entry.previous != nil {
					_, err = tx.Put(ctx, "agreementAcceptances", entry.previous)
				} else {
					err = tx.Delete(ctx, "agreementAcceptances", entry.id)
				}
				if err != nil {
					return nil, err
				}
			}
		}
	}

	// Eligible bindings the caller holds directly or through a group, simulated as activated.
	memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	groupIDs := newOrderedSet()
	for _, member := range memberships {
		if server.LiveMembership(member) {
			groupIDs.Add(jsString(member.Get("groupId")))
		}
	}
	bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	var eligible []*core.Object
	for _, binding := range bindings {
		if binding.Get("eligible") != true || !server.LiveBinding(binding) {
			continue
		}
		subjectID := binding.Get("subjectId")
		var holds bool
		if binding.Get("subjectType") == "identity" {
			holds = subjectID == identityID
		} else {
			subject, ok := subjectID.(string)
			holds = ok && groupIDs.Has(subject)
		}
		if holds {
			eligible = append(eligible, binding)
		}
	}
	if len(eligible) > accessPathsMaxCandidates {
		eligible = eligible[:accessPathsMaxCandidates]
	}
	existing, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	activations := map[string]*core.Object{}
	for _, activation := range existing {
		activations[jsString(activation.Get("bindingId"))] = activation
	}
	for _, binding := range eligible {
		role, err := tx.Get(ctx, "roles", jsString(binding.Get("roleId")))
		if err != nil {
			return nil, err
		}
		if role == nil {
			continue
		}
		bindingID := jsString(binding.Get("id"))
		previous := activations[bindingID]
		var activationID any = ID()
		if previous != nil && !nullish(previous.Get("id")) {
			activationID = previous.Get("id")
		}
		simulated := core.NewObject(
			"id", activationID, "tenantId", tenantID, "uniqueKey", bindingID+":"+identityID, "bindingId", binding.Get("id"),
			"identityId", identityID, "roleId", binding.Get("roleId"), "activatedAt", float64(now),
			"expiresAt", float64(now+3_600_000), "sessionId", principal.Session.Get("id"),
		)
		if previous != nil {
			_, err = tx.Put(ctx, "bindingActivations", simulated)
		} else {
			_, err = tx.Insert(ctx, "bindingActivations", simulated)
		}
		if err != nil {
			return nil, err
		}
		// `requireMfa` gates the activation itself, not the grants it brings, so the caller is evaluated as is.
		helps, err := check(principal)
		if err != nil {
			return nil, err
		}
		if previous != nil {
			_, err = tx.Put(ctx, "bindingActivations", previous)
		} else {
			err = tx.Delete(ctx, "bindingActivations", jsString(activationID))
		}
		if err != nil {
			return nil, err
		}
		if !helps {
			continue
		}
		permitted, err := api.may(ctx, tx, principal, tenantID, "iam:bindings:activate", jsString(binding.Get("roleId")))
		if err != nil {
			return nil, err
		}
		if permitted {
			path := core.NewObject(
				"kind", "activate", "bindingId", binding.Get("id"),
				"role", core.NewObject("id", role.Get("id"), "name", role.Get("name")),
				"requireApproval", binding.Get("requireApproval") == true,
				"requireJustification", binding.Get("requireJustification") == true,
				"requireMfa", binding.Get("requireMfa") == true,
			)
			if maximum := binding.Get("maxActivationMs"); !isUndefined(maximum) {
				path.Set("maxActivationMs", maximum)
			}
			found = append(found, path)
		}
	}

	// Requestable packages, simulated as assigned (standing bindings under each role's own authority, memberships).
	stored, err := tx.Find(ctx, "accessPackages", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	var packages []*core.Object
	for _, pkg := range stored {
		if pkg.Get("requestable") == true {
			packages = append(packages, pkg)
		}
	}
	if len(packages) > accessPathsMaxCandidates {
		packages = packages[:accessPathsMaxCandidates]
	}
	for _, pkg := range packages {
		permitted, err := api.may(ctx, tx, principal, tenantID, "iam:packages:request", jsString(pkg.Get("id")))
		if err != nil {
			return nil, err
		}
		if !permitted {
			continue
		}
		type createdRecord struct{ collection, id string }
		var created []createdRecord
		roleIDs, _ := pkg.Get("roleIds").([]any)
		for _, roleID := range roleIDs {
			role, err := tx.Get(ctx, "roles", jsString(roleID))
			if err != nil {
				return nil, err
			}
			if role == nil {
				continue
			}
			authorityID, ok := role.Get("authorityId").(string)
			if !ok {
				continue
			}
			bindingID := ID()
			if _, err := tx.Insert(ctx, "bindings", core.NewObject(
				"id", bindingID, "tenantId", tenantID, "uniqueKey", "simulation:"+bindingID, "subjectType", "identity",
				"subjectId", identityID, "roleId", roleID, "authorityId", authorityID,
			)); err != nil {
				return nil, err
			}
			created = append(created, createdRecord{"bindings", bindingID})
		}
		packageGroups, _ := pkg.Get("groupIds").([]any)
		for _, groupID := range packageGroups {
			if group, ok := groupID.(string); ok && groupIDs.Has(group) {
				continue
			}
			memberID := ID()
			if _, err := tx.Insert(ctx, "groupMembers", core.NewObject(
				"id", memberID, "tenantId", tenantID, "uniqueKey", "simulation:"+memberID, "groupId", groupID,
				"identityId", identityID,
			)); err != nil {
				return nil, err
			}
			created = append(created, createdRecord{"groupMembers", memberID})
		}
		helps := false
		if len(created) > 0 {
			if helps, err = check(principal); err != nil {
				return nil, err
			}
		}
		for _, record := range created {
			if err := tx.Delete(ctx, record.collection, record.id); err != nil {
				return nil, err
			}
		}
		if helps {
			reference := core.NewObject("id", pkg.Get("id"), "name", pkg.Get("name"))
			if description := pkg.Get("description"); !isUndefined(description) {
				reference.Set("description", description)
			}
			found = append(found, core.NewObject(
				"kind", "request-package", "package", reference,
				"requireJustification", pkg.Get("requireJustification") == true,
			))
		}
	}
	// Like `authorize`, a denial does not reveal which rule refused it.
	return core.NewObject("allowed", false, "reason", "ACCESS_DENIED", "paths", found), nil
}

// Find is POST {basePath}/accessPaths/find. For an `action` on a `resource` the caller is denied, lists what they
// could do themselves to be allowed. Nothing is saved. The caller's own ordinary session only (not impersonation,
// assumed roles or session tokens).
func (api *AccessPathsAPI) Find(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessPathsFindInput]) (Out[apitypes.AccessPathsFindOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.AccessPathsFindOutput]{}, err
	}
	action, err := Text(input.Get("action"), "action")
	if err != nil {
		return Out[apitypes.AccessPathsFindOutput]{}, err
	}
	reference, err := Object(input.Get("resource"))
	if err != nil {
		return Out[apitypes.AccessPathsFindOutput]{}, err
	}
	resourceType, err := Text(reference.Get("type"), "resource type")
	if err != nil {
		return Out[apitypes.AccessPathsFindOutput]{}, err
	}
	resourceID, err := Text(reference.Get("id"), "resource id")
	if err != nil {
		return Out[apitypes.AccessPathsFindOutput]{}, err
	}
	resource := ResourceTarget{Type: resourceType, ID: resourceID}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.AccessPathsFindOutput]{}, err
	}
	err = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return err
		}
		if !ActsInOwnRight(principal.Session) || principal.Session.Get("tenantId") != tenantID || principal.Identity.Get("tenantId") != tenantID {
			return core.NewIamError("ACCESS_DENIED", "Access paths are for an ordinary session of the tenant", 403)
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return core.NewIamError("IMPERSONATION_RESTRICTED", "Access paths are not available while impersonating", 403)
		}
		known, err := server.Catalog.KnownAction(ctx, tx, tenantID, action)
		if err != nil {
			return err
		}
		if !known {
			return core.NewIamError("INVALID_ACTION", "Unknown action "+action)
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		result, err := api.paths(ctx, tx, principal, tenant, action, resource)
		if err != nil {
			return err
		}
		return &accessPathsRollback{result: result}
	})
	var rollback *accessPathsRollback
	if errors.As(err, &rollback) {
		return Out[apitypes.AccessPathsFindOutput]{Value: rollback.result}, nil
	}
	if err != nil {
		return Out[apitypes.AccessPathsFindOutput]{}, err
	}
	return Out[apitypes.AccessPathsFindOutput]{}, core.NewIamError("INTERNAL_ERROR", "Access paths did not complete", 500)
}
