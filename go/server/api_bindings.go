package server

// Port of packages/server/src/api/bindings.ts: the `bindings` API group (role bindings, eligible bindings and their
// just-in-time activations, activation approvals) and the `authorities` API group (delegated grant authorities), plus
// createBinding and deleteBinding, which invitations, access packages and configuration sync share.

import (
	"context"
	"math"
	"slices"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// bindingsBoolean is bindings.ts boolean(): a boolean member, or INVALID_INPUT `${name} must be boolean`.
func bindingsBoolean(value any, name string) (bool, error) {
	flag, ok := value.(bool)
	if !ok {
		return false, invalidInput(name + " must be boolean")
	}
	return flag, nil
}

// applyEligibility applies eligibility settings (the EligibilityInput members of input) to a binding; activation
// options are only meaningful on eligible bindings.
func applyEligibility(binding *core.Object, input *core.Object) error {
	if eligible := input.Get("eligible"); !isUndefined(eligible) {
		flag, err := bindingsBoolean(eligible, "eligible")
		if err != nil {
			return err
		}
		if flag {
			binding.Set("eligible", true)
		} else {
			for _, key := range []string{"eligible", "maxActivationMs", "requireJustification", "requireMfa", "requireApproval", "approverGroupId", "managerApproval"} {
				binding.Delete(key)
			}
		}
	}
	for _, name := range []string{"requireJustification", "requireMfa", "requireApproval", "managerApproval"} {
		if value := input.Get(name); !isUndefined(value) {
			if _, err := bindingsBoolean(value, name); err != nil {
				return err
			}
		}
	}
	// Explicit `false` flags are harmless on standing bindings (forms send every checkbox); settings are not.
	approverGroupID := input.Get("approverGroupId")
	settings := !isUndefined(input.Get("maxActivationMs")) ||
		input.Get("requireJustification") == true ||
		input.Get("requireMfa") == true ||
		input.Get("requireApproval") == true ||
		input.Get("managerApproval") == true ||
		(!isUndefined(approverGroupID) && approverGroupID != nil)
	if settings && !truthy(binding.Get("eligible")) {
		return invalidInput("Activation settings apply to eligible bindings only")
	}
	if !truthy(binding.Get("eligible")) {
		return nil
	}
	setFlag := func(name string) {
		if value := input.Get(name); !isUndefined(value) {
			if value == true {
				binding.Set(name, true)
			} else {
				binding.Delete(name)
			}
		}
	}
	setFlag("requireApproval")
	setFlag("managerApproval")
	if value := input.Get("maxActivationMs"); !isUndefined(value) {
		maxActivation, err := Integer(value, "maxActivationMs", 60_000, MaxActivationMs)
		if err != nil {
			return err
		}
		binding.Set("maxActivationMs", maxActivation)
	}
	setFlag("requireJustification")
	setFlag("requireMfa")
	return nil
}

// grantingAuthorityFor is ctx.grantingAuthority with the raw `authorityId` member: absent or falsy uses the caller's
// own authority; a truthy non-string fails where TypeScript's scoped() fails on it (after the impersonation check).
func grantingAuthorityFor(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, authorityID any) (*core.Object, error) {
	if !truthy(authorityID) {
		return server.GrantingAuthority(ctx, tx, principal, tenantID, "")
	}
	id, ok := authorityID.(string)
	if !ok {
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Access cannot be granted while impersonating", 403)
		}
		return nil, invalidInput("Invalid id")
	}
	return server.GrantingAuthority(ctx, tx, principal, tenantID, id)
}

// CreateBinding (api/bindings.ts createBinding): Creates a binding under the caller's grant authority; shared by
// `bindings.create`, invitations, access packages, and configuration sync. input is a BindingInput ({ tenantId,
// roleId, subjectType, subjectId, authorityId?, startsAt?, expiresAt?, window?, eligibility settings }); options
// (nil: none) may carry packageAssignmentId. A package assignment's bindings carry `packageAssignmentId` and a key of
// their own, so they never collide with, replace, or depend on a binding someone granted by hand.
func CreateBinding(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object, options *core.Object) (*core.Object, error) {
	tenantID, _ := input.Get("tenantId").(string)
	role, err := server.Scoped(ctx, tx, "roles", input.Get("roleId"), tenantID)
	if err != nil {
		return nil, err
	}
	if truthy(role.Get("protected")) {
		return nil, core.NewIamError("PROTECTED_RESOURCE", "Use owner transfer for protected roles", 403)
	}
	subjectType := input.Get("subjectType")
	if subjectType != "identity" && subjectType != "group" {
		return nil, invalidInput("Invalid subject type")
	}
	if subjectType == "identity" {
		if _, err := server.ActiveIdentity(ctx, tx, input.Get("subjectId"), tenantID); err != nil {
			return nil, err
		}
	} else if _, err := server.Scoped(ctx, tx, "groups", input.Get("subjectId"), tenantID); err != nil {
		return nil, err
	}
	authority, err := grantingAuthorityFor(ctx, server, tx, principal, tenantID, input.Get("authorityId"))
	if err != nil {
		return nil, err
	}
	packageAssignmentID := options.Get("packageAssignmentId")
	uniqueKey := jsString(subjectType) + ":" + jsString(input.Get("subjectId")) + ":" + jsString(input.Get("roleId")) + ":" + jsString(authority.Get("id"))
	if truthy(packageAssignmentID) {
		uniqueKey += ":package:" + jsString(packageAssignmentID)
	}
	binding := core.NewObject(
		"id", ID(),
		"tenantId", input.Get("tenantId"),
		"uniqueKey", uniqueKey,
		"subjectType", subjectType,
		"subjectId", input.Get("subjectId"),
		"roleId", input.Get("roleId"),
		"authorityId", authority.Get("id"),
	)
	if truthy(packageAssignmentID) {
		binding.Set("packageAssignmentId", packageAssignmentID)
	}
	if expiresAt := input.Get("expiresAt"); !isUndefined(expiresAt) {
		value, err := server.BindingExpiry(expiresAt)
		if err != nil {
			return nil, err
		}
		binding.Set("expiresAt", value)
	}
	if startsAt := input.Get("startsAt"); !isUndefined(startsAt) {
		value, err := server.BindingStart(startsAt)
		if err != nil {
			return nil, err
		}
		binding.Set("startsAt", value)
	}
	if err := checkBindingPeriod(binding); err != nil {
		return nil, err
	}
	if window := input.Get("window"); !isUndefined(window) {
		value, err := server.AccessWindow(window)
		if err != nil {
			return nil, err
		}
		binding.Set("window", value)
	}
	if err := applyEligibility(binding, input); err != nil {
		return nil, err
	}
	if err := applyApprovers(ctx, server, tx, binding, input); err != nil {
		return nil, err
	}
	return tx.Insert(ctx, "bindings", binding)
}

// checkBindingPeriod refuses a binding whose start is not before its end.
func checkBindingPeriod(binding *core.Object) error {
	startsAt, expiresAt := binding.Get("startsAt"), binding.Get("expiresAt")
	if !isUndefined(startsAt) && !isUndefined(expiresAt) && jsNumber(startsAt) >= jsNumber(expiresAt) {
		return invalidInput("startsAt must be before expiresAt")
	}
	return nil
}

// applyApprovers sets or clears the approver group of an eligible binding; the group must belong to the tenant.
func applyApprovers(ctx context.Context, server *ServerContext, tx core.IamStore, binding *core.Object, input *core.Object) error {
	approverGroupID := input.Get("approverGroupId")
	if isUndefined(approverGroupID) {
		return nil
	}
	if approverGroupID == nil {
		binding.Delete("approverGroupId")
		return nil
	}
	if !truthy(binding.Get("eligible")) {
		return nil
	}
	tenantID, _ := binding.Get("tenantId").(string)
	if _, err := server.Scoped(ctx, tx, "groups", approverGroupID, tenantID); err != nil {
		return err
	}
	binding.Set("approverGroupId", approverGroupID)
	return nil
}

// issuedByCaller is whether the caller issued a binding: its authority is their own, or they are root. A "view as"
// session never counts as the member it shows, so it cannot lengthen, change or remove what the member granted.
func issuedByCaller(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, binding *core.Object) (bool, error) {
	authority, err := tx.Get(ctx, "grantAuthorities", jsString(binding.Get("authorityId")))
	if err != nil {
		return false, err
	}
	if authority != nil && stsStrictEqual(authority.Get("identityId"), principal.Identity.Get("id")) && !truthy(principal.Session.Get("impersonatorId")) {
		return true, nil
	}
	return server.RootPrincipal(ctx, tx, principal)
}

// DeleteBinding (api/bindings.ts deleteBinding): A binding may be removed by the administrator whose authority
// issued it, or by root. Its activations are removed with it.
func DeleteBinding(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, binding *core.Object) error {
	role, err := tx.Get(ctx, "roles", jsString(binding.Get("roleId")))
	if err != nil {
		return err
	}
	if role != nil && truthy(role.Get("protected")) {
		return core.NewIamError("PROTECTED_RESOURCE", "Use owner transfer", 403)
	}
	issued, err := issuedByCaller(ctx, server, tx, principal, binding)
	if err != nil {
		return err
	}
	if !issued {
		return core.NewIamError("ACCESS_DENIED", "Cannot mutate a higher authority binding", 403)
	}
	if err := deleteBindingActivations(ctx, tx, binding.Get("tenantId"), binding.Get("id")); err != nil {
		return err
	}
	return tx.Delete(ctx, "bindings", jsString(binding.Get("id")))
}

// deleteBindingActivations deletes every activation (and request) of a binding.
func deleteBindingActivations(ctx context.Context, tx core.IamStore, tenantID, bindingID any) error {
	activations, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", tenantID, "bindingId", bindingID), nil)
	if err != nil {
		return err
	}
	for _, activation := range activations {
		if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
			return err
		}
	}
	return nil
}

// liveBindingActivation is an activation that grants: not past its end, not awaiting approval, not denied.
func liveBindingActivation(activation *core.Object, now float64) bool {
	status := activation.Get("status")
	return jsNumber(activation.Get("expiresAt")) > now && status != "pending" && status != "denied"
}

// pendingBindingActivation is a request that still waits for a decision.
func pendingBindingActivation(activation *core.Object, now float64) bool {
	return activation.Get("status") == "pending" && jsNumber(activation.Get("expiresAt")) > now
}

// bindingActivationOrder is the comparator `(a, b) => a.activatedAt - b.activatedAt || (a.id < b.id ? -1 : 1)`, or with
// `b.activatedAt - a.activatedAt` (newest first) when descending.
func bindingActivationOrder(descending bool) func(a, b *core.Object) int {
	return func(a, b *core.Object) int {
		difference := jsNumber(a.Get("activatedAt")) - jsNumber(b.Get("activatedAt"))
		if descending {
			difference = -difference
		}
		if difference != 0 && !math.IsNaN(difference) {
			if difference < 0 {
				return -1
			}
			return 1
		}
		if stsValueLess(a.Get("id"), b.Get("id")) {
			return -1
		}
		return 1
	}
}

// BindingsAPI is the `bindings` API group (packages/server/src/api/bindings.ts createBindingsApi): every method runs
// through the operation envelope; the router maps POST {basePath}/bindings/{method} onto it.
type BindingsAPI struct {
	server *ServerContext
}

// CreateBindingsAPI builds the `bindings` API group.
func CreateBindingsAPI(server *ServerContext) *BindingsAPI {
	return &BindingsAPI{server: server}
}

// appliesTo is whether a binding's subject is this identity, directly or through group membership.
func (api *BindingsAPI) appliesTo(ctx context.Context, tx core.IamStore, binding *core.Object, identityID any) (bool, error) {
	if binding.Get("subjectType") == "identity" {
		return stsStrictEqual(binding.Get("subjectId"), identityID), nil
	}
	members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", binding.Get("tenantId"), "groupId", binding.Get("subjectId"), "identityId", identityID), nil)
	if err != nil {
		return false, err
	}
	for _, member := range members {
		if api.server.LiveMembership(member) {
			return true, nil
		}
	}
	return false, nil
}

// publicBindingActivation is an activation without its unique key, with its status ('active' when it has none) and
// whether it grants right now.
func publicBindingActivation(activation *core.Object, now float64) *core.Object {
	result := activation.Clone()
	result.Delete("uniqueKey")
	result.Set("status", coalesce(activation.Get("status"), "active"))
	result.Set("active", liveBindingActivation(activation, now))
	return result
}

// notify queues an email through the host outbox when the deployment delivers email at all.
func (api *BindingsAPI) notify(ctx context.Context, tx core.IamStore, tenantID string, to any, template string, payload *core.Object) error {
	options := api.server.Options
	if !truthy(to) || options == nil || options.Authentication == nil || options.Authentication.SendEmail == nil {
		return nil
	}
	_, err := api.server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{TenantID: tenantID, Kind: "email", To: jsString(to), Template: template, Payload: payload})
	return err
}

// mayApprove is whether the caller may decide on an activation of this binding: anyone holding the permission when
// the binding names no approvers; otherwise root, the requester's manager (`managerApproval`), or an approver-group
// member.
func (api *BindingsAPI) mayApprove(ctx context.Context, tx core.IamStore, binding *core.Object, principal *Principal, requesterID any) (bool, error) {
	if !truthy(binding.Get("approverGroupId")) && !truthy(binding.Get("managerApproval")) {
		return true, nil
	}
	root, err := api.server.RootPrincipal(ctx, tx, principal)
	if err != nil || root {
		return root, err
	}
	if truthy(binding.Get("managerApproval")) {
		requester, err := tx.Get(ctx, "identities", jsString(requesterID))
		if err != nil {
			return false, err
		}
		if requester != nil && stsStrictEqual(requester.Get("managerId"), principal.Identity.Get("id")) {
			return true, nil
		}
	}
	if !truthy(binding.Get("approverGroupId")) {
		return false, nil
	}
	members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", binding.Get("tenantId"), "groupId", binding.Get("approverGroupId"), "identityId", principal.Identity.Get("id")), nil)
	if err != nil {
		return false, err
	}
	for _, member := range members {
		if api.server.LiveMembership(member) {
			return true, nil
		}
	}
	return false, nil
}

// approverIDs is who is emailed an activation request: live approver-group members and, with `managerApproval`, the
// requester's manager (never the requester).
func (api *BindingsAPI) approverIDs(ctx context.Context, tx core.IamStore, binding *core.Object, requesterID any) ([]string, error) {
	recipients := newOrderedSet()
	if truthy(binding.Get("approverGroupId")) {
		members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", binding.Get("tenantId"), "groupId", binding.Get("approverGroupId")), nil)
		if err != nil {
			return nil, err
		}
		for _, member := range members {
			if api.server.LiveMembership(member) {
				recipients.Add(jsString(member.Get("identityId")))
			}
		}
	}
	if truthy(binding.Get("managerApproval")) {
		requester, err := tx.Get(ctx, "identities", jsString(requesterID))
		if err != nil {
			return nil, err
		}
		if requester != nil && truthy(requester.Get("managerId")) {
			recipients.Add(jsString(requester.Get("managerId")))
		}
	}
	if id, ok := requesterID.(string); ok {
		recipients.Delete(id)
	}
	return recipients.Values(), nil
}

// bindingsTenantAccessPolicy is a tenant's accessPolicy object (nil when it has none).
func bindingsTenantAccessPolicy(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID any) (*core.Object, error) {
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	policy, _ := tenant.Get("accessPolicy").(*core.Object)
	return policy, nil
}

// decideActivation approves or denies a pending activation request (input: tenantId, activationId, note?;
// durationMs is the approver's duration, undefined for a denial).
func (api *BindingsAPI) decideActivation(ctx context.Context, credential core.CredentialInput, input *core.Object, durationMs any, decision string) (any, error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	existing, err := server.Scoped(ctx, server.Store, "bindingActivations", input.Get("activationId"), tenantID)
	if err != nil {
		return nil, err
	}
	return Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:bindings:approve", jsString(existing.Get("roleId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		activation, err := server.Scoped(ctx, tx, "bindingActivations", input.Get("activationId"), tenantID)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		if !pendingBindingActivation(activation, now) {
			return nil, core.NewIamError("INVALID_TRANSITION", "This request is not awaiting a decision", 409)
		}
		if stsStrictEqual(activation.Get("identityId"), principal.Identity.Get("id")) {
			return nil, invalidInput("You cannot decide on your own request")
		}
		// Two-person control: an administrator viewing as an approver must not decide in their name.
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Requests cannot be decided while impersonating", 403)
		}
		binding, err := tx.Get(ctx, "bindings", jsString(activation.Get("bindingId")))
		if err != nil {
			return nil, err
		}
		if binding == nil || !truthy(binding.Get("eligible")) || !server.LiveBinding(binding) {
			return nil, core.NewIamError("INVALID_TRANSITION", "The binding is no longer eligible", 409)
		}
		allowed, err := api.mayApprove(ctx, tx, binding, principal, activation.Get("identityId"))
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, core.NewIamError("ACCESS_DENIED", "Only the designated approvers may decide", 403)
		}
		var note any = core.Undefined
		if raw := input.Get("note"); !isUndefined(raw) {
			text, err := Text(raw, "note", 2048)
			if err != nil {
				return nil, err
			}
			note = text
		}
		decided := activation.Clone()
		decided.Set("decidedBy", principal.Identity.Get("id"))
		decided.Set("decidedAt", now)
		if !isUndefined(note) {
			decided.Set("note", note)
		}
		if decision == "approved" {
			policy, err := bindingsTenantAccessPolicy(ctx, server, tx, tenantID)
			if err != nil {
				return nil, err
			}
			limit := ActivationRulesFor(binding, policy).MaxActivationMs
			// Approvers may shorten what was asked for, never lengthen it.
			requested := math.Min(numberOr(activation.Get("requestedDurationMs"), limit), limit)
			duration, err := Integer(coalesce(durationMs, requested), "durationMs", 60_000, math.Max(requested, 60_000))
			if err != nil {
				return nil, err
			}
			decided.Set("status", "active")
			decided.Set("activatedAt", now)
			decided.Set("expiresAt", now+duration)
		} else {
			decided.Set("status", "denied")
			decided.Set("expiresAt", now)
		}
		if _, err := tx.Put(ctx, "bindingActivations", decided); err != nil {
			return nil, err
		}
		role, err := tx.Get(ctx, "roles", jsString(activation.Get("roleId")))
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("activationId", activation.Get("id"), "roleId", activation.Get("roleId"), "identityId", activation.Get("identityId"))
		if decision == "approved" {
			metadata.Set("expiresAt", decided.Get("expiresAt"))
		}
		if !isUndefined(note) {
			metadata.Set("note", note)
		}
		if err := server.Events.Audit(ctx, tx, principal, "binding:activation-"+decision, tenantID, jsString(activation.Get("bindingId")), "allow", false, metadata); err != nil {
			return nil, err
		}
		requester, err := tx.Get(ctx, "identities", jsString(activation.Get("identityId")))
		if err != nil {
			return nil, err
		}
		roleName := activation.Get("roleId")
		if role != nil {
			roleName = coalesce(role.Get("name"), activation.Get("roleId"))
		}
		payload := core.NewObject(
			"activationId", activation.Get("id"),
			"roleId", activation.Get("roleId"),
			"roleName", roleName,
			"decision", decision,
			"deciderName", principal.Identity.Get("name"),
		)
		if !isUndefined(note) {
			payload.Set("note", note)
		}
		if decision == "approved" {
			payload.Set("expiresAt", jsString(decided.Get("expiresAt")))
		}
		if err := api.notify(ctx, tx, tenantID, member(requester, "email"), "activation-decided", payload); err != nil {
			return nil, err
		}
		return publicBindingActivation(decided, now), nil
	}, false)
}

// Activate is POST {basePath}/bindings/activate: just-in-time elevation. The subject of an eligible binding
// (directly, or through a group) activates it for `durationMs` (at most the binding's `maxActivationMs`, one hour by
// default) with an optional justification, or records an approval request when the binding requires one. Requires
// iam:bindings:activate on the role (`iam/{roleId}`) from an ordinary session of the tenant; the binding may require
// MFA or a justification. Audited as `binding:activate` (or `binding:activation-requested`) with the justification.
func (api *BindingsAPI) Activate(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsActivateInput]) (Out[apitypes.BindingsActivateOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.BindingsActivateOutput]{}, err
	}
	existing, err := server.Scoped(ctx, server.Store, "bindings", input.Get("bindingId"), tenantID)
	if err != nil {
		return Out[apitypes.BindingsActivateOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:bindings:activate", jsString(existing.Get("roleId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		binding, err := server.Scoped(ctx, tx, "bindings", input.Get("bindingId"), tenantID)
		if err != nil {
			return nil, err
		}
		if !truthy(binding.Get("eligible")) || !server.LiveBinding(binding) {
			return nil, core.NewIamError("INVALID_TRANSITION", "This binding is not eligible for activation")
		}
		if !ActsInOwnRight(principal.Session) || !stsStrictEqual(principal.Session.Get("tenantId"), tenantID) {
			return nil, invalidInput("Activations are made from an ordinary session of the target tenant")
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Roles cannot be activated while impersonating", 403)
		}
		identityID := principal.Identity.Get("id")
		applies, err := api.appliesTo(ctx, tx, binding, identityID)
		if err != nil {
			return nil, err
		}
		if !applies {
			return nil, core.NewIamError("ACCESS_DENIED", "This binding does not apply to you", 403)
		}
		policy, err := bindingsTenantAccessPolicy(ctx, server, tx, tenantID)
		if err != nil {
			return nil, err
		}
		rules := ActivationRulesFor(binding, policy)
		if rules.RequireMfa && !truthy(principal.Session.Get("mfa")) {
			return nil, core.NewIamError("MFA_REQUIRED", "Activation requires an MFA-verified session", 403)
		}
		var justification any = core.Undefined
		if raw := input.Get("justification"); !isUndefined(raw) {
			text, err := Text(raw, "justification", 2048)
			if err != nil {
				return nil, err
			}
			justification = text
		}
		if rules.RequireJustification && isUndefined(justification) {
			return nil, invalidInput("This activation requires a justification")
		}
		limit := rules.MaxActivationMs
		durationMs, err := Integer(coalesce(input.Get("durationMs"), limit), "durationMs", 60_000, limit)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		uniqueKey := jsString(binding.Get("id")) + ":" + jsString(identityID)
		previous, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
		if err != nil {
			return nil, err
		}
		if len(previous) > 0 {
			if liveBindingActivation(previous[0], now) {
				return nil, core.NewIamError("CONFLICT", "This role is already active for you", 409)
			}
			if pendingBindingActivation(previous[0], now) {
				return nil, core.NewIamError("CONFLICT", "Your request is still awaiting a decision", 409)
			}
			if err := tx.Delete(ctx, "bindingActivations", jsString(previous[0].Get("id"))); err != nil {
				return nil, err
			}
		}
		approval := rules.RequireApproval
		// A request that names its approvers must reach at least one who can act on it.
		if approval && (truthy(binding.Get("approverGroupId")) || truthy(binding.Get("managerApproval"))) {
			approvers, err := api.approverIDs(ctx, tx, binding, identityID)
			if err != nil {
				return nil, err
			}
			available := false
			for _, approverID := range approvers {
				approver, err := tx.Get(ctx, "identities", approverID)
				if err != nil {
					return nil, err
				}
				if approver != nil && approver.Get("status") == "active" {
					available = true
					break
				}
			}
			if !available {
				return nil, core.NewIamError("INVALID_TRANSITION", "Nobody can approve this request: the approver group is empty and you have no active manager", 409)
			}
		}
		lifetime := durationMs
		if approval {
			lifetime = rules.ApprovalLifetimeMs
		}
		activation := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"uniqueKey", uniqueKey,
			"bindingId", binding.Get("id"),
			"identityId", identityID,
			"roleId", binding.Get("roleId"),
			"activatedAt", now,
			"expiresAt", now+lifetime,
			"sessionId", principal.Session.Get("id"),
		)
		if approval {
			activation.Set("status", "pending")
			activation.Set("requestedDurationMs", durationMs)
		}
		if !isUndefined(justification) {
			activation.Set("justification", justification)
		}
		if _, err := tx.Insert(ctx, "bindingActivations", activation); err != nil {
			return nil, err
		}
		action := "binding:activate"
		if approval {
			action = "binding:activation-requested"
		}
		metadata := core.NewObject("activationId", activation.Get("id"), "roleId", binding.Get("roleId"), "expiresAt", activation.Get("expiresAt"))
		if approval {
			metadata.Set("requestedDurationMs", durationMs)
		}
		if !isUndefined(justification) {
			metadata.Set("justification", justification)
		}
		if err := server.Events.Audit(ctx, tx, principal, action, tenantID, jsString(binding.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		// The designated approvers (group members, the requester's manager) learn about the request by email.
		if approval {
			role, err := tx.Get(ctx, "roles", jsString(binding.Get("roleId")))
			if err != nil {
				return nil, err
			}
			roleName := binding.Get("roleId")
			if role != nil {
				roleName = coalesce(role.Get("name"), binding.Get("roleId"))
			}
			approvers, err := api.approverIDs(ctx, tx, binding, identityID)
			if err != nil {
				return nil, err
			}
			for _, approverID := range approvers {
				approver, err := tx.Get(ctx, "identities", approverID)
				if err != nil {
					return nil, err
				}
				if approver == nil || approver.Get("status") != "active" {
					continue
				}
				payload := core.NewObject(
					"activationId", activation.Get("id"),
					"roleId", binding.Get("roleId"),
					"roleName", roleName,
					"requesterId", identityID,
					"requesterName", principal.Identity.Get("name"),
				)
				if email := principal.Identity.Get("email"); truthy(email) {
					payload.Set("requesterEmail", email)
				}
				payload.Set("requestedDurationMs", core.NumberString(durationMs))
				payload.Set("expiresAt", jsString(activation.Get("expiresAt")))
				if !isUndefined(justification) {
					payload.Set("justification", justification)
				}
				if err := api.notify(ctx, tx, tenantID, approver.Get("email"), "activation-request", payload); err != nil {
					return nil, err
				}
			}
		}
		return publicBindingActivation(activation, now), nil
	}, false)
	return Out[apitypes.BindingsActivateOutput]{Value: result}, err
}

// ApproveActivation is POST {basePath}/bindings/approveActivation: grants a pending activation request, so the role
// becomes live for the requested duration (or the approver's shorter `durationMs`), bounded by the binding's
// `maxActivationMs`. Requires iam:bindings:approve on the role (`iam/{roleId}`), membership of the binding's
// approver group when one is set, and never one's own request. Audited as `binding:activation-approved`; the
// requester is emailed (`activation-decided`).
func (api *BindingsAPI) ApproveActivation(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsApproveActivationInput]) (Out[apitypes.BindingsApproveActivationOutput], error) {
	result, err := api.decideActivation(ctx, credential, input.Body, input.Get("durationMs"), "approved")
	return Out[apitypes.BindingsApproveActivationOutput]{Value: result}, err
}

// Create is POST {basePath}/bindings/create. expiresAt (epoch milliseconds) makes the grant temporary; it must lie
// in the future and within ten years. `eligible` makes it a just-in-time grant: the subject holds the role only after
// `bindings.activate`, for at most `maxActivationMs` (default one hour), optionally with a justification and an
// MFA-verified session.
func (api *BindingsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsCreateInput]) (Out[apitypes.BindingsCreateOutput], error) {
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:bindings:create", jsString(input.Get("roleId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return CreateBinding(ctx, api.server, call.Tx, call.Principal, input.Body, nil)
	}, false)
	return Out[apitypes.BindingsCreateOutput]{Value: result}, err
}

// Deactivate is POST {basePath}/bindings/deactivate: ends the caller's own activation early, or withdraws their own
// pending request. Audited as `binding:deactivate`.
func (api *BindingsAPI) Deactivate(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsDeactivateInput]) (Out[apitypes.BindingsDeactivateOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.BindingsDeactivateOutput]{}, err
	}
	existing, err := server.Scoped(ctx, server.Store, "bindingActivations", input.Get("activationId"), tenantID)
	if err != nil {
		return Out[apitypes.BindingsDeactivateOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:bindings:activate", jsString(existing.Get("roleId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		activation, err := server.Scoped(ctx, tx, "bindingActivations", input.Get("activationId"), tenantID)
		if err != nil {
			return nil, err
		}
		if !stsStrictEqual(activation.Get("identityId"), principal.Identity.Get("id")) {
			return nil, core.NewIamError("ACCESS_DENIED", "Only the holder can end this activation", 403)
		}
		cancelled := activation.Get("status") == "pending"
		if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
			return nil, err
		}
		metadata := core.NewObject("activationId", activation.Get("id"), "roleId", activation.Get("roleId"))
		if cancelled {
			metadata.Set("cancelled", true)
		}
		if err := server.Events.Audit(ctx, tx, principal, "binding:deactivate", tenantID, jsString(activation.Get("bindingId")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return core.NewObject("deactivated", true), nil
	}, false)
	return Out[apitypes.BindingsDeactivateOutput]{Value: result}, err
}

// Delete is POST {basePath}/bindings/delete: removes a binding and every activation of it.
func (api *BindingsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsDeleteInput]) (Out[apitypes.BindingsDeleteOutput], error) {
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:bindings:delete", jsString(input.Get("bindingId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID, _ := input.Get("tenantId").(string)
		binding, err := api.server.Scoped(ctx, call.Tx, "bindings", input.Get("bindingId"), tenantID)
		if err != nil {
			return nil, err
		}
		if err := DeleteBinding(ctx, api.server, call.Tx, call.Principal, binding); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.BindingsDeleteOutput]{Value: result}, err
}

// DenyActivation is POST {basePath}/bindings/denyActivation: refuses a pending activation request, with an optional
// note. Audited as `binding:activation-denied`.
func (api *BindingsAPI) DenyActivation(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsDenyActivationInput]) (Out[apitypes.BindingsDenyActivationOutput], error) {
	result, err := api.decideActivation(ctx, credential, input.Body, core.Undefined, "denied")
	return Out[apitypes.BindingsDenyActivationOutput]{Value: result}, err
}

// List is POST {basePath}/bindings/list: the tenant's bindings, filtered by role, subject, eligibility (`eligible`:
// only just-in-time or only standing ones), or upcoming expiry (`expiresBefore`); expired ones only with
// includeExpired.
func (api *BindingsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsListInput]) (Out[apitypes.BindingsListOutput], error) {
	server := api.server
	resourceID := coalesce(coalesce(input.Get("roleId"), input.Get("subjectId")), input.Get("tenantId"))
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:bindings:read", jsString(resourceID), func(ctx context.Context, call MutationContext) ([]any, error) {
		filter := core.NewObject("tenantId", input.Get("tenantId"))
		if roleID := input.Get("roleId"); !isUndefined(roleID) {
			text, err := Text(roleID, "roleId")
			if err != nil {
				return nil, err
			}
			filter.Set("roleId", text)
		}
		if subjectType := input.Get("subjectType"); !isUndefined(subjectType) {
			if subjectType != "identity" && subjectType != "group" {
				return nil, invalidInput("Invalid subject type")
			}
			filter.Set("subjectType", subjectType)
		}
		if subjectID := input.Get("subjectId"); !isUndefined(subjectID) {
			text, err := Text(subjectID, "subjectId")
			if err != nil {
				return nil, err
			}
			filter.Set("subjectId", text)
		}
		var eligible *bool
		if raw := input.Get("eligible"); !isUndefined(raw) {
			flag, err := bindingsBoolean(raw, "eligible")
			if err != nil {
				return nil, err
			}
			eligible = &flag
		}
		var expiresBefore *float64
		if raw := input.Get("expiresBefore"); !isUndefined(raw) {
			value, err := Integer(raw, "expiresBefore", 0, maxSafeInteger)
			if err != nil {
				return nil, err
			}
			expiresBefore = &value
		}
		found, err := call.Tx.Find(ctx, "bindings", filter, nil)
		if err != nil {
			return nil, err
		}
		includeExpired := input.Get("includeExpired") == true
		result := []any{}
		for _, binding := range found {
			expiresAt := binding.Get("expiresAt")
			if (includeExpired || !server.ExpiredBinding(binding)) &&
				(eligible == nil || truthy(binding.Get("eligible")) == *eligible) &&
				(expiresBefore == nil || (!isUndefined(expiresAt) && jsNumber(expiresAt) <= *expiresBefore)) {
				result = append(result, binding)
			}
		}
		return result, nil
	}, false)
	return Out[apitypes.BindingsListOutput]{Value: result}, err
}

// ListActivations is POST {basePath}/bindings/listActivations: activations of eligible bindings, newest first.
// Without `status`, live activations; `status: 'pending'` lists open requests and `'denied'` refused ones; ended
// records are included only with includeExpired.
func (api *BindingsAPI) ListActivations(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsListActivationsInput]) (Out[apitypes.BindingsListActivationsOutput], error) {
	server := api.server
	resourceID := coalesce(coalesce(coalesce(input.Get("bindingId"), input.Get("identityId")), input.Get("roleId")), input.Get("tenantId"))
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:bindings:read", jsString(resourceID), func(ctx context.Context, call MutationContext) ([]any, error) {
		filter := core.NewObject("tenantId", input.Get("tenantId"))
		for _, name := range []string{"bindingId", "identityId", "roleId"} {
			if raw := input.Get(name); !isUndefined(raw) {
				text, err := Text(raw, name)
				if err != nil {
					return nil, err
				}
				filter.Set(name, text)
			}
		}
		status := input.Get("status")
		if !isUndefined(status) && status != "pending" && status != "active" && status != "denied" {
			return nil, invalidInput("status must be pending, active, or denied")
		}
		now := float64(server.Now())
		found, err := call.Tx.Find(ctx, "bindingActivations", filter, nil)
		if err != nil {
			return nil, err
		}
		includeExpired := input.Get("includeExpired") == true
		kept := []*core.Object{}
		for _, activation := range found {
			var keep bool
			if isUndefined(status) {
				keep = includeExpired || liveBindingActivation(activation, now)
			} else {
				keep = stsStrictEqual(coalesce(activation.Get("status"), "active"), status) &&
					(includeExpired || status == "denied" || jsNumber(activation.Get("expiresAt")) > now)
			}
			if keep {
				kept = append(kept, activation)
			}
		}
		slices.SortStableFunc(kept, bindingActivationOrder(true))
		result := make([]any, len(kept))
		for index, activation := range kept {
			result[index] = publicBindingActivation(activation, now)
		}
		return result, nil
	}, false)
	return Out[apitypes.BindingsListActivationsOutput]{Value: result}, err
}

// ListApprovals is POST {basePath}/bindings/listApprovals: the pending activation requests the caller may decide
// on, oldest first: those of bindings whose approver group they belong to (any binding without a group, for holders
// of iam:bindings:approve on the role), never their own. Requires iam:bindings:approve on the tenant.
func (api *BindingsAPI) ListApprovals(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsListApprovalsInput]) (Out[apitypes.BindingsListApprovalsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:bindings:approve", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx, principal := call.Tx, call.Principal
		tenantID, _ := input.Get("tenantId").(string)
		now := float64(server.Now())
		result := []any{}
		activations, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", input.Get("tenantId")), nil)
		if err != nil {
			return nil, err
		}
		slices.SortStableFunc(activations, bindingActivationOrder(false))
		for _, activation := range activations {
			if !pendingBindingActivation(activation, now) || stsStrictEqual(activation.Get("identityId"), principal.Identity.Get("id")) {
				continue
			}
			binding, err := tx.Get(ctx, "bindings", jsString(activation.Get("bindingId")))
			if err != nil {
				return nil, err
			}
			if binding == nil {
				continue
			}
			allowed, err := api.mayApprove(ctx, tx, binding, principal, activation.Get("identityId"))
			if err != nil {
				return nil, err
			}
			if !allowed {
				continue
			}
			decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
				TenantID: tenantID, Action: "iam:bindings:approve", Resource: ResourceTarget{Type: "iam", ID: jsString(activation.Get("roleId"))},
			}, true)
			if err != nil {
				return nil, err
			}
			if !decision.Allowed {
				continue
			}
			role, err := tx.Get(ctx, "roles", jsString(activation.Get("roleId")))
			if err != nil {
				return nil, err
			}
			requester, err := tx.Get(ctx, "identities", jsString(activation.Get("identityId")))
			if err != nil {
				return nil, err
			}
			entry := publicBindingActivation(activation, now)
			if role != nil {
				entry.Set("role", core.NewObject("id", role.Get("id"), "name", role.Get("name")))
			}
			if requester != nil {
				summary := core.NewObject("id", requester.Get("id"), "name", requester.Get("name"))
				if email := requester.Get("email"); truthy(email) {
					summary.Set("email", email)
				}
				entry.Set("requester", summary)
			}
			result = append(result, entry)
		}
		return result, nil
	}, false)
	return Out[apitypes.BindingsListApprovalsOutput]{Value: result}, err
}

// ListMine is POST {basePath}/bindings/listMine: the caller's own bindings, direct and through groups, including
// eligible ones with their live activation or waiting request. Needs only iam:bindings:activate on the tenant, so
// members can see what they may elevate to.
func (api *BindingsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsListMineInput]) (Out[apitypes.BindingsListMineOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:bindings:activate", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) ([]any, error) {
		principal := call.Principal
		if !ActsInOwnRight(principal.Session) || !stsStrictEqual(principal.Session.Get("tenantId"), input.Get("tenantId")) {
			return nil, invalidInput("Bindings are listed from an ordinary session of the target tenant")
		}
		tenantID, _ := input.Get("tenantId").(string)
		effective, err := server.Decisions.EffectiveBindings(ctx, call.Tx, tenantID, jsString(principal.Identity.Get("id")))
		if err != nil {
			return nil, err
		}
		result := make([]any, len(effective))
		for index, binding := range effective {
			result[index] = binding.Model()
		}
		return result, nil
	}, false)
	return Out[apitypes.BindingsListMineOutput]{Value: result}, err
}

// RevokeActivation is POST {basePath}/bindings/revokeActivation: ends someone else's activation or pending request
// (incident response). Requires iam:bindings:delete on the binding and the binding's own authority, like deleting
// it. Audited as `binding:deactivate` with the holder.
func (api *BindingsAPI) RevokeActivation(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsRevokeActivationInput]) (Out[apitypes.BindingsRevokeActivationOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.BindingsRevokeActivationOutput]{}, err
	}
	existing, err := server.Scoped(ctx, server.Store, "bindingActivations", input.Get("activationId"), tenantID)
	if err != nil {
		return Out[apitypes.BindingsRevokeActivationOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:bindings:delete", jsString(existing.Get("bindingId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		activation, err := server.Scoped(ctx, tx, "bindingActivations", input.Get("activationId"), tenantID)
		if err != nil {
			return nil, err
		}
		binding, err := tx.Get(ctx, "bindings", jsString(activation.Get("bindingId")))
		if err != nil {
			return nil, err
		}
		if binding != nil {
			issued, err := issuedByCaller(ctx, server, tx, principal, binding)
			if err != nil {
				return nil, err
			}
			if !issued {
				return nil, core.NewIamError("ACCESS_DENIED", "Cannot mutate a higher authority binding", 403)
			}
		}
		if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
			return nil, err
		}
		metadata := core.NewObject(
			"activationId", activation.Get("id"),
			"roleId", activation.Get("roleId"),
			"identityId", activation.Get("identityId"),
			"revoked", true,
		)
		if err := server.Events.Audit(ctx, tx, principal, "binding:deactivate", tenantID, jsString(activation.Get("bindingId")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return core.NewObject("deactivated", true), nil
	}, false)
	return Out[apitypes.BindingsRevokeActivationOutput]{Value: result}, err
}

// Update is POST {basePath}/bindings/update: extends, shortens, or removes (null) a binding's expiry or start, sets
// or clears (null) its access window, or changes its eligibility settings. Requires iam:bindings:create on the role
// and the binding's own authority, like delete. Turning eligibility off ends every activation of the binding;
// editing a package's binding by hand takes it over.
func (api *BindingsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsUpdateInput]) (Out[apitypes.BindingsUpdateOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.BindingsUpdateOutput]{}, err
	}
	existing, err := server.Scoped(ctx, server.Store, "bindings", input.Get("bindingId"), tenantID)
	if err != nil {
		return Out[apitypes.BindingsUpdateOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:bindings:create", jsString(existing.Get("roleId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		binding, err := server.Scoped(ctx, tx, "bindings", input.Get("bindingId"), tenantID)
		if err != nil {
			return nil, err
		}
		role, err := tx.Get(ctx, "roles", jsString(binding.Get("roleId")))
		if err != nil {
			return nil, err
		}
		if role != nil && truthy(role.Get("protected")) {
			return nil, core.NewIamError("PROTECTED_RESOURCE", "Use owner transfer", 403)
		}
		issued, err := issuedByCaller(ctx, server, tx, principal, binding)
		if err != nil {
			return nil, err
		}
		if !issued {
			return nil, core.NewIamError("ACCESS_DENIED", "Cannot mutate a higher authority binding", 403)
		}
		changes := false
		for _, name := range []string{"startsAt", "expiresAt", "window", "eligible", "maxActivationMs", "requireJustification", "requireMfa", "requireApproval", "approverGroupId", "managerApproval"} {
			if !isUndefined(input.Get(name)) {
				changes = true
				break
			}
		}
		if !changes {
			return nil, invalidInput("Nothing to update")
		}
		// Editing a package's binding by hand takes it over: revoking the package no longer removes it.
		next := binding.Clone()
		next.Delete("packageAssignmentId")
		if expiresAt := input.Get("expiresAt"); expiresAt == nil {
			next.Delete("expiresAt")
		} else if !isUndefined(expiresAt) {
			value, err := server.BindingExpiry(expiresAt)
			if err != nil {
				return nil, err
			}
			next.Set("expiresAt", value)
		}
		if startsAt := input.Get("startsAt"); startsAt == nil {
			next.Delete("startsAt")
		} else if !isUndefined(startsAt) {
			value, err := server.BindingStart(startsAt)
			if err != nil {
				return nil, err
			}
			next.Set("startsAt", value)
		}
		if err := checkBindingPeriod(next); err != nil {
			return nil, err
		}
		if window := input.Get("window"); window == nil {
			next.Delete("window")
		} else if !isUndefined(window) {
			value, err := server.AccessWindow(window)
			if err != nil {
				return nil, err
			}
			next.Set("window", value)
		}
		if err := applyEligibility(next, input.Body); err != nil {
			return nil, err
		}
		if err := applyApprovers(ctx, server, tx, next, input.Body); err != nil {
			return nil, err
		}
		if truthy(binding.Get("eligible")) && !truthy(next.Get("eligible")) {
			if err := deleteBindingActivations(ctx, tx, tenantID, binding.Get("id")); err != nil {
				return nil, err
			}
		}
		return tx.Put(ctx, "bindings", next)
	}, false)
	return Out[apitypes.BindingsUpdateOutput]{Value: result}, err
}

// AuthoritiesAPI is the `authorities` API group (packages/server/src/api/bindings.ts createAuthoritiesApi): every
// method runs through the operation envelope; the router maps POST {basePath}/authorities/{method} onto it.
type AuthoritiesAPI struct {
	server *ServerContext
}

// CreateAuthoritiesAPI builds the `authorities` API group.
func CreateAuthoritiesAPI(server *ServerContext) *AuthoritiesAPI {
	return &AuthoritiesAPI{server: server}
}

// Create is POST {basePath}/authorities/create: delegates a narrower grant authority to another identity, bounded by
// a ceiling (validated against the catalog) and by the caller's own authority chain.
func (api *AuthoritiesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthoritiesCreateInput]) (Out[apitypes.AuthoritiesCreateOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:authorities:create", jsString(input.Get("identityId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID, _ := input.Get("tenantId").(string)
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if err := server.Catalog.Validate(ctx, tx, tenantID, input.Get("ceiling")); err != nil {
			return nil, err
		}
		if _, err := server.Scoped(ctx, tx, "identities", input.Get("identityId"), tenantID); err != nil {
			return nil, err
		}
		if stsStrictEqual(input.Get("identityId"), principal.Identity.Get("id")) {
			root, err := server.RootPrincipal(ctx, tx, principal)
			if err != nil {
				return nil, err
			}
			if !root {
				return nil, core.NewIamError("ACCESS_DENIED", "Cannot issue authority to yourself", 403)
			}
		}
		parent, err := grantingAuthorityFor(ctx, server, tx, principal, tenantID, input.Get("parentAuthorityId"))
		if err != nil {
			return nil, err
		}
		return tx.Insert(ctx, "grantAuthorities", core.NewObject(
			"id", ID(),
			"tenantId", input.Get("tenantId"),
			"identityId", input.Get("identityId"),
			"ceiling", input.Get("ceiling"),
			"parentAuthorityId", parent.Get("id"),
			"revoked", false,
		))
	}, false)
	return Out[apitypes.AuthoritiesCreateOutput]{Value: result}, err
}

// Revoke is POST {basePath}/authorities/revoke: withdraws a grant authority (root, or the holder of its parent
// authority, never on oneself), so everything issued under it, and under authorities delegated from it, stops
// granting at the next request.
func (api *AuthoritiesAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthoritiesRevokeInput]) (Out[apitypes.AuthoritiesRevokeOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:authorities:revoke", jsString(input.Get("authorityId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID, _ := input.Get("tenantId").(string)
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		authority, err := server.Scoped(ctx, tx, "grantAuthorities", input.Get("authorityId"), tenantID)
		if err != nil {
			return nil, err
		}
		var parent *core.Object
		if parentID := authority.Get("parentAuthorityId"); truthy(parentID) {
			if parent, err = tx.Get(ctx, "grantAuthorities", jsString(parentID)); err != nil {
				return nil, err
			}
		}
		root, err := server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		identityID := principal.Identity.Get("id")
		if !root && (parent == nil ||
			!stsStrictEqual(parent.Get("identityId"), identityID) ||
			stsStrictEqual(authority.Get("identityId"), identityID)) {
			return nil, core.NewIamError("ACCESS_DENIED", "Only superior authority can revoke this grant", 403)
		}
		return tx.Put(ctx, "grantAuthorities", authority.Spread(core.NewObject("revoked", true)))
	}, false)
	return Out[apitypes.AuthoritiesRevokeOutput]{Value: result}, err
}
