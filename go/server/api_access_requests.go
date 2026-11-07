package server

// Port of packages/server/src/api/access-requests.ts: members ask for roles, optionally for a limited time, and a
// reviewer approves them under their own grant authority (nothing is granted before that).

import (
	"context"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// AccessRequestsAPI is the `accessRequests` API group (packages/server/src/api/access-requests.ts createAccessRequestsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/accessRequests/{method} onto it.
type AccessRequestsAPI struct {
	server *ServerContext
}

// CreateAccessRequestsAPI builds the `accessRequests` API group.
func CreateAccessRequestsAPI(server *ServerContext) *AccessRequestsAPI {
	return &AccessRequestsAPI{server: server}
}

var accessRequestStatuses = newOrderedSet("pending", "approved", "denied", "cancelled", "expired")

// effective reads a pending request past its lifetime as expired, even before the purge worker marks it.
func (api *AccessRequestsAPI) effective(request *core.Object) *core.Object {
	if request.Get("status") == "pending" && jsNumber(request.Get("expiresAt")) <= float64(api.server.Now()) {
		return request.Spread(core.NewObject("status", "expired"))
	}
	return request
}

// pending is the request when it is still pending (INVALID_TRANSITION otherwise).
func (api *AccessRequestsAPI) pending(ctx context.Context, tx core.IamStore, requestID any, tenantID string) (*core.Object, error) {
	found, err := api.server.Scoped(ctx, tx, "accessRequests", requestID, tenantID)
	if err != nil {
		return nil, err
	}
	request := api.effective(found)
	if request.Get("status") != "pending" {
		return nil, core.NewIamError("INVALID_TRANSITION", "Request is "+jsString(request.Get("status")), 409)
	}
	return request, nil
}

// accessRequestStatusFilter adds a validated status to a filter (nothing when the status is absent).
func accessRequestStatusFilter(status any, filter *core.Object) error {
	if isUndefined(status) {
		return nil
	}
	text, ok := status.(string)
	if !ok || !accessRequestStatuses.Has(text) {
		return invalidInput("Invalid status")
	}
	filter.Set("status", text)
	return nil
}

// newestRequests is the requests read as effective, newest first.
func (api *AccessRequestsAPI) newestRequests(requests []*core.Object) []any {
	effective := make([]*core.Object, len(requests))
	for index, request := range requests {
		effective[index] = api.effective(request)
	}
	sort.SliceStable(effective, func(i, j int) bool { return ByNewest(effective[i], effective[j]) < 0 })
	return certRecordList(effective)
}

// Approve is POST {basePath}/accessRequests/approve. Approval binds the requested roles under the reviewer's grant
// authority, exactly as bindings.create would, so a reviewer can never grant more than they could bind directly.
// durationSeconds overrides the requested duration; the grant expires accordingly.
func (api *AccessRequestsAPI) Approve(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsApproveInput]) (Out[apitypes.AccessRequestsApproveOutput], error) {
	server := api.server
	config := server.Config
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:access-requests:review", jsString(input.Get("requestId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(rawTenantID)
		request, err := api.pending(ctx, tx, input.Get("requestId"), tenantID)
		if err != nil {
			return nil, err
		}
		if request.Get("requesterId") == principal.Identity.Get("id") {
			return nil, core.NewIamError("ACCESS_DENIED", "A request cannot be approved by its requester", 403)
		}
		// Two-person control: an administrator viewing as a reviewer must not decide in their name.
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Requests cannot be decided while impersonating", 403)
		}
		requester, err := server.ActiveIdentity(ctx, tx, request.Get("requesterId"), tenantID)
		if err != nil {
			return nil, err
		}
		if requester.Get("status") != "active" {
			return nil, core.NewIamError("INVALID_IDENTITY", "Requester is not active")
		}
		duration := request.Get("durationSeconds")
		if raw := input.Get("durationSeconds"); !isUndefined(raw) {
			if duration, err = Integer(raw, "durationSeconds", 60, float64(config.AccessRequestMaxDurationSeconds)); err != nil {
				return nil, err
			}
		}
		var grantExpiresAt any = core.Undefined
		if !isUndefined(duration) {
			grantExpiresAt = float64(server.Now()) + jsNumber(duration)*1000
		}
		authority, err := server.GrantingAuthority(ctx, tx, principal, tenantID, "")
		if err != nil {
			return nil, err
		}
		bindingIDs := []any{}
		roleIDs, _ := request.Get("roleIds").([]any)
		for _, roleID := range roleIDs {
			role, err := server.Scoped(ctx, tx, "roles", roleID, tenantID)
			if err != nil {
				return nil, err
			}
			if truthy(role.Get("protected")) {
				return nil, core.NewIamError("PROTECTED_RESOURCE", "Owner roles cannot be granted this way", 403)
			}
			decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
				TenantID: tenantID, Action: "iam:bindings:create", Resource: ResourceTarget{Type: "iam", ID: jsString(role.Get("id"))},
			}, true)
			if err != nil {
				return nil, err
			}
			if !decision.Allowed {
				return nil, core.NewIamError("ACCESS_DENIED", "Cannot grant role "+jsString(role.Get("name")), 403)
			}
			uniqueKey := "identity:" + jsString(requester.Get("id")) + ":" + jsString(role.Get("id")) + ":" + jsString(authority.Get("id"))
			found, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
			if err != nil {
				return nil, err
			}
			var existing *core.Object
			if len(found) > 0 {
				existing = found[0]
			}
			var base *core.Object
			if existing != nil {
				base = existing.Spread()
			} else {
				base = core.NewObject(
					"id", ID(),
					"tenantId", tenantID,
					"uniqueKey", uniqueKey,
					"subjectType", "identity",
					"subjectId", requester.Get("id"),
					"roleId", role.Get("id"),
					"authorityId", authority.Get("id"),
				)
			}
			base.Delete("expiresAt")
			binding := base.Set("accessRequestId", request.Get("id"))
			if !isUndefined(grantExpiresAt) {
				binding.Set("expiresAt", grantExpiresAt)
			}
			var written *core.Object
			if existing != nil {
				written, err = tx.Put(ctx, "bindings", binding)
			} else {
				written, err = tx.Insert(ctx, "bindings", binding)
			}
			if err != nil {
				return nil, err
			}
			bindingIDs = append(bindingIDs, written.Get("id"))
		}
		decided := request.Spread(core.NewObject(
			"status", "approved",
			"reviewerId", principal.Identity.Get("id"),
			"reviewedAt", float64(server.Now()),
			"bindingIds", bindingIDs,
		))
		if !isUndefined(grantExpiresAt) {
			decided.Set("grantExpiresAt", grantExpiresAt)
		}
		if note := input.Get("note"); !isUndefined(note) {
			text, err := Text(note, "note", 2048)
			if err != nil {
				return nil, err
			}
			decided.Set("note", text)
		}
		metadata := core.NewObject("requesterId", request.Get("requesterId"), "roleIds", request.Get("roleIds"), "bindingIds", bindingIDs)
		if !isUndefined(grantExpiresAt) {
			metadata.Set("grantExpiresAt", grantExpiresAt)
		}
		if err := server.Events.Audit(ctx, tx, principal, "access-request:approve", tenantID, jsString(request.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return tx.Put(ctx, "accessRequests", decided)
	}, false)
	return Out[apitypes.AccessRequestsApproveOutput]{Value: result}, err
}

// Cancel is POST {basePath}/accessRequests/cancel. Withdraws one of your own pending requests.
func (api *AccessRequestsAPI) Cancel(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsCancelInput]) (Out[apitypes.AccessRequestsCancelOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:access-requests:create", jsString(input.Get("requestId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		request, err := api.pending(ctx, call.Tx, input.Get("requestId"), jsString(rawTenantID))
		if err != nil {
			return nil, err
		}
		if request.Get("requesterId") != call.Principal.Identity.Get("id") {
			return nil, core.NewIamError("ACCESS_DENIED", "Only the requester can cancel a request", 403)
		}
		return call.Tx.Put(ctx, "accessRequests", request.Spread(core.NewObject("status", "cancelled", "reviewedAt", float64(server.Now()))))
	}, false)
	return Out[apitypes.AccessRequestsCancelOutput]{Value: result}, err
}

// Create is POST {basePath}/accessRequests/create. A member asks for roles, optionally for a limited time. Nothing is
// granted until a reviewer approves under their own grant authority.
func (api *AccessRequestsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsCreateInput]) (Out[apitypes.AccessRequestsCreateOutput], error) {
	server := api.server
	config := server.Config
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:access-requests:create", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, realm := call.Tx, call.Principal, call.Tenant
		realmID := jsString(realm.Get("id"))
		if realm.Get("status") != "active" {
			return nil, core.NewIamError("TENANT_INACTIVE", "Tenant must be active")
		}
		if principal.Session.Get("tenantId") != realm.Get("id") || !ActsInOwnRight(principal.Session) {
			return nil, invalidInput("Requests are made from an ordinary session of the target tenant")
		}
		requested, err := Strings(input.Get("roleIds"), "roleIds")
		if err != nil {
			return nil, err
		}
		roleIDs := unique(requested)
		if len(roleIDs) == 0 || len(roleIDs) > 20 {
			return nil, invalidInput("Request 1-20 roles")
		}
		for _, roleID := range roleIDs {
			role, err := server.Scoped(ctx, tx, "roles", roleID, realmID)
			if err != nil {
				return nil, err
			}
			if truthy(role.Get("protected")) {
				return nil, core.NewIamError("PROTECTED_RESOURCE", "Owner roles cannot be requested", 403)
			}
		}
		open, err := tx.Find(ctx, "accessRequests", core.NewObject("tenantId", realm.Get("id"), "requesterId", principal.Identity.Get("id"), "status", "pending"), nil)
		if err != nil {
			return nil, err
		}
		if len(open) >= 20 {
			return nil, core.NewIamError("TOO_MANY_REQUESTS", "Resolve pending requests before opening more", 429)
		}
		for _, existing := range open {
			existingRoles, _ := existing.Get("roleIds").([]any)
			if jsNumber(existing.Get("expiresAt")) > float64(server.Now()) && len(existingRoles) == len(roleIDs) {
				every := true
				for _, roleID := range existingRoles {
					if text, ok := roleID.(string); !ok || !containsString(roleIDs, text) {
						every = false
						break
					}
				}
				if every {
					return nil, core.NewIamError("CONFLICT", "An identical request is already pending", 409)
				}
			}
		}
		request := core.NewObject(
			"id", ID(),
			"tenantId", realm.Get("id"),
			"requesterId", principal.Identity.Get("id"),
			"roleIds", stringsOf(roleIDs),
			"status", "pending",
			"createdAt", float64(server.Now()),
			"expiresAt", float64(server.Now())+float64(config.AccessRequestLifetimeMs),
		)
		if justification := input.Get("justification"); !isUndefined(justification) {
			text, err := Text(justification, "justification", 2048)
			if err != nil {
				return nil, err
			}
			request.Set("justification", text)
		}
		if duration := input.Get("durationSeconds"); !isUndefined(duration) {
			seconds, err := Integer(duration, "durationSeconds", 60, float64(config.AccessRequestMaxDurationSeconds))
			if err != nil {
				return nil, err
			}
			request.Set("durationSeconds", seconds)
		}
		return tx.Insert(ctx, "accessRequests", request)
	}, false)
	return Out[apitypes.AccessRequestsCreateOutput]{Value: result}, err
}

// Deny is POST {basePath}/accessRequests/deny. Refuses a pending request, with an optional note for the requester.
func (api *AccessRequestsAPI) Deny(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsDenyInput]) (Out[apitypes.AccessRequestsDenyOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:access-requests:review", jsString(input.Get("requestId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(rawTenantID)
		request, err := api.pending(ctx, tx, input.Get("requestId"), tenantID)
		if err != nil {
			return nil, err
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Requests cannot be decided while impersonating", 403)
		}
		decided := request.Spread(core.NewObject(
			"status", "denied",
			"reviewerId", principal.Identity.Get("id"),
			"reviewedAt", float64(server.Now()),
		))
		if note := input.Get("note"); !isUndefined(note) {
			text, err := Text(note, "note", 2048)
			if err != nil {
				return nil, err
			}
			decided.Set("note", text)
		}
		if err := server.Events.Audit(ctx, tx, principal, "access-request:deny", tenantID, jsString(request.Get("id")), "allow", false,
			core.NewObject("requesterId", request.Get("requesterId"), "roleIds", request.Get("roleIds"))); err != nil {
			return nil, err
		}
		return tx.Put(ctx, "accessRequests", decided)
	}, false)
	return Out[apitypes.AccessRequestsDenyOutput]{Value: result}, err
}

// Get is POST {basePath}/accessRequests/get. Returns one request.
func (api *AccessRequestsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsGetInput]) (Out[apitypes.AccessRequestsGetOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:access-requests:read", jsString(input.Get("requestId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		request, err := api.server.Scoped(ctx, call.Tx, "accessRequests", input.Get("requestId"), jsString(rawTenantID))
		if err != nil {
			return nil, err
		}
		return api.effective(request), nil
	}, false)
	return Out[apitypes.AccessRequestsGetOutput]{Value: result}, err
}

// List is POST {basePath}/accessRequests/list. Lists the tenant's requests, newest first, optionally by status or requester.
func (api *AccessRequestsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsListInput]) (Out[apitypes.AccessRequestsListOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:access-requests:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		filter := core.NewObject("tenantId", rawTenantID)
		if err := accessRequestStatusFilter(input.Get("status"), filter); err != nil {
			return nil, err
		}
		if requesterID := input.Get("requesterId"); !isUndefined(requesterID) {
			text, err := Text(requesterID, "requesterId")
			if err != nil {
				return nil, err
			}
			filter.Set("requesterId", text)
		}
		requests, err := call.Tx.Find(ctx, "accessRequests", filter, nil)
		if err != nil {
			return nil, err
		}
		return api.newestRequests(requests), nil
	}, false)
	return Out[apitypes.AccessRequestsListOutput]{Value: result}, err
}

// ListMine is POST {basePath}/accessRequests/listMine. The caller's own requests, newest first, optionally by status;
// needs only the permission to create requests.
func (api *AccessRequestsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.AccessRequestsListMineInput]) (Out[apitypes.AccessRequestsListMineOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:access-requests:create", jsString(rawTenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		filter := core.NewObject("tenantId", rawTenantID, "requesterId", call.Principal.Identity.Get("id"))
		if err := accessRequestStatusFilter(input.Get("status"), filter); err != nil {
			return nil, err
		}
		requests, err := call.Tx.Find(ctx, "accessRequests", filter, nil)
		if err != nil {
			return nil, err
		}
		return api.newestRequests(requests), nil
	}, false)
	return Out[apitypes.AccessRequestsListMineOutput]{Value: result}, err
}
