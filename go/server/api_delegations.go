package server

// Skeleton of packages/server/src/api/delegations.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// DelegationsAPI is the `delegations` API group (packages/server/src/api/delegations.ts createDelegationsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/delegations/{method} onto it.
type DelegationsAPI struct {
	server *ServerContext
}

// CreateDelegationsAPI builds the `delegations` API group.
func CreateDelegationsAPI(server *ServerContext) *DelegationsAPI {
	return &DelegationsAPI{server: server}
}

// Activity is POST {basePath}/delegations/activity. Returns what happened under a delegation, newest first: its lifecycle and everything the agent did for the person.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) Activity(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsActivityInput]) (Out[apitypes.DelegationsActivityOutput], error) {
	return Out[apitypes.DelegationsActivityOutput]{}, notImplemented("delegations.activity")
}

// Approve is POST {basePath}/delegations/approve. Approves an agent's pending request, optionally with a different scope, lifetime, or session cap.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) Approve(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsApproveInput]) (Out[apitypes.DelegationsApproveOutput], error) {
	return Out[apitypes.DelegationsApproveOutput]{}, notImplemented("delegations.approve")
}

// Assume is POST {basePath}/delegations/assume. Opens a delegated session in which the agent acts for the person, and returns its bearer token once.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) Assume(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsAssumeInput]) (Out[apitypes.DelegationsAssumeOutput], error) {
	return Out[apitypes.DelegationsAssumeOutput]{}, notImplemented("delegations.assume")
}

// DecideConfirmation is POST {basePath}/delegations/decideConfirmation. Approves or rejects an agent's pending confirmation request.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) DecideConfirmation(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsDecideConfirmationInput]) (Out[apitypes.DelegationsDecideConfirmationOutput], error) {
	return Out[apitypes.DelegationsDecideConfirmationOutput]{}, notImplemented("delegations.decideConfirmation")
}

// Deny is POST {basePath}/delegations/deny. Turns down an agent's pending request.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) Deny(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsDenyInput]) (Out[apitypes.DelegationsDenyOutput], error) {
	return Out[apitypes.DelegationsDenyOutput]{}, notImplemented("delegations.deny")
}

// Get is POST {basePath}/delegations/get. Returns one delegation to the person, the agent, or the agent's sponsor, or to an administrator.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsGetInput]) (Out[apitypes.DelegationsGetOutput], error) {
	return Out[apitypes.DelegationsGetOutput]{}, notImplemented("delegations.get")
}

// GetConfirmation is POST {basePath}/delegations/getConfirmation. Returns one confirmation request to the person it asks or to the agent that made it.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) GetConfirmation(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsGetConfirmationInput]) (Out[apitypes.DelegationsGetConfirmationOutput], error) {
	return Out[apitypes.DelegationsGetConfirmationOutput]{}, notImplemented("delegations.getConfirmation")
}

// Grant is POST {basePath}/delegations/grant. Lets an agent act for you, within a scope and for a limited time.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) Grant(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsGrantInput]) (Out[apitypes.DelegationsGrantOutput], error) {
	return Out[apitypes.DelegationsGrantOutput]{}, notImplemented("delegations.grant")
}

// Handoff is POST {basePath}/delegations/handoff. Hands part of the delegation an agent acts under on to another agent, for the same person.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) Handoff(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsHandoffInput]) (Out[apitypes.DelegationsHandoffOutput], error) {
	return Out[apitypes.DelegationsHandoffOutput]{}, notImplemented("delegations.handoff")
}

// IssueToken is POST {basePath}/delegations/issueToken. Gives an agent acting for a person a delegation token: a short-lived signed JWT that shows one service outside Better IAM that the agent acts for that person.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) IssueToken(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsIssueTokenInput]) (Out[apitypes.DelegationsIssueTokenOutput], error) {
	return Out[apitypes.DelegationsIssueTokenOutput]{}, notImplemented("delegations.issueToken")
}

// List is POST {basePath}/delegations/list. Lists the tenant's delegations, newest first, filtered by agent, person, or status.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsListInput]) (Out[apitypes.DelegationsListOutput], error) {
	return Out[apitypes.DelegationsListOutput]{}, notImplemented("delegations.list")
}

// ListConfirmations is POST {basePath}/delegations/listConfirmations. Lists confirmation requests newest first: those addressed to the caller, or those the calling agent made.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) ListConfirmations(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsListConfirmationsInput]) (Out[apitypes.DelegationsListConfirmationsOutput], error) {
	return Out[apitypes.DelegationsListConfirmationsOutput]{}, notImplemented("delegations.listConfirmations")
}

// ListMine is POST {basePath}/delegations/listMine. Returns your own delegations, newest first: the agents acting or asking to act for you, or, for an agent, the people it acts for.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsListMineInput]) (Out[apitypes.DelegationsListMineOutput], error) {
	return Out[apitypes.DelegationsListMineOutput]{}, notImplemented("delegations.listMine")
}

// Request is POST {basePath}/delegations/request. Asks a person to delegate to the calling agent, and emails them the request when the deployment sends email.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) Request(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsRequestInput]) (Out[apitypes.DelegationsRequestOutput], error) {
	return Out[apitypes.DelegationsRequestOutput]{}, notImplemented("delegations.request")
}

// RequestConfirmation is POST {basePath}/delegations/requestConfirmation. Asks the person an agent acts for to confirm one action the delegation holds back.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) RequestConfirmation(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsRequestConfirmationInput]) (Out[apitypes.DelegationsRequestConfirmationOutput], error) {
	return Out[apitypes.DelegationsRequestConfirmationOutput]{}, notImplemented("delegations.requestConfirmation")
}

// Revoke is POST {basePath}/delegations/revoke. Ends a pending or active delegation and deletes its live delegated sessions at once.
//
// STUB: returns NOT_IMPLEMENTED until api/delegations.ts is ported.
func (api *DelegationsAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsRevokeInput]) (Out[apitypes.DelegationsRevokeOutput], error) {
	return Out[apitypes.DelegationsRevokeOutput]{}, notImplemented("delegations.revoke")
}
