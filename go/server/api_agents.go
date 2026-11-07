package server

// Skeleton of packages/server/src/api/agents.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// AgentsAPI is the `agents` API group (packages/server/src/api/agents.ts createAgentsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/agents/{method} onto it.
type AgentsAPI struct {
	server *ServerContext
}

// CreateAgentsAPI builds the `agents` API group.
func CreateAgentsAPI(server *ServerContext) *AgentsAPI {
	return &AgentsAPI{server: server}
}

// Activity is POST {basePath}/agents/activity. Returns what an agent did, newest first: the audit events of its own credentials and of the sessions in which it acted for people.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) Activity(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsActivityInput]) (Out[apitypes.AgentsActivityOutput], error) {
	return Out[apitypes.AgentsActivityOutput]{}, notImplemented("agents.activity")
}

// Catalog is POST {basePath}/agents/catalog. Lists the agents people of the tenant may delegate to, with what a person needs to decide.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) Catalog(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsCatalogInput]) (Out[apitypes.AgentsCatalogOutput], error) {
	return Out[apitypes.AgentsCatalogOutput]{}, notImplemented("agents.catalog")
}

// Create is POST {basePath}/agents/create. Registers an AI agent with a sponsor and an optional profile.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsCreateInput]) (Out[apitypes.AgentsCreateOutput], error) {
	return Out[apitypes.AgentsCreateOutput]{}, notImplemented("agents.create")
}

// Delete is POST {basePath}/agents/delete. Deletes an agent, ending its keys and sessions and revoking every delegation to it.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsDeleteInput]) (Out[apitypes.AgentsDeleteOutput], error) {
	return Out[apitypes.AgentsDeleteOutput]{}, notImplemented("agents.delete")
}

// Directory is POST {basePath}/agents/directory. Lists the tenant's agents that hold a current attested A2A card, for finding an agent to work with or hand work to.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) Directory(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsDirectoryInput]) (Out[apitypes.AgentsDirectoryOutput], error) {
	return Out[apitypes.AgentsDirectoryOutput]{}, notImplemented("agents.directory")
}

// Get is POST {basePath}/agents/get. Returns one agent with its standing, its live API keys, and counts of its delegations.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsGetInput]) (Out[apitypes.AgentsGetOutput], error) {
	return Out[apitypes.AgentsGetOutput]{}, notImplemented("agents.get")
}

// List is POST {basePath}/agents/list. Lists the tenant's agents, newest first, optionally only one sponsor's or those in one standing.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsListInput]) (Out[apitypes.AgentsListOutput], error) {
	return Out[apitypes.AgentsListOutput]{}, notImplemented("agents.list")
}

// ListMine is POST {basePath}/agents/listMine. Returns the agents you sponsor, newest first, with the same detail as get.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsListMineInput]) (Out[apitypes.AgentsListMineOutput], error) {
	return Out[apitypes.AgentsListMineOutput]{}, notImplemented("agents.listMine")
}

// Resume is POST {basePath}/agents/resume. Lifts an agent's suspension, so its kept API keys work again.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) Resume(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsResumeInput]) (Out[apitypes.AgentsResumeOutput], error) {
	return Out[apitypes.AgentsResumeOutput]{}, notImplemented("agents.resume")
}

// SignCard is POST {basePath}/agents/signCard. Signs an agent's A2A (Agent2Agent) agent card, so other agents can check that it is a registered agent in good standing of your organization.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) SignCard(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsSignCardInput]) (Out[apitypes.AgentsSignCardOutput], error) {
	return Out[apitypes.AgentsSignCardOutput]{}, notImplemented("agents.signCard")
}

// Standing is POST {basePath}/agents/standing. Tells whether an agent may act right now and, if not, why.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) Standing(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsStandingInput]) (Out[apitypes.AgentsStandingOutput], error) {
	return Out[apitypes.AgentsStandingOutput]{}, notImplemented("agents.standing")
}

// Suspend is POST {basePath}/agents/suspend. Stops an agent at once (the kill switch) and keeps its API keys for resume.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) Suspend(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsSuspendInput]) (Out[apitypes.AgentsSuspendOutput], error) {
	return Out[apitypes.AgentsSuspendOutput]{}, notImplemented("agents.suspend")
}

// SuspendAll is POST {basePath}/agents/suspendAll. The organization-wide emergency stop: suspends every active agent of the tenant at once.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) SuspendAll(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsSuspendAllInput]) (Out[apitypes.AgentsSuspendAllOutput], error) {
	return Out[apitypes.AgentsSuspendAllOutput]{}, notImplemented("agents.suspendAll")
}

// Update is POST {basePath}/agents/update. Changes an agent's name, description, expiry, attributes, profile, or sponsor.
//
// STUB: returns NOT_IMPLEMENTED until api/agents.ts is ported.
func (api *AgentsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsUpdateInput]) (Out[apitypes.AgentsUpdateOutput], error) {
	return Out[apitypes.AgentsUpdateOutput]{}, notImplemented("agents.update")
}

// AgentMutationsResult is api/agents.ts agentMutations().
type AgentMutationsResult struct {
	server *ServerContext
}

// CreateAgent (api/agents.ts agentMutations().createAgent): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *AgentMutationsResult) CreateAgent(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/agents.ts agentMutations().createAgent")
	return
}

// UpdateAgent (api/agents.ts agentMutations().updateAgent): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *AgentMutationsResult) UpdateAgent(ctx context.Context, tx core.IamStore, principal *Principal, agent *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/agents.ts agentMutations().updateAgent")
	return
}

// DeleteAgent (api/agents.ts agentMutations().deleteAgent): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *AgentMutationsResult) DeleteAgent(ctx context.Context, tx core.IamStore, principal *Principal, agent *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/agents.ts agentMutations().deleteAgent")
	return
}

// AgentMutations (api/agents.ts agentMutations): Agent changes without a credential, for the `agents` API (which
// authorizes first) and for configuration sync (ai-sync.ts). Every function runs inside the caller's transaction and
// audits like the API.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AgentMutations(server *ServerContext) (result *AgentMutationsResult, err error) {
	err = notImplemented("api/agents.ts agentMutations")
	return
}

// AuditActivity (api/agents.ts auditActivity): Audit events newest first in a tenant that match `where`, with the
// paging of an activity query.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AuditActivity(ctx context.Context, tx core.IamStore, tenantID string, query *core.Object, where func(*core.Object) bool) (result []*core.Object, err error) {
	err = notImplemented("api/agents.ts auditActivity")
	return
}
