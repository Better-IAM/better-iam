package server

// Skeleton of packages/server/src/api/inference.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"
	"net/http"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// InferenceAPI is the `inference` API group (packages/server/src/api/inference.ts createInferenceApi): every method runs through the
// operation envelope; the router maps POST {basePath}/inference/{method} onto it.
type InferenceAPI struct {
	server *ServerContext
}

// CreateInferenceAPI builds the `inference` API group.
func CreateInferenceAPI(server *ServerContext) *InferenceAPI {
	return &InferenceAPI{server: server}
}

// Check is POST {basePath}/inference/check. Tells the caller whether they may invoke a model now and, when they may, returns a single-use ticket for an external gateway.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) Check(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceCheckInput]) (Out[apitypes.InferenceCheckOutput], error) {
	return Out[apitypes.InferenceCheckOutput]{}, notImplemented("inference.check")
}

// CreateModel is POST {basePath}/inference/createModel. Publishes a model under a public name, served by a provider of this tenant or an ancestor.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) CreateModel(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceCreateModelInput]) (Out[apitypes.InferenceCreateModelOutput], error) {
	return Out[apitypes.InferenceCreateModelOutput]{}, notImplemented("inference.createModel")
}

// CreateProvider is POST {basePath}/inference/createProvider. Registers an upstream model provider account, whose API key is sealed and never returned.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) CreateProvider(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceCreateProviderInput]) (Out[apitypes.InferenceCreateProviderOutput], error) {
	return Out[apitypes.InferenceCreateProviderOutput]{}, notImplemented("inference.createProvider")
}

// DeleteBudget is POST {basePath}/inference/deleteBudget. Deletes a budget together with its usage counters.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) DeleteBudget(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceDeleteBudgetInput]) (Out[apitypes.InferenceDeleteBudgetOutput], error) {
	return Out[apitypes.InferenceDeleteBudgetOutput]{}, notImplemented("inference.deleteBudget")
}

// DeleteModel is POST {basePath}/inference/deleteModel. Removes one of this tenant's models; an inherited model of the same name becomes visible again.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) DeleteModel(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceDeleteModelInput]) (Out[apitypes.InferenceDeleteModelOutput], error) {
	return Out[apitypes.InferenceDeleteModelOutput]{}, notImplemented("inference.deleteModel")
}

// DeleteProvider is POST {basePath}/inference/deleteProvider. Deletes a provider that no model uses, together with its sealed key.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) DeleteProvider(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceDeleteProviderInput]) (Out[apitypes.InferenceDeleteProviderOutput], error) {
	return Out[apitypes.InferenceDeleteProviderOutput]{}, notImplemented("inference.deleteProvider")
}

// ListBudgets is POST {basePath}/inference/listBudgets. Lists the tenant's budgets by name, with the current window's standing of each shared pool.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) ListBudgets(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceListBudgetsInput]) (Out[apitypes.InferenceListBudgetsOutput], error) {
	return Out[apitypes.InferenceListBudgetsOutput]{}, notImplemented("inference.listBudgets")
}

// ListMine is POST {basePath}/inference/listMine. Lists the enabled models the caller may invoke, for a model picker.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceListMineInput]) (Out[apitypes.InferenceListMineOutput], error) {
	return Out[apitypes.InferenceListMineOutput]{}, notImplemented("inference.listMine")
}

// ListModels is POST {basePath}/inference/listModels. Lists every model the tenant can see, its own and inherited ones, by name.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) ListModels(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceListModelsInput]) (Out[apitypes.InferenceListModelsOutput], error) {
	return Out[apitypes.InferenceListModelsOutput]{}, notImplemented("inference.listModels")
}

// ListProviders is POST {basePath}/inference/listProviders. Lists the providers this tenant's models may use: its own, then its ancestors'.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) ListProviders(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceListProvidersInput]) (Out[apitypes.InferenceListProvidersOutput], error) {
	return Out[apitypes.InferenceListProvidersOutput]{}, notImplemented("inference.listProviders")
}

// MyUsage is POST {basePath}/inference/myUsage. Returns the caller's own usage by model and the standing of every budget that covers them.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) MyUsage(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceMyUsageInput]) (Out[apitypes.InferenceMyUsageOutput], error) {
	return Out[apitypes.InferenceMyUsageOutput]{}, notImplemented("inference.myUsage")
}

// Record is POST {basePath}/inference/record. Meters a call an external gateway made after check, by redeeming the check's ticket.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) Record(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceRecordInput]) (Out[apitypes.InferenceRecordOutput], error) {
	return Out[apitypes.InferenceRecordOutput]{}, notImplemented("inference.record")
}

// SetBudget is POST {basePath}/inference/setBudget. Creates a budget, or replaces one when budgetId is given.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) SetBudget(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceSetBudgetInput]) (Out[apitypes.InferenceSetBudgetOutput], error) {
	return Out[apitypes.InferenceSetBudgetOutput]{}, notImplemented("inference.setBudget")
}

// UpdateModel is POST {basePath}/inference/updateModel. Changes one of this tenant's models, found by its name.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) UpdateModel(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceUpdateModelInput]) (Out[apitypes.InferenceUpdateModelOutput], error) {
	return Out[apitypes.InferenceUpdateModelOutput]{}, notImplemented("inference.updateModel")
}

// UpdateProvider is POST {basePath}/inference/updateProvider. Renames a provider, moves its base URL, or replaces its API key.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) UpdateProvider(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceUpdateProviderInput]) (Out[apitypes.InferenceUpdateProviderOutput], error) {
	return Out[apitypes.InferenceUpdateProviderOutput]{}, notImplemented("inference.updateProvider")
}

// Usage is POST {basePath}/inference/usage. Reports model calls between two times, grouped by identity, agent, model, or day.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (api *InferenceAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceUsageInput]) (Out[apitypes.InferenceUsageOutput], error) {
	return Out[apitypes.InferenceUsageOutput]{}, notImplemented("inference.usage")
}

// InferenceRuntime is inference access control (`inference` option), server side (api/inference.ts
// createInferenceRuntime): model checks that return the opened provider credential, metering, and the HTTP gateway.
type InferenceRuntime struct {
	server *ServerContext
}

// CreateInferenceRuntime builds the runtime; its methods are stubs until api/inference.ts is ported.
func CreateInferenceRuntime(server *ServerContext) *InferenceRuntime {
	return &InferenceRuntime{server: server}
}

// Authorize checks a model invocation for a credential and returns the permit with the opened provider credential.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (r *InferenceRuntime) Authorize(ctx context.Context, input *core.Object) (*core.Object, error) {
	return nil, notImplemented("api/inference.ts createInferenceRuntime().authorize")
}

// Record meters one invocation for a permit (tokens, cost) and charges budgets.
//
// STUB: returns NOT_IMPLEMENTED until api/inference.ts is ported.
func (r *InferenceRuntime) Record(ctx context.Context, permit *core.Object, usage *core.Object) (*core.Object, error) {
	return nil, notImplemented("api/inference.ts createInferenceRuntime().record")
}

// Gateway is the HTTP inference gateway (OpenAI Responses and embeddings shaped) governed by the inference policies.
//
// STUB: the handler answers 501 until api/inference.ts and inference-gateway.ts are ported.
func (r *InferenceRuntime) Gateway(options *core.Object) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeResponse(w, errorResponse(notImplemented("inference-gateway.ts createInferenceGateway")))
	})
}

// InferenceMutationsResult is api/inference.ts inferenceMutations().
type InferenceMutationsResult struct {
	server *ServerContext
}

// OwnModel (api/inference.ts inferenceMutations().ownModel): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *InferenceMutationsResult) OwnModel(ctx context.Context, tx core.IamStore, tenantID string, name string) (result *core.Object, err error) {
	err = notImplemented("api/inference.ts inferenceMutations().ownModel")
	return
}

// ApplyModelFields (api/inference.ts inferenceMutations().applyModelFields): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *InferenceMutationsResult) ApplyModelFields(next *core.Object, input *core.Object) (err error) {
	err = notImplemented("api/inference.ts inferenceMutations().applyModelFields")
	return
}

// BudgetView (api/inference.ts inferenceMutations().budgetView): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *InferenceMutationsResult) BudgetView(ctx context.Context, tx core.IamStore, budget *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/inference.ts inferenceMutations().budgetView")
	return
}

// BudgetFields (api/inference.ts inferenceMutations().budgetFields): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *InferenceMutationsResult) BudgetFields(ctx context.Context, tx core.IamStore, tenantID string, input *core.Object, previous *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/inference.ts inferenceMutations().budgetFields")
	return
}

// CreateModel (api/inference.ts inferenceMutations().createModel): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *InferenceMutationsResult) CreateModel(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/inference.ts inferenceMutations().createModel")
	return
}

// UpdateModel (api/inference.ts inferenceMutations().updateModel): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *InferenceMutationsResult) UpdateModel(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/inference.ts inferenceMutations().updateModel")
	return
}

// DeleteModel (api/inference.ts inferenceMutations().deleteModel): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *InferenceMutationsResult) DeleteModel(ctx context.Context, tx core.IamStore, tenantID string, name string) (err error) {
	err = notImplemented("api/inference.ts inferenceMutations().deleteModel")
	return
}

// SaveBudget (api/inference.ts inferenceMutations().saveBudget): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *InferenceMutationsResult) SaveBudget(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, input *core.Object, previous *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/inference.ts inferenceMutations().saveBudget")
	return
}

// DeleteBudget (api/inference.ts inferenceMutations().deleteBudget): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *InferenceMutationsResult) DeleteBudget(ctx context.Context, tx core.IamStore, principal *Principal, budget *core.Object) (err error) {
	err = notImplemented("api/inference.ts inferenceMutations().deleteBudget")
	return
}

// InferenceMutations (api/inference.ts inferenceMutations): Model and budget changes without a credential, for the
// `inference` API (which authorizes first) and for configuration sync (sync.ts, ai-sync.ts). Every function runs
// inside the caller's transaction.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func InferenceMutations(server *ServerContext) (result *InferenceMutationsResult, err error) {
	err = notImplemented("api/inference.ts inferenceMutations")
	return
}
