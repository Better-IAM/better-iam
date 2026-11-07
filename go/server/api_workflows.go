package server

// Skeleton of packages/server/src/api/workflows.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// WorkflowsAPI is the `workflows` API group (packages/server/src/api/workflows.ts createWorkflowsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/workflows/{method} onto it.
type WorkflowsAPI struct {
	server *ServerContext
}

// CreateWorkflowsAPI builds the `workflows` API group.
func CreateWorkflowsAPI(server *ServerContext) *WorkflowsAPI {
	return &WorkflowsAPI{server: server}
}

// CancelRun is POST {basePath}/workflows/cancelRun. Stops a pending, running, waiting or failed run; steps already done stay done.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) CancelRun(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsCancelRunInput]) (Out[apitypes.WorkflowsCancelRunOutput], error) {
	return Out[apitypes.WorkflowsCancelRunOutput]{}, notImplemented("workflows.cancelRun")
}

// Create is POST {basePath}/workflows/create. Creates a workflow owned by the caller, who must hold every permission its steps use.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsCreateInput]) (Out[apitypes.WorkflowsCreateOutput], error) {
	return Out[apitypes.WorkflowsCreateOutput]{}, notImplemented("workflows.create")
}

// Delete is POST {basePath}/workflows/delete. Deletes a workflow and cancels its pending, running and waiting runs; finished runs stay as history.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsDeleteInput]) (Out[apitypes.WorkflowsDeleteOutput], error) {
	return Out[apitypes.WorkflowsDeleteOutput]{}, notImplemented("workflows.delete")
}

// Evaluate is POST {basePath}/workflows/evaluate. Evaluates this organization's workflows and runs whatever is due now, instead of waiting for the scheduler.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) Evaluate(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsEvaluateInput]) (Out[apitypes.WorkflowsEvaluateOutput], error) {
	return Out[apitypes.WorkflowsEvaluateOutput]{}, notImplemented("workflows.evaluate")
}

// Get is POST {basePath}/workflows/get. Returns one workflow with run statistics and its 50 most recent runs.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsGetInput]) (Out[apitypes.WorkflowsGetOutput], error) {
	return Out[apitypes.WorkflowsGetOutput]{}, notImplemented("workflows.get")
}

// GetRun is POST {basePath}/workflows/getRun. Returns one run with its steps and results.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) GetRun(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsGetRunInput]) (Out[apitypes.WorkflowsGetRunOutput], error) {
	return Out[apitypes.WorkflowsGetRunOutput]{}, notImplemented("workflows.getRun")
}

// List is POST {basePath}/workflows/list. Lists the tenant's workflows by name, with run statistics.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsListInput]) (Out[apitypes.WorkflowsListOutput], error) {
	return Out[apitypes.WorkflowsListOutput]{}, notImplemented("workflows.list")
}

// ListRuns is POST {basePath}/workflows/listRuns. Lists runs, newest first, optionally of one workflow, one person or one status.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) ListRuns(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsListRunsInput]) (Out[apitypes.WorkflowsListRunsOutput], error) {
	return Out[apitypes.WorkflowsListRunsOutput]{}, notImplemented("workflows.listRuns")
}

// Preview is POST {basePath}/workflows/preview. Shows what a workflow would do right now, without changing anything.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) Preview(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsPreviewInput]) (Out[apitypes.WorkflowsPreviewOutput], error) {
	return Out[apitypes.WorkflowsPreviewOutput]{}, notImplemented("workflows.preview")
}

// RetryRun is POST {basePath}/workflows/retryRun. Resumes a failed run at the step that failed, with the caller's rights.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) RetryRun(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsRetryRunInput]) (Out[apitypes.WorkflowsRetryRunOutput], error) {
	return Out[apitypes.WorkflowsRetryRunOutput]{}, notImplemented("workflows.retryRun")
}

// Run is POST {basePath}/workflows/run. Runs a workflow now for up to 100 people you choose, whatever its trigger and scope.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) Run(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsRunInput]) (Out[apitypes.WorkflowsRunOutput], error) {
	return Out[apitypes.WorkflowsRunOutput]{}, notImplemented("workflows.run")
}

// Update is POST {basePath}/workflows/update. Edits a workflow; the caller becomes its owner and must hold the steps' permissions.
//
// STUB: returns NOT_IMPLEMENTED until api/workflows.ts is ported.
func (api *WorkflowsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.WorkflowsUpdateInput]) (Out[apitypes.WorkflowsUpdateOutput], error) {
	return Out[apitypes.WorkflowsUpdateOutput]{}, notImplemented("workflows.update")
}

// WorkflowsRuntime is api/workflows.ts createWorkflowsRuntime().
type WorkflowsRuntime struct {
	server *ServerContext
}

// RunDue (api/workflows.ts createWorkflowsRuntime().runDue): Evaluates every enabled workflow and runs the steps
// that are due (a scheduler job, every few minutes).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *WorkflowsRuntime) RunDue(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/workflows.ts createWorkflowsRuntime().runDue")
	return
}

// Subscribe (api/workflows.ts createWorkflowsRuntime().subscribe): Reacts to changes to each organization's people
// (see above); returns the unsubscribe function.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *WorkflowsRuntime) Subscribe() (result func(), err error) {
	err = notImplemented("api/workflows.ts createWorkflowsRuntime().subscribe")
	return
}

// Idle (api/workflows.ts createWorkflowsRuntime().idle): Resolves once every evaluation `subscribe()` scheduled has
// finished (for tests and graceful shutdown).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *WorkflowsRuntime) Idle(ctx context.Context) (err error) {
	err = notImplemented("api/workflows.ts createWorkflowsRuntime().idle")
	return
}

// CreateWorkflowsRuntime builds the WorkflowsRuntime (api/workflows.ts createWorkflowsRuntime). Its methods are stubs until the module is ported.
func CreateWorkflowsRuntime(server *ServerContext) *WorkflowsRuntime {
	return &WorkflowsRuntime{server: server}
}
