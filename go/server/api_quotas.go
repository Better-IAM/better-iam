package server

// Skeleton of packages/server/src/api/quotas.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// QuotasAPI is the `quotas` API group (packages/server/src/api/quotas.ts createQuotasApi): every method runs through the
// operation envelope; the router maps POST {basePath}/quotas/{method} onto it.
type QuotasAPI struct {
	server *ServerContext
}

// CreateQuotasAPI builds the `quotas` API group.
func CreateQuotasAPI(server *ServerContext) *QuotasAPI {
	return &QuotasAPI{server: server}
}

// Assign is POST {basePath}/quotas/assign. Assigns a plan to an API key (subjectType: 'apiKey' with the key's credentialId), an identity, or a group, replacing the subject's plan for the same meter.
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) Assign(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasAssignInput]) (Out[apitypes.QuotasAssignOutput], error) {
	return Out[apitypes.QuotasAssignOutput]{}, notImplemented("quotas.assign")
}

// Consume is POST {basePath}/quotas/consume. Counts cost (default 1) units of a meter for the caller's own session, or refuses without counting anything when the throttle or a period limit would be exceeded: allowed: false with reason (throttle…
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) Consume(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasConsumeInput]) (Out[apitypes.QuotasConsumeOutput], error) {
	return Out[apitypes.QuotasConsumeOutput]{}, notImplemented("quotas.consume")
}

// CreatePlan is POST {basePath}/quotas/createPlan. Defines a plan for a meter with a throttle, limits, or both.
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) CreatePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasCreatePlanInput]) (Out[apitypes.QuotasCreatePlanOutput], error) {
	return Out[apitypes.QuotasCreatePlanOutput]{}, notImplemented("quotas.createPlan")
}

// DeletePlan is POST {basePath}/quotas/deletePlan. Deletes a plan with its assignments and counters.
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) DeletePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasDeletePlanInput]) (Out[apitypes.QuotasDeletePlanOutput], error) {
	return Out[apitypes.QuotasDeletePlanOutput]{}, notImplemented("quotas.deletePlan")
}

// GetPlan is POST {basePath}/quotas/getPlan. One plan.
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) GetPlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasGetPlanInput]) (Out[apitypes.QuotasGetPlanOutput], error) {
	return Out[apitypes.QuotasGetPlanOutput]{}, notImplemented("quotas.getPlan")
}

// ListAssignments is POST {basePath}/quotas/listAssignments. Assignments, optionally of one plan, with each subject's name (an API key's label).
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) ListAssignments(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasListAssignmentsInput]) (Out[apitypes.QuotasListAssignmentsOutput], error) {
	return Out[apitypes.QuotasListAssignmentsOutput]{}, notImplemented("quotas.listAssignments")
}

// ListPlans is POST {basePath}/quotas/listPlans. Every plan of the tenant, by name, with how many subjects are assigned to each.
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) ListPlans(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasListPlansInput]) (Out[apitypes.QuotasListPlansOutput], error) {
	return Out[apitypes.QuotasListPlansOutput]{}, notImplemented("quotas.listPlans")
}

// Reset is POST {basePath}/quotas/reset. Starts one subject's counters and throttle over (as usage names it), or every subject's when none is given.
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) Reset(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasResetInput]) (Out[apitypes.QuotasResetOutput], error) {
	return Out[apitypes.QuotasResetOutput]{}, notImplemented("quotas.reset")
}

// Status is POST {basePath}/quotas/status. The caller's own plan for a meter and what is left in each window, without counting.
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) Status(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasStatusInput]) (Out[apitypes.QuotasStatusOutput], error) {
	return Out[apitypes.QuotasStatusOutput]{}, notImplemented("quotas.status")
}

// Unassign is POST {basePath}/quotas/unassign. Removes a subject's plan for a meter; removed says whether there was one.
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) Unassign(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasUnassignInput]) (Out[apitypes.QuotasUnassignOutput], error) {
	return Out[apitypes.QuotasUnassignOutput]{}, notImplemented("quotas.unassign")
}

// UpdatePlan is POST {basePath}/quotas/updatePlan. Changes a plan; fields left out keep their value, throttle: null and description: null clear them, and limits replaces the list. The meter cannot change.
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) UpdatePlan(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasUpdatePlanInput]) (Out[apitypes.QuotasUpdatePlanOutput], error) {
	return Out[apitypes.QuotasUpdatePlanOutput]{}, notImplemented("quotas.updatePlan")
}

// Usage is POST {basePath}/quotas/usage. Every subject's use of a plan in the current windows, the most used first. Subjects are named identity:{id}, key:{credentialId}, or tenant for a tenant-scoped plan.
//
// STUB: returns NOT_IMPLEMENTED until api/quotas.ts is ported.
func (api *QuotasAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.QuotasUsageInput]) (Out[apitypes.QuotasUsageOutput], error) {
	return Out[apitypes.QuotasUsageOutput]{}, notImplemented("quotas.usage")
}

// IamQuotas is api/quotas.ts IamQuotas.
type IamQuotas struct {
	server *ServerContext
}

// Consume (api/quotas.ts IamQuotas.consume): Counts use for the request's credential (as `quotas.consume`) and
// returns the decision.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamQuotas) Consume(ctx context.Context, request *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/quotas.ts IamQuotas.consume")
	return
}

// Enforce (api/quotas.ts IamQuotas.enforce): As `consume`, but throws QUOTA_EXCEEDED (429, with `retryAfterMs` for
// the Retry-After header) when refused.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamQuotas) Enforce(ctx context.Context, request *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/quotas.ts IamQuotas.enforce")
	return
}

// Status (api/quotas.ts IamQuotas.status): The request credential's quota for a meter without counting.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamQuotas) Status(ctx context.Context, request *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/quotas.ts IamQuotas.status")
	return
}

// ConsumeFor (api/quotas.ts IamQuotas.consumeFor): Counts use for a subject your code identified itself (a
// background job, a webhook sender): an identity of the tenant, optionally through one of its API keys. No
// credential; events are recorded as `deployment-operator`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamQuotas) ConsumeFor(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/quotas.ts IamQuotas.consumeFor")
	return
}

// CreateQuotasRuntime builds the IamQuotas (api/quotas.ts createQuotasRuntime). Its methods are stubs until the module is ported.
func CreateQuotasRuntime(server *ServerContext) *IamQuotas {
	return &IamQuotas{server: server}
}
