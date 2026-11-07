package server

// Skeleton of packages/server/src/api/onboarding.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// OnboardingAPI is the `onboarding` API group (packages/server/src/api/onboarding.ts createOnboardingApi): every method runs through the
// operation envelope; the router maps POST {basePath}/onboarding/{method} onto it.
type OnboardingAPI struct {
	server *ServerContext
}

// CreateOnboardingAPI builds the `onboarding` API group.
func CreateOnboardingAPI(server *ServerContext) *OnboardingAPI {
	return &OnboardingAPI{server: server}
}

// CreateFlow is POST {basePath}/onboarding/createFlow. Creates a flow at this tenant's level.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) CreateFlow(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingCreateFlowInput]) (Out[apitypes.OnboardingCreateFlowOutput], error) {
	return Out[apitypes.OnboardingCreateFlowOutput]{}, notImplemented("onboarding.createFlow")
}

// DeleteFlow is POST {basePath}/onboarding/deleteFlow. Deletes a flow with every progress record of it, in every tenant it reached, and removes it from tenants' disabledFlowIds.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) DeleteFlow(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingDeleteFlowInput]) (Out[apitypes.OnboardingDeleteFlowOutput], error) {
	return Out[apitypes.OnboardingDeleteFlowOutput]{}, notImplemented("onboarding.deleteFlow")
}

// Effective is POST {basePath}/onboarding/effective. Everything onboarding looks like from this tenant, for administration pages.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) Effective(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingEffectiveInput]) (Out[apitypes.OnboardingEffectiveOutput], error) {
	return Out[apitypes.OnboardingEffectiveOutput]{}, notImplemented("onboarding.effective")
}

// GetFlow is POST {basePath}/onboarding/getFlow. Returns one flow this tenant defines.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) GetFlow(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingGetFlowInput]) (Out[apitypes.OnboardingGetFlowOutput], error) {
	return Out[apitypes.OnboardingGetFlowOutput]{}, notImplemented("onboarding.getFlow")
}

// ListFlows is POST {basePath}/onboarding/listFlows. Lists the flows this tenant defines, oldest first, optionally for one audience.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) ListFlows(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingListFlowsInput]) (Out[apitypes.OnboardingListFlowsOutput], error) {
	return Out[apitypes.OnboardingListFlowsOutput]{}, notImplemented("onboarding.listFlows")
}

// MemberProgress is POST {basePath}/onboarding/memberProgress. One person's member flows in this tenant, with the state of every step and their answers, and pending (required flows still open).
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) MemberProgress(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingMemberProgressInput]) (Out[apitypes.OnboardingMemberProgressOutput], error) {
	return Out[apitypes.OnboardingMemberProgressOutput]{}, notImplemented("onboarding.memberProgress")
}

// Mine is POST {basePath}/onboarding/mine. The caller's own onboarding: the welcome screen and their member flows, with step states and their own answers.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingMineInput]) (Out[apitypes.OnboardingMineOutput], error) {
	return Out[apitypes.OnboardingMineOutput]{}, notImplemented("onboarding.mine")
}

// Progress is POST {basePath}/onboarding/progress. Progress through one flow as this tenant sees it.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) Progress(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingProgressInput]) (Out[apitypes.OnboardingProgressOutput], error) {
	return Out[apitypes.OnboardingProgressOutput]{}, notImplemented("onboarding.progress")
}

// ResetProgress is POST {basePath}/onboarding/resetProgress. Clears progress through a flow, or one step of it (stepId), so people or tenants go through it again.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) ResetProgress(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingResetProgressInput]) (Out[apitypes.OnboardingResetProgressOutput], error) {
	return Out[apitypes.OnboardingResetProgressOutput]{}, notImplemented("onboarding.resetProgress")
}

// SetSettings is POST {basePath}/onboarding/setSettings. Replaces this tenant's onboarding settings: welcomeTitle, welcomeMessage, supportEmail, supportUrl (empty or null falls back to the level above), and disabledFlowIds, the inherited member flows switc…
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) SetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingSetSettingsInput]) (Out[apitypes.OnboardingSetSettingsOutput], error) {
	return Out[apitypes.OnboardingSetSettingsOutput]{}, notImplemented("onboarding.setSettings")
}

// Setup is POST {basePath}/onboarding/setup. This tenant's own setup checklists (the tenant flows defined above it), with the state of every step and the answers.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) Setup(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingSetupInput]) (Out[apitypes.OnboardingSetupOutput], error) {
	return Out[apitypes.OnboardingSetupOutput]{}, notImplemented("onboarding.setup")
}

// SubmitSetupStep is POST {basePath}/onboarding/submitSetupStep. Completes a form, acknowledge, or task step of this tenant's setup.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) SubmitSetupStep(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingSubmitSetupStepInput]) (Out[apitypes.OnboardingSubmitSetupStepOutput], error) {
	return Out[apitypes.OnboardingSubmitSetupStepOutput]{}, notImplemented("onboarding.submitSetupStep")
}

// SubmitStep is POST {basePath}/onboarding/submitStep. Completes one step of the caller's own member flow: answers for a form, acknowledged: true for an acknowledgement, nothing for a task (an admin-verified task is submitted for review).
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) SubmitStep(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingSubmitStepInput]) (Out[apitypes.OnboardingSubmitStepOutput], error) {
	return Out[apitypes.OnboardingSubmitStepOutput]{}, notImplemented("onboarding.submitStep")
}

// UpdateFlow is POST {basePath}/onboarding/updateFlow. Changes any field of a flow but its audience.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) UpdateFlow(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingUpdateFlowInput]) (Out[apitypes.OnboardingUpdateFlowOutput], error) {
	return Out[apitypes.OnboardingUpdateFlowOutput]{}, notImplemented("onboarding.updateFlow")
}

// VerifyStep is POST {basePath}/onboarding/verifyStep. Approves (the default) or sends back (approve: false, with an optional note) an administrator-verified task.
//
// STUB: returns NOT_IMPLEMENTED until api/onboarding.ts is ported.
func (api *OnboardingAPI) VerifyStep(ctx context.Context, credential core.CredentialInput, input In[apitypes.OnboardingVerifyStepInput]) (Out[apitypes.OnboardingVerifyStepOutput], error) {
	return Out[apitypes.OnboardingVerifyStepOutput]{}, notImplemented("onboarding.verifyStep")
}
