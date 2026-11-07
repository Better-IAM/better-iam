package server

// Skeleton of packages/server/src/api/clearances.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ClearancesAPI is the `clearances` API group (packages/server/src/api/clearances.ts createClearancesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/clearances/{method} onto it.
type ClearancesAPI struct {
	server *ServerContext
}

// CreateClearancesAPI builds the `clearances` API group.
func CreateClearancesAPI(server *ServerContext) *ClearancesAPI {
	return &ClearancesAPI{server: server}
}

// Debrief is POST {basePath}/clearances/debrief. Ends one read-in.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Debrief(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesDebriefInput]) (Out[apitypes.ClearancesDebriefOutput], error) {
	return Out[apitypes.ClearancesDebriefOutput]{}, notImplemented("clearances.debrief")
}

// Declassify is POST {basePath}/clearances/declassify. Lowers, changes, or removes a resource's label, with a reason.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Declassify(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesDeclassifyInput]) (Out[apitypes.ClearancesDeclassifyOutput], error) {
	return Out[apitypes.ClearancesDeclassifyOutput]{}, notImplemented("clearances.declassify")
}

// DefineScheme is POST {basePath}/clearances/defineScheme. Defines the tenant's classification scheme from a template or a definition of your own.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) DefineScheme(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesDefineSchemeInput]) (Out[apitypes.ClearancesDefineSchemeOutput], error) {
	return Out[apitypes.ClearancesDefineSchemeOutput]{}, notImplemented("clearances.defineScheme")
}

// Explain is POST {basePath}/clearances/explain. Tells an officer whether a person may read a resource and, if not, which dimension of the label they fail.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Explain(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesExplainInput]) (Out[apitypes.ClearancesExplainOutput], error) {
	return Out[apitypes.ClearancesExplainOutput]{}, notImplemented("clearances.explain")
}

// Get is POST {basePath}/clearances/get. Returns one identity's clearance as officers see it, or null.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesGetInput]) (Out[apitypes.ClearancesGetOutput], error) {
	return Out[apitypes.ClearancesGetOutput]{}, notImplemented("clearances.get")
}

// GetLabel is POST {basePath}/clearances/getLabel. Returns a resource's own IAM label and what it inherits from its managed parents.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) GetLabel(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesGetLabelInput]) (Out[apitypes.ClearancesGetLabelOutput], error) {
	return Out[apitypes.ClearancesGetLabelOutput]{}, notImplemented("clearances.getLabel")
}

// GetScheme is POST {basePath}/clearances/getScheme. Returns the classification scheme in force for a tenant and where it is defined, or null.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) GetScheme(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesGetSchemeInput]) (Out[apitypes.ClearancesGetSchemeOutput], error) {
	return Out[apitypes.ClearancesGetSchemeOutput]{}, notImplemented("clearances.getScheme")
}

// Grant is POST {basePath}/clearances/grant. Grants an identity a clearance under the scheme in force: a level, adjudicated citizenship, and optional dates.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Grant(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesGrantInput]) (Out[apitypes.ClearancesGrantOutput], error) {
	return Out[apitypes.ClearancesGrantOutput]{}, notImplemented("clearances.grant")
}

// Label is POST {basePath}/clearances/label. Labels a resource or raises its label; lowering any part of a label is a declassification.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Label(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesLabelInput]) (Out[apitypes.ClearancesLabelOutput], error) {
	return Out[apitypes.ClearancesLabelOutput]{}, notImplemented("clearances.label")
}

// List is POST {basePath}/clearances/list. Lists the tenant's clearances by person name, optionally by status, level, or end.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesListInput]) (Out[apitypes.ClearancesListOutput], error) {
	return Out[apitypes.ClearancesListOutput]{}, notImplemented("clearances.list")
}

// ListLabels is POST {basePath}/clearances/listLabels. Lists the tenant's IAM labels, optionally of one resource type or level.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) ListLabels(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesListLabelsInput]) (Out[apitypes.ClearancesListLabelsOutput], error) {
	return Out[apitypes.ClearancesListLabelsOutput]{}, notImplemented("clearances.listLabels")
}

// Mine is POST {basePath}/clearances/mine. Returns the caller's own clearance under the scheme in force, with the scheme's levels.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesMineInput]) (Out[apitypes.ClearancesMineOutput], error) {
	return Out[apitypes.ClearancesMineOutput]{}, notImplemented("clearances.mine")
}

// ReadIn is POST {basePath}/clearances/readIn. Reads a person into a compartment of the scheme, optionally backed by a non-disclosure agreement.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) ReadIn(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesReadInInput]) (Out[apitypes.ClearancesReadInOutput], error) {
	return Out[apitypes.ClearancesReadInOutput]{}, notImplemented("clearances.readIn")
}

// Reinstate is POST {basePath}/clearances/reinstate. Lifts a suspension, back to the active or interim status the clearance had.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Reinstate(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesReinstateInput]) (Out[apitypes.ClearancesReinstateOutput], error) {
	return Out[apitypes.ClearancesReinstateOutput]{}, notImplemented("clearances.reinstate")
}

// Revoke is POST {basePath}/clearances/revoke. Revokes a clearance for cause and debriefs every compartment.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesRevokeInput]) (Out[apitypes.ClearancesRevokeOutput], error) {
	return Out[apitypes.ClearancesRevokeOutput]{}, notImplemented("clearances.revoke")
}

// Suspend is POST {basePath}/clearances/suspend. Takes a clearance out of force at once, for an incident or an investigation.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Suspend(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesSuspendInput]) (Out[apitypes.ClearancesSuspendOutput], error) {
	return Out[apitypes.ClearancesSuspendOutput]{}, notImplemented("clearances.suspend")
}

// Templates is POST {basePath}/clearances/templates. Lists the built-in schemes a tenant can start from: us, uk, nato, and corporate.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Templates(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesTemplatesInput]) (Out[apitypes.ClearancesTemplatesOutput], error) {
	return Out[apitypes.ClearancesTemplatesOutput]{}, notImplemented("clearances.templates")
}

// Update is POST {basePath}/clearances/update. Changes a live clearance's level, citizenship, interim status, investigation, or dates.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesUpdateInput]) (Out[apitypes.ClearancesUpdateOutput], error) {
	return Out[apitypes.ClearancesUpdateOutput]{}, notImplemented("clearances.update")
}

// UpdateScheme is POST {basePath}/clearances/updateScheme. Changes the scheme the tenant defines: its settings, or its definition within rules that keep what is in use.
//
// STUB: returns NOT_IMPLEMENTED until api/clearances.ts is ported.
func (api *ClearancesAPI) UpdateScheme(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesUpdateSchemeInput]) (Out[apitypes.ClearancesUpdateSchemeOutput], error) {
	return Out[apitypes.ClearancesUpdateSchemeOutput]{}, notImplemented("clearances.updateScheme")
}

// IamClearances is api/clearances.ts IamClearances.
type IamClearances struct {
	server *ServerContext
}

// SendReminders (api/clearances.ts IamClearances.sendReminders): Emails the owners of each scheme's defining tenant
// and the scheme's `notify.emails` (template `clearance-reminder`, naming the level only, never compartments) about
// clearances whose periodic reinvestigation is due or whose end (interim or final) falls within `withinDays`
// (default 60): each date once. `tenantId` limits the run to the clearances held in that tenant. Requires an email
// delivery callback and the `clearances` option.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamClearances) SendReminders(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/clearances.ts IamClearances.sendReminders")
	return
}

// CreateClearancesRuntime builds the IamClearances (api/clearances.ts createClearancesRuntime). Its methods are stubs until the module is ported.
func CreateClearancesRuntime(server *ServerContext) *IamClearances {
	return &IamClearances{server: server}
}
