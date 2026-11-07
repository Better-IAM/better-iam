package server

// Skeleton of packages/server/src/api/compliance.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ComplianceAPI is the `compliance` API group (packages/server/src/api/compliance.ts createComplianceApi): every method runs through the
// operation envelope; the router maps POST {basePath}/compliance/{method} onto it.
type ComplianceAPI struct {
	server *ServerContext
}

// CreateComplianceAPI builds the `compliance` API group.
func CreateComplianceAPI(server *ServerContext) *ComplianceAPI {
	return &ComplianceAPI{server: server}
}

// AdoptFramework is POST {basePath}/compliance/adoptFramework. Adopts a framework: one control per check its requirements use, mapped to those requirements.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) AdoptFramework(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceAdoptFrameworkInput]) (Out[apitypes.ComplianceAdoptFrameworkOutput], error) {
	return Out[apitypes.ComplianceAdoptFrameworkOutput]{}, notImplemented("compliance.adoptFramework")
}

// ApproveException is POST {basePath}/compliance/approveException. Approves a pending exception, so it covers its finding from the next evaluation until it expires.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) ApproveException(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceApproveExceptionInput]) (Out[apitypes.ComplianceApproveExceptionOutput], error) {
	return Out[apitypes.ComplianceApproveExceptionOutput]{}, notImplemented("compliance.approveException")
}

// Catalog is POST {basePath}/compliance/catalog. Returns the built-in checks with their parameters, and the framework mappings.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) Catalog(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceCatalogInput]) (Out[apitypes.ComplianceCatalogOutput], error) {
	return Out[apitypes.ComplianceCatalogOutput]{}, notImplemented("compliance.catalog")
}

// CreateControl is POST {basePath}/compliance/createControl. Adds a control that runs one check with parameters and mappings of your own.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) CreateControl(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceCreateControlInput]) (Out[apitypes.ComplianceCreateControlOutput], error) {
	return Out[apitypes.ComplianceCreateControlOutput]{}, notImplemented("compliance.createControl")
}

// CreateException is POST {basePath}/compliance/createException. Proposes accepting one finding of a control until a date; once a second person approves it, the finding no longer counts toward the control's status.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) CreateException(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceCreateExceptionInput]) (Out[apitypes.ComplianceCreateExceptionOutput], error) {
	return Out[apitypes.ComplianceCreateExceptionOutput]{}, notImplemented("compliance.createException")
}

// DeleteControl is POST {basePath}/compliance/deleteControl. Deletes a control and revokes its exceptions.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) DeleteControl(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceDeleteControlInput]) (Out[apitypes.ComplianceDeleteControlOutput], error) {
	return Out[apitypes.ComplianceDeleteControlOutput]{}, notImplemented("compliance.deleteControl")
}

// Evaluate is POST {basePath}/compliance/evaluate. Runs the tenant's enabled controls now, or the ones named in controlKeys.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) Evaluate(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceEvaluateInput]) (Out[apitypes.ComplianceEvaluateOutput], error) {
	return Out[apitypes.ComplianceEvaluateOutput]{}, notImplemented("compliance.evaluate")
}

// EvidenceKeys is POST {basePath}/compliance/evidenceKeys. Returns the public keys evidence packs are signed with, as a JWKS, for auditors' offline checks.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) EvidenceKeys(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceEvidenceKeysInput]) (Out[apitypes.ComplianceEvidenceKeysOutput], error) {
	return Out[apitypes.ComplianceEvidenceKeysOutput]{}, notImplemented("compliance.evidenceKeys")
}

// ExportEvidence is POST {basePath}/compliance/exportEvidence. Returns a signed evidence pack for auditors: the controls, their latest results, exceptions and recent runs.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) ExportEvidence(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceExportEvidenceInput]) (Out[apitypes.ComplianceExportEvidenceOutput], error) {
	return Out[apitypes.ComplianceExportEvidenceOutput]{}, notImplemented("compliance.exportEvidence")
}

// ListControls is POST {basePath}/compliance/listControls. Lists the tenant's controls by name, each with its latest result.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) ListControls(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceListControlsInput]) (Out[apitypes.ComplianceListControlsOutput], error) {
	return Out[apitypes.ComplianceListControlsOutput]{}, notImplemented("compliance.listControls")
}

// ListExceptions is POST {basePath}/compliance/listExceptions. Lists the tenant's exceptions by expiry, pending, revoked and expired ones included.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) ListExceptions(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceListExceptionsInput]) (Out[apitypes.ComplianceListExceptionsOutput], error) {
	return Out[apitypes.ComplianceListExceptionsOutput]{}, notImplemented("compliance.listExceptions")
}

// ListResults is POST {basePath}/compliance/listResults. Returns results: the latest of every control, or a control's history, or one run's results.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) ListResults(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceListResultsInput]) (Out[apitypes.ComplianceListResultsOutput], error) {
	return Out[apitypes.ComplianceListResultsOutput]{}, notImplemented("compliance.listResults")
}

// ListRuns is POST {basePath}/compliance/listRuns. Lists evaluation runs, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) ListRuns(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceListRunsInput]) (Out[apitypes.ComplianceListRunsOutput], error) {
	return Out[apitypes.ComplianceListRunsOutput]{}, notImplemented("compliance.listRuns")
}

// RevokeException is POST {basePath}/compliance/revokeException. Ends an exception, or withdraws a pending one, so its finding counts again from the next evaluation.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) RevokeException(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceRevokeExceptionInput]) (Out[apitypes.ComplianceRevokeExceptionOutput], error) {
	return Out[apitypes.ComplianceRevokeExceptionOutput]{}, notImplemented("compliance.revokeException")
}

// Status is POST {basePath}/compliance/status. Returns each framework requirement with the controls that evidence it and their latest status.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) Status(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceStatusInput]) (Out[apitypes.ComplianceStatusOutput], error) {
	return Out[apitypes.ComplianceStatusOutput]{}, notImplemented("compliance.status")
}

// UpdateControl is POST {basePath}/compliance/updateControl. Changes a control's name, description, parameters, mappings, or whether it is evaluated.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) UpdateControl(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceUpdateControlInput]) (Out[apitypes.ComplianceUpdateControlOutput], error) {
	return Out[apitypes.ComplianceUpdateControlOutput]{}, notImplemented("compliance.updateControl")
}

// VerifyEvidence is POST {basePath}/compliance/verifyEvidence. Tells whether an evidence pack is unaltered and was signed by this deployment.
//
// STUB: returns NOT_IMPLEMENTED until api/compliance.ts is ported.
func (api *ComplianceAPI) VerifyEvidence(ctx context.Context, credential core.CredentialInput, input In[apitypes.ComplianceVerifyEvidenceInput]) (Out[apitypes.ComplianceVerifyEvidenceOutput], error) {
	return Out[apitypes.ComplianceVerifyEvidenceOutput]{}, notImplemented("compliance.verifyEvidence")
}

// ComplianceRuntime is api/compliance.ts createComplianceRuntime().
type ComplianceRuntime struct {
	server *ServerContext
}

// EvaluateAll (api/compliance.ts createComplianceRuntime().evaluateAll): Evaluates every active tenant (or one) that
// has enabled controls, one after another. A tenant's failure is reported in `failed` and never stops the others.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *ComplianceRuntime) EvaluateAll(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/compliance.ts createComplianceRuntime().evaluateAll")
	return
}

// CreateComplianceRuntime builds the ComplianceRuntime (api/compliance.ts createComplianceRuntime). Its methods are stubs until the module is ported.
func CreateComplianceRuntime(server *ServerContext) *ComplianceRuntime {
	return &ComplianceRuntime{server: server}
}
