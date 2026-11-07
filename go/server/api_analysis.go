package server

// Skeleton of packages/server/src/api/analysis.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// AnalysisAPI is the `analysis` API group (packages/server/src/api/analysis.ts createAnalysisApi): every method runs through the
// operation envelope; the router maps POST {basePath}/analysis/{method} onto it.
type AnalysisAPI struct {
	server *ServerContext
}

// CreateAnalysisAPI builds the `analysis` API group.
func CreateAnalysisAPI(server *ServerContext) *AnalysisAPI {
	return &AnalysisAPI{server: server}
}

// Findings is POST {basePath}/analysis/findings. Runs every access-analysis check on the tenant and returns the findings, most severe first, with counts per severity.
//
// STUB: returns NOT_IMPLEMENTED until api/analysis.ts is ported.
func (api *AnalysisAPI) Findings(ctx context.Context, credential core.CredentialInput, input In[apitypes.AnalysisFindingsInput]) (Out[apitypes.AnalysisFindingsOutput], error) {
	return Out[apitypes.AnalysisFindingsOutput]{}, notImplemented("analysis.findings")
}

// LintPolicy is POST {basePath}/analysis/lintPolicy. Checks a policy document, or a stored policy, for errors and for statements that likely do not do what they say.
//
// STUB: returns NOT_IMPLEMENTED until api/analysis.ts is ported.
func (api *AnalysisAPI) LintPolicy(ctx context.Context, credential core.CredentialInput, input In[apitypes.AnalysisLintPolicyInput]) (Out[apitypes.AnalysisLintPolicyOutput], error) {
	return Out[apitypes.AnalysisLintPolicyOutput]{}, notImplemented("analysis.lintPolicy")
}

// Suppress is POST {basePath}/analysis/suppress. Hides one finding from future results and records why.
//
// STUB: returns NOT_IMPLEMENTED until api/analysis.ts is ported.
func (api *AnalysisAPI) Suppress(ctx context.Context, credential core.CredentialInput, input In[apitypes.AnalysisSuppressInput]) (Out[apitypes.AnalysisSuppressOutput], error) {
	return Out[apitypes.AnalysisSuppressOutput]{}, notImplemented("analysis.suppress")
}

// Unsuppress is POST {basePath}/analysis/unsuppress. Shows a suppressed finding again.
//
// STUB: returns NOT_IMPLEMENTED until api/analysis.ts is ported.
func (api *AnalysisAPI) Unsuppress(ctx context.Context, credential core.CredentialInput, input In[apitypes.AnalysisUnsuppressInput]) (Out[apitypes.AnalysisUnsuppressOutput], error) {
	return Out[apitypes.AnalysisUnsuppressOutput]{}, notImplemented("analysis.unsuppress")
}

// UnrestrictedAdmin (api/analysis.ts unrestrictedAdmin): An allow statement without conditions over every action (or
// every platform action) on every resource.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func UnrestrictedAdmin(document *core.Object) (result bool, err error) {
	err = notImplemented("api/analysis.ts unrestrictedAdmin")
	return
}
