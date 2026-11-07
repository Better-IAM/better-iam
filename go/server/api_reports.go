package server

// Skeleton of packages/server/src/api/reports.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ReportsAPI is the `reports` API group (packages/server/src/api/reports.ts createReportsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/reports/{method} onto it.
type ReportsAPI struct {
	server *ServerContext
}

// CreateReportsAPI builds the `reports` API group.
func CreateReportsAPI(server *ServerContext) *ReportsAPI {
	return &ReportsAPI{server: server}
}

// Access is POST {basePath}/reports/access. Returns the tenant's access report: identities and grants ending soon, live elevations, pending requests, and unused or expiring API keys.
//
// STUB: returns NOT_IMPLEMENTED until api/reports.ts is ported.
func (api *ReportsAPI) Access(ctx context.Context, credential core.CredentialInput, input In[apitypes.ReportsAccessInput]) (Out[apitypes.ReportsAccessOutput], error) {
	return Out[apitypes.ReportsAccessOutput]{}, notImplemented("reports.access")
}

// BuildAccessReport (api/reports.ts buildAccessReport): Builds the access report of one tenant inside a transaction.
// The API decides per caller which sections to include; deployment operations (the digest) include every section.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BuildAccessReport(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, windows *core.Object, sections *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/reports.ts buildAccessReport")
	return
}

// ReportHasFindings (api/reports.ts reportHasFindings): Whether a report has anything worth telling someone about.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReportHasFindings(report *core.Object) (result bool, err error) {
	err = notImplemented("api/reports.ts reportHasFindings")
	return
}

// ReportWindows (api/reports.ts reportWindows): Validates the report windows: 0 to ten years, 30 days by default.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReportWindows(input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/reports.ts reportWindows")
	return
}
