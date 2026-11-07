package server

// Skeleton of packages/server/src/sync.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ConfigAPI is the `config` API group (packages/server/src/sync.ts createConfigApi): every method runs through the
// operation envelope; the router maps POST {basePath}/config/{method} onto it.
type ConfigAPI struct {
	server *ServerContext
}

// CreateConfigAPI builds the `config` API group.
func CreateConfigAPI(server *ServerContext) *ConfigAPI {
	return &ConfigAPI{server: server}
}

// Apply is POST {basePath}/config/apply. Applies a configuration document to the tenant in one transaction, and returns the changes it made.
//
// STUB: returns NOT_IMPLEMENTED until sync.ts is ported.
func (api *ConfigAPI) Apply(ctx context.Context, credential core.CredentialInput, input In[apitypes.ConfigApplyInput]) (Out[apitypes.ConfigApplyOutput], error) {
	return Out[apitypes.ConfigApplyOutput]{}, notImplemented("config.apply")
}

// Export is POST {basePath}/config/export. Returns the tenant's roles, policies, groups, bindings, and the other configuration kinds as a document that plan and apply accept.
//
// STUB: returns NOT_IMPLEMENTED until sync.ts is ported.
func (api *ConfigAPI) Export(ctx context.Context, credential core.CredentialInput, input In[apitypes.ConfigExportInput]) (Out[apitypes.ConfigExportOutput], error) {
	return Out[apitypes.ConfigExportOutput]{}, notImplemented("config.export")
}

// Plan is POST {basePath}/config/plan. Shows, without writing anything, every change apply would make for a configuration document.
//
// STUB: returns NOT_IMPLEMENTED until sync.ts is ported.
func (api *ConfigAPI) Plan(ctx context.Context, credential core.CredentialInput, input In[apitypes.ConfigPlanInput]) (Out[apitypes.ConfigPlanOutput], error) {
	return Out[apitypes.ConfigPlanOutput]{}, notImplemented("config.plan")
}
