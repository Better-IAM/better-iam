package server

// Skeleton of packages/server/src/ai-sync.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// ApplyAi (ai-sync.ts applyAi): Applies a planned AI change set inside the configuration apply transaction. `upsert`
// creates and updates (agents first, so budgets can name them), `delete` removes (budgets first, then models and
// agents); both by default. Every change is authorized like the equivalent API call (`allow`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ApplyAi(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, plan *core.Object, env any, phase string) (err error) {
	err = notImplemented("ai-sync.ts applyAi")
	return
}

// ExportAi (ai-sync.ts exportAi): The AI part of an export, each kind only when the tenant has some (so other
// exports stay unchanged).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ExportAi(state *core.Object, names *core.Object) (result *core.Object, err error) {
	err = notImplemented("ai-sync.ts exportAi")
	return
}

// ParseAgentsConfig (ai-sync.ts parseAgentsConfig): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseAgentsConfig(items []*core.Object) (result []*core.Object, err error) {
	err = notImplemented("ai-sync.ts parseAgentsConfig")
	return
}

// ParseBudgetsConfig (ai-sync.ts parseBudgetsConfig): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseBudgetsConfig(items []*core.Object) (result []*core.Object, err error) {
	err = notImplemented("ai-sync.ts parseBudgetsConfig")
	return
}

// ParseModelsConfig (ai-sync.ts parseModelsConfig): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseModelsConfig(items []*core.Object) (result []*core.Object, err error) {
	err = notImplemented("ai-sync.ts parseModelsConfig")
	return
}

// PlanAi (ai-sync.ts planAi): Plans the AI kinds a document names (a kind the document leaves out is left alone).
// Sponsors must be people of the tenant now; budget groups must exist after the apply (`groupNamesAfter`); a
// budget's agent must be an agent now or one this document creates; a model's provider must be visible to the
// tenant.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PlanAi(desired *core.Object, state *core.Object, env *core.Object) (result *core.Object, err error) {
	err = notImplemented("ai-sync.ts planAi")
	return
}

// ReadAiState (ai-sync.ts readAiState): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReadAiState(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("ai-sync.ts readAiState")
	return
}
