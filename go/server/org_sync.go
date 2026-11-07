package server

// Skeleton of packages/server/src/org-sync.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// ApplyOrg (org-sync.ts applyOrg): Applies a planned `teams`/`departments` change set inside the configuration apply
// transaction, after roles exist and before any role is deleted. Every change is authorized like the equivalent API
// call (`allow`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ApplyOrg(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, plan *core.Object, env any, phase string) (err error) {
	err = notImplemented("org-sync.ts applyOrg")
	return
}

// ExportOrg (org-sync.ts exportOrg): The tenant's teams and departments in document form; each kind appears only
// when the tenant has some.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ExportOrg(state *core.Object, directory *core.Object) (result *core.Object, err error) {
	err = notImplemented("org-sync.ts exportOrg")
	return
}

// OrgRuleEnvironmentAfterResult is org-sync.ts orgRuleEnvironmentAfter().
type OrgRuleEnvironmentAfterResult struct {
	server *ServerContext
	Env    *core.Object
}

// Canonical (org-sync.ts orgRuleEnvironmentAfter().canonical): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *OrgRuleEnvironmentAfterResult) Canonical(rule any) (result any, err error) {
	err = notImplemented("org-sync.ts orgRuleEnvironmentAfter().canonical")
	return
}

// OrgRuleEnvironmentAfter (org-sync.ts orgRuleEnvironmentAfter): The teams and departments that exist after an
// apply, for validating package rules at plan time: team slugs, and department names ignoring case. `canonical`
// rewrites a rule's department names to their spelling in the document (or the tenant), so a case-only difference
// never shows as a change.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OrgRuleEnvironmentAfter(desired *core.Object, state *core.Object, prune bool) (result *OrgRuleEnvironmentAfterResult, err error) {
	err = notImplemented("org-sync.ts orgRuleEnvironmentAfter")
	return
}

// OrgRuleIDs (org-sync.ts orgRuleIds): Maps a document rule's team slugs and department names to the tenant's IDs
// (after teams and departments exist).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OrgRuleIDs(ctx context.Context, tx core.IamStore, tenantID string) (result func(any) any, err error) {
	err = notImplemented("org-sync.ts orgRuleIds")
	return
}

// OrgRuleNames (org-sync.ts orgRuleNames): Birthright rules (access package `autoAssign`) name teams by slug and
// departments by name in a configuration document; the tenant stores IDs. `orgRuleNames` maps a stored rule's IDs to
// names (export and plan comparisons).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OrgRuleNames(state *core.Object, rule any) (result any, err error) {
	err = notImplemented("org-sync.ts orgRuleNames")
	return
}

// ParseDepartmentsConfig (org-sync.ts parseDepartmentsConfig): Validates the `departments` list of a configuration
// document.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseDepartmentsConfig(items []*core.Object) (result []*core.Object, err error) {
	err = notImplemented("org-sync.ts parseDepartmentsConfig")
	return
}

// ParseTeamsConfig (org-sync.ts parseTeamsConfig): Validates the `teams` list of a configuration document.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseTeamsConfig(items []*core.Object) (result []*core.Object, err error) {
	err = notImplemented("org-sync.ts parseTeamsConfig")
	return
}

// PlanOrg (org-sync.ts planOrg): Plans the `teams` and `departments` kinds. References are checked against what will
// exist after the apply: people now (by email), roles (`roleNamesAfter`), parents and departments from the document
// or the tenant. Kinds absent from the document are left alone; with `prune`, listed kinds lose the items the
// document omits.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PlanOrg(desired *core.Object, state *core.Object, env *core.Object) (result *core.Object, err error) {
	err = notImplemented("org-sync.ts planOrg")
	return
}

// ReadOrgState (org-sync.ts readOrgState): Reads what the `teams` and `departments` kinds compare against.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReadOrgState(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("org-sync.ts readOrgState")
	return
}
