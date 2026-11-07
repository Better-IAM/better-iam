package server

// Skeleton of packages/server/src/org-rules.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// TenantOrgFacts is org-rules.ts TenantOrgFacts.
type TenantOrgFacts struct {
	server        *ServerContext
	TeamIDs       []string
	DepartmentIDs []string
	// LicenseKeys The keys of the license products visible to the tenant: the valid identity.licenses values (licenses.ts).
	LicenseKeys []string
}

// Of (org-rules.ts TenantOrgFacts.of): What a rule sees for one person, given their live memberships no access
// package created.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TenantOrgFacts) Of(identityID string, directGroupIDs []string) (result *core.Object, err error) {
	err = notImplemented("org-rules.ts TenantOrgFacts.of")
	return
}

// LoadOrgFacts (org-rules.ts loadOrgFacts): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LoadOrgFacts(ctx context.Context, reader core.IamStore, tenantID string, now int64) (result *TenantOrgFacts, err error) {
	err = notImplemented("org-rules.ts loadOrgFacts")
	return
}

// OrgRuleEnvironment (org-rules.ts orgRuleEnvironment): The valid identity.teams and identity.departments values of
// a tenant: its team and department IDs; and the valid identity.licenses values, the keys of the license products it
// can use.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OrgRuleEnvironment(ctx context.Context, reader core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("org-rules.ts orgRuleEnvironment")
	return
}

// PackagesNaming (org-rules.ts packagesNaming): The names of the tenant's access packages whose rule names one of
// `ids` under `key` (a team's backing group under identity.groups counts for the team). Teams and departments stay
// while a rule names them, like groups.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PackagesNaming(ctx context.Context, reader core.IamStore, tenantID string, key string, ids []string, backingGroupIDs []string) (result []string, err error) {
	err = notImplemented("org-rules.ts packagesNaming")
	return
}
