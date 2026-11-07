package server

// Skeleton of packages/server/src/api/departments.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// DepartmentsAPI is the `departments` API group (packages/server/src/api/departments.ts createDepartmentsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/departments/{method} onto it.
type DepartmentsAPI struct {
	server *ServerContext
}

// CreateDepartmentsAPI builds the `departments` API group.
func CreateDepartmentsAPI(server *ServerContext) *DepartmentsAPI {
	return &DepartmentsAPI{server: server}
}

// Assign is POST {basePath}/departments/assign. Places up to 100 people (identityIds, or one identityId) in a department, moving them out of any other, with an optional title. Returns how many changed.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) Assign(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsAssignInput]) (Out[apitypes.DepartmentsAssignOutput], error) {
	return Out[apitypes.DepartmentsAssignOutput]{}, notImplemented("departments.assign")
}

// Create is POST {basePath}/departments/create. Creates a department, optionally under parentId, with a code, a headId (an active person of the organization), a costCenter, and a description.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsCreateInput]) (Out[apitypes.DepartmentsCreateOutput], error) {
	return Out[apitypes.DepartmentsCreateOutput]{}, notImplemented("departments.create")
}

// Delete is POST {basePath}/departments/delete. Deletes a department. Its people become unassigned and its teams lose the link.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsDeleteInput]) (Out[apitypes.DepartmentsDeleteOutput], error) {
	return Out[apitypes.DepartmentsDeleteOutput]{}, notImplemented("departments.delete")
}

// Get is POST {basePath}/departments/get. One department with its path (the departments above it), sub-departments, head, and teams, and member counts with and without the departments below.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsGetInput]) (Out[apitypes.DepartmentsGetOutput], error) {
	return Out[apitypes.DepartmentsGetOutput]{}, notImplemented("departments.get")
}

// ImportFromAttribute is POST {basePath}/departments/importFromAttribute. Places every active person whose string identity attribute (such as department, filled by SCIM provisioning or an onboarding form) names a department, matched by name or code ignoring case.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) ImportFromAttribute(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsImportFromAttributeInput]) (Out[apitypes.DepartmentsImportFromAttributeOutput], error) {
	return Out[apitypes.DepartmentsImportFromAttributeOutput]{}, notImplemented("departments.importFromAttribute")
}

// List is POST {basePath}/departments/list. Every department with member counts (with and without sub-departments), child and team counts, in name order.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsListInput]) (Out[apitypes.DepartmentsListOutput], error) {
	return Out[apitypes.DepartmentsListOutput]{}, notImplemented("departments.list")
}

// ListMembers is POST {basePath}/departments/listMembers. The people of a department, heads first; includeSubdepartments adds those of every department below, each with their department.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) ListMembers(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsListMembersInput]) (Out[apitypes.DepartmentsListMembersOutput], error) {
	return Out[apitypes.DepartmentsListMembersOutput]{}, notImplemented("departments.listMembers")
}

// Mine is POST {basePath}/departments/mine. Your own place in the org chart and, if you head departments, the people you lead.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsMineInput]) (Out[apitypes.DepartmentsMineOutput], error) {
	return Out[apitypes.DepartmentsMineOutput]{}, notImplemented("departments.mine")
}

// OfIdentity is POST {basePath}/departments/ofIdentity. A person's department with the path from the top, their title, since when, the department's head and cost center; null when they have none.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) OfIdentity(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsOfIdentityInput]) (Out[apitypes.DepartmentsOfIdentityOutput], error) {
	return Out[apitypes.DepartmentsOfIdentityOutput]{}, notImplemented("departments.ofIdentity")
}

// SuggestBirthright is POST {basePath}/departments/suggestBirthright. Roles and groups that most of a department's people already hold by hand, proposed as a ready-made automatic access package whose rule names the department.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) SuggestBirthright(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsSuggestBirthrightInput]) (Out[apitypes.DepartmentsSuggestBirthrightOutput], error) {
	return Out[apitypes.DepartmentsSuggestBirthrightOutput]{}, notImplemented("departments.suggestBirthright")
}

// SyncManagers is POST {basePath}/departments/syncManagers. Makes department heads the managers of their departments' people (see above).
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) SyncManagers(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsSyncManagersInput]) (Out[apitypes.DepartmentsSyncManagersOutput], error) {
	return Out[apitypes.DepartmentsSyncManagersOutput]{}, notImplemented("departments.syncManagers")
}

// Tree is POST {basePath}/departments/tree. The org chart: top-level departments with their sub-departments, heads, and member counts.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) Tree(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsTreeInput]) (Out[apitypes.DepartmentsTreeOutput], error) {
	return Out[apitypes.DepartmentsTreeOutput]{}, notImplemented("departments.tree")
}

// Unassign is POST {basePath}/departments/unassign. Takes a person out of their department.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) Unassign(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsUnassignInput]) (Out[apitypes.DepartmentsUnassignOutput], error) {
	return Out[apitypes.DepartmentsUnassignOutput]{}, notImplemented("departments.unassign")
}

// Update is POST {basePath}/departments/update. Renames, re-codes, moves (parentId, null for top level), or changes the head, cost center, or description of a department; null (or an empty string) clears an optional field.
//
// STUB: returns NOT_IMPLEMENTED until api/departments.ts is ported.
func (api *DepartmentsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsUpdateInput]) (Out[apitypes.DepartmentsUpdateOutput], error) {
	return Out[apitypes.DepartmentsUpdateOutput]{}, notImplemented("departments.update")
}

// DepartmentMutationsResult is api/departments.ts departmentMutations().
type DepartmentMutationsResult struct {
	server *ServerContext
}

// CreateDepartment (api/departments.ts departmentMutations().createDepartment): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *DepartmentMutationsResult) CreateDepartment(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/departments.ts departmentMutations().createDepartment")
	return
}

// UpdateDepartment (api/departments.ts departmentMutations().updateDepartment): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *DepartmentMutationsResult) UpdateDepartment(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/departments.ts departmentMutations().updateDepartment")
	return
}

// DeleteDepartment (api/departments.ts departmentMutations().deleteDepartment): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *DepartmentMutationsResult) DeleteDepartment(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/departments.ts departmentMutations().deleteDepartment")
	return
}

// Place (api/departments.ts departmentMutations().place): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *DepartmentMutationsResult) Place(ctx context.Context, tx core.IamStore, principal *Principal, department *core.Object, identity *core.Object, title string) (result bool, err error) {
	err = notImplemented("api/departments.ts departmentMutations().place")
	return
}

// DepartmentPerson (api/departments.ts departmentMutations().departmentPerson): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *DepartmentMutationsResult) DepartmentPerson(ctx context.Context, tx core.IamStore, tenantID string, identityID any) (result *core.Object, err error) {
	err = notImplemented("api/departments.ts departmentMutations().departmentPerson")
	return
}

// DepartmentMutations (api/departments.ts departmentMutations): Transaction-level department changes for
// configuration sync (org-sync.ts): the same validation and audit events as the API. Callers authorize each change
// first.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DepartmentMutations(server *ServerContext) (result *DepartmentMutationsResult, err error) {
	err = notImplemented("api/departments.ts departmentMutations")
	return
}
