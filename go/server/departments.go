package server

// Skeleton of packages/server/src/departments.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// DepartmentChain (departments.ts departmentChain): The department followed by the departments above it, nearest
// first; stops at a missing parent.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DepartmentChain(departments map[string]*core.Object, departmentID string) (result []*core.Object, err error) {
	err = notImplemented("departments.ts departmentChain")
	return
}

// DepartmentCode (departments.ts departmentCode): A department code: 1-32 letters, digits, `.`, `_` or `-`, starting
// with a letter or digit.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DepartmentCode(value any) (result string, err error) {
	err = notImplemented("departments.ts departmentCode")
	return
}

// DepartmentContext (departments.ts departmentContext): Policy context for a person in their own tenant:
// `principal.departmentId` (absent without a department) and `principal.departments`, the department with every
// department above it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DepartmentContext(ctx context.Context, tx core.IamStore, tenantID string, identityID string) (result *core.Object, err error) {
	err = notImplemented("departments.ts departmentContext")
	return
}

// DepartmentDescendants (departments.ts departmentDescendants): Every department below `departmentId`, not including
// the department itself.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DepartmentDescendants(departments []*core.Object, departmentID string) (result []*core.Object, err error) {
	err = notImplemented("departments.ts departmentDescendants")
	return
}

// DepartmentHeads (departments.ts departmentHeads): The heads of a department (identity IDs): its own head and, with
// `includeAncestors`, the heads of the departments above it, nearest first and without duplicates.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DepartmentHeads(ctx context.Context, tx core.IamStore, tenantID string, departmentID string, options *core.Object) (result []string, err error) {
	err = notImplemented("departments.ts departmentHeads")
	return
}

// DepartmentMembership (departments.ts departmentMembership): The person's department membership record, if any.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DepartmentMembership(ctx context.Context, tx core.IamStore, tenantID string, identityID string) (result *core.Object, err error) {
	err = notImplemented("departments.ts departmentMembership")
	return
}

// DepartmentOf (departments.ts departmentOf): The ID of the department a person belongs to, if any.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DepartmentOf(ctx context.Context, tx core.IamStore, tenantID string, identityID string) (result string, err error) {
	err = notImplemented("departments.ts departmentOf")
	return
}

// DepartmentPath (departments.ts departmentPath): Department IDs from the top of the tree down to `departmentId`
// itself (for roll-ups); empty when unknown.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DepartmentPath(ctx context.Context, tx core.IamStore, tenantID string, departmentID string) (result []string, err error) {
	err = notImplemented("departments.ts departmentPath")
	return
}

// LoadDepartment (departments.ts loadDepartment): Loads a department of the tenant or fails with NOT_FOUND.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LoadDepartment(ctx context.Context, tx core.IamStore, tenantID string, departmentID any) (result *core.Object, err error) {
	err = notImplemented("departments.ts loadDepartment")
	return
}

// ReleaseDepartments (departments.ts releaseDepartments): Offboarding and deletion: takes the person out of their
// department, and hands the departments they head to `successorId` (or leaves them without a head). Returns what
// changed.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReleaseDepartments(ctx context.Context, tx core.IamStore, tenantID string, identityID string, now int64, successorID string) (result *core.Object, err error) {
	err = notImplemented("departments.ts releaseDepartments")
	return
}

// TenantDepartments (departments.ts tenantDepartments): The tenant's departments by ID.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TenantDepartments(ctx context.Context, tx core.IamStore, tenantID string) (result map[string]*core.Object, err error) {
	err = notImplemented("departments.ts tenantDepartments")
	return
}

// DepartmentCollections is departments.ts departmentCollections.
var DepartmentCollections = struct {
	Departments string
	Members     string
}{"departments", "departmentMembers"}

// MaxDepartmentDepth is departments.ts maxDepartmentDepth.
const MaxDepartmentDepth = 20

// MaxDepartments is departments.ts maxDepartments.
const MaxDepartments = 2000
