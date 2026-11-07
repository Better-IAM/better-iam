package server

// Port of packages/server/src/departments.ts: the organization's reporting structure. Departments nest (`parentId`),
// may name a head, and hold people; each person belongs to at most one department (`departmentMembers`, uniqueKey
// `identity:{identityId}`). Policies see `principal.departmentId` and `principal.departments` (the department and
// every department above it), teams may name the department they belong to, and roll-ups (spend, reports) walk
// `departmentPath`.

import (
	"context"
	"regexp"
	"slices"

	"github.com/Better-IAM/better-iam/go/core"
)

var departmentCodePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// DepartmentCode (departments.ts departmentCode): A department code: 1-32 letters, digits, `.`, `_` or `-`, starting
// with a letter or digit.
func DepartmentCode(value any) (string, error) {
	text, ok := value.(string)
	if !ok || !departmentCodePattern.MatchString(text) {
		return "", invalidInput("code must use 1-32 letters, digits, dots, underscores, or hyphens")
	}
	return text, nil
}

// LoadDepartment (departments.ts loadDepartment): Loads a department of the tenant or fails with NOT_FOUND.
func LoadDepartment(ctx context.Context, tx core.IamStore, tenantID string, departmentID any) (*core.Object, error) {
	id, ok := departmentID.(string)
	if !ok || id == "" {
		return nil, invalidInput("Invalid departmentId")
	}
	department, err := tx.Get(ctx, DepartmentCollections.Departments, id)
	if err != nil {
		return nil, err
	}
	if department == nil || !orgOwned(department, tenantID) {
		return nil, core.NewIamError("NOT_FOUND", "Department not found", 404)
	}
	return department, nil
}

// DepartmentChain (departments.ts departmentChain): The department followed by the departments above it, nearest
// first; stops at a missing parent.
func DepartmentChain(departments map[string]*core.Object, departmentID string) ([]*core.Object, error) {
	return departmentChain(departments, departmentID), nil
}

func departmentChain(departments map[string]*core.Object, departmentID string) []*core.Object {
	return orgChain(departments, departmentID, MaxDepartmentDepth)
}

// DepartmentDescendants (departments.ts departmentDescendants): Every department below `departmentId`, not including
// the department itself.
func DepartmentDescendants(departments []*core.Object, departmentID string) ([]*core.Object, error) {
	return orgDescendants(departments, departmentID), nil
}

// TenantDepartments (departments.ts tenantDepartments): The tenant's departments by ID.
func TenantDepartments(ctx context.Context, tx core.IamStore, tenantID string) (map[string]*core.Object, error) {
	records, err := tx.Find(ctx, DepartmentCollections.Departments, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	byID, _ := orgByID(records)
	return byID, nil
}

// DepartmentMembership (departments.ts departmentMembership): The person's department membership record, if any
// (nil when none).
func DepartmentMembership(ctx context.Context, tx core.IamStore, tenantID string, identityID string) (*core.Object, error) {
	records, err := tx.Find(ctx, DepartmentCollections.Members, core.NewObject("tenantId", tenantID, "uniqueKey", "identity:"+identityID), nil)
	if err != nil || len(records) == 0 {
		return nil, err
	}
	return records[0], nil
}

// DepartmentOf (departments.ts departmentOf): The ID of the department a person belongs to, if any ("" when none).
func DepartmentOf(ctx context.Context, tx core.IamStore, tenantID string, identityID string) (string, error) {
	membership, err := DepartmentMembership(ctx, tx, tenantID, identityID)
	if err != nil || membership == nil {
		return "", err
	}
	department, err := tx.Get(ctx, DepartmentCollections.Departments, orgString(membership, "departmentId"))
	if err != nil {
		return "", err
	}
	if department != nil && orgOwned(department, tenantID) {
		return orgString(department, "id"), nil
	}
	return "", nil
}

// DepartmentPath (departments.ts departmentPath): Department IDs from the top of the tree down to `departmentId`
// itself (for roll-ups); empty when unknown.
func DepartmentPath(ctx context.Context, tx core.IamStore, tenantID string, departmentID string) ([]string, error) {
	departments, err := TenantDepartments(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	chain := departmentChain(departments, departmentID)
	path := make([]string, 0, len(chain))
	for index := len(chain) - 1; index >= 0; index-- {
		path = append(path, orgString(chain[index], "id"))
	}
	return path, nil
}

// DepartmentHeads (departments.ts departmentHeads): The heads of a department (identity IDs): its own head and, with
// `includeAncestors`, the heads of the departments above it, nearest first and without duplicates. Options:
// `{ includeAncestors? }`.
func DepartmentHeads(ctx context.Context, tx core.IamStore, tenantID string, departmentID string, options *core.Object) ([]string, error) {
	departments, err := TenantDepartments(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	chain := departmentChain(departments, departmentID)
	if (options == nil || !truthy(options.Get("includeAncestors"))) && len(chain) > 1 {
		chain = chain[:1]
	}
	heads := []string{}
	for _, department := range chain {
		if headID := orgString(department, "headId"); headID != "" && !slices.Contains(heads, headID) {
			heads = append(heads, headID)
		}
	}
	return heads, nil
}

// RemoveFromDepartment (departments.ts removeFromDepartment): Removes a person from their department; true when they
// had one.
func RemoveFromDepartment(ctx context.Context, tx core.IamStore, tenantID string, identityID string) (bool, error) {
	membership, err := DepartmentMembership(ctx, tx, tenantID, identityID)
	if err != nil {
		return false, err
	}
	if membership != nil {
		if err := tx.Delete(ctx, DepartmentCollections.Members, orgString(membership, "id")); err != nil {
			return false, err
		}
	}
	return membership != nil, nil
}

// ReleaseDepartments (departments.ts releaseDepartments): Offboarding and deletion: takes the person out of their
// department, and hands the departments they head to `successorId` (or leaves them without a head). Returns what
// changed: `{ left, headsReassigned, headsCleared }`.
func ReleaseDepartments(ctx context.Context, tx core.IamStore, tenantID string, identityID string, now int64, successorID string) (*core.Object, error) {
	left, err := RemoveFromDepartment(ctx, tx, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	headsReassigned, headsCleared := 0, 0
	departments, err := tx.Find(ctx, DepartmentCollections.Departments, core.NewObject("tenantId", tenantID, "headId", identityID), nil)
	if err != nil {
		return nil, err
	}
	for _, department := range departments {
		rest := department.Clone()
		rest.Delete("headId")
		if successorID != "" {
			rest.Set("headId", successorID)
		}
		rest.Set("updatedAt", now)
		if _, err := tx.Put(ctx, DepartmentCollections.Departments, rest); err != nil {
			return nil, err
		}
		if successorID != "" {
			headsReassigned++
		} else {
			headsCleared++
		}
	}
	return core.NewObject("left", left, "headsReassigned", headsReassigned, "headsCleared", headsCleared), nil
}

// DepartmentContext (departments.ts departmentContext): Policy context for a person in their own tenant:
// `principal.departmentId` (absent without a department) and `principal.departments`, the department with every
// department above it.
func DepartmentContext(ctx context.Context, tx core.IamStore, tenantID string, identityID string) (*core.Object, error) {
	departmentID, err := DepartmentOf(ctx, tx, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	if departmentID == "" {
		return core.NewObject("principal.departments", []any{}), nil
	}
	path, err := DepartmentPath(ctx, tx, tenantID, departmentID)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(path, compareUTF16)
	return core.NewObject("principal.departmentId", departmentID, "principal.departments", stringsOf(path)), nil
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
