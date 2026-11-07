package server

// Port of packages/server/src/api/departments.ts: the organization's reporting structure (departments.ts).
// `iam:departments:read` lists and reads it, `iam:departments:manage` changes it and places people. Policies see
// `principal.departmentId` and `principal.departments`; `syncManagers` turns department heads into managers for
// approvals routed to managers.

import (
	"context"
	"math"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// departmentMaxAssign is api/departments.ts maxAssign: people placed by one assign call.
const departmentMaxAssign = 100

// departmentOptionalText is api/departments.ts optionalText: "" (undefined) for undefined, null, or an empty string,
// otherwise a valid trimmed text.
func departmentOptionalText(value any, name string, max int) (string, error) {
	if nullish(value) || value == "" {
		return "", nil
	}
	text, err := Text(value, name, max)
	if err != nil {
		return "", err
	}
	return core.JSTrim(text), nil
}

// departmentPersonOf is api/departments.ts person: `{ id, name, email?, status }`.
func departmentPersonOf(identity *core.Object) *core.Object {
	view := core.NewObject("id", identity.Get("id"), "name", identity.Get("name"))
	if email := identity.Get("email"); truthy(email) {
		view.Set("email", email)
	}
	return view.Set("status", identity.Get("status"))
}

// departmentRefOf is api/departments.ts ref: `{ id, name, code? }`.
func departmentRefOf(department *core.Object) *core.Object {
	view := core.NewObject("id", department.Get("id"), "name", department.Get("name"))
	if code := department.Get("code"); truthy(code) {
		view.Set("code", code)
	}
	return view
}

// departmentRefs maps departments to refs.
func departmentRefs(departments []*core.Object) []any {
	refs := make([]any, len(departments))
	for index, department := range departments {
		refs[index] = departmentRefOf(department)
	}
	return refs
}

// reversedDepartments is `[...list].reverse()`.
func reversedDepartments(list []*core.Object) []*core.Object {
	out := make([]*core.Object, len(list))
	for index, item := range list {
		out[len(list)-1-index] = item
	}
	return out
}

// departmentIndex is the tenant's departments as tenantDepartments returns them: by ID, and in the order a
// JavaScript Map built from the stored records iterates (the store's order), which list, tree and the sync walk
// follow.
type departmentIndex struct {
	list []*core.Object
	byID map[string]*core.Object
}

// departmentsOf reads the tenant's departments (departments.ts tenantDepartments, keeping the iteration order).
func departmentsOf(ctx context.Context, tx core.IamStore, tenantID string) (*departmentIndex, error) {
	records, err := tx.Find(ctx, DepartmentCollections.Departments, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	index := &departmentIndex{byID: map[string]*core.Object{}}
	for _, record := range records {
		id := jsString(record.Get("id"))
		if _, seen := index.byID[id]; !seen {
			index.list = append(index.list, record)
		} else {
			for position, item := range index.list {
				if jsString(item.Get("id")) == id {
					index.list[position] = record
				}
			}
		}
		index.byID[id] = record
	}
	return index, nil
}

// has is `departments.has(key)` for an untrusted key.
func (d *departmentIndex) has(key any) bool {
	id, ok := key.(string)
	if !ok {
		return false
	}
	_, found := d.byID[id]
	return found
}

// childrenOf is the departments whose parentId is departmentID, in iteration order.
func (d *departmentIndex) childrenOf(departmentID any) []*core.Object {
	children := []*core.Object{}
	for _, other := range d.list {
		if other.Get("parentId") == departmentID {
			children = append(children, other)
		}
	}
	return children
}

// sortDepartmentsByName is `.sort((a, b) => a.name.localeCompare(b.name))`.
func sortDepartmentsByName(list []*core.Object) {
	sort.SliceStable(list, func(i, j int) bool {
		return localeCompare(jsString(list[i].Get("name")), jsString(list[j].Get("name"))) < 0
	})
}

// sortDepartmentMembers is the member order of listMembers and mine: heads first, then by email (or name).
func sortDepartmentMembers(views []*core.Object) {
	label := func(view *core.Object) string { return jsString(coalesce(view.Get("email"), view.Get("name"))) }
	headRank := func(view *core.Object) int {
		if truthy(view.Get("head")) {
			return 1
		}
		return 0
	}
	sort.SliceStable(views, func(i, j int) bool {
		a, b := views[i], views[j]
		if rank := headRank(b) - headRank(a); rank != 0 {
			return rank < 0
		}
		return localeCompare(label(a), label(b)) < 0
	})
}

// departmentMemberView is a DepartmentMemberView: the person, their department, title, since, head, and manager.
func departmentMemberView(identity, department, member *core.Object) *core.Object {
	view := departmentPersonOf(identity).Set("department", departmentRefOf(department))
	if title := member.Get("title"); truthy(title) {
		view.Set("title", title)
	}
	view.Set("since", member.Get("since"))
	if department.Get("headId") == identity.Get("id") {
		view.Set("head", true)
	}
	if managerID := identity.Get("managerId"); truthy(managerID) {
		view.Set("managerId", managerID)
	}
	return view
}

func objectsToList(items []*core.Object) []any {
	list := make([]any, len(items))
	for index, item := range items {
		list[index] = item
	}
	return list
}

// DepartmentsAPI is the `departments` API group (packages/server/src/api/departments.ts createDepartmentsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/departments/{method} onto it.
type DepartmentsAPI struct {
	server *ServerContext
	module *DepartmentMutationsResult
}

// CreateDepartmentsAPI builds the `departments` API group.
func CreateDepartmentsAPI(server *ServerContext) *DepartmentsAPI {
	return &DepartmentsAPI{server: server, module: &DepartmentMutationsResult{server: server}}
}

// Assign is POST {basePath}/departments/assign. Places up to 100 people (identityIds, or one identityId) in a department, moving them out of any other, with an optional title. Returns how many changed.
func (api *DepartmentsAPI) Assign(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsAssignInput]) (Out[apitypes.DepartmentsAssignOutput], error) {
	server, m := api.server, api.module
	tenantID := input.Get("tenantId")
	result, err := m.reconciling(ctx, tenantID, func(touch func(identityIDs ...string)) (any, error) {
		departmentID, err := Text(input.Get("departmentId"), "departmentId", 128)
		if err != nil {
			return nil, err
		}
		return Operate(ctx, server.Operations, credential, tenantID, "iam:departments:manage", departmentID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx := call.Tx
			tenant := jsString(tenantID)
			department, err := LoadDepartment(ctx, tx, tenant, input.Get("departmentId"))
			if err != nil {
				return nil, err
			}
			rawIDs, rawID := input.Get("identityIds"), input.Get("identityId")
			if isUndefined(rawIDs) == isUndefined(rawID) {
				return nil, invalidInput("Provide identityIds or identityId")
			}
			var listed []string
			if !isUndefined(rawIDs) {
				if listed, err = Strings(rawIDs, "identityIds"); err != nil {
					return nil, err
				}
			} else {
				one, err := Text(rawID, "identityId", 128)
				if err != nil {
					return nil, err
				}
				listed = []string{one}
			}
			identityIDs := unique(listed)
			if len(identityIDs) == 0 || len(identityIDs) > departmentMaxAssign {
				return nil, invalidInput("Provide 1-100 identityIds")
			}
			title, err := departmentOptionalText(input.Get("title"), "title", 100)
			if err != nil {
				return nil, err
			}
			assigned := 0
			for _, identityID := range identityIDs {
				person, err := m.DepartmentPerson(ctx, tx, tenant, identityID)
				if err != nil {
					return nil, err
				}
				changed, err := m.Place(ctx, tx, call.Principal, department, person, title)
				if err != nil {
					return nil, err
				}
				if changed {
					assigned++
					touch(identityID)
				}
			}
			return core.NewObject("assigned", float64(assigned), "unchanged", float64(len(identityIDs)-assigned)), nil
		}, false)
	})
	return Out[apitypes.DepartmentsAssignOutput]{Value: result}, err
}

// Create is POST {basePath}/departments/create. Creates a department, optionally under parentId, with a code, a headId (an active person of the organization), a costCenter, and a description.
func (api *DepartmentsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsCreateInput]) (Out[apitypes.DepartmentsCreateOutput], error) {
	server, m := api.server, api.module
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:departments:manage", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		department, err := m.CreateDepartment(ctx, call.Tx, call.Principal, call.Tenant, input.Body)
		if err != nil {
			return nil, err
		}
		return m.detail(ctx, call.Tx, department)
	}, false)
	return Out[apitypes.DepartmentsCreateOutput]{Value: result}, err
}

// Delete is POST {basePath}/departments/delete. Deletes a department. Its people become unassigned and its teams lose the link.
// Departments below it must be moved or deleted first (RESOURCE_IN_USE).
func (api *DepartmentsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsDeleteInput]) (Out[apitypes.DepartmentsDeleteOutput], error) {
	server, m := api.server, api.module
	tenantID := input.Get("tenantId")
	result, err := m.reconciling(ctx, tenantID, func(touch func(identityIDs ...string)) (any, error) {
		departmentID, err := Text(input.Get("departmentId"), "departmentId", 128)
		if err != nil {
			return nil, err
		}
		return Operate(ctx, server.Operations, credential, tenantID, "iam:departments:manage", departmentID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tenant := jsString(call.Tenant.Get("id"))
			people, err := m.peopleBelow(ctx, call.Tx, tenant, departmentID)
			if err != nil {
				return nil, err
			}
			touch(people...)
			removed, err := m.DeleteDepartment(ctx, call.Tx, call.Principal, call.Tenant, input.Body)
			if err != nil {
				return nil, err
			}
			return core.NewObject("deleted", true).Assign(removed), nil
		}, false)
	})
	return Out[apitypes.DepartmentsDeleteOutput]{Value: result}, err
}

// Get is POST {basePath}/departments/get. One department with its path (the departments above it), sub-departments, head, and teams, and member counts with and without the departments below.
func (api *DepartmentsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsGetInput]) (Out[apitypes.DepartmentsGetOutput], error) {
	server, m := api.server, api.module
	tenantID := input.Get("tenantId")
	departmentID, err := Text(input.Get("departmentId"), "departmentId", 128)
	if err != nil {
		return Out[apitypes.DepartmentsGetOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:departments:read", departmentID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		department, err := LoadDepartment(ctx, call.Tx, jsString(tenantID), input.Get("departmentId"))
		if err != nil {
			return nil, err
		}
		return m.detail(ctx, call.Tx, department)
	}, false)
	return Out[apitypes.DepartmentsGetOutput]{Value: result}, err
}

// ImportFromAttribute is POST {basePath}/departments/importFromAttribute. Places every active person whose string identity attribute (such as department, filled by SCIM provisioning or an onboarding form) names a department, matched by name or code ignoring case.
// createMissing creates top-level departments for unmatched values; dryRun reports without changing anything.
func (api *DepartmentsAPI) ImportFromAttribute(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsImportFromAttributeInput]) (Out[apitypes.DepartmentsImportFromAttributeOutput], error) {
	server, m := api.server, api.module
	tenantID := input.Get("tenantId")
	result, err := m.reconciling(ctx, tenantID, func(touch func(identityIDs ...string)) (any, error) {
		return Operate(ctx, server.Operations, credential, tenantID, "iam:departments:manage", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx := call.Tx
			attribute, err := Text(input.Get("attribute"), "attribute", 64)
			if err != nil {
				return nil, err
			}
			var declared any = core.Undefined
			if server.Catalog != nil {
				declared = member(server.Catalog.IdentityAttributes, attribute)
			}
			if declared != "string" {
				return nil, invalidInput(attribute + " is not a declared string identity attribute (permissions.identityAttributes)")
			}
			dryRun := input.Get("dryRun") == true
			tenant := jsString(call.Tenant.Get("id"))
			departments, err := departmentsOf(ctx, tx, tenant)
			if err != nil {
				return nil, err
			}
			byKey := map[string]*core.Object{}
			for _, department := range departments.list {
				byKey[core.JSLower(jsString(department.Get("name")))] = department
				if code := department.Get("code"); truthy(code) {
					byKey[core.JSLower(jsString(code))] = department
				}
			}
			created := []any{}
			assigned, unchanged, missing := 0, 0, 0
			identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenant), nil)
			if err != nil {
				return nil, err
			}
			unmatched := newOrderedSet()
			for _, identity := range identities {
				if identity.Get("kind") != "user" || identity.Get("status") != "active" {
					continue
				}
				value := ""
				if raw, ok := member(identity.Get("attributes"), attribute).(string); ok {
					value = core.JSTrim(raw)
				}
				if value == "" {
					missing++
					continue
				}
				department := byKey[core.JSLower(value)]
				if department == nil && truthy(input.Get("createMissing")) {
					if len(departments.list)+len(created) >= MaxDepartments {
						return nil, core.NewIamError("LIMIT_EXCEEDED", "At most 2000 departments", 409)
					}
					name := stsSliceUTF16(value, 0, 100)
					now := float64(server.Now())
					department = core.NewObject(
						"id", ID(),
						"tenantId", tenant,
						"uniqueKey", "name:"+core.JSLower(name),
						"name", name,
						"createdAt", now,
						"updatedAt", now,
					)
					if !dryRun {
						if _, err := tx.Insert(ctx, DepartmentCollections.Departments, department); err != nil {
							return nil, err
						}
						if err := m.audit(ctx, tx, call.Principal, "department:create", tenant, jsString(department.Get("id")), core.NewObject(
							"name", name,
							"source", "attribute:"+attribute,
						)); err != nil {
							return nil, err
						}
					}
					byKey[core.JSLower(name)] = department
					created = append(created, name)
				}
				if department == nil {
					unmatched.Add(value)
					continue
				}
				current, err := DepartmentMembership(ctx, tx, tenant, jsString(identity.Get("id")))
				if err != nil {
					return nil, err
				}
				if current != nil && current.Get("departmentId") == department.Get("id") {
					unchanged++
					continue
				}
				if !dryRun {
					title := ""
					if current != nil {
						title, _ = current.Get("title").(string)
					}
					if _, err := m.Place(ctx, tx, call.Principal, department, identity, title); err != nil {
						return nil, err
					}
					touch(jsString(identity.Get("id")))
				}
				assigned++
			}
			values := unmatched.Values()
			sort.SliceStable(values, func(i, j int) bool { return compareUTF16(values[i], values[j]) < 0 })
			return core.NewObject(
				"dryRun", dryRun,
				"created", created,
				"assigned", float64(assigned),
				"unchanged", float64(unchanged),
				"unmatched", stringsOf(values),
				"missing", float64(missing),
			), nil
		}, false)
	})
	return Out[apitypes.DepartmentsImportFromAttributeOutput]{Value: result}, err
}

// List is POST {basePath}/departments/list. Every department with member counts (with and without sub-departments), child and team counts, in name order.
func (api *DepartmentsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsListInput]) (Out[apitypes.DepartmentsListOutput], error) {
	server, m := api.server, api.module
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:departments:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		order, _, err := m.summaries(ctx, call.Tx, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		sort.SliceStable(order, func(i, j int) bool {
			a, b := order[i], order[j]
			if compared := localeCompare(jsString(a.Get("name")), jsString(b.Get("name"))); compared != 0 {
				return compared < 0
			}
			return compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0
		})
		return objectsToList(order), nil
	}, false)
	return Out[apitypes.DepartmentsListOutput]{Value: result}, err
}

// ListMembers is POST {basePath}/departments/listMembers. The people of a department, heads first; includeSubdepartments adds those of every department below, each with their department.
func (api *DepartmentsAPI) ListMembers(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsListMembersInput]) (Out[apitypes.DepartmentsListMembersOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	departmentID, err := Text(input.Get("departmentId"), "departmentId", 128)
	if err != nil {
		return Out[apitypes.DepartmentsListMembersOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:departments:read", departmentID, func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		tenant := jsString(tenantID)
		department, err := LoadDepartment(ctx, tx, tenant, input.Get("departmentId"))
		if err != nil {
			return nil, err
		}
		departments, err := departmentsOf(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		scope := []*core.Object{department}
		if truthy(input.Get("includeSubdepartments")) {
			below, err := DepartmentDescendants(departments.list, jsString(department.Get("id")))
			if err != nil {
				return nil, err
			}
			scope = append(scope, below...)
		}
		views, err := departmentPeople(ctx, tx, tenant, scope)
		if err != nil {
			return nil, err
		}
		return objectsToList(views), nil
	}, false)
	return Out[apitypes.DepartmentsListMembersOutput]{Value: result}, err
}

// departmentPeople is the member views of the people placed in the departments of scope (in scope order, then the
// store's), without deleted identities, heads first and then by email or name.
func departmentPeople(ctx context.Context, tx core.IamStore, tenantID string, scope []*core.Object) ([]*core.Object, error) {
	views := []*core.Object{}
	for _, item := range scope {
		members, err := tx.Find(ctx, DepartmentCollections.Members, core.NewObject("tenantId", tenantID, "departmentId", item.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		for _, member := range members {
			identity, err := tx.Get(ctx, "identities", jsString(member.Get("identityId")))
			if err != nil {
				return nil, err
			}
			if identity == nil || identity.Get("status") == "deleted" {
				continue
			}
			views = append(views, departmentMemberView(identity, item, member))
		}
	}
	sortDepartmentMembers(views)
	return views, nil
}

// Mine is POST {basePath}/departments/mine. Your own place in the org chart and, if you head departments, the people you lead.
// Needs only an ordinary session of a person in the organization.
func (api *DepartmentsAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsMineInput]) (Out[apitypes.DepartmentsMineOutput], error) {
	server, m := api.server, api.module
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.DepartmentsMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.DepartmentsMineOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if !ActsInOwnRight(principal.Session) ||
			principal.Session.Get("tenantId") != tenantID ||
			principal.Identity.Get("tenantId") != tenantID ||
			principal.Identity.Get("kind") != "user" {
			return nil, core.NewIamError("ACCESS_DENIED", "Departments are read from a person’s own session in their organization", 403)
		}
		me := principal.Identity.Get("id")
		departments, err := departmentsOf(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		membership, err := DepartmentMembership(ctx, tx, tenantID, jsString(me))
		if err != nil {
			return nil, err
		}
		var placement any
		if membership != nil {
			if own := departments.byID[jsString(membership.Get("departmentId"))]; own != nil {
				view, err := m.placement(ctx, tx, departments, own, membership)
				if err != nil {
					return nil, err
				}
				placement = view
			}
		}
		headed := []*core.Object{}
		for _, item := range departments.list {
			if item.Get("headId") == me {
				headed = append(headed, item)
			}
		}
		sortDepartmentsByName(headed)
		leads := []any{}
		for _, department := range headed {
			below, err := DepartmentDescendants(departments.list, jsString(department.Get("id")))
			if err != nil {
				return nil, err
			}
			people, err := departmentPeople(ctx, tx, tenantID, append([]*core.Object{department}, below...))
			if err != nil {
				return nil, err
			}
			chain, err := DepartmentChain(departments.byID, jsString(department.Get("id")))
			if err != nil {
				return nil, err
			}
			leads = append(leads, core.NewObject(
				"department", departmentRefOf(department),
				"path", departmentRefs(reversedDepartments(chain)),
				"people", objectsToList(people),
			))
		}
		return core.NewObject("department", placement, "leads", leads), nil
	})
	if err != nil {
		return Out[apitypes.DepartmentsMineOutput]{}, err
	}
	return Out[apitypes.DepartmentsMineOutput]{Value: result}, nil
}

// OfIdentity is POST {basePath}/departments/ofIdentity. A person's department with the path from the top, their title, since when, the department's head and cost center; null when they have none.
func (api *DepartmentsAPI) OfIdentity(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsOfIdentityInput]) (Out[apitypes.DepartmentsOfIdentityOutput], error) {
	server, m := api.server, api.module
	tenantID := input.Get("tenantId")
	identityID, err := Text(input.Get("identityId"), "identityId", 128)
	if err != nil {
		return Out[apitypes.DepartmentsOfIdentityOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:departments:read", identityID, func(ctx context.Context, call MutationContext) (any, error) {
		tx := call.Tx
		tenant := jsString(tenantID)
		if _, err := server.Scoped(ctx, tx, "identities", input.Get("identityId"), tenant); err != nil {
			return nil, err
		}
		membership, err := DepartmentMembership(ctx, tx, tenant, identityID)
		if err != nil {
			return nil, err
		}
		departments, err := departmentsOf(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		if membership == nil {
			return nil, nil
		}
		department := departments.byID[jsString(membership.Get("departmentId"))]
		if department == nil {
			return nil, nil
		}
		return m.placement(ctx, tx, departments, department, membership)
	}, false)
	if err != nil {
		return Out[apitypes.DepartmentsOfIdentityOutput]{}, err
	}
	return Out[apitypes.DepartmentsOfIdentityOutput]{Value: result}, nil
}

// placement is a DepartmentPlacement (ofIdentity, mine): the department, the path from the top, title, since, head
// and cost center.
func (m *DepartmentMutationsResult) placement(ctx context.Context, tx core.IamStore, departments *departmentIndex, department, membership *core.Object) (*core.Object, error) {
	head, err := m.headOf(ctx, tx, department)
	if err != nil {
		return nil, err
	}
	chain, err := DepartmentChain(departments.byID, jsString(department.Get("id")))
	if err != nil {
		return nil, err
	}
	view := core.NewObject(
		"department", departmentRefOf(department),
		"path", departmentRefs(reversedDepartments(chain)),
	)
	if title := membership.Get("title"); truthy(title) {
		view.Set("title", title)
	}
	view.Set("since", membership.Get("since"))
	if head != nil {
		view.Set("head", head)
	}
	if costCenter := department.Get("costCenter"); truthy(costCenter) {
		view.Set("costCenter", costCenter)
	}
	return view, nil
}

// SuggestBirthright is POST {basePath}/departments/suggestBirthright. Roles and groups that most of a department's people already hold by hand, proposed as a ready-made automatic access package whose rule names the department.
// Read-only; requires iam:analysis:read.
func (api *DepartmentsAPI) SuggestBirthright(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsSuggestBirthrightInput]) (Out[apitypes.DepartmentsSuggestBirthrightOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:analysis:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		tenant := jsString(call.Tenant.Get("id"))
		options, err := BirthrightOptions(input.Body)
		if err != nil {
			return nil, err
		}
		departmentID := input.Get("departmentId")
		if !isUndefined(departmentID) {
			if _, err := LoadDepartment(ctx, tx, tenant, departmentID); err != nil {
				return nil, err
			}
		}
		settings := options.Spread()
		if !isUndefined(departmentID) {
			settings.Set("unitId", departmentID)
		}
		suggestions, err := SuggestBirthright(ctx, server, tx, tenant, "department", settings)
		if err != nil {
			return nil, err
		}
		return objectsToList(suggestions), nil
	}, false)
	return Out[apitypes.DepartmentsSuggestBirthrightOutput]{Value: result}, err
}

// SyncManagers is POST {basePath}/departments/syncManagers. Makes department heads the managers of their departments' people (see above).
// Each person reports to their department's head, and a head to the nearest head above. Without overwrite only
// people without a manager change; departmentId limits it to one department (and the ones below it); dryRun reports
// only. Cycles are never created.
func (api *DepartmentsAPI) SyncManagers(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsSyncManagersInput]) (Out[apitypes.DepartmentsSyncManagersOutput], error) {
	server, m := api.server, api.module
	tenantID := input.Get("tenantId")
	result, err := m.reconciling(ctx, tenantID, func(touch func(identityIDs ...string)) (any, error) {
		rawDepartmentID := input.Get("departmentId")
		resourceID := jsString(tenantID)
		if !isUndefined(rawDepartmentID) {
			text, err := Text(rawDepartmentID, "departmentId", 128)
			if err != nil {
				return nil, err
			}
			resourceID = text
		}
		return Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx := call.Tx
			tenant := jsString(call.Tenant.Get("id"))
			readable, err := server.Decisions.Decide(ctx, tx, call.Principal, AuthorizationRequest{
				TenantID: tenant, Action: "iam:departments:read", Resource: ResourceTarget{Type: "iam", ID: tenant},
			}, true)
			if err != nil {
				return nil, err
			}
			if !readable.Allowed {
				return nil, core.NewIamError("ACCESS_DENIED", "Reading departments needs iam:departments:read", 403)
			}
			departments, err := departmentsOf(ctx, tx, tenant)
			if err != nil {
				return nil, err
			}
			var scope []*core.Object
			if isUndefined(rawDepartmentID) {
				scope = departments.list
			} else {
				root := departments.byID[resourceID]
				if root == nil {
					return nil, core.NewIamError("NOT_FOUND", "Department not found", 404)
				}
				below, err := DepartmentDescendants(departments.list, jsString(root.Get("id")))
				if err != nil {
					return nil, err
				}
				scope = append([]*core.Object{root}, below...)
			}
			dryRun := input.Get("dryRun") == true
			updated := []any{}
			kept, noHead := 0, 0
			records, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenant), nil)
			if err != nil {
				return nil, err
			}
			identities := map[string]*core.Object{}
			for _, identity := range records {
				identities[jsString(identity.Get("id"))] = identity
			}
			liveHead := func(department *core.Object) *core.Object {
				headID := department.Get("headId")
				if !truthy(headID) {
					return nil
				}
				head := identities[jsString(headID)]
				if head != nil && head.Get("status") == "active" {
					return head
				}
				return nil
			}
			// Whether managerID's own chain of managers reaches identityID (which would close a cycle).
			reaches := func(managerID, identityID string) bool {
				cursor := identities[managerID]
				for depth := 0; cursor != nil && depth < 100; depth++ {
					if jsString(cursor.Get("id")) == identityID {
						return true
					}
					if next := cursor.Get("managerId"); truthy(next) {
						cursor = identities[jsString(next)]
					} else {
						cursor = nil
					}
				}
				return false
			}
			var changedIDs []string
			for _, department := range scope {
				members, err := tx.Find(ctx, DepartmentCollections.Members, core.NewObject("tenantId", tenant, "departmentId", department.Get("id")), nil)
				if err != nil {
					return nil, err
				}
				for _, member := range members {
					identity := identities[jsString(member.Get("identityId"))]
					if identity == nil || identity.Get("status") != "active" {
						continue
					}
					identityID := jsString(identity.Get("id"))
					chain, err := DepartmentChain(departments.byID, jsString(department.Get("id")))
					if err != nil {
						return nil, err
					}
					var manager *core.Object
					for _, step := range chain {
						if head := liveHead(step); head != nil && jsString(head.Get("id")) != identityID {
							manager = head
							break
						}
					}
					if manager == nil {
						noHead++
						continue
					}
					managerID := jsString(manager.Get("id"))
					if identity.Get("managerId") == manager.Get("id") {
						continue
					}
					if truthy(identity.Get("managerId")) && !truthy(input.Get("overwrite")) {
						kept++
						continue
					}
					if reaches(managerID, identityID) {
						kept++
						continue
					}
					// Each person is updated as identities.update would: a deny protecting that identity holds.
					may, err := server.Decisions.Decide(ctx, tx, call.Principal, AuthorizationRequest{
						TenantID: tenant, Action: "iam:identities:update", Resource: ResourceTarget{Type: "iam", ID: identityID},
					}, true)
					if err != nil {
						return nil, err
					}
					if !may.Allowed {
						kept++
						continue
					}
					updated = append(updated, core.NewObject(
						"identityId", identity.Get("id"),
						"name", identity.Get("name"),
						"managerId", manager.Get("id"),
						"managerName", manager.Get("name"),
					))
					changedIDs = append(changedIDs, identityID)
					next := identity.Spread(core.NewObject("managerId", manager.Get("id")))
					identities[identityID] = next
					if !dryRun {
						if _, err := tx.Put(ctx, "identities", next); err != nil {
							return nil, err
						}
					}
				}
			}
			if !dryRun && len(updated) > 0 {
				metadata := core.NewObject("updated", float64(len(updated)))
				if truthy(rawDepartmentID) {
					metadata.Set("departmentId", rawDepartmentID)
				}
				if err := m.audit(ctx, tx, call.Principal, "department:sync-managers", tenant, tenant, metadata); err != nil {
					return nil, err
				}
			}
			// Rules may test identity.managerId.
			if !dryRun {
				touch(changedIDs...)
			}
			return core.NewObject(
				"dryRun", dryRun,
				"updated", updated,
				"kept", float64(kept),
				"noHead", float64(noHead),
			), nil
		}, false)
	})
	return Out[apitypes.DepartmentsSyncManagersOutput]{Value: result}, err
}

// Tree is POST {basePath}/departments/tree. The org chart: top-level departments with their sub-departments, heads, and member counts.
func (api *DepartmentsAPI) Tree(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsTreeInput]) (Out[apitypes.DepartmentsTreeOutput], error) {
	server, m := api.server, api.module
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:departments:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		tenant := jsString(tenantID)
		departments, err := departmentsOf(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		_, all, err := m.summaries(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		heads := map[string]*core.Object{}
		for _, department := range departments.list {
			head, err := m.headOf(ctx, tx, department)
			if err != nil {
				return nil, err
			}
			if head != nil {
				heads[jsString(department.Get("id"))] = head
			}
		}
		var build func(parentID any, depth int) []any
		build = func(parentID any, depth int) []any {
			nodes := []any{}
			if depth > MaxDepartmentDepth {
				return nodes
			}
			matched := []*core.Object{}
			for _, department := range departments.list {
				own := department.Get("parentId")
				var include bool
				if isUndefined(parentID) {
					// A department whose parent is gone is shown at the top.
					include = nullish(own) || !departments.has(own)
				} else {
					include = !nullish(own) && own == parentID
				}
				if include {
					matched = append(matched, department)
				}
			}
			sortDepartmentsByName(matched)
			for _, department := range matched {
				id := jsString(department.Get("id"))
				node := all[id].Spread()
				if head, ok := heads[id]; ok {
					node.Set("head", head)
				}
				node.Set("children", build(department.Get("id"), depth+1))
				nodes = append(nodes, node)
			}
			return nodes
		}
		return build(core.Undefined, 0), nil
	}, false)
	return Out[apitypes.DepartmentsTreeOutput]{Value: result}, err
}

// Unassign is POST {basePath}/departments/unassign. Takes a person out of their department.
func (api *DepartmentsAPI) Unassign(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsUnassignInput]) (Out[apitypes.DepartmentsUnassignOutput], error) {
	server, m := api.server, api.module
	tenantID := input.Get("tenantId")
	result, err := m.reconciling(ctx, tenantID, func(touch func(identityIDs ...string)) (any, error) {
		identityID, err := Text(input.Get("identityId"), "identityId", 128)
		if err != nil {
			return nil, err
		}
		return Operate(ctx, server.Operations, credential, tenantID, "iam:departments:manage", identityID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx := call.Tx
			tenant := jsString(tenantID)
			membership, err := DepartmentMembership(ctx, tx, tenant, identityID)
			if err != nil {
				return nil, err
			}
			if membership == nil {
				return nil, core.NewIamError("NOT_FOUND", "Not in a department", 404)
			}
			if err := tx.Delete(ctx, DepartmentCollections.Members, jsString(membership.Get("id"))); err != nil {
				return nil, err
			}
			if err := m.audit(ctx, tx, call.Principal, "department:unassign", tenant, jsString(membership.Get("departmentId")), core.NewObject("identityId", identityID)); err != nil {
				return nil, err
			}
			touch(identityID)
			return core.NewObject("deleted", true), nil
		}, false)
	})
	return Out[apitypes.DepartmentsUnassignOutput]{Value: result}, err
}

// Update is POST {basePath}/departments/update. Renames, re-codes, moves (parentId, null for top level), or changes the head, cost center, or description of a department; null (or an empty string) clears an optional field.
func (api *DepartmentsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.DepartmentsUpdateInput]) (Out[apitypes.DepartmentsUpdateOutput], error) {
	server, m := api.server, api.module
	tenantID := input.Get("tenantId")
	result, err := m.reconciling(ctx, tenantID, func(touch func(identityIDs ...string)) (any, error) {
		departmentID, err := Text(input.Get("departmentId"), "departmentId", 128)
		if err != nil {
			return nil, err
		}
		return Operate(ctx, server.Operations, credential, tenantID, "iam:departments:manage", departmentID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx := call.Tx
			updated, err := m.UpdateDepartment(ctx, tx, call.Principal, call.Tenant, input.Body)
			if err != nil {
				return nil, err
			}
			// A move changes identity.departments for everyone at or below it.
			if !isUndefined(input.Get("parentId")) {
				people, err := m.peopleBelow(ctx, tx, jsString(call.Tenant.Get("id")), jsString(updated.Get("id")))
				if err != nil {
					return nil, err
				}
				touch(people...)
			}
			return m.detail(ctx, tx, updated)
		}, false)
	})
	return Out[apitypes.DepartmentsUpdateOutput]{Value: result}, err
}

// DepartmentMutationsResult is api/departments.ts departmentMutations() (the department module's helpers).
type DepartmentMutationsResult struct {
	server *ServerContext
}

// reconciling runs a change, then (once it committed) re-evaluates the birthright access package rules of the people
// it touched: rules may test identity.departments and identity.managerId.
func (m *DepartmentMutationsResult) reconciling(ctx context.Context, tenantID any, run func(touch func(identityIDs ...string)) (any, error)) (any, error) {
	touched := newOrderedSet()
	result, err := run(func(identityIDs ...string) {
		for _, identityID := range identityIDs {
			touched.Add(identityID)
		}
	})
	if err != nil {
		return nil, err
	}
	return AfterIdentityChange(ctx, m.server, jsString(tenantID), touched.Values(), result)
}

// peopleBelow is the people placed in a department or any department below it.
func (m *DepartmentMutationsResult) peopleBelow(ctx context.Context, tx core.IamStore, tenantID, departmentID string) ([]string, error) {
	departments, err := departmentsOf(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	below, err := DepartmentDescendants(departments.list, departmentID)
	if err != nil {
		return nil, err
	}
	scope := map[string]bool{departmentID: true}
	for _, item := range below {
		scope[jsString(item.Get("id"))] = true
	}
	members, err := tx.Find(ctx, DepartmentCollections.Members, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	people := []string{}
	for _, placement := range members {
		if scope[jsString(placement.Get("departmentId"))] {
			people = append(people, jsString(placement.Get("identityId")))
		}
	}
	return people, nil
}

func (m *DepartmentMutationsResult) audit(ctx context.Context, tx core.IamStore, principal *Principal, action, tenantID, resourceID string, metadata *core.Object) error {
	return m.server.Events.Audit(ctx, tx, principal, action, tenantID, resourceID, "allow", false, metadata)
}

// DepartmentPerson (api/departments.ts departmentMutations().departmentPerson): An active person of the tenant who
// can head a department or belong to one.
func (m *DepartmentMutationsResult) DepartmentPerson(ctx context.Context, tx core.IamStore, tenantID string, identityID any) (*core.Object, error) {
	id, err := Text(identityID, "identityId", 128)
	if err != nil {
		return nil, err
	}
	identity, err := m.server.ActiveIdentity(ctx, tx, id, tenantID)
	if err != nil {
		return nil, err
	}
	if identity.Get("kind") != "user" {
		return nil, invalidInput("Departments hold people; service accounts and agents have none")
	}
	return identity, nil
}

// assertUnique refuses a name (or code, when not "") another department of the tenant has, ignoring case.
func (m *DepartmentMutationsResult) assertUnique(ctx context.Context, tx core.IamStore, tenantID, name, code, exceptID string) error {
	departments, err := departmentsOf(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	for _, other := range departments.list {
		if exceptID != "" && other.Get("id") == exceptID {
			continue
		}
		otherName := jsString(other.Get("name"))
		if core.JSLower(otherName) == core.JSLower(name) {
			return core.NewIamError("CONFLICT", "A department named "+otherName+" exists", 409)
		}
		if otherCode, ok := other.Get("code").(string); ok && code != "" && core.JSLower(otherCode) == core.JSLower(code) {
			return core.NewIamError("CONFLICT", "The code "+code+" is taken by "+otherName, 409)
		}
	}
	return nil
}

func (m *DepartmentMutationsResult) depthCheck(departments *departmentIndex, parent *core.Object, subtreeHeight int) error {
	chain, err := DepartmentChain(departments.byID, jsString(parent.Get("id")))
	if err != nil {
		return err
	}
	if len(chain)+subtreeHeight > MaxDepartmentDepth {
		return invalidInput("Departments nest at most 20 levels deep")
	}
	return nil
}

// summaries is every department as lists return it (DepartmentSummary), in the departments' order and by ID.
func (m *DepartmentMutationsResult) summaries(ctx context.Context, tx core.IamStore, tenantID string) ([]*core.Object, map[string]*core.Object, error) {
	departments, err := departmentsOf(ctx, tx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	memberRecords, err := tx.Find(ctx, DepartmentCollections.Members, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, nil, err
	}
	members := map[string]int{}
	for _, member := range memberRecords {
		members[jsString(member.Get("departmentId"))]++
	}
	teamRecords, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, nil, err
	}
	teams := map[string]int{}
	for _, team := range teamRecords {
		if departmentID := team.Get("departmentId"); truthy(departmentID) {
			teams[jsString(departmentID)]++
		}
	}
	order := make([]*core.Object, 0, len(departments.list))
	byID := map[string]*core.Object{}
	for _, department := range departments.list {
		id := jsString(department.Get("id"))
		rest := department.Spread()
		rest.Delete("uniqueKey")
		below, err := DepartmentDescendants(departments.list, id)
		if err != nil {
			return nil, nil, err
		}
		total := members[id]
		for _, item := range below {
			total += members[jsString(item.Get("id"))]
		}
		rest.Set("memberCount", float64(members[id]))
		rest.Set("totalMemberCount", float64(total))
		rest.Set("childCount", float64(len(departments.childrenOf(department.Get("id")))))
		rest.Set("teamCount", float64(teams[id]))
		order = append(order, rest)
		byID[id] = rest
	}
	return order, byID, nil
}

// headOf is the department's head as a DepartmentPerson, nil without one (or when it is not a person of the tenant).
func (m *DepartmentMutationsResult) headOf(ctx context.Context, tx core.IamStore, department *core.Object) (*core.Object, error) {
	headID := department.Get("headId")
	if !truthy(headID) {
		return nil, nil
	}
	identity, err := tx.Get(ctx, "identities", jsString(headID))
	if err != nil {
		return nil, err
	}
	if identity != nil && identity.Get("tenantId") == department.Get("tenantId") {
		return departmentPersonOf(identity), nil
	}
	return nil, nil
}

// detail is a DepartmentDetail: the summary with the path, children, head, and teams.
func (m *DepartmentMutationsResult) detail(ctx context.Context, tx core.IamStore, department *core.Object) (*core.Object, error) {
	tenantID := jsString(department.Get("tenantId"))
	id := jsString(department.Get("id"))
	departments, err := departmentsOf(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	_, all, err := m.summaries(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	children := departments.childrenOf(department.Get("id"))
	sortDepartmentsByName(children)
	head, err := m.headOf(ctx, tx, department)
	if err != nil {
		return nil, err
	}
	teamRecords, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	filed := []*core.Object{}
	for _, team := range teamRecords {
		if team.Get("departmentId") == department.Get("id") {
			filed = append(filed, team)
		}
	}
	sortDepartmentsByName(filed)
	teams := make([]any, len(filed))
	for index, team := range filed {
		teams[index] = core.NewObject("id", team.Get("id"), "name", team.Get("name"), "slug", team.Get("slug"))
	}
	chain, err := DepartmentChain(departments.byID, id)
	if err != nil {
		return nil, err
	}
	above := []*core.Object{}
	if len(chain) > 1 {
		above = chain[1:]
	}
	childViews := make([]any, len(children))
	for index, child := range children {
		summary := all[jsString(child.Get("id"))]
		childViews[index] = departmentRefOf(child).
			Set("memberCount", summary.Get("memberCount")).
			Set("totalMemberCount", summary.Get("totalMemberCount"))
	}
	view := all[id].Spread()
	view.Set("path", departmentRefs(reversedDepartments(above)))
	view.Set("children", childViews)
	if head != nil {
		view.Set("head", head)
	}
	view.Set("teams", teams)
	return view, nil
}

// Place (api/departments.ts departmentMutations().place): Places a person in a department (moving them out of any
// other); false when they were already there with the same title. title "" is no title.
func (m *DepartmentMutationsResult) Place(ctx context.Context, tx core.IamStore, principal *Principal, department *core.Object, identity *core.Object, title string) (bool, error) {
	tenantID := jsString(department.Get("tenantId"))
	identityID := jsString(identity.Get("id"))
	existing, err := DepartmentMembership(ctx, tx, tenantID, identityID)
	if err != nil {
		return false, err
	}
	sameDepartment := existing != nil && existing.Get("departmentId") == department.Get("id")
	if sameDepartment {
		current := existing.Get("title")
		if (title == "" && isUndefined(current)) || (title != "" && current == title) {
			return false, nil
		}
	}
	var recordID any = ID()
	if existing != nil && !nullish(existing.Get("id")) {
		recordID = existing.Get("id")
	}
	record := core.NewObject(
		"id", recordID,
		"tenantId", department.Get("tenantId"),
		"uniqueKey", "identity:"+identityID,
		"departmentId", department.Get("id"),
		"identityId", identity.Get("id"),
	)
	if title != "" {
		record.Set("title", title)
	}
	if sameDepartment {
		record.Set("since", existing.Get("since"))
	} else {
		record.Set("since", float64(m.server.Now()))
	}
	record.Set("assignedBy", principal.Identity.Get("id"))
	if existing != nil {
		_, err = tx.Put(ctx, DepartmentCollections.Members, record)
	} else {
		_, err = tx.Insert(ctx, DepartmentCollections.Members, record)
	}
	if err != nil {
		return false, err
	}
	metadata := core.NewObject("identityId", identity.Get("id"))
	if existing != nil && !sameDepartment {
		metadata.Set("previousDepartmentId", existing.Get("departmentId"))
	}
	if title != "" {
		metadata.Set("title", title)
	}
	return true, m.audit(ctx, tx, principal, "department:assign", tenantID, jsString(department.Get("id")), metadata)
}

// CreateDepartment (api/departments.ts departmentMutations().createDepartment): Creates a department from a
// DepartmentInput ({ name, code?, description?, parentId?, headId?, costCenter? }); the caller has authorized
// `iam:departments:manage`.
func (m *DepartmentMutationsResult) CreateDepartment(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (*core.Object, error) {
	tenantID := jsString(tenant.Get("id"))
	departments, err := departmentsOf(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(departments.list) >= MaxDepartments {
		return nil, core.NewIamError("LIMIT_EXCEEDED", "At most 2000 departments", 409)
	}
	rawName, err := Text(input.Get("name"), "name", 100)
	if err != nil {
		return nil, err
	}
	name := core.JSTrim(rawName)
	code := ""
	if rawCode := input.Get("code"); !isUndefined(rawCode) && rawCode != "" {
		if code, err = DepartmentCode(rawCode); err != nil {
			return nil, err
		}
	}
	if err := m.assertUnique(ctx, tx, tenantID, name, code, ""); err != nil {
		return nil, err
	}
	parentID := ""
	if rawParent := input.Get("parentId"); !isUndefined(rawParent) {
		parent, err := LoadDepartment(ctx, tx, tenantID, rawParent)
		if err != nil {
			return nil, err
		}
		if err := m.depthCheck(departments, parent, 1); err != nil {
			return nil, err
		}
		parentID = jsString(parent.Get("id"))
	}
	headID := ""
	if rawHead := input.Get("headId"); !isUndefined(rawHead) {
		head, err := m.DepartmentPerson(ctx, tx, tenantID, rawHead)
		if err != nil {
			return nil, err
		}
		headID = jsString(head.Get("id"))
	}
	description, err := departmentOptionalText(input.Get("description"), "description", 512)
	if err != nil {
		return nil, err
	}
	costCenter, err := departmentOptionalText(input.Get("costCenter"), "costCenter", 64)
	if err != nil {
		return nil, err
	}
	now := float64(m.server.Now())
	department := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", "name:"+core.JSLower(name),
		"name", name,
	)
	if code != "" {
		department.Set("code", code)
	}
	if description != "" {
		department.Set("description", description)
	}
	if parentID != "" {
		department.Set("parentId", parentID)
	}
	if headID != "" {
		department.Set("headId", headID)
	}
	if costCenter != "" {
		department.Set("costCenter", costCenter)
	}
	department.Set("createdAt", now)
	department.Set("updatedAt", now)
	if _, err := tx.Insert(ctx, DepartmentCollections.Departments, department); err != nil {
		return nil, err
	}
	metadata := core.NewObject("name", name)
	if parentID != "" {
		metadata.Set("parentId", parentID)
	}
	if err := m.audit(ctx, tx, principal, "department:create", tenantID, jsString(department.Get("id")), metadata); err != nil {
		return nil, err
	}
	return department, nil
}

// departmentUpdateFields are the members a DepartmentUpdate may change, in the order the audit event lists them.
var departmentUpdateFields = []string{"name", "code", "description", "parentId", "headId", "costCenter"}

// UpdateDepartment (api/departments.ts departmentMutations().updateDepartment): Changes a department from a
// DepartmentUpdate ({ departmentId, name?, code?, description?, parentId?, headId?, costCenter? }; null or an empty
// string clears an optional member); the caller has authorized `iam:departments:manage` on it.
func (m *DepartmentMutationsResult) UpdateDepartment(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (*core.Object, error) {
	tenantID := jsString(tenant.Get("id"))
	department, err := LoadDepartment(ctx, tx, tenantID, input.Get("departmentId"))
	if err != nil {
		return nil, err
	}
	departmentID := jsString(department.Get("id"))
	fields := []any{}
	for _, key := range departmentUpdateFields {
		if !isUndefined(input.Get(key)) {
			fields = append(fields, key)
		}
	}
	if len(fields) == 0 {
		return nil, invalidInput("Nothing to update")
	}
	departments, err := departmentsOf(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	next := department.Spread(core.NewObject("updatedAt", float64(m.server.Now())))
	if rawName := input.Get("name"); !isUndefined(rawName) {
		text, err := Text(rawName, "name", 100)
		if err != nil {
			return nil, err
		}
		name := core.JSTrim(text)
		next.Set("name", name)
		next.Set("uniqueKey", "name:"+core.JSLower(name))
	}
	if rawCode := input.Get("code"); !isUndefined(rawCode) {
		next.Delete("code")
		if rawCode != nil && rawCode != "" {
			code, err := DepartmentCode(rawCode)
			if err != nil {
				return nil, err
			}
			next.Set("code", code)
		}
	}
	nextCode, _ := next.Get("code").(string)
	if err := m.assertUnique(ctx, tx, tenantID, jsString(next.Get("name")), nextCode, departmentID); err != nil {
		return nil, err
	}
	if rawDescription := input.Get("description"); !isUndefined(rawDescription) {
		next.Delete("description")
		description, err := departmentOptionalText(rawDescription, "description", 512)
		if err != nil {
			return nil, err
		}
		if description != "" {
			next.Set("description", description)
		}
	}
	if rawCostCenter := input.Get("costCenter"); !isUndefined(rawCostCenter) {
		next.Delete("costCenter")
		costCenter, err := departmentOptionalText(rawCostCenter, "costCenter", 64)
		if err != nil {
			return nil, err
		}
		if costCenter != "" {
			next.Set("costCenter", costCenter)
		}
	}
	if rawHead := input.Get("headId"); !isUndefined(rawHead) {
		next.Delete("headId")
		if rawHead != nil && rawHead != "" {
			head, err := m.DepartmentPerson(ctx, tx, tenantID, rawHead)
			if err != nil {
				return nil, err
			}
			next.Set("headId", head.Get("id"))
		}
	}
	if rawParent := input.Get("parentId"); !isUndefined(rawParent) {
		next.Delete("parentId")
		if rawParent != nil && rawParent != "" {
			parent, err := LoadDepartment(ctx, tx, tenantID, rawParent)
			if err != nil {
				return nil, err
			}
			below, err := DepartmentDescendants(departments.list, departmentID)
			if err != nil {
				return nil, err
			}
			parentID := jsString(parent.Get("id"))
			moving := parentID == departmentID
			for _, item := range below {
				if jsString(item.Get("id")) == parentID {
					moving = true
				}
			}
			if moving {
				return nil, invalidInput("A department cannot move under itself or a department below it")
			}
			height := 1.0
			for _, item := range below {
				chain, err := DepartmentChain(departments.byID, jsString(item.Get("id")))
				if err != nil {
					return nil, err
				}
				position := -1
				for index, step := range chain {
					if jsString(step.Get("id")) == departmentID {
						position = index
						break
					}
				}
				height = math.Max(height, float64(position+1))
			}
			if err := m.depthCheck(departments, parent, int(height)); err != nil {
				return nil, err
			}
			next.Set("parentId", parent.Get("id"))
		}
	}
	if _, err := tx.Put(ctx, DepartmentCollections.Departments, next); err != nil {
		return nil, err
	}
	if err := m.audit(ctx, tx, principal, "department:update", tenantID, departmentID, core.NewObject("fields", fields)); err != nil {
		return nil, err
	}
	return next, nil
}

// DeleteDepartment (api/departments.ts departmentMutations().deleteDepartment): Deletes a department ({
// departmentId }), unassigning its people and unfiling its teams; answers `{ unassigned, teams }`.
func (m *DepartmentMutationsResult) DeleteDepartment(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (*core.Object, error) {
	tenantID := jsString(tenant.Get("id"))
	department, err := LoadDepartment(ctx, tx, tenantID, input.Get("departmentId"))
	if err != nil {
		return nil, err
	}
	departmentID := jsString(department.Get("id"))
	departments, err := departmentsOf(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	if children := departments.childrenOf(department.Get("id")); len(children) > 0 {
		names := make([]string, len(children))
		for index, child := range children {
			names[index] = jsString(child.Get("name"))
		}
		return nil, core.NewIamError("RESOURCE_IN_USE", "Move or delete the departments below it first: "+strings.Join(names, ", "), 409)
	}
	// A department a birthright rule names stays until the package stops naming it (like groups).
	naming, err := PackagesNaming(ctx, tx, tenantID, "identity.departments", []string{departmentID}, nil)
	if err != nil {
		return nil, err
	}
	if len(naming) > 0 {
		return nil, core.NewIamError("RESOURCE_IN_USE", "Access packages name it in a rule: "+strings.Join(naming, ", "), 409)
	}
	unassigned := 0
	members, err := tx.Find(ctx, DepartmentCollections.Members, core.NewObject("tenantId", tenantID, "departmentId", department.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		if err := tx.Delete(ctx, DepartmentCollections.Members, jsString(member.Get("id"))); err != nil {
			return nil, err
		}
		unassigned++
	}
	teams := 0
	teamRecords, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	for _, team := range teamRecords {
		if team.Get("departmentId") != department.Get("id") {
			continue
		}
		rest := team.Spread()
		rest.Delete("departmentId")
		rest.Set("updatedAt", float64(m.server.Now()))
		if _, err := tx.Put(ctx, TeamCollections.Teams, rest); err != nil {
			return nil, err
		}
		teams++
	}
	if err := tx.Delete(ctx, DepartmentCollections.Departments, departmentID); err != nil {
		return nil, err
	}
	if err := m.audit(ctx, tx, principal, "department:delete", tenantID, departmentID, core.NewObject(
		"name", department.Get("name"),
		"unassigned", float64(unassigned),
		"teams", float64(teams),
	)); err != nil {
		return nil, err
	}
	return core.NewObject("unassigned", float64(unassigned), "teams", float64(teams)), nil
}

// DepartmentMutations (api/departments.ts departmentMutations): Transaction-level department changes for
// configuration sync (org-sync.ts): the same validation and audit events as the API. Callers authorize each change
// first.
func DepartmentMutations(server *ServerContext) (*DepartmentMutationsResult, error) {
	return &DepartmentMutationsResult{server: server}, nil
}
