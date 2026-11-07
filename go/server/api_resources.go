package server

// Port of packages/server/src/api/resources.ts: the `resources` API group, registered managed resources whose
// ownership, attributes, and parent authorization resolves without an application callback.

import (
	"context"
	"regexp"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ResourcesAPI is the `resources` API group (packages/server/src/api/resources.ts createResourcesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/resources/{method} onto it.
type ResourcesAPI struct {
	server *ServerContext
}

// CreateResourcesAPI builds the `resources` API group.
func CreateResourcesAPI(server *ServerContext) *ResourcesAPI {
	return &ResourcesAPI{server: server}
}

// resourceKey is `${text(type, 'resource type', 64)}/${text(id, 'resource id', 128)}`.
func resourceKey(kind, id any) (string, error) {
	typeName, err := Text(kind, "resource type", 64)
	if err != nil {
		return "", err
	}
	resourceID, err := Text(id, "resource id", 128)
	if err != nil {
		return "", err
	}
	return typeName + "/" + resourceID, nil
}

func countResources(ctx context.Context, tx core.IamStore, tenantID any) (int, error) {
	records, err := tx.Find(ctx, "resources", core.NewObject("tenantId", tenantID), nil)
	return len(records), err
}

// resourcePatternCharacters is /[*?]/: resource patterns treat them as wildcards.
var resourcePatternCharacters = regexp.MustCompile(`[*?]`)

// applyResourceLinks sets the parent and owner links of a registration. input holds parentId and ownerId.
func (api *ResourcesAPI) applyResourceLinks(ctx context.Context, tx core.IamStore, record *core.Object, definition *CatalogResourceType, input *core.Object) error {
	tenantID := jsString(record.Get("tenantId"))
	parentID := input.Get("parentId")
	if definition.Parent != "" {
		if isUndefined(parentID) {
			return invalidInput("Resources of type " + definition.Name + " require a " + definition.Parent + " parent")
		}
		id, err := Text(parentID, "parentId", 128)
		if err != nil {
			return err
		}
		parent, err := ManagedResource(ctx, tx, tenantID, definition.Parent, id)
		if err != nil {
			return err
		}
		if parent == nil {
			return core.NewIamError("NOT_FOUND", "Parent resource is not registered", 404)
		}
		record.Set("parentType", definition.Parent)
		record.Set("parentId", parent.Get("resourceId"))
	} else if !isUndefined(parentID) {
		return invalidInput("This resource type has no parent")
	}
	if ownerID := input.Get("ownerId"); !isUndefined(ownerID) {
		if _, err := api.server.ActiveIdentity(ctx, tx, ownerID, tenantID); err != nil {
			return err
		}
		record.Set("ownerId", ownerID)
	}
	return nil
}

// registerResource registers one resource. input holds type, id (validated), attributes, parentId, and ownerId.
func (api *ResourcesAPI) registerResource(ctx context.Context, tx core.IamStore, tenantID string, input *core.Object) (*core.Object, error) {
	definition, err := api.server.Catalog.ManagedDefinition(ctx, tx, tenantID, input.Get("type"))
	if err != nil {
		return nil, err
	}
	id := jsString(input.Get("id"))
	// Resource patterns treat `*` and `?` as wildcards: an ID holding them would read as a pattern in `iam/{type}/{id}`.
	if resourcePatternCharacters.MatchString(id) {
		return nil, invalidInput("A resource ID cannot contain * or ?")
	}
	existing, err := ManagedResource(ctx, tx, tenantID, definition.Name, id)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, core.NewIamError("CONFLICT", "Resource is already registered", 409)
	}
	at := float64(api.server.Wall())
	attributes, err := AttributeValues(definition.Attributes, input.Get("attributes"))
	if err != nil {
		return nil, err
	}
	item := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", definition.Name+"/"+id,
		"type", definition.Name,
		"resourceId", id,
		"attributes", attributes,
		"createdAt", at,
		"updatedAt", at,
	)
	if err := api.applyResourceLinks(ctx, tx, item, definition, input); err != nil {
		return nil, err
	}
	return tx.Insert(ctx, "resources", item)
}

// Delete is POST {basePath}/resources/delete. Removes a registered resource, its relationship tuples, and keeps the
// security label it inherited.
func (api *ResourcesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesDeleteInput]) (Out[apitypes.ResourcesDeleteOutput], error) {
	server := api.server
	key, err := resourceKey(input.Get("type"), input.Get("id"))
	if err != nil {
		return Out[apitypes.ResourcesDeleteOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:resources:delete", key, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenant := jsString(tenantID)
		record, err := ManagedResource(ctx, tx, tenant, jsString(input.Get("type")), jsString(input.Get("id")))
		if err != nil {
			return nil, err
		}
		if record == nil {
			return nil, core.NewIamError("NOT_FOUND", "Resource is not registered", 404)
		}
		children, err := tx.Find(ctx, "resources", core.NewObject("tenantId", tenantID, "parentType", record.Get("type"), "parentId", record.Get("resourceId")), nil)
		if err != nil {
			return nil, err
		}
		if len(children) > 0 {
			return nil, core.NewIamError("RESOURCE_IN_USE", "Delete child resources first", 409)
		}
		tuples, err := tx.Find(ctx, "relationships", core.NewObject("tenantId", tenantID, "type", record.Get("type"), "resourceId", record.Get("resourceId")), nil)
		if err != nil {
			return nil, err
		}
		for _, tuple := range tuples {
			if err := tx.Delete(ctx, "relationships", jsString(tuple.Get("id"))); err != nil {
				return nil, err
			}
		}
		// Security clearances: what it inherits stays its label, so registering it again elsewhere cannot declassify.
		if err := KeepInheritedLabel(ctx, server, tx, call.Principal, record); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "resources", jsString(record.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.ResourcesDeleteOutput]{Value: result}, err
}

// Get is POST {basePath}/resources/get. Returns one registered resource.
func (api *ResourcesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesGetInput]) (Out[apitypes.ResourcesGetOutput], error) {
	key, err := resourceKey(input.Get("type"), input.Get("id"))
	if err != nil {
		return Out[apitypes.ResourcesGetOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:resources:read", key, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		record, err := ManagedResource(ctx, call.Tx, jsString(tenantID), jsString(input.Get("type")), jsString(input.Get("id")))
		if err != nil {
			return nil, err
		}
		if record == nil {
			return nil, core.NewIamError("NOT_FOUND", "Resource is not registered", 404)
		}
		return record, nil
	}, false)
	return Out[apitypes.ResourcesGetOutput]{Value: result}, err
}

// readersOf are the principals a listing must satisfy: the caller and, in a "view as" session, the actor behind it.
func readersOf(ctx context.Context, tx core.IamStore, principal *Principal) ([]*Principal, error) {
	readers := []*Principal{principal}
	actor, err := ImpersonatingActor(ctx, tx, principal)
	if err != nil {
		return nil, err
	}
	if actor != nil {
		readers = append(readers, actor)
	}
	return readers, nil
}

// prepareReaders prepares the decision of every reader on the tenant for one action.
func prepareReaders(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, action string) ([]*PreparedDecision, error) {
	readers, err := readersOf(ctx, tx, principal)
	if err != nil {
		return nil, err
	}
	prepared := make([]*PreparedDecision, len(readers))
	for index, who := range readers {
		if prepared[index], err = server.Decisions.PrepareDecision(ctx, tx, who, tenant, action); err != nil {
			return nil, err
		}
	}
	return prepared, nil
}

// everyAllows is whether every prepared decision allows the resource.
func everyAllows(prepared []*PreparedDecision, resource ResolvedResource) (bool, error) {
	for _, ready := range prepared {
		decision, err := DecideOn(ready, resource, "")
		if err != nil {
			return false, err
		}
		if !decision.Allowed {
			return false, nil
		}
	}
	return true, nil
}

// List is POST {basePath}/resources/list. Lists registered resources, ordered by type and ID, leaving out the ones
// the caller may not read.
func (api *ResourcesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesListInput]) (Out[apitypes.ResourcesListOutput], error) {
	server := api.server
	resourceID := "*"
	if kind := input.Get("type"); !isUndefined(kind) {
		typeName, err := Text(kind, "resource type", 64)
		if err != nil {
			return Out[apitypes.ResourcesListOutput]{}, err
		}
		resourceID = typeName + "/*"
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:resources:read", resourceID, func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		filter := core.NewObject("tenantId", tenantID)
		if kind := input.Get("type"); !isUndefined(kind) {
			filter.Set("type", kind)
		}
		if value := input.Get("parentId"); !isUndefined(value) {
			parentID, err := Text(value, "parentId", 128)
			if err != nil {
				return nil, err
			}
			filter.Set("parentId", parentID)
		}
		if value := input.Get("ownerId"); !isUndefined(value) {
			ownerID, err := Text(value, "ownerId")
			if err != nil {
				return nil, err
			}
			filter.Set("ownerId", ownerID)
		}
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000)
		if err != nil {
			return nil, err
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1000000)
		if err != nil {
			return nil, err
		}
		// Listing is reading each record: one a policy keeps from the caller (a Deny on iam/document/payroll, an
		// owner condition) is left out, as resources.get would refuse it. A "view as" session sees what both may.
		prepared, err := prepareReaders(ctx, server, tx, call.Principal, call.Tenant, "iam:resources:read")
		if err != nil {
			return nil, err
		}
		records, err := tx.Find(ctx, "resources", filter, nil)
		if err != nil {
			return nil, err
		}
		readable := make([]*core.Object, 0, len(records))
		for _, record := range records {
			allowed, err := everyAllows(prepared, ResolvedResource{
				TenantID:   jsString(record.Get("tenantId")),
				Type:       "iam",
				ID:         jsString(record.Get("type")) + "/" + jsString(record.Get("resourceId")),
				Attributes: ResolvedManaged(record).Attributes,
			})
			if err != nil {
				return nil, err
			}
			if allowed {
				readable = append(readable, record)
			}
		}
		// Order by type/id rather than by opaque record ID so pages are meaningful to callers.
		sort.SliceStable(readable, func(i, j int) bool {
			return compareUTF16(jsString(readable[i].Get("uniqueKey")), jsString(readable[j].Get("uniqueKey"))) < 0
		})
		start := min(int(offset), len(readable))
		end := min(start+int(limit), len(readable))
		return recordList(readable[start:end]), nil
	}, false)
	return Out[apitypes.ResourcesListOutput]{Value: result}, err
}

// Register is POST {basePath}/resources/register. Registers a managed resource so authorization can resolve its
// ownership, attributes, and parent without an application callback.
func (api *ResourcesAPI) Register(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesRegisterInput]) (Out[apitypes.ResourcesRegisterOutput], error) {
	server := api.server
	key, err := resourceKey(input.Get("type"), input.Get("id"))
	if err != nil {
		return Out[apitypes.ResourcesRegisterOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:resources:create", key, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, call.Tenant
		if err := server.EnforceLimit(ctx, tx, tenant, "resources", func(ctx context.Context) (int, error) {
			return countResources(ctx, tx, tenant.Get("id"))
		}); err != nil {
			return nil, err
		}
		return api.registerResource(ctx, tx, jsString(tenantID), input.Body)
	}, false)
	return Out[apitypes.ResourcesRegisterOutput]{Value: result}, err
}

type registerManyOutcome struct {
	denied     string
	registered []*core.Object
}

// RegisterMany is POST {basePath}/resources/registerMany. Registers up to 100 resources atomically. Each item is
// authorized as `iam:resources:create` on `iam/{type}/{id}`, so one denied item rejects the batch.
func (api *ResourcesAPI) RegisterMany(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesRegisterManyInput]) (Out[apitypes.ResourcesRegisterManyOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.ResourcesRegisterManyOutput]{}, err
	}
	resources, ok := input.Get("resources").([]any)
	if !ok || len(resources) == 0 || len(resources) > 100 {
		return Out[apitypes.ResourcesRegisterManyOutput]{}, invalidInput("Provide 1-100 resources")
	}
	items := make([]*core.Object, len(resources))
	for index, item := range resources {
		value, err := Object(item)
		if err != nil {
			return Out[apitypes.ResourcesRegisterManyOutput]{}, err
		}
		kind, err := Text(value.Get("type"), "resource type", 64)
		if err != nil {
			return Out[apitypes.ResourcesRegisterManyOutput]{}, err
		}
		id, err := Text(value.Get("id"), "resource id", 128)
		if err != nil {
			return Out[apitypes.ResourcesRegisterManyOutput]{}, err
		}
		items[index] = core.NewObject(
			"type", kind,
			"id", id,
			"attributes", value.Get("attributes"),
			"parentId", value.Get("parentId"),
			"ownerId", value.Get("ownerId"),
		)
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.ResourcesRegisterManyOutput]{}, err
	}
	outcome, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (registerManyOutcome, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return registerManyOutcome{}, err
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return registerManyOutcome{}, err
		}
		if err := server.EnforceLimit(ctx, tx, tenant, "resources", func(ctx context.Context) (int, error) {
			return countResources(ctx, tx, tenantID)
		}, len(items)); err != nil {
			return registerManyOutcome{}, err
		}
		// Authorize every item before writing anything, so a denial commits only its audit record.
		decisions := make([]core.Decision, 0, len(items))
		for _, item := range items {
			resourceID := jsString(item.Get("type")) + "/" + jsString(item.Get("id"))
			decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
				TenantID: tenantID, Action: "iam:resources:create", Resource: ResourceTarget{Type: "iam", ID: resourceID},
			}, true)
			if err != nil {
				return registerManyOutcome{}, err
			}
			if !decision.Allowed {
				if err := server.Events.Audit(ctx, tx, principal, "iam:resources:create", tenantID, resourceID, "deny", false, nil); err != nil {
					return registerManyOutcome{}, err
				}
				return registerManyOutcome{denied: resourceID}, nil
			}
			decisions = append(decisions, decision)
		}
		registered := make([]*core.Object, 0, len(items))
		for index, item := range items {
			record, err := api.registerResource(ctx, tx, tenantID, item)
			if err != nil {
				return registerManyOutcome{}, err
			}
			registered = append(registered, record)
			resourceID := jsString(item.Get("type")) + "/" + jsString(item.Get("id"))
			if err := server.Events.Audit(ctx, tx, principal, "iam:resources:create", tenantID, resourceID, "allow", decisions[index].Reason == "ROOT_OVERRIDE", nil); err != nil {
				return registerManyOutcome{}, err
			}
		}
		return registerManyOutcome{registered: registered}, nil
	})
	if err != nil {
		return Out[apitypes.ResourcesRegisterManyOutput]{}, err
	}
	if outcome.denied != "" {
		return Out[apitypes.ResourcesRegisterManyOutput]{}, core.NewIamError("ACCESS_DENIED", "Access denied for "+outcome.denied, 403)
	}
	return Out[apitypes.ResourcesRegisterManyOutput]{Value: core.NewObject("resources", recordList(outcome.registered))}, nil
}

// Update is POST {basePath}/resources/update. Replaces a registered resource's attributes or changes its owner
// (`ownerId: null` clears it).
func (api *ResourcesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourcesUpdateInput]) (Out[apitypes.ResourcesUpdateOutput], error) {
	server := api.server
	key, err := resourceKey(input.Get("type"), input.Get("id"))
	if err != nil {
		return Out[apitypes.ResourcesUpdateOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:resources:update", key, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenant := jsString(tenantID)
		definition, err := server.Catalog.ManagedDefinition(ctx, tx, tenant, input.Get("type"))
		if err != nil {
			return nil, err
		}
		record, err := ManagedResource(ctx, tx, tenant, definition.Name, jsString(input.Get("id")))
		if err != nil {
			return nil, err
		}
		if record == nil {
			return nil, core.NewIamError("NOT_FOUND", "Resource is not registered", 404)
		}
		next := record.Spread(core.NewObject("updatedAt", float64(server.Wall())))
		if value := input.Get("attributes"); !isUndefined(value) {
			attributes, err := AttributeValues(definition.Attributes, value)
			if err != nil {
				return nil, err
			}
			next.Set("attributes", attributes)
		}
		if ownerID := input.Get("ownerId"); ownerID == nil {
			next.Delete("ownerId")
		} else if !isUndefined(ownerID) {
			if _, err := server.Scoped(ctx, tx, "identities", ownerID, tenant); err != nil {
				return nil, err
			}
			next.Set("ownerId", ownerID)
		}
		return tx.Put(ctx, "resources", next)
	}, false)
	return Out[apitypes.ResourcesUpdateOutput]{Value: result}, err
}
