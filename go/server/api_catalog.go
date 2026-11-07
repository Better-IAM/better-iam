package server

// Port of packages/server/src/api/catalog.ts: the `actions` and `resourceTypes` API groups (tenant-defined actions
// and resource types, when permissions.mode is tenant-defined) and the helpers configuration sync shares.

import (
	"context"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ActionsAPI is the `actions` API group (packages/server/src/api/catalog.ts createActionsApi).
type ActionsAPI struct {
	server *ServerContext
}

// CreateActionsAPI builds the `actions` API group.
func CreateActionsAPI(server *ServerContext) *ActionsAPI {
	return &ActionsAPI{server: server}
}

// catalogTypeModel is a CatalogResourceType as the JSON model the TypeScript object serializes to.
func catalogTypeModel(definition *CatalogResourceType) any {
	model, err := ToModel(definition)
	if err != nil {
		return nil
	}
	if object, ok := model.(*core.Object); ok && definition.Attributes != nil {
		object.Set("attributes", definition.Attributes)
	}
	return model
}

// List is POST {basePath}/actions/list: the platform's actions, then the tenant's own.
func (api *ActionsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.ActionsListInput]) (Out[apitypes.ActionsListOutput], error) {
	catalog := api.server.Catalog
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:actions:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		result := []any{}
		for _, name := range catalog.Actions.Values() {
			summary := core.NewObject("name", name, "source", "platform")
			if resourceType, ok := catalog.ActionTypes[name]; ok {
				summary.Set("resourceType", resourceType)
			} else {
				summary.Set("resourceType", core.Undefined)
			}
			result = append(result, summary)
		}
		definitions, err := call.Tx.Find(ctx, "actions", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, definition := range definitions {
			result = append(result, core.NewObject("name", definition.Get("name"), "source", "tenant",
				"resourceType", definition.Get("resourceType"), "description", definition.Get("description")))
		}
		return result, nil
	}, false)
	return Out[apitypes.ActionsListOutput]{Value: result}, err
}

// Register is POST {basePath}/actions/register: a tenant-defined action, namespaced under a tenant-defined resource
// type (`{type}:{verb}`).
func (api *ActionsAPI) Register(ctx context.Context, credential core.CredentialInput, input In[apitypes.ActionsRegisterInput]) (Out[apitypes.ActionsRegisterOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:actions:create", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return api.server.Catalog.RegisterTenantAction(ctx, call.Tx, jsString(tenantID), input.Get("name"), input.Get("description"))
	}, false)
	return Out[apitypes.ActionsRegisterOutput]{Value: result}, err
}

// Unregister is POST {basePath}/actions/unregister: deletes a tenant-defined action no policy or role names.
func (api *ActionsAPI) Unregister(ctx context.Context, credential core.CredentialInput, input In[apitypes.ActionsUnregisterInput]) (Out[apitypes.ActionsUnregisterOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:actions:delete", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		name, err := Text(input.Get("name"), "action", 128)
		if err != nil {
			return nil, err
		}
		found, err := call.Tx.Find(ctx, "actions", core.NewObject("tenantId", tenantID, "uniqueKey", name), nil)
		if err != nil {
			return nil, err
		}
		if len(found) == 0 {
			return nil, core.NewIamError("NOT_FOUND", "Action not found", 404)
		}
		definition := found[0]
		if err := api.server.Catalog.AssertActionUnused(ctx, call.Tx, jsString(tenantID), jsString(definition.Get("name"))); err != nil {
			return nil, err
		}
		if err := call.Tx.Delete(ctx, "actions", jsString(definition.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.ActionsUnregisterOutput]{Value: result}, err
}

// ResourceTypesAPI is the `resourceTypes` API group (packages/server/src/api/catalog.ts createResourceTypesApi).
type ResourceTypesAPI struct {
	server *ServerContext
}

// CreateResourceTypesAPI builds the `resourceTypes` API group.
func CreateResourceTypesAPI(server *ServerContext) *ResourceTypesAPI {
	return &ResourceTypesAPI{server: server}
}

// Delete is POST {basePath}/resourceTypes/delete.
func (api *ResourceTypesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourceTypesDeleteInput]) (Out[apitypes.ResourceTypesDeleteOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:resource-types:delete", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		name, err := Text(input.Get("name"), "name", 64)
		if err != nil {
			return nil, err
		}
		record, err := api.server.Catalog.TenantResourceType(ctx, call.Tx, jsString(tenantID), name)
		if err != nil {
			return nil, err
		}
		if record == nil {
			return nil, core.NewIamError("NOT_FOUND", "Resource type not found", 404)
		}
		if err := DeleteResourceType(ctx, api.server, call.Tx, record); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.ResourceTypesDeleteOutput]{Value: result}, err
}

// Get is POST {basePath}/resourceTypes/get: a platform or tenant-defined resource type.
func (api *ResourceTypesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourceTypesGetInput]) (Out[apitypes.ResourceTypesGetOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:resource-types:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (any, error) {
		name, err := Text(input.Get("name"), "name", 64)
		if err != nil {
			return nil, err
		}
		definition, err := api.server.Catalog.ResourceTypeDefinition(ctx, call.Tx, jsString(tenantID), name)
		if err != nil {
			return nil, err
		}
		if definition == nil {
			return nil, core.NewIamError("NOT_FOUND", "Resource type not found", 404)
		}
		return catalogTypeModel(definition), nil
	}, false)
	return Out[apitypes.ResourceTypesGetOutput]{Value: result}, err
}

// List is POST {basePath}/resourceTypes/list: the platform's types, then the tenant's own.
func (api *ResourceTypesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourceTypesListInput]) (Out[apitypes.ResourceTypesListOutput], error) {
	catalog := api.server.Catalog
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:resource-types:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		result := []any{}
		for _, name := range catalog.ResourceTypeNames {
			result = append(result, catalogTypeModel(catalog.ResourceTypes[name]))
		}
		records, err := call.Tx.Find(ctx, "resourceTypes", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			definition, err := catalog.ResourceTypeDefinition(ctx, call.Tx, jsString(tenantID), jsString(record.Get("name")))
			if err != nil {
				return nil, err
			}
			result = append(result, catalogTypeModel(definition))
		}
		return result, nil
	}, false)
	return Out[apitypes.ResourceTypesListOutput]{Value: result}, err
}

// Register is POST {basePath}/resourceTypes/register: a tenant-defined resource type, managed by IAM, whose actions
// are `{name}:{verb}`.
func (api *ResourceTypesAPI) Register(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourceTypesRegisterInput]) (Out[apitypes.ResourceTypesRegisterOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:resource-types:create", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return RegisterResourceType(ctx, api.server, call.Tx, input.Body)
	}, false)
	return Out[apitypes.ResourceTypesRegisterOutput]{Value: result}, err
}

// Update is POST {basePath}/resourceTypes/update: changes description, attributes, or relations, and adds action
// verbs; existing verbs are kept.
func (api *ResourceTypesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.ResourceTypesUpdateInput]) (Out[apitypes.ResourceTypesUpdateOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:resource-types:update", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return UpdateResourceType(ctx, api.server, call.Tx, input.Body, false)
	}, false)
	return Out[apitypes.ResourceTypesUpdateOutput]{Value: result}, err
}

// DeleteResourceType (api/catalog.ts deleteResourceType) deletes a tenant-defined resource type once nothing
// registered, related, nested, or granted depends on it.
func DeleteResourceType(ctx context.Context, server *ServerContext, tx core.IamStore, record *core.Object) error {
	tenantID, name := record.Get("tenantId"), record.Get("name")
	for _, check := range []struct {
		collection string
		filter     *core.Object
		message    string
	}{
		{"resources", core.NewObject("tenantId", tenantID, "type", name), "Delete registered resources first"},
		{"relationships", core.NewObject("tenantId", tenantID, "type", name), "Delete relationships first"},
		{"resourceTypes", core.NewObject("tenantId", tenantID, "parent", name), "Other resource types use this type as their parent"},
	} {
		found, err := tx.Find(ctx, check.collection, check.filter, nil)
		if err != nil {
			return err
		}
		if len(found) > 0 {
			return core.NewIamError("RESOURCE_IN_USE", check.message, 409)
		}
	}
	actions, err := tx.Find(ctx, "actions", core.NewObject("tenantId", tenantID, "resourceType", name), nil)
	if err != nil {
		return err
	}
	for _, action := range actions {
		if err := server.Catalog.AssertActionUnused(ctx, tx, jsString(tenantID), jsString(action.Get("name"))); err != nil {
			return err
		}
		if err := tx.Delete(ctx, "actions", jsString(action.Get("id"))); err != nil {
			return err
		}
	}
	return tx.Delete(ctx, "resourceTypes", jsString(record.Get("id")))
}

// RegisterResourceType (api/catalog.ts registerResourceType) registers a tenant-defined resource type ({ tenantId,
// name, description?, actions?, attributes?, parent?, relations? }); shared by resourceTypes.register and
// configuration sync. It answers the CatalogResourceType.
func RegisterResourceType(ctx context.Context, server *ServerContext, tx core.IamStore, input *core.Object) (*core.Object, error) {
	catalog := server.Catalog
	if !server.Config.TenantDefined {
		return nil, core.NewIamError("CATALOG_LOCKED", "Tenant-defined resource types are disabled", 403)
	}
	name, err := Text(input.Get("name"), "name", 64)
	if err != nil {
		return nil, err
	}
	_, platform := catalog.ResourceTypes[name]
	if !ResourceTypeName.MatchString(name) || ReservedResourceTypes.Has(name) || platform || catalog.Namespaces.Has(name) {
		return nil, core.NewIamError("INVALID_RESOURCE_TYPE", "Resource type name is reserved or already defined by the platform")
	}
	tenantID := jsString(input.Get("tenantId"))
	existing, err := catalog.TenantResourceType(ctx, tx, tenantID, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, core.NewIamError("CONFLICT", "Resource type already exists", 409)
	}
	attributes, err := AttributeSchema(input.Get("attributes"), catalog.ReservedAttributes)
	if err != nil {
		return nil, err
	}
	record := core.NewObject("id", ID(), "tenantId", input.Get("tenantId"), "uniqueKey", name, "name", name,
		"attributes", attributes, "createdAt", float64(server.Wall()))
	if description := input.Get("description"); !isUndefined(description) {
		text, err := Text(description, "description", 512)
		if err != nil {
			return nil, err
		}
		record.Set("description", text)
	}
	if relations := input.Get("relations"); !isUndefined(relations) {
		names, err := RelationNames(relations)
		if err != nil {
			return nil, err
		}
		record.Set("relations", stringsOf(names))
	}
	if parentName := input.Get("parent"); !isUndefined(parentName) {
		text, err := Text(parentName, "parent", 64)
		if err != nil {
			return nil, err
		}
		parent, err := catalog.ResourceTypeDefinition(ctx, tx, tenantID, text)
		if err != nil {
			return nil, err
		}
		if parent == nil || parent.Name == name || !parent.Managed {
			return nil, core.NewIamError("INVALID_RESOURCE_TYPE", "Parent must be an existing managed resource type")
		}
		record.Set("parent", parent.Name)
	}
	if _, err := tx.Insert(ctx, "resourceTypes", record); err != nil {
		return nil, err
	}
	verbsValue := input.Get("actions")
	if isUndefined(verbsValue) {
		verbsValue = []any{}
	}
	verbs, err := Strings(verbsValue, "actions")
	if err != nil {
		return nil, err
	}
	registered := []any{}
	for _, verb := range verbs {
		action, err := catalog.RegisterTenantAction(ctx, tx, tenantID, name+":"+verb, core.Undefined)
		if err != nil {
			return nil, err
		}
		registered = append(registered, action.Get("name"))
	}
	relations := record.Get("relations")
	if isUndefined(relations) {
		relations = []any{}
	}
	return core.NewObject("name", name, "source", "tenant", "description", record.Get("description"), "actions", registered,
		"attributes", attributes, "parent", record.Get("parent"), "managed", true, "relations", relations), nil
}

// UpdateResourceType (api/catalog.ts updateResourceType) updates a tenant-defined resource type ({ tenantId, name,
// description?, attributes?, actions?, relations? }). `actions` adds verbs; with replaceActions (configuration sync)
// verbs no longer listed are removed too, provided no policy or role still names them.
func UpdateResourceType(ctx context.Context, server *ServerContext, tx core.IamStore, input *core.Object, replaceActions bool) (*core.Object, error) {
	catalog := server.Catalog
	tenantID := jsString(input.Get("tenantId"))
	name, err := Text(input.Get("name"), "name", 64)
	if err != nil {
		return nil, err
	}
	record, err := catalog.TenantResourceType(ctx, tx, tenantID, name)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, core.NewIamError("NOT_FOUND", "Resource type not found", 404)
	}
	typeName := jsString(record.Get("name"))
	next := record.Spread()
	if description := input.Get("description"); !isUndefined(description) {
		text, err := Text(description, "description", 512)
		if err != nil {
			return nil, err
		}
		next.Set("description", text)
	}
	if relations := input.Get("relations"); !isUndefined(relations) {
		names, err := RelationNames(relations)
		if err != nil {
			return nil, err
		}
		next.Set("relations", stringsOf(names))
		// A relation still held by someone cannot be removed from the type.
		held, err := tx.Find(ctx, "relationships", core.NewObject("tenantId", input.Get("tenantId"), "type", typeName), nil)
		if err != nil {
			return nil, err
		}
		for _, item := range held {
			if !containsString(names, jsString(item.Get("relation"))) {
				return nil, core.NewIamError("RESOURCE_IN_USE", "Remove relationships before dropping a relation", 409)
			}
		}
	}
	if attributes := input.Get("attributes"); !isUndefined(attributes) {
		schema, err := AttributeSchema(attributes, catalog.ReservedAttributes)
		if err != nil {
			return nil, err
		}
		next.Set("attributes", schema)
		// Registered resources must keep satisfying the schema, otherwise conditions would silently stop matching.
		resources, err := tx.Find(ctx, "resources", core.NewObject("tenantId", input.Get("tenantId"), "type", typeName), nil)
		if err != nil {
			return nil, err
		}
		for _, resource := range resources {
			if _, err := AttributeValues(schema, resource.Get("attributes")); err != nil {
				return nil, err
			}
		}
	}
	if _, err := tx.Put(ctx, "resourceTypes", next); err != nil {
		return nil, err
	}
	verbsValue := input.Get("actions")
	if isUndefined(verbsValue) {
		verbsValue = []any{}
	}
	verbs, err := Strings(verbsValue, "actions")
	if err != nil {
		return nil, err
	}
	for _, verb := range verbs {
		action := typeName + ":" + verb
		known, err := catalog.KnownAction(ctx, tx, tenantID, action)
		if err != nil {
			return nil, err
		}
		if !known {
			if _, err := catalog.RegisterTenantAction(ctx, tx, tenantID, action, core.Undefined); err != nil {
				return nil, err
			}
		}
	}
	if replaceActions && !isUndefined(input.Get("actions")) {
		actions, err := tx.Find(ctx, "actions", core.NewObject("tenantId", input.Get("tenantId"), "resourceType", typeName), nil)
		if err != nil {
			return nil, err
		}
		for _, action := range actions {
			actionName := jsString(action.Get("name"))
			if containsString(verbs, strings.TrimPrefix(actionName, typeName+":")) {
				continue
			}
			if err := catalog.AssertActionUnused(ctx, tx, tenantID, actionName); err != nil {
				return nil, err
			}
			if err := tx.Delete(ctx, "actions", jsString(action.Get("id"))); err != nil {
				return nil, err
			}
		}
	}
	definition, err := catalog.ResourceTypeDefinition(ctx, tx, tenantID, typeName)
	if err != nil {
		return nil, err
	}
	model, _ := catalogTypeModel(definition).(*core.Object)
	return model, nil
}
