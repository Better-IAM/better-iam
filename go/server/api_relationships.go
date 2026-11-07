package server

// Port of packages/server/src/api/relationships.ts: relationship tuples, "this identity or group is a {relation} of
// {type}/{id}". Policies read the relations a principal holds on the evaluated resource as `resource.relations` (and
// on its parent as `resource.parentRelations`), so a role such as `{ ArrayContains: { 'resource.relations':
// ['editor'] } }` expresses sharing without listing IDs.

import (
	"context"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// relationshipSubjectTypes are the subjects a relation may be granted to.
func relationshipSubjectType(value any) bool {
	return value == "identity" || value == "group"
}

// RelationshipsAPI is the `relationships` API group (packages/server/src/api/relationships.ts createRelationshipsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/relationships/{method} onto it.
type RelationshipsAPI struct {
	server *ServerContext
}

// CreateRelationshipsAPI builds the `relationships` API group.
func CreateRelationshipsAPI(server *ServerContext) *RelationshipsAPI {
	return &RelationshipsAPI{server: server}
}

// live is whether a tuple has not expired.
func (api *RelationshipsAPI) live(tuple *core.Object) bool {
	expiresAt := tuple.Get("expiresAt")
	return isUndefined(expiresAt) || jsNumber(expiresAt) > float64(api.server.Now())
}

// Create is POST {basePath}/relationships/create. Grants a declared relation on one resource to an identity or
// group. Requires iam:relationships:create on `iam/{type}/{id}`.
func (api *RelationshipsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.RelationshipsCreateInput]) (Out[apitypes.RelationshipsCreateOutput], error) {
	server := api.server
	key, err := resourceKey(input.Get("type"), input.Get("id"))
	if err != nil {
		return Out[apitypes.RelationshipsCreateOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:relationships:create", key, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenant := jsString(tenantID)
		resourceID := jsString(input.Get("id"))
		definition, err := server.Catalog.ResourceTypeDefinition(ctx, tx, tenant, jsString(input.Get("type")))
		if err != nil {
			return nil, err
		}
		if definition == nil {
			return nil, core.NewIamError("INVALID_RESOURCE_TYPE", "Unknown resource type")
		}
		relation, err := Text(input.Get("relation"), "relation", 64)
		if err != nil {
			return nil, err
		}
		if !containsString(definition.Relations, relation) {
			return nil, invalidInput("Relation " + relation + " is not declared for " + definition.Name)
		}
		if definition.Managed {
			registered, err := ManagedResource(ctx, tx, tenant, definition.Name, resourceID)
			if err != nil {
				return nil, err
			}
			if registered == nil {
				return nil, core.NewIamError("NOT_FOUND", "Resource is not registered", 404)
			}
		}
		subjectType, subjectID := input.Get("subjectType"), input.Get("subjectId")
		if !relationshipSubjectType(subjectType) {
			return nil, invalidInput("Invalid subject type")
		}
		if subjectType == "identity" {
			if _, err := server.ActiveIdentity(ctx, tx, subjectID, tenant); err != nil {
				return nil, err
			}
		} else if _, err := server.Scoped(ctx, tx, "groups", subjectID, tenant); err != nil {
			return nil, err
		}
		uniqueKey := definition.Name + "/" + resourceID + "#" + relation + "@" + jsString(subjectType) + ":" + jsString(subjectID)
		found, err := tx.Find(ctx, "relationships", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
		if err != nil {
			return nil, err
		}
		var existing *core.Object
		if len(found) > 0 {
			existing = found[0]
		}
		var id, createdAt any = ID(), float64(server.Now())
		if existing != nil {
			id = coalesce(existing.Get("id"), id)
			createdAt = coalesce(existing.Get("createdAt"), createdAt)
		}
		tuple := core.NewObject(
			"id", id,
			"tenantId", tenantID,
			"uniqueKey", uniqueKey,
			"type", definition.Name,
			"resourceId", resourceID,
			"relation", relation,
			"subjectType", subjectType,
			"subjectId", subjectID,
			"createdAt", createdAt,
			"createdBy", call.Principal.Identity.Get("id"),
		)
		if value := input.Get("expiresAt"); !isUndefined(value) {
			expiresAt, err := server.BindingExpiry(value)
			if err != nil {
				return nil, err
			}
			tuple.Set("expiresAt", expiresAt)
		}
		if existing != nil {
			return tx.Put(ctx, "relationships", tuple)
		}
		return tx.Insert(ctx, "relationships", tuple)
	}, false)
	return Out[apitypes.RelationshipsCreateOutput]{Value: result}, err
}

// Delete is POST {basePath}/relationships/delete. Removes one tuple. Requires iam:relationships:delete on the
// tuple's resource.
func (api *RelationshipsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.RelationshipsDeleteInput]) (Out[apitypes.RelationshipsDeleteOutput], error) {
	server := api.server
	tenant, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.RelationshipsDeleteOutput]{}, err
	}
	relationshipID := input.Get("relationshipId")
	existing, err := server.Scoped(ctx, server.Store, "relationships", relationshipID, tenant)
	if err != nil {
		return Out[apitypes.RelationshipsDeleteOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:relationships:delete", jsString(existing.Get("type"))+"/"+jsString(existing.Get("resourceId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if _, err := server.Scoped(ctx, tx, "relationships", relationshipID, jsString(tenantID)); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "relationships", jsString(relationshipID)); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.RelationshipsDeleteOutput]{Value: result}, err
}

// List is POST {basePath}/relationships/list. Relationships of a resource, of a subject, or of the whole tenant;
// expired tuples are omitted unless requested.
func (api *RelationshipsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.RelationshipsListInput]) (Out[apitypes.RelationshipsListOutput], error) {
	server := api.server
	kind, id := input.Get("type"), input.Get("id")
	resource := "*"
	if !isUndefined(kind) && !isUndefined(id) {
		key, err := resourceKey(kind, id)
		if err != nil {
			return Out[apitypes.RelationshipsListOutput]{}, err
		}
		resource = key
	} else if !isUndefined(kind) {
		typeName, err := Text(kind, "resource type", 64)
		if err != nil {
			return Out[apitypes.RelationshipsListOutput]{}, err
		}
		resource = typeName + "/*"
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:relationships:read", resource, func(ctx context.Context, call MutationContext) ([]any, error) {
		tx, tenant := call.Tx, call.Tenant
		realmID := jsString(tenant.Get("id"))
		// Listing is reading each resource's tuples: one a policy keeps from the caller (a Deny on
		// iam/document/payroll, an owner condition) is left out. A "view as" session sees what both may.
		prepared, err := prepareReaders(ctx, server, tx, call.Principal, tenant, "iam:relationships:read")
		if err != nil {
			return nil, err
		}
		verdicts := map[string]bool{}
		readable := func(tuple *core.Object) (bool, error) {
			key := jsString(tuple.Get("type")) + "/" + jsString(tuple.Get("resourceId"))
			if verdict, ok := verdicts[key]; ok {
				return verdict, nil
			}
			record, err := ManagedResource(ctx, tx, realmID, jsString(tuple.Get("type")), jsString(tuple.Get("resourceId")))
			if err != nil {
				return false, err
			}
			target := ResolvedResource{TenantID: realmID, Type: "iam", ID: key}
			if record != nil {
				target.Attributes = ResolvedManaged(record).Attributes
			}
			verdict, err := everyAllows(prepared, target)
			if err != nil {
				return false, err
			}
			verdicts[key] = verdict
			return verdict, nil
		}
		filter := core.NewObject("tenantId", tenantID)
		if !isUndefined(kind) {
			filter.Set("type", kind)
		}
		if !isUndefined(id) {
			resourceID, err := Text(id, "resource id", 128)
			if err != nil {
				return nil, err
			}
			filter.Set("resourceId", resourceID)
		}
		if value := input.Get("relation"); !isUndefined(value) {
			relation, err := Text(value, "relation", 64)
			if err != nil {
				return nil, err
			}
			filter.Set("relation", relation)
		}
		if subjectType := input.Get("subjectType"); !isUndefined(subjectType) {
			if !relationshipSubjectType(subjectType) {
				return nil, invalidInput("Invalid subject type")
			}
			filter.Set("subjectType", subjectType)
		}
		if value := input.Get("subjectId"); !isUndefined(value) {
			subjectID, err := Text(value, "subjectId")
			if err != nil {
				return nil, err
			}
			filter.Set("subjectId", subjectID)
		}
		stored, err := tx.Find(ctx, "relationships", filter, nil)
		if err != nil {
			return nil, err
		}
		includeExpired := input.Get("includeExpired") == true
		tuples := []*core.Object{}
		for _, tuple := range stored {
			if !includeExpired && !api.live(tuple) {
				continue
			}
			allowed, err := readable(tuple)
			if err != nil {
				return nil, err
			}
			if allowed {
				tuples = append(tuples, tuple)
			}
		}
		sort.SliceStable(tuples, func(i, j int) bool { return ByNewest(tuples[i], tuples[j]) < 0 })
		return recordList(tuples), nil
	}, false)
	return Out[apitypes.RelationshipsListOutput]{Value: result}, err
}
