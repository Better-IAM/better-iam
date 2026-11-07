package server

// Skeleton of packages/server/src/api/relationships.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// RelationshipsAPI is the `relationships` API group (packages/server/src/api/relationships.ts createRelationshipsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/relationships/{method} onto it.
type RelationshipsAPI struct {
	server *ServerContext
}

// CreateRelationshipsAPI builds the `relationships` API group.
func CreateRelationshipsAPI(server *ServerContext) *RelationshipsAPI {
	return &RelationshipsAPI{server: server}
}

// Create is POST {basePath}/relationships/create. Gives an identity or group a declared relation on one resource, optionally until a given time.
//
// STUB: returns NOT_IMPLEMENTED until api/relationships.ts is ported.
func (api *RelationshipsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.RelationshipsCreateInput]) (Out[apitypes.RelationshipsCreateOutput], error) {
	return Out[apitypes.RelationshipsCreateOutput]{}, notImplemented("relationships.create")
}

// Delete is POST {basePath}/relationships/delete. Removes one relationship tuple, ending the access it gave.
//
// STUB: returns NOT_IMPLEMENTED until api/relationships.ts is ported.
func (api *RelationshipsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.RelationshipsDeleteInput]) (Out[apitypes.RelationshipsDeleteOutput], error) {
	return Out[apitypes.RelationshipsDeleteOutput]{}, notImplemented("relationships.delete")
}

// List is POST {basePath}/relationships/list. Lists relationship tuples of one resource, one subject, one type, or the whole tenant, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/relationships.ts is ported.
func (api *RelationshipsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.RelationshipsListInput]) (Out[apitypes.RelationshipsListOutput], error) {
	return Out[apitypes.RelationshipsListOutput]{}, notImplemented("relationships.list")
}
