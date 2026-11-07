package server

// Skeleton of packages/server/src/federation.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// Federation is federation.ts createFederation().
type Federation struct {
	server       *ServerContext
	ProtocolHost any
}

// CompleteAuthentication (federation.ts createFederation().completeAuthentication): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *Federation) CompleteAuthentication(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("federation.ts createFederation().completeAuthentication")
	return
}

// SyncRoleMappings (federation.ts createFederation().syncRoleMappings): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *Federation) SyncRoleMappings(ctx context.Context, tx core.IamStore, input *core.Object) (err error) {
	err = notImplemented("federation.ts createFederation().syncRoleMappings")
	return
}

// CreateFederation builds the Federation (federation.ts createFederation). Its methods are stubs until the module is ported.
func CreateFederation(server *ServerContext, bindings *BindingsAPI) *Federation {
	return &Federation{server: server}
}
