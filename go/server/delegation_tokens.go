package server

// Skeleton of packages/server/src/delegation-tokens.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// AudienceRefusal (delegation-tokens.ts audienceRefusal): The first agent of the chain that may not present
// delegations to `audience`, if any.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AudienceRefusal(agents []*core.Object, audience string) (result *core.Object, err error) {
	err = notImplemented("delegation-tokens.ts audienceRefusal")
	return
}

// ScopeRefusal (delegation-tokens.ts scopeRefusal): The first scope the chain may not carry, or undefined when it
// may carry them all. Every scope must be allowed outright by every limit a decision for the acting session applies
// (the delegations and their ceilings, the agents' boundaries, the session's policies, the key issuers' authority,
// the tenant's and the person's boundaries, and the tenant's guest boundary for a guest). None may be one the person
// confirms call by call (`confirm`, anywhere in the chain), nor one a deny statement among the person's own grants
// could touch: a token carries no resource or condition to refine them with.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ScopeRefusal(ctx context.Context, server *ServerContext, tx core.IamStore, basis *core.Object, scopes []string) (result *core.Object, err error) {
	err = notImplemented("delegation-tokens.ts scopeRefusal")
	return
}

// TokenStillStands (delegation-tokens.ts tokenStillStands): Re-checks an issued token's record against the current
// state: the delegation and those above it live, the person active, every agent in good standing and still allowed
// the audience, the acting key live, and the scopes still allowed. False when anything the token stands on has
// changed.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TokenStillStands(ctx context.Context, server *ServerContext, tx core.IamStore, record *core.Object, now int64) (result bool, err error) {
	err = notImplemented("delegation-tokens.ts tokenStillStands")
	return
}
