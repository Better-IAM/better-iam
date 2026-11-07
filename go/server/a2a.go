package server

// Skeleton of packages/server/src/a2a.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"
	"net/http"

	"github.com/Better-IAM/better-iam/go/core"
)

// CardSigner (a2a.ts cardSigner): The deployment's card signer, validated once per context; undefined without the
// `a2a` option.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CardSigner(server *ServerContext) (result *CardSignerType, err error) {
	err = notImplemented("a2a.ts cardSigner")
	return
}

// A2aRuntime is a2a.ts A2aRuntime.
type A2aRuntime struct {
	server *ServerContext
	// Enabled Whether cards can be signed (the `a2a` option is set).
	Enabled bool
}

// Jwks (a2a.ts A2aRuntime.jwks): The public card keys (signing and retired), for verifiers. Empty without the `a2a`
// option.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *A2aRuntime) Jwks() (result *core.Object, err error) {
	err = notImplemented("a2a.ts A2aRuntime.jwks")
	return
}

// JwksResponse (a2a.ts A2aRuntime.jwksResponse): A GET response publishing `jwks()`, cacheable for five minutes:
// serve it at `a2a.jwksUrl`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *A2aRuntime) JwksResponse() (result *http.Response, err error) {
	err = notImplemented("a2a.ts A2aRuntime.jwksResponse")
	return
}

// VerifyDelegationToken (a2a.ts A2aRuntime.verifyDelegationToken): Verifies a delegation token
// (`delegations.issueToken`) this deployment issued, for a service running next to it: the signature with the
// deployment's keys, the type, the issuer, `audience`, `tenantId` when given, and the times. With `live`, also that
// everything it stands on is still in place (the delegation chain, the person, the agents and the agent's key, the
// audience and the scopes), so a revocation takes effect before the token expires. Throws DELEGATION_TOKEN_INVALID
// (401).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *A2aRuntime) VerifyDelegationToken(ctx context.Context, token string, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("a2a.ts A2aRuntime.verifyDelegationToken")
	return
}

// CreateA2aRuntime builds the A2aRuntime (a2a.ts createA2aRuntime). Its methods are stubs until the module is ported.
func CreateA2aRuntime(server *ServerContext) *A2aRuntime {
	return &A2aRuntime{server: server}
}

// SignAgentCard (a2a.ts signAgentCard): Signs `input` for `agent`: an A2A agent card whose `url` (and every
// `additionalInterfaces[].url`) is on the origin of the agent's registered `url`. The caller has already been
// authorized; the agent must be in good standing.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SignAgentCard(ctx context.Context, server *ServerContext, tenant *core.Object, agent *core.Object, input any) (result *core.Object, err error) {
	err = notImplemented("a2a.ts signAgentCard")
	return
}

// CardSignerType is a2a.ts CardSigner.
type CardSignerType struct {
	server          *ServerContext
	Issuer          string
	JwksURL         string
	LifetimeSeconds float64
	Jwks            *core.Object
}

// Sign (a2a.ts CardSigner.sign): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *CardSignerType) Sign(ctx context.Context, payload []byte) (result *core.Object, err error) {
	err = notImplemented("a2a.ts CardSigner.sign")
	return
}

// SignJwt (a2a.ts CardSigner.signJwt): Signs `claims` as a compact JWT with the active key and an explicit `typ`
// (never `JOSE`, the card type).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *CardSignerType) SignJwt(ctx context.Context, claims *core.Object, typ string) (result string, err error) {
	err = notImplemented("a2a.ts CardSigner.signJwt")
	return
}

// VerifyJwt (a2a.ts CardSigner.verifyJwt): Verifies a compact JWT of type `typ` with the published keys; the
// payload, or undefined when it does not verify.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *CardSignerType) VerifyJwt(ctx context.Context, token string, typ string) (result *core.Object, err error) {
	err = notImplemented("a2a.ts CardSigner.verifyJwt")
	return
}
