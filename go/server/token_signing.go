package server

// Skeleton of packages/server/src/token-signing.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// CreateSessionTokenSigner (token-signing.ts createSessionTokenSigner): the deployment's session token signer, or nil
// when sts.jwt is not configured. Every option is validated synchronously (INVALID_CONFIG).
//
// STUB: returns NOT_IMPLEMENTED when sts.jwt is configured, until the module is ported.
func CreateSessionTokenSigner(options *SessionTokenSigningOptions, issuer string, now func() int64) (result *SessionTokenSigner, err error) {
	if options == nil {
		return nil, nil
	}
	err = notImplemented("token-signing.ts createSessionTokenSigner")
	return
}

// SessionTokenSigner is token-signing.ts SessionTokenSigner.
type SessionTokenSigner struct {
	server *ServerContext
	// Issuer The `iss` of every token.
	Issuer string
	// Audiences The audiences tokens may be issued for; always includes the issuer (first).
	Audiences []string
	// MaxLifetimeSeconds Longest allowed `exp - iat`, in seconds.
	MaxLifetimeSeconds float64
}

// Sign (token-signing.ts SessionTokenSigner.sign): Signs the claims with the active key; the header is `{ alg, kid,
// typ: 'biam-session+jwt' }`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SessionTokenSigner) Sign(ctx context.Context, claims *core.Object) (result string, err error) {
	err = notImplemented("token-signing.ts SessionTokenSigner.sign")
	return
}

// Verify (token-signing.ts SessionTokenSigner.verify): Verifies a token for `audience` (default: the issuer) with a
// 5 second clock tolerance.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SessionTokenSigner) Verify(ctx context.Context, token string, audience string) (result *core.Object, err error) {
	err = notImplemented("token-signing.ts SessionTokenSigner.verify")
	return
}

// PublicJwks (token-signing.ts SessionTokenSigner.publicJwks): The public members of the signing and verification
// keys, for the JWKS route.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SessionTokenSigner) PublicJwks() (result *core.Object, err error) {
	err = notImplemented("token-signing.ts SessionTokenSigner.publicJwks")
	return
}
