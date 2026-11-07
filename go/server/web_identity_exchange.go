package server

// Skeleton of packages/server/src/web-identity-exchange.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// WebIdentityStsAPI is web-identity-exchange.ts createWebIdentityStsApi().
type WebIdentityStsAPI struct {
	server *ServerContext
}

// AssumeRoleWithWebIdentity (web-identity-exchange.ts createWebIdentityStsApi().assumeRoleWithWebIdentity):
// AssumeRoleWithWebIdentity (public; no IAM credential): exchanges a verified external OIDC token for a role session
// of kind 'role' under a web-identity trust, acting as the trust's service account and bounded by the role, the
// trust's ceiling, and the authorities of the trust's and the provider's creators. The token must be signed by the
// provider's keys with an allowed algorithm, name the provider's issuer and one of its audiences, be fresh, satisfy
// the trust's claim conditions and (by default) not have been redeemed before at this provider. Every refusal that
// depends on stored state or on the token is WEB_IDENTITY_REJECTED (403) with the same body. The attempt counts
// against `sts.webIdentity.maxExchangesPerWindow` for the trust before anything is looked up. The credential is
// returned once, in the body; this route never sets a cookie. Audited as `role:assumed-with-web-identity` (allow, or
// deny with a reason once the trust resolved).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *WebIdentityStsAPI) AssumeRoleWithWebIdentity(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("web-identity-exchange.ts createWebIdentityStsApi().assumeRoleWithWebIdentity")
	return
}

// CreateWebIdentityStsAPI builds the WebIdentityStsAPI (web-identity-exchange.ts createWebIdentityStsApi). Its methods are stubs until the module is ported.
func CreateWebIdentityStsAPI(server *ServerContext) *WebIdentityStsAPI {
	return &WebIdentityStsAPI{server: server}
}

// EvaluateWebIdentity (web-identity-exchange.ts evaluateWebIdentity): The dry run behind
// `trust.evaluateWebIdentity`: verification, trust conditions and claim mappings for a token, with no replay record
// and no issuance. The caller has authorized the read and loaded the trust and its provider. Stored state that would
// refuse the exchange is reported too, in the exchange's order: a revoked trust or a disabled provider comes before
// the token's own problems, and the role, service account and authorities after them.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EvaluateWebIdentity(ctx context.Context, server *ServerContext, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("web-identity-exchange.ts evaluateWebIdentity")
	return
}
