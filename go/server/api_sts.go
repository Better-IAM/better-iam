package server

// Skeleton of packages/server/src/api/sts.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// StsAPI is the `sts` API group (packages/server/src/api/sts.ts createStsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/sts/{method} onto it.
type StsAPI struct {
	server *ServerContext
}

// CreateStsAPI builds the `sts` API group.
func CreateStsAPI(server *ServerContext) *StsAPI {
	return &StsAPI{server: server}
}

// AssumeRoleWithWebIdentity is POST {basePath}/sts/assumeRoleWithWebIdentity (public: no request credential). Exchanges a verified external OpenID Connect token, such as a GitHub Actions or Kubernetes token, for a role session under a web-identity trust.
//
// STUB: returns NOT_IMPLEMENTED until api/sts.ts is ported.
func (api *StsAPI) AssumeRoleWithWebIdentity(ctx context.Context, input In[apitypes.StsAssumeRoleWithWebIdentityInput]) (Out[apitypes.StsAssumeRoleWithWebIdentityOutput], error) {
	return Out[apitypes.StsAssumeRoleWithWebIdentityOutput]{}, notImplemented("sts.assumeRoleWithWebIdentity")
}

// GetCallerIdentity is POST {basePath}/sts/getCallerIdentity. Returns who the presented credential acts as: identity, tenant, session kind and id, format, MFA, expiry, and any role, trust, session name, tags, or web identity behind it.
//
// STUB: returns NOT_IMPLEMENTED until api/sts.ts is ported.
func (api *StsAPI) GetCallerIdentity(ctx context.Context, credential core.CredentialInput, input In[apitypes.StsGetCallerIdentityInput]) (Out[apitypes.StsGetCallerIdentityOutput], error) {
	return Out[apitypes.StsGetCallerIdentityOutput]{}, notImplemented("sts.getCallerIdentity")
}

// GetSessionToken is POST {basePath}/sts/getSessionToken. Mints a short-lived session token for your own identity from a signed-in session or an API key, optionally narrowed by a policy and attested with a fresh MFA code.
//
// STUB: returns NOT_IMPLEMENTED until api/sts.ts is ported.
func (api *StsAPI) GetSessionToken(ctx context.Context, credential core.CredentialInput, input In[apitypes.StsGetSessionTokenInput]) (Out[apitypes.StsGetSessionTokenOutput], error) {
	return Out[apitypes.StsGetSessionTokenOutput]{}, notImplemented("sts.getSessionToken")
}
