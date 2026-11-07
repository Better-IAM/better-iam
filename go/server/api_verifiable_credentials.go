package server

// Skeleton of packages/server/src/api/verifiable-credentials.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// VerifiableCredentialsAPI is the `verifiableCredentials` API group (packages/server/src/api/verifiable-credentials.ts createVerifiableCredentialsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/verifiableCredentials/{method} onto it.
type VerifiableCredentialsAPI struct {
	server *ServerContext
}

// CreateVerifiableCredentialsAPI builds the `verifiableCredentials` API group.
func CreateVerifiableCredentialsAPI(server *ServerContext) *VerifiableCredentialsAPI {
	return &VerifiableCredentialsAPI{server: server}
}

// Available is POST {basePath}/verifiableCredentials/available. The enabled types the caller may request for themselves right now: vc:request allowed on credential-type/{name}, MFA when the type asks, and not in a "view as" session or a delegated agent session.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) Available(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsAvailableInput]) (Out[apitypes.VerifiableCredentialsAvailableOutput], error) {
	return Out[apitypes.VerifiableCredentialsAvailableOutput]{}, notImplemented("verifiableCredentials.available")
}

// CreateOffer is POST {basePath}/verifiableCredentials/createOffer. An OpenID4VCI credential offer with a pre-authorized code, and its openid-credential-offer:// link for a wallet to scan.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) CreateOffer(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsCreateOfferInput]) (Out[apitypes.VerifiableCredentialsCreateOfferOutput], error) {
	return Out[apitypes.VerifiableCredentialsCreateOfferOutput]{}, notImplemented("verifiableCredentials.createOffer")
}

// CreateType is POST {basePath}/verifiableCredentials/createType. Defines a credential type: a name, a displayName and description for wallets, card colors, a lifetime (default 30 days, at most the deployment's maxLifetimeMs), requireMfa, and 1 to 32 claims.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) CreateType(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsCreateTypeInput]) (Out[apitypes.VerifiableCredentialsCreateTypeOutput], error) {
	return Out[apitypes.VerifiableCredentialsCreateTypeOutput]{}, notImplemented("verifiableCredentials.createType")
}

// DeleteType is POST {basePath}/verifiableCredentials/deleteType. Deletes a type and its pending offers.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) DeleteType(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsDeleteTypeInput]) (Out[apitypes.VerifiableCredentialsDeleteTypeOutput], error) {
	return Out[apitypes.VerifiableCredentialsDeleteTypeOutput]{}, notImplemented("verifiableCredentials.deleteType")
}

// GetType is POST {basePath}/verifiableCredentials/getType. One credential type.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) GetType(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsGetTypeInput]) (Out[apitypes.VerifiableCredentialsGetTypeOutput], error) {
	return Out[apitypes.VerifiableCredentialsGetTypeOutput]{}, notImplemented("verifiableCredentials.getType")
}

// IssuerMetadata is POST {basePath}/verifiableCredentials/issuerMetadata (public: no request credential). The tenant's OpenID4VCI credential issuer metadata: endpoints, and every enabled type with its format (dc+sd-jwt), vct, binding methods, proof algorithms and wallet display.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) IssuerMetadata(ctx context.Context, input In[apitypes.VerifiableCredentialsIssuerMetadataInput]) (Out[apitypes.VerifiableCredentialsIssuerMetadataOutput], error) {
	return Out[apitypes.VerifiableCredentialsIssuerMetadataOutput]{}, notImplemented("verifiableCredentials.issuerMetadata")
}

// ListIssued is POST {basePath}/verifiableCredentials/listIssued. Issued credentials, newest first, by type, identityId or state (valid, suspended, revoked, expired), with limit (at most 500) and offset. Records hold claim names, never values.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) ListIssued(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsListIssuedInput]) (Out[apitypes.VerifiableCredentialsListIssuedOutput], error) {
	return Out[apitypes.VerifiableCredentialsListIssuedOutput]{}, notImplemented("verifiableCredentials.listIssued")
}

// ListKeys is POST {basePath}/verifiableCredentials/listKeys. The issuer's signing keys, oldest first: active, previous (still published, so its credentials verify) and retired.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) ListKeys(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsListKeysInput]) (Out[apitypes.VerifiableCredentialsListKeysOutput], error) {
	return Out[apitypes.VerifiableCredentialsListKeysOutput]{}, notImplemented("verifiableCredentials.listKeys")
}

// ListTypes is POST {basePath}/verifiableCredentials/listTypes. Every credential type of the tenant, by name.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) ListTypes(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsListTypesInput]) (Out[apitypes.VerifiableCredentialsListTypesOutput], error) {
	return Out[apitypes.VerifiableCredentialsListTypesOutput]{}, notImplemented("verifiableCredentials.listTypes")
}

// Mine is POST {basePath}/verifiableCredentials/mine. The caller's own credentials in the tenant, newest first (the last 100), with their state. Refused for delegated agent sessions (ACCESSDENIED).
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsMineInput]) (Out[apitypes.VerifiableCredentialsMineOutput], error) {
	return Out[apitypes.VerifiableCredentialsMineOutput]{}, notImplemented("verifiableCredentials.mine")
}

// Nonce is POST {basePath}/verifiableCredentials/nonce (public: no request credential). A single-use proof nonce (cnonce) for the tenant's issuer, valid five minutes. Nonces are signed rather than stored, so handing one out writes nothing; a proof spends its nonce. Public.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) Nonce(ctx context.Context, input In[apitypes.VerifiableCredentialsNonceInput]) (Out[apitypes.VerifiableCredentialsNonceOutput], error) {
	return Out[apitypes.VerifiableCredentialsNonceOutput]{}, notImplemented("verifiableCredentials.nonce")
}

// Reinstate is POST {basePath}/verifiableCredentials/reinstate. Lifts a suspension.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) Reinstate(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsReinstateInput]) (Out[apitypes.VerifiableCredentialsReinstateOutput], error) {
	return Out[apitypes.VerifiableCredentialsReinstateOutput]{}, notImplemented("verifiableCredentials.reinstate")
}

// Request is POST {basePath}/verifiableCredentials/request. Issues a credential of type to the caller, bound to the key in proof.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) Request(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsRequestInput]) (Out[apitypes.VerifiableCredentialsRequestOutput], error) {
	return Out[apitypes.VerifiableCredentialsRequestOutput]{}, notImplemented("verifiableCredentials.request")
}

// RetireKey is POST {basePath}/verifiableCredentials/retireKey. Stops publishing a previous key, after which credentials it signed no longer verify.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) RetireKey(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsRetireKeyInput]) (Out[apitypes.VerifiableCredentialsRetireKeyOutput], error) {
	return Out[apitypes.VerifiableCredentialsRetireKeyOutput]{}, notImplemented("verifiableCredentials.retireKey")
}

// Revoke is POST {basePath}/verifiableCredentials/revoke. Revokes a credential for good: its status list entry becomes invalid.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsRevokeInput]) (Out[apitypes.VerifiableCredentialsRevokeOutput], error) {
	return Out[apitypes.VerifiableCredentialsRevokeOutput]{}, notImplemented("verifiableCredentials.revoke")
}

// RotateKey is POST {basePath}/verifiableCredentials/rotateKey. Starts signing with a new ES256 key. The current one stays published as previous.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) RotateKey(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsRotateKeyInput]) (Out[apitypes.VerifiableCredentialsRotateKeyOutput], error) {
	return Out[apitypes.VerifiableCredentialsRotateKeyOutput]{}, notImplemented("verifiableCredentials.rotateKey")
}

// Status is POST {basePath}/verifiableCredentials/status. The issuer at a glance: its identifier and metadata URL, the published keys, the number of credential types, issued credentials by state (valid, suspended, revoked, expired), and status lists.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) Status(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsStatusInput]) (Out[apitypes.VerifiableCredentialsStatusOutput], error) {
	return Out[apitypes.VerifiableCredentialsStatusOutput]{}, notImplemented("verifiableCredentials.status")
}

// Suspend is POST {basePath}/verifiableCredentials/suspend. Suspends a valid credential (a lost phone). Verifiers see it as suspended until reinstate.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) Suspend(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsSuspendInput]) (Out[apitypes.VerifiableCredentialsSuspendOutput], error) {
	return Out[apitypes.VerifiableCredentialsSuspendOutput]{}, notImplemented("verifiableCredentials.suspend")
}

// UpdateType is POST {basePath}/verifiableCredentials/updateType. Changes a type's display, claims, lifetime, requireMfa or enabled. The name and vct never change.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) UpdateType(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsUpdateTypeInput]) (Out[apitypes.VerifiableCredentialsUpdateTypeOutput], error) {
	return Out[apitypes.VerifiableCredentialsUpdateTypeOutput]{}, notImplemented("verifiableCredentials.updateType")
}

// Verify is POST {basePath}/verifiableCredentials/verify (public: no request credential). Verifies a presentation of a credential this deployment issued.
//
// STUB: returns NOT_IMPLEMENTED until api/verifiable-credentials.ts is ported.
func (api *VerifiableCredentialsAPI) Verify(ctx context.Context, input In[apitypes.VerifiableCredentialsVerifyInput]) (Out[apitypes.VerifiableCredentialsVerifyOutput], error) {
	return Out[apitypes.VerifiableCredentialsVerifyOutput]{}, notImplemented("verifiableCredentials.verify")
}

// CreateVcProtocol (api/verifiable-credentials.ts createVcProtocol): The wallet-facing endpoints of every tenant's
// issuer, mounted beside the HTTP API (`{issuer}` is `{origin}{basePath}/vc/{tenantId}`):
// `/.well-known/openid-credential-issuer{path}`, `/.well-known/jwt-vc-issuer{path}` and
// `/.well-known/oauth-authorization-server{path}` metadata, `{issuer}/token` (pre-authorized code),
// `{issuer}/nonce`, `{issuer}/credential`, `{issuer}/jwks.json`, `{issuer}/types/{name}` and
// `{issuer}/status/{listId}` (Token Status List).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreateVcProtocol(server *ServerContext) (result ProtocolMount, err error) {
	err = notImplemented("api/verifiable-credentials.ts createVcProtocol")
	return
}

// VcRuntime is api/verifiable-credentials.ts createVcRuntime().
type VcRuntime struct {
	server *ServerContext
	// Enabled Whether the `verifiableCredentials` option is on.
	Enabled bool
}

// Verify (api/verifiable-credentials.ts createVcRuntime().verify): Verifies a presentation of a credential this
// deployment issued; throws `SdJwtError` with the reason.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *VcRuntime) Verify(ctx context.Context, presentation string, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/verifiable-credentials.ts createVcRuntime().verify")
	return
}

// Sweep (api/verifiable-credentials.ts createVcRuntime().sweep): Revokes credentials of people who are no longer
// active members (run hourly).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *VcRuntime) Sweep(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/verifiable-credentials.ts createVcRuntime().sweep")
	return
}

// Nonce (api/verifiable-credentials.ts createVcRuntime().nonce): A holder-proof nonce for a tenant, for applications
// embedding their own wallet flow.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *VcRuntime) Nonce(tenantID string) (result string, err error) {
	err = notImplemented("api/verifiable-credentials.ts createVcRuntime().nonce")
	return
}

// Issuer (api/verifiable-credentials.ts createVcRuntime().issuer): The tenant's issuer identifier.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *VcRuntime) Issuer(tenantID string) (result string, err error) {
	err = notImplemented("api/verifiable-credentials.ts createVcRuntime().issuer")
	return
}

// CreateVcRuntime builds the VcRuntime (api/verifiable-credentials.ts createVcRuntime). Its methods are stubs until the module is ported.
func CreateVcRuntime(server *ServerContext) *VcRuntime {
	return &VcRuntime{server: server}
}
