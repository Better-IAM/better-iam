package server

// Skeleton of packages/server/src/api/pki.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"
	"net/http"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// PkiAPI is the `pki` API group (packages/server/src/api/pki.ts createPkiApi): every method runs through the
// operation envelope; the router maps POST {basePath}/pki/{method} onto it.
type PkiAPI struct {
	server *ServerContext
}

// CreatePkiAPI builds the `pki` API group.
func CreatePkiAPI(server *ServerContext) *PkiAPI {
	return &PkiAPI{server: server}
}

// Bundle is POST {basePath}/pki/bundle. The tenant's active root certificates as one PEM bundle: what relying parties trust. Intermediates travel in each server's chain.
//
// STUB: returns NOT_IMPLEMENTED until api/pki.ts is ported.
func (api *PkiAPI) Bundle(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiBundleInput]) (Out[apitypes.PkiBundleOutput], error) {
	return Out[apitypes.PkiBundleOutput]{}, notImplemented("pki.bundle")
}

// CreateAuthority is POST {basePath}/pki/createAuthority. Creates a root (self-signed) or an intermediate authority (signed by parentId in the same tenant), with a new KMS signing key (keySpec, default ecc-p256) or an existing one (keyId) whose current vers…
//
// STUB: returns NOT_IMPLEMENTED until api/pki.ts is ported.
func (api *PkiAPI) CreateAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiCreateAuthorityInput]) (Out[apitypes.PkiCreateAuthorityOutput], error) {
	return Out[apitypes.PkiCreateAuthorityOutput]{}, notImplemented("pki.createAuthority")
}

// Crl is POST {basePath}/pki/crl. The authority's current certificate revocation list as PEM, rebuilt after revocations and at least every 12 hours.
//
// STUB: returns NOT_IMPLEMENTED until api/pki.ts is ported.
func (api *PkiAPI) Crl(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiCrlInput]) (Out[apitypes.PkiCrlOutput], error) {
	return Out[apitypes.PkiCrlOutput]{}, notImplemented("pki.crl")
}

// GetAuthority is POST {basePath}/pki/getAuthority. One authority: subject, type, parent, KMS key and pinned version, certificate, validity, state, trust domain, name constraints and leaf limits.
//
// STUB: returns NOT_IMPLEMENTED until api/pki.ts is ported.
func (api *PkiAPI) GetAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiGetAuthorityInput]) (Out[apitypes.PkiGetAuthorityOutput], error) {
	return Out[apitypes.PkiGetAuthorityOutput]{}, notImplemented("pki.getAuthority")
}

// GetCertificate is POST {basePath}/pki/getCertificate. One certificate by serial number (hexadecimal, colons allowed).
//
// STUB: returns NOT_IMPLEMENTED until api/pki.ts is ported.
func (api *PkiAPI) GetCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiGetCertificateInput]) (Out[apitypes.PkiGetCertificateOutput], error) {
	return Out[apitypes.PkiGetCertificateOutput]{}, notImplemented("pki.getCertificate")
}

// IssueCertificate is POST {basePath}/pki/issueCertificate. Issues a certificate for the key in a PEM PKCS#10 request (csr). The request must be signed by its own key, which proves the requester holds the private key.
//
// STUB: returns NOT_IMPLEMENTED until api/pki.ts is ported.
func (api *PkiAPI) IssueCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiIssueCertificateInput]) (Out[apitypes.PkiIssueCertificateOutput], error) {
	return Out[apitypes.PkiIssueCertificateOutput]{}, notImplemented("pki.issueCertificate")
}

// ListAuthorities is POST {basePath}/pki/listAuthorities. The tenant's authorities the caller may read, oldest first.
//
// STUB: returns NOT_IMPLEMENTED until api/pki.ts is ported.
func (api *PkiAPI) ListAuthorities(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiListAuthoritiesInput]) (Out[apitypes.PkiListAuthoritiesOutput], error) {
	return Out[apitypes.PkiListAuthoritiesOutput]{}, notImplemented("pki.listAuthorities")
}

// ListCertificates is POST {basePath}/pki/listCertificates. Certificates the caller may read, newest first, filtered by authorityId, status (valid, revoked, expired) or identityId.
//
// STUB: returns NOT_IMPLEMENTED until api/pki.ts is ported.
func (api *PkiAPI) ListCertificates(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiListCertificatesInput]) (Out[apitypes.PkiListCertificatesOutput], error) {
	return Out[apitypes.PkiListCertificatesOutput]{}, notImplemented("pki.listCertificates")
}

// RequestCertificate is POST {basePath}/pki/requestCertificate. A workload certificate (SPIFFE X.509-SVID) for the caller's own identity.
//
// STUB: returns NOT_IMPLEMENTED until api/pki.ts is ported.
func (api *PkiAPI) RequestCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiRequestCertificateInput]) (Out[apitypes.PkiRequestCertificateOutput], error) {
	return Out[apitypes.PkiRequestCertificateOutput]{}, notImplemented("pki.requestCertificate")
}

// RevokeCertificate is POST {basePath}/pki/revokeCertificate. Revokes a certificate with a reason (unspecified, keyCompromise, caCompromise, affiliationChanged, superseded, cessationOfOperation or privilegeWithdrawn).
//
// STUB: returns NOT_IMPLEMENTED until api/pki.ts is ported.
func (api *PkiAPI) RevokeCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiRevokeCertificateInput]) (Out[apitypes.PkiRevokeCertificateOutput], error) {
	return Out[apitypes.PkiRevokeCertificateOutput]{}, notImplemented("pki.revokeCertificate")
}

// UpdateAuthority is POST {basePath}/pki/updateAuthority. Disables or re-enables an authority (state), and changes maxValiditySeconds, defaultValiditySeconds or crlUrl (null clears it) for future certificates.
//
// STUB: returns NOT_IMPLEMENTED until api/pki.ts is ported.
func (api *PkiAPI) UpdateAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiUpdateAuthorityInput]) (Out[apitypes.PkiUpdateAuthorityOutput], error) {
	return Out[apitypes.PkiUpdateAuthorityOutput]{}, notImplemented("pki.updateAuthority")
}

// PkiRuntime is api/pki.ts createPkiRuntime().
type PkiRuntime struct {
	server *ServerContext
}

// Crl (api/pki.ts createPkiRuntime().crl): An authority's current CRL (DER and PEM), with no credential: CRLs are
// public.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *PkiRuntime) Crl(ctx context.Context, authorityID string) (result *core.Object, err error) {
	err = notImplemented("api/pki.ts createPkiRuntime().crl")
	return
}

// CrlResponse (api/pki.ts createPkiRuntime().crlResponse): An HTTP response for an authority's CRL distribution
// point (`application/pkix-crl`). When a fresh CRL cannot be signed (the authority's KMS key is disabled), the last
// one is served while it is still valid; otherwise 503.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *PkiRuntime) CrlResponse(ctx context.Context, authorityID string) (result *http.Response, err error) {
	err = notImplemented("api/pki.ts createPkiRuntime().crlResponse")
	return
}

// Bundle (api/pki.ts createPkiRuntime().bundle): A tenant's trust anchors (active, unexpired roots) as one PEM
// bundle.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *PkiRuntime) Bundle(ctx context.Context, tenantID string) (result string, err error) {
	err = notImplemented("api/pki.ts createPkiRuntime().bundle")
	return
}

// Verify (api/pki.ts createPkiRuntime().verify): Verifies a presented certificate (leaf first; intermediates
// optional) against one tenant's stored chains: signatures, path lengths, validity, authority state and revocation,
// and for workload certificates the standing of the identity they name. Returns the SPIFFE ID and identity of
// workload certificates; throws `CERTIFICATE_INVALID` (401) otherwise. `tenantId` is required: trust is per
// organization.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *PkiRuntime) Verify(ctx context.Context, chain any, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/pki.ts createPkiRuntime().verify")
	return
}

// CreatePkiRuntime builds the PkiRuntime (api/pki.ts createPkiRuntime). Its methods are stubs until the module is ported.
func CreatePkiRuntime(server *ServerContext) *PkiRuntime {
	return &PkiRuntime{server: server}
}
