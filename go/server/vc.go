package server

// Skeleton of packages/server/src/vc.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// ActiveIssuerKey (vc.ts activeIssuerKey): The active signing key, created on first use.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ActiveIssuerKey(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, actorID string) (result *core.Object, err error) {
	err = notImplemented("vc.ts activeIssuerKey")
	return
}

// AssertVc (vc.ts assertVc): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertVc(server *ServerContext) (result *core.Object, err error) {
	err = notImplemented("vc.ts assertVc")
	return
}

// CreateIssuerKey (vc.ts createIssuerKey): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreateIssuerKey(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, actorID string) (result *core.Object, err error) {
	err = notImplemented("vc.ts createIssuerKey")
	return
}

// CreateNonce (vc.ts createNonce): A proof nonce (`c_nonce`) for one tenant, valid five minutes: stateless
// (`{time}.{random}.{mac}`), so handing them out writes nothing; only using one records it, once.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreateNonce(server *ServerContext, tenantID string) (result string, err error) {
	err = notImplemented("vc.ts createNonce")
	return
}

// HolderCleared (vc.ts holderCleared): Whether a person (an agent with its sponsor) is cleared for the
// classification label of credential type `typeName` (security clearances), whatever roles and policies say: what an
// administrator offers or issues still needs the holder to dominate the type's label, at the offer, at redemption,
// and in the sweep. Self-service credentials are decided through `mayRequest`, which applies the label itself. True
// without clearances.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func HolderCleared(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, identity *core.Object, typeName string, mfa bool) (result bool, err error) {
	err = notImplemented("vc.ts holderCleared")
	return
}

// HolderFromProof (vc.ts holderFromProof): Checks an OpenID4VCI proof for the tenant's issuer and consumes its
// nonce; returns the holder key.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func HolderFromProof(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, proof any) (result *core.Object, err error) {
	err = notImplemented("vc.ts holderFromProof")
	return
}

// IssueCredential (vc.ts issueCredential): Issues one SD-JWT VC of `type` for `identity`, bound to `holderJwk`, and
// records it (status index allocated, audit event `vc:credential:issue`). The lifetime never outlives the account's
// scheduled expiry nor `deadline` (the end of the grant or session that allowed a self-service request).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func IssueCredential(ctx context.Context, server *ServerContext, tx core.IamStore, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("vc.ts issueCredential")
	return
}

// IssuerJwks (vc.ts issuerJwks): The public keys verifiers accept: active and previous (retired keys verify
// nothing).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func IssuerJwks(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("vc.ts issuerJwks")
	return
}

// IssuerKeys (vc.ts issuerKeys): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func IssuerKeys(ctx context.Context, tx core.IamStore, tenantID string) (result []*core.Object, err error) {
	err = notImplemented("vc.ts issuerKeys")
	return
}

// IssuerURL (vc.ts issuerUrl): The issuer identifier (and base URL of its endpoints) of a tenant.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func IssuerURL(server *ServerContext, tenantID string) (result string, err error) {
	err = notImplemented("vc.ts issuerUrl")
	return
}

// MatchesHash (vc.ts matchesHash): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MatchesHash(stored string, value string) (result bool, err error) {
	err = notImplemented("vc.ts matchesHash")
	return
}

// MayRequest (vc.ts mayRequest): Whether a principal may request a type for themselves (`vc:request`), outside a
// root override from elsewhere.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MayRequest(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, typeValue *core.Object) (result bool, err error) {
	err = notImplemented("vc.ts mayRequest")
	return
}

// OfferIDOf (vc.ts offerIdOf): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OfferIDOf(value any, prefix string) (result string, err error) {
	err = notImplemented("vc.ts offerIdOf")
	return
}

// OfferToken (vc.ts offerToken): Pre-authorized codes and access tokens name their offer:
// `biam_vco.{offerId}.{secret}` / `biam_vcat.…`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OfferToken(prefix string, offerID string) (result string, err error) {
	err = notImplemented("vc.ts offerToken")
	return
}

// ResolveCredentialTypeResource (vc.ts resolveCredentialTypeResource): resolves `credential-type/{name}` for the
// decision engine; nil for other types or when verifiable credentials are off.
//
// PARTIAL: the guard is ported; the type lookup is a stub.
func ResolveCredentialTypeResource(ctx context.Context, server *ServerContext, tx core.IamStore, reference core.ResourceRef) (*ResolvedResource, error) {
	if reference.Type != CredentialTypeResource || !server.Options.VerifiableCredentials.IsOn() {
		return nil, nil
	}
	return nil, notImplemented("vc.ts resolveCredentialTypeResource")
}

// StatusListToken (vc.ts statusListToken): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func StatusListToken(ctx context.Context, server *ServerContext, reader core.IamStore, list *core.Object) (result string, err error) {
	err = notImplemented("vc.ts statusListToken")
	return
}

// SweepCredentials (vc.ts sweepCredentials): Revokes valid credentials whose holder is no longer an active member,
// self-service ones whose holder may no longer request them (`vc:request` decided again, with the MFA state of the
// issuing session), and, with security clearances, any other whose holder no longer dominates the type's
// classification label (`holderCleared`). A scheduler job; each tenant in its own transaction.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SweepCredentials(ctx context.Context, server *ServerContext, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("vc.ts sweepCredentials")
	return
}

// TypeByName (vc.ts typeByName): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TypeByName(ctx context.Context, tx core.IamStore, tenantID string, name string) (result *core.Object, err error) {
	err = notImplemented("vc.ts typeByName")
	return
}

// VcClaims (vc.ts vcClaims): Validates a type's claim list (1 to 32 claims, unique names, known sources).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VcClaims(value any, attributes *core.Object) (result []*core.Object, err error) {
	err = notImplemented("vc.ts vcClaims")
	return
}

// VcOptions (vc.ts vcOptions): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VcOptions(server *ServerContext) (result *core.Object, err error) {
	err = notImplemented("vc.ts vcOptions")
	return
}

// VcPlugins (vc.ts vcPlugins): the catalog entries the module contributes when enabled (the `credential-type` type and
// its actions); none when it is off.
//
// STUB: returns NOT_IMPLEMENTED when verifiable credentials are enabled, until the module is ported.
func VcPlugins(options *BetterIamOptions) (result []*core.IamPlugin, err error) {
	if !options.VerifiableCredentials.IsOn() {
		return nil, nil
	}
	err = notImplemented("vc.ts vcPlugins")
	return
}

// VerifyLocalPresentation (vc.ts verifyLocalPresentation): Verifies a presentation of a credential this deployment
// issued: the tenant's keys, disclosures, key binding (for `audience` and `nonce`, both required unless
// `requireKeyBinding: false`) and the credential's current standing: revoked and suspended credentials fail, and so
// do those of holders who are no longer active members or of an organization that is suspended (even before the
// sweep revokes them). Reads only, outside any transaction.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VerifyLocalPresentation(ctx context.Context, server *ServerContext, presentation string, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("vc.ts verifyLocalPresentation")
	return
}

// WriteStatus (vc.ts writeStatus): Writes a credential's status into its list.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WriteStatus(ctx context.Context, server *ServerContext, tx core.IamStore, record *core.Object, status string) (err error) {
	err = notImplemented("vc.ts writeStatus")
	return
}

// CredentialTypeResource is the resource type of credential types (`credential-type/{name}`).
const CredentialTypeResource = "credential-type"
