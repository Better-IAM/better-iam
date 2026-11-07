package server

// Skeleton of packages/server/src/sd-jwt.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// SdJwtError is sd-jwt.ts SdJwtError.
// TypeScript: super(message);
type SdJwtError struct {
	Reason string
}

// IssueSdJwt (sd-jwt.ts issueSdJwt): Issues an SD-JWT: `plain` claims are visible to anyone holding the credential;
// each `disclosable` claim becomes a disclosure the holder decides to reveal or keep. Random decoy digests hide how
// many claims exist. Returns the issued form `<jwt>~<disclosure>~...~` and its parts.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func IssueSdJwt(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("sd-jwt.ts issueSdJwt")
	return
}

// SetStatusAt (sd-jwt.ts setStatusAt): Writes the status of `index` into a raw list.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SetStatusAt(bytes []byte, index float64, bits float64, value float64) (err error) {
	err = notImplemented("sd-jwt.ts setStatusAt")
	return
}

// SignStatusList (sd-jwt.ts signStatusList): A Status List Token (JWT, `typ: statuslist+jwt`) for a raw list.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SignStatusList(ctx context.Context, input *core.Object) (result string, err error) {
	err = notImplemented("sd-jwt.ts signStatusList")
	return
}

// StatusAt (sd-jwt.ts statusAt): Reads the status of `index` from a raw list of `bits`-bit entries (index 0 is the
// low bits of byte 0).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func StatusAt(bytes []byte, index float64, bits float64) (result float64, err error) {
	err = notImplemented("sd-jwt.ts statusAt")
	return
}

// VerifyHolderProof (sd-jwt.ts verifyHolderProof): Verifies an OpenID4VCI holder proof (`typ: openid4vci-proof+jwt`,
// the holder's public key in the `jwk` header): signature, `aud` (the credential issuer), freshness, and the nonce
// the issuer handed out. Returns the holder key and its RFC 7638 thumbprint.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VerifyHolderProof(ctx context.Context, proof any, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("sd-jwt.ts verifyHolderProof")
	return
}

// VerifySdJwt (sd-jwt.ts verifySdJwt): Verifies an SD-JWT VC or presentation: the issuer's signature (`issuerKey`
// resolves `kid`/`iss`), validity times, every disclosure against the signed digests, and, for presentations, the
// key-binding JWT (`audience`, `nonce`, freshness, `sd_hash`) with the holder key in `cnf.jwk`. Throws `SdJwtError`
// with the reason.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VerifySdJwt(ctx context.Context, value string, options any) (result *core.Object, err error) {
	err = notImplemented("sd-jwt.ts verifySdJwt")
	return
}

// SdJwtVcType is sd-jwt.ts SD_JWT_VC_TYPE.
const SdJwtVcType = "dc+sd-jwt"

// StatusInvalid is sd-jwt.ts STATUS_INVALID.
const StatusInvalid = 1

// StatusSuspended is sd-jwt.ts STATUS_SUSPENDED.
const StatusSuspended = 2

// StatusValid is sd-jwt.ts STATUS_VALID.
const StatusValid = 0

// ReservedVcClaims is sd-jwt.ts reservedVcClaims.
var ReservedVcClaims = newOrderedSet("iss", "sub", "iat", "nbf", "exp", "cnf", "vct", "vct#integrity", "status", "jti", "aud", "_sd", "_sd_alg", "...", "__proto__", "constructor", "prototype")

// Error is the failure reason (the module's messages are ported with sd-jwt.ts).
func (e *SdJwtError) Error() string { return e.Reason }
