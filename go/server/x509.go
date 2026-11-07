package server

// Skeleton of packages/server/src/x509.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"regexp"

	"github.com/Better-IAM/better-iam/go/core"
)

// CertificateDer (x509.ts certificateDer): The DER bytes of a PEM certificate.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CertificateDer(pemText string) (result []byte, err error) {
	err = notImplemented("x509.ts certificateDer")
	return
}

// EncodeName (x509.ts encodeName): Encodes a name in the conventional order (C, ST, L, O, OU, CN), one attribute per
// RDN.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EncodeName(name *core.Object) (result []byte, err error) {
	err = notImplemented("x509.ts encodeName")
	return
}

// KeyIdentifier (x509.ts keyIdentifier): RFC 5280 key identifier (method 1): SHA-1 of the subject public key bits.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KeyIdentifier(spki []byte) (result []byte, err error) {
	err = notImplemented("x509.ts keyIdentifier")
	return
}

// ParseCertificateRequest (x509.ts parseCertificateRequest): Parses and verifies a PEM (or base64 DER) PKCS#10
// request: the signature must verify with the request's own key (proof of possession), and the key must be of an
// accepted kind. Returns the key, the subject common name and the requested subject alternative names.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseCertificateRequest(value any) (result *core.Object, err error) {
	err = notImplemented("x509.ts parseCertificateRequest")
	return
}

// Pem (x509.ts pem): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Pem(label string, der []byte) (result string, err error) {
	err = notImplemented("x509.ts pem")
	return
}

// RandomSerial (x509.ts randomSerial): A positive random serial number (about 123 random bits), as lowercase hex
// whose first digit is never `0`, so it reads the same with or without leading-zero stripping (Node's
// `X509Certificate.serialNumber` strips them).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RandomSerial() (result string, err error) {
	err = notImplemented("x509.ts randomSerial")
	return
}

// Sha256Fingerprint (x509.ts sha256Fingerprint): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Sha256Fingerprint(der []byte) (result string, err error) {
	err = notImplemented("x509.ts sha256Fingerprint")
	return
}

// SignedStructure (x509.ts signedStructure): Wraps a signed TBS structure (certificate or CRL).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SignedStructure(tbs []byte, algorithm string, signature []byte) (result []byte, err error) {
	err = notImplemented("x509.ts signedStructure")
	return
}

// SubjectAltNames (x509.ts subjectAltNames): Validates and canonicalizes requested names, at most 100 in total:
// lowercase DNS names and email addresses (ASCII only), URIs in canonical form (SPIFFE IDs by the SPIFFE grammar),
// and IP addresses in canonical text.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SubjectAltNames(input *core.Object) (result *core.Object, err error) {
	err = notImplemented("x509.ts subjectAltNames")
	return
}

// TbsCertList (x509.ts tbsCertList): A TBSCertList (RFC 5280 5.1) with a CRL number and the issuer's key identifier.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TbsCertList(spec *core.Object, algorithm string) (result []byte, err error) {
	err = notImplemented("x509.ts tbsCertList")
	return
}

// TbsCertificate (x509.ts tbsCertificate): The TBSCertificate DER for a spec, signed by the caller with the issuer's
// key.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TbsCertificate(spec *core.Object, algorithm string) (result []byte, err error) {
	err = notImplemented("x509.ts tbsCertificate")
	return
}

// DnsName is x509.ts dnsName.
var DnsName = regexp.MustCompile("^(?:\\*\\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

// RevocationReasons is x509.ts revocationReasons.
var RevocationReasons = struct {
	Unspecified          float64
	KeyCompromise        float64
	CaCompromise         float64
	AffiliationChanged   float64
	Superseded           float64
	CessationOfOperation float64
	CertificateHold      float64
	PrivilegeWithdrawn   float64
}{0, 1, 2, 3, 4, 5, 6, 9}
