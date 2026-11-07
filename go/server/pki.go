package server

// Skeleton of packages/server/src/pki.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// AlgorithmForSpec (pki.ts algorithmForSpec): The X.509 signature algorithm a KMS signing key uses for certificates.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AlgorithmForSpec(spec string) (result string, err error) {
	err = notImplemented("pki.ts algorithmForSpec")
	return
}

// AssertAuthorityUsable (pki.ts assertAuthorityUsable): Usable for signing: active, within its validity, and every
// authority above it active too.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertAuthorityUsable(chain []*core.Object, now int64) (err error) {
	err = notImplemented("pki.ts assertAuthorityUsable")
	return
}

// AuthorityAttributes (pki.ts authorityAttributes): The attributes an authority presents to policies
// (`resource.{name}`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AuthorityAttributes(authority *core.Object) (result *core.Object, err error) {
	err = notImplemented("pki.ts authorityAttributes")
	return
}

// AuthorityChain (pki.ts authorityChain): The authority and its parents up to the root.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AuthorityChain(ctx context.Context, tx core.IamStore, authority *core.Object) (result []*core.Object, err error) {
	err = notImplemented("pki.ts authorityChain")
	return
}

// AuthoritySigner (pki.ts authoritySigner): The signature an authority's KMS key makes over `data`, audited on the
// key as used by `pki`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AuthoritySigner(ctx context.Context, server *ServerContext, tx core.IamStore, authority *core.Object) (result func(context.Context, []byte, *Principal) ([]byte, error), err error) {
	err = notImplemented("pki.ts authoritySigner")
	return
}

// CertificatePem (pki.ts certificatePem): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CertificatePem(der []byte) (result string, err error) {
	err = notImplemented("pki.ts certificatePem")
	return
}

// CrlPem (pki.ts crlPem): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CrlPem(der []byte) (result string, err error) {
	err = notImplemented("pki.ts crlPem")
	return
}

// CurrentCrl (pki.ts currentCrl): The authority's current CRL (DER), rebuilt when a certificate was revoked since
// the last one or half its lifetime has passed. Lists every revoked certificate that has not expired yet.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CurrentCrl(ctx context.Context, server *ServerContext, tx core.IamStore, authority *core.Object) (result *core.Object, err error) {
	err = notImplemented("pki.ts currentCrl")
	return
}

// DistinguishedName (pki.ts distinguishedName): A distinguished name: `commonName` required for authorities, every
// part within X.520 bounds.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DistinguishedName(value any, requireCommonName bool) (result *core.Object, err error) {
	err = notImplemented("pki.ts distinguishedName")
	return
}

// FindAuthority (pki.ts findAuthority): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func FindAuthority(ctx context.Context, tx core.IamStore, tenantID string, authorityID any) (result *core.Object, err error) {
	err = notImplemented("pki.ts findAuthority")
	return
}

// HttpURL (pki.ts httpUrl): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func HttpURL(value any, name string) (result string, err error) {
	err = notImplemented("pki.ts httpUrl")
	return
}

// NamesPermitted (pki.ts namesPermitted): Checks names against the name constraints of an authority and every
// authority above it. A constraint list applies to its kind of name only: DNS names against `dnsNames`, URI hosts
// against `uriHosts`. A common name that looks like a host name counts as a DNS name, because TLS clients still fall
// back to it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func NamesPermitted(chain []*core.Object, names *core.Object, commonName string) (result bool, err error) {
	err = notImplemented("pki.ts namesPermitted")
	return
}

// PermittedNames (pki.ts permittedNames): Name constraints: DNS suffixes (`example.internal`, matching it and its
// subdomains) and URI hosts.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PermittedNames(value any) (result *core.Object, err error) {
	err = notImplemented("pki.ts permittedNames")
	return
}

// SpkiOf (pki.ts spkiOf): The DER SubjectPublicKeyInfo of a KMS key version's public key.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SpkiOf(publicKeyPem string) (result []byte, err error) {
	err = notImplemented("pki.ts spkiOf")
	return
}

// SummarizeAuthority (pki.ts summarizeAuthority): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SummarizeAuthority(authority *core.Object) (result *core.Object, err error) {
	err = notImplemented("pki.ts summarizeAuthority")
	return
}

// SummarizeCertificate (pki.ts summarizeCertificate): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SummarizeCertificate(certificate *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("pki.ts summarizeCertificate")
	return
}

// TrustDomain (pki.ts trustDomain): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TrustDomain(value any) (result string, err error) {
	err = notImplemented("pki.ts trustDomain")
	return
}

// VerifyCertificateChain (pki.ts verifyCertificateChain): Verifies a client or server certificate chain (leaf first,
// PEM concatenated or as a list) against one tenant's certificate authorities: every signature, path length,
// validity period, authority state and revocation, and for a workload certificate the standing of the identity it
// names. For mTLS: a server that terminates TLS passes the peer's certificate and gets the identity behind a
// workload certificate.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VerifyCertificateChain(ctx context.Context, server *ServerContext, chain any, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("pki.ts verifyCertificateChain")
	return
}

// MaxAuthoritiesPerTenant is pki.ts MAX_AUTHORITIES_PER_TENANT.
const MaxAuthoritiesPerTenant = 50

// MaxLeafValiditySeconds is pki.ts MAX_LEAF_VALIDITY_SECONDS.
const MaxLeafValiditySeconds = 71280000

// PkiActions is pki.ts pkiActions.
var PkiActions = struct {
	Create  string
	Read    string
	Update  string
	Issue   string
	Request string
	Revoke  string
}{"iam:pki:create", "iam:pki:read", "iam:pki:update", "iam:pki:issue", "iam:pki:request", "iam:pki:revoke"}
