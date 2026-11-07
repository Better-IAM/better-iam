package server

// Skeleton of packages/server/src/ssh-ca.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"github.com/Better-IAM/better-iam/go/core"
)

// BuildSshKrl (ssh-ca.ts buildSshKrl): A binary OpenSSH key revocation list (PROTOCOL.krl) for sshd `RevokedKeys`
// and ssh `RevokedHostKeys`: certificate serials and key IDs per authority, plus plain keys revoked outright (such
// as a disabled host's key).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BuildSshKrl(input *core.Object) (result []byte, err error) {
	err = notImplemented("ssh-ca.ts buildSshKrl")
	return
}

// GenerateSshAuthorityKey (ssh-ca.ts generateSshAuthorityKey): A new Ed25519 authority key, with the private key as
// base64 PKCS#8 DER (the caller seals it).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func GenerateSshAuthorityKey() (result *core.Object, err error) {
	err = notImplemented("ssh-ca.ts generateSshAuthorityKey")
	return
}

// ParseSshPublicKey (ssh-ca.ts parseSshPublicKey): Parses and validates one public key line (`type base64
// [comment]`). Certificates, DSA keys, RSA keys under 2048 bits, malformed points and trailing data are refused.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseSshPublicKey(line any, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("ssh-ca.ts parseSshPublicKey")
	return
}

// SignSshCertificate (ssh-ca.ts signSshCertificate): Issues an OpenSSH certificate; returns the certificate blob and
// its `*-cert.pub` line.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SignSshCertificate(authority *core.Object, spec *core.Object, comment string) (result *core.Object, err error) {
	err = notImplemented("ssh-ca.ts signSshCertificate")
	return
}

// SshFingerprint (ssh-ca.ts sshFingerprint): `SHA256:` plus the unpadded base64 SHA-256 of a key blob.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SshFingerprint(blob []byte) (result string, err error) {
	err = notImplemented("ssh-ca.ts sshFingerprint")
	return
}

// SshHostAddress (ssh-ca.ts sshHostAddress): A host certificate principal: a DNS name (a leading `*.` is refused),
// or an IPv4/IPv6 address.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SshHostAddress(value any) (result string, err error) {
	err = notImplemented("ssh-ca.ts sshHostAddress")
	return
}

// SshKeyLine (ssh-ca.ts sshKeyLine): An `authorized_keys`-style line for a key blob.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SshKeyLine(blob []byte, comment string) (result string, err error) {
	err = notImplemented("ssh-ca.ts sshKeyLine")
	return
}

// SshLogin (ssh-ca.ts sshLogin): A Unix login name, as certificate principals carry them: portable user names only.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SshLogin(value any) (result string, err error) {
	err = notImplemented("ssh-ca.ts sshLogin")
	return
}

// SshLoginPrincipal (ssh-ca.ts sshLoginPrincipal): The principal a host accepts for a login: `{login}@{host}`, so a
// certificate names the hosts it opens.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SshLoginPrincipal(login string, host string) (result string, err error) {
	err = notImplemented("ssh-ca.ts sshLoginPrincipal")
	return
}

// SshSerial (ssh-ca.ts sshSerial): A random non-zero 63-bit serial (KRLs cannot revoke serial 0).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SshSerial() (result any, err error) {
	err = notImplemented("ssh-ca.ts sshSerial")
	return
}

// SshSigningKey (ssh-ca.ts sshSigningKey): Opens a stored authority key.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SshSigningKey(publicBlob []byte, privatePkcs8 string) (result *core.Object, err error) {
	err = notImplemented("ssh-ca.ts sshSigningKey")
	return
}

// SshCertHost is ssh-ca.ts SSH_CERT_HOST.
const SshCertHost = 2

// SshCertUser is ssh-ca.ts SSH_CERT_USER.
const SshCertUser = 1
