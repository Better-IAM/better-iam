package server

// Partial port of packages/server/src/kms.ts: where KMS key material sealed under the deployment secret lives, for
// RotateSecrets (secrets.go). The key management service itself is ported with the KMS module.

import (
	"context"
	"regexp"

	"github.com/Better-IAM/better-iam/go/core"
)

// kmsVersionContext is the sealing context of a key version's material.
func kmsVersionContext(keyID string, version float64) string {
	return "kms-key:" + keyID + ":" + core.NumberString(version)
}

// KmsSealedField is where sealed key material lives (collection kmsKeyVersions, wrapper "secret").
var KmsSealedField = SealedField{
	Collection: "kmsKeyVersions",
	Filter:     func() *core.Object { return core.NewObject("wrapper", "secret") },
	Read:       stringMember("materialSealed"),
	Write:      setMember("materialSealed"),
	Context: func(record *core.Object) string {
		return kmsVersionContext(jsString(record.Get("keyId")), jsNumber(record.Get("version")))
	},
}

// AddKeyVersion (kms.ts addKeyVersion): Generates, seals and stores a new version of a key.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AddKeyVersion(ctx context.Context, server *ServerContext, tx core.IamStore, key *core.Object, version float64, origin string) (result *core.Object, err error) {
	err = notImplemented("kms.ts addKeyVersion")
	return
}

// AliasNames (kms.ts aliasNames): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AliasNames(ctx context.Context, tx core.IamStore, key *core.Object) (result []string, err error) {
	err = notImplemented("kms.ts aliasNames")
	return
}

// AssertUnmanaged (kms.ts assertUnmanaged): Refuses direct cryptographic use of a key another module owns
// (`KEY_MANAGED`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertUnmanaged(key *core.Object) (err error) {
	err = notImplemented("kms.ts assertUnmanaged")
	return
}

// AssertUsable (kms.ts assertUsable): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertUsable(key *core.Object, usage string) (err error) {
	err = notImplemented("kms.ts assertUsable")
	return
}

// Base64Bytes (kms.ts base64Bytes): Decodes canonical standard or URL-safe base64 (padding optional), refusing
// anything else and anything longer than `max` bytes. Canonical only: one byte string has one accepted spelling, so
// string-keyed replay caches hold.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Base64Bytes(value any, name string, maxValue float64) (result []byte, err error) {
	err = notImplemented("kms.ts base64Bytes")
	return
}

// CandidateGrants (kms.ts candidateGrants): The live grants on the key that allow `operation` to the principal's own
// identity, satisfying their constraints, oldest first. Grants serve people and machine accounts acting in their own
// right (user sessions and API keys): assumed roles, session tokens, delegated agent sessions and impersonation
// never use them. The caller still checks that each grant's creator could make the call now (api/keys.ts), so a
// grant never outlives its creator's access.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CandidateGrants(ctx context.Context, server *ServerContext, tx core.IamStore, key *core.Object, principal *Principal, operation string, context *core.Object) (result []*core.Object, err error) {
	err = notImplemented("kms.ts candidateGrants")
	return
}

// CreateServiceKey (kms.ts createServiceKey): Creates a key for another module's own use, such as a certificate
// authority's signing key, without a caller permission check (the calling module authorizes its caller). The key is
// an ordinary KMS key: visible, taggable, and disabled or deleted like any other.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreateServiceKey(ctx context.Context, server *ServerContext, tx core.IamStore, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("kms.ts createServiceKey")
	return
}

// DecryptWith (kms.ts decryptWith): Decrypts; any tampering, wrong key version or different encryption context fails
// the same way.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DecryptWith(server *ServerContext, key *core.Object, version *core.Object, parsed *core.Object, context *core.Object) (result []byte, err error) {
	err = notImplemented("kms.ts decryptWith")
	return
}

// EncryptWith (kms.ts encryptWith): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EncryptWith(server *ServerContext, key *core.Object, version *core.Object, plaintext []byte, isText bool, context *core.Object) (result string, err error) {
	err = notImplemented("kms.ts encryptWith")
	return
}

// EncryptionContext (kms.ts encryptionContext): An encryption context: up to 16 non-secret key/value pairs bound to
// a ciphertext as additional authenticated data. Decryption must present the same pairs. They are recorded in the
// audit trail and exposed to policies as `resource.encryptionContext.{key}`, so never put secrets in them.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EncryptionContext(value any, name string) (result *core.Object, err error) {
	err = notImplemented("kms.ts encryptionContext")
	return
}

// FindKey (kms.ts findKey): A key by id or `alias/{name}` within a tenant.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func FindKey(ctx context.Context, tx core.IamStore, tenantID string, reference any) (result *core.Object, err error) {
	err = notImplemented("kms.ts findKey")
	return
}

// Fingerprint (kms.ts fingerprint): A short fingerprint of public material, for listings (never of secret material).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Fingerprint(pem string) (result string, err error) {
	err = notImplemented("kms.ts fingerprint")
	return
}

// GrantConstraints (kms.ts grantConstraints): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func GrantConstraints(value any, operations []string) (result *core.Object, err error) {
	err = notImplemented("kms.ts grantConstraints")
	return
}

// GrantOperations (kms.ts grantOperations): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func GrantOperations(value any, usage string) (result []string, err error) {
	err = notImplemented("kms.ts grantOperations")
	return
}

// KeyAlgorithms (kms.ts keyAlgorithms): The algorithms a key signs or computes MACs with (encryption keys: none).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KeyAlgorithms(key *core.Object) (result []string, err error) {
	err = notImplemented("kms.ts keyAlgorithms")
	return
}

// KeyAttributes (kms.ts keyAttributes): The attributes a key presents to policies (`resource.{name}`): identity,
// spec, usage, state, aliases, tags as `resource.tags.{key}`, and for calls with one the encryption context as
// `resource.encryptionContext.{key}` plus `resource.encryptionContextKeys`, and a signing call's
// `resource.algorithm`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KeyAttributes(key *core.Object, aliases []string, extra *core.Object) (result *core.Object, err error) {
	err = notImplemented("kms.ts keyAttributes")
	return
}

// KeySpec (kms.ts keySpec): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KeySpec(value any) (result string, err error) {
	err = notImplemented("kms.ts keySpec")
	return
}

// KeyTags (kms.ts keyTags): Up to 50 tags; keys are identifiers, values short strings (they become
// `resource.tags.{key}`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KeyTags(value any) (result *core.Object, err error) {
	err = notImplemented("kms.ts keyTags")
	return
}

// KeyUsageFor (kms.ts keyUsageFor): The usage a new key gets: the one its spec allows, or (for RSA) the one asked
// for.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KeyUsageFor(spec string, value any) (result string, err error) {
	err = notImplemented("kms.ts keyUsageFor")
	return
}

// KeyVersion (kms.ts keyVersion): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KeyVersion(ctx context.Context, tx core.IamStore, key *core.Object, version float64) (result *core.Object, err error) {
	err = notImplemented("kms.ts keyVersion")
	return
}

// KmsDataKeyFor (kms.ts kmsDataKeyFor): A fresh 32-byte data key wrapped under a tenant AES key, for a module that
// protects many values in one call (tokenization): the caller encrypts locally, stores `wrapped` beside the data,
// and must wipe `dataKey` after use. Audited once as `iam:kms:generate-data-key` with `metadata.via`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KmsDataKeyFor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, keyRef string, context *core.Object, use *core.Object) (result *core.Object, err error) {
	err = notImplemented("kms.ts kmsDataKeyFor")
	return
}

// KmsDecryptFor (kms.ts kmsDecryptFor): Decrypts what `kmsEncryptFor` returned; the key must still be enabled and
// the context the same.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KmsDecryptFor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, sealed *core.Object, context any, use *core.Object) (result string, err error) {
	err = notImplemented("kms.ts kmsDecryptFor")
	return
}

// KmsEncryptFor (kms.ts kmsEncryptFor): Encrypts a UTF-8 string of any size (up to 16 MiB) under a tenant's AES key
// (id or alias) by envelope encryption: a fresh data key encrypts the value locally and the key's current version
// wraps the data key. The result is `{wrapped data key}~{iv|tag|ciphertext}`, both bound to the encryption context
// (a string `context` is bound as `{ context }`). Refuses disabled keys, keys pending deletion and non-AES keys.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KmsEncryptFor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, keyRef string, plaintext string, context any, use *core.Object) (result *core.Object, err error) {
	err = notImplemented("kms.ts kmsEncryptFor")
	return
}

// KmsOpenDataKeyFor (kms.ts kmsOpenDataKeyFor): Unwraps a data key from `kmsDataKeyFor`; the key must still be
// enabled and the context the same.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KmsOpenDataKeyFor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, wrapped string, context *core.Object, use *core.Object) (result []byte, err error) {
	err = notImplemented("kms.ts kmsOpenDataKeyFor")
	return
}

// KmsSignFor (kms.ts kmsSignFor): Signs `data` with one pinned version of a signing key for another module (a
// certificate authority signing certificates and CRLs). The key must be enabled; the use is audited as
// `iam:kms:sign` with `metadata.via`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func KmsSignFor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, keyID string, version float64, algorithm string, data []byte, use *core.Object) (result []byte, err error) {
	err = notImplemented("kms.ts kmsSignFor")
	return
}

// MacWith (kms.ts macWith): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MacWith(server *ServerContext, key *core.Object, version *core.Object, message []byte) (result []byte, err error) {
	err = notImplemented("kms.ts macWith")
	return
}

// ParseCiphertext (kms.ts parseCiphertext): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseCiphertext(value any) (result *core.Object, err error) {
	err = notImplemented("kms.ts parseCiphertext")
	return
}

// ParseKid (kms.ts parseKid): A JWT `kid` of the form `{keyId}.{version}`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseKid(value any) (result *core.Object, err error) {
	err = notImplemented("kms.ts parseKid")
	return
}

// Payload (kms.ts payload): Reads a payload given as text (`{name}`, UTF-8) or bytes (`{name}Base64`): exactly one
// of the two. Says which, so decryption can return the same form.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Payload(input *core.Object, name string, maxValue float64) (result *core.Object, err error) {
	err = notImplemented("kms.ts payload")
	return
}

// RequestAttributes (kms.ts requestAttributes): Attributes for creating a key: what it would be, so policies can
// require tags or specs (`resource.tags.team`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RequestAttributes(spec string, usage string, tags *core.Object) (result *core.Object, err error) {
	err = notImplemented("kms.ts requestAttributes")
	return
}

// RetireServiceKey (kms.ts retireServiceKey): Schedules deletion of a key a module created for its own use once the
// module is done with it (a deleted data protection profile), after the shortest waiting period. Keys the module
// does not manage are left alone. Returns the deletion date, or undefined when nothing was scheduled.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RetireServiceKey(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, keyID string, managedBy string, managedID string) (result *float64, err error) {
	err = notImplemented("kms.ts retireServiceKey")
	return
}

// SameBytes (kms.ts sameBytes): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SameBytes(left []byte, right []byte) (result bool, err error) {
	err = notImplemented("kms.ts sameBytes")
	return
}

// SignWith (kms.ts signWith): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SignWith(server *ServerContext, version *core.Object, algorithm string, message []byte, format string) (result []byte, err error) {
	err = notImplemented("kms.ts signWith")
	return
}

// SigningAlgorithm (kms.ts signingAlgorithm): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SigningAlgorithm(key *core.Object, value any) (result string, err error) {
	err = notImplemented("kms.ts signingAlgorithm")
	return
}

// SummarizeGrant (kms.ts summarizeGrant): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SummarizeGrant(grant *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("kms.ts summarizeGrant")
	return
}

// SummarizeKey (kms.ts summarizeKey): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SummarizeKey(key *core.Object, aliases []string) (result *core.Object, err error) {
	err = notImplemented("kms.ts summarizeKey")
	return
}

// VerifyWith (kms.ts verifyWith): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VerifyWith(version *core.Object, algorithm string, message []byte, signature []byte, format string) (result bool, err error) {
	err = notImplemented("kms.ts verifyWith")
	return
}

// MaxAliasesPerKey is kms.ts MAX_ALIASES_PER_KEY.
const MaxAliasesPerKey = 50

// MaxGrantsPerKey is kms.ts MAX_GRANTS_PER_KEY.
const MaxGrantsPerKey = 50

// MaxKeysPerTenant is kms.ts MAX_KEYS_PER_TENANT.
const MaxKeysPerTenant = 1000

// MaxMessageBytes is kms.ts MAX_MESSAGE_BYTES.
const MaxMessageBytes = 65536

// MaxPlaintextBytes is kms.ts MAX_PLAINTEXT_BYTES.
const MaxPlaintextBytes = 4096

// MaxVersions is kms.ts MAX_VERSIONS.
const MaxVersions = 1000

// AliasPattern is kms.ts aliasPattern.
var AliasPattern = regexp.MustCompile("^alias\\/[A-Za-z0-9/_-]{1,250}$")

// GrantOperationOf is kms.ts grantOperationOf.
var GrantOperationOf = mustObject(`{"iam:kms:read":"read","iam:kms:encrypt":"encrypt","iam:kms:decrypt":"decrypt","iam:kms:generate-data-key":"generate-data-key","iam:kms:sign":"sign","iam:kms:verify":"verify","iam:kms:generate-mac":"generate-mac","iam:kms:verify-mac":"verify-mac"}`)

// KeySpecs is kms.ts keySpecs.
var KeySpecs = mustObject(`{"aes-256-gcm":{"usages":["encrypt"],"family":"aes"},"hmac-sha256":{"usages":["mac"],"family":"hmac","size":32,"hash":"sha256"},"hmac-sha384":{"usages":["mac"],"family":"hmac","size":48,"hash":"sha384"},"hmac-sha512":{"usages":["mac"],"family":"hmac","size":64,"hash":"sha512"},"ecc-p256":{"usages":["sign"],"family":"ec","curve":"P-256","hash":"sha256"},"ecc-p384":{"usages":["sign"],"family":"ec","curve":"P-384","hash":"sha384"},"ed25519":{"usages":["sign"],"family":"ed25519"},"rsa-2048":{"usages":["encrypt","sign"],"family":"rsa","size":2048},"rsa-3072":{"usages":["encrypt","sign"],"family":"rsa","size":3072},"rsa-4096":{"usages":["encrypt","sign"],"family":"rsa","size":4096}}`)

// KmsActions is kms.ts kmsActions.
var KmsActions = mustObject(`{"create":"iam:kms:create","read":"iam:kms:read","update":"iam:kms:update","delete":"iam:kms:delete","grant":"iam:kms:grant","encrypt":"iam:kms:encrypt","decrypt":"iam:kms:decrypt","generate-data-key":"iam:kms:generate-data-key","sign":"iam:kms:sign","verify":"iam:kms:verify","generate-mac":"iam:kms:generate-mac","verify-mac":"iam:kms:verify-mac"}`)
