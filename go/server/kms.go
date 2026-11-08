package server

// Port of packages/server/src/kms.ts: key management (KMS). Tenant keys whose material never leaves the server.
// Symmetric keys encrypt and decrypt (AES-256-GCM, bound to an encryption context), asymmetric keys sign and verify
// (ECDSA, Ed25519, RSA) or encrypt (RSA-OAEP), and HMAC keys compute and check message authentication codes. Every
// key keeps its old versions, so rotation never breaks existing ciphertexts or signatures. Material is sealed under
// the deployment secret (and re-sealed by RotateSecrets); the API lives in api_keys.go.

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"hash"
	"math"
	"math/big"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
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

// MaxAliasesPerKey is kms.ts MAX_ALIASES_PER_KEY.
const MaxAliasesPerKey = 50

// MaxGrantsPerKey is kms.ts MAX_GRANTS_PER_KEY.
const MaxGrantsPerKey = 50

// MaxKeysPerTenant is kms.ts MAX_KEYS_PER_TENANT.
const MaxKeysPerTenant = 1000

// MaxMessageBytes is kms.ts MAX_MESSAGE_BYTES: messages accepted by sign, verify and the MAC calls.
const MaxMessageBytes = 65536

// MaxPlaintextBytes is kms.ts MAX_PLAINTEXT_BYTES: plaintext accepted by encrypt (AES-GCM); RSA-OAEP accepts what
// the modulus allows.
const MaxPlaintextBytes = 4096

// MaxVersions is kms.ts MAX_VERSIONS.
const MaxVersions = 1000

const kmsMaxCiphertextChars = 16384

const kmsCiphertextPrefix = "kms1"

// kmsMaxServicePlaintext is at most 16 MiB through the service helpers.
const kmsMaxServicePlaintext = 16 * 1024 * 1024

// AliasPattern is kms.ts aliasPattern.
var AliasPattern = regexp.MustCompile("^alias\\/[A-Za-z0-9/_-]{1,250}$")

var (
	kmsTagKey        = regexp.MustCompile(`^[A-Za-z0-9_.:/=+@-]{1,128}$`)
	kmsContextKey    = regexp.MustCompile(`^[A-Za-z0-9_.:/=+@-]{1,128}$`)
	kmsKeyIDPattern  = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	kmsVersionText   = regexp.MustCompile(`^[1-9]\d{0,5}$`)
	kmsBase64URL     = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	kmsBase64URLAny  = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	kmsBase64Std     = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	kmsKidPattern    = regexp.MustCompile(`^([A-Za-z0-9-]{1,64})\.([1-9]\d{0,5})$`)
	kmsTrailingEqual = regexp.MustCompile(`=+$`)
)

// kmsUnsafeKeys are the keys that would reach the prototype of a JavaScript object.
var kmsUnsafeKeys = map[string]bool{"__proto__": true, "prototype": true, "constructor": true}

// GrantOperationOf is kms.ts grantOperationOf.
var GrantOperationOf = mustObject(`{"iam:kms:read":"read","iam:kms:encrypt":"encrypt","iam:kms:decrypt":"decrypt","iam:kms:generate-data-key":"generate-data-key","iam:kms:sign":"sign","iam:kms:verify":"verify","iam:kms:generate-mac":"generate-mac","iam:kms:verify-mac":"verify-mac"}`)

// KeySpecs is kms.ts keySpecs.
var KeySpecs = mustObject(`{"aes-256-gcm":{"usages":["encrypt"],"family":"aes"},"hmac-sha256":{"usages":["mac"],"family":"hmac","size":32,"hash":"sha256"},"hmac-sha384":{"usages":["mac"],"family":"hmac","size":48,"hash":"sha384"},"hmac-sha512":{"usages":["mac"],"family":"hmac","size":64,"hash":"sha512"},"ecc-p256":{"usages":["sign"],"family":"ec","curve":"P-256","hash":"sha256"},"ecc-p384":{"usages":["sign"],"family":"ec","curve":"P-384","hash":"sha384"},"ed25519":{"usages":["sign"],"family":"ed25519"},"rsa-2048":{"usages":["encrypt","sign"],"family":"rsa","size":2048},"rsa-3072":{"usages":["encrypt","sign"],"family":"rsa","size":3072},"rsa-4096":{"usages":["encrypt","sign"],"family":"rsa","size":4096}}`)

// KmsActions is kms.ts kmsActions.
var KmsActions = mustObject(`{"create":"iam:kms:create","read":"iam:kms:read","update":"iam:kms:update","delete":"iam:kms:delete","grant":"iam:kms:grant","encrypt":"iam:kms:encrypt","decrypt":"iam:kms:decrypt","generate-data-key":"iam:kms:generate-data-key","sign":"iam:kms:sign","verify":"iam:kms:verify","generate-mac":"iam:kms:generate-mac","verify-mac":"iam:kms:verify-mac"}`)

// kmsAction is kmsActions[name].
func kmsAction(name string) string { return jsString(KmsActions.Get(name)) }

// kmsOperationsByUsage are the grant operations a key of each usage allows.
var kmsOperationsByUsage = map[string][]string{
	"encrypt": {"read", "encrypt", "decrypt", "generate-data-key"},
	"sign":    {"read", "sign", "verify"},
	"mac":     {"read", "generate-mac", "verify-mac"},
}

// kmsContextOperations carry an encryption context, the only ones a context-constrained grant may allow.
var kmsContextOperations = map[string]bool{"encrypt": true, "decrypt": true, "generate-data-key": true}

// kmsSpec is keySpecs[spec] (nil for an unknown spec).
func kmsSpec(spec string) *core.Object {
	info, _ := KeySpecs.Get(spec).(*core.Object)
	return info
}

func kmsSpecFamily(spec string) string {
	if info := kmsSpec(spec); info != nil {
		return jsString(info.Get("family"))
	}
	return ""
}

func kmsSpecSize(spec string) float64 {
	if info := kmsSpec(spec); info != nil {
		return jsNumber(info.Get("size"))
	}
	return math.NaN()
}

func kmsSpecString(spec, name string) string {
	if info := kmsSpec(spec); info != nil {
		if value, ok := info.Get(name).(string); ok {
			return value
		}
	}
	return ""
}

func kmsSpecUsages(spec string) []string {
	info := kmsSpec(spec)
	if info == nil {
		return nil
	}
	list, _ := info.Get("usages").([]any)
	usages := make([]string, len(list))
	for index, item := range list {
		usages[index] = jsString(item)
	}
	return usages
}

// kmsSortedStrings is `[...items].sort()` (UTF-16 code unit order).
func kmsSortedStrings(items []string) []string {
	sorted := append([]string{}, items...)
	sortStable(sorted, compareUTF16)
	return sorted
}

// kmsStringList reads a string array member.
func kmsStringList(value any) []string {
	switch list := value.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, 0, len(list))
		for _, item := range list {
			out = append(out, jsString(item))
		}
		return out
	}
	return []string{}
}

func kmsRandomBytes(size int) []byte {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return buffer
}

// KeySpec (kms.ts keySpec) validates a key spec.
func KeySpec(value any) (result string, err error) {
	spec, ok := value.(string)
	if !ok || !KeySpecs.Has(spec) {
		return "", invalidInput("keySpec must be one of " + strings.Join(KeySpecs.Keys(), ", "))
	}
	return spec, nil
}

// KeyUsageFor (kms.ts keyUsageFor): The usage a new key gets: the one its spec allows, or (for RSA) the one asked
// for.
func KeyUsageFor(spec string, value any) (result string, err error) {
	if kmsSpec(spec) == nil {
		return "", errors.New("Cannot read properties of undefined (reading 'usages')")
	}
	usages := kmsSpecUsages(spec)
	if isUndefined(value) {
		if len(usages) == 1 {
			return usages[0], nil
		}
		return "", invalidInput("keyUsage is required for " + spec + " (encrypt or sign)")
	}
	usage, ok := value.(string)
	if !ok || !containsString(usages, usage) {
		return "", invalidInput(spec + " keys support keyUsage " + strings.Join(usages, " or "))
	}
	return usage, nil
}

// KeyTags (kms.ts keyTags): Up to 50 tags; keys are identifiers, values short strings (they become
// `resource.tags.{key}`).
func KeyTags(value any) (result *core.Object, err error) {
	if isUndefined(value) {
		return core.NewObject(), nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	if input.Len() > 50 {
		return nil, invalidInput("At most 50 tags")
	}
	tags := core.NewObject()
	for _, key := range input.Keys() {
		item := input.Get(key)
		if !kmsTagKey.MatchString(key) || kmsUnsafeKeys[key] {
			return nil, invalidInput("Invalid tag key " + key)
		}
		text, ok := item.(string)
		if !ok || utf16Len(text) > 256 || hasC0Control(text) {
			return nil, invalidInput("Tag " + key + " must be a string of at most 256 characters")
		}
		tags.Set(key, text)
	}
	return tags, nil
}

// EncryptionContext (kms.ts encryptionContext): An encryption context: up to 16 non-secret key/value pairs bound to
// a ciphertext as additional authenticated data. Decryption must present the same pairs. They are recorded in the
// audit trail and exposed to policies as `resource.encryptionContext.{key}`, so never put secrets in them. name is
// "encryptionContext" when empty.
func EncryptionContext(value any, name string) (result *core.Object, err error) {
	if name == "" {
		name = "encryptionContext"
	}
	if isUndefined(value) {
		return core.NewObject(), nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	if input.Len() > 16 {
		return nil, invalidInput(name + " has more than 16 pairs")
	}
	context := core.NewObject()
	for _, key := range input.Keys() {
		item := input.Get(key)
		if !kmsContextKey.MatchString(key) || kmsUnsafeKeys[key] {
			return nil, invalidInput("Invalid " + name + " key " + key)
		}
		text, ok := item.(string)
		if !ok || text == "" || utf16Len(text) > 1024 || hasC0Control(text) {
			return nil, invalidInput(name + " values must be non-empty strings of at most 1024 characters")
		}
		context.Set(key, text)
	}
	return context, nil
}

// Base64Bytes (kms.ts base64Bytes): Decodes canonical standard or URL-safe base64 (padding optional), refusing
// anything else and anything longer than `max` bytes. Canonical only: one byte string has one accepted spelling, so
// string-keyed replay caches hold.
func Base64Bytes(value any, name string, maxValue float64) (result []byte, err error) {
	text, isString := value.(string)
	urlSafe := isString && kmsBase64URLAny.MatchString(text)
	if !isString || float64(utf16Len(text)) > math.Ceil(maxValue*4/3)+4 || !(urlSafe || kmsBase64Std.MatchString(text)) {
		return nil, invalidInput(name + " must be base64")
	}
	bytes := nodeBase64Decode(text)
	var again string
	if urlSafe {
		again = base64url(bytes)
	} else {
		again = base64.StdEncoding.EncodeToString(bytes)
	}
	if kmsTrailingEqual.ReplaceAllString(again, "") != kmsTrailingEqual.ReplaceAllString(text, "") {
		return nil, invalidInput(name + " must be canonical base64")
	}
	if float64(len(bytes)) > maxValue {
		return nil, invalidInput(name + " is longer than " + core.NumberString(maxValue) + " bytes")
	}
	return bytes, nil
}

// Payload (kms.ts payload): Reads a payload given as text (`{name}`, UTF-8) or bytes (`{name}Base64`): exactly one
// of the two. Says which, so decryption can return the same form: `{ bytes: []byte, text: bool }`.
func Payload(input *core.Object, name string, maxValue float64) (result *core.Object, err error) {
	plain := input.Get(name)
	encoded := input.Get(name + "Base64")
	if isUndefined(plain) == isUndefined(encoded) {
		return nil, invalidInput("Provide either " + name + " or " + name + "Base64")
	}
	if !isUndefined(plain) {
		text, ok := plain.(string)
		if !ok {
			return nil, invalidInput(name + " must be a string")
		}
		bytes := utf8Bytes(text)
		if float64(len(bytes)) > maxValue {
			return nil, invalidInput(name + " is longer than " + core.NumberString(maxValue) + " bytes")
		}
		return core.NewObject().SetRaw("bytes", bytes).SetRaw("text", true), nil
	}
	bytes, err := Base64Bytes(encoded, name+"Base64", maxValue)
	if err != nil {
		return nil, err
	}
	return core.NewObject().SetRaw("bytes", bytes).SetRaw("text", false), nil
}

// payloadBytes reads the bytes of a Payload result.
func payloadBytes(payload *core.Object) []byte {
	bytes, _ := payload.Get("bytes").([]byte)
	return bytes
}

// KeyAlgorithms (kms.ts keyAlgorithms): The algorithms a key signs or computes MACs with (encryption keys: none).
func KeyAlgorithms(key *core.Object) (result []string, err error) {
	spec := jsString(key.Get("keySpec"))
	usage := key.Get("keyUsage")
	if usage == "mac" {
		hashName := kmsSpecString(spec, "hash")
		if len(hashName) < 3 {
			return nil, errors.New("Cannot read properties of undefined (reading 'slice')")
		}
		return []string{"HS" + hashName[3:]}, nil
	}
	if usage != "sign" {
		return []string{}, nil
	}
	switch kmsSpecFamily(spec) {
	case "ec":
		if kmsSpecString(spec, "curve") == "P-256" {
			return []string{"ES256"}, nil
		}
		return []string{"ES384"}, nil
	case "ed25519":
		return []string{"EdDSA"}, nil
	}
	return []string{"PS256", "PS384", "PS512", "RS256", "RS384", "RS512"}, nil
}

// SigningAlgorithm (kms.ts signingAlgorithm) is the algorithm a call names, or the key's first.
func SigningAlgorithm(key *core.Object, value any) (result string, err error) {
	supported, err := KeyAlgorithms(key)
	if err != nil {
		return "", err
	}
	if isUndefined(value) {
		if len(supported) == 0 {
			return "", nil
		}
		return supported[0], nil
	}
	algorithm, ok := value.(string)
	if !ok || !containsString(supported, algorithm) {
		return "", invalidInput("This key supports the algorithms " + strings.Join(supported, ", "))
	}
	return algorithm, nil
}

// SummarizeKey (kms.ts summarizeKey) is the public view of a key: never its material.
func SummarizeKey(key *core.Object, aliases []string) (result *core.Object, err error) {
	algorithms, err := KeyAlgorithms(key)
	if err != nil {
		return nil, err
	}
	tags := core.NewObject()
	if stored, ok := key.Get("tags").(*core.Object); ok {
		tags = stored.Clone()
	}
	summary := core.NewObject(
		"id", key.Get("id"),
		"tenantId", key.Get("tenantId"),
		"keySpec", key.Get("keySpec"),
		"keyUsage", key.Get("keyUsage"),
		"state", key.Get("state"),
		"currentVersion", key.Get("currentVersion"),
		"tags", tags,
		"aliases", stringsOf(kmsSortedStrings(aliases)),
		"algorithms", stringsOf(algorithms),
		"createdAt", key.Get("createdAt"),
		"createdBy", key.Get("createdBy"),
		"updatedAt", key.Get("updatedAt"),
	)
	for _, name := range []string{"description", "rotationPeriodDays", "nextRotationAt", "lastRotatedAt", "deletionDate", "managedBy", "managedId"} {
		if value := key.Get(name); !isUndefined(value) {
			summary.Set(name, value)
		}
	}
	return summary, nil
}

// AssertUnmanaged (kms.ts assertUnmanaged): Refuses direct cryptographic use of a key another module owns
// (`KEY_MANAGED`).
func AssertUnmanaged(key *core.Object) (err error) {
	managedBy := key.Get("managedBy")
	if !truthy(managedBy) {
		return nil
	}
	message := "This key protects a data protection profile; use the protection API"
	if managedBy == "pki" {
		message = "This key signs for a certificate authority; issue certificates through the pki API"
	}
	return core.NewIamError("KEY_MANAGED", message, 409)
}

// kmsGrantActive is `grant.expiresAt === undefined || grant.expiresAt > now`.
func kmsGrantActive(grant *core.Object, now float64) bool {
	expiresAt := grant.Get("expiresAt")
	if isUndefined(expiresAt) {
		return true
	}
	value, ok := expiresAt.(float64)
	return ok && value > now
}

// SummarizeGrant (kms.ts summarizeGrant) is the public view of a grant, with whether it is active.
func SummarizeGrant(grant *core.Object, now int64) (result *core.Object, err error) {
	summary := core.NewObject(
		"id", grant.Get("id"),
		"tenantId", grant.Get("tenantId"),
		"keyId", grant.Get("keyId"),
		"granteeType", grant.Get("granteeType"),
		"granteeId", grant.Get("granteeId"),
		"operations", core.CloneValue(grant.Get("operations")),
		"active", kmsGrantActive(grant, float64(now)),
		"createdAt", grant.Get("createdAt"),
		"createdBy", grant.Get("createdBy"),
	)
	if name := grant.Get("name"); !isUndefined(name) {
		summary.Set("name", name)
	}
	if constraints := grant.Get("constraints"); !isUndefined(constraints) {
		summary.Set("constraints", core.CloneValue(constraints))
	}
	if expiresAt := grant.Get("expiresAt"); !isUndefined(expiresAt) {
		summary.Set("expiresAt", expiresAt)
	}
	return summary, nil
}

// KeyAttributes (kms.ts keyAttributes): The attributes a key presents to policies (`resource.{name}`): identity,
// spec, usage, state, aliases, tags as `resource.tags.{key}`, and for calls with one the encryption context as
// `resource.encryptionContext.{key}` plus `resource.encryptionContextKeys`, and a signing call's
// `resource.algorithm`. extra may name `context` (an object) and `algorithm` (a string).
func KeyAttributes(key *core.Object, aliases []string, extra *core.Object) (result *core.Object, err error) {
	attributes := core.NewObject(
		"keyId", key.Get("id"),
		"keySpec", key.Get("keySpec"),
		"keyUsage", key.Get("keyUsage"),
		"keyState", key.Get("state"),
		"aliases", stringsOf(kmsSortedStrings(aliases)),
		"createdBy", key.Get("createdBy"),
	)
	if managedBy := key.Get("managedBy"); truthy(managedBy) {
		attributes.Set("managedBy", managedBy)
	}
	if tags, ok := key.Get("tags").(*core.Object); ok {
		for _, name := range tags.Keys() {
			attributes.Set("tags."+name, tags.Get(name))
		}
	}
	if extra != nil {
		if context, ok := extra.Get("context").(*core.Object); ok && context != nil {
			keys := kmsSortedStrings(context.Keys())
			attributes.Set("encryptionContextKeys", stringsOf(keys))
			for _, name := range keys {
				attributes.Set("encryptionContext."+name, context.Get(name))
			}
		}
		if algorithm := extra.Get("algorithm"); !isUndefined(algorithm) {
			attributes.Set("algorithm", algorithm)
		}
	}
	return attributes, nil
}

// RequestAttributes (kms.ts requestAttributes): Attributes for creating a key: what it would be, so policies can
// require tags or specs (`resource.tags.team`).
func RequestAttributes(spec string, usage string, tags *core.Object) (result *core.Object, err error) {
	attributes := core.NewObject("keySpec", spec, "keyUsage", usage)
	if tags != nil {
		for _, name := range tags.Keys() {
			attributes.Set("tags."+name, tags.Get(name))
		}
	}
	return attributes, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Key material

func kmsPem(kind string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
}

// kmsGenerateMaterial is new key material: raw bytes (base64url) for AES and HMAC keys, a PKCS#8 PEM private key
// otherwise (with the SPKI PEM public key).
func kmsGenerateMaterial(spec string) (material string, publicKeyPem string, err error) {
	var private crypto.Signer
	switch kmsSpecFamily(spec) {
	case "aes":
		return base64url(kmsRandomBytes(32)), "", nil
	case "hmac":
		return base64url(kmsRandomBytes(int(kmsSpecSize(spec)))), "", nil
	case "ec":
		curve := elliptic.P256()
		if kmsSpecString(spec, "curve") == "P-384" {
			curve = elliptic.P384()
		}
		private, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "ed25519":
		_, private, err = ed25519.GenerateKey(rand.Reader)
	case "rsa":
		private, err = rsa.GenerateKey(rand.Reader, int(kmsSpecSize(spec)))
	default:
		return "", "", errors.New("Cannot read properties of undefined (reading 'family')")
	}
	if err != nil {
		return "", "", err
	}
	privateDer, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return "", "", err
	}
	publicDer, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		return "", "", err
	}
	return kmsPem("PRIVATE KEY", privateDer), kmsPem("PUBLIC KEY", publicDer), nil
}

// AddKeyVersion (kms.ts addKeyVersion): Generates, seals and stores a new version of a key.
func AddKeyVersion(ctx context.Context, server *ServerContext, tx core.IamStore, key *core.Object, version float64, origin string) (result *core.Object, err error) {
	material, publicKeyPem, err := kmsGenerateMaterial(jsString(key.Get("keySpec")))
	if err != nil {
		return nil, err
	}
	keyID := jsString(key.Get("id"))
	record := core.NewObject(
		"id", ID(),
		"tenantId", key.Get("tenantId"),
		"uniqueKey", keyID+":"+core.NumberString(version),
		"keyId", keyID,
		"version", version,
		"wrapper", "secret",
		"materialSealed", auth.EncryptSecret(material, server.Options.Secret, kmsVersionContext(keyID, version)),
		"createdAt", float64(server.Now()),
		"origin", origin,
	)
	if publicKeyPem != "" {
		record.Set("publicKeyPem", publicKeyPem)
	}
	return tx.Insert(ctx, "kmsKeyVersions", record)
}

// KeyVersion (kms.ts keyVersion) is one stored version of a key.
func KeyVersion(ctx context.Context, tx core.IamStore, key *core.Object, version float64) (result *core.Object, err error) {
	found, err := tx.Find(ctx, "kmsKeyVersions", core.NewObject(
		"tenantId", key.Get("tenantId"),
		"uniqueKey", jsString(key.Get("id"))+":"+core.NumberString(version),
	), nil)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, core.NewIamError("NOT_FOUND", "Key version not found", 404)
	}
	return found[0], nil
}

// kmsOpenMaterial opens a version's sealed material with the deployment secret (or a previous one during a
// rotation).
func kmsOpenMaterial(server *ServerContext, version *core.Object) (string, error) {
	sealed, _ := version.Get("materialSealed").(string)
	secrets := append([]string{server.Options.Secret}, server.Options.PreviousSecrets...)
	opened, ok := auth.OpenSecret(sealed, secrets, kmsVersionContext(jsString(version.Get("keyId")), jsNumber(version.Get("version"))))
	if !ok {
		return "", core.NewIamError("KEY_MATERIAL_UNAVAILABLE", "The key material cannot be opened with the configured secrets", 500)
	}
	return opened.Value, nil
}

func kmsSymmetricKey(server *ServerContext, version *core.Object) ([]byte, error) {
	material, err := kmsOpenMaterial(server, version)
	if err != nil {
		return nil, err
	}
	return nodeBase64Decode(material), nil
}

func kmsPrivateKey(server *ServerContext, version *core.Object) (crypto.Signer, error) {
	material, err := kmsOpenMaterial(server, version)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(material))
	if block == nil {
		return nil, errors.New("error:1E08010C:DECODER routines::unsupported")
	}
	var parsed any
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported private key")
	}
	return signer, nil
}

func kmsPublicKey(version *core.Object) (crypto.PublicKey, error) {
	pemText, _ := version.Get("publicKeyPem").(string)
	if pemText == "" {
		return nil, invalidInput("This key has no public key")
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("error:1E08010C:DECODER routines::unsupported")
	}
	if block.Type == "RSA PUBLIC KEY" {
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// ---------------------------------------------------------------------------------------------------------------
// Ciphertexts: `kms1.{keyId}.{version}.{t|b}.{payload}`. The header (with the plaintext form `t` text / `b` bytes)
// and the canonical encryption context are authenticated; the payload is iv|tag|ciphertext (AES-GCM) or the
// RSA-OAEP (SHA-256) ciphertext, whose label carries the same associated data.

func kmsInvalidCiphertext() *core.IamError {
	return core.NewIamError("INVALID_CIPHERTEXT", "The ciphertext is not valid", 400)
}

// ParseCiphertext (kms.ts parseCiphertext) reads a ciphertext's header: `{ keyId, version, text, payload, header }`
// (payload is a []byte).
func ParseCiphertext(value any) (result *core.Object, err error) {
	text, ok := value.(string)
	if !ok || utf16Len(text) > kmsMaxCiphertextChars {
		return nil, kmsInvalidCiphertext()
	}
	parts := strings.Split(text, ".")
	if len(parts) != 5 || parts[0] != kmsCiphertextPrefix {
		return nil, kmsInvalidCiphertext()
	}
	keyID, versionText, form, encoded := parts[1], parts[2], parts[3], parts[4]
	if !kmsKeyIDPattern.MatchString(keyID) || !kmsVersionText.MatchString(versionText) {
		return nil, kmsInvalidCiphertext()
	}
	if form != "t" && form != "b" {
		return nil, kmsInvalidCiphertext()
	}
	if !kmsBase64URL.MatchString(encoded) {
		return nil, kmsInvalidCiphertext()
	}
	payload := nodeBase64Decode(encoded)
	// One spelling per ciphertext: non-canonical trailing bits would give the same bytes several string forms.
	if base64url(payload) != encoded {
		return nil, kmsInvalidCiphertext()
	}
	return core.NewObject(
		"keyId", keyID,
		"version", stringToNumber(versionText),
		"text", form == "t",
	).SetRaw("payload", payload).Set("header", kmsCiphertextPrefix+"."+keyID+"."+versionText+"."+form), nil
}

// kmsAssociatedData is the header and the canonical encryption context, as authenticated data.
func kmsAssociatedData(header string, context *core.Object) ([]byte, error) {
	if context == nil {
		context = core.NewObject()
	}
	canonical, err := core.CanonicalizeJSON(context)
	if err != nil {
		return nil, err
	}
	return utf8Bytes(header + "\n" + canonical), nil
}

func kmsOaepCapacity(spec string) float64 { return kmsSpecSize(spec)/8 - 2*32 - 2 }

func kmsGcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// kmsGcmSeal is AES-256-GCM with a fresh IV: iv|tag|ciphertext.
func kmsGcmSeal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := kmsGcm(key)
	if err != nil {
		return nil, err
	}
	iv := kmsRandomBytes(12)
	sealed := gcm.Seal(nil, iv, plaintext, aad)
	encrypted, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	out := make([]byte, 0, 12+16+len(encrypted))
	out = append(out, iv...)
	out = append(out, tag...)
	return append(out, encrypted...), nil
}

// kmsGcmOpen opens iv|tag|ciphertext (at least 28 bytes).
func kmsGcmOpen(key, payload, aad []byte) ([]byte, error) {
	if len(payload) < 28 {
		return nil, errors.New("short")
	}
	gcm, err := kmsGcm(key)
	if err != nil {
		return nil, err
	}
	sealed := append(append([]byte{}, payload[28:]...), payload[12:28]...)
	return gcm.Open(nil, payload[:12], sealed, aad)
}

// EncryptWith (kms.ts encryptWith) encrypts under one version of a key, bound to the encryption context.
func EncryptWith(server *ServerContext, key *core.Object, version *core.Object, plaintext []byte, isText bool, context *core.Object) (result string, err error) {
	form := "b"
	if isText {
		form = "t"
	}
	spec := jsString(key.Get("keySpec"))
	header := kmsCiphertextPrefix + "." + jsString(key.Get("id")) + "." + core.NumberString(jsNumber(version.Get("version"))) + "." + form
	aad, err := kmsAssociatedData(header, context)
	if err != nil {
		return "", err
	}
	if kmsSpecFamily(spec) == "rsa" {
		capacity := kmsOaepCapacity(spec)
		if float64(len(plaintext)) > capacity {
			return "", invalidInput(spec + " keys encrypt at most " + core.NumberString(capacity) + " bytes; encrypt a data key instead")
		}
		public, err := kmsPublicKey(version)
		if err != nil {
			return "", err
		}
		rsaKey, ok := public.(*rsa.PublicKey)
		if !ok {
			return "", errors.New("error:02000068:rsa routines::bad signature")
		}
		encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, plaintext, aad)
		if err != nil {
			return "", err
		}
		return header + "." + base64url(encrypted), nil
	}
	if len(plaintext) > MaxPlaintextBytes {
		return "", invalidInput("Encrypt at most " + core.NumberString(MaxPlaintextBytes) + " bytes directly; use generateDataKey for more")
	}
	symmetric, err := kmsSymmetricKey(server, version)
	if err != nil {
		return "", err
	}
	sealed, err := kmsGcmSeal(symmetric, plaintext, aad)
	if err != nil {
		return "", err
	}
	return header + "." + base64url(sealed), nil
}

// DecryptWith (kms.ts decryptWith): Decrypts; any tampering, wrong key version or different encryption context fails
// the same way.
func DecryptWith(server *ServerContext, key *core.Object, version *core.Object, parsed *core.Object, context *core.Object) (result []byte, err error) {
	aad, err := kmsAssociatedData(jsString(parsed.Get("header")), context)
	if err != nil {
		return nil, err
	}
	payload, _ := parsed.Get("payload").([]byte)
	opened, err := func() ([]byte, error) {
		if kmsSpecFamily(jsString(key.Get("keySpec"))) == "rsa" {
			private, err := kmsPrivateKey(server, version)
			if err != nil {
				return nil, err
			}
			rsaKey, ok := private.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("not an RSA key")
			}
			return rsa.DecryptOAEP(sha256.New(), nil, rsaKey, payload, aad)
		}
		if len(payload) < 28 {
			return nil, errors.New("short")
		}
		symmetric, err := kmsSymmetricKey(server, version)
		if err != nil {
			return nil, err
		}
		return kmsGcmOpen(symmetric, payload, aad)
	}()
	if err != nil {
		if known, ok := asIamError(err); ok && known.Code == "KEY_MATERIAL_UNAVAILABLE" {
			return nil, err
		}
		return nil, core.NewIamError("INVALID_CIPHERTEXT", "The ciphertext could not be decrypted with this key and encryption context", 400)
	}
	if opened == nil {
		opened = []byte{}
	}
	return opened, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Signatures and MACs

// kmsHashOf is the hash an algorithm names (sha256 by default).
func kmsHashOf(algorithm string) crypto.Hash {
	switch {
	case strings.HasSuffix(algorithm, "384"):
		return crypto.SHA384
	case strings.HasSuffix(algorithm, "512"):
		return crypto.SHA512
	}
	return crypto.SHA256
}

func kmsDigest(algorithm string, message []byte) (crypto.Hash, []byte) {
	hashID := kmsHashOf(algorithm)
	hasher := hashID.New()
	hasher.Write(message)
	return hashID, hasher.Sum(nil)
}

func kmsCurveBytes(curve elliptic.Curve) int { return (curve.Params().BitSize + 7) / 8 }

// SignWith (kms.ts signWith) signs with one version's private key; format is "der" (default) or "jose" (ECDSA as
// raw r||s).
func SignWith(server *ServerContext, version *core.Object, algorithm string, message []byte, format string) (result []byte, err error) {
	if format == "" {
		format = "der"
	}
	private, err := kmsPrivateKey(server, version)
	if err != nil {
		return nil, err
	}
	if algorithm == "EdDSA" {
		key, ok := private.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("error:1C8000E6:Provider routines::invalid digest")
		}
		return ed25519.Sign(key, message), nil
	}
	hashID, digest := kmsDigest(algorithm, message)
	if strings.HasPrefix(algorithm, "ES") {
		key, ok := private.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("error:1C8000E6:Provider routines::invalid digest")
		}
		if format == "jose" {
			r, s, err := ecdsa.Sign(rand.Reader, key, digest)
			if err != nil {
				return nil, err
			}
			size := kmsCurveBytes(key.Curve)
			out := make([]byte, 2*size)
			r.FillBytes(out[:size])
			s.FillBytes(out[size:])
			return out, nil
		}
		return ecdsa.SignASN1(rand.Reader, key, digest)
	}
	key, ok := private.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("error:1C8000E6:Provider routines::invalid digest")
	}
	if strings.HasPrefix(algorithm, "PS") {
		return rsa.SignPSS(rand.Reader, key, hashID, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hashID})
	}
	return rsa.SignPKCS1v15(nil, key, hashID, digest)
}

// VerifyWith (kms.ts verifyWith) checks a signature with one version's public key; a malformed signature is false.
func VerifyWith(version *core.Object, algorithm string, message []byte, signature []byte, format string) (result bool, err error) {
	if format == "" {
		format = "der"
	}
	public, err := kmsPublicKey(version)
	if err != nil {
		return false, err
	}
	if algorithm == "EdDSA" {
		key, ok := public.(ed25519.PublicKey)
		return ok && len(signature) == ed25519.SignatureSize && ed25519.Verify(key, message, signature), nil
	}
	hashID, digest := kmsDigest(algorithm, message)
	if strings.HasPrefix(algorithm, "ES") {
		key, ok := public.(*ecdsa.PublicKey)
		if !ok {
			return false, nil
		}
		if format == "jose" {
			size := kmsCurveBytes(key.Curve)
			if len(signature) != 2*size {
				return false, nil
			}
			r := new(big.Int).SetBytes(signature[:size])
			s := new(big.Int).SetBytes(signature[size:])
			return ecdsa.Verify(key, digest, r, s), nil
		}
		return ecdsa.VerifyASN1(key, digest, signature), nil
	}
	key, ok := public.(*rsa.PublicKey)
	if !ok {
		return false, nil
	}
	if strings.HasPrefix(algorithm, "PS") {
		return rsa.VerifyPSS(key, hashID, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hashID}) == nil, nil
	}
	return rsa.VerifyPKCS1v15(key, hashID, digest, signature) == nil, nil
}

// MacWith (kms.ts macWith) is the HMAC of a message with one version of a MAC key.
func MacWith(server *ServerContext, key *core.Object, version *core.Object, message []byte) (result []byte, err error) {
	var constructor func() hash.Hash
	switch kmsSpecString(jsString(key.Get("keySpec")), "hash") {
	case "sha256":
		constructor = sha256.New
	case "sha384":
		constructor = sha512.New384
	case "sha512":
		constructor = sha512.New
	default:
		return nil, errors.New("Invalid digest: undefined")
	}
	symmetric, err := kmsSymmetricKey(server, version)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(constructor, symmetric)
	mac.Write(message)
	return mac.Sum(nil), nil
}

// SameBytes (kms.ts sameBytes) compares in constant time.
func SameBytes(left []byte, right []byte) (result bool, err error) {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1, nil
}

// kmsPublicJwk is kms.ts publicJwk: the public key of an asymmetric version as a JWK, `kid` = `{keyId}.{version}`.
func kmsPublicJwk(key *core.Object, version *core.Object) (*core.Object, error) {
	public, err := kmsPublicKey(version)
	if err != nil {
		return nil, err
	}
	var jwk *core.Object
	switch typed := public.(type) {
	case *ecdsa.PublicKey:
		size := kmsCurveBytes(typed.Curve)
		x, y := make([]byte, size), make([]byte, size)
		typed.X.FillBytes(x)
		typed.Y.FillBytes(y)
		jwk = core.NewObject("kty", "EC", "x", base64url(x), "y", base64url(y), "crv", typed.Curve.Params().Name)
	case ed25519.PublicKey:
		jwk = core.NewObject("crv", "Ed25519", "x", base64url(typed), "kty", "OKP")
	case *rsa.PublicKey:
		jwk = core.NewObject("kty", "RSA", "n", base64url(typed.N.Bytes()), "e", base64url(big.NewInt(int64(typed.E)).Bytes()))
	default:
		return nil, errors.New("unsupported public key")
	}
	use := "enc"
	if key.Get("keyUsage") == "sign" {
		use = "sig"
	}
	jwk.Set("kid", jsString(key.Get("id"))+"."+core.NumberString(jsNumber(version.Get("version"))))
	jwk.Set("use", use)
	algorithms, err := KeyAlgorithms(key)
	if err != nil {
		return nil, err
	}
	if key.Get("keyUsage") == "sign" && len(algorithms) == 1 {
		jwk.Set("alg", algorithms[0])
	}
	// No `alg` for RSA encryption keys: KMS binds its header and encryption context as the OAEP label, so what a
	// plain RSA-OAEP-256 encrypter produces offline is not a KMS ciphertext.
	return jwk, nil
}

// ParseKid (kms.ts parseKid): A JWT `kid` of the form `{keyId}.{version}` (nil when it is not one).
func ParseKid(value any) (result *core.Object, err error) {
	text, ok := value.(string)
	if !ok {
		return nil, nil
	}
	match := kmsKidPattern.FindStringSubmatch(text)
	if match == nil {
		return nil, nil
	}
	return core.NewObject("keyId", match[1], "version", stringToNumber(match[2])), nil
}

// ---------------------------------------------------------------------------------------------------------------
// Grants

// GrantOperations (kms.ts grantOperations) validates the operations of a grant on a key of the usage.
func GrantOperations(value any, usage string) (result []string, err error) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 || len(list) > 8 {
		return nil, invalidInput("operations must list 1-8 grant operations")
	}
	allowed := kmsOperationsByUsage[usage]
	operations := newOrderedSet()
	for _, operation := range list {
		text, ok := operation.(string)
		if !ok || !containsString(allowed, text) {
			return nil, invalidInput("A " + usage + " key's grants may allow " + strings.Join(allowed, ", "))
		}
		operations.Add(text)
	}
	return kmsSortedStrings(operations.Values()), nil
}

// GrantConstraints (kms.ts grantConstraints) validates a grant's encryption context constraints (nil when none).
func GrantConstraints(value any, operations []string) (result *core.Object, err error) {
	if isUndefined(value) {
		return nil, nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	for _, name := range input.Keys() {
		if name != "encryptionContextEquals" && name != "encryptionContextSubset" {
			return nil, invalidInput("Unknown grant constraint " + name)
		}
	}
	constraints := core.NewObject()
	if equals := input.Get("encryptionContextEquals"); !isUndefined(equals) {
		context, err := EncryptionContext(equals, "encryptionContextEquals")
		if err != nil {
			return nil, err
		}
		constraints.Set("encryptionContextEquals", context)
	}
	if subset := input.Get("encryptionContextSubset"); !isUndefined(subset) {
		context, err := EncryptionContext(subset, "encryptionContextSubset")
		if err != nil {
			return nil, err
		}
		constraints.Set("encryptionContextSubset", context)
	}
	if constraints.Len() == 0 {
		return nil, invalidInput("constraints must name an encryption context")
	}
	for _, operation := range operations {
		if !kmsContextOperations[operation] {
			return nil, invalidInput("Encryption context constraints apply only to encrypt, decrypt and generate-data-key grants")
		}
	}
	return constraints, nil
}

// kmsContextSatisfies says whether an encryption context meets a grant's constraints.
func kmsContextSatisfies(constraints any, context *core.Object) bool {
	limits, ok := constraints.(*core.Object)
	if !ok || limits == nil {
		return true
	}
	actual := context
	if actual == nil {
		actual = core.NewObject()
	}
	if wanted, ok := limits.Get("encryptionContextEquals").(*core.Object); ok && wanted != nil {
		if wanted.Len() != actual.Len() {
			return false
		}
		for _, key := range wanted.Keys() {
			if !core.StrictEquals(actual.Get(key), wanted.Get(key)) {
				return false
			}
		}
	}
	if subset, ok := limits.Get("encryptionContextSubset").(*core.Object); ok && subset != nil {
		for _, key := range subset.Keys() {
			if !actual.Has(key) || !core.StrictEquals(actual.Get(key), subset.Get(key)) {
				return false
			}
		}
	}
	return true
}

// kmsActsInOwnRight is kms.ts actsInOwnRight: a session that acts in its own right: a user session or an API key,
// not derived, not "view as".
func kmsActsInOwnRight(principal *Principal) bool {
	session := principal.Session
	kind := session.Get("kind")
	return (kind == "user" || kind == "api-key") && !truthy(session.Get("impersonatorId")) && isUndefined(session.Get("sourceSessionId"))
}

// CandidateGrants (kms.ts candidateGrants): The live grants on the key that allow `operation` to the principal's own
// identity, satisfying their constraints, oldest first. Grants serve people and machine accounts acting in their own
// right (user sessions and API keys): assumed roles, session tokens, delegated agent sessions and impersonation
// never use them. The caller still checks that each grant's creator could make the call now (api/keys.ts), so a
// grant never outlives its creator's access.
func CandidateGrants(ctx context.Context, server *ServerContext, tx core.IamStore, key *core.Object, principal *Principal, operation string, context *core.Object) (result []*core.Object, err error) {
	if !kmsActsInOwnRight(principal) || !core.StrictEquals(principal.Session.Get("tenantId"), key.Get("tenantId")) ||
		!core.StrictEquals(principal.Identity.Get("tenantId"), key.Get("tenantId")) {
		return []*core.Object{}, nil
	}
	now := float64(server.Now())
	grants, err := tx.Find(ctx, "kmsGrants", core.NewObject(
		"tenantId", key.Get("tenantId"),
		"keyId", key.Get("id"),
		"granteeId", principal.Identity.Get("id"),
	), nil)
	if err != nil {
		return nil, err
	}
	result = []*core.Object{}
	for _, grant := range grants {
		if grant.Get("granteeType") == "identity" && kmsGrantActive(grant, now) &&
			containsString(kmsStringList(grant.Get("operations")), operation) && kmsContextSatisfies(grant.Get("constraints"), context) {
			result = append(result, grant)
		}
	}
	sortStable(result, func(a, b *core.Object) int {
		if difference := jsNumber(a.Get("createdAt")) - jsNumber(b.Get("createdAt")); difference != 0 && !math.IsNaN(difference) {
			if difference < 0 {
				return -1
			}
			return 1
		}
		if jsString(a.Get("id")) < jsString(b.Get("id")) {
			return -1
		}
		return 1
	})
	return result, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Lookups

// FindKey (kms.ts findKey): A key by id or `alias/{name}` within a tenant.
func FindKey(ctx context.Context, tx core.IamStore, tenantID string, reference any) (result *core.Object, err error) {
	value, err := Text(reference, "keyId", 256)
	if err != nil {
		return nil, err
	}
	notFound := core.NewIamError("NOT_FOUND", "Key not found", 404)
	var key *core.Object
	if strings.HasPrefix(value, "alias/") {
		aliases, err := tx.Find(ctx, "kmsAliases", core.NewObject("tenantId", tenantID, "uniqueKey", value), nil)
		if err != nil {
			return nil, err
		}
		if len(aliases) > 0 {
			if key, err = tx.Get(ctx, "kmsKeys", jsString(aliases[0].Get("keyId"))); err != nil {
				return nil, err
			}
		}
	} else if kmsKeyIDPattern.MatchString(value) {
		if key, err = tx.Get(ctx, "kmsKeys", value); err != nil {
			return nil, err
		}
	}
	if key == nil || key.Get("tenantId") != tenantID {
		return nil, notFound
	}
	return key, nil
}

// AliasNames (kms.ts aliasNames): the names of a key's aliases, sorted.
func AliasNames(ctx context.Context, tx core.IamStore, key *core.Object) (result []string, err error) {
	aliases, err := tx.Find(ctx, "kmsAliases", core.NewObject("tenantId", key.Get("tenantId"), "keyId", key.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(aliases))
	for index, alias := range aliases {
		names[index] = jsString(alias.Get("name"))
	}
	return kmsSortedStrings(names), nil
}

// AssertUsable (kms.ts assertUsable) refuses keys that are not enabled or not for the usage.
func AssertUsable(key *core.Object, usage string) (err error) {
	state := key.Get("state")
	if state != "enabled" {
		message := "The key is pending deletion"
		if state == "disabled" {
			message = "The key is disabled"
		}
		return core.NewIamError("KEY_STATE_INVALID", message, 409)
	}
	if key.Get("keyUsage") != usage {
		return invalidInput("This key is for " + jsString(key.Get("keyUsage")) + ", not " + usage)
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------
// Service helpers for other modules (the secrets vault, data protection): encryption under a tenant key without a
// caller permission check. The calling module authorizes its own caller; the key's state is still enforced and the
// use is audited. A use is `{ via, principal? }`: the module using the key, recorded as `metadata.via`, and the
// caller it acts for, recorded as the event's actor (otherwise `deployment-operator`).

// kmsUsePrincipal reads the principal of a service use (a *Principal, or one normalized into an object).
func kmsUsePrincipal(use *core.Object) *Principal {
	if use == nil {
		return nil
	}
	switch value := use.Get("principal").(type) {
	case *Principal:
		return value
	case *core.Object:
		identity, _ := value.Get("Identity").(*core.Object)
		session, _ := value.Get("Session").(*core.Object)
		if identity == nil || session == nil {
			return nil
		}
		proof, _ := value.Get("DeviceProof").(string)
		return &Principal{Identity: identity, Session: session, DeviceProof: proof}
	}
	return nil
}

func kmsServiceAudit(ctx context.Context, server *ServerContext, tx core.IamStore, use *core.Object, action string, key *core.Object, metadata *core.Object) error {
	var via any = "service"
	if use != nil {
		via = use.Get("via")
	}
	viaText, err := Text(via, "via", 64)
	if err != nil {
		return err
	}
	details := metadata.Spread()
	details.Set("via", viaText)
	tenantID := jsString(key.Get("tenantId"))
	resourceID := "kms/" + jsString(key.Get("id"))
	if principal := kmsUsePrincipal(use); principal != nil {
		return server.Events.Audit(ctx, tx, principal, action, tenantID, resourceID, "allow", false, details)
	}
	return server.Events.RecordAudit(ctx, tx, core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"actorId", "deployment-operator",
		"action", action,
		"resourceId", resourceID,
		"timestamp", float64(server.Now()),
		"outcome", "allow",
		"metadata", details,
	))
}

// kmsServiceContext is a service call's context: a string is bound as `{ context }`.
func kmsServiceContext(context any) (*core.Object, error) {
	if text, ok := context.(string); ok {
		value, err := Text(text, "context", 1024)
		if err != nil {
			return nil, err
		}
		return core.NewObject("context", value), nil
	}
	if object, ok := context.(*core.Object); ok && object == nil {
		context = core.Undefined
	}
	return EncryptionContext(context, "")
}

// kmsObjectContext is encryptionContext(context) for a context the caller passed as an object (nil = undefined).
func kmsObjectContext(context *core.Object) (*core.Object, error) {
	if context == nil {
		return EncryptionContext(core.Undefined, "")
	}
	return EncryptionContext(context, "")
}

// kmsServiceKey checks a key the service helpers accept: AES only, since they wrap data keys of any payload size.
func kmsServiceKey(key *core.Object) error {
	if err := AssertUsable(key, "encrypt"); err != nil {
		return err
	}
	if key.Get("keySpec") != "aes-256-gcm" {
		return invalidInput("Only aes-256-gcm keys can protect stored values")
	}
	return nil
}

func kmsUseMetadata(version *core.Object, bound *core.Object) *core.Object {
	return core.NewObject("keyVersion", version.Get("version"), "encryptionContextKeys", stringsOf(kmsSortedStrings(bound.Keys())))
}

// KmsEncryptFor (kms.ts kmsEncryptFor): Encrypts a UTF-8 string of any size (up to 16 MiB) under a tenant's AES key
// (id or alias) by envelope encryption: a fresh data key encrypts the value locally and the key's current version
// wraps the data key. The result is `{wrapped data key}~{iv|tag|ciphertext}`, both bound to the encryption context
// (a string `context` is bound as `{ context }`). Refuses disabled keys, keys pending deletion and non-AES keys.
func KmsEncryptFor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, keyRef string, plaintext string, context any, use *core.Object) (result *core.Object, err error) {
	key, err := FindKey(ctx, tx, tenantID, keyRef)
	if err != nil {
		return nil, err
	}
	if err := kmsServiceKey(key); err != nil {
		return nil, err
	}
	value := utf8Bytes(plaintext)
	if len(value) > kmsMaxServicePlaintext {
		return nil, invalidInput("The value is larger than 16 MiB")
	}
	version, err := KeyVersion(ctx, tx, key, jsNumber(key.Get("currentVersion")))
	if err != nil {
		return nil, err
	}
	bound, err := kmsServiceContext(context)
	if err != nil {
		return nil, err
	}
	dataKey := kmsRandomBytes(32)
	defer wipe(dataKey)
	wrapped, err := EncryptWith(server, key, version, dataKey, false, bound)
	if err != nil {
		return nil, err
	}
	// The wrapped key is associated data too, so a payload cannot be paired with another wrapped key.
	aad, err := kmsAssociatedData(wrapped, bound)
	if err != nil {
		return nil, err
	}
	sealed, err := kmsGcmSeal(dataKey, value, aad)
	if err != nil {
		return nil, err
	}
	if err := kmsServiceAudit(ctx, server, tx, use, kmsAction("encrypt"), key, kmsUseMetadata(version, bound)); err != nil {
		return nil, err
	}
	return core.NewObject(
		"ciphertext", wrapped+"~"+base64url(sealed),
		"keyId", key.Get("id"),
		"keyVersion", version.Get("version"),
	), nil
}

// KmsDecryptFor (kms.ts kmsDecryptFor): Decrypts what `kmsEncryptFor` returned (`{ ciphertext, keyId?,
// keyVersion? }`); the key must still be enabled and the context the same.
func KmsDecryptFor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, sealed *core.Object, context any, use *core.Object) (result string, err error) {
	if sealed == nil {
		sealed = core.NewObject()
	}
	ciphertext, ok := sealed.Get("ciphertext").(string)
	if !ok || utf16Len(ciphertext) > 23_000_000 {
		return "", kmsInvalidCiphertext()
	}
	parts := strings.Split(ciphertext, "~")
	wrapped, payload := parts[0], ""
	if len(parts) > 1 {
		payload = parts[1]
	}
	if len(parts) > 2 || !kmsBase64URL.MatchString(payload) {
		return "", kmsInvalidCiphertext()
	}
	parsed, err := ParseCiphertext(wrapped)
	if err != nil {
		return "", err
	}
	if keyID := sealed.Get("keyId"); !isUndefined(keyID) && !core.StrictEquals(keyID, parsed.Get("keyId")) {
		return "", kmsInvalidCiphertext()
	}
	if keyVersion := sealed.Get("keyVersion"); !isUndefined(keyVersion) && !core.StrictEquals(core.Normalize(keyVersion), parsed.Get("version")) {
		return "", kmsInvalidCiphertext()
	}
	key, err := FindKey(ctx, tx, tenantID, parsed.Get("keyId"))
	if err != nil {
		return "", err
	}
	if err := kmsServiceKey(key); err != nil {
		return "", err
	}
	version, err := KeyVersion(ctx, tx, key, jsNumber(parsed.Get("version")))
	if err != nil {
		return "", err
	}
	bound, err := kmsServiceContext(context)
	if err != nil {
		return "", err
	}
	dataKey, err := DecryptWith(server, key, version, parsed, bound)
	if err != nil {
		return "", err
	}
	defer wipe(dataKey)
	bytes := nodeBase64Decode(payload)
	if len(bytes) < 28 || len(dataKey) != 32 {
		return "", kmsInvalidCiphertext()
	}
	aad, err := kmsAssociatedData(wrapped, bound)
	if err != nil {
		return "", err
	}
	plaintext, err := kmsGcmOpen(dataKey, bytes, aad)
	if err != nil {
		return "", kmsInvalidCiphertext()
	}
	if err := kmsServiceAudit(ctx, server, tx, use, kmsAction("decrypt"), key, kmsUseMetadata(version, bound)); err != nil {
		return "", err
	}
	return decodeUTF8(plaintext), nil
}

// KmsDataKeyFor (kms.ts kmsDataKeyFor): A fresh 32-byte data key wrapped under a tenant AES key, for a module that
// protects many values in one call (tokenization): the caller encrypts locally, stores `wrapped` beside the data,
// and must wipe `dataKey` after use. Audited once as `iam:kms:generate-data-key` with `metadata.via`. The result is
// `{ dataKey: []byte, wrapped, keyId, keyVersion }`.
func KmsDataKeyFor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, keyRef string, context *core.Object, use *core.Object) (result *core.Object, err error) {
	key, err := FindKey(ctx, tx, tenantID, keyRef)
	if err != nil {
		return nil, err
	}
	if err := kmsServiceKey(key); err != nil {
		return nil, err
	}
	version, err := KeyVersion(ctx, tx, key, jsNumber(key.Get("currentVersion")))
	if err != nil {
		return nil, err
	}
	bound, err := kmsObjectContext(context)
	if err != nil {
		return nil, err
	}
	dataKey := kmsRandomBytes(32)
	wrapped, err := EncryptWith(server, key, version, dataKey, false, bound)
	if err != nil {
		return nil, err
	}
	if err := kmsServiceAudit(ctx, server, tx, use, kmsAction("generate-data-key"), key, kmsUseMetadata(version, bound)); err != nil {
		return nil, err
	}
	return core.NewObject().SetRaw("dataKey", dataKey).
		Set("wrapped", wrapped).Set("keyId", key.Get("id")).Set("keyVersion", version.Get("version")), nil
}

// KmsOpenDataKeyFor (kms.ts kmsOpenDataKeyFor): Unwraps a data key from `kmsDataKeyFor`; the key must still be
// enabled and the context the same.
func KmsOpenDataKeyFor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, wrapped string, context *core.Object, use *core.Object) (result []byte, err error) {
	parsed, err := ParseCiphertext(wrapped)
	if err != nil {
		return nil, err
	}
	key, err := FindKey(ctx, tx, tenantID, parsed.Get("keyId"))
	if err != nil {
		return nil, err
	}
	if err := kmsServiceKey(key); err != nil {
		return nil, err
	}
	version, err := KeyVersion(ctx, tx, key, jsNumber(parsed.Get("version")))
	if err != nil {
		return nil, err
	}
	bound, err := kmsObjectContext(context)
	if err != nil {
		return nil, err
	}
	dataKey, err := DecryptWith(server, key, version, parsed, bound)
	if err != nil {
		return nil, err
	}
	if len(dataKey) != 32 {
		return nil, kmsInvalidCiphertext()
	}
	if err := kmsServiceAudit(ctx, server, tx, use, kmsAction("decrypt"), key, kmsUseMetadata(version, bound)); err != nil {
		return nil, err
	}
	return dataKey, nil
}

// CreateServiceKey (kms.ts createServiceKey): Creates a key for another module's own use, such as a certificate
// authority's signing key, without a caller permission check (the calling module authorizes its caller). The key is
// an ordinary KMS key: visible, taggable, and disabled or deleted like any other. input names tenantId, keySpec,
// keyUsage, description, tags, createdBy, managedBy and managedId.
func CreateServiceKey(ctx context.Context, server *ServerContext, tx core.IamStore, input *core.Object) (result *core.Object, err error) {
	existing, err := tx.Find(ctx, "kmsKeys", core.NewObject("tenantId", input.Get("tenantId")), nil)
	if err != nil {
		return nil, err
	}
	if len(existing) >= MaxKeysPerTenant {
		return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant keeps at most "+core.NumberString(MaxKeysPerTenant)+" keys", 409)
	}
	now := float64(server.Now())
	description, err := Text(input.Get("description"), "description", 512)
	if err != nil {
		return nil, err
	}
	spec := jsString(input.Get("keySpec"))
	usage, err := KeyUsageFor(spec, input.Get("keyUsage"))
	if err != nil {
		return nil, err
	}
	tags, err := KeyTags(input.Get("tags"))
	if err != nil {
		return nil, err
	}
	key := core.NewObject(
		"id", ID(),
		"tenantId", input.Get("tenantId"),
		"description", description,
		"keySpec", input.Get("keySpec"),
		"keyUsage", usage,
		"state", "enabled",
		"currentVersion", 1.0,
		"tags", tags,
		"managedBy", input.Get("managedBy"),
		"managedId", input.Get("managedId"),
		"createdAt", now,
		"createdBy", input.Get("createdBy"),
		"updatedAt", now,
	)
	if _, err := tx.Insert(ctx, "kmsKeys", key); err != nil {
		return nil, err
	}
	if _, err := AddKeyVersion(ctx, server, tx, key, 1, "create"); err != nil {
		return nil, err
	}
	return key, nil
}

// RetireServiceKey (kms.ts retireServiceKey): Schedules deletion of a key a module created for its own use once the
// module is done with it (a deleted data protection profile), after the shortest waiting period. Keys the module
// does not manage are left alone. Returns the deletion date, or nil when nothing was scheduled.
func RetireServiceKey(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, keyID string, managedBy string, managedID string) (result *float64, err error) {
	key, err := tx.Get(ctx, "kmsKeys", keyID)
	if err != nil {
		return nil, err
	}
	if key == nil || key.Get("tenantId") != tenantID || key.Get("managedBy") != managedBy || key.Get("managedId") != managedID ||
		key.Get("state") == "pending-deletion" {
		return nil, nil
	}
	now := float64(server.Now())
	deletionDate := now + 7*86_400_000
	next := key.Spread()
	next.Set("state", "pending-deletion")
	next.Set("deletionDate", deletionDate)
	next.Set("updatedAt", now)
	if _, err := tx.Put(ctx, "kmsKeys", next); err != nil {
		return nil, err
	}
	return &deletionDate, nil
}

// KmsSignFor (kms.ts kmsSignFor): Signs `data` with one pinned version of a signing key for another module (a
// certificate authority signing certificates and CRLs). The key must be enabled; the use is audited as
// `iam:kms:sign` with `metadata.via`.
func KmsSignFor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, keyID string, version float64, algorithm string, data []byte, use *core.Object) (result []byte, err error) {
	key, err := FindKey(ctx, tx, tenantID, keyID)
	if err != nil {
		return nil, err
	}
	if err := AssertUsable(key, "sign"); err != nil {
		return nil, err
	}
	algorithms, err := KeyAlgorithms(key)
	if err != nil {
		return nil, err
	}
	if !containsString(algorithms, algorithm) {
		return nil, invalidInput("This key does not sign with " + algorithm)
	}
	pinned, err := KeyVersion(ctx, tx, key, version)
	if err != nil {
		return nil, err
	}
	signature, err := SignWith(server, pinned, algorithm, data, "der")
	if err != nil {
		return nil, err
	}
	if err := kmsServiceAudit(ctx, server, tx, use, kmsAction("sign"), key, core.NewObject("keyVersion", version, "algorithm", algorithm)); err != nil {
		return nil, err
	}
	return signature, nil
}

// Fingerprint (kms.ts fingerprint): A short fingerprint of public material, for listings (never of secret material).
func Fingerprint(pem string) (result string, err error) {
	digest := sha256.Sum256(utf8Bytes(pem))
	return base64url(digest[:])[:16], nil
}
