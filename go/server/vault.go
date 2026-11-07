package server

// Skeleton of packages/server/src/vault.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// AddVersion (vault.ts addVersion): Adds a version (encrypted) and returns it; the caller moves stages.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AddVersion(ctx context.Context, server *ServerContext, tx core.IamStore, secret *core.Object, value string, source string, actorID string, use *Principal) (result *core.Object, err error) {
	err = notImplemented("vault.ts addVersion")
	return
}

// CheckoutPolicy (vault.ts checkoutPolicy): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CheckoutPolicy(value any, previous *core.Object) (result *core.Object, err error) {
	err = notImplemented("vault.ts checkoutPolicy")
	return
}

// EncryptVersion (vault.ts encryptVersion): Encrypts a version's value: under the secret's customer-managed key when
// it has one, else the deployment secret.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EncryptVersion(ctx context.Context, server *ServerContext, tx core.IamStore, secret *core.Object, record *core.Object, value string, use *Principal) (result *core.Object, err error) {
	err = notImplemented("vault.ts encryptVersion")
	return
}

// EngineConfig (vault.ts engineConfig): Engine configuration: any JSON value up to 8 KiB.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EngineConfig(value any) (result any, err error) {
	err = notImplemented("vault.ts engineConfig")
	return
}

// FindSecret (vault.ts findSecret): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func FindSecret(ctx context.Context, tx core.IamStore, tenantID string, name string) (result *core.Object, err error) {
	err = notImplemented("vault.ts findSecret")
	return
}

// GenerateValue (vault.ts generateValue): A random value from the generator: uniform draws, with one character of
// each kept class placed at random.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func GenerateValue(generator *core.Object) (result string, err error) {
	err = notImplemented("vault.ts generateValue")
	return
}

// LeaseHandleContext (vault.ts leaseHandleContext): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LeaseHandleContext(leaseID string) (result string, err error) {
	err = notImplemented("vault.ts leaseHandleContext")
	return
}

// LeaseSettings (vault.ts leaseSettings): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LeaseSettings(value any, previous *core.Object) (result *core.Object, err error) {
	err = notImplemented("vault.ts leaseSettings")
	return
}

// LiveLeases (vault.ts liveLeases): Active check-outs and leases of a secret, in issue order.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LiveLeases(ctx context.Context, server *ServerContext, tx core.IamStore, secret *core.Object) (result []*core.Object, err error) {
	err = notImplemented("vault.ts liveLeases")
	return
}

// OpenStored (vault.ts openStored): A version's value whatever its state (re-encryption under another key);
// destroyed versions have none.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OpenStored(ctx context.Context, server *ServerContext, tx core.IamStore, version *core.Object, use *Principal) (result string, err error) {
	err = notImplemented("vault.ts openStored")
	return
}

// VaultOpenValue (vault.ts openValue): Opens a sealed value with the current secret or a previous one
// (`rotateSecrets` re-seals).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VaultOpenValue(server *ServerContext, sealed string, context string) (result string, err error) {
	err = notImplemented("vault.ts openValue")
	return
}

// OpenVersion (vault.ts openVersion): The value of one version; refuses disabled and destroyed versions. A version
// under a customer-managed key opens only while that key is enabled (KEY_STATE_INVALID otherwise); the key's audit
// log records the use.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OpenVersion(ctx context.Context, server *ServerContext, tx core.IamStore, version *core.Object, use *Principal) (result string, err error) {
	err = notImplemented("vault.ts openVersion")
	return
}

// OwnField (vault.ts ownField): One field of a json secret's parsed value, own properties only.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OwnField(fields *core.Object, field string) (result any, err error) {
	err = notImplemented("vault.ts ownField")
	return
}

// ParseFields (vault.ts parseFields): A json secret's fields; INVALID_INPUT when the value is not a JSON object.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ParseFields(value string) (result *core.Object, err error) {
	err = notImplemented("vault.ts parseFields")
	return
}

// PasswordGenerator (vault.ts passwordGenerator): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PasswordGenerator(value any) (result *core.Object, err error) {
	err = notImplemented("vault.ts passwordGenerator")
	return
}

// PromoteVersion (vault.ts promoteVersion): Makes a version current: the old current becomes `previous`, a `pending`
// label on it is dropped, and versions past `maxVersions` that no stage names are deleted. Returns the stored
// secret.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PromoteVersion(ctx context.Context, server *ServerContext, tx core.IamStore, secret *core.Object, version float64, actorID string, rotated bool) (result *core.Object, err error) {
	err = notImplemented("vault.ts promoteVersion")
	return
}

// PruneVersions (vault.ts pruneVersions): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PruneVersions(ctx context.Context, tx core.IamStore, secret *core.Object) (result float64, err error) {
	err = notImplemented("vault.ts pruneVersions")
	return
}

// RecordAccess (vault.ts recordAccess): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RecordAccess(ctx context.Context, server *ServerContext, tx core.IamStore, secret *core.Object, entry *core.Object) (err error) {
	err = notImplemented("vault.ts recordAccess")
	return
}

// RedactedMessage (vault.ts redactedMessage): An error message safe to store: at most 512 characters, with any
// secret value (or field of one) it quotes redacted.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RedactedMessage(errorValue any, values []string) (result string, err error) {
	err = notImplemented("vault.ts redactedMessage")
	return
}

// ResolveSecretResource (vault.ts resolveSecretResource): the decision engine's resolver for
// `iam/vault/secrets/{name}`: an existing secret carries its attributes; a name nobody uses yet resolves without any.
// nil for other resources.
//
// PARTIAL: the guard is ported; reading an existing secret's attributes (findSecret, secretAttributes) is a stub.
func ResolveSecretResource(ctx context.Context, tx core.IamStore, reference core.ResourceRef) (*ResolvedResource, error) {
	if reference.Type != "iam" || !strings.HasPrefix(reference.ID, SecretResourcePrefix) {
		return nil, nil
	}
	name := reference.ID[len(SecretResourcePrefix):]
	plain := &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID}
	if name == "" || utf16Len(name) > 256 {
		return plain, nil
	}
	secret, err := FindSecret(ctx, tx, reference.TenantID, name)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return plain, nil
	}
	attributes, err := SecretAttributes(secret)
	if err != nil {
		return nil, err
	}
	plain.Attributes = attributes
	return plain, nil
}

// RotationSettings (vault.ts rotationSettings): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RotationSettings(settings *core.Object, format string, value any, previous *core.Object) (result *core.Object, err error) {
	err = notImplemented("vault.ts rotationSettings")
	return
}

// ScheduleRotation (vault.ts scheduleRotation): Recomputes the next due date after settings change (the interval
// counts from the last rotation or creation).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ScheduleRotation(rotation *core.Object, createdAt float64, now int64) (result *core.Object, err error) {
	err = notImplemented("vault.ts scheduleRotation")
	return
}

// VaultSealValue (vault.ts sealValue): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VaultSealValue(server *ServerContext, value string, context string) (result string, err error) {
	err = notImplemented("vault.ts sealValue")
	return
}

// SecretAttributes (vault.ts secretAttributes): The policy attributes of a secret: `resource.name`,
// `resource.tag.{key}`, and its settings.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SecretAttributes(secret *core.Object) (result *core.Object, err error) {
	err = notImplemented("vault.ts secretAttributes")
	return
}

// SecretFormat (vault.ts secretFormat): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SecretFormat(value any) (result string, err error) {
	err = notImplemented("vault.ts secretFormat")
	return
}

// SecretName (vault.ts secretName): A secret name: 1-16 `/`-separated segments of letters, digits and `_.-` (not
// starting with `.` or `-`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SecretName(value any) (result string, err error) {
	err = notImplemented("vault.ts secretName")
	return
}

// SecretPrefix (vault.ts secretPrefix): A listing prefix: a name prefix, optionally ending in `/`; the empty string
// lists everything.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SecretPrefix(value any) (result string, err error) {
	err = notImplemented("vault.ts secretPrefix")
	return
}

// SecretResource (vault.ts secretResource): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SecretResource(name string) (result string, err error) {
	err = notImplemented("vault.ts secretResource")
	return
}

// SecretTags (vault.ts secretTags): Up to 20 tags; keys are identifiers, values 1-256 printable characters.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SecretTags(value any) (result *core.Object, err error) {
	err = notImplemented("vault.ts secretTags")
	return
}

// SecretValue (vault.ts secretValue): The stored form of a value: the text itself, or for `json` secrets the object
// serialized (callers may pass it as a JSON string or as `fields`). Refuses empty values and values over the size
// limit.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SecretValue(settings *core.Object, format string, input *core.Object) (result string, err error) {
	err = notImplemented("vault.ts secretValue")
	return
}

// SecretVersions (vault.ts secretVersions): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SecretVersions(ctx context.Context, tx core.IamStore, secret *core.Object) (result []*core.Object, err error) {
	err = notImplemented("vault.ts secretVersions")
	return
}

// SelectVersion (vault.ts selectVersion): Resolves `version` / `stage` (default `current`) to a version record of
// the secret.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SelectVersion(ctx context.Context, tx core.IamStore, secret *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("vault.ts selectVersion")
	return
}

// StageName (vault.ts stageName): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func StageName(value any) (result string, err error) {
	err = notImplemented("vault.ts stageName")
	return
}

// VaultSettings (vault.ts vaultSettings): The validated `vault` option (INVALID_CONFIG on a bad value); cached per
// options object.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VaultSettings(server *core.Object) (result *core.Object, err error) {
	err = notImplemented("vault.ts vaultSettings")
	return
}

// VersionOf (vault.ts versionOf): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VersionOf(ctx context.Context, tx core.IamStore, secret *core.Object, version float64) (result *core.Object, err error) {
	err = notImplemented("vault.ts versionOf")
	return
}

// WithTimeout (vault.ts withTimeout): Runs a rotator or engine call with the configured timeout.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WithTimeout(ctx context.Context, server *ServerContext, what string, call func(context.Context) (any, error)) (result any, err error) {
	err = notImplemented("vault.ts withTimeout")
	return
}

// DefaultGenerator is vault.ts defaultGenerator.
var DefaultGenerator = struct {
	Length    float64
	Charset   string
	EachClass bool
}{32, "alphanumeric", true}

// SystemStages is vault.ts systemStages.
var SystemStages = newOrderedSet("current", "previous", "pending")

// VaultCollections is vault.ts vaultCollections.
var VaultCollections = struct {
	Secrets  string
	Versions string
	Leases   string
	Access   string
}{"vaultSecrets", "vaultVersions", "vaultLeases", "vaultAccess"}

// VaultOperator is vault.ts vaultOperator.
const VaultOperator = "deployment-operator"

// VaultTime is vault.ts vaultTime.
var VaultTime = struct {
	MINUTE float64
	HOUR   float64
	DAY    float64
}{60000, 3600000, 86400000}

// SecretResourcePrefix is the IAM resource ID prefix of vault secrets (`iam/vault/secrets/{name}`).
const SecretResourcePrefix = "vault/secrets/"
