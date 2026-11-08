package server

// Port of packages/server/src/vault.ts: the secrets vault's records, validation, sealing and helpers. Tenant-scoped
// secrets with versions, stage labels, rotation, check-out leases for shared privileged credentials, and dynamic
// secrets minted per caller by an engine. Values are sealed at rest with the deployment secret (AES-256-GCM, bound to
// tenant, secret, and version) and leave storage only through `reveal`, a check-out, a lease, or the trusted
// `iam.vault` runtime. Access is decided like every administrative action: `iam:vault:*` on
// `iam/vault/secrets/{name}`, where the secret's tags and settings are resource attributes.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// VaultCollections is vault.ts vaultCollections.
var VaultCollections = struct {
	Secrets  string
	Versions string
	Leases   string
	Access   string
}{"vaultSecrets", "vaultVersions", "vaultLeases", "vaultAccess"}

// SecretResourcePrefix is the IAM resource ID prefix of vault secrets (`iam/vault/secrets/{name}` in policies).
const SecretResourcePrefix = "vault/secrets/"

// SecretResource (vault.ts secretResource): the resource ID of a secret.
func SecretResource(name string) (result string, err error) {
	return SecretResourcePrefix + name, nil
}

// VaultOperator is vault.ts vaultOperator: the audit actor of the scheduler jobs, as elsewhere.
const VaultOperator = "deployment-operator"

const (
	vaultMinute = 60_000.0
	vaultHour   = 60 * vaultMinute
	vaultDay    = 24 * vaultHour
)

// VaultTime is vault.ts vaultTime.
var VaultTime = struct {
	MINUTE float64
	HOUR   float64
	DAY    float64
}{vaultMinute, vaultHour, vaultDay}

// --- options -------------------------------------------------------------------------------------

var vaultPluginName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// vaultSettingsCache is settingsCache: the validated settings per options object.
var vaultSettingsCache sync.Map

// VaultSettings (vault.ts vaultSettings): The validated `vault` option (INVALID_CONFIG on a bad value); cached per
// options object. The result holds `rotators` (map[string]VaultRotator, read with VaultRotators), `engines`
// (map[string]VaultEngine, read with VaultEngines), `maxValueBytes`, `maxSecretsPerTenant`, `accessRetentionMs` and
// `callTimeoutMs`.
func VaultSettings(server *ServerContext) (result *core.Object, err error) {
	var options *BetterIamOptions
	if server != nil {
		options = server.Options
	}
	if options != nil {
		if cached, ok := vaultSettingsCache.Load(options); ok {
			return cached.(*core.Object), nil
		}
	}
	input := &VaultOptions{}
	if options != nil && options.Vault != nil {
		input = options.Vault
	}
	bounded := func(value *float64, fallback, min, max float64, name string) (float64, error) {
		if value == nil {
			return fallback, nil
		}
		if !core.IsSafeInteger(*value) || *value < min || *value > max {
			return 0, invalidConfig("vault." + name + " must be an integer from " + core.NumberString(min) + " to " + core.NumberString(max))
		}
		return *value, nil
	}
	checkNames := func(keys []string, name string, method string, missing func(key string) bool) error {
		sort.Strings(keys)
		for _, key := range keys {
			if !vaultPluginName.MatchString(key) {
				return invalidConfig("vault." + name + " keys must be lowercase identifiers")
			}
			if missing(key) {
				return invalidConfig("vault." + name + "." + key + " must have a " + method + " function")
			}
		}
		return nil
	}
	rotators := map[string]VaultRotator{}
	rotatorKeys := make([]string, 0, len(input.Rotators))
	for key, rotator := range input.Rotators {
		rotators[key] = rotator
		rotatorKeys = append(rotatorKeys, key)
	}
	if err := checkNames(rotatorKeys, "rotators", "rotate", func(key string) bool { return rotators[key].Rotate == nil }); err != nil {
		return nil, err
	}
	engines := map[string]VaultEngine{}
	engineKeys := make([]string, 0, len(input.Engines))
	for key, engine := range input.Engines {
		engines[key] = engine
		engineKeys = append(engineKeys, key)
	}
	if err := checkNames(engineKeys, "engines", "issue", func(key string) bool { return engines[key].Issue == nil }); err != nil {
		return nil, err
	}
	maxValueBytes, err := bounded(input.MaxValueBytes, 65536, 16, 1048576, "maxValueBytes")
	if err != nil {
		return nil, err
	}
	maxSecrets, err := bounded(input.MaxSecretsPerTenant, 1000, 1, 100000, "maxSecretsPerTenant")
	if err != nil {
		return nil, err
	}
	retentionDays, err := bounded(input.AccessRetentionDays, 90, 1, 3650, "accessRetentionDays")
	if err != nil {
		return nil, err
	}
	callTimeout, err := bounded(input.CallTimeoutMs, 30_000, 1000, 300_000, "callTimeoutMs")
	if err != nil {
		return nil, err
	}
	settings := core.NewObject()
	settings.SetRaw("rotators", rotators)
	settings.SetRaw("engines", engines)
	settings.Set("maxValueBytes", maxValueBytes)
	settings.Set("maxSecretsPerTenant", maxSecrets)
	settings.Set("accessRetentionMs", retentionDays*vaultDay)
	settings.Set("callTimeoutMs", callTimeout)
	if options != nil {
		vaultSettingsCache.Store(options, settings)
	}
	return settings, nil
}

// VaultRotators is `settings.rotators` of a VaultSettings result.
func VaultRotators(settings *core.Object) map[string]VaultRotator {
	if rotators, ok := settings.Get("rotators").(map[string]VaultRotator); ok {
		return rotators
	}
	return map[string]VaultRotator{}
}

// VaultEngines is `settings.engines` of a VaultSettings result.
func VaultEngines(settings *core.Object) map[string]VaultEngine {
	if engines, ok := settings.Get("engines").(map[string]VaultEngine); ok {
		return engines
	}
	return map[string]VaultEngine{}
}

// --- validation ----------------------------------------------------------------------------------

var secretSegment = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

// SecretName (vault.ts secretName): A secret name: 1-16 `/`-separated segments of letters, digits and `_.-` (not
// starting with `.` or `-`).
func SecretName(value any) (result string, err error) {
	name, err := Text(value, "name", 256)
	if err != nil {
		return "", err
	}
	parts := strings.Split(name, "/")
	valid := len(parts) <= 16
	for _, part := range parts {
		if !valid {
			break
		}
		valid = secretSegment.MatchString(part)
	}
	if !valid {
		return "", invalidInput("Secret names are 1-16 segments of letters, digits and _.- (not starting with . or -) separated by /")
	}
	return name, nil
}

// SecretPrefix (vault.ts secretPrefix): A listing prefix: a name prefix, optionally ending in `/`; the empty string
// lists everything.
func SecretPrefix(value any) (result string, err error) {
	if isUndefined(value) || value == "" {
		return "", nil
	}
	prefix, err := Text(value, "prefix", 256)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSuffix(prefix, "/")
	if trimmed != "" {
		if _, err := SecretName(trimmed); err != nil {
			return "", err
		}
	}
	return prefix, nil
}

var secretTagKey = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)

// SecretTags (vault.ts secretTags): Up to 20 tags; keys are identifiers, values 1-256 printable characters.
func SecretTags(value any) (result *core.Object, err error) {
	if isUndefined(value) {
		return core.NewObject(), nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	keys := input.Keys()
	if len(keys) > 20 {
		return nil, invalidInput("A secret has at most 20 tags")
	}
	sort.SliceStable(keys, func(a, b int) bool { return compareUTF16(keys[a], keys[b]) < 0 })
	tags := core.NewObject()
	for _, key := range keys {
		if !secretTagKey.MatchString(key) {
			return nil, invalidInput("Invalid tag name " + key)
		}
		item, err := Text(input.Get(key), "tag "+key, 256)
		if err != nil {
			return nil, err
		}
		tags.Set(key, item)
	}
	return tags, nil
}

var stageLabel = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// SystemStages is vault.ts systemStages: stage labels the vault moves itself.
var SystemStages = newOrderedSet("current", "previous", "pending")

// StageName (vault.ts stageName) validates a stage label.
func StageName(value any) (result string, err error) {
	label, err := Text(value, "stage", 32)
	if err != nil {
		return "", err
	}
	if !stageLabel.MatchString(label) {
		return "", invalidInput("Stage labels are 1-32 lowercase letters, digits or hyphens, starting with a letter")
	}
	return label, nil
}

// SecretFormat (vault.ts secretFormat): `text` (the default) or `json`.
func SecretFormat(value any) (result string, err error) {
	if isUndefined(value) {
		return "text", nil
	}
	if value != "text" && value != "json" {
		return "", invalidInput("format must be text or json")
	}
	return value.(string), nil
}

// SecretValue (vault.ts secretValue): The stored form of a value: the text itself, or for `json` secrets the object
// serialized (callers may pass it as a JSON string or as `fields`). Refuses empty values and values over the size
// limit.
func SecretValue(settings *core.Object, format string, input *core.Object) (result string, err error) {
	var value string
	if fields := input.Get("fields"); !isUndefined(fields) {
		if format != "json" {
			return "", invalidInput("fields are for json secrets; pass value instead")
		}
		object, err := Object(fields)
		if err != nil {
			return "", err
		}
		value, _, err = core.Stringify(object)
		if err != nil {
			return "", err
		}
	} else {
		text, isString := input.Get("value").(string)
		if !isString || text == "" {
			return "", invalidInput("value must be a nonempty string")
		}
		value = text
	}
	maxValueBytes := jsNumber(settings.Get("maxValueBytes"))
	if float64(len(utf8Bytes(value))) > maxValueBytes {
		return "", invalidInput("Secret values are at most " + core.NumberString(maxValueBytes) + " bytes")
	}
	if format == "json" {
		if _, err := ParseFields(value); err != nil {
			return "", err
		}
	}
	return value, nil
}

var (
	vaultFieldPattern  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)
	reservedFieldNames = newOrderedSet("__proto__", "constructor", "prototype")
)

// FieldName (vault.ts fieldName): A json secret's field name: 1-64 letters, digits and `_.-`, never one that names an
// object's prototype.
func FieldName(value any, name string) (string, error) {
	field, err := Text(value, name, 64)
	if err != nil {
		return "", err
	}
	if !vaultFieldPattern.MatchString(field) || reservedFieldNames.Has(field) {
		return "", invalidInput(name + " must be a field name of letters, digits and _.-")
	}
	return field, nil
}

// OwnField (vault.ts ownField): One field of a json secret's parsed value, own properties only.
func OwnField(fields *core.Object, field string) (result any, err error) {
	if fields == nil {
		return core.Undefined, nil
	}
	if value, ok := fields.Lookup(field); ok {
		return value, nil
	}
	return core.Undefined, nil
}

// ParseFields (vault.ts parseFields): A json secret's fields; INVALID_INPUT when the value is not a JSON object.
func ParseFields(value string) (result *core.Object, err error) {
	parsed, err := core.ParseJSONString(value)
	if err != nil {
		return nil, invalidInput("json secrets hold a JSON object")
	}
	object, ok := parsed.(*core.Object)
	if !ok || object == nil {
		return nil, invalidInput("json secrets hold a JSON object")
	}
	return object, nil
}

// generatorCharsets are vault.ts charsets.
var generatorCharsets = map[string]string{
	"alphanumeric": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	// Printable ASCII without space, quotes, backslash and backtick, which break shells and connection strings.
	"ascii":     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~",
	"hex":       "0123456789abcdef",
	"base64url": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
	"numeric":   "0123456789",
}

// generatorClasses are vault.ts classes: lowercase, uppercase, digits, symbols.
var generatorClasses = []func(c byte) bool{
	func(c byte) bool { return c >= 'a' && c <= 'z' },
	func(c byte) bool { return c >= 'A' && c <= 'Z' },
	func(c byte) bool { return c >= '0' && c <= '9' },
	func(c byte) bool {
		return !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9')
	},
}

// DefaultGenerator is vault.ts defaultGenerator.
var DefaultGenerator = struct {
	Length    float64
	Charset   string
	EachClass bool
}{32, "alphanumeric", true}

// defaultGeneratorObject is `{ ...defaultGenerator }`.
func defaultGeneratorObject() *core.Object {
	return core.NewObject("length", DefaultGenerator.Length, "charset", DefaultGenerator.Charset, "eachClass", DefaultGenerator.EachClass)
}

// PasswordGenerator (vault.ts passwordGenerator) validates how generated values look.
func PasswordGenerator(value any) (result *core.Object, err error) {
	if isUndefined(value) || value == true {
		return defaultGeneratorObject(), nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	length := 32.0
	if raw := input.Get("length"); !isUndefined(raw) {
		if length, err = Integer(raw, "generator.length", 8, 256); err != nil {
			return nil, err
		}
	}
	charset := coalesce(input.Get("charset"), "alphanumeric")
	eachClass := true
	if raw := input.Get("eachClass"); !isUndefined(raw) {
		eachClass = raw == true
	}
	generator := core.NewObject("length", length)
	generator.SetRaw("charset", charset)
	generator.Set("eachClass", eachClass)
	if _, known := generatorCharsets[propertyKey(charset)]; !known {
		return nil, invalidInput("generator.charset must be alphanumeric, ascii, hex, base64url or numeric")
	}
	if raw := input.Get("eachClass"); !isUndefined(raw) {
		if _, isBool := raw.(bool); !isBool {
			return nil, invalidInput("generator.eachClass must be a boolean")
		}
	}
	if raw := input.Get("exclude"); !isUndefined(raw) && raw != "" {
		exclude, err := Text(raw, "generator.exclude", 64)
		if err != nil {
			return nil, err
		}
		generator.Set("exclude", exclude)
	}
	if len(generatorPool(generator)) < 10 {
		return nil, invalidInput("The generator must keep at least 10 characters")
	}
	return generator, nil
}

// propertyKey is ToPropertyKey for a value used to index an object (`charsets[value]`).
func propertyKey(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return jsString(value)
}

// generatorPool is pool: the charset without the excluded characters.
func generatorPool(generator *core.Object) string {
	excluded := map[string]bool{}
	if exclude, ok := generator.Get("exclude").(string); ok {
		for _, piece := range core.CodePoints(exclude) {
			excluded[piece] = true
		}
	}
	characters := generatorCharsets[propertyKey(generator.Get("charset"))]
	var b strings.Builder
	for index := 0; index < len(characters); index++ {
		if !excluded[characters[index:index+1]] {
			b.WriteByte(characters[index])
		}
	}
	return b.String()
}

// GenerateValue (vault.ts generateValue): A random value from the generator: uniform draws, with one character of
// each kept class placed at random.
func GenerateValue(generator *core.Object) (result string, err error) {
	characters := generatorPool(generator)
	draw := func(from string) byte { return from[cryptoRandomInt(len(from))] }
	var picked []byte
	if truthy(generator.Get("eachClass")) {
		for _, class := range generatorClasses {
			var set []byte
			for index := 0; index < len(characters); index++ {
				if class(characters[index]) {
					set = append(set, characters[index])
				}
			}
			if len(set) > 0 {
				picked = append(picked, draw(string(set)))
			}
		}
	}
	length := jsNumber(generator.Get("length"))
	if characters == "" && float64(len(picked)) < length {
		return "", errors.New("The value of \"max\" is out of range. It must be greater than the value of \"min\" (0). Received 0")
	}
	for float64(len(picked)) < length {
		picked = append(picked, draw(characters))
	}
	// Fisher-Yates, so the required characters land anywhere.
	for index := len(picked) - 1; index > 0; index-- {
		other := cryptoRandomInt(index + 1)
		picked[index], picked[other] = picked[other], picked[index]
	}
	return string(picked), nil
}

// RotationSettings (vault.ts rotationSettings) validates a secret's rotation settings; undefined keeps previous,
// null clears them (nil).
func RotationSettings(settings *core.Object, format string, value any, previous *core.Object) (result *core.Object, err error) {
	if isUndefined(value) {
		return previous, nil
	}
	if value == nil {
		return nil, nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	rotation := core.NewObject()
	if raw := input.Get("intervalDays"); !nullish(raw) {
		interval, err := Integer(raw, "rotation.intervalDays", 1, 365)
		if err != nil {
			return nil, err
		}
		rotation.Set("intervalDays", interval)
	}
	if raw := input.Get("rotator"); !nullish(raw) {
		rotator, err := Text(raw, "rotation.rotator", 64)
		if err != nil {
			return nil, err
		}
		if _, known := VaultRotators(settings)[rotator]; !known {
			return nil, invalidInput("Unknown rotator " + rotator)
		}
		rotation.Set("rotator", rotator)
	}
	if raw := input.Get("generator"); !nullish(raw) && raw != false {
		generator, err := PasswordGenerator(raw)
		if err != nil {
			return nil, err
		}
		rotation.Set("generator", generator)
	}
	if raw := input.Get("field"); !nullish(raw) {
		if format != "json" {
			return nil, invalidInput("rotation.field is for json secrets")
		}
		field, err := FieldName(raw, "rotation.field")
		if err != nil {
			return nil, err
		}
		rotation.Set("field", field)
	}
	if format == "json" && (rotation.Has("generator") || rotation.Has("rotator")) && !truthy(rotation.Get("field")) {
		return nil, invalidInput("json secrets name the field rotation replaces (rotation.field)")
	}
	// History carries over; a new interval counts from the last rotation.
	if previous != nil {
		if last := previous.Get("lastRotatedAt"); !isUndefined(last) {
			rotation.Set("lastRotatedAt", last)
		}
	}
	return rotation, nil
}

// CheckoutPolicy (vault.ts checkoutPolicy) validates check-out rules; undefined keeps previous, null clears them
// (nil).
func CheckoutPolicy(value any, previous *core.Object) (result *core.Object, err error) {
	if isUndefined(value) {
		return previous, nil
	}
	if value == nil {
		return nil, nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	flag := func(key string, fallback bool) (bool, error) {
		item := input.Get(key)
		if isUndefined(item) {
			return fallback, nil
		}
		flag, isBool := item.(bool)
		if !isBool {
			return false, invalidInput("checkout." + key + " must be a boolean")
		}
		return flag, nil
	}
	required, err := flag("required", true)
	if err != nil {
		return nil, err
	}
	exclusive, err := flag("exclusive", false)
	if err != nil {
		return nil, err
	}
	maxDuration := vaultHour
	if raw := input.Get("maxDurationMs"); !isUndefined(raw) {
		if maxDuration, err = Integer(raw, "checkout.maxDurationMs", vaultMinute, vaultDay); err != nil {
			return nil, err
		}
	}
	rotateOnCheckin, err := flag("rotateOnCheckin", false)
	if err != nil {
		return nil, err
	}
	requireReason, err := flag("requireReason", false)
	if err != nil {
		return nil, err
	}
	return core.NewObject(
		"required", required,
		"exclusive", exclusive,
		"maxDurationMs", maxDuration,
		"rotateOnCheckin", rotateOnCheckin,
		"requireReason", requireReason,
	), nil
}

// LeaseSettings (vault.ts leaseSettings) validates the lease lengths of a dynamic secret.
func LeaseSettings(value any, previous *core.Object) (result *core.Object, err error) {
	if isUndefined(value) && previous != nil {
		return previous, nil
	}
	input := core.NewObject()
	if !isUndefined(value) {
		if input, err = Object(value); err != nil {
			return nil, err
		}
	}
	defaultTtl := vaultHour
	if raw := input.Get("defaultTtlMs"); !isUndefined(raw) {
		if defaultTtl, err = Integer(raw, "lease.defaultTtlMs", vaultMinute, 30*vaultDay); err != nil {
			return nil, err
		}
	}
	maxTtl := math.Max(vaultDay, defaultTtl)
	if raw := input.Get("maxTtlMs"); !isUndefined(raw) {
		if maxTtl, err = Integer(raw, "lease.maxTtlMs", vaultMinute, 30*vaultDay); err != nil {
			return nil, err
		}
	}
	if defaultTtl > maxTtl {
		return nil, invalidInput("lease.defaultTtlMs must not exceed lease.maxTtlMs")
	}
	return core.NewObject("defaultTtlMs", defaultTtl, "maxTtlMs", maxTtl), nil
}

// EngineConfig (vault.ts engineConfig): Engine configuration: any JSON value up to 8 KiB.
func EngineConfig(value any) (result any, err error) {
	if isUndefined(value) {
		return core.NewObject(), nil
	}
	serialized, ok, err := core.Stringify(value)
	if err != nil {
		return nil, invalidInput("engineConfig must be JSON")
	}
	if !ok || utf16Len(serialized) > 8192 {
		return nil, invalidInput("engineConfig must be JSON of at most 8 KiB")
	}
	return core.ParseJSONString(serialized)
}

// --- sealing -------------------------------------------------------------------------------------

// VersionContext (vault.ts versionContext): The encryption context of a version: a sealed value opens only as that
// version of that secret.
func VersionContext(record *core.Object) string {
	return "vault:" + jsString(record.Get("tenantId")) + ":" + jsString(record.Get("secretId")) + ":" + jsString(record.Get("version"))
}

// LeaseHandleContext (vault.ts leaseHandleContext): the encryption context of a dynamic lease's revocation handle.
func LeaseHandleContext(leaseID string) (result string, err error) {
	return "vault-lease:" + leaseID, nil
}

// VaultSealValue (vault.ts sealValue): seals a value with the deployment secret, bound to the context.
func VaultSealValue(server *ServerContext, value string, context string) (result string, err error) {
	return auth.EncryptSecret(value, server.Options.Secret, context), nil
}

// VaultOpenValue (vault.ts openValue): Opens a sealed value with the current secret or a previous one
// (`rotateSecrets` re-seals).
func VaultOpenValue(server *ServerContext, sealed string, context string) (result string, err error) {
	secrets := append([]string{server.Options.Secret}, server.Options.PreviousSecrets...)
	opened, ok := auth.OpenSecret(sealed, secrets, context)
	if !ok {
		return "", core.NewIamError("INVALID_SEALED_VALUE", "The secret value cannot be opened", 500)
	}
	return opened.Value, nil
}

// --- records -------------------------------------------------------------------------------------

// FindSecret (vault.ts findSecret): the secret of a tenant by name, nil when there is none.
func FindSecret(ctx context.Context, tx core.IamStore, tenantID string, name string) (result *core.Object, err error) {
	found, err := tx.Find(ctx, VaultCollections.Secrets, core.NewObject("tenantId", tenantID, "uniqueKey", name), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// SecretVersions (vault.ts secretVersions): every version of a secret, newest first.
func SecretVersions(ctx context.Context, tx core.IamStore, secret *core.Object) (result []*core.Object, err error) {
	versions, err := tx.Find(ctx, VaultCollections.Versions, core.NewObject("tenantId", secret.Get("tenantId"), "secretId", secret.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(versions, func(a, b int) bool {
		return jsNumber(versions[b].Get("version"))-jsNumber(versions[a].Get("version")) < 0
	})
	return versions, nil
}

// VersionOf (vault.ts versionOf): one version of a secret, nil when there is none.
func VersionOf(ctx context.Context, tx core.IamStore, secret *core.Object, version float64) (result *core.Object, err error) {
	return versionOfKey(ctx, tx, secret, core.NumberString(version))
}

func versionOfKey(ctx context.Context, tx core.IamStore, secret *core.Object, version string) (*core.Object, error) {
	found, err := tx.Find(ctx, VaultCollections.Versions, core.NewObject(
		"tenantId", secret.Get("tenantId"),
		"uniqueKey", jsString(secret.Get("id"))+":"+version,
	), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// vaultUse is the KMS use of a vault call: `{ via: 'vault', ...(use ? { principal: use } : {}) }`.
func vaultUse(use *Principal) *core.Object {
	object := core.NewObject("via", "vault")
	if use != nil {
		object.SetRaw("principal", use)
	}
	return object
}

// EncryptVersion (vault.ts encryptVersion): Encrypts a version's value: under the secret's customer-managed key when
// it has one, else the deployment secret.
func EncryptVersion(ctx context.Context, server *ServerContext, tx core.IamStore, secret *core.Object, record *core.Object, value string, use *Principal) (result *core.Object, err error) {
	rest := record.Spread()
	rest.Delete("sealed")
	rest.Delete("kmsKeyId")
	keyID := secret.Get("kmsKeyId")
	if isUndefined(keyID) {
		sealed, err := VaultSealValue(server, value, VersionContext(record))
		if err != nil {
			return nil, err
		}
		return rest.Set("sealed", sealed), nil
	}
	encrypted, err := KmsEncryptFor(ctx, server, tx, jsString(record.Get("tenantId")), jsString(keyID), value, VersionContext(record), vaultUse(use))
	if err != nil {
		return nil, err
	}
	rest.Set("sealed", encrypted.Get("ciphertext"))
	rest.Set("kmsKeyId", encrypted.Get("keyId"))
	return rest, nil
}

// AddVersion (vault.ts addVersion): Adds a version (encrypted) and returns `{ secret, version }`: the secret with
// its new `latestVersion` (not stored) and the stored version; the caller moves stages.
func AddVersion(ctx context.Context, server *ServerContext, tx core.IamStore, secret *core.Object, value string, source string, actorID string, use *Principal) (result *core.Object, err error) {
	number := jsNumber(secret.Get("latestVersion")) + 1
	record, err := EncryptVersion(ctx, server, tx, secret, core.NewObject(
		"id", ID(),
		"tenantId", secret.Get("tenantId"),
		"uniqueKey", jsString(secret.Get("id"))+":"+core.NumberString(number),
		"secretId", secret.Get("id"),
		"version", number,
		"state", "enabled",
		"source", source,
		"createdAt", server.Now(),
		"createdBy", actorID,
	), value, use)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Insert(ctx, VaultCollections.Versions, record); err != nil {
		return nil, err
	}
	return core.NewObject("secret", secret.Spread(core.NewObject("latestVersion", number)), "version", record), nil
}

// stageOf is `stages[label]` as a number; false when the label is absent.
func stageOf(stages *core.Object, label string) (float64, bool) {
	value, ok := stages.Lookup(label)
	if !ok || isUndefined(value) {
		return 0, false
	}
	return jsNumber(value), true
}

// PromoteVersion (vault.ts promoteVersion): Makes a version current: the old current becomes `previous`, a `pending`
// label on it is dropped, and versions past `maxVersions` that no stage names are deleted. Returns the stored
// secret.
func PromoteVersion(ctx context.Context, server *ServerContext, tx core.IamStore, secret *core.Object, version float64, actorID string, rotated bool) (result *core.Object, err error) {
	stages := core.NewObject()
	if current, ok := secret.Get("stages").(*core.Object); ok {
		stages = current.Spread()
	}
	// A newer value restarts the rotation clock; rolling back to an older version does not.
	current, hasCurrent := stageOf(stages, "current")
	fresher := !hasCurrent || version > current
	if !hasCurrent || current != version {
		if hasCurrent {
			stages.Set("previous", stages.Get("current"))
		}
		stages.Set("current", version)
	}
	if pending, ok := stageOf(stages, "pending"); ok && pending == version {
		stages.Delete("pending")
	}
	if previous, ok := stageOf(stages, "previous"); ok && previous == version {
		stages.Delete("previous")
	}
	now := server.Now()
	rotationPending := secret.Get("rotationPending")
	next := secret.Spread()
	next.Delete("rotationPending")
	// A rotation's staged version stays marked until it becomes current (or another version does).
	if !isUndefined(rotationPending) && !strictEquals(rotationPending, version) && strictEquals(stages.Get("pending"), rotationPending) {
		next.Set("rotationPending", rotationPending)
	}
	next.Set("stages", stages)
	next.Set("updatedAt", now)
	next.Set("updatedBy", actorID)
	if rotated || (truthy(next.Get("rotation")) && fresher) {
		rotation, _ := next.Get("rotation").(*core.Object)
		if after := rotationAfter(rotation, float64(now), rotated); after != nil {
			next.Set("rotation", after)
		} else {
			next.SetRaw("rotation", core.Undefined)
		}
	}
	stored, err := tx.Put(ctx, VaultCollections.Secrets, next)
	if err != nil {
		return nil, err
	}
	if _, err := PruneVersions(ctx, tx, stored); err != nil {
		return nil, err
	}
	return stored, nil
}

// rotationAfter is the rotation bookkeeping after a new current version: the next due date counts from now.
func rotationAfter(rotation *core.Object, now float64, rotated bool) *core.Object {
	if rotation == nil {
		if rotated {
			return core.NewObject("lastRotatedAt", now)
		}
		return nil
	}
	next := rotation.Spread()
	next.Delete("lastFailure")
	next.Delete("failures")
	next.Delete("dueNotifiedAt")
	next.Delete("nextRotationAt")
	next.Set("lastRotatedAt", now)
	if interval := next.Get("intervalDays"); !isUndefined(interval) {
		next.Set("nextRotationAt", now+jsNumber(interval)*vaultDay)
	}
	return next
}

// ScheduleRotation (vault.ts scheduleRotation): Recomputes the next due date after settings change (the interval
// counts from the last rotation or creation).
func ScheduleRotation(rotation *core.Object, createdAt float64, now int64) (result *core.Object, err error) {
	if rotation == nil {
		return nil, nil
	}
	rest := rotation.Spread()
	rest.Delete("nextRotationAt")
	interval := rest.Get("intervalDays")
	if isUndefined(interval) {
		return rest, nil
	}
	from := createdAt
	if last := rest.Get("lastRotatedAt"); !nullish(last) {
		from = jsNumber(last)
	}
	return rest.Set("nextRotationAt", math.Max(from+jsNumber(interval)*vaultDay, float64(now))), nil
}

// PruneVersions (vault.ts pruneVersions): deletes the versions past `maxVersions` that no stage names; returns how
// many it deleted.
func PruneVersions(ctx context.Context, tx core.IamStore, secret *core.Object) (result float64, err error) {
	var staged []any
	if stages, ok := secret.Get("stages").(*core.Object); ok {
		stages.Entries(func(_ string, value any) bool {
			staged = append(staged, value)
			return true
		})
	}
	versions, err := SecretVersions(ctx, tx, secret)
	if err != nil {
		return 0, err
	}
	maxVersions := jsNumber(secret.Get("maxVersions"))
	removed := 0.0
	for index, version := range versions {
		if float64(index) >= maxVersions && !vaultStaged(staged, version.Get("version")) {
			if err := tx.Delete(ctx, VaultCollections.Versions, jsString(version.Get("id"))); err != nil {
				return removed, err
			}
			removed++
		}
	}
	return removed, nil
}

// vaultStaged is `new Set(values).has(value)` (SameValueZero over model primitives).
func vaultStaged(values []any, value any) bool {
	for _, item := range values {
		if strictEquals(item, value) {
			return true
		}
	}
	return false
}

// OpenVersion (vault.ts openVersion): The value of one version; refuses disabled and destroyed versions. A version
// under a customer-managed key opens only while that key is enabled (KEY_STATE_INVALID otherwise); the key's audit
// log records the use.
func OpenVersion(ctx context.Context, server *ServerContext, tx core.IamStore, version *core.Object, use *Principal) (result string, err error) {
	if version.Get("state") == "disabled" {
		return "", core.NewIamError("VERSION_DISABLED", "This version is disabled", 409)
	}
	return OpenStored(ctx, server, tx, version, use)
}

// OpenStored (vault.ts openStored): A version's value whatever its state (re-encryption under another key);
// destroyed versions have none.
func OpenStored(ctx context.Context, server *ServerContext, tx core.IamStore, version *core.Object, use *Principal) (result string, err error) {
	sealed := version.Get("sealed")
	if version.Get("state") == "destroyed" || isUndefined(sealed) {
		return "", core.NewIamError("VERSION_DESTROYED", "This version was destroyed", 410)
	}
	keyID := version.Get("kmsKeyId")
	if isUndefined(keyID) {
		return VaultOpenValue(server, jsString(sealed), VersionContext(version))
	}
	return KmsDecryptFor(ctx, server, tx, jsString(version.Get("tenantId")),
		core.NewObject("ciphertext", sealed, "keyId", keyID), VersionContext(version), vaultUse(use))
}

// SelectVersion (vault.ts selectVersion): Resolves `version` / `stage` (default `current`) to a version record of
// the secret.
func SelectVersion(ctx context.Context, tx core.IamStore, secret *core.Object, input *core.Object) (result *core.Object, err error) {
	rawVersion, rawStage := input.Get("version"), input.Get("stage")
	if !isUndefined(rawVersion) && !isUndefined(rawStage) {
		return nil, invalidInput("Pass version or stage, not both")
	}
	var number any = core.Undefined
	if !isUndefined(rawVersion) {
		value, err := Integer(rawVersion, "version", 1, maxSafeInteger)
		if err != nil {
			return nil, err
		}
		number = value
	} else {
		label := "current"
		if !isUndefined(rawStage) {
			if label, err = StageName(rawStage); err != nil {
				return nil, err
			}
		}
		stages, _ := secret.Get("stages").(*core.Object)
		if value, ok := stages.Lookup(label); ok {
			number = value
		} else if label == "constructor" {
			// `stages.constructor` is Object.prototype.constructor: defined, and no version is keyed by it.
			number = "function Object() { [native code] }"
		}
	}
	if isUndefined(number) {
		message := "No version has this stage"
		if isUndefined(rawStage) {
			message = "This secret has no current version"
		}
		return nil, core.NewIamError("NOT_FOUND", message, 404)
	}
	version, err := versionOfKey(ctx, tx, secret, jsString(number))
	if err != nil {
		return nil, err
	}
	if version == nil {
		return nil, core.NewIamError("NOT_FOUND", "Version not found", 404)
	}
	return version, nil
}

// RecordAccess (vault.ts recordAccess): records one use of a secret for its access log (`identityId`, `action`, and
// optional `version`, `leaseId`, `sessionKind`, `agentId`); a reveal, check-out or lease also stamps the secret's
// `lastAccessedAt`.
func RecordAccess(ctx context.Context, server *ServerContext, tx core.IamStore, secret *core.Object, entry *core.Object) (err error) {
	at := float64(server.Now())
	record := core.NewObject(
		"id", ID(),
		"tenantId", secret.Get("tenantId"),
		"secretId", secret.Get("id"),
		"name", secret.Get("name"),
		"identityId", entry.Get("identityId"),
		"action", entry.Get("action"),
	)
	for _, key := range []string{"version", "leaseId", "sessionKind", "agentId"} {
		if value := entry.Get(key); !isUndefined(value) {
			record.Set(key, value)
		}
	}
	settings, err := VaultSettings(server)
	if err != nil {
		return err
	}
	record.Set("at", at)
	record.Set("expiresAt", at+jsNumber(settings.Get("accessRetentionMs")))
	if _, err := tx.Insert(ctx, VaultCollections.Access, record); err != nil {
		return err
	}
	switch entry.Get("action") {
	case "reveal", "checkout", "lease":
		current, err := tx.Get(ctx, VaultCollections.Secrets, jsString(secret.Get("id")))
		if err != nil {
			return err
		}
		if current != nil {
			if _, err := tx.Put(ctx, VaultCollections.Secrets, current.Spread(core.NewObject("lastAccessedAt", at))); err != nil {
				return err
			}
		}
	}
	return nil
}

// LiveLeases (vault.ts liveLeases): Active check-outs and leases of a secret, in issue order.
func LiveLeases(ctx context.Context, server *ServerContext, tx core.IamStore, secret *core.Object) (result []*core.Object, err error) {
	now := float64(server.Now())
	leases, err := tx.Find(ctx, VaultCollections.Leases, core.NewObject(
		"tenantId", secret.Get("tenantId"),
		"secretId", secret.Get("id"),
		"state", "active",
	), nil)
	if err != nil {
		return nil, err
	}
	live := make([]*core.Object, 0, len(leases))
	for _, lease := range leases {
		if jsNumber(lease.Get("expiresAt")) > now {
			live = append(live, lease)
		}
	}
	sort.SliceStable(live, func(a, b int) bool {
		return jsNumber(live[a].Get("issuedAt"))-jsNumber(live[b].Get("issuedAt")) < 0
	})
	return live, nil
}

// SecretAttributes (vault.ts secretAttributes): The policy attributes of a secret: `resource.name`,
// `resource.tag.{key}`, and its settings.
func SecretAttributes(secret *core.Object) (result *core.Object, err error) {
	attributes := core.NewObject(
		"name", secret.Get("name"),
		"kind", secret.Get("kind"),
		"format", secret.Get("format"),
		"status", secret.Get("status"),
		"createdBy", secret.Get("createdBy"),
		"checkoutRequired", member(secret.Get("checkout"), "required") == true,
		"rotationEnabled", !isUndefined(member(secret.Get("rotation"), "intervalDays")),
		"customerManagedKey", !isUndefined(secret.Get("kmsKeyId")),
	)
	if engine := secret.Get("engine"); !isUndefined(engine) {
		attributes.Set("engine", engine)
	}
	if tags, ok := secret.Get("tags").(*core.Object); ok {
		tags.Entries(func(key string, value any) bool {
			attributes.Set("tag."+key, value)
			return true
		})
	}
	return attributes, nil
}

// ResolveSecretResource (vault.ts resolveSecretResource): the decision engine's resolver for
// `iam/vault/secrets/{name}`: an existing secret carries its attributes; a name nobody uses yet resolves without any
// (conditions on them then fail closed), never falling through to a managed resource that could plant attributes.
// nil for other resources.
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

// --- external calls ------------------------------------------------------------------------------

// WithTimeout (vault.ts withTimeout): Runs a rotator or engine call with the configured timeout. The call's context
// ends at the timeout; a call that panics fails like one that throws.
func WithTimeout(ctx context.Context, server *ServerContext, what string, call func(context.Context) (any, error)) (result any, err error) {
	settings, err := VaultSettings(server)
	if err != nil {
		return nil, err
	}
	timeout := jsNumber(settings.Get("callTimeoutMs"))
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
	defer cancel()
	type outcome struct {
		value any
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if recoveredErr, ok := recovered.(error); ok {
					done <- outcome{nil, recoveredErr}
				} else {
					done <- outcome{nil, errors.New(fmt.Sprint(recovered))}
				}
			}
		}()
		value, err := call(callCtx)
		done <- outcome{value, err}
	}()
	timer := time.NewTimer(time.Duration(timeout) * time.Millisecond)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.value, result.err
	case <-timer.C:
		return nil, errors.New(what + " did not finish within " + core.NumberString(timeout) + " ms")
	}
}

// sensitiveForms: Every form a secret value might take inside an error message: the value itself and, for a JSON
// object, each string (and number) field, each with its JSON-escaped, URL-encoded and base64 spellings. Longest
// first, so a field inside a longer match is not left half-redacted.
func sensitiveForms(values []string) []string {
	plain := newOrderedSet()
	for _, value := range values {
		if value == "" {
			continue
		}
		plain.Add(value)
		if strings.HasPrefix(value, "{") {
			// Not JSON: the value alone.
			if parsed, err := core.ParseJSONString(value); err == nil {
				if object, ok := parsed.(*core.Object); ok && object != nil {
					object.Entries(func(_ string, field any) bool {
						switch field.(type) {
						case string, float64:
							plain.Add(jsString(field))
						}
						return true
					})
				}
			}
		}
	}
	forms := newOrderedSet()
	for _, value := range plain.Values() {
		if utf16Len(value) < 4 {
			continue
		}
		forms.Add(value)
		quoted := core.MustStringify(value)
		forms.Add(quoted[1 : len(quoted)-1])
		forms.Add(encodeURIComponent(value))
		forms.Add(strings.TrimRight(base64.StdEncoding.EncodeToString(utf8Bytes(value)), "="))
	}
	out := make([]string, 0, forms.Len())
	for _, form := range forms.Values() {
		if utf16Len(form) >= 4 {
			out = append(out, form)
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return utf16Len(out[b])-utf16Len(out[a]) < 0 })
	return out
}

// RedactedMessage (vault.ts redactedMessage): An error message safe to store: at most 512 characters, with any
// secret value (or field of one) it quotes redacted. Empty strings in values stand for absent ones.
func RedactedMessage(errorValue any, values []string) (result string, err error) {
	var message string
	switch value := errorValue.(type) {
	case error:
		message = value.Error()
	default:
		message = jsString(value)
	}
	for _, form := range sensitiveForms(values) {
		message = strings.ReplaceAll(message, form, "[redacted]")
	}
	cleaned := []byte(message)
	for index, c := range cleaned {
		if c < 0x20 {
			cleaned[index] = ' '
		}
	}
	units := core.ToUTF16(string(cleaned))
	if len(units) > 512 {
		units = units[:512]
	}
	message = core.FromUTF16(units)
	if message == "" {
		return "Unknown error", nil
	}
	return message, nil
}
