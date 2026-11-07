package server

// Port of packages/server/src/devices.ts. Device posture: registered devices, the keys that prove a request comes from
// one, and the compliance of the devices an MDM or EDR integration manages. A browser or agent enrols a public key
// (`devices.enroll`); every request can then carry a short-lived signed proof (`x-better-iam-device`) bound to the
// presenting session. Decisions verify that proof against the stored key only (never a key the proof carries) and
// expose the device's assurance to policies as `request.deviceAssurance`, `request.deviceManaged`,
// `request.deviceCompliant`, `request.deviceId` and `request.devicePlatform`, read only when a document names them.
//
// Not to be confused with remembered browsers (`authDevices`, `TrustedDevice`), which skip a second factor: a
// registered device never satisfies MFA and remembered browsers never count as registered devices.

import (
	"context"
	"math"
	"net/http"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// DeviceProofType is the `typ` every device proof's protected header must carry, exactly.
const DeviceProofType = "device-proof+jwt"

// DeviceProofSkewSeconds is how far a proof's `iat` may lie from the server clock, either way.
const DeviceProofSkewSeconds = 300

// dottedVersion is a dotted numeric version: 1 to 8 parts of at most 9 digits.
var dottedVersion = regexp.MustCompile(`^[0-9]{1,9}(?:\.[0-9]{1,9}){0,7}$`)

// proofHeaderMembers are the only protected header members a device proof may carry; `jwk`, `jku`, `x5u`, `x5c`,
// `crit` and all others are refused.
var proofHeaderMembers = []string{"alg", "typ", "kid"}

// defaultDeviceSettings is devices.ts defaultDeviceSettings.
func defaultDeviceSettings() *core.Object {
	return core.NewObject(
		"requireEncrypted", false,
		"requireScreenLock", false,
		"requireFirewall", false,
		"requireEdr", false,
		"blockJailbroken", true,
		"minOsVersions", core.NewObject(),
		"maxCheckInAgeHours", 24.0,
	)
}

// IsOsVersion (devices.ts isOsVersion): Whether a value is a dotted numeric version of at most 32 characters.
func IsOsVersion(value any) (result bool, err error) {
	text, ok := value.(string)
	return ok && utf16Len(text) <= 32 && dottedVersion.MatchString(text), nil
}

// isOsVersion is IsOsVersion without the error.
func isOsVersion(value any) bool {
	result, _ := IsOsVersion(value)
	return result
}

// compareOsVersions (devices.ts compareOsVersions) compares two dotted numeric versions part by part (missing parts
// count as 0): negative, 0 or positive.
func compareOsVersions(left, right string) int {
	parts := func(version string) []float64 {
		split := strings.Split(version, ".")
		out := make([]float64, len(split))
		for index, part := range split {
			out[index] = stringToNumber(part)
		}
		return out
	}
	a, b := parts(left), parts(right)
	length := len(a)
	if len(b) > length {
		length = len(b)
	}
	for index := 0; index < length; index++ {
		var x, y float64
		if index < len(a) {
			x = a[index]
		}
		if index < len(b) {
			y = b[index]
		}
		if difference := x - y; difference != 0 {
			if difference < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ResolveDeviceSettings (devices.ts resolveDeviceSettings): The requirements for a tenant: the stored settings over
// the defaults (stored values were validated on write).
func ResolveDeviceSettings(stored *core.Object) (result *core.Object, err error) {
	defaults := defaultDeviceSettings()
	flagOf := func(name string) bool {
		if stored != nil {
			if value, ok := stored.Get(name).(bool); ok {
				return value
			}
		}
		return defaults.Get(name).(bool)
	}
	minimums := core.NewObject()
	if stored != nil {
		if map_, ok := stored.Get("minOsVersions").(*core.Object); ok && map_ != nil {
			for _, platform := range DevicePlatforms {
				if minimum := map_.Get(platform); isOsVersion(minimum) {
					minimums.Set(platform, minimum)
				}
			}
		}
	}
	hours := defaults.Get("maxCheckInAgeHours")
	if stored != nil {
		if value, ok := stored.Get("maxCheckInAgeHours").(float64); ok && core.IsSafeInteger(value) && value >= 1 && value <= 720 {
			hours = value
		}
	}
	return core.NewObject(
		"requireEncrypted", flagOf("requireEncrypted"),
		"requireScreenLock", flagOf("requireScreenLock"),
		"requireFirewall", flagOf("requireFirewall"),
		"requireEdr", flagOf("requireEdr"),
		"blockJailbroken", flagOf("blockJailbroken"),
		"minOsVersions", minimums,
		"maxCheckInAgeHours", hours,
	), nil
}

// resolveDeviceSettings is ResolveDeviceSettings without the error.
func resolveDeviceSettings(stored *core.Object) *core.Object {
	result, _ := ResolveDeviceSettings(stored)
	return result
}

// DeviceSettingsOf (devices.ts deviceSettingsOf): The tenant's resolved requirements, read from storage.
func DeviceSettingsOf(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	stored, err := tx.Get(ctx, DeviceCollections.Settings, tenantID)
	if err != nil {
		return nil, err
	}
	if stored != nil && stored.Get("tenantId") != tenantID {
		stored = nil
	}
	return resolveDeviceSettings(stored), nil
}

// EvaluateCompliance (devices.ts evaluateCompliance): Judges a device against the tenant's requirements. Only an
// active device an active integration manages can be compliant: its last check-in must be recent, the vendor's
// verdict (when trusted) must not be `false`, every required posture field must be reported `true` (unknown fails),
// a jailbroken device fails while `blockJailbroken` is on, and a minimum OS version for the platform needs a
// reported version at least that high.
func EvaluateCompliance(device *core.Object, integration *core.Object, settings *core.Object, now int64) (result *core.Object, err error) {
	reasons := []any{}
	switch device.Get("status") {
	case "lost":
		reasons = append(reasons, "lost")
	case "active":
	default:
		reasons = append(reasons, "retired")
	}
	source := device.Get("source")
	linked := !isUndefined(source) && integration != nil &&
		integration.Get("id") == member(source, "integrationId") &&
		integration.Get("tenantId") == device.Get("tenantId")
	managed := linked && integration.Get("status") == "active"
	if !linked {
		reasons = append(reasons, "not-managed")
	} else if !managed {
		reasons = append(reasons, "integration-disabled")
	}
	if !managed {
		return core.NewObject("compliant", false, "managed", managed, "reasons", reasons), nil
	}
	// Posture reported under another integration (before the device moved) says nothing about this one.
	posture, _ := device.Get("posture").(*core.Object)
	if posture != nil && posture.Get("integrationId") != integration.Get("id") {
		posture = nil
	}
	if posture == nil {
		return core.NewObject("compliant", false, "managed", managed, "reasons", append(reasons, "stale")), nil
	}
	checkedAt := device.Get("lastCheckInAt")
	if nullish(checkedAt) {
		checkedAt = posture.Get("reportedAt")
	}
	if !(float64(now)-jsNumber(checkedAt) <= jsNumber(settings.Get("maxCheckInAgeHours"))*3_600_000) {
		reasons = append(reasons, "stale")
	}
	if truthy(integration.Get("trustVendorCompliance")) && posture.Get("compliant") == false {
		reasons = append(reasons, "vendor-noncompliant")
	}
	if truthy(settings.Get("requireEncrypted")) && posture.Get("encrypted") != true {
		reasons = append(reasons, "not-encrypted")
	}
	if truthy(settings.Get("requireScreenLock")) && posture.Get("screenLock") != true {
		reasons = append(reasons, "no-screen-lock")
	}
	if truthy(settings.Get("requireFirewall")) && posture.Get("firewall") != true {
		reasons = append(reasons, "no-firewall")
	}
	if truthy(settings.Get("requireEdr")) && posture.Get("edrHealthy") != true {
		reasons = append(reasons, "edr-unhealthy")
	}
	if truthy(settings.Get("blockJailbroken")) && posture.Get("jailbroken") == true {
		reasons = append(reasons, "jailbroken")
	}
	minimum := member(settings.Get("minOsVersions"), jsString(device.Get("platform")))
	if !isUndefined(minimum) {
		osVersion := posture.Get("osVersion")
		if !isOsVersion(osVersion) {
			reasons = append(reasons, "os-unknown")
		} else if compareOsVersions(osVersion.(string), jsString(minimum)) < 0 {
			reasons = append(reasons, "os-too-old")
		}
	}
	return core.NewObject("compliant", len(reasons) == 0, "managed", managed, "reasons", reasons), nil
}

// evaluateCompliance is EvaluateCompliance without the error.
func evaluateCompliance(device, integration, settings *core.Object, now int64) *core.Object {
	result, _ := EvaluateCompliance(device, integration, settings, now)
	return result
}

// AssuranceOf (devices.ts assuranceOf): The assurance a request gets from a device: `none` unless `registered` (a
// verified, active device).
func AssuranceOf(result2 *core.Object, registered bool) (result string, err error) {
	if !registered {
		return "none", nil
	}
	if truthy(result2.Get("compliant")) {
		return "compliant", nil
	}
	if truthy(result2.Get("managed")) {
		return "managed", nil
	}
	return "registered", nil
}

// assuranceOf is AssuranceOf without the error.
func assuranceOf(compliance *core.Object, registered bool) string {
	result, _ := AssuranceOf(compliance, registered)
	return result
}

// complianceOf (devices.ts complianceOf) is a device's compliance, reading its integration and the tenant's settings.
func complianceOf(ctx context.Context, tx core.IamStore, device *core.Object, now int64) (*core.Object, error) {
	var integration *core.Object
	if source := device.Get("source"); truthy(source) {
		found, err := tx.Get(ctx, DeviceCollections.Integrations, jsString(member(source, "integrationId")))
		if err != nil {
			return nil, err
		}
		integration = found
	}
	settings, err := DeviceSettingsOf(ctx, tx, jsString(device.Get("tenantId")))
	if err != nil {
		return nil, err
	}
	return evaluateCompliance(device, integration, settings, now), nil
}

// DeviceKeyAlgorithm (devices.ts deviceKeyAlgorithm): The JWS algorithm a stored key admits: ES256 for EC P-256,
// EdDSA for Ed25519, nothing else ("").
func DeviceKeyAlgorithm(jwk *core.Object) (result string, err error) {
	if jwk == nil {
		return "", nil
	}
	if jwk.Get("kty") == "EC" && jwk.Get("crv") == "P-256" {
		return "ES256", nil
	}
	if jwk.Get("kty") == "OKP" && jwk.Get("crv") == "Ed25519" {
		return "EdDSA", nil
	}
	return "", nil
}

// deviceKeyAlgorithm is DeviceKeyAlgorithm without the error, over any value.
func deviceKeyAlgorithm(jwk any) string {
	object, _ := jwk.(*core.Object)
	result, _ := DeviceKeyAlgorithm(object)
	return result
}

// DeviceProofOf (devices.ts deviceProofOf): the device proof a credential's headers carry (x-better-iam-device), or ""
// when there is none or it is not shaped like a compact JWS of at most 2048 characters.
func DeviceProofOf(headers http.Header) string {
	if headers == nil {
		return ""
	}
	value, present := headerValue(headers, DeviceProofHeader)
	if !present || value == "" || utf16Len(value) > MaxDeviceProofLength || !compactJWS.MatchString(value) {
		return ""
	}
	return value
}

// DeviceProofHeader is the request header that carries a device proof (a compact JWS).
const DeviceProofHeader = "x-better-iam-device"

// MaxDeviceProofLength: proofs longer than this are ignored (never an error).
const MaxDeviceProofLength = 2048

// compactJWS is three base64url segments.
var compactJWS = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// ProofBinding is the session and tenant a principal's device proof is bound to (devices.ts proofBindings): the
// request's own session, or for principals WithRequestDevice made, the session of the request that carried it.
type ProofBinding struct {
	SessionID string
	TenantID  string
}

// BindingOf is the proof binding of a principal (devices.ts bindingOf).
func BindingOf(principal *Principal) ProofBinding {
	if principal.proofBinding != nil {
		return *principal.proofBinding
	}
	return ProofBinding{SessionID: jsString(principal.Session.Get("id")), TenantID: jsString(principal.Session.Get("tenantId"))}
}

// WithRequestDevice (devices.ts withRequestDevice): another principal a request is decided for besides its own (the
// source identity of a role session, the administrator behind a "view as" session), carrying the request's device
// proof, still bound to the request's session and tenant. Without a proof on the request, derived is returned as is.
func WithRequestDevice(derived *Principal, request *Principal) *Principal {
	if request.DeviceProof == "" {
		return derived
	}
	binding := BindingOf(request)
	return &Principal{Identity: derived.Identity, Session: derived.Session, DeviceProof: request.DeviceProof, proofBinding: &binding}
}

// WithDeviceKey (devices.ts withDeviceKey): A principal a job without a request decides for again (the SSH
// certificate sweep), with the device key its original request proved: device conditions then judge that device as
// it stands now (still active, still the identity's or shared, and its current compliance), where they would
// otherwise always see no device.
func WithDeviceKey(principal *Principal, keyID string) (result *Principal, err error) {
	// `{ ...principal }`: a new principal object, so neither the original's proof binding nor its cache carries over.
	return &Principal{Identity: principal.Identity, Session: principal.Session, DeviceProof: principal.DeviceProof, pinnedKey: &keyID}, nil
}

// proofHeaderOf (devices.ts proofHeaderOf) is a well-formed proof's protected header: only `alg`, `typ` (exactly
// `device-proof+jwt`) and a thumbprint `kid`. ok is false otherwise (also where TypeScript throws).
func proofHeaderOf(proof string) (alg any, kid string, ok bool) {
	if proof == "" || utf16Len(proof) > MaxDeviceProofLength || !compactJWS.MatchString(proof) {
		return nil, "", false
	}
	header, err := sjwtDecodeProtectedHeader(proof)
	if err != nil {
		return nil, "", false
	}
	for _, name := range header.Keys() {
		if !containsString(proofHeaderMembers, name) {
			return nil, "", false
		}
	}
	if header.Get("typ") != DeviceProofType {
		return nil, "", false
	}
	kid, isText := header.Get("kid").(string)
	if !isText || !DeviceKeyIDPattern.MatchString(kid) {
		return nil, "", false
	}
	return header.Get("alg"), kid, true
}

// proofSigned (devices.ts proofSigned) is whether a proof is signed with jwk under the algorithm the key's type pins,
// and its claims hold: `iat` within 300 seconds of now either way, `sid` the bound session and `tid`, when present,
// that session's tenant. Malformed input (where TypeScript throws) is false.
func proofSigned(proof string, alg any, jwk *core.Object, binding ProofBinding, now int64) bool {
	algorithm := deviceKeyAlgorithm(jwk)
	if algorithm == "" || alg != algorithm {
		return false
	}
	// Key material comes only from the given key, rebuilt from its public members.
	var key *core.Object
	if jwk.Get("kty") == "EC" {
		key = core.NewObject("kty", "EC", "crv", "P-256", "x", jwk.Get("x"), "y", jwk.Get("y"))
	} else {
		key = core.NewObject("kty", "OKP", "crv", "Ed25519", "x", jwk.Get("x"))
	}
	entry, err := sjwtJwsAlgorithm(algorithm)
	if err != nil {
		return false
	}
	imported, err := sjwtImportJwk(entry, key)
	if err != nil {
		return false
	}
	// compactVerify with algorithms [algorithm].
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return false
	}
	header, err := sjwtParseHeader(parts[0], "JWSInvalid", "JWS Protected Header is invalid")
	if err != nil || header.Get("alg") != algorithm {
		return false
	}
	signature, err := sjwtDecode(parts[2])
	if err != nil {
		return false
	}
	if !sjwtVerifySignature(entry, imported, signature, []byte(parts[0]+"."+parts[1])) {
		return false
	}
	payload, err := sjwtDecode(parts[1])
	if err != nil {
		return false
	}
	// JSON.parse(new TextDecoder().decode(payload)): replacement characters for invalid UTF-8, a leading BOM dropped.
	parsed, err := core.ParseJSONString(strings.TrimPrefix(decodeUTF8(payload), string(rune(0xFEFF))))
	if err != nil {
		return false
	}
	claims, isObject := parsed.(*core.Object)
	if !isObject || claims == nil {
		return false
	}
	iat, isNumber := claims.Get("iat").(float64)
	sid, isText := claims.Get("sid").(string)
	tid := claims.Get("tid")
	return isNumber && !math.IsNaN(iat) && !math.IsInf(iat, 0) &&
		math.Abs(float64(now)/1000-iat) <= DeviceProofSkewSeconds &&
		isText && sid == binding.SessionID &&
		(isUndefined(tid) || tid == binding.TenantID)
}

// deviceOfKey (devices.ts deviceOfKey) is the device a stored key stands for, when it may vouch for the principal:
// active, and shared or the identity's. The answer is a VerifiedDevice ({device, key}), or nil.
func deviceOfKey(ctx context.Context, tx core.IamStore, principal *Principal, key *core.Object) (*core.Object, error) {
	if key == nil || key.Get("tenantId") != principal.Identity.Get("tenantId") {
		return nil, nil
	}
	device, err := tx.Get(ctx, DeviceCollections.Devices, jsString(key.Get("deviceId")))
	if err != nil {
		return nil, err
	}
	if device == nil ||
		device.Get("tenantId") != key.Get("tenantId") ||
		device.Get("status") != "active" ||
		(!isUndefined(device.Get("ownerIdentityId")) && device.Get("ownerIdentityId") != principal.Identity.Get("id")) {
		return nil, nil
	}
	return core.NewObject("device", device, "key", key), nil
}

// verifyDeviceProof (devices.ts verifyDeviceProof) verifies a device proof for a principal; nil for anything short of
// a valid proof (never fails). Simulated principals never verify. Reads only: nothing is written.
func verifyDeviceProof(ctx context.Context, tx core.IamStore, principal *Principal, proof string, now int64) *core.Object {
	if principal.Session.Get("id") == "simulation" {
		return nil
	}
	alg, kid, ok := proofHeaderOf(proof)
	if !ok {
		return nil
	}
	key, err := tx.Get(ctx, DeviceCollections.Keys, kid)
	if err != nil || key == nil || key.Get("id") != kid || key.Get("tenantId") != principal.Identity.Get("tenantId") {
		return nil
	}
	jwk, _ := key.Get("jwk").(*core.Object)
	if !proofSigned(proof, alg, jwk, BindingOf(principal), now) {
		return nil
	}
	verified, err := deviceOfKey(ctx, tx, principal, key)
	if err != nil {
		return nil
	}
	return verified
}

// ProvesPossession (devices.ts provesPossession): Proof of possession for enrolment: the request's device proof must
// be signed with the key being enrolled (its `kid` that key's thumbprint) and bound to the enrolling session, with
// the checks every proof gets. Without it, anyone who saw a public key (one proof is enough to recover it) could
// enrol it first and lock its holder out. Never throws.
func ProvesPossession(ctx context.Context, principal *Principal, jwk *core.Object, keyID string, now int64) (result bool, err error) {
	alg, kid, ok := proofHeaderOf(principal.DeviceProof)
	if !ok || kid != keyID {
		return false, nil
	}
	return proofSigned(principal.DeviceProof, alg, jwk, BindingOf(principal), now), nil
}

// presentedCache is one verification per principal object, so a batch of decisions (authorizeMany) verifies the
// proof once.
type presentedCache struct {
	device *core.Object
}

// PresentedDevice (devices.ts presentedDevice): The device the principal's request presents (its `deviceProof`, or
// the key `withDeviceKey` pinned), verified and judged ({device, key, compliance, assurance}), or nil. A session
// acting in another tenant than the device's (a cross-tenant role session) is decided there, and that tenant neither
// manages the device nor set the requirements it was judged by, so the device counts as registered only: never
// managed or compliant. Cached on the principal object: `currentPrincipal` builds a fresh one per transaction, so the
// cache never outlives the reads. Never fails.
func PresentedDevice(ctx context.Context, tx core.IamStore, principal *Principal, now int64) (result *core.Object, err error) {
	if principal.presented == nil {
		principal.presented = &presentedCache{device: presentDevice(ctx, tx, principal, now)}
	}
	return principal.presented.device, nil
}

// presentDevice is the uncached PresentedDevice (nil for anything that fails).
func presentDevice(ctx context.Context, tx core.IamStore, principal *Principal, now int64) *core.Object {
	var verified *core.Object
	if principal.pinnedKey == nil {
		verified = verifyDeviceProof(ctx, tx, principal, principal.DeviceProof, now)
	} else if principal.Session.Get("id") != "simulation" {
		key, err := tx.Get(ctx, DeviceCollections.Keys, *principal.pinnedKey)
		if err != nil {
			return nil
		}
		if verified, err = deviceOfKey(ctx, tx, principal, key); err != nil {
			return nil
		}
	}
	if verified == nil {
		return nil
	}
	device := verified.Get("device").(*core.Object)
	var compliance *core.Object
	if principal.Session.Get("tenantId") == device.Get("tenantId") {
		judged, err := complianceOf(ctx, tx, device, now)
		if err != nil {
			return nil
		}
		compliance = judged
	} else {
		compliance = core.NewObject("compliant", false, "managed", false, "reasons", []any{"not-managed"})
	}
	return verified.Spread(core.NewObject("compliance", compliance, "assurance", assuranceOf(compliance, true)))
}

// DeviceContext (devices.ts deviceContext): The device keys for a decision: the assurance, managed and compliant
// flags always, the device id and platform when a proof verified. Simulated principals and requests without a valid
// proof get `none`/false. Never throws.
func DeviceContext(ctx context.Context, tx core.IamStore, principal *Principal, now int64) (result *core.Object, err error) {
	presented, _ := PresentedDevice(ctx, tx, principal, now)
	if presented == nil {
		return core.NewObject(
			"request.deviceAssurance", "none",
			"request.deviceManaged", false,
			"request.deviceCompliant", false,
		), nil
	}
	compliance := presented.Get("compliance").(*core.Object)
	device := presented.Get("device").(*core.Object)
	return core.NewObject(
		"request.deviceAssurance", presented.Get("assurance"),
		"request.deviceManaged", compliance.Get("managed"),
		"request.deviceCompliant", compliance.Get("compliant"),
		"request.deviceId", device.Get("id"),
		"request.devicePlatform", device.Get("platform"),
	), nil
}

// MentionsDevice (devices.ts mentionsDevice): whether any document names a device key (`request.device…`), in
// conditions or `${…}` variables.
func MentionsDevice(documents []any) bool {
	return anyStatementsMention(documents, "request.device")
}

// RetireDevice (devices.ts retireDevice): Retires a device: status `retired`, every key and pending enrollment code
// for it deleted. Returns {device, keysRemoved}.
func RetireDevice(ctx context.Context, tx core.IamStore, device *core.Object, now int64) (result *core.Object, err error) {
	filter := core.NewObject("tenantId", device.Get("tenantId"), "deviceId", device.Get("id"))
	keys, err := tx.Find(ctx, DeviceCollections.Keys, filter, nil)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if err := tx.Delete(ctx, DeviceCollections.Keys, jsString(key.Get("id"))); err != nil {
			return nil, err
		}
	}
	enrollments, err := tx.Find(ctx, DeviceCollections.Enrollments, filter.Clone(), nil)
	if err != nil {
		return nil, err
	}
	for _, enrollment := range enrollments {
		if err := tx.Delete(ctx, DeviceCollections.Enrollments, jsString(enrollment.Get("id"))); err != nil {
			return nil, err
		}
	}
	retired, err := tx.Put(ctx, DeviceCollections.Devices, device.Spread(core.NewObject("status", "retired", "updatedAt", float64(now))))
	if err != nil {
		return nil, err
	}
	return core.NewObject("device", retired, "keysRemoved", float64(len(keys))), nil
}

// ReleaseDevicesOf (devices.ts releaseDevicesOf): Devices of a deleted identity: its self-enrolled (unmanaged)
// devices are retired with their keys, managed ones lose their owner (the integration may assign someone else) and
// the keys the person bound to them, and enrollment codes issued for the person are withdrawn. Shared devices keep
// the keys the person enrolled on them.
func ReleaseDevicesOf(ctx context.Context, tx core.IamStore, identity *core.Object, now int64) (err error) {
	tenantID, identityID := identity.Get("tenantId"), identity.Get("id")
	devices, err := tx.Find(ctx, DeviceCollections.Devices, core.NewObject("tenantId", tenantID, "ownerIdentityId", identityID), nil)
	if err != nil {
		return err
	}
	for _, device := range devices {
		if !truthy(device.Get("source")) {
			if device.Get("status") != "retired" {
				if _, err := RetireDevice(ctx, tx, device, now); err != nil {
					return err
				}
			}
			continue
		}
		keys, err := tx.Find(ctx, DeviceCollections.Keys, core.NewObject("tenantId", tenantID, "deviceId", device.Get("id"), "createdBy", identityID), nil)
		if err != nil {
			return err
		}
		for _, key := range keys {
			if err := tx.Delete(ctx, DeviceCollections.Keys, jsString(key.Get("id"))); err != nil {
				return err
			}
		}
		rest := device.Spread()
		rest.Delete("ownerIdentityId")
		if _, err := tx.Put(ctx, DeviceCollections.Devices, rest.Set("updatedAt", float64(now))); err != nil {
			return err
		}
	}
	enrollments, err := tx.Find(ctx, DeviceCollections.Enrollments, core.NewObject("tenantId", tenantID, "ownerIdentityId", identityID), nil)
	if err != nil {
		return err
	}
	for _, enrollment := range enrollments {
		if err := tx.Delete(ctx, DeviceCollections.Enrollments, jsString(enrollment.Get("id"))); err != nil {
			return err
		}
	}
	return nil
}

// anyStatementsMention is `JSON.stringify(document.statements).includes(text)` over documents (undefined skipped).
func anyStatementsMention(documents []any, text string) bool {
	for _, document := range documents {
		if nullish(document) {
			continue
		}
		serialized, _, _ := core.Stringify(member(document, "statements"))
		if strings.Contains(serialized, text) {
			return true
		}
	}
	return false
}

// anyConditionNames is whether any statement of the documents names one of keys in a condition block.
func anyConditionNames(documents []any, keys ...string) bool {
	for _, document := range documents {
		for _, statement := range statementsOf(document) {
			conditions, _ := member(statement, "conditions").(*core.Object)
			if conditions == nil {
				continue
			}
			found := false
			conditions.Entries(func(_ string, block any) bool {
				object, ok := block.(*core.Object)
				if !ok || object == nil {
					return true
				}
				for _, key := range keys {
					if object.Has(key) {
						found = true
						return false
					}
				}
				return true
			})
			if found {
				return true
			}
		}
	}
	return false
}

// DeviceCollections is devices.ts deviceCollections.
var DeviceCollections = struct {
	Devices      string
	Keys         string
	Enrollments  string
	Integrations string
	Settings     string
}{"registeredDevices", "deviceKeys", "deviceEnrollments", "deviceIntegrations", "deviceSettings"}

// DeviceIntegrationVendors is devices.ts deviceIntegrationVendors.
var DeviceIntegrationVendors = []string{"intune", "jamf", "kandji", "workspace-one", "google-endpoint", "crowdstrike", "sentinelone", "custom"}

// DeviceKeyIDPattern is devices.ts deviceKeyIdPattern.
var DeviceKeyIDPattern = regexp.MustCompile("^[A-Za-z0-9_-]{43}$")

// DevicePlatforms is devices.ts devicePlatforms.
var DevicePlatforms = []string{"windows", "macos", "linux", "ios", "android", "chromeos", "other"}

// MaxDeviceIntegrations is devices.ts maxDeviceIntegrations.
const MaxDeviceIntegrations = 20

// MaxDevicesPerPerson is devices.ts maxDevicesPerPerson.
const MaxDevicesPerPerson = 20

// MaxKeysPerDevice is devices.ts maxKeysPerDevice.
const MaxKeysPerDevice = 20
