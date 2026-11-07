package server

// Skeleton of packages/server/src/devices.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// AssuranceOf (devices.ts assuranceOf): The assurance a request gets from a device: `none` unless `registered` (a
// verified, active device).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssuranceOf(result2 *core.Object, registered bool) (result string, err error) {
	err = notImplemented("devices.ts assuranceOf")
	return
}

// DeviceContext (devices.ts deviceContext): The device keys for a decision: the assurance, managed and compliant
// flags always, the device id and platform when a proof verified. Simulated principals and requests without a valid
// proof get `none`/false. Never throws.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeviceContext(ctx context.Context, tx core.IamStore, principal *Principal, now int64) (result *core.Object, err error) {
	err = notImplemented("devices.ts deviceContext")
	return
}

// DeviceKeyAlgorithm (devices.ts deviceKeyAlgorithm): The JWS algorithm a stored key admits: ES256 for EC P-256,
// EdDSA for Ed25519, nothing else.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeviceKeyAlgorithm(jwk *core.Object) (result string, err error) {
	err = notImplemented("devices.ts deviceKeyAlgorithm")
	return
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

// DeviceSettingsOf (devices.ts deviceSettingsOf): The tenant's resolved requirements, read from storage.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeviceSettingsOf(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("devices.ts deviceSettingsOf")
	return
}

// EvaluateCompliance (devices.ts evaluateCompliance): Judges a device against the tenant's requirements. Only an
// active device an active integration manages can be compliant: its last check-in must be recent, the vendor's
// verdict (when trusted) must not be `false`, every required posture field must be reported `true` (unknown fails),
// a jailbroken device fails while `blockJailbroken` is on, and a minimum OS version for the platform needs a
// reported version at least that high.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EvaluateCompliance(device *core.Object, integration *core.Object, settings *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("devices.ts evaluateCompliance")
	return
}

// IsOsVersion (devices.ts isOsVersion): Whether a value is a dotted numeric version of at most 32 characters.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func IsOsVersion(value any) (result bool, err error) {
	err = notImplemented("devices.ts isOsVersion")
	return
}

// MentionsDevice (devices.ts mentionsDevice): whether any document names a device key (`request.device…`), in
// conditions or `${…}` variables.
func MentionsDevice(documents []any) bool {
	return anyStatementsMention(documents, "request.device")
}

// PresentedDevice (devices.ts presentedDevice): The device the principal's request presents (its `deviceProof`, or
// the key `withDeviceKey` pinned), verified and judged, or undefined. A session acting in another tenant than the
// device's (a cross-tenant role session) is decided there, and that tenant neither manages the device nor set the
// requirements it was judged by, so the device counts as registered only: never managed or compliant. Cached on the
// principal object: `currentPrincipal` builds a fresh one per transaction, so the cache never outlives the reads.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PresentedDevice(ctx context.Context, tx core.IamStore, principal *Principal, now int64) (result *core.Object, err error) {
	err = notImplemented("devices.ts presentedDevice")
	return
}

// ProvesPossession (devices.ts provesPossession): Proof of possession for enrolment: the request's device proof must
// be signed with the key being enrolled (its `kid` that key's thumbprint) and bound to the enrolling session, with
// the checks every proof gets. Without it, anyone who saw a public key (one proof is enough to recover it) could
// enrol it first and lock its holder out. Never throws.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ProvesPossession(ctx context.Context, principal *Principal, jwk *core.Object, keyID string, now int64) (result bool, err error) {
	err = notImplemented("devices.ts provesPossession")
	return
}

// ReleaseDevicesOf (devices.ts releaseDevicesOf): Devices of a deleted identity: its self-enrolled (unmanaged)
// devices are retired with their keys, managed ones lose their owner (the integration may assign someone else) and
// the keys the person bound to them, and enrollment codes issued for the person are withdrawn. Shared devices keep
// the keys the person enrolled on them.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReleaseDevicesOf(ctx context.Context, tx core.IamStore, identity *core.Object, now int64) (err error) {
	err = notImplemented("devices.ts releaseDevicesOf")
	return
}

// ResolveDeviceSettings (devices.ts resolveDeviceSettings): The requirements for a tenant: the stored settings over
// the defaults (stored values were validated on write).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ResolveDeviceSettings(stored *core.Object) (result *core.Object, err error) {
	err = notImplemented("devices.ts resolveDeviceSettings")
	return
}

// RetireDevice (devices.ts retireDevice): Retires a device: status `retired`, every key and pending enrollment code
// for it deleted. Returns the keys removed.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RetireDevice(ctx context.Context, tx core.IamStore, device *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("devices.ts retireDevice")
	return
}

// WithDeviceKey (devices.ts withDeviceKey): A principal a job without a request decides for again (the SSH
// certificate sweep), with the device key its original request proved: device conditions then judge that device as
// it stands now (still active, still the identity's or shared, and its current compliance), where they would
// otherwise always see no device.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WithDeviceKey(principal *Principal, keyID string) (result *Principal, err error) {
	err = notImplemented("devices.ts withDeviceKey")
	return
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
