package server

// Port of packages/server/src/api/devices.ts. Device posture: registered devices, the keys that prove a request comes
// from one, the integrations (MDM, EDR) that manage devices and report their posture, and the tenant's compliance
// requirements. People enrol their own devices and list or retire them without a permission; administrators hold
// `iam:devices:read` / `iam:devices:manage` on `iam/devices…`; integrations report with `iam:devices:report` on
// `iam/devices/integrations/{id}` (an API key of a service account). Policies see the presenting device as
// `request.deviceAssurance`, `request.deviceManaged`, `request.deviceCompliant`, `request.deviceId` and
// `request.devicePlatform`.

import (
	"context"
	"crypto/sha256"
	"regexp"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// DevicesAPI is the `devices` API group (packages/server/src/api/devices.ts createDevicesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/devices/{method} onto it.
type DevicesAPI struct {
	server *ServerContext
}

// CreateDevicesAPI builds the `devices` API group.
func CreateDevicesAPI(server *ServerContext) *DevicesAPI {
	return &DevicesAPI{server: server}
}

const (
	deviceDay                   = 86_400_000
	deviceMinEnrollmentMs       = 10 * 60_000
	deviceMaxEnrollmentMs       = 30 * deviceDay
	deviceDefaultEnrollmentMs   = 7 * deviceDay
	deviceMaxPendingEnrollments = 1000 // pending (unused, unexpired) enrollment codes per tenant
	deviceMaxReportedDevices    = 500  // devices per `devices.report` call
	deviceEnrollAttempts        = 30   // self-enrolments one person may attempt per rate-limit window
	// deviceTouchMs: `lastCheckInAt`, `lastSeenAt` and `lastUsedAt` are written at most this often unless something
	// else changed.
	deviceTouchMs = 60_000
)

var (
	deviceEnrollmentCodePattern = regexp.MustCompile(`^biam_denr_[A-Za-z0-9_-]{43}$`)
	deviceCoordinate            = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	devicePrivateMembers        = []string{"d", "p", "q", "dp", "dq", "qi", "k", "oth"}
	// deviceExternalIDPattern is a vendor device id: printable ASCII without leading or trailing spaces.
	deviceExternalIDPattern = regexp.MustCompile(`^[!-~](?:[ -~]{0,198}[!-~])?$`)
	deviceLeadingVersion    = regexp.MustCompile(`(?i)^v?([0-9]{1,9}(?:\.[0-9]{1,9}){0,7})`)
	devicePostureFields     = []string{"compliant", "encrypted", "firewall", "screenLock", "edrHealthy", "jailbroken"}
	deviceReportFields      = []string{"externalId", "name", "platform", "serialNumber", "model", "osVersion", "ownerEmail", "ownerIdentityId", "keyThumbprint", "posture", "checkedInAt"}
)

func deviceResource(deviceID string) string { return "devices/" + deviceID }

func deviceIntegrationResource(integrationID string) string {
	return "devices/integrations/" + integrationID
}

// devicePlatformOf is api/devices.ts platformOf.
func devicePlatformOf(value any, name string) (string, error) {
	text, ok := value.(string)
	if !ok || !containsString(DevicePlatforms, text) {
		return "", invalidInput(name + " must be one of " + strings.Join(DevicePlatforms, ", "))
	}
	return text, nil
}

// deviceFlag is api/devices.ts flag.
func deviceFlag(value any, name string) (bool, error) {
	result, ok := value.(bool)
	if !ok {
		return false, invalidInput(name + " must be a boolean")
	}
	return result, nil
}

// deviceFieldsOf is the input object, refusing fields the call does not know (a misspelt setting must not pass
// silently).
func deviceFieldsOf(value any, allowed []string) (*core.Object, error) {
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	for _, key := range input.Keys() {
		if !containsString(allowed, key) {
			return nil, invalidInput("Unknown field " + key)
		}
	}
	return input, nil
}

func deviceNameOf(value any) (string, error) {
	text, err := Text(value, "name", 128)
	if err != nil {
		return "", err
	}
	return core.JSTrim(text), nil
}

func deviceInvalidKey() error {
	return invalidInput("publicKey must be a public EC P-256 or Ed25519 JWK")
}

// devicePublicKeyOf is a public EC P-256 or Ed25519 JWK reduced to its public members; private material is refused
// outright.
func devicePublicKeyOf(value any) (*core.Object, error) {
	jwk, ok := value.(*core.Object)
	if !ok || jwk == nil {
		return nil, deviceInvalidKey()
	}
	for _, name := range devicePrivateMembers {
		if !isUndefined(jwk.Get(name)) {
			return nil, invalidInput("publicKey must not contain private key material")
		}
	}
	if use := jwk.Get("use"); !isUndefined(use) && use != "sig" {
		return nil, deviceInvalidKey()
	}
	x, xOK := jwk.Get("x").(string)
	xOK = xOK && deviceCoordinate.MatchString(x)
	alg := jwk.Get("alg")
	if y, yOK := jwk.Get("y").(string); jwk.Get("kty") == "EC" && jwk.Get("crv") == "P-256" && xOK && yOK &&
		deviceCoordinate.MatchString(y) && (isUndefined(alg) || alg == "ES256") {
		return core.NewObject("kty", "EC", "crv", "P-256", "x", x, "y", y), nil
	}
	if jwk.Get("kty") == "OKP" && jwk.Get("crv") == "Ed25519" && xOK && isUndefined(jwk.Get("y")) &&
		(isUndefined(alg) || alg == "EdDSA" || alg == "Ed25519") {
		return core.NewObject("kty", "OKP", "crv", "Ed25519", "x", x), nil
	}
	return nil, deviceInvalidKey()
}

// deviceKeyIDOf is the key's RFC 7638 thumbprint (its id), after checking the key imports (an EC point must lie on
// the curve).
func deviceKeyIDOf(jwk *core.Object) (string, error) {
	entry, err := sjwtJwsAlgorithm(deviceKeyAlgorithm(jwk))
	if err != nil {
		return "", deviceInvalidKey()
	}
	if _, err := sjwtImportJwk(entry, jwk.Spread()); err != nil {
		return "", deviceInvalidKey()
	}
	var members *core.Object
	if jwk.Get("kty") == "EC" {
		members = core.NewObject("crv", jwk.Get("crv"), "kty", jwk.Get("kty"), "x", jwk.Get("x"), "y", jwk.Get("y"))
	} else {
		members = core.NewObject("crv", jwk.Get("crv"), "kty", jwk.Get("kty"), "x", jwk.Get("x"))
	}
	digest := sha256.Sum256([]byte(core.MustStringify(members)))
	return base64url(digest[:]), nil
}

// deviceOwnSession: self-service calls act for the caller in their own tenant, from a session in their own right.
func deviceOwnSession(principal *Principal, tenantID, message string) error {
	if !ActsInOwnRight(principal.Session) ||
		principal.Session.Get("tenantId") != tenantID ||
		principal.Identity.Get("tenantId") != tenantID {
		return core.NewIamError("ACCESS_DENIED", message, 403)
	}
	return nil
}

func deviceNotImpersonating(principal *Principal) error {
	if truthy(principal.Session.Get("impersonatorId")) {
		return core.NewIamError("IMPERSONATION_RESTRICTED", "Devices cannot be enrolled or retired while impersonating", 403)
	}
	return nil
}

func deviceInvalidCode() error { return invalidInput("Invalid or expired enrollment code") }

func deviceNotFound() error { return core.NewIamError("NOT_FOUND", "Resource not found", 404) }

// deviceView is a registered device as administrators see it (`devices.list`, `devices.get`).
func deviceView(device, compliance *core.Object, keys int, owner *core.Object) *core.Object {
	view := core.NewObject(
		"id", device.Get("id"),
		"tenantId", device.Get("tenantId"),
		"name", device.Get("name"),
		"platform", device.Get("platform"),
		"status", device.Get("status"),
	)
	if value := device.Get("ownerIdentityId"); !isUndefined(value) {
		view.Set("ownerIdentityId", value)
	}
	if owner != nil {
		described := core.NewObject("id", owner.Get("id"), "name", owner.Get("name"))
		if email := owner.Get("email"); !isUndefined(email) {
			described.Set("email", email)
		}
		view.Set("owner", described)
	}
	if source := device.Get("source"); truthy(source) {
		view.Set("source", core.NewObject("integrationId", member(source, "integrationId"), "externalId", member(source, "externalId")))
	}
	for _, name := range []string{"serialNumber", "model"} {
		if value := device.Get(name); !isUndefined(value) {
			view.Set(name, value)
		}
	}
	if posture := device.Get("posture"); truthy(posture) {
		if object, ok := posture.(*core.Object); ok {
			view.Set("posture", object.Spread())
		} else {
			view.Set("posture", core.NewObject())
		}
	}
	for _, name := range []string{"lastCheckInAt", "lastSeenAt", "enrolledBy"} {
		if value := device.Get(name); !isUndefined(value) {
			view.Set(name, value)
		}
	}
	return view.Set("createdAt", device.Get("createdAt")).
		Set("updatedAt", device.Get("updatedAt")).
		Set("compliance", compliance).
		Set("assurance", assuranceOf(compliance, device.Get("status") == "active" && keys > 0)).
		Set("keys", float64(keys))
}

// deviceDescribe is views of devices of one tenant, reading the settings, integrations, key counts and owners once.
func deviceDescribe(ctx context.Context, tx core.IamStore, tenantID string, devices []*core.Object, now int64) ([]*core.Object, error) {
	if len(devices) == 0 {
		return []*core.Object{}, nil
	}
	settings, err := DeviceSettingsOf(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	integrationList, err := tx.Find(ctx, DeviceCollections.Integrations, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	integrations := map[string]*core.Object{}
	for _, integration := range integrationList {
		integrations[jsString(integration.Get("id"))] = integration
	}
	keyCounts := map[string]int{}
	if len(devices) > 20 {
		keys, err := tx.Find(ctx, DeviceCollections.Keys, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			keyCounts[jsString(key.Get("deviceId"))]++
		}
	} else {
		for _, device := range devices {
			keys, err := tx.Find(ctx, DeviceCollections.Keys, core.NewObject("tenantId", tenantID, "deviceId", device.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			keyCounts[jsString(device.Get("id"))] = len(keys)
		}
	}
	owners := map[string]*core.Object{}
	known := map[string]bool{}
	views := []*core.Object{}
	for _, device := range devices {
		ownerID := device.Get("ownerIdentityId")
		var owner *core.Object
		if !isUndefined(ownerID) {
			key := jsString(ownerID)
			if !known[key] {
				identity, err := tx.Get(ctx, "identities", key)
				if err != nil {
					return nil, err
				}
				if identity != nil && identity.Get("tenantId") != tenantID {
					identity = nil
				}
				owners[key], known[key] = identity, true
			}
			owner = owners[key]
		}
		var integration *core.Object
		if source := device.Get("source"); truthy(source) {
			integration = integrations[jsString(member(source, "integrationId"))]
		}
		views = append(views, deviceView(device, evaluateCompliance(device, integration, settings, now), keyCounts[jsString(device.Get("id"))], owner))
	}
	return views, nil
}

// deviceEnrollmentView is an enrollment code as administrators see it; the code itself is shown once, at creation.
func deviceEnrollmentView(enrollment *core.Object, now int64) *core.Object {
	view := core.NewObject("id", enrollment.Get("id"), "tenantId", enrollment.Get("tenantId"))
	for _, name := range []string{"deviceId", "ownerIdentityId"} {
		if value := enrollment.Get(name); !isUndefined(value) {
			view.Set(name, value)
		}
	}
	status := "pending"
	if !isUndefined(enrollment.Get("usedAt")) {
		status = "used"
	} else if jsNumber(enrollment.Get("expiresAt")) <= float64(now) {
		status = "expired"
	}
	view.Set("status", status).
		Set("expiresAt", enrollment.Get("expiresAt")).
		Set("createdAt", enrollment.Get("createdAt")).
		Set("createdBy", enrollment.Get("createdBy"))
	for _, name := range []string{"usedAt", "usedBy"} {
		if value := enrollment.Get(name); !isUndefined(value) {
			view.Set(name, value)
		}
	}
	return view
}

// deviceIntegrationView is a device integration with the number of devices it manages.
func deviceIntegrationView(integration *core.Object, devices int) *core.Object {
	view := core.NewObject(
		"id", integration.Get("id"),
		"tenantId", integration.Get("tenantId"),
		"name", integration.Get("name"),
		"vendor", integration.Get("vendor"),
		"status", integration.Get("status"),
		"trustVendorCompliance", integration.Get("trustVendorCompliance"),
		"createdAt", integration.Get("createdAt"),
		"createdBy", integration.Get("createdBy"),
		"updatedAt", integration.Get("updatedAt"),
	)
	if value := integration.Get("lastReportAt"); !isUndefined(value) {
		view.Set("lastReportAt", value)
	}
	return view.Set("devices", float64(devices))
}

func deviceIntegrationMetadata(integration *core.Object) *core.Object {
	return core.NewObject(
		"name", integration.Get("name"),
		"vendor", integration.Get("vendor"),
		"status", integration.Get("status"),
		"trustVendorCompliance", integration.Get("trustVendorCompliance"),
	)
}

// deviceSettingsView is the tenant's compliance requirements (`devices.getSettings`, `devices.configure`).
func deviceSettingsView(tenantID string, stored *core.Object) *core.Object {
	view := resolveDeviceSettings(stored).Set("tenantId", tenantID).Set("configured", stored != nil)
	if stored != nil {
		view.Set("updatedAt", stored.Get("updatedAt")).Set("updatedBy", stored.Get("updatedBy"))
	}
	return view
}

func deviceSettingsMetadata(settings *core.Object) *core.Object {
	minimums, _ := settings.Get("minOsVersions").(*core.Object)
	return core.NewObject(
		"requireEncrypted", settings.Get("requireEncrypted"),
		"requireScreenLock", settings.Get("requireScreenLock"),
		"requireFirewall", settings.Get("requireFirewall"),
		"requireEdr", settings.Get("requireEdr"),
		"blockJailbroken", settings.Get("blockJailbroken"),
		"minOsVersions", minimums.Spread(),
		"maxCheckInAgeHours", settings.Get("maxCheckInAgeHours"),
	)
}

// devicePerson is a person of the tenant who can own a device (a user identity that is not deleted).
func devicePerson(identity *core.Object, tenantID string) bool {
	return identity != nil &&
		identity.Get("tenantId") == tenantID &&
		identity.Get("kind") == "user" &&
		identity.Get("status") != "deleted"
}

// deviceReportItem is a report item after validation ("" members are absent).
type deviceReportItem struct {
	externalID   string
	name         string
	platform     string
	serialNumber string
	model        string
	osVersion    string
	// ownerNamed is whether the report names an owner at all (then an unknown one clears it).
	ownerNamed      bool
	ownerIdentityID string
	ownerEmail      string
	keyThumbprint   string
	posture         *core.Object
	checkedInAt     float64
}

// deviceReportItems validates the devices of a report.
func deviceReportItems(value any, now int64) ([]*deviceReportItem, error) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 || len(list) > deviceMaxReportedDevices {
		return nil, invalidInput("devices must list 1-" + strconv.Itoa(deviceMaxReportedDevices) + " device reports")
	}
	seen := map[string]bool{}
	items := make([]*deviceReportItem, 0, len(list))
	for index, raw := range list {
		at := "devices[" + strconv.Itoa(index) + "]"
		input, err := deviceFieldsOf(raw, deviceReportFields)
		if err != nil {
			return nil, err
		}
		externalID, isText := input.Get("externalId").(string)
		if !isText || !deviceExternalIDPattern.MatchString(externalID) {
			return nil, invalidInput(at + ".externalId is invalid")
		}
		if seen[externalID] {
			return nil, invalidInput(at + ".externalId repeats an earlier device")
		}
		seen[externalID] = true
		// Connectors often send null or an empty string for a field the vendor does not know: both read as absent.
		given := func(name string) any {
			value := input.Get(name)
			if nullish(value) {
				return core.Undefined
			}
			if text, ok := value.(string); ok && core.JSTrim(text) == "" {
				return core.Undefined
			}
			return value
		}
		optional := func(name string, max int) (string, error) {
			value := given(name)
			if isUndefined(value) {
				return "", nil
			}
			text, err := Text(value, at+"."+name, max)
			if err != nil {
				return "", err
			}
			return core.JSTrim(text), nil
		}
		postureInput := given("posture")
		if isUndefined(postureInput) {
			postureInput = core.NewObject()
		}
		posture, err := deviceFieldsOf(postureInput, devicePostureFields)
		if err != nil {
			return nil, err
		}
		reported := core.NewObject()
		for _, field := range devicePostureFields {
			if value := posture.Get(field); !nullish(value) {
				flagged, err := deviceFlag(value, at+".posture."+field)
				if err != nil {
					return nil, err
				}
				reported.Set(field, flagged)
			}
		}
		osVersion := ""
		if os := given("osVersion"); !isUndefined(os) {
			text, isText := os.(string)
			if !isText || utf16Len(text) > 64 {
				return nil, invalidInput(at + ".osVersion must be a string of at most 64 characters")
			}
			if match := deviceLeadingVersion.FindStringSubmatch(core.JSTrim(text)); match != nil && isOsVersion(match[1]) {
				osVersion = match[1]
			}
		}
		ownerIdentityID, err := optional("ownerIdentityId", 256)
		if err != nil {
			return nil, err
		}
		ownerEmail, err := optional("ownerEmail", 254)
		if err != nil {
			return nil, err
		}
		ownerEmail = core.JSLower(ownerEmail)
		keyThumbprint := ""
		if thumbprint := given("keyThumbprint"); !isUndefined(thumbprint) {
			text, isText := thumbprint.(string)
			if !isText || !DeviceKeyIDPattern.MatchString(text) {
				return nil, invalidInput(at + ".keyThumbprint must be a JWK thumbprint")
			}
			keyThumbprint = text
		}
		checkedInAt := float64(now)
		if reportedAt := given("checkedInAt"); !isUndefined(reportedAt) {
			number, err := Integer(reportedAt, at+".checkedInAt", 0, float64(now)+5*60_000)
			if err != nil {
				return nil, err
			}
			if number < checkedInAt {
				checkedInAt = number
			}
		}
		name, err := optional("name", 128)
		if err != nil {
			return nil, err
		}
		serialNumber, err := optional("serialNumber", 128)
		if err != nil {
			return nil, err
		}
		model, err := optional("model", 128)
		if err != nil {
			return nil, err
		}
		platform, err := devicePlatformOf(input.Get("platform"), at+".platform")
		if err != nil {
			return nil, err
		}
		items = append(items, &deviceReportItem{
			externalID:      externalID,
			name:            name,
			platform:        platform,
			serialNumber:    serialNumber,
			model:           model,
			osVersion:       osVersion,
			ownerNamed:      ownerIdentityID != "" || ownerEmail != "",
			ownerIdentityID: ownerIdentityID,
			ownerEmail:      ownerEmail,
			keyThumbprint:   keyThumbprint,
			posture:         reported,
			checkedInAt:     checkedInAt,
		})
	}
	return items, nil
}

// deviceReportedState is what a report can change on a device, for telling a real change from a repeated check-in.
func deviceReportedState(device *core.Object) string {
	posture := device.Get("posture")
	orNull := func(value any) any {
		if nullish(value) {
			return nil
		}
		return value
	}
	state := []any{device.Get("name"), device.Get("platform"), orNull(device.Get("ownerIdentityId")),
		orNull(device.Get("serialNumber")), orNull(device.Get("model")), orNull(member(posture, "integrationId"))}
	for _, field := range devicePostureFields {
		state = append(state, orNull(member(posture, field)))
	}
	state = append(state, orNull(member(posture, "osVersion")))
	return core.MustStringify(state)
}

// deviceSliceUTF16 is String.prototype.slice(0, end) over UTF-16 units.
func deviceSliceUTF16(text string, end int) string {
	if utf16Len(text) <= end {
		return text
	}
	units := 0
	for index, r := range text {
		width := 1
		if r > 0xFFFF {
			width = 2
		}
		if units+width > end {
			if units < end {
				// A surrogate pair cut in half keeps its lone high surrogate, as JavaScript does.
				return text[:index] + string(rune(0xFFFD))
			}
			return text[:index]
		}
		units += width
	}
	return text
}

// audit writes an allowed audit event.
func (api *DevicesAPI) audit(ctx context.Context, tx core.IamStore, principal *Principal, action, tenantID, resourceID string, metadata *core.Object) error {
	return api.server.Events.Audit(ctx, tx, principal, action, tenantID, resourceID, "allow", false, metadata)
}

// currentDeviceID is the id of the device this request's proof verifies for, if any ("" when none).
func (api *DevicesAPI) currentDeviceID(ctx context.Context, tx core.IamStore, principal *Principal) string {
	presented, _ := PresentedDevice(ctx, tx, principal, api.server.Now())
	if presented == nil {
		return ""
	}
	return jsString(member(presented.Get("device"), "id"))
}

// usableEnrollment is a pending, unexpired enrollment code of the tenant, or INVALID_INPUT.
func (api *DevicesAPI) usableEnrollment(ctx context.Context, tx core.IamStore, tenantID, code string, now int64) (*core.Object, error) {
	codeHash := Hash(code)
	found, err := tx.Find(ctx, DeviceCollections.Enrollments, core.NewObject("tenantId", tenantID, "uniqueKey", codeHash), nil)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, deviceInvalidCode()
	}
	enrollment := found[0]
	if !SameHash(enrollment.Get("codeHash"), codeHash) ||
		!isUndefined(enrollment.Get("usedAt")) ||
		jsNumber(enrollment.Get("expiresAt")) <= float64(now) {
		return nil, deviceInvalidCode()
	}
	return enrollment, nil
}

// ownerOf is a person of the tenant, for owner fields; INVALID_INPUT for anyone else.
func (api *DevicesAPI) ownerOf(ctx context.Context, tx core.IamStore, tenantID string, value any) (*core.Object, error) {
	id, err := Text(value, "ownerIdentityId")
	if err != nil {
		return nil, err
	}
	identity, err := tx.Get(ctx, "identities", id)
	if err != nil {
		return nil, err
	}
	if !devicePerson(identity, tenantID) {
		return nil, invalidInput("ownerIdentityId must name a person of the tenant")
	}
	return identity, nil
}

// claimKey moves a key an integration's agent enrolled onto the device the integration reports it on. Only the key's
// own record of this machine gives it up: the same person's self-enrolled device, or another record of this
// integration with the same owner, and only while that device is active. So a report never revives a key on a device
// an administrator marked lost, never takes one off a shared device, another person's device, or a device another
// integration manages, and never hands a key to a device without the key's owner.
func (api *DevicesAPI) claimKey(ctx context.Context, tx core.IamStore, thumbprint string, device *core.Object, now int64) (bool, error) {
	key, err := tx.Get(ctx, DeviceCollections.Keys, thumbprint)
	if err != nil {
		return false, err
	}
	if key == nil || key.Get("tenantId") != device.Get("tenantId") || key.Get("deviceId") == device.Get("id") {
		return false, nil
	}
	previous, err := tx.Get(ctx, DeviceCollections.Devices, jsString(key.Get("deviceId")))
	if err != nil {
		return false, err
	}
	if previous == nil ||
		previous.Get("tenantId") != device.Get("tenantId") ||
		previous.Get("status") != "active" ||
		isUndefined(previous.Get("ownerIdentityId")) ||
		previous.Get("ownerIdentityId") != device.Get("ownerIdentityId") ||
		(!isUndefined(previous.Get("source")) &&
			member(previous.Get("source"), "integrationId") != member(device.Get("source"), "integrationId")) {
		return false, nil
	}
	if _, err := tx.Put(ctx, DeviceCollections.Keys, key.Spread(core.NewObject("deviceId", device.Get("id")))); err != nil {
		return false, err
	}
	// The same person's self-enrolled record of this machine is superseded by the managed one.
	if !truthy(previous.Get("source")) {
		remaining, err := tx.Find(ctx, DeviceCollections.Keys, core.NewObject("tenantId", previous.Get("tenantId"), "deviceId", previous.Get("id")), nil)
		if err != nil {
			return false, err
		}
		if len(remaining) == 0 {
			if _, err := RetireDevice(ctx, tx, previous, now); err != nil {
				return false, err
			}
		}
	}
	return true, nil
}

// ---------------------------------------------------------------------------------------------------------
// Self-service

// Enroll is POST {basePath}/devices/enroll. Enrolls a public key for the caller's browser or agent, creating their device or binding the key to a device with an enrollment code.
func (api *DevicesAPI) Enroll(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesEnrollInput]) (Out[apitypes.DevicesEnrollOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.DevicesEnrollOutput], error) {
		return Out[apitypes.DevicesEnrollOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	name, err := deviceNameOf(input.Get("name"))
	if err != nil {
		return fail(err)
	}
	platform, err := devicePlatformOf(input.Get("platform"), "platform")
	if err != nil {
		return fail(err)
	}
	jwk, err := devicePublicKeyOf(input.Get("publicKey"))
	if err != nil {
		return fail(err)
	}
	codeValue := input.Get("enrollmentCode")
	hasCode := !isUndefined(codeValue)
	code, _ := codeValue.(string)
	if hasCode && !deviceEnrollmentCodePattern.MatchString(code) {
		return fail(deviceInvalidCode())
	}
	keyID, err := deviceKeyIDOf(jwk)
	if err != nil {
		return fail(err)
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	if authenticated.Session.Get("tenantId") != tenantID {
		return fail(core.NewIamError("ACCESS_DENIED", "Devices are enrolled from an ordinary session of their tenant", 403))
	}
	// Outside the transaction, so a refusal inside it cannot roll the counter back.
	limit := int64(deviceEnrollAttempts)
	if err := server.Auth.LimitAttempt(ctx, tenantID, "device-enroll:"+jsString(authenticated.Identity.Get("id")), auth.LimitAttemptOptions{Limit: &limit}); err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := deviceOwnSession(principal, tenantID, "Devices are enrolled from an ordinary session of their tenant"); err != nil {
			return nil, err
		}
		if err := deviceNotImpersonating(principal); err != nil {
			return nil, err
		}
		if principal.Identity.Get("kind") != "user" {
			return nil, invalidInput("Only people enrol devices")
		}
		// A stolen session must not bring a key of its own (passkey registration asks for a recent sign-in too), and
		// the caller must hold the key: the request carries a proof signed with it for this session.
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if proven, _ := ProvesPossession(ctx, principal, jwk, keyID, server.Now()); !proven {
			return nil, invalidInput("Send a device proof (x-better-iam-device) signed with the key being enrolled")
		}
		callerID := principal.Identity.Get("id")
		existingKey, err := tx.Get(ctx, DeviceCollections.Keys, keyID)
		if err != nil {
			return nil, err
		}
		if existingKey != nil {
			return nil, core.NewIamError("CONFLICT", "This key is already enrolled", 409)
		}
		now := server.Now()
		var enrollment *core.Object
		if hasCode {
			if enrollment, err = api.usableEnrollment(ctx, tx, tenantID, code, now); err != nil {
				return nil, err
			}
		}
		if enrollment != nil && !isUndefined(enrollment.Get("ownerIdentityId")) && enrollment.Get("ownerIdentityId") != callerID {
			return nil, core.NewIamError("ACCESS_DENIED", "This enrollment code is for someone else", 403)
		}
		var device *core.Object
		created := false
		if enrollment != nil && !isUndefined(enrollment.Get("deviceId")) {
			target, err := tx.Get(ctx, DeviceCollections.Devices, jsString(enrollment.Get("deviceId")))
			if err != nil {
				return nil, err
			}
			if target == nil || target.Get("tenantId") != tenantID {
				return nil, deviceInvalidCode()
			}
			if target.Get("status") != "active" {
				return nil, core.NewIamError("INVALID_TRANSITION", "The device is not active", 409)
			}
			if !isUndefined(target.Get("ownerIdentityId")) && target.Get("ownerIdentityId") != callerID {
				return nil, core.NewIamError("ACCESS_DENIED", "The device belongs to someone else", 403)
			}
			keys, err := tx.Find(ctx, DeviceCollections.Keys, core.NewObject("tenantId", tenantID, "deviceId", target.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			if len(keys) >= MaxKeysPerDevice {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "A device can hold at most "+strconv.Itoa(MaxKeysPerDevice)+" keys", 409)
			}
			next := target.Spread()
			if owner := enrollment.Get("ownerIdentityId"); !isUndefined(owner) {
				next.Set("ownerIdentityId", owner)
			}
			next.Set("enrolledBy", callerID).Set("updatedAt", float64(now))
			if device, err = tx.Put(ctx, DeviceCollections.Devices, next); err != nil {
				return nil, err
			}
		} else {
			// Without a code the caller owns the device; a code without a device names its owner (or none: shared).
			owner := callerID
			if enrollment != nil {
				owner = enrollment.Get("ownerIdentityId")
			}
			if !isUndefined(owner) {
				records, err := tx.Find(ctx, DeviceCollections.Devices, core.NewObject("tenantId", tenantID, "ownerIdentityId", owner), nil)
				if err != nil {
					return nil, err
				}
				owned := 0
				for _, record := range records {
					if record.Get("status") != "retired" {
						owned++
					}
				}
				if owned >= MaxDevicesPerPerson {
					return nil, core.NewIamError("LIMIT_EXCEEDED", "A person can register at most "+strconv.Itoa(MaxDevicesPerPerson)+" devices", 409)
				}
			}
			record := core.NewObject("id", ID(), "tenantId", tenantID, "name", name, "platform", platform, "status", "active")
			if !isUndefined(owner) {
				record.Set("ownerIdentityId", owner)
			}
			record.Set("enrolledBy", callerID).Set("createdAt", float64(now)).Set("updatedAt", float64(now))
			if device, err = tx.Insert(ctx, DeviceCollections.Devices, record); err != nil {
				return nil, err
			}
			created = true
		}
		if _, err := tx.Insert(ctx, DeviceCollections.Keys, core.NewObject(
			"id", keyID,
			"tenantId", tenantID,
			"deviceId", device.Get("id"),
			"jwk", jwk,
			"createdAt", float64(now),
			"createdBy", callerID,
		)); err != nil {
			return nil, err
		}
		if enrollment != nil {
			if _, err := tx.Put(ctx, DeviceCollections.Enrollments, enrollment.Spread(core.NewObject("usedAt", float64(now), "usedBy", callerID))); err != nil {
				return nil, err
			}
		}
		metadata := core.NewObject(
			"deviceId", device.Get("id"),
			"keyId", keyID,
			"platform", device.Get("platform"),
			"created", created,
			"managed", !isUndefined(device.Get("source")),
		)
		if enrollment != nil {
			metadata.Set("enrollmentId", enrollment.Get("id"))
		}
		if err := api.audit(ctx, tx, principal, "device:enroll", tenantID, deviceResource(jsString(device.Get("id"))), metadata); err != nil {
			return nil, err
		}
		views, err := deviceDescribe(ctx, tx, tenantID, []*core.Object{device}, now)
		if err != nil {
			return nil, err
		}
		current := api.currentDeviceID(ctx, tx, principal)
		return core.NewObject(
			"device", views[0].Set("current", current != "" && current == jsString(device.Get("id"))),
			"keyId", keyID,
		), nil
	})
	return Out[apitypes.DevicesEnrollOutput]{Value: result}, err
}

// Mine is POST {basePath}/devices/mine. Lists the caller's devices that are not retired, each with its compliance and assurance, the device presenting this request first.
func (api *DevicesAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesMineInput]) (Out[apitypes.DevicesMineOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.DevicesMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.DevicesMineOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := deviceOwnSession(principal, tenantID, "Devices are listed from an ordinary session of their tenant"); err != nil {
			return nil, err
		}
		records, err := tx.Find(ctx, DeviceCollections.Devices, core.NewObject("tenantId", tenantID, "ownerIdentityId", principal.Identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		devices := []*core.Object{}
		for _, device := range records {
			if device.Get("status") != "retired" {
				devices = append(devices, device)
			}
		}
		current := api.currentDeviceID(ctx, tx, principal)
		views, err := deviceDescribe(ctx, tx, tenantID, devices, server.Now())
		if err != nil {
			return nil, err
		}
		mine := make([]*core.Object, len(views))
		for index, view := range views {
			mine[index] = view.Spread(core.NewObject("current", current != "" && jsString(view.Get("id")) == current))
		}
		sortStable(mine, func(a, b *core.Object) int {
			left, right := 0, 0
			if a.Get("current") == true {
				left = 1
			}
			if b.Get("current") == true {
				right = 1
			}
			if difference := right - left; difference != 0 {
				return difference
			}
			return ByNewest(a, b)
		})
		out := make([]any, len(mine))
		for index, view := range mine {
			out[index] = view
		}
		return out, nil
	})
	return Out[apitypes.DevicesMineOutput]{Value: result}, err
}

// RetireMine is POST {basePath}/devices/retireMine. Retires one of the caller's own unmanaged devices and deletes its keys.
func (api *DevicesAPI) RetireMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesRetireMineInput]) (Out[apitypes.DevicesRetireMineOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.DevicesRetireMineOutput], error) {
		return Out[apitypes.DevicesRetireMineOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	deviceID, err := Text(input.Get("deviceId"), "deviceId")
	if err != nil {
		return fail(err)
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := deviceOwnSession(principal, tenantID, "Devices are retired from an ordinary session of their tenant"); err != nil {
			return nil, err
		}
		if err := deviceNotImpersonating(principal); err != nil {
			return nil, err
		}
		// A stolen session must not take the person's own devices away either.
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		device, err := server.Scoped(ctx, tx, DeviceCollections.Devices, deviceID, tenantID)
		if err != nil {
			return nil, err
		}
		if device.Get("ownerIdentityId") != principal.Identity.Get("id") {
			return nil, deviceNotFound()
		}
		if truthy(device.Get("source")) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Managed devices are retired by administrators", 409)
		}
		if device.Get("status") == "retired" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The device is already retired", 409)
		}
		retired, err := RetireDevice(ctx, tx, device, server.Now())
		if err != nil {
			return nil, err
		}
		keysRemoved := retired.Get("keysRemoved")
		if err := api.audit(ctx, tx, principal, "device:retire", tenantID, deviceResource(jsString(device.Get("id"))), core.NewObject(
			"deviceId", device.Get("id"), "keysRemoved", keysRemoved, "self", true,
		)); err != nil {
			return nil, err
		}
		return core.NewObject("success", true, "keysRemoved", keysRemoved), nil
	})
	return Out[apitypes.DevicesRetireMineOutput]{Value: result}, err
}

// Check is POST {basePath}/devices/check. Reports what the device presenting this request proves: its assurance, id, platform and compliance.
func (api *DevicesAPI) Check(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesCheckInput]) (Out[apitypes.DevicesCheckOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.DevicesCheckOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.DevicesCheckOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if principal.Session.Get("tenantId") != tenantID {
			return nil, core.NewIamError("ACCESS_DENIED", "Devices are checked from a session of their tenant", 403)
		}
		now := server.Now()
		presented, _ := PresentedDevice(ctx, tx, principal, now)
		if presented == nil {
			proof := "invalid"
			if principal.DeviceProof == "" {
				proof = "absent"
			}
			return core.NewObject("assurance", "none", "managed", false, "compliant", false, "reasons", []any{}, "proof", proof), nil
		}
		device := presented.Get("device").(*core.Object)
		key := presented.Get("key").(*core.Object)
		compliance := presented.Get("compliance").(*core.Object)
		if float64(now)-jsNumber(coalesce(device.Get("lastSeenAt"), 0.0)) >= deviceTouchMs {
			if _, err := tx.Put(ctx, DeviceCollections.Devices, device.Spread(core.NewObject("lastSeenAt", float64(now)))); err != nil {
				return nil, err
			}
		}
		if float64(now)-jsNumber(coalesce(key.Get("lastUsedAt"), 0.0)) >= deviceTouchMs {
			if _, err := tx.Put(ctx, DeviceCollections.Keys, key.Spread(core.NewObject("lastUsedAt", float64(now)))); err != nil {
				return nil, err
			}
		}
		return core.NewObject(
			"assurance", presented.Get("assurance"),
			"deviceId", device.Get("id"),
			"platform", device.Get("platform"),
			"managed", compliance.Get("managed"),
			"compliant", compliance.Get("compliant"),
			"reasons", compliance.Get("reasons"),
			"proof", "verified",
		), nil
	})
	return Out[apitypes.DevicesCheckOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------
// Administration

// List is POST {basePath}/devices/list. Lists the tenant's devices, newest first, each with its compliance, assurance, key count and owner.
func (api *DevicesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesListInput]) (Out[apitypes.DevicesListOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.DevicesListOutput], error) {
		return Out[apitypes.DevicesListOutput]{}, err
	}
	limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000)
	if err != nil {
		return fail(err)
	}
	offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000)
	if err != nil {
		return fail(err)
	}
	ownerIdentityID := ""
	hasOwner := !isUndefined(input.Get("ownerIdentityId"))
	if hasOwner {
		if ownerIdentityID, err = Text(input.Get("ownerIdentityId"), "ownerIdentityId"); err != nil {
			return fail(err)
		}
	}
	status := input.Get("status")
	if !isUndefined(status) && status != "active" && status != "lost" && status != "retired" {
		return fail(invalidInput("status must be active, lost or retired"))
	}
	platform := ""
	if value := input.Get("platform"); !isUndefined(value) {
		if platform, err = devicePlatformOf(value, "platform"); err != nil {
			return fail(err)
		}
	}
	var managed, compliant *bool
	if value := input.Get("managed"); !isUndefined(value) {
		flagged, err := deviceFlag(value, "managed")
		if err != nil {
			return fail(err)
		}
		managed = &flagged
	}
	if value := input.Get("compliant"); !isUndefined(value) {
		flagged, err := deviceFlag(value, "compliant")
		if err != nil {
			return fail(err)
		}
		compliant = &flagged
	}
	query := ""
	if value := input.Get("query"); !isUndefined(value) {
		text, err := Text(value, "query", 200)
		if err != nil {
			return fail(err)
		}
		query = core.JSLower(core.JSTrim(text))
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:read", "devices", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		filter := core.NewObject("tenantId", tenantID)
		if hasOwner {
			filter.Set("ownerIdentityId", ownerIdentityID)
		}
		if !isUndefined(status) {
			filter.Set("status", status)
		}
		if platform != "" {
			filter.Set("platform", platform)
		}
		devices, err := call.Tx.Find(ctx, DeviceCollections.Devices, filter, nil)
		if err != nil {
			return nil, err
		}
		described, err := deviceDescribe(ctx, call.Tx, tenantID, devices, server.Now())
		if err != nil {
			return nil, err
		}
		views := []*core.Object{}
		for _, view := range described {
			compliance := view.Get("compliance").(*core.Object)
			if managed != nil && compliance.Get("managed") != *managed {
				continue
			}
			if compliant != nil && compliance.Get("compliant") != *compliant {
				continue
			}
			if query != "" {
				matched := false
				for _, value := range []any{view.Get("id"), view.Get("name"), view.Get("serialNumber"), view.Get("model"),
					member(view.Get("source"), "externalId"), member(view.Get("owner"), "name"), member(view.Get("owner"), "email")} {
					if text, ok := value.(string); ok && strings.Contains(core.JSLower(text), query) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}
			views = append(views, view)
		}
		sortStable(views, ByNewest)
		total := len(views)
		start, end := int(offset), int(offset+limit)
		if start > total {
			start = total
		}
		if end > total {
			end = total
		}
		page := make([]any, 0, end-start)
		for _, view := range views[start:end] {
			page = append(page, view)
		}
		return core.NewObject("devices", page, "total", float64(total)), nil
	}, false)
	return Out[apitypes.DevicesListOutput]{Value: result}, err
}

// Get is POST {basePath}/devices/get. Returns one device with its enrolled keys.
func (api *DevicesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesGetInput]) (Out[apitypes.DevicesGetOutput], error) {
	server := api.server
	deviceID, err := Text(input.Get("deviceId"), "deviceId")
	if err != nil {
		return Out[apitypes.DevicesGetOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:read", deviceResource(deviceID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		device, err := server.Scoped(ctx, call.Tx, DeviceCollections.Devices, deviceID, tenantID)
		if err != nil {
			return nil, err
		}
		views, err := deviceDescribe(ctx, call.Tx, tenantID, []*core.Object{device}, server.Now())
		if err != nil {
			return nil, err
		}
		keys, err := call.Tx.Find(ctx, DeviceCollections.Keys, core.NewObject("tenantId", tenantID, "deviceId", device.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		sortStable(keys, ByNewest)
		publicKeys := make([]any, len(keys))
		for index, key := range keys {
			algorithm := deviceKeyAlgorithm(key.Get("jwk"))
			if algorithm == "" {
				algorithm = "ES256"
			}
			view := core.NewObject("id", key.Get("id"), "algorithm", algorithm, "createdAt", key.Get("createdAt"), "createdBy", key.Get("createdBy"))
			if lastUsedAt := key.Get("lastUsedAt"); !isUndefined(lastUsedAt) {
				view.Set("lastUsedAt", lastUsedAt)
			}
			publicKeys[index] = view
		}
		return views[0].Spread(core.NewObject("publicKeys", publicKeys)), nil
	}, false)
	return Out[apitypes.DevicesGetOutput]{Value: result}, err
}

// Update is POST {basePath}/devices/update. Renames a device, changes its owner, or marks it lost or active again.
func (api *DevicesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesUpdateInput]) (Out[apitypes.DevicesUpdateOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.DevicesUpdateOutput], error) {
		return Out[apitypes.DevicesUpdateOutput]{}, err
	}
	fields, err := deviceFieldsOf(input.Body, []string{"tenantId", "deviceId", "name", "ownerIdentityId", "status"})
	if err != nil {
		return fail(err)
	}
	deviceID, err := Text(input.Get("deviceId"), "deviceId")
	if err != nil {
		return fail(err)
	}
	name := ""
	hasName := !isUndefined(fields.Get("name"))
	if hasName {
		if name, err = deviceNameOf(fields.Get("name")); err != nil {
			return fail(err)
		}
	}
	status := fields.Get("status")
	if !isUndefined(status) && status != "active" && status != "lost" {
		return fail(invalidInput("status must be active or lost"))
	}
	ownerInput := fields.Get("ownerIdentityId")
	if !hasName && isUndefined(status) && isUndefined(ownerInput) {
		return fail(invalidInput("Nothing to update"))
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:manage", deviceResource(deviceID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		device, err := server.Scoped(ctx, tx, DeviceCollections.Devices, deviceID, tenantID)
		if err != nil {
			return nil, err
		}
		if device.Get("status") == "retired" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Retired devices cannot change", 409)
		}
		previousOwner := device.Get("ownerIdentityId")
		owner := previousOwner
		if ownerInput == nil {
			owner = core.Undefined
		} else if !isUndefined(ownerInput) {
			identity, err := api.ownerOf(ctx, tx, tenantID, ownerInput)
			if err != nil {
				return nil, err
			}
			owner = identity.Get("id")
		}
		nextStatus := status
		if isUndefined(nextStatus) {
			nextStatus = device.Get("status")
		}
		now := server.Now()
		keysRemoved := 0
		if owner != previousOwner && !isUndefined(previousOwner) {
			keys, err := tx.Find(ctx, DeviceCollections.Keys, core.NewObject("tenantId", tenantID, "deviceId", device.Get("id"), "createdBy", previousOwner), nil)
			if err != nil {
				return nil, err
			}
			for _, key := range keys {
				if err := tx.Delete(ctx, DeviceCollections.Keys, jsString(key.Get("id"))); err != nil {
					return nil, err
				}
				keysRemoved++
			}
		}
		rest := device.Spread()
		rest.Delete("ownerIdentityId")
		nextName := device.Get("name")
		if hasName {
			nextName = name
		}
		rest.Set("name", nextName).Set("status", nextStatus)
		if !isUndefined(owner) {
			rest.Set("ownerIdentityId", owner)
		}
		rest.Set("updatedAt", float64(now))
		next, err := tx.Put(ctx, DeviceCollections.Devices, rest)
		if err != nil {
			return nil, err
		}
		orNull := func(value any) any {
			if nullish(value) {
				return nil
			}
			return value
		}
		if err := api.audit(ctx, tx, principal, "device:update", tenantID, deviceResource(jsString(device.Get("id"))), core.NewObject(
			"deviceId", device.Get("id"),
			"before", core.NewObject("name", device.Get("name"), "status", device.Get("status"), "ownerIdentityId", orNull(previousOwner)),
			"after", core.NewObject("name", next.Get("name"), "status", next.Get("status"), "ownerIdentityId", orNull(owner)),
			"keysRemoved", float64(keysRemoved),
		)); err != nil {
			return nil, err
		}
		views, err := deviceDescribe(ctx, tx, tenantID, []*core.Object{next}, now)
		if err != nil {
			return nil, err
		}
		return views[0], nil
	}, false)
	return Out[apitypes.DevicesUpdateOutput]{Value: result}, err
}

// Retire is POST {basePath}/devices/retire. Retires a device for good, deleting its keys and pending enrollment codes.
func (api *DevicesAPI) Retire(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesRetireInput]) (Out[apitypes.DevicesRetireOutput], error) {
	server := api.server
	deviceID, err := Text(input.Get("deviceId"), "deviceId")
	if err != nil {
		return Out[apitypes.DevicesRetireOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:manage", deviceResource(deviceID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		device, err := server.Scoped(ctx, tx, DeviceCollections.Devices, deviceID, tenantID)
		if err != nil {
			return nil, err
		}
		if device.Get("status") == "retired" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The device is already retired", 409)
		}
		now := server.Now()
		retired, err := RetireDevice(ctx, tx, device, now)
		if err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "device:retire", tenantID, deviceResource(jsString(device.Get("id"))), core.NewObject(
			"deviceId", device.Get("id"), "keysRemoved", retired.Get("keysRemoved"), "self", false,
		)); err != nil {
			return nil, err
		}
		views, err := deviceDescribe(ctx, tx, tenantID, []*core.Object{retired.Get("device").(*core.Object)}, now)
		if err != nil {
			return nil, err
		}
		return views[0], nil
	}, false)
	return Out[apitypes.DevicesRetireOutput]{Value: result}, err
}

// Delete is POST {basePath}/devices/delete. Deletes a device with its keys and enrollment codes.
func (api *DevicesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesDeleteInput]) (Out[apitypes.DevicesDeleteOutput], error) {
	server := api.server
	deviceID, err := Text(input.Get("deviceId"), "deviceId")
	if err != nil {
		return Out[apitypes.DevicesDeleteOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:manage", deviceResource(deviceID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		device, err := server.Scoped(ctx, tx, DeviceCollections.Devices, deviceID, tenantID)
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", tenantID, "deviceId", device.Get("id"))
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
		if err := tx.Delete(ctx, DeviceCollections.Devices, jsString(device.Get("id"))); err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "device:delete", tenantID, deviceResource(jsString(device.Get("id"))), core.NewObject(
			"deviceId", device.Get("id"),
			"name", device.Get("name"),
			"managed", !isUndefined(device.Get("source")),
			"keysRemoved", float64(len(keys)),
			"enrollmentsRemoved", float64(len(enrollments)),
		)); err != nil {
			return nil, err
		}
		return core.NewObject("success", true, "keysRemoved", float64(len(keys)), "enrollmentsRemoved", float64(len(enrollments))), nil
	}, false)
	return Out[apitypes.DevicesDeleteOutput]{Value: result}, err
}

// RemoveKey is POST {basePath}/devices/removeKey. Removes one enrolled key from a device, such as a lost browser profile or a replaced agent.
func (api *DevicesAPI) RemoveKey(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesRemoveKeyInput]) (Out[apitypes.DevicesRemoveKeyOutput], error) {
	server := api.server
	deviceID, err := Text(input.Get("deviceId"), "deviceId")
	if err != nil {
		return Out[apitypes.DevicesRemoveKeyOutput]{}, err
	}
	keyID, err := Text(input.Get("keyId"), "keyId")
	if err != nil {
		return Out[apitypes.DevicesRemoveKeyOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:manage", deviceResource(deviceID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		device, err := server.Scoped(ctx, tx, DeviceCollections.Devices, deviceID, tenantID)
		if err != nil {
			return nil, err
		}
		key, err := tx.Get(ctx, DeviceCollections.Keys, keyID)
		if err != nil {
			return nil, err
		}
		if key == nil || key.Get("tenantId") != tenantID || key.Get("deviceId") != device.Get("id") {
			return nil, deviceNotFound()
		}
		if err := tx.Delete(ctx, DeviceCollections.Keys, jsString(key.Get("id"))); err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "device:key-remove", tenantID, deviceResource(jsString(device.Get("id"))), core.NewObject(
			"deviceId", device.Get("id"), "keyId", key.Get("id"),
		)); err != nil {
			return nil, err
		}
		return core.NewObject("success", true), nil
	}, false)
	return Out[apitypes.DevicesRemoveKeyOutput]{Value: result}, err
}

// CreateEnrollment is POST {basePath}/devices/createEnrollment. Creates a one-time enrollment code that binds a browser or agent key to a device, usually one an integration manages.
func (api *DevicesAPI) CreateEnrollment(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesCreateEnrollmentInput]) (Out[apitypes.DevicesCreateEnrollmentOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.DevicesCreateEnrollmentOutput], error) {
		return Out[apitypes.DevicesCreateEnrollmentOutput]{}, err
	}
	deviceID := ""
	hasDevice := !isUndefined(input.Get("deviceId"))
	var err error
	if hasDevice {
		if deviceID, err = Text(input.Get("deviceId"), "deviceId"); err != nil {
			return fail(err)
		}
	}
	lifetime, err := Integer(coalesce(input.Get("expiresInMs"), float64(deviceDefaultEnrollmentMs)), "expiresInMs", deviceMinEnrollmentMs, deviceMaxEnrollmentMs)
	if err != nil {
		return fail(err)
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:manage", "devices/enrollments", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		now := server.Now()
		var owner any = core.Undefined
		if value := input.Get("ownerIdentityId"); !isUndefined(value) {
			identity, err := api.ownerOf(ctx, tx, tenantID, value)
			if err != nil {
				return nil, err
			}
			owner = identity.Get("id")
		}
		if hasDevice {
			device, err := server.Scoped(ctx, tx, DeviceCollections.Devices, deviceID, tenantID)
			if err != nil {
				return nil, err
			}
			// Using the code adds a key to the device (and may give a shared one an owner), which devices.update and
			// removeKey allow only with iam:devices:manage on the device itself.
			onDevice, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
				TenantID: tenantID,
				Action:   "iam:devices:manage",
				Resource: ResourceTarget{Type: "iam", ID: deviceResource(jsString(device.Get("id")))},
			}, true)
			if err != nil {
				return nil, err
			}
			if !onDevice.Allowed {
				return nil, NewOperationDenied("A code for an existing device requires iam:devices:manage on that device")
			}
			if device.Get("status") != "active" {
				return nil, core.NewIamError("INVALID_TRANSITION", "The device is not active", 409)
			}
			if deviceOwner := device.Get("ownerIdentityId"); !isUndefined(deviceOwner) {
				if !isUndefined(owner) && owner != deviceOwner {
					return nil, invalidInput("The device belongs to someone else")
				}
				owner = deviceOwner
			}
		}
		existing, err := tx.Find(ctx, DeviceCollections.Enrollments, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		pending := 0
		for _, enrollment := range existing {
			if isUndefined(enrollment.Get("usedAt")) && jsNumber(enrollment.Get("expiresAt")) > float64(now) {
				pending++
			}
		}
		if pending >= deviceMaxPendingEnrollments {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant can hold at most "+strconv.Itoa(deviceMaxPendingEnrollments)+" pending enrollment codes", 409)
		}
		code := "biam_denr_" + Token()
		codeHash := Hash(code)
		record := core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", codeHash, "codeHash", codeHash)
		if hasDevice {
			record.Set("deviceId", deviceID)
		}
		if !isUndefined(owner) {
			record.Set("ownerIdentityId", owner)
		}
		record.Set("expiresAt", float64(now)+lifetime).Set("createdAt", float64(now)).Set("createdBy", principal.Identity.Get("id"))
		enrollment, err := tx.Insert(ctx, DeviceCollections.Enrollments, record)
		if err != nil {
			return nil, err
		}
		var auditDevice, auditOwner any
		if hasDevice {
			auditDevice = deviceID
		}
		if !isUndefined(owner) {
			auditOwner = owner
		}
		if err := api.audit(ctx, tx, principal, "device:enrollment-create", tenantID, "devices/enrollments", core.NewObject(
			"enrollmentId", enrollment.Get("id"),
			"deviceId", auditDevice,
			"ownerIdentityId", auditOwner,
			"expiresAt", enrollment.Get("expiresAt"),
		)); err != nil {
			return nil, err
		}
		return core.NewObject("code", code, "expiresAt", enrollment.Get("expiresAt"), "enrollmentId", enrollment.Get("id")), nil
	}, false)
	return Out[apitypes.DevicesCreateEnrollmentOutput]{Value: result}, err
}

// ListEnrollments is POST {basePath}/devices/listEnrollments. Lists the tenant's enrollment codes, newest first, without the codes themselves.
func (api *DevicesAPI) ListEnrollments(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesListEnrollmentsInput]) (Out[apitypes.DevicesListEnrollmentsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:manage", "devices/enrollments", func(ctx context.Context, call MutationContext) ([]any, error) {
		now := server.Now()
		enrollments, err := call.Tx.Find(ctx, DeviceCollections.Enrollments, core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		sortStable(enrollments, ByNewest)
		out := make([]any, len(enrollments))
		for index, enrollment := range enrollments {
			out[index] = deviceEnrollmentView(enrollment, now)
		}
		return out, nil
	}, false)
	return Out[apitypes.DevicesListEnrollmentsOutput]{Value: result}, err
}

// RevokeEnrollment is POST {basePath}/devices/revokeEnrollment. Withdraws an enrollment code, used or not.
func (api *DevicesAPI) RevokeEnrollment(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesRevokeEnrollmentInput]) (Out[apitypes.DevicesRevokeEnrollmentOutput], error) {
	server := api.server
	enrollmentID, err := Text(input.Get("enrollmentId"), "enrollmentId")
	if err != nil {
		return Out[apitypes.DevicesRevokeEnrollmentOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:manage", "devices/enrollments", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		enrollment, err := server.Scoped(ctx, tx, DeviceCollections.Enrollments, enrollmentID, tenantID)
		if err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, DeviceCollections.Enrollments, jsString(enrollment.Get("id"))); err != nil {
			return nil, err
		}
		deviceID := enrollment.Get("deviceId")
		if nullish(deviceID) {
			deviceID = nil
		}
		if err := api.audit(ctx, tx, call.Principal, "device:enrollment-revoke", tenantID, "devices/enrollments", core.NewObject(
			"enrollmentId", enrollment.Get("id"),
			"deviceId", deviceID,
			"used", !isUndefined(enrollment.Get("usedAt")),
		)); err != nil {
			return nil, err
		}
		return core.NewObject("success", true), nil
	}, false)
	return Out[apitypes.DevicesRevokeEnrollmentOutput]{Value: result}, err
}

// GetSettings is POST {basePath}/devices/getSettings. Returns the tenant's compliance requirements, or the defaults until they are configured.
func (api *DevicesAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesGetSettingsInput]) (Out[apitypes.DevicesGetSettingsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:read", "devices/settings", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		stored, err := call.Tx.Get(ctx, DeviceCollections.Settings, tenantID)
		if err != nil {
			return nil, err
		}
		if stored != nil && stored.Get("tenantId") != tenantID {
			stored = nil
		}
		return deviceSettingsView(tenantID, stored), nil
	}, false)
	return Out[apitypes.DevicesGetSettingsOutput]{Value: result}, err
}

// Configure is POST {basePath}/devices/configure. Sets the requirements a managed device must meet to be compliant.
func (api *DevicesAPI) Configure(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesConfigureInput]) (Out[apitypes.DevicesConfigureOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.DevicesConfigureOutput], error) {
		return Out[apitypes.DevicesConfigureOutput]{}, err
	}
	fields, err := deviceFieldsOf(input.Body, []string{"tenantId", "requireEncrypted", "requireScreenLock", "requireFirewall", "requireEdr", "blockJailbroken", "minOsVersions", "maxCheckInAgeHours"})
	if err != nil {
		return fail(err)
	}
	changes := core.NewObject()
	for _, name := range []string{"requireEncrypted", "requireScreenLock", "requireFirewall", "requireEdr", "blockJailbroken"} {
		if value := fields.Get(name); !isUndefined(value) {
			flagged, err := deviceFlag(value, name)
			if err != nil {
				return fail(err)
			}
			changes.Set(name, flagged)
		}
	}
	if value := fields.Get("minOsVersions"); !isUndefined(value) {
		entries, err := Object(value)
		if err != nil {
			return fail(err)
		}
		minimums := core.NewObject()
		var failure error
		entries.Entries(func(platform string, version any) bool {
			key, err := devicePlatformOf(platform, "minOsVersions platform")
			if err != nil {
				failure = err
				return false
			}
			if !isOsVersion(version) {
				failure = invalidInput("minOsVersions." + key + " must be a dotted version such as 14.5")
				return false
			}
			minimums.Set(key, version)
			return true
		})
		if failure != nil {
			return fail(failure)
		}
		changes.Set("minOsVersions", minimums)
	}
	if value := fields.Get("maxCheckInAgeHours"); !isUndefined(value) {
		hours, err := Integer(value, "maxCheckInAgeHours", 1, 720)
		if err != nil {
			return fail(err)
		}
		changes.Set("maxCheckInAgeHours", hours)
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:manage", "devices/settings", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		stored, err := tx.Get(ctx, DeviceCollections.Settings, tenantID)
		if err != nil {
			return nil, err
		}
		previous := stored
		if previous != nil && previous.Get("tenantId") != tenantID {
			previous = nil
		}
		before := resolveDeviceSettings(previous)
		record := core.NewObject("id", tenantID, "tenantId", tenantID).
			Assign(before, changes).
			Set("updatedAt", float64(server.Now())).
			Set("updatedBy", principal.Identity.Get("id"))
		var saved *core.Object
		if previous != nil {
			saved, err = tx.Put(ctx, DeviceCollections.Settings, record)
		} else {
			saved, err = tx.Insert(ctx, DeviceCollections.Settings, record)
		}
		if err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "device:settings", tenantID, "devices/settings", core.NewObject(
			"before", deviceSettingsMetadata(before),
			"after", deviceSettingsMetadata(resolveDeviceSettings(saved)),
		)); err != nil {
			return nil, err
		}
		return deviceSettingsView(tenantID, saved), nil
	}, false)
	return Out[apitypes.DevicesConfigureOutput]{Value: result}, err
}

// ListIntegrations is POST {basePath}/devices/listIntegrations. Lists the tenant's MDM and EDR integrations by name, with the number of devices each manages.
func (api *DevicesAPI) ListIntegrations(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesListIntegrationsInput]) (Out[apitypes.DevicesListIntegrationsOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:read", "devices/integrations", func(ctx context.Context, call MutationContext) ([]any, error) {
		tenantID := call.Tenant.Get("id")
		counts := map[string]int{}
		devices, err := call.Tx.Find(ctx, DeviceCollections.Devices, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, device := range devices {
			if source := device.Get("source"); truthy(source) {
				counts[jsString(member(source, "integrationId"))]++
			}
		}
		integrations, err := call.Tx.Find(ctx, DeviceCollections.Integrations, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		sortStable(integrations, func(a, b *core.Object) int {
			return localeCompare(jsString(a.Get("name")), jsString(b.Get("name")))
		})
		out := make([]any, len(integrations))
		for index, integration := range integrations {
			out[index] = deviceIntegrationView(integration, counts[jsString(integration.Get("id"))])
		}
		return out, nil
	}, false)
	return Out[apitypes.DevicesListIntegrationsOutput]{Value: result}, err
}

// CreateIntegration is POST {basePath}/devices/createIntegration. Adds an MDM or EDR integration that can report devices and their posture.
func (api *DevicesAPI) CreateIntegration(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesCreateIntegrationInput]) (Out[apitypes.DevicesCreateIntegrationOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.DevicesCreateIntegrationOutput], error) {
		return Out[apitypes.DevicesCreateIntegrationOutput]{}, err
	}
	if _, err := deviceFieldsOf(input.Body, []string{"tenantId", "name", "vendor", "trustVendorCompliance"}); err != nil {
		return fail(err)
	}
	nameText, err := Text(input.Get("name"), "name", 100)
	if err != nil {
		return fail(err)
	}
	name := core.JSTrim(nameText)
	vendor, isText := input.Get("vendor").(string)
	if !isText || !containsString(DeviceIntegrationVendors, vendor) {
		return fail(invalidInput("vendor must be one of " + strings.Join(DeviceIntegrationVendors, ", ")))
	}
	trust := true
	if value := input.Get("trustVendorCompliance"); !isUndefined(value) {
		if trust, err = deviceFlag(value, "trustVendorCompliance"); err != nil {
			return fail(err)
		}
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:manage", "devices/integrations", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		existing, err := tx.Find(ctx, DeviceCollections.Integrations, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		uniqueKey := "name:" + core.JSLower(name)
		for _, integration := range existing {
			if integration.Get("uniqueKey") == uniqueKey {
				return nil, core.NewIamError("CONFLICT", "An integration with this name exists", 409)
			}
		}
		if len(existing) >= MaxDeviceIntegrations {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant can have at most "+strconv.Itoa(MaxDeviceIntegrations)+" device integrations", 409)
		}
		now := float64(server.Now())
		integration, err := tx.Insert(ctx, DeviceCollections.Integrations, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"uniqueKey", uniqueKey,
			"name", name,
			"vendor", vendor,
			"status", "active",
			"trustVendorCompliance", trust,
			"createdAt", now,
			"createdBy", principal.Identity.Get("id"),
			"updatedAt", now,
		))
		if err != nil {
			return nil, err
		}
		integrationID := jsString(integration.Get("id"))
		if err := api.audit(ctx, tx, principal, "device:integration-create", tenantID, deviceIntegrationResource(integrationID),
			core.NewObject("integrationId", integration.Get("id")).Assign(deviceIntegrationMetadata(integration))); err != nil {
			return nil, err
		}
		return deviceIntegrationView(integration, 0), nil
	}, false)
	return Out[apitypes.DevicesCreateIntegrationOutput]{Value: result}, err
}

// UpdateIntegration is POST {basePath}/devices/updateIntegration. Renames an integration, disables or enables it, or changes whether the vendor's verdict counts.
func (api *DevicesAPI) UpdateIntegration(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesUpdateIntegrationInput]) (Out[apitypes.DevicesUpdateIntegrationOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.DevicesUpdateIntegrationOutput], error) {
		return Out[apitypes.DevicesUpdateIntegrationOutput]{}, err
	}
	if _, err := deviceFieldsOf(input.Body, []string{"tenantId", "integrationId", "name", "status", "trustVendorCompliance"}); err != nil {
		return fail(err)
	}
	integrationID, err := Text(input.Get("integrationId"), "integrationId")
	if err != nil {
		return fail(err)
	}
	name := ""
	hasName := !isUndefined(input.Get("name"))
	if hasName {
		text, err := Text(input.Get("name"), "name", 100)
		if err != nil {
			return fail(err)
		}
		name = core.JSTrim(text)
	}
	status := input.Get("status")
	if !isUndefined(status) && status != "active" && status != "disabled" {
		return fail(invalidInput("status must be active or disabled"))
	}
	var trust any = core.Undefined
	if value := input.Get("trustVendorCompliance"); !isUndefined(value) {
		flagged, err := deviceFlag(value, "trustVendorCompliance")
		if err != nil {
			return fail(err)
		}
		trust = flagged
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:manage", deviceIntegrationResource(integrationID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		integration, err := server.Scoped(ctx, tx, DeviceCollections.Integrations, integrationID, tenantID)
		if err != nil {
			return nil, err
		}
		uniqueKey := integration.Get("uniqueKey")
		if hasName {
			uniqueKey = "name:" + core.JSLower(name)
			others, err := tx.Find(ctx, DeviceCollections.Integrations, core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
			if err != nil {
				return nil, err
			}
			for _, other := range others {
				if other.Get("id") != integration.Get("id") {
					return nil, core.NewIamError("CONFLICT", "An integration with this name exists", 409)
				}
			}
		}
		next := integration.Spread()
		if !isUndefined(uniqueKey) {
			next.Set("uniqueKey", uniqueKey)
		}
		if hasName {
			next.Set("name", name)
		} else {
			next.Set("name", integration.Get("name"))
		}
		next.Set("status", coalesce(status, integration.Get("status"))).
			Set("trustVendorCompliance", coalesce(trust, integration.Get("trustVendorCompliance"))).
			Set("updatedAt", float64(server.Now()))
		saved, err := tx.Put(ctx, DeviceCollections.Integrations, next)
		if err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "device:integration-update", tenantID, deviceIntegrationResource(jsString(integration.Get("id"))), core.NewObject(
			"integrationId", integration.Get("id"),
			"before", deviceIntegrationMetadata(integration),
			"after", deviceIntegrationMetadata(saved),
		)); err != nil {
			return nil, err
		}
		devices, err := tx.Find(ctx, DeviceCollections.Devices, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		managed := 0
		for _, device := range devices {
			if member(device.Get("source"), "integrationId") == integration.Get("id") {
				managed++
			}
		}
		return deviceIntegrationView(saved, managed), nil
	}, false)
	return Out[apitypes.DevicesUpdateIntegrationOutput]{Value: result}, err
}

// DeleteIntegration is POST {basePath}/devices/deleteIntegration. Deletes an integration, optionally leaving the devices it manages unmanaged.
func (api *DevicesAPI) DeleteIntegration(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesDeleteIntegrationInput]) (Out[apitypes.DevicesDeleteIntegrationOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.DevicesDeleteIntegrationOutput], error) {
		return Out[apitypes.DevicesDeleteIntegrationOutput]{}, err
	}
	integrationID, err := Text(input.Get("integrationId"), "integrationId")
	if err != nil {
		return fail(err)
	}
	detach := false
	if value := input.Get("detach"); !isUndefined(value) {
		if detach, err = deviceFlag(value, "detach"); err != nil {
			return fail(err)
		}
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:manage", deviceIntegrationResource(integrationID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		integration, err := server.Scoped(ctx, tx, DeviceCollections.Integrations, integrationID, tenantID)
		if err != nil {
			return nil, err
		}
		devices, err := tx.Find(ctx, DeviceCollections.Devices, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		managed := []*core.Object{}
		for _, device := range devices {
			if member(device.Get("source"), "integrationId") == integration.Get("id") {
				managed = append(managed, device)
			}
		}
		if len(managed) > 0 && !detach {
			return nil, core.NewIamError("RESOURCE_IN_USE", "The integration manages "+strconv.Itoa(len(managed))+" devices; pass detach to make them unmanaged", 409)
		}
		now := float64(server.Now())
		for _, device := range managed {
			rest := device.Spread()
			rest.Delete("source")
			rest.Delete("uniqueKey")
			if _, err := tx.Put(ctx, DeviceCollections.Devices, rest.Set("updatedAt", now)); err != nil {
				return nil, err
			}
		}
		if err := tx.Delete(ctx, DeviceCollections.Integrations, jsString(integration.Get("id"))); err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "device:integration-delete", tenantID, deviceIntegrationResource(jsString(integration.Get("id"))), core.NewObject(
			"integrationId", integration.Get("id"), "name", integration.Get("name"), "detached", float64(len(managed)),
		)); err != nil {
			return nil, err
		}
		return core.NewObject("success", true, "detached", float64(len(managed))), nil
	}, false)
	return Out[apitypes.DevicesDeleteIntegrationOutput]{Value: result}, err
}

// ---------------------------------------------------------------------------------------------------------
// Integration reports

// Report is POST {basePath}/devices/report. Creates or updates up to 500 devices with their posture, as reported by an integration, all or nothing.
func (api *DevicesAPI) Report(ctx context.Context, credential core.CredentialInput, input In[apitypes.DevicesReportInput]) (Out[apitypes.DevicesReportOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.DevicesReportOutput], error) {
		return Out[apitypes.DevicesReportOutput]{}, err
	}
	integrationID, err := Text(input.Get("integrationId"), "integrationId")
	if err != nil {
		return fail(err)
	}
	items, err := deviceReportItems(input.Get("devices"), server.Now())
	if err != nil {
		return fail(err)
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:devices:report", deviceIntegrationResource(integrationID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		integration, err := server.Scoped(ctx, tx, DeviceCollections.Integrations, integrationID, tenantID)
		if err != nil {
			return nil, err
		}
		if integration.Get("status") != "active" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The integration is disabled", 409)
		}
		settings, err := DeviceSettingsOf(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		owners := map[string]any{}
		resolveOwner := func(item *deviceReportItem) (any, error) {
			if item.ownerIdentityID != "" {
				key := "id:" + item.ownerIdentityID
				if _, ok := owners[key]; !ok {
					identity, err := tx.Get(ctx, "identities", item.ownerIdentityID)
					if err != nil {
						return nil, err
					}
					if devicePerson(identity, tenantID) {
						owners[key] = identity.Get("id")
					} else {
						owners[key] = core.Undefined
					}
				}
				if found := owners[key]; !isUndefined(found) {
					return found, nil
				}
			}
			if item.ownerEmail == "" {
				return core.Undefined, nil
			}
			key := "email:" + item.ownerEmail
			if _, ok := owners[key]; !ok {
				identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", item.ownerEmail), nil)
				if err != nil {
					return nil, err
				}
				var found any = core.Undefined
				for _, identity := range identities {
					if devicePerson(identity, tenantID) {
						found = identity.Get("id")
						break
					}
				}
				owners[key] = found
			}
			return owners[key], nil
		}
		created, updated, unchanged, complianceChanged := 0, 0, 0, 0
		integrationKey := jsString(integration.Get("id"))
		for _, item := range items {
			uniqueKey := "src:" + integrationKey + ":" + item.externalID
			found, err := tx.Find(ctx, DeviceCollections.Devices, core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
			if err != nil {
				return nil, err
			}
			var existing *core.Object
			if len(found) > 0 {
				existing = found[0]
			}
			if existing != nil && !isUndefined(existing.Get("lastCheckInAt")) && item.checkedInAt < jsNumber(existing.Get("lastCheckInAt")) {
				unchanged++
				continue
			}
			existingMember := func(name string) any {
				if existing == nil {
					return core.Undefined
				}
				return existing.Get(name)
			}
			var owner any
			if item.ownerNamed {
				if owner, err = resolveOwner(item); err != nil {
					return nil, err
				}
			} else {
				owner = existingMember("ownerIdentityId")
			}
			posture := item.posture.Spread()
			if item.osVersion != "" {
				posture.Set("osVersion", item.osVersion)
			}
			posture.Set("reportedAt", item.checkedInAt).Set("integrationId", integration.Get("id"))
			optional := func(value string) any {
				if value == "" {
					return core.Undefined
				}
				return value
			}
			serialNumber := coalesce(optional(item.serialNumber), existingMember("serialNumber"))
			model := coalesce(optional(item.model), existingMember("model"))
			name := coalesce(optional(item.name), existingMember("name"))
			for _, fallback := range []string{item.model, item.serialNumber, item.externalID} {
				if !nullish(name) {
					break
				}
				name = optional(fallback)
			}
			described := core.NewObject("name", deviceSliceUTF16(jsString(name), 128), "platform", item.platform)
			if !isUndefined(owner) {
				described.Set("ownerIdentityId", owner)
			}
			if !isUndefined(serialNumber) {
				described.Set("serialNumber", serialNumber)
			}
			if !isUndefined(model) {
				described.Set("model", model)
			}
			described.Set("posture", posture).Set("lastCheckInAt", item.checkedInAt)
			if existing == nil {
				record := core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", uniqueKey).
					Assign(described).
					Set("status", "active").
					Set("source", core.NewObject("integrationId", integration.Get("id"), "externalId", item.externalID)).
					Set("createdAt", float64(now)).
					Set("updatedAt", float64(now))
				device, err := tx.Insert(ctx, DeviceCollections.Devices, record)
				if err != nil {
					return nil, err
				}
				if item.keyThumbprint != "" {
					if _, err := api.claimKey(ctx, tx, item.keyThumbprint, device, now); err != nil {
						return nil, err
					}
				}
				created++
				continue
			}
			kept := existing.Spread()
			kept.Delete("ownerIdentityId")
			kept.Delete("serialNumber")
			kept.Delete("model")
			next := kept.Assign(described).Set("updatedAt", float64(now))
			changed := deviceReportedState(existing) != deviceReportedState(next)
			moved := false
			if item.keyThumbprint != "" {
				if moved, err = api.claimKey(ctx, tx, item.keyThumbprint, next, now); err != nil {
					return nil, err
				}
			}
			before := evaluateCompliance(existing, integration, settings, now)
			after := evaluateCompliance(next, integration, settings, now)
			flipped := before.Get("compliant") != after.Get("compliant")
			// A check-in that flips compliance (the stored one had just gone stale) is written however soon it comes,
			// so the verdict audited below is the one decisions see.
			due := flipped ||
				isUndefined(existing.Get("lastCheckInAt")) ||
				item.checkedInAt-jsNumber(existing.Get("lastCheckInAt")) >= deviceTouchMs
			if changed || moved {
				if _, err := tx.Put(ctx, DeviceCollections.Devices, next); err != nil {
					return nil, err
				}
				updated++
			} else {
				if due {
					if _, err := tx.Put(ctx, DeviceCollections.Devices, existing.Spread(core.NewObject(
						"lastCheckInAt", item.checkedInAt,
						"posture", posture.Spread(),
					))); err != nil {
						return nil, err
					}
				}
				unchanged++
			}
			if flipped {
				complianceChanged++
				if err := api.audit(ctx, tx, principal, "device:compliance-change", tenantID, deviceResource(jsString(existing.Get("id"))), core.NewObject(
					"deviceId", existing.Get("id"),
					"integrationId", integration.Get("id"),
					"from", before.Get("compliant"),
					"to", after.Get("compliant"),
					"reasons", after.Get("reasons"),
				)); err != nil {
					return nil, err
				}
			}
		}
		if _, err := tx.Put(ctx, DeviceCollections.Integrations, integration.Spread(core.NewObject("lastReportAt", float64(now)))); err != nil {
			return nil, err
		}
		if err := api.audit(ctx, tx, principal, "device:report", tenantID, deviceIntegrationResource(integrationKey), core.NewObject(
			"integrationId", integration.Get("id"),
			"received", float64(len(items)),
			"created", float64(created),
			"updated", float64(updated),
			"unchanged", float64(unchanged),
			"complianceChanged", float64(complianceChanged),
		)); err != nil {
			return nil, err
		}
		return core.NewObject(
			"created", float64(created),
			"updated", float64(updated),
			"unchanged", float64(unchanged),
			"complianceChanged", float64(complianceChanged),
		), nil
	}, false)
	return Out[apitypes.DevicesReportOutput]{Value: result}, err
}
