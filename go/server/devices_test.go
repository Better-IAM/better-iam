package server

// Ports of tests/device-posture.test.ts and tests/device-proof.test.ts (the browser key store test of
// device-posture.test.ts exercises @better-iam/client only). Organizations, people, roles and bindings are seeded
// with the directory fixture; the devices API group is called through iam.API, and proofs are signed the way
// @better-iam/client/device signs them (ES256 compact JWS over { iat, sid }, kid = the RFC 7638 thumbprint).

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const devHour = 3_600_000

// devProver is a device key pair, as createDeviceProver({ store: memoryKeyStore() }) holds one.
type devProver struct {
	f      *directoryFixture
	signer crypto.Signer
	alg    string
	jwk    *core.Object
	kid    string
}

func newDevProver(t *testing.T, f *directoryFixture, kind string) *devProver {
	t.Helper()
	p := &devProver{f: f}
	if kind == "OKP" {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p.signer, p.alg = private, "EdDSA"
		p.jwk = core.NewObject("kty", "OKP", "crv", "Ed25519", "x", base64url(public))
	} else {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p.signer, p.alg = private, "ES256"
		x, y := make([]byte, 32), make([]byte, 32)
		private.PublicKey.X.FillBytes(x)
		private.PublicKey.Y.FillBytes(y)
		p.jwk = core.NewObject("kty", "EC", "crv", "P-256", "x", base64url(x), "y", base64url(y))
	}
	kid, err := deviceKeyIDOf(p.jwk)
	if err != nil {
		t.Fatal(err)
	}
	p.kid = kid
	return p
}

// sign signs a proof with any protected header and payload.
func (p *devProver) sign(header, payload *core.Object) string {
	proof, err := sjwtSign(header, payload, p.signer, p.alg)
	if err != nil {
		p.f.t.Fatal(err)
	}
	return proof
}

func (p *devProver) goodHeader() *core.Object {
	return core.NewObject("alg", p.alg, "typ", DeviceProofType, "kid", p.kid)
}

func (p *devProver) iat() float64 { return math.Floor(p.f.now() / 1000) }

// proof is the proof the client helper sends for a session.
func (p *devProver) proof(sessionID string) string {
	return p.sign(p.goodHeader(), core.NewObject("iat", p.iat(), "sid", sessionID))
}

// devSignIn signs an identity in, returning the token and the session id.
func devSignIn(f *directoryFixture, identity *core.Object) (string, string) {
	f.t.Helper()
	issued, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.IssueSession(ctx, tx, identity, auth.IssueSessionOptions{Method: "password"})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return jsString(issued.Get("token")), jsString(member(issued.Get("session"), "id"))
}

// devHeaders is a credential carrying a bearer token and, when given, a device proof.
func devHeaders(token, proof string) core.CredentialInput {
	headers := http.Header{}
	headers.Set("authorization", "Bearer "+token)
	if proof != "" {
		headers.Set(DeviceProofHeader, proof)
	}
	return core.CredentialInput{Headers: headers}
}

type devSetup struct {
	f        *directoryFixture
	tenantID string
	owner    core.CredentialInput
	alice    *core.Object
	token    string
	session  string
	prover   *devProver
	api      *DevicesAPI
}

var devCompliantOnly = allow(items("documents:read"), items("*"), "conditions",
	core.NewObject("Bool", core.NewObject("request.deviceCompliant", true)))

func newDevSetup(t *testing.T) *devSetup {
	t.Helper()
	f := newAnalysisFixture(t, func(options *BetterIamOptions) {
		week := int64(7 * 86_400_000)
		options.Authentication.SessionLifetimeMs, options.Authentication.SessionIdleTimeoutMs = &week, &week
	})
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	alice, _ := f.person(tenantID, "alice")
	token, session := devSignIn(f, alice)
	role := f.role(tenantID, "Readers on compliant devices", devCompliantOnly)
	f.bind(tenantID, role, "identity", jsString(alice.Get("id")))
	return &devSetup{f: f, tenantID: tenantID, owner: owner, alice: alice, token: token, session: session,
		prover: newDevProver(t, f, "EC"), api: f.iam.API.Devices}
}

// withDevice is alice's credential with a proof for the session (alice's own by default).
func (s *devSetup) withDevice(sessionID ...string) core.CredentialInput {
	id := s.session
	if len(sessionID) > 0 {
		id = sessionID[0]
	}
	return devHeaders(s.token, s.prover.proof(id))
}

func (s *devSetup) canRead(credential core.CredentialInput) bool {
	s.f.t.Helper()
	decision, err := s.f.iam.Authorize(s.f.ctx, AuthorizationRequest{Credential: credential, TenantID: s.tenantID,
		Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "d1"}})
	if err != nil {
		s.f.t.Fatal(err)
	}
	return decision.Allowed
}

func (s *devSetup) enroll(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := s.api.Enroll(s.f.ctx, credential, Input[apitypes.DevicesEnrollInput](body(members...)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (s *devSetup) check(credential core.CredentialInput) *core.Object {
	return answerObject(s.api.Check(s.f.ctx, credential, Input[apitypes.DevicesCheckInput](body("tenantId", s.tenantID))))
}

func (s *devSetup) createIntegration(name, vendor string) *core.Object {
	return answerObject(s.api.CreateIntegration(s.f.ctx, s.owner, Input[apitypes.DevicesCreateIntegrationInput](
		body("tenantId", s.tenantID, "name", name, "vendor", vendor))))
}

func (s *devSetup) report(integrationID string, devices ...*core.Object) *core.Object {
	list := make([]any, len(devices))
	for index, device := range devices {
		list[index] = device
	}
	return answerObject(s.api.Report(s.f.ctx, s.owner, Input[apitypes.DevicesReportInput](
		body("tenantId", s.tenantID, "integrationId", integrationID, "devices", list))))
}

func (s *devSetup) listManaged() []*core.Object {
	listed := answerObject(s.api.List(s.f.ctx, s.owner, Input[apitypes.DevicesListInput](body("tenantId", s.tenantID, "managed", true))))
	return anaObjects(listed.Get("devices"))
}

func (s *devSetup) auditActions(action string) []*core.Object {
	out := []*core.Object{}
	for _, event := range s.f.find("audit", core.NewObject("tenantId", s.tenantID)) {
		if event.Get("action") == action {
			out = append(out, event)
		}
	}
	return out
}

func devExpectCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got no error", code)
	}
	if known := iamError(t, err); known.Code != code {
		t.Fatalf("expected %s, got %s %q", code, known.Code, known.Message)
	}
}

func devExpect(t *testing.T, object *core.Object, key string, want any) {
	t.Helper()
	if got := object.Get(key); got != want {
		t.Fatalf("%s: got %#v, want %#v in %s", key, got, want, stringify(object))
	}
}

func devHasReason(compliance any, reason string) bool {
	reasons, _ := member(compliance, "reasons").([]any)
	if reasons == nil {
		reasons, _ = compliance.([]any)
	}
	for _, item := range reasons {
		if item == reason {
			return true
		}
	}
	return false
}

func TestDevicesEnrollsKeyVerifiesBoundProofsAndReportsAssurance(t *testing.T) {
	s := newDevSetup(t)
	if !RouteGroups.Has("devices") {
		t.Fatal("devices route group missing")
	}
	enrolled, err := s.enroll(s.withDevice(), "tenantId", s.tenantID, "name", "Alice laptop", "platform", "macos", "publicKey", s.prover.jwk)
	if err != nil {
		t.Fatal(err)
	}
	devExpect(t, enrolled, "keyId", s.prover.kid)
	_, err = s.enroll(s.withDevice(), "tenantId", s.tenantID, "name", "Again", "platform", "macos", "publicKey", s.prover.jwk)
	devExpectCode(t, err, "CONFLICT")

	absent := s.check(devHeaders(s.token, ""))
	devExpect(t, absent, "assurance", "none")
	devExpect(t, absent, "proof", "absent")
	devExpect(t, absent, "managed", false)
	verified := s.check(s.withDevice())
	devExpect(t, verified, "assurance", "registered")
	devExpect(t, verified, "proof", "verified")
	devExpect(t, verified, "deviceId", member(enrolled.Get("device"), "id"))
	devExpect(t, verified, "platform", "macos")
	devExpect(t, verified, "compliant", false)
	if !devHasReason(verified.Get("reasons"), "not-managed") {
		t.Fatalf("reasons: %s", stringify(verified))
	}

	// A proof made for another session does not transfer.
	other := s.check(s.withDevice("ses_someone_else"))
	devExpect(t, other, "assurance", "none")
	devExpect(t, other, "proof", "invalid")
	// Garbage in the header is "no device", never an error.
	garbage := s.check(devHeaders(s.token, "not.a.jws"))
	devExpect(t, garbage, "assurance", "none")
	devExpect(t, garbage, "proof", "invalid")

	mine := answerList(s.api.Mine(s.f.ctx, s.withDevice(), Input[apitypes.DevicesMineInput](body("tenantId", s.tenantID))))
	if len(mine) != 1 {
		t.Fatalf("mine: %d", len(mine))
	}
	devExpect(t, mine[0], "id", member(enrolled.Get("device"), "id"))
	devExpect(t, mine[0], "current", true)
}

func TestDevicesTurnsMdmPostureIntoCompliancePoliciesCanRequire(t *testing.T) {
	s := newDevSetup(t)
	f := s.f
	enrolled, err := s.enroll(s.withDevice(), "tenantId", s.tenantID, "name", "Alice laptop", "platform", "macos", "publicKey", s.prover.jwk)
	if err != nil {
		t.Fatal(err)
	}
	laptopID := member(enrolled.Get("device"), "id")
	// Without a compliant device the policy grants nothing.
	if s.canRead(devHeaders(s.token, "")) || s.canRead(s.withDevice()) {
		t.Fatal("granted without a compliant device")
	}
	integration := s.createIntegration("Jamf", "jamf")
	answer(s.api.Configure(f.ctx, s.owner, Input[apitypes.DevicesConfigureInput](body(
		"tenantId", s.tenantID, "requireEncrypted", true, "minOsVersions", core.NewObject("macos", "14.0")))))
	integrationID := jsString(integration.Get("id"))
	// The MDM record does not know the key yet: the self-enrolled device stays unmanaged.
	first := s.report(integrationID, core.NewObject("externalId", "jamf-42", "platform", "macos", "serialNumber", "C02XYZ",
		"osVersion", "14.5 (23F79)", "ownerEmail", "alice@acme.test", "posture", core.NewObject("compliant", true, "encrypted", true)))
	devExpect(t, first, "created", 1.0)
	if s.canRead(s.withDevice()) {
		t.Fatal("granted before the key moved")
	}

	// The agent the MDM deployed reports the key it enrolled: the key moves onto the managed record.
	keyed := s.report(integrationID, core.NewObject("externalId", "jamf-42", "platform", "macos", "osVersion", "14.5",
		"ownerEmail", "alice@acme.test", "keyThumbprint", s.prover.kid, "posture", core.NewObject("compliant", true, "encrypted", true)))
	devExpect(t, keyed, "updated", 1.0)
	check := s.check(s.withDevice())
	devExpect(t, check, "assurance", "compliant")
	devExpect(t, check, "managed", true)
	devExpect(t, check, "compliant", true)
	if check.Get("deviceId") == laptopID {
		t.Fatal("the key did not move")
	}
	laptop := answerObject(s.api.Get(f.ctx, s.owner, Input[apitypes.DevicesGetInput](body("tenantId", s.tenantID, "deviceId", laptopID))))
	devExpect(t, laptop, "status", "retired")
	if !s.canRead(s.withDevice()) {
		t.Fatal("refused on a compliant device")
	}
	// The same session without the proof, or another session with a replayed header, is refused.
	if s.canRead(devHeaders(s.token, "")) {
		t.Fatal("granted without the proof")
	}
	secondToken, _ := devSignIn(f, s.alice)
	if s.canRead(devHeaders(secondToken, s.prover.proof(s.session))) {
		t.Fatal("granted with a replayed proof")
	}

	// Posture drift flips compliance and is audited once.
	drift := s.report(integrationID, core.NewObject("externalId", "jamf-42", "platform", "macos", "osVersion", "13.6",
		"posture", core.NewObject("compliant", true, "encrypted", true)))
	devExpect(t, drift, "complianceChanged", 1.0)
	reasons := s.check(s.withDevice())
	devExpect(t, reasons, "assurance", "managed")
	devExpect(t, reasons, "compliant", false)
	if !devHasReason(reasons.Get("reasons"), "os-too-old") {
		t.Fatalf("reasons: %s", stringify(reasons))
	}
	if s.canRead(s.withDevice()) {
		t.Fatal("granted after the drift")
	}
	// Only the drift changed the verdict (the record was created compliant and stayed so when the key moved).
	changes := s.auditActions("device:compliance-change")
	if len(changes) != 1 {
		t.Fatalf("compliance changes: %d", len(changes))
	}
	metadata := changes[0].Get("metadata").(*core.Object)
	devExpect(t, metadata, "from", true)
	devExpect(t, metadata, "to", false)
	if len(s.auditActions("device:report")) == 0 {
		t.Fatal("no device:report event")
	}
}

func TestDevicesBindsKeysToManagedRecordsWithSingleUseEnrollmentCodes(t *testing.T) {
	s := newDevSetup(t)
	f := s.f
	aliceID := jsString(s.alice.Get("id"))
	integration := s.createIntegration("Intune", "intune")
	s.report(jsString(integration.Get("id")), core.NewObject("externalId", "intune-7", "platform", "windows",
		"osVersion", "10.0.22631", "ownerIdentityId", aliceID, "posture", core.NewObject("compliant", true)))
	managed := s.listManaged()[0]
	devExpect(t, managed, "platform", "windows")
	devExpect(t, managed, "ownerIdentityId", aliceID)
	devExpect(t, managed, "keys", 0.0)

	code := answerObject(s.api.CreateEnrollment(f.ctx, s.owner, Input[apitypes.DevicesCreateEnrollmentInput](body(
		"tenantId", s.tenantID, "deviceId", managed.Get("id"), "ownerIdentityId", aliceID))))
	if !strings.HasPrefix(jsString(code.Get("code")), "biam_") {
		t.Fatalf("code: %s", stringify(code))
	}
	// Someone else cannot use a code issued for alice.
	mallory, _ := f.person(s.tenantID, "mallory")
	malloryToken, mallorySession := devSignIn(f, mallory)
	malloryProver := newDevProver(t, f, "EC")
	_, err := s.enroll(devHeaders(malloryToken, malloryProver.proof(mallorySession)), "tenantId", s.tenantID, "name", "x",
		"platform", "windows", "publicKey", malloryProver.jwk, "enrollmentCode", code.Get("code"))
	devExpectCode(t, err, "ACCESS_DENIED")
	bound, err := s.enroll(s.withDevice(), "tenantId", s.tenantID, "name", "ignored", "platform", "windows",
		"publicKey", s.prover.jwk, "enrollmentCode", code.Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	devExpect(t, bound.Get("device").(*core.Object), "id", managed.Get("id"))
	check := s.check(s.withDevice())
	devExpect(t, check, "assurance", "compliant")
	devExpect(t, check, "deviceId", managed.Get("id"))
	// The code is spent.
	another := newDevProver(t, f, "EC")
	_, err = s.enroll(devHeaders(s.token, another.proof(s.session)), "tenantId", s.tenantID, "name", "again",
		"platform", "windows", "publicKey", another.jwk, "enrollmentCode", code.Get("code"))
	expectError(t, err, "INVALID_INPUT", "Invalid or expired enrollment code")

	// Retiring the device ends what its proofs prove.
	answer(s.api.Retire(f.ctx, s.owner, Input[apitypes.DevicesRetireInput](body("tenantId", s.tenantID, "deviceId", managed.Get("id")))))
	devExpect(t, s.check(s.withDevice()), "assurance", "none")
}

func TestDevicesKeepsAdministrationReportsAndPolicyDefaultsBehindPermissions(t *testing.T) {
	s := newDevSetup(t)
	f := s.f
	alice := devHeaders(s.token, "")
	_, err := s.api.List(f.ctx, alice, Input[apitypes.DevicesListInput](body("tenantId", s.tenantID)))
	devExpectCode(t, err, "ACCESS_DENIED")
	integration := s.createIntegration("CrowdStrike", "crowdstrike")
	_, err = s.api.Report(f.ctx, alice, Input[apitypes.DevicesReportInput](body("tenantId", s.tenantID,
		"integrationId", integration.Get("id"), "devices", items(core.NewObject("externalId", "x", "platform", "linux", "posture", core.NewObject())))))
	devExpectCode(t, err, "ACCESS_DENIED")
	// policies.test fills the always-present device keys.
	document := core.NewObject("version", 1.0, "statements", items(devCompliantOnly))
	tested, err := f.iam.API.Policies.Test(f.ctx, s.owner, Input[apitypes.PoliciesTestInput](body("tenantId", s.tenantID,
		"document", document, "action", "documents:read", "resource", "document/d1")))
	anaSkipUnported(t, err)
	devExpect(t, answerObject(tested, err), "allowed", false)
	compliant, err := f.iam.API.Policies.Test(f.ctx, s.owner, Input[apitypes.PoliciesTestInput](body("tenantId", s.tenantID,
		"document", document, "action", "documents:read", "resource", "document/d1",
		"context", core.NewObject("request.deviceCompliant", true))))
	devExpect(t, answerObject(compliant, err), "allowed", true)
}

func TestDevicesCarriesTheProofThroughTheHTTPTransport(t *testing.T) {
	s := newDevSetup(t)
	if _, err := s.enroll(s.withDevice(), "tenantId", s.tenantID, "name", "Phone", "platform", "ios", "publicKey", s.prover.jwk); err != nil {
		t.Fatal(err)
	}
	response := s.f.post(directoryOrigin, "devices/check", `{"tenantId":"`+s.tenantID+`"}`, map[string]string{
		"authorization": "Bearer " + s.token, DeviceProofHeader: s.prover.proof(s.session),
	})
	if response.Status != 200 {
		t.Fatalf("status %d: %s", response.Status, response.Body)
	}
	if got := member(jsonBody(t, response).Get("data"), "assurance"); got != "registered" {
		t.Fatalf("assurance: %v (%s)", got, response.Body)
	}
}

func TestDevicesMovesAReportedKeyOnlyOffItsOwnersOwnActiveRecord(t *testing.T) {
	s := newDevSetup(t)
	f := s.f
	enrolled, err := s.enroll(s.withDevice(), "tenantId", s.tenantID, "name", "Laptop", "platform", "macos", "publicKey", s.prover.jwk)
	if err != nil {
		t.Fatal(err)
	}
	laptopID := member(enrolled.Get("device"), "id")
	jamf := jsString(s.createIntegration("Jamf", "jamf").Get("id"))
	contractor := jsString(s.createIntegration("Contractor MDM", "custom").Get("id"))
	report := func(integrationID, externalID, ownerEmail string) {
		device := core.NewObject("externalId", externalID, "platform", "macos", "keyThumbprint", s.prover.kid)
		if ownerEmail != "" {
			device.Set("ownerEmail", ownerEmail)
		}
		s.report(integrationID, device.Set("posture", core.NewObject("compliant", true)))
	}
	presenting := func() any { return s.check(s.withDevice()).Get("deviceId") }
	update := func(status string) {
		answer(s.api.Update(f.ctx, s.owner, Input[apitypes.DevicesUpdateInput](body("tenantId", s.tenantID, "deviceId", laptopID, "status", status))))
	}

	// A report naming nobody, or someone else, takes nothing.
	report(contractor, "c-1", "")
	f.person(s.tenantID, "mallory")
	report(contractor, "c-2", "mallory@acme.test")
	if got := presenting(); got != laptopID {
		t.Fatalf("presenting %v, want the laptop", got)
	}
	// A device marked lost keeps its key dead.
	update("lost")
	report(jamf, "jamf-1", "alice@acme.test")
	if got := presenting(); !isUndefined(got) {
		t.Fatalf("presenting %v, want none", got)
	}
	laptop := answerObject(s.api.Get(f.ctx, s.owner, Input[apitypes.DevicesGetInput](body("tenantId", s.tenantID, "deviceId", laptopID))))
	devExpect(t, laptop, "status", "lost")
	// Found again: the managed record takes the key over.
	update("active")
	report(jamf, "jamf-1", "alice@acme.test")
	managed := presenting()
	if isUndefined(managed) || managed == laptopID {
		t.Fatalf("presenting %v, want the managed record", managed)
	}
	// Another integration cannot take it off Jamf's record, even naming the owner.
	report(contractor, "c-3", "alice@acme.test")
	if got := presenting(); got != managed {
		t.Fatalf("presenting %v, want %v", got, managed)
	}
}

func TestDevicesWritesAThrottledCheckInThatFlipsComplianceAndAuditsOnce(t *testing.T) {
	s := newDevSetup(t)
	f := s.f
	integrationID := jsString(s.createIntegration("Jamf", "jamf").Get("id"))
	answer(s.api.Configure(f.ctx, s.owner, Input[apitypes.DevicesConfigureInput](body("tenantId", s.tenantID, "maxCheckInAgeHours", 1.0))))
	start := f.now()
	report := func(checkedInAt float64) *core.Object {
		return s.report(integrationID, core.NewObject("externalId", "jamf-7", "platform", "macos",
			"posture", core.NewObject("compliant", true), "checkedInAt", checkedInAt))
	}
	report(start)
	// The stored check-in has just gone stale; the vendor's timestamp of the new one is fresh but within a minute.
	f.advance(devHour + 500)
	owner := f.ownerSignIn(s.tenantID)
	s.owner = owner
	devExpect(t, report(start+30_000), "complianceChanged", 1.0)
	device := s.listManaged()[0]
	devExpect(t, device, "lastCheckInAt", start+30_000)
	devExpect(t, device.Get("compliance").(*core.Object), "compliant", true)
	devExpect(t, report(start+59_000), "complianceChanged", 0.0)
	if changes := s.auditActions("device:compliance-change"); len(changes) != 1 {
		t.Fatalf("compliance changes: %d", len(changes))
	}
}

func TestDevicesBindsCodesToAnExistingDeviceOnlyForThoseWhoManageIt(t *testing.T) {
	s := newDevSetup(t)
	f := s.f
	// A helpdesk member whose only grant is iam:devices:manage on the enrollment codes.
	helpdesk, key := f.person(s.tenantID, "helpdesk")
	role := f.role(s.tenantID, "Enrollment codes", allow(items("iam:devices:manage"), items("iam/devices/enrollments")))
	f.bind(s.tenantID, role, "identity", jsString(helpdesk.Get("id")))
	integrationID := jsString(s.createIntegration("Intune", "intune").Get("id"))
	s.report(integrationID, core.NewObject("externalId", "kiosk-1", "platform", "windows", "posture", core.NewObject("compliant", true)))
	kiosk := s.listManaged()[0]
	_, err := s.api.CreateEnrollment(f.ctx, key, Input[apitypes.DevicesCreateEnrollmentInput](body(
		"tenantId", s.tenantID, "deviceId", kiosk.Get("id"), "ownerIdentityId", s.alice.Get("id"))))
	devExpectCode(t, err, "ACCESS_DENIED")
	if listed := answerList(s.api.ListEnrollments(f.ctx, s.owner, Input[apitypes.DevicesListEnrollmentsInput](body("tenantId", s.tenantID)))); len(listed) != 0 {
		t.Fatalf("enrollments: %d", len(listed))
	}
	// Codes for new devices are what the grant is for; the owner may still bind the kiosk.
	fresh := answerObject(s.api.CreateEnrollment(f.ctx, key, Input[apitypes.DevicesCreateEnrollmentInput](body("tenantId", s.tenantID))))
	if !strings.HasPrefix(jsString(fresh.Get("code")), "biam_denr_") {
		t.Fatalf("code: %s", stringify(fresh))
	}
	answer(s.api.CreateEnrollment(f.ctx, s.owner, Input[apitypes.DevicesCreateEnrollmentInput](body("tenantId", s.tenantID, "deviceId", kiosk.Get("id")))))
}

func TestDevicesEnrolsOnlyAKeyTheCallerHoldsFromARecentSignIn(t *testing.T) {
	s := newDevSetup(t)
	f := s.f
	enroll := func(credential core.CredentialInput, publicKey *core.Object) (*core.Object, error) {
		return s.enroll(credential, "tenantId", s.tenantID, "name", "Laptop", "platform", "linux", "publicKey", publicKey)
	}
	// No proof at all.
	_, err := enroll(devHeaders(s.token, ""), s.prover.jwk)
	devExpectCode(t, err, "INVALID_INPUT")
	// Mallory saw Alice's public key and enrols it first, signing with her own key: refused.
	mallory, _ := f.person(s.tenantID, "mallory")
	malloryToken, mallorySession := devSignIn(f, mallory)
	malloryProver := newDevProver(t, f, "EC")
	_, err = enroll(devHeaders(malloryToken, malloryProver.proof(mallorySession)), s.prover.jwk)
	devExpectCode(t, err, "INVALID_INPUT")
	// A proof Alice made for her own session proves nothing for Mallory's.
	_, err = enroll(devHeaders(malloryToken, s.prover.proof(s.session)), s.prover.jwk)
	devExpectCode(t, err, "INVALID_INPUT")
	// Alice enrols her key.
	enrolled, err := enroll(s.withDevice(), s.prover.jwk)
	if err != nil {
		t.Fatal(err)
	}

	// Hours later, her (possibly stolen) session can neither add a key nor retire her device.
	f.advance(6 * devHour)
	thief := newDevProver(t, f, "EC")
	_, err = enroll(devHeaders(s.token, thief.proof(s.session)), thief.jwk)
	devExpectCode(t, err, "RECENT_AUTH_REQUIRED")
	_, err = s.api.RetireMine(f.ctx, devHeaders(s.token, ""), Input[apitypes.DevicesRetireMineInput](body(
		"tenantId", s.tenantID, "deviceId", member(enrolled.Get("device"), "id"))))
	devExpectCode(t, err, "RECENT_AUTH_REQUIRED")
}

func TestDevicesCountsADeviceAsRegisteredOnlyForASessionActingInAnotherTenant(t *testing.T) {
	s := newDevSetup(t)
	f := s.f
	if _, err := s.enroll(s.withDevice(), "tenantId", s.tenantID, "name", "Laptop", "platform", "macos", "publicKey", s.prover.jwk); err != nil {
		t.Fatal(err)
	}
	integrationID := jsString(s.createIntegration("Jamf", "jamf").Get("id"))
	s.report(integrationID, core.NewObject("externalId", "jamf-9", "platform", "macos", "ownerEmail", "alice@acme.test",
		"keyThumbprint", s.prover.kid, "posture", core.NewObject("compliant", true)))
	home, err := f.iam.Authenticate(f.ctx, s.withDevice())
	if err != nil {
		t.Fatal(err)
	}
	now := int64(f.now())
	presented, _ := PresentedDevice(f.ctx, f.iam.Store, home, now)
	if presented == nil || presented.Get("assurance") != "compliant" {
		t.Fatalf("home: %s", stringify(presented))
	}
	// The same identity and proof acting in another tenant, as a cross-tenant role session does: that tenant neither
	// manages the device nor set the requirements it was judged by.
	elsewhere := &Principal{Identity: home.Identity, Session: home.Session.Spread(core.NewObject("tenantId", f.rootTenantID())), DeviceProof: home.DeviceProof}
	judged, _ := PresentedDevice(f.ctx, f.iam.Store, elsewhere, now)
	if judged == nil {
		t.Fatal("no device elsewhere")
	}
	devExpect(t, judged, "assurance", "registered")
	compliance := judged.Get("compliance").(*core.Object)
	devExpect(t, compliance, "managed", false)
	devExpect(t, compliance, "compliant", false)
}

func TestDevicesKeepsThePresentingDeviceInViewWhenARoleSessionReDecides(t *testing.T) {
	s := newDevSetup(t)
	f := s.f
	aliceID := jsString(s.alice.Get("id"))
	if _, err := s.enroll(s.withDevice(), "tenantId", s.tenantID, "name", "Laptop", "platform", "linux", "publicKey", s.prover.jwk); err != nil {
		t.Fatal(err)
	}
	fromDevices := f.role(s.tenantID, "Assume from registered devices", allow(items("iam:roles:assume"), items("*"),
		"conditions", core.NewObject("StringEquals", core.NewObject("request.deviceAssurance", "registered"))))
	f.bind(s.tenantID, fromDevices, "identity", aliceID)
	writer := f.role(s.tenantID, "Writer", allow(items("documents:write"), items("*")))
	trust, err := f.iam.API.Trust.Create(f.ctx, f.rootCred, Input[apitypes.TrustCreateInput](body("tenantId", s.tenantID,
		"sourceTenantId", s.tenantID, "sourceIdentityId", aliceID, "roleId", writer, "requireMfa", false)))
	anaSkipUnported(t, err)
	trustID := answerObject(trust, err).Get("id")
	assumedOut, err := f.iam.API.Roles.Assume(f.ctx, s.withDevice(), Input[apitypes.RolesAssumeInput](body("tenantId", s.tenantID, "trustId", trustID)))
	anaSkipUnported(t, err)
	assumed := answerObject(assumedOut, err)
	assumedToken, assumedSession := jsString(assumed.Get("token")), jsString(member(assumed.Get("session"), "id"))
	write := func(credential core.CredentialInput) (bool, error) {
		decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{Credential: credential, TenantID: s.tenantID,
			Action: "documents:write", Resource: ResourceTarget{Type: "document", ID: "d1"}})
		return decision.Allowed, err
	}
	allowed, err := write(devHeaders(assumedToken, s.prover.proof(assumedSession)))
	if err != nil || !allowed {
		t.Fatalf("with the device: %v %v", allowed, err)
	}
	// Without the device, the right to the role no longer holds.
	_, err = write(devHeaders(assumedToken, ""))
	devExpectCode(t, err, "UNAUTHENTICATED")
}

// tests/device-proof.test.ts

func TestDeviceProofAcceptsOnlyWellFormedProofsFromEnrolledKeysBoundToTheSession(t *testing.T) {
	s := newDevSetup(t)
	f := s.f
	ec := s.prover
	sid := s.session
	if _, err := s.enroll(s.withDevice(), "tenantId", s.tenantID, "name", "Laptop", "platform", "linux", "publicKey", ec.jwk); err != nil {
		t.Fatal(err)
	}
	now := ec.iat()
	check := func(proof string) any { return s.check(devHeaders(s.token, proof)).Get("assurance") }
	good := ec.goodHeader()
	with := func(header *core.Object, pairs ...any) *core.Object { return header.Spread(core.NewObject(pairs...)) }
	claims := func(pairs ...any) *core.Object { return core.NewObject(pairs...) }
	expect := func(label string, got, want any) {
		t.Helper()
		if got != want {
			t.Fatalf("%s: got %v, want %v", label, got, want)
		}
	}
	expect("good", check(ec.sign(good, claims("iat", now, "sid", sid))), "registered")
	// typ must be exact.
	expect("typ", check(ec.sign(with(good, "typ", "JWT"), claims("iat", now, "sid", sid))), "none")
	// Key material from the header is never used, even when it is the enrolled key.
	expect("jwk", check(ec.sign(with(good, "jwk", ec.jwk), claims("iat", now, "sid", sid))), "none")
	expect("jku", check(ec.sign(with(good, "jku", "https://attacker.example/jwks"), claims("iat", now, "sid", sid))), "none")
	// iat is bounded both ways.
	expect("old", check(ec.sign(good, claims("iat", now-3600, "sid", sid))), "none")
	expect("future", check(ec.sign(good, claims("iat", now+3600, "sid", sid))), "none")
	expect("no iat", check(ec.sign(good, claims("sid", sid))), "none")
	// The session binding is the presenting session, not a caller-chosen id.
	expect("sid", check(ec.sign(good, claims("iat", now, "sid", "ses_other"))), "none")
	// An unknown key id, or a signature by another key under the enrolled kid.
	stranger := newDevProver(t, f, "EC")
	expect("stranger kid", check(stranger.sign(with(good, "kid", stranger.kid), claims("iat", now, "sid", sid))), "none")
	expect("stranger signature", check(stranger.sign(good, claims("iat", now, "sid", sid))), "none")
	// The algorithm is pinned by the stored key type.
	ed := newDevProver(t, f, "OKP")
	if _, err := s.enroll(devHeaders(s.token, ed.proof(sid)), "tenantId", s.tenantID, "name", "Phone", "platform", "android", "publicKey", ed.jwk); err != nil {
		t.Fatal(err)
	}
	expect("eddsa", check(ed.sign(ed.goodHeader(), claims("iat", now, "sid", sid))), "registered")
	expect("eddsa as es256", check(ed.sign(with(ed.goodHeader(), "alg", "ES256"), claims("iat", now, "sid", sid))), "none")
	// Oversized headers are ignored.
	expect("oversized", check(strings.Repeat("a", 5000)), "none")
}

func TestDeviceProofDoesNotLetOnePersonsDeviceVouchForAnothersSession(t *testing.T) {
	s := newDevSetup(t)
	f := s.f
	bob, _ := f.person(s.tenantID, "bob")
	bobToken, bobSession := devSignIn(f, bob)
	if _, err := s.enroll(s.withDevice(), "tenantId", s.tenantID, "name", "Alice laptop", "platform", "macos", "publicKey", s.prover.jwk); err != nil {
		t.Fatal(err)
	}
	result := s.check(devHeaders(bobToken, s.prover.proof(bobSession)))
	devExpect(t, result, "assurance", "none")
}

// Unit checks of the pure helpers of devices.ts.

func TestDevicesComplianceEvaluation(t *testing.T) {
	settings := resolveDeviceSettings(core.NewObject("requireEncrypted", true, "minOsVersions", core.NewObject("macos", "14.0", "ios", "bad"),
		"maxCheckInAgeHours", 2.0, "blockJailbroken", "yes"))
	if got := stringify(settings); got != `{"requireEncrypted":true,"requireScreenLock":false,"requireFirewall":false,"requireEdr":false,"blockJailbroken":true,"minOsVersions":{"macos":"14.0"},"maxCheckInAgeHours":2}` {
		t.Fatalf("settings: %s", got)
	}
	now := int64(1_000_000_000)
	integration := core.NewObject("id", "int1", "tenantId", "t1", "status", "active", "trustVendorCompliance", true)
	device := core.NewObject("id", "d1", "tenantId", "t1", "platform", "macos", "status", "active",
		"source", core.NewObject("integrationId", "int1", "externalId", "x"),
		"posture", core.NewObject("encrypted", true, "osVersion", "14.5.1", "reportedAt", float64(now), "integrationId", "int1"))
	if got := stringify(evaluateCompliance(device, integration, settings, now)); got != `{"compliant":true,"managed":true,"reasons":[]}` {
		t.Fatalf("compliant: %s", got)
	}
	old := device.Spread(core.NewObject("status", "lost", "posture", device.Get("posture").(*core.Object).Spread(core.NewObject("osVersion", "13.9", "compliant", false))))
	if got := stringify(evaluateCompliance(old, integration, settings, now+3*devHour)); got != `{"compliant":false,"managed":true,"reasons":["lost","stale","vendor-noncompliant","os-too-old"]}` {
		t.Fatalf("noncompliant: %s", got)
	}
	if got := stringify(evaluateCompliance(device, integration.Spread(core.NewObject("status", "disabled")), settings, now)); got != `{"compliant":false,"managed":false,"reasons":["integration-disabled"]}` {
		t.Fatalf("disabled: %s", got)
	}
	if got := stringify(evaluateCompliance(device, nil, settings, now)); got != `{"compliant":false,"managed":false,"reasons":["not-managed"]}` {
		t.Fatalf("unmanaged: %s", got)
	}
	if compareOsVersions("14.5", "14.5.0") != 0 || compareOsVersions("10.10", "10.9") != 1 || compareOsVersions("1", "1.0.1") != -1 {
		t.Fatal("compareOsVersions")
	}
	if !isOsVersion("1.2.3") || isOsVersion("1.2.3.4.5.6.7.8.9") || isOsVersion("v1") || isOsVersion(14.0) {
		t.Fatal("isOsVersion")
	}
}
