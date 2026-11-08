package server

// Port of tests/vc.test.ts (verifiable credentials: types, self-service requests, the Token Status List, the
// OpenID4VCI wallet endpoints, offers, the sweep, key rotation) and the verifiable-credential part of
// tests/clearances-hardening.test.ts. Steps that reach another unit's NOT_IMPLEMENTED stub skip the rest of the test.

import (
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// vcWallet is a wallet: a P-256 holder key that signs OpenID4VCI proofs and presentations.
type vcWallet struct {
	jwk *core.Object
	key *ecdsa.PrivateKey
}

func newVcWallet(t *testing.T) *vcWallet {
	key := newP256(t)
	return &vcWallet{jwk: publicJwkOf(key), key: key}
}

func (w *vcWallet) proof(t *testing.T, audience, nonce string, at float64) string {
	t.Helper()
	token, err := sdJwtSign(core.NewObject("alg", "ES256", "typ", "openid4vci-proof+jwt", "jwk", w.jwk),
		core.NewObject("aud", audience, "nonce", nonce, "iat", float64(int64(at/1000))), w.key, "ES256")
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (w *vcWallet) present(t *testing.T, credential string, disclose []string, audience, nonce string, at float64) string {
	t.Helper()
	return must(PresentSdJwt(credential, SdJwtPresentOptions{Disclose: disclose, HolderKey: w.key, Alg: "ES256", Audience: audience, Nonce: nonce, IssuedAt: &at}))
}

type vcFixture struct {
	*orgFixture
	vc *VerifiableCredentialsAPI
}

func newVcFixture(t *testing.T, mutate func(options *BetterIamOptions)) *vcFixture {
	f := newOrgFixture(t, func(options *BetterIamOptions) {
		options.VerifiableCredentials = On[VerifiableCredentialOptions]()
		if mutate != nil {
			mutate(options)
		}
	})
	return &vcFixture{orgFixture: f, vc: f.iam.API.VerifiableCredentials}
}

func (f *vcFixture) now() float64 { return float64(f.clock.Load()) }

func (f *vcFixture) issuer() string { return "http://localhost:3000/api/iam/vc/" + f.tenantID }

func (f *vcFixture) in(members ...any) *core.Object {
	return core.NewObject("tenantId", f.tenantID).Assign(core.NewObject(members...))
}

func (f *vcFixture) nonce() string {
	f.t.Helper()
	return jsString(f.object(f.vc.Nonce(f.ctx, Input[apitypes.VerifiableCredentialsNonceInput](f.in()))).Get("nonce"))
}

func (f *vcFixture) request(session core.CredentialInput, holder *vcWallet) (*core.Object, error) {
	f.t.Helper()
	out, err := f.vc.Request(f.ctx, session, Input[apitypes.VerifiableCredentialsRequestInput](f.in(
		"type", "employee", "proof", holder.proof(f.t, f.issuer(), f.nonce(), f.now()))))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

// requestOK is requestCredential: the credential and its record.
func (f *vcFixture) requestOK(session core.CredentialInput, holder *vcWallet) (string, *core.Object) {
	f.t.Helper()
	result, err := f.request(session, holder)
	requirePorted(f.t, err)
	return jsString(result.Get("credential")), result.Get("record").(*core.Object)
}

// serve is iam.handler(new Request(url, init)).
func (f *vcFixture) serve(method, target, body string, headers ...string) *httptest.ResponseRecorder {
	f.t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	for index := 0; index+1 < len(headers); index += 2 {
		request.Header.Set(headers[index], headers[index+1])
	}
	recorder := httptest.NewRecorder()
	f.iam.ServeHTTP(recorder, request)
	return recorder
}

func vcBody(t *testing.T, recorder *httptest.ResponseRecorder) *core.Object {
	t.Helper()
	parsed, err := core.ParseJSONString(recorder.Body.String())
	if err != nil {
		t.Fatalf("not JSON (%d): %s", recorder.Code, recorder.Body.String())
	}
	object, _ := parsed.(*core.Object)
	return object
}

func (f *vcFixture) token(values url.Values) *httptest.ResponseRecorder {
	return f.serve(http.MethodPost, f.issuer()+"/token", values.Encode(), "content-type", "application/x-www-form-urlencoded")
}

func (f *vcFixture) credentialRequest(authorization string, body *core.Object) *httptest.ResponseRecorder {
	return f.serve(http.MethodPost, f.issuer()+"/credential", core.MustStringify(body), "content-type", "application/json", "authorization", authorization)
}

func preAuthorizedCode(offer *core.Object) string {
	return jsString(member(member(offer.Get("credentialOffer"), "grants"), vcPreAuthorized).(*core.Object).Get("pre-authorized_code"))
}

func (f *vcFixture) auditOf(action string) []*core.Object {
	f.t.Helper()
	return f.items(f.iam.API.Audit.List(f.ctx, f.owner, Input[apitypes.AuditListInput](f.in("action", action))))
}

// vcSetup is setup(): Acme issuing an `employee` credential that alice may request for herself.
func vcSetup(t *testing.T) (*vcFixture, *core.Object, *core.Object, core.CredentialInput) {
	f := newVcFixture(t, nil)
	typeValue := f.object(f.vc.CreateType(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsCreateTypeInput](f.in(
		"name", "employee",
		"displayName", "Acme employee",
		"description", "Works at Acme",
		"claims", []any{
			core.NewObject("name", "email", "source", "email", "label", "Email"),
			core.NewObject("name", "name", "source", "name", "selective", false),
			core.NewObject("name", "organization", "source", "tenantName", "selective", false),
			core.NewObject("name", "employee_id", "source", "identityId"),
			core.NewObject("name", "clearance", "source", "static", "value", "standard"),
			core.NewObject("name", "team_names", "source", "teams"),
		},
		"lifetimeMs", 7*dayMs,
		"backgroundColor", "#112233",
	))))
	alice := f.member("alice")
	role := f.createRole(f.owner, "name", "Badge holders", "document", core.NewObject("version", 1, "statements", []any{
		core.NewObject("effect", "allow", "actions", []any{"vc:request"}, "resources", []any{"credential-type/employee"}),
	}))
	f.bind(f.owner, role.Get("id"), "identity", alice.Get("id"))
	return f, typeValue, alice, f.login("alice")
}

func TestVcIsOffUnlessTheOptionIsSet(t *testing.T) {
	f := newOrgFixture(t, nil)
	_, err := f.iam.API.VerifiableCredentials.ListTypes(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsListTypesInput](core.NewObject("tenantId", f.tenantID)))
	requirePortedFailure(t, err)
	expectError(t, err, "FEATURE_DISABLED", "Verifiable credentials are not enabled on this deployment")
}

func TestVcIssuesHolderBoundCredentialsThatVerifyWithSelectiveDisclosure(t *testing.T) {
	f, typeValue, alice, aliceSession := vcSetup(t)
	if typeValue.Get("vct") != f.issuer()+"/types/employee" {
		t.Fatalf("vct: %v", typeValue.Get("vct"))
	}
	holder := newVcWallet(t)
	credential, record := f.requestOK(aliceSession, holder)
	if record.Get("typeName") != "employee" || record.Get("identityId") != alice.Get("id") || record.Get("status") != "valid" || record.Get("via") != "request" {
		t.Fatalf("record: %s", core.MustStringify(record))
	}
	split := must(SplitSdJwt(credential))
	header, payload, err := sdDecodeJwt(split.Jwt)
	if err != nil {
		t.Fatal(err)
	}
	if header.Get("alg") != "ES256" || header.Get("typ") != "dc+sd-jwt" {
		t.Fatalf("header: %s", core.MustStringify(header))
	}
	expectedStatus := core.NewObject("status_list", core.NewObject("idx", record.Get("statusIndex"), "uri", f.issuer()+"/status/"+jsString(record.Get("statusListId"))))
	if payload.Get("iss") != f.issuer() || payload.Get("vct") != typeValue.Get("vct") ||
		core.MustStringify(member(payload.Get("cnf"), "jwk")) != core.MustStringify(holder.jwk) ||
		payload.Get("name") != "alice" || payload.Get("organization") != "Acme" ||
		core.MustStringify(payload.Get("status")) != core.MustStringify(expectedStatus) {
		t.Fatalf("payload: %s", core.MustStringify(payload))
	}
	if jsNumber(payload.Get("exp"))-jsNumber(payload.Get("iat")) != 7*86_400 {
		t.Fatalf("lifetime: %v - %v", payload.Get("exp"), payload.Get("iat"))
	}
	if strings.Contains(core.MustStringify(payload), "alice@acme.test") {
		t.Fatal("the payload holds the email")
	}
	if names := disclosureNames(t, split.Disclosures); !reflect.DeepEqual(names, []string{"clearance", "email", "employee_id"}) {
		t.Fatalf("disclosures: %v", names)
	}

	// The holder shows only the email to a verifier, bound to its nonce.
	presentation := holder.present(t, credential, []string{"email"}, "https://verifier.example", "n-1", f.now())
	verified, err := f.iam.VerifiableCredentials.Verify(f.ctx, presentation, core.NewObject("audience", "https://verifier.example", "nonce", "n-1"))
	if err != nil {
		t.Fatal(err)
	}
	claims := verified.Get("claims").(*core.Object)
	if verified.Get("tenantId") != f.tenantID || verified.Get("type") != "employee" || core.MustStringify(verified.Get("disclosed")) != `["email"]` ||
		verified.Get("keyBound") != true || claims.Get("email") != "alice@acme.test" || claims.Get("name") != "alice" ||
		claims.Get("organization") != "Acme" || claims.Has("employee_id") {
		t.Fatalf("verified: %s", core.MustStringify(verified))
	}
	// The public API reports instead of throwing.
	answer := f.object(f.vc.Verify(f.ctx, Input[apitypes.VerifiableCredentialsVerifyInput](core.NewObject(
		"presentation", presentation, "audience", "https://other.example", "nonce", "n-1"))))
	if answer.Get("valid") != false || answer.Get("reason") != "wrong-audience" {
		t.Fatalf("verify: %s", core.MustStringify(answer))
	}

	// A proof nonce works once, and a proof for another issuer is refused.
	proof := holder.proof(t, f.issuer(), f.nonce(), f.now())
	request := func(proof string) error {
		_, err := f.vc.Request(f.ctx, aliceSession, Input[apitypes.VerifiableCredentialsRequestInput](f.in("type", "employee", "proof", proof)))
		return err
	}
	if err := request(proof); err != nil {
		t.Fatal(err)
	}
	expectError(t, request(proof), "INVALID_NONCE", "The proof needs a fresh nonce from verifiableCredentials.nonce")
	expectError(t, request(holder.proof(t, "https://evil.example", f.nonce(), f.now())), "INVALID_PROOF", "The proof does not verify for this issuer")
	if mine := f.items(f.vc.Mine(f.ctx, aliceSession, Input[apitypes.VerifiableCredentialsMineInput](f.in()))); len(mine) != 2 {
		t.Fatalf("mine: %d", len(mine))
	}
}

func TestVcDecidesSelfServiceWithPolicy(t *testing.T) {
	f, _, _, _ := vcSetup(t)
	f.member("bob")
	bobSession := f.login("bob")
	_, err := f.request(bobSession, newVcWallet(t))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	if available := f.items(f.vc.Available(f.ctx, bobSession, Input[apitypes.VerifiableCredentialsAvailableInput](f.in()))); len(available) != 0 {
		t.Fatalf("available: %d", len(available))
	}
	denied := false
	for _, event := range f.auditOf("vc:request") {
		denied = denied || event.Get("outcome") == "deny"
	}
	if !denied {
		t.Fatal("the refusal was not audited")
	}
	// Types that require MFA refuse sessions without it (the owner signed in with a password only).
	f.object(f.vc.UpdateType(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsUpdateTypeInput](f.in("name", "employee", "requireMfa", true))))
	_, err = f.request(f.owner, newVcWallet(t))
	expectError(t, err, "MFA_REQUIRED", "Sign in with multi-factor authentication to get this credential")
}

func TestVcRevokesAndSuspendsThroughTheStatusList(t *testing.T) {
	f, _, _, aliceSession := vcSetup(t)
	holder := newVcWallet(t)
	credential, record := f.requestOK(aliceSession, holder)
	check := func() *core.Object {
		presentation := holder.present(t, credential, nil, "https://verifier.example", "n", f.now())
		return f.object(f.vc.Verify(f.ctx, Input[apitypes.VerifiableCredentialsVerifyInput](core.NewObject(
			"presentation", presentation, "audience", "https://verifier.example", "nonce", "n"))))
	}
	expectValid := func(label string, valid bool, reason string) {
		t.Helper()
		answer := check()
		if answer.Get("valid") != valid || (reason != "" && answer.Get("reason") != reason) {
			t.Fatalf("%s: %s", label, core.MustStringify(answer))
		}
	}
	expectValid("issued", true, "")
	f.object(f.vc.Suspend(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsSuspendInput](f.in("credentialId", record.Get("id"), "reason", "Lost laptop"))))
	expectValid("suspended", false, "suspended")

	// Verifiers read the same status from the public status list token, signed by the issuer.
	statusURL := f.issuer() + "/status/" + jsString(record.Get("statusListId"))
	response := f.serve(http.MethodGet, statusURL, "")
	if response.Header().Get("content-type") != "application/statuslist+jwt" {
		t.Fatalf("status list: %d %v %s", response.Code, response.Header(), response.Body.String())
	}
	metadata := vcBody(t, f.serve(http.MethodGet, "http://localhost:3000/.well-known/jwt-vc-issuer/api/iam/vc/"+f.tenantID, ""))
	if metadata.Get("issuer") != f.issuer() {
		t.Fatalf("metadata: %s", core.MustStringify(metadata))
	}
	keys := member(metadata.Get("jwks"), "keys").([]any)
	now := f.now()
	_, raw, err := ReadStatusList(f.ctx, response.Body.String(), keys[0], statusURL, &now)
	if err != nil {
		t.Fatal(err)
	}
	if status := must(StatusAt(raw, jsNumber(record.Get("statusIndex")), 2)); status != 2 {
		t.Fatalf("status: %v", status)
	}

	f.object(f.vc.Reinstate(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsReinstateInput](f.in("credentialId", record.Get("id")))))
	expectValid("reinstated", true, "")
	// The holder may revoke their own credential; revocation is final.
	f.object(f.vc.Revoke(f.ctx, aliceSession, Input[apitypes.VerifiableCredentialsRevokeInput](f.in("credentialId", record.Get("id")))))
	expectValid("revoked", false, "revoked")
	_, err = f.vc.Reinstate(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsReinstateInput](f.in("credentialId", record.Get("id"))))
	expectError(t, err, "INVALID_TRANSITION", "A revoked credential cannot become valid")
}

func TestVcServesOpenID4VCIWallets(t *testing.T) {
	f, _, _, aliceSession := vcSetup(t)
	issuer := f.issuer()
	offer := f.object(f.vc.CreateOffer(f.ctx, aliceSession, Input[apitypes.VerifiableCredentialsCreateOfferInput](f.in("type", "employee", "txCode", true))))
	if !strings.HasPrefix(jsString(offer.Get("offerUri")), "openid-credential-offer://?credential_offer=") {
		t.Fatalf("offerUri: %v", offer.Get("offerUri"))
	}
	credentialOffer := offer.Get("credentialOffer").(*core.Object)
	if credentialOffer.Get("credential_issuer") != issuer || core.MustStringify(credentialOffer.Get("credential_configuration_ids")) != `["employee"]` {
		t.Fatalf("offer: %s", core.MustStringify(credentialOffer))
	}
	code := preAuthorizedCode(offer)
	txCode := jsString(offer.Get("txCode"))

	metadata := vcBody(t, f.serve(http.MethodGet, "http://localhost:3000/.well-known/openid-credential-issuer/api/iam/vc/"+f.tenantID, ""))
	employee := member(metadata.Get("credential_configurations_supported"), "employee").(*core.Object)
	if metadata.Get("credential_issuer") != issuer || metadata.Get("credential_endpoint") != issuer+"/credential" ||
		metadata.Get("nonce_endpoint") != issuer+"/nonce" || employee.Get("format") != "dc+sd-jwt" ||
		employee.Get("vct") != issuer+"/types/employee" || core.MustStringify(employee.Get("cryptographic_binding_methods_supported")) != `["jwk"]` {
		t.Fatalf("metadata: %s", core.MustStringify(metadata))
	}
	display := member(employee.Get("credential_metadata"), "display").([]any)[0].(*core.Object)
	if display.Get("name") != "Acme employee" || display.Get("background_color") != "#112233" {
		t.Fatalf("display: %s", core.MustStringify(display))
	}
	typeMetadata := vcBody(t, f.serve(http.MethodGet, issuer+"/types/employee", ""))
	if typeMetadata.Get("vct") != issuer+"/types/employee" || typeMetadata.Get("name") != "Acme employee" {
		t.Fatalf("type metadata: %s", core.MustStringify(typeMetadata))
	}

	wrongPin := "000000"
	if txCode == wrongPin {
		wrongPin = "111111"
	}
	wrong := f.token(url.Values{"grant_type": {vcPreAuthorized}, "pre-authorized_code": {code}, "tx_code": {wrongPin}})
	if wrong.Code != 400 || vcBody(t, wrong).Get("error") != "invalid_grant" {
		t.Fatalf("wrong PIN: %d %s", wrong.Code, wrong.Body.String())
	}
	granted := f.token(url.Values{"grant_type": {vcPreAuthorized}, "pre-authorized_code": {code}, "tx_code": {txCode}})
	if granted.Code != 200 {
		t.Fatalf("token: %d %s", granted.Code, granted.Body.String())
	}
	accessToken := jsString(vcBody(t, granted).Get("access_token"))
	// The code works once.
	if again := f.token(url.Values{"grant_type": {vcPreAuthorized}, "pre-authorized_code": {code}, "tx_code": {txCode}}); again.Code != 400 {
		t.Fatalf("second redemption: %d", again.Code)
	}

	cNonce := jsString(vcBody(t, f.serve(http.MethodPost, issuer+"/nonce", "")).Get("c_nonce"))
	holder := newVcWallet(t)
	credential := func(authorization string) *httptest.ResponseRecorder {
		return f.credentialRequest(authorization, core.NewObject(
			"credential_configuration_id", "employee",
			"proofs", core.NewObject("jwt", []any{holder.proof(t, issuer, cNonce, f.now())}),
		))
	}
	if refused := credential("Bearer biam_vcat.x.y"); refused.Code != 401 {
		t.Fatalf("unknown token: %d %s", refused.Code, refused.Body.String())
	}
	issued := credential("Bearer " + accessToken)
	if issued.Code != 200 {
		t.Fatalf("credential: %d %s", issued.Code, issued.Body.String())
	}
	first := vcBody(t, issued).Get("credentials").([]any)[0].(*core.Object)
	_, payload, err := sdDecodeJwt(must(SplitSdJwt(first.Get("credential"))).Jwt)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Get("iss") != issuer || core.MustStringify(member(payload.Get("cnf"), "jwk")) != core.MustStringify(holder.jwk) {
		t.Fatalf("payload: %s", core.MustStringify(payload))
	}
	// One credential per offer.
	if again := credential("Bearer " + accessToken); again.Code != 401 {
		t.Fatalf("second credential: %d", again.Code)
	}
	mine := f.items(f.vc.Mine(f.ctx, aliceSession, Input[apitypes.VerifiableCredentialsMineInput](f.in())))
	if len(mine) != 1 || mine[0].Get("via") != "offer" {
		t.Fatalf("mine: %s", core.MustStringify(vcObjects(mine)))
	}
}

func TestVcAdministratorsOfferToOthersAndTheSweepRevokesLeavers(t *testing.T) {
	f, _, _, aliceSession := vcSetup(t)
	bob := f.member("bob")
	offer := f.object(f.vc.CreateOffer(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsCreateOfferInput](f.in("type", "employee", "identityId", bob.Get("id")))))
	if offer.Has("txCode") {
		t.Fatalf("offer: %s", core.MustStringify(offer))
	}
	credential, record := f.requestOK(aliceSession, newVcWallet(t))
	if credential == "" {
		t.Fatal("no credential")
	}
	expectSweep := func(input *core.Object, examined, revoked float64) {
		t.Helper()
		result, err := f.iam.VerifiableCredentials.Sweep(f.ctx, input)
		requirePorted(t, err)
		if core.MustStringify(result) != core.MustStringify(core.NewObject("examined", examined, "revoked", revoked)) {
			t.Fatalf("sweep: %s", core.MustStringify(result))
		}
	}
	expectSweep(nil, 1, 0)
	f.object(f.iam.API.Identities.SetStatus(f.ctx, f.owner, Input[apitypes.IdentitiesSetStatusInput](f.in("identityId", record.Get("identityId"), "status", "disabled"))))
	expectSweep(f.in(), 1, 1)
	issued := f.object(f.vc.ListIssued(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsListIssuedInput](f.in())))
	first := issued.Get("credentials").([]any)[0].(*core.Object)
	if first.Get("status") != "revoked" || first.Get("reason") != "identity-inactive" {
		t.Fatalf("issued: %s", core.MustStringify(first))
	}
}

func TestVcCapsCredentialsAtTheirGrantsAndRevokesThemWhenAccessGoes(t *testing.T) {
	f, typeValue, _, _ := vcSetup(t)
	carol := f.member("carol")
	role := f.createRole(f.owner, "name", "Visitors", "document", core.NewObject("version", 1, "statements", []any{
		core.NewObject("effect", "allow", "actions", []any{"vc:request"}, "resources", []any{"credential-type/employee"}),
	}))
	binding := f.bind(f.owner, role.Get("id"), "identity", carol.Get("id"), "expiresAt", f.now()+2*dayMs)
	carolSession := f.login("carol")
	_, record := f.requestOK(carolSession, newVcWallet(t))
	// A week-long type, but the grant ends in two days.
	if jsNumber(record.Get("validUntil")) != f.now()+2*dayMs || jsNumber(typeValue.Get("lifetimeMs")) != 7*dayMs {
		t.Fatalf("validUntil: %v", record.Get("validUntil"))
	}

	// A self-service offer is re-decided at redemption, and the refusal is audited.
	offer := f.object(f.vc.CreateOffer(f.ctx, carolSession, Input[apitypes.VerifiableCredentialsCreateOfferInput](f.in("type", "employee"))))
	f.object(f.iam.API.Bindings.Delete(f.ctx, f.owner, Input[apitypes.BindingsDeleteInput](f.in("bindingId", binding.Get("id")))))
	granted := f.token(url.Values{"grant_type": {vcPreAuthorized}, "pre-authorized_code": {preAuthorizedCode(offer)}})
	accessToken := jsString(vcBody(t, granted).Get("access_token"))
	holder := newVcWallet(t)
	refused := f.credentialRequest("Bearer "+accessToken, core.NewObject(
		"credential_configuration_id", "employee",
		"proofs", core.NewObject("jwt", []any{holder.proof(t, f.issuer(), f.nonce(), f.now())}),
	))
	if refused.Code != 403 {
		t.Fatalf("redemption: %d %s", refused.Code, refused.Body.String())
	}
	reason := ""
	for _, event := range f.auditOf("vc:offer:redeem") {
		if event.Get("outcome") == "deny" && reason == "" {
			reason = jsString(member(event.Get("metadata"), "reason"))
		}
	}
	if reason != "access-changed" {
		t.Fatalf("refusal reason: %q", reason)
	}

	// The sweep revokes what was issued once `vc:request` no longer allows it.
	result, err := f.iam.VerifiableCredentials.Sweep(f.ctx, f.in())
	requirePorted(t, err)
	if core.MustStringify(result) != `{"examined":1,"revoked":1}` {
		t.Fatalf("sweep: %s", core.MustStringify(result))
	}
	issued := f.object(f.vc.ListIssued(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsListIssuedInput](f.in())))
	for _, item := range issued.Get("credentials").([]any) {
		view := item.(*core.Object)
		if view.Get("id") == record.Get("id") && (view.Get("status") != "revoked" || view.Get("reason") != "access-changed") {
			t.Fatalf("issued: %s", core.MustStringify(view))
		}
	}
}

func TestVcRefusesReplaysSquattedTypesAndPinGuessing(t *testing.T) {
	f, _, _, aliceSession := vcSetup(t)
	holder := newVcWallet(t)
	credential, _ := f.requestOK(aliceSession, holder)
	presentation := holder.present(t, credential, []string{}, "a", "n", f.now())
	// Without the verifier's audience and nonce, a captured presentation would verify for anyone.
	_, err := f.vc.Verify(f.ctx, Input[apitypes.VerifiableCredentialsVerifyInput](core.NewObject("presentation", presentation)))
	expectError(t, err, "INVALID_INPUT", "Verify a presentation for your audience and the nonce you issued; without them it could be a replay")
	verified, err := f.iam.VerifiableCredentials.Verify(f.ctx, presentation, core.NewObject("audience", "a", "nonce", "n"))
	if err != nil {
		t.Fatal(err)
	}
	if binding := verified.Get("keyBinding").(*core.Object); binding.Get("audience") != "a" || binding.Get("nonce") != "n" {
		t.Fatalf("keyBinding: %s", core.MustStringify(binding))
	}

	// Type identifiers under another organization's issuer are not this one's to claim.
	_, err = f.vc.CreateType(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsCreateTypeInput](f.in(
		"name", "squat", "displayName", "Squat", "vct", "http://localhost:3000/api/iam/vc/other-org/types/employee",
		"claims", []any{core.NewObject("name", "email", "source", "email")})))
	expectError(t, err, "INVALID_INPUT", "vct names another organization's issuer")
	external := f.object(f.vc.CreateType(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsCreateTypeInput](f.in(
		"name", "external", "displayName", "External schema", "vct", "https://schemas.example/employee",
		"claims", []any{core.NewObject("name", "email", "source", "email")}))))
	if external.Get("vct") != "https://schemas.example/employee" {
		t.Fatalf("external: %s", core.MustStringify(external))
	}

	// A wallet that has not asked for the PIN yet has not guessed wrong; wrong guesses are audited and five end the offer.
	offer := f.object(f.vc.CreateOffer(f.ctx, aliceSession, Input[apitypes.VerifiableCredentialsCreateOfferInput](f.in("type", "employee", "txCode", true))))
	code := preAuthorizedCode(offer)
	txCode := jsString(offer.Get("txCode"))
	token := func(pin *string) (int, string) {
		values := url.Values{"grant_type": {vcPreAuthorized}, "pre-authorized_code": {code}}
		if pin != nil {
			values.Set("tx_code", *pin)
		}
		response := f.token(values)
		return response.Code, jsString(vcBody(t, response).Get("error"))
	}
	for i := 0; i < 6; i++ {
		if _, failure := token(nil); failure != "invalid_request" {
			t.Fatalf("no PIN %d: %s", i, failure)
		}
	}
	wrongPin := "000000"
	if txCode == wrongPin {
		wrongPin = "111111"
	}
	for i := 0; i < 5; i++ {
		if _, failure := token(&wrongPin); failure != "invalid_grant" {
			t.Fatalf("wrong PIN %d: %s", i, failure)
		}
	}
	if status, _ := token(&txCode); status != 400 {
		t.Fatalf("locked offer: %d", status)
	}
	reasons := []string{}
	for _, event := range f.auditOf("vc:offer:redeem") {
		if event.Get("outcome") == "deny" {
			reasons = append(reasons, jsString(member(event.Get("metadata"), "reason")))
		}
	}
	slices.Sort(reasons)
	if !reflect.DeepEqual(reasons, []string{"pin-locked", "wrong-pin", "wrong-pin", "wrong-pin", "wrong-pin"}) {
		t.Fatalf("reasons: %v", reasons)
	}
}

func TestVcRotatesIssuerKeys(t *testing.T) {
	f, _, _, aliceSession := vcSetup(t)
	holder := newVcWallet(t)
	credential, _ := f.requestOK(aliceSession, holder)
	keys := f.items(f.vc.ListKeys(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsListKeysInput](f.in())))
	first := keys[0]
	next := f.object(f.vc.RotateKey(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsRotateKeyInput](f.in())))
	if next.Get("kid") == first.Get("kid") {
		t.Fatal("the key did not change")
	}
	presentation := holder.present(t, credential, []string{}, "a", "n", f.now())
	verify := func() *core.Object {
		return f.object(f.vc.Verify(f.ctx, Input[apitypes.VerifiableCredentialsVerifyInput](core.NewObject("presentation", presentation, "audience", "a", "nonce", "n"))))
	}
	if answer := verify(); answer.Get("valid") != true {
		t.Fatalf("after rotation: %s", core.MustStringify(answer))
	}
	fresh, _ := f.requestOK(aliceSession, holder)
	header, _, err := sdDecodeJwt(must(SplitSdJwt(fresh)).Jwt)
	if err != nil || header.Get("kid") != next.Get("kid") {
		t.Fatalf("fresh kid: %v %v", header, err)
	}
	_, err = f.vc.RetireKey(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsRetireKeyInput](f.in("kid", first.Get("kid"))))
	expectError(t, err, "RESOURCE_IN_USE", "1 credentials signed by this key are still valid")
	f.object(f.vc.RetireKey(f.ctx, f.owner, Input[apitypes.VerifiableCredentialsRetireKeyInput](f.in("kid", first.Get("kid"), "force", true))))
	if answer := verify(); answer.Get("valid") != false || answer.Get("reason") != "unknown-issuer" {
		t.Fatalf("after retirement: %s", core.MustStringify(answer))
	}
}

// TestVcAdministratorOffersNeedTheHolderCleared is the verifiable-credential case of
// tests/clearances-hardening.test.ts: the holder of an administrator's offer must be cleared at the offer, the
// redemption and the sweep.
func TestVcAdministratorOffersNeedTheHolderCleared(t *testing.T) {
	f := newVcFixture(t, func(options *BetterIamOptions) { options.Clearances = &ClearanceOptions{} })
	owner := f.owner
	clearances := f.iam.API.Clearances
	f.object(clearances.DefineScheme(f.ctx, owner, Input[apitypes.ClearancesDefineSchemeInput](f.in(
		"name", "Acme", "template", "us", "adjudication", "unrestricted"))))
	f.object(f.vc.CreateType(f.ctx, owner, Input[apitypes.VerifiableCredentialsCreateTypeInput](f.in(
		"name", "facility-badge", "displayName", "Facility badge",
		"claims", []any{core.NewObject("name", "name", "source", "name", "selective", false)}))))
	f.ported(clearances.Label(f.ctx, owner, Input[apitypes.ClearancesLabelInput](f.in(
		"type", "credential-type", "id", "facility-badge", "label", core.NewObject("level", "TS")))))
	bob := f.member("bob")
	offer := func() (*core.Object, error) {
		out, err := f.vc.CreateOffer(f.ctx, owner, Input[apitypes.VerifiableCredentialsCreateOfferInput](f.in("type", "facility-badge", "identityId", bob.Get("id"))))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	_, err := offer()
	requirePortedFailure(t, err)
	expectError(t, err, "ACCESS_DENIED", "The holder is not cleared for this credential type")
	f.ported(clearances.Grant(f.ctx, owner, Input[apitypes.ClearancesGrantInput](f.in(
		"identityId", bob.Get("id"), "level", "TS", "citizenship", []any{"USA"}))))
	early, err := offer()
	requirePorted(t, err)
	suspend := func() {
		f.ported(clearances.Suspend(f.ctx, owner, Input[apitypes.ClearancesSuspendInput](f.in(
			"identityId", bob.Get("id"), "reason", "review", "notifyPerson", false))))
	}
	redeem := func(offer *core.Object) int {
		granted := f.token(url.Values{"grant_type": {vcPreAuthorized}, "pre-authorized_code": {preAuthorizedCode(offer)}})
		accessToken := jsString(vcBody(t, granted).Get("access_token"))
		return f.credentialRequest("Bearer "+accessToken, core.NewObject(
			"credential_configuration_id", "facility-badge",
			"proofs", core.NewObject("jwt", []any{newVcWallet(t).proof(t, f.issuer(), f.nonce(), f.now())}),
		)).Code
	}
	// Suspended before the wallet redeems it: the offer is decided again and refused.
	suspend()
	if status := redeem(early); status != 403 {
		t.Fatalf("suspended redemption: %d", status)
	}
	reasons := []string{}
	for _, event := range f.auditOf("vc:offer:redeem") {
		if event.Get("outcome") == "deny" {
			reasons = append(reasons, jsString(member(event.Get("metadata"), "reason")))
		}
	}
	if !reflect.DeepEqual(reasons, []string{"access-changed"}) {
		t.Fatalf("refusals: %v", reasons)
	}
	f.ported(clearances.Reinstate(f.ctx, owner, Input[apitypes.ClearancesReinstateInput](f.in("identityId", bob.Get("id")))))
	again, err := offer()
	requirePorted(t, err)
	if status := redeem(again); status != 200 {
		t.Fatalf("cleared redemption: %d", status)
	}
	sweep := func() string {
		result, err := f.iam.VerifiableCredentials.Sweep(f.ctx, f.in())
		requirePorted(t, err)
		return core.MustStringify(result)
	}
	if result := sweep(); result != `{"examined":1,"revoked":0}` {
		t.Fatalf("sweep: %s", result)
	}
	// The sweep revokes it once the holder no longer dominates the type's label.
	suspend()
	if result := sweep(); result != `{"examined":1,"revoked":1}` {
		t.Fatalf("sweep after suspension: %s", result)
	}
	issued := f.object(f.vc.ListIssued(f.ctx, owner, Input[apitypes.VerifiableCredentialsListIssuedInput](f.in())))
	first := issued.Get("credentials").([]any)[0].(*core.Object)
	if first.Get("identityId") != bob.Get("id") || first.Get("status") != "revoked" || first.Get("reason") != "access-changed" {
		t.Fatalf("issued: %s", core.MustStringify(first))
	}
}
