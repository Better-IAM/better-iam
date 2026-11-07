package server

// Privacy and consent tests, after tests/privacy.test.ts: purposes, people's own decisions with receipts and
// versions, application subjects, data-subject requests (access, erasure, restriction, objection, extension, public
// intake, reminders) and the review fixes. The roles and bindings the scenarios need are seeded directly in the store
// (the roles and bindings API groups are ported separately). Steps that reach another unit's NOT_IMPLEMENTED stub
// (privacy.ts helpers among them) end the test with a skip. The rendering of the privacy emails is tested with the
// auth package's templates, and the organization-deletion hold check with the tenants API group.

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const pvDay = 86_400_000

type privacyScenario struct {
	*govFixture
	api        *PrivacyAPI
	marketing  *core.Object
	analytics  *core.Object
	sale       *core.Object
	billing    *core.Object
	alice      *core.Object
	aliceID    string
	aliceToken string
}

func newPrivacyScenario(t *testing.T) *privacyScenario {
	t.Helper()
	f := newGovFixture(t, nil)
	s := &privacyScenario{govFixture: f, api: f.iam.API.Privacy}
	s.marketing = s.ok(call(s.api.CreatePurpose, f.adminToken, s.body(
		"key", "marketing-email", "name", "Marketing email", "description", "Product news and offers by email.",
		"legalBasis", "consent", "dataCategories", []any{"contact"})))
	s.analytics = s.ok(call(s.api.CreatePurpose, f.adminToken, s.body(
		"key", "product-analytics", "name", "Product analytics", "description", "How features are used, to improve them.",
		"legalBasis", "legitimate-interests", "dataCategories", []any{"usage"})))
	s.sale = s.ok(call(s.api.CreatePurpose, f.adminToken, s.body(
		"key", "data-sharing", "name", "Sharing with partners", "description", "Sharing contact data with advertising partners.",
		"legalBasis", "consent", "mode", "opt-out")))
	s.billing = s.ok(call(s.api.CreatePurpose, f.adminToken, s.body(
		"key", "billing", "name", "Billing", "description", "Invoices and payments for your plan.", "legalBasis", "contract")))
	s.alice = f.person("alice")
	s.aliceID = jsString(s.alice.Get("id"))
	s.aliceToken = f.token(s.alice)
	return s
}

// body is a request body for the scenario's tenant.
func (s *privacyScenario) body(members ...any) *core.Object {
	return core.NewObject(append([]any{"tenantId", s.tenantID}, members...)...)
}

// ok unwraps an object answer; another unit's NOT_IMPLEMENTED stub skips the rest of the test.
func (s *privacyScenario) ok(value any, err error) *core.Object {
	s.t.Helper()
	skipUnported(s.t, err)
	return okObject(s.t, value, err)
}

// many unwraps a list answer; another unit's NOT_IMPLEMENTED stub skips the rest of the test.
func (s *privacyScenario) many(value any, err error) []*core.Object {
	s.t.Helper()
	skipUnported(s.t, err)
	return okList(s.t, value, err)
}

// refused expects an IamError with code; another unit's NOT_IMPLEMENTED stub skips the rest of the test.
func (s *privacyScenario) refused(err error, code string) {
	s.t.Helper()
	if code != "NOT_IMPLEMENTED" {
		skipUnported(s.t, err)
	}
	expectCodeStatus(s.t, err, code, 0)
}

func (s *privacyScenario) decide(token, key string, version float64, granted bool, members ...any) *core.Object {
	s.t.Helper()
	return s.ok(call(s.api.Decide, token, s.body(append([]any{"purposeKey", key, "version", version, "granted", granted}, members...)...)))
}

func (s *privacyScenario) check(token string, subject *core.Object, key string) *core.Object {
	s.t.Helper()
	return s.ok(call(s.api.Check, token, s.body("subject", subject, "purposeKey", key)))
}

func (s *privacyScenario) aliceSubject() *core.Object { return core.NewObject("identityId", s.aliceID) }

func (s *privacyScenario) submit(token string, members ...any) *core.Object {
	s.t.Helper()
	return s.ok(call(s.api.SubmitRequest, token, s.body(members...)))
}

func (s *privacyScenario) fulfil(token, requestID string, members ...any) (any, error) {
	return call(s.api.FulfilRequest, token, s.body(append([]any{"requestId", requestID}, members...)...))
}

func stateOf(page *core.Object, key string) *core.Object {
	for _, item := range page.Get("purposes").([]any) {
		purpose := item.(*core.Object)
		if purpose.Get("key") == key {
			return purpose
		}
	}
	return nil
}

func TestPrivacyValidatesPurposesAndRefusesDuplicateKeys(t *testing.T) {
	s := newPrivacyScenario(t)
	expectJSON(t, "purpose member order", s.marketing.Keys(),
		`["uniqueKey","key","name","description","legalBasis","mode","dataCategories","reconsentOnVersion","id","tenantId","version","archived","createdAt","updatedAt"]`)
	_, err := call(s.api.CreatePurpose, s.adminToken, s.body("key", "marketing-email", "name", "Again", "description", "x", "legalBasis", "consent"))
	s.refused(err, "CONFLICT")
	_, err = call(s.api.CreatePurpose, s.adminToken, s.body("key", "Bad Key", "name", "Bad", "description", "x", "legalBasis", "consent"))
	s.refused(err, "INVALID_INPUT")
	_, err = call(s.api.CreatePurpose, s.adminToken, s.body("key", "fraud", "name", "Fraud", "description", "x", "legalBasis", "legal-obligation", "mode", "opt-out"))
	expectError(t, err, "INVALID_INPUT", "Only consent purposes can be opt-out")
	_, err = call(s.api.CreatePurpose, s.adminToken, s.body("key", "fraud", "name", "Fraud", "description", "x", "legalBasis", "contract", "consentLifetimeDays", 30.0))
	expectError(t, err, "INVALID_INPUT", "consentLifetimeDays applies to consent purposes only")
	_, err = call(s.api.CreatePurpose, s.adminToken, s.body("key", "fraud", "name", "Fraud", "description", "x", "legalBasis", "consent", "dataCategories", []any{"Contact"}))
	expectError(t, err, "INVALID_INPUT", "dataCategories must hold at most 32 lowercase identifiers such as contact or usage")
	// Changing the legal basis is material and needs a new version.
	_, err = call(s.api.UpdatePurpose, s.adminToken, s.body("purposeId", s.analytics.Get("id"), "legalBasis", "consent"))
	expectError(t, err, "INVALID_INPUT", "Changing the legal basis or consent mode is a material change: publish it with newVersion")
	_, err = call(s.api.UpdatePurpose, s.adminToken, s.body("purposeId", s.analytics.Get("id"), "key", "other"))
	expectError(t, err, "INVALID_INPUT", "A purpose key cannot change; create a new purpose")
	// A member without permissions cannot manage purposes.
	_, err = call(s.api.ListPurposes, s.aliceToken, s.body())
	s.refused(err, "ACCESS_DENIED")
	listed := s.many(call(s.api.ListPurposes, s.adminToken, s.body()))
	var names []string
	for _, purpose := range listed {
		names = append(names, jsString(purpose.Get("name")))
	}
	if strings.Join(names, ",") != "Billing,Marketing email,Product analytics,Sharing with partners" {
		t.Errorf("purposes by name = %v", names)
	}
	// Purposes nobody decided on can be deleted.
	deleted := s.ok(call(s.api.DeletePurpose, s.adminToken, s.body("purposeId", s.billing.Get("id"))))
	expectJSON(t, "deleted", deleted, `{"deleted":true}`)
}

func TestPrivacyPeopleDecideWithReceiptsVersionsAndBases(t *testing.T) {
	s := newPrivacyScenario(t)
	mine := s.ok(call(s.api.Mine, s.aliceToken, s.body()))
	expectJSON(t, "marketing", stateOf(mine, "marketing-email").Get("state"), `{"allowed":false,"reason":"NO_CONSENT"}`)
	expectJSON(t, "analytics", stateOf(mine, "product-analytics").Get("state"), `{"allowed":true,"reason":"LEGITIMATE_INTERESTS"}`)
	expectJSON(t, "sharing", stateOf(mine, "data-sharing").Get("state"), `{"allowed":true,"reason":"NOT_OPTED_OUT"}`)
	expectJSON(t, "billing", stateOf(mine, "billing").Get("state"), `{"allowed":true,"reason":"LEGAL_BASIS"}`)
	if stateOf(mine, "billing").Get("decidable") != false {
		t.Errorf("billing decidable = %v", stateOf(mine, "billing").Get("decidable"))
	}
	// Purposes people decide on come first, then by name.
	var order []string
	for _, item := range mine.Get("purposes").([]any) {
		order = append(order, jsString(item.(*core.Object).Get("key")))
	}
	if strings.Join(order, ",") != "marketing-email,product-analytics,data-sharing,billing" {
		t.Errorf("mine order = %v", order)
	}

	receipt := s.decide(s.aliceToken, "marketing-email", 1, true, "evidence", "Signup form v3")
	if receipt.Get("tenantId") != s.tenantID || receipt.Get("subject") != "identity:"+s.aliceID || receipt.Get("granted") != true || receipt.Get("source") != "self" ||
		member(receipt.Get("purpose"), "key") != "marketing-email" || member(receipt.Get("purpose"), "version") != 1.0 || member(receipt.Get("purpose"), "legalBasis") != "consent" {
		t.Errorf("receipt = %s", stringify(receipt))
	}
	if events := s.find("audit", core.NewObject("tenantId", s.tenantID, "action", "privacy:consent")); len(events) != 1 ||
		stringify(events[0].Get("metadata")) != `{"purposeKey":"marketing-email","granted":true,"purposeVersion":1,"source":"self","receiptId":"`+jsString(receipt.Get("receiptId"))+`"}` {
		t.Errorf("consent audit = %s", stringify(pvList(events)))
	}
	if got := s.check(s.adminToken, s.aliceSubject(), "marketing-email"); got.Get("allowed") != true || got.Get("reason") != "CONSENT_GIVEN" {
		t.Errorf("check = %s", stringify(got))
	}
	// Opting out and objecting.
	s.decide(s.aliceToken, "data-sharing", 1, false)
	s.decide(s.aliceToken, "product-analytics", 1, false)
	after := s.ok(call(s.api.Mine, s.aliceToken, s.body()))
	if reason := member(stateOf(after, "data-sharing").Get("state"), "reason"); reason != "CONSENT_WITHDRAWN" {
		t.Errorf("data-sharing = %v", reason)
	}
	if reason := member(stateOf(after, "product-analytics").Get("state"), "reason"); reason != "OBJECTED" {
		t.Errorf("product-analytics = %v", reason)
	}
	// Contract purposes are not a matter of consent.
	_, err := call(s.api.Decide, s.aliceToken, s.body("purposeKey", "billing", "version", 1.0, "granted", false))
	expectError(t, err, "INVALID_INPUT", "Purpose billing relies on contract, not on consent")
	_, err = call(s.api.Decide, s.aliceToken, s.body("purposeKey", "billing", "version", 1.0, "granted", "yes"))
	expectError(t, err, "INVALID_INPUT", "granted must be a boolean")
	_, err = call(s.api.Decide, s.aliceToken, s.body("purposeKey", "marketing-email", "version", 1.0, "granted", true, "method", "bad|method"))
	expectError(t, err, "INVALID_INPUT", "Invalid method")
	// Another organization's people decide in their own organization only.
	_, err = call(s.api.Decide, s.aliceToken, core.NewObject("tenantId", "elsewhere", "purposeKey", "marketing-email", "version", 1.0, "granted", true))
	expectError(t, err, "ACCESS_DENIED", "Privacy choices are made by the person, from a signed-in session of their organization")

	// A new version asks again: the old grant no longer counts, and deciding on the old text is refused.
	updated := s.ok(call(s.api.UpdatePurpose, s.adminToken, s.body("purposeId", s.marketing.Get("id"),
		"description", "Product news, offers and partner offers by email.", "newVersion", true)))
	if updated.Get("version") != 2.0 {
		t.Errorf("updated = %s", stringify(updated))
	}
	if got := s.check(s.adminToken, s.aliceSubject(), "marketing-email"); got.Get("allowed") != false || got.Get("reason") != "CONSENT_OUTDATED" {
		t.Errorf("check after version = %s", stringify(got))
	}
	_, err = call(s.api.Decide, s.aliceToken, s.body("purposeKey", "marketing-email", "version", 1.0, "granted", true))
	expectError(t, err, "VERSION_CONFLICT", "The purpose changed; review the current version before deciding")

	// The receipt verifies; a tampered copy does not; a later decision makes it historical.
	expectJSON(t, "verify", s.ok(call(s.api.VerifyReceipt, s.adminToken, s.body("receipt", receipt))), `{"valid":true,"current":true}`)
	tampered := receipt.Spread(core.NewObject("granted", false))
	expectJSON(t, "tampered", s.ok(call(s.api.VerifyReceipt, s.adminToken, s.body("receipt", tampered))), `{"valid":false,"reason":"SIGNATURE_INVALID"}`)
	unknown := receipt.Spread(core.NewObject("tenantId", "elsewhere"))
	expectJSON(t, "other tenant", s.ok(call(s.api.VerifyReceipt, s.adminToken, s.body("receipt", unknown))), `{"valid":false,"reason":"SIGNATURE_INVALID"}`)
	// History is newest first by decision time; decisions at the same instant have no defined order.
	s.advance(1_000)
	s.decide(s.aliceToken, "marketing-email", 2, true)
	expectJSON(t, "verify historical", s.ok(call(s.api.VerifyReceipt, s.adminToken, s.body("receipt", receipt))), `{"valid":true,"current":false}`)
	own := s.ok(call(s.api.MyReceipt, s.aliceToken, s.body("receiptId", receipt.Get("receiptId"))))
	expectJSON(t, "my receipt", own, stringify(receipt))
	_, err = call(s.api.MyReceipt, s.aliceToken, s.body("receiptId", "missing"))
	expectError(t, err, "NOT_FOUND", "Receipt not found")
	history := s.many(call(s.api.MyHistory, s.aliceToken, s.body("purposeKey", "marketing-email")))
	if len(history) != 2 || history[0].Get("purposeVersion") != 2.0 || history[1].Get("purposeVersion") != 1.0 || history[1].Get("evidence") != "Signup form v3" {
		t.Errorf("history = %s", stringify(pvList(history)))
	}
	expectJSON(t, "history entry members", history[1].Keys(), `["receiptId","purposeKey","purposeVersion","subject","granted","source","method","evidence","recordedAt","recordedBy"]`)
	if history[1].Get("method") != "self-service" {
		t.Errorf("default method = %v", history[1].Get("method"))
	}
}

func TestPrivacyGrantsLapseAfterTheConsentLifetime(t *testing.T) {
	s := newPrivacyScenario(t)
	cookies := s.ok(call(s.api.CreatePurpose, s.adminToken, s.body(
		"key", "cookies.ads", "name", "Advertising cookies", "description", "Cookies that measure ads.", "legalBasis", "consent", "consentLifetimeDays", 30.0)))
	if cookies.Get("consentLifetimeDays") != 30.0 {
		t.Errorf("cookies = %s", stringify(cookies))
	}
	receipt := s.decide(s.aliceToken, "cookies.ads", 1, true)
	if got := s.check(s.adminToken, s.aliceSubject(), "cookies.ads"); got.Get("allowed") != true {
		t.Errorf("check = %s", stringify(got))
	}
	consent := s.find("privacyConsents", core.NewObject("tenantId", s.tenantID, "purposeKey", "cookies.ads"))
	if len(consent) != 1 || consent[0].Get("expiresAt") != s.now()+30*pvDay || consent[0].Get("receiptId") != receipt.Get("receiptId") {
		t.Errorf("consent = %s", stringify(pvList(consent)))
	}
	s.advance(31 * pvDay)
	owner := s.token(s.admin)
	if got := s.check(owner, s.aliceSubject(), "cookies.ads"); got.Get("allowed") != false || got.Get("reason") != "CONSENT_EXPIRED" {
		t.Errorf("check after lifetime = %s", stringify(got))
	}
}

func TestPrivacyExposesConsentsToPolicies(t *testing.T) {
	s := newPrivacyScenario(t)
	reader := document(allowStatement("documents:read", "*", "conditions",
		core.NewObject("ArrayContains", core.NewObject("principal.consents", []any{"marketing-email"}))))
	s.seed("policies", core.NewObject("id", "policy-newsletter", "tenantId", s.tenantID, "name", "Newsletter reader", "document", reader, "version", 1.0, "authorityId", adminAuthority))
	s.seed("roles", core.NewObject("id", "role-newsletter", "tenantId", s.tenantID, "name", "Newsletter reader", "policyIds", []any{"policy-newsletter"}, "authorityId", adminAuthority))
	s.bind("binding-newsletter", "role-newsletter", "identity", s.aliceID, adminAuthority)
	canRead := func() bool {
		decision, err := s.iam.Authorize(context.Background(), AuthorizationRequest{
			Credential: core.CredentialInput{Token: s.aliceToken}, TenantID: s.tenantID, Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "d1"},
		})
		skipUnported(t, err)
		if err != nil {
			t.Fatal(err)
		}
		return decision.Allowed
	}
	if canRead() {
		t.Fatal("no consent, no access")
	}
	s.decide(s.aliceToken, "marketing-email", 1, true)
	if !canRead() {
		t.Fatal("the consent reaches policies")
	}
	s.decide(s.aliceToken, "marketing-email", 1, false)
	if canRead() {
		t.Fatal("withdrawing ends access")
	}
}

func TestPrivacyApplicationSubjectsRecordImportCheckAndList(t *testing.T) {
	s := newPrivacyScenario(t)
	recorded := s.ok(call(s.api.Record, s.adminToken, s.body("subject", core.NewObject("externalId", "cus_100"),
		"purposeKey", "marketing-email", "granted", true, "method", "banner", "ip", "203.0.113.9")))
	if recorded.Get("subject") != "external:cus_100" || recorded.Get("granted") != true || recorded.Get("current") != true {
		t.Errorf("recorded = %s", stringify(recorded))
	}
	if events := s.find("audit", core.NewObject("tenantId", s.tenantID, "action", "privacy:consent")); len(events) != 1 ||
		events[0].Get("resourceId") != "external:cus_100" || member(events[0].Get("metadata"), "externalId") != "cus_100" {
		t.Errorf("record audit = %s", stringify(pvList(events)))
	}
	_, err := call(s.api.Record, s.adminToken, s.body("subject", core.NewObject("externalId", "cus_1"), "purposeKey", "marketing-email", "granted", true, "recordedAt", s.now()-pvDay))
	expectError(t, err, "INVALID_INPUT", "recordedAt is accepted for imports only")
	// An older imported decision is kept in the history but does not replace the newer one.
	imported := s.ok(call(s.api.ImportDecisions, s.adminToken, s.body("decisions", []any{
		core.NewObject("subject", core.NewObject("externalId", "cus_100"), "purposeKey", "marketing-email", "granted", false, "version", 1.0, "recordedAt", s.now()-10*pvDay),
		core.NewObject("subject", core.NewObject("externalId", "cus_200"), "purposeKey", "marketing-email", "granted", false, "version", 1.0, "recordedAt", s.now()-pvDay),
	})))
	expectJSON(t, "imported", imported, `{"imported":2,"current":1}`)
	if events := s.find("audit", core.NewObject("tenantId", s.tenantID, "action", "privacy:consent-import")); len(events) != 1 ||
		stringify(events[0].Get("metadata")) != `{"count":2,"current":1,"purposes":["marketing-email"]}` {
		t.Errorf("import audit = %s", stringify(pvList(events)))
	}
	_, err = call(s.api.ImportDecisions, s.adminToken, s.body("decisions", []any{}))
	expectError(t, err, "INVALID_INPUT", "Provide 1-500 decisions")
	_, err = call(s.api.ImportDecisions, s.adminToken, s.body("decisions", []any{
		core.NewObject("subject", core.NewObject("externalId", "cus_9"), "purposeKey", "marketing-email", "granted", true, "recordedAt", s.now()),
	}))
	expectError(t, err, "INVALID_INPUT", "Each imported decision must state its purpose version")

	filtered := s.ok(call(s.api.FilterSubjects, s.adminToken, s.body("purposeKey", "marketing-email", "subjects", []any{
		core.NewObject("externalId", "cus_100"),
		core.NewObject("externalId", "cus_200"),
		core.NewObject("externalId", "cus_300"),
		core.NewObject("identityId", "missing"),
	})))
	expectJSON(t, "allowed", filtered.Get("allowed"), `[{"externalId":"cus_100"}]`)
	var reasons []string
	for _, item := range filtered.Get("refused").([]any) {
		reasons = append(reasons, jsString(member(item, "reason")))
	}
	if strings.Join(reasons, ",") != "CONSENT_WITHDRAWN,NO_CONSENT,UNKNOWN_SUBJECT" {
		t.Errorf("refused = %s", stringify(filtered.Get("refused")))
	}
	// The opt-out purpose's audience is every active person until they opt out.
	people := 0
	for _, identity := range s.find("identities", core.NewObject("tenantId", s.tenantID)) {
		if identity.Get("kind") == "user" && identity.Get("status") == "active" {
			people++
		}
	}
	audience := s.ok(call(s.api.Audience, s.adminToken, s.body("purposeKey", "data-sharing")))
	if audience.Get("total") != float64(people) || audience.Get("purposeKey") != "data-sharing" {
		t.Errorf("audience = %s (people %d)", stringify(audience), people)
	}
	paged := s.ok(call(s.api.Audience, s.adminToken, s.body("purposeKey", "data-sharing", "limit", 1.0, "offset", 1.0)))
	if len(paged.Get("subjects").([]any)) != min(1, people-1) {
		t.Errorf("paged audience = %s", stringify(paged))
	}
	consents := s.ok(call(s.api.ListConsents, s.adminToken, s.body("purposeKey", "marketing-email")))
	if consents.Get("total") != 2.0 {
		t.Errorf("consents = %s", stringify(consents))
	}
	granted := s.ok(call(s.api.ListConsents, s.adminToken, s.body("purposeKey", "marketing-email", "granted", true)))
	if granted.Get("total") != 1.0 || member(granted.Get("consents").([]any)[0], "subject") != "external:cus_100" {
		t.Errorf("granted consents = %s", stringify(granted))
	}
	history := s.many(call(s.api.History, s.adminToken, s.body("subject", core.NewObject("externalId", "cus_100"))))
	if len(history) != 2 || history[0].Get("granted") != true || history[0].Get("ip") != "203.0.113.9" || history[0].Get("method") != "banner" {
		t.Errorf("history = %s", stringify(pvList(history)))
	}
	// The deployment's own code can check without a credential.
	checked, err := s.iam.Privacy.Check(context.Background(), s.body("subject", core.NewObject("externalId", "cus_100"), "purposeKey", "marketing-email"))
	skipUnported(t, err)
	if err != nil || checked.Get("allowed") != true {
		t.Errorf("runtime check = %s %v", stringify(checked), err)
	}
	summary := s.ok(call(s.api.Summary, s.adminToken, s.body()))
	for _, item := range summary.Get("purposes").([]any) {
		purpose := item.(*core.Object)
		if purpose.Get("key") == "marketing-email" && (purpose.Get("granted") != 1.0 || purpose.Get("withdrawn") != 1.0) {
			t.Errorf("summary purpose = %s", stringify(purpose))
		}
	}
	// The application records what it captured itself, attributed to `application`.
	receipt, err := s.iam.Privacy.Record(context.Background(), s.body("subject", core.NewObject("externalId", "cus_300"), "purposeKey", "marketing-email", "granted", true, "userAgent", "Banner/1"))
	skipUnported(t, err)
	if err != nil || receipt.Get("source") != "api" {
		t.Fatalf("runtime record = %s %v", stringify(receipt), err)
	}
	events := s.find("privacyConsentEvents", core.NewObject("tenantId", s.tenantID, "receiptId", receipt.Get("receiptId")))
	if len(events) != 1 || events[0].Get("recordedBy") != "application" || events[0].Get("userAgent") != "Banner/1" {
		t.Errorf("runtime event = %s", stringify(pvList(events)))
	}
}

func TestPrivacyAccessRequestExportOnlyTheSubjectOrAHandlerDownloads(t *testing.T) {
	s := newPrivacyScenario(t)
	s.decide(s.aliceToken, "marketing-email", 1, true)
	settings := s.ok(call(s.api.UpdateSettings, s.adminToken, s.body("contactEmail", "dpo@acme.test", "responseDays", core.NewObject("gdpr", 20.0))))
	if settings.Get("contactEmail") != "dpo@acme.test" || stringify(settings.Get("responseDays")) != `{"gdpr":20}` ||
		stringify(member(settings.Get("statutory"), "lgpd")) != `{"responseDays":15,"extensionDays":0}` {
		t.Errorf("settings = %s", stringify(settings))
	}
	_, err := call(s.api.UpdateSettings, s.adminToken, s.body("responseDays", core.NewObject("gdpr", 31.0)))
	expectError(t, err, "INVALID_INPUT", "Invalid responseDays.gdpr")
	request := s.submit(s.aliceToken, "type", "access")
	if request.Get("status") != "open" || request.Get("regulation") != "gdpr" ||
		member(request.Get("verification"), "status") != "verified" || member(request.Get("verification"), "method") != "authenticated-session" {
		t.Errorf("request = %s", stringify(request))
	}
	if jsNumber(request.Get("dueAt"))-jsNumber(request.Get("receivedAt")) != 20*pvDay {
		t.Errorf("window = %s", stringify(request))
	}
	requestID := jsString(request.Get("id"))
	_, err = call(s.api.SubmitRequest, s.aliceToken, s.body("type", "access"))
	expectError(t, err, "CONFLICT", "You already have an open request of this type")
	s.dispatch()
	if received := s.messages("privacy-request-received"); len(received) != 1 || received[0].To != "dpo@acme.test" {
		t.Errorf("received = %+v", received)
	}

	done := s.ok(s.fulfil(s.adminToken, requestID))
	if done.Get("status") != "completed" || stringify(done.Get("actions")) != `["export:full"]` || !truthy(done.Get("exportId")) {
		t.Errorf("done = %s", stringify(done))
	}
	download := s.ok(call(s.api.DownloadExport, s.aliceToken, s.body("requestId", requestID)))
	data := download.Get("data").(*core.Object)
	if member(data.Get("profile"), "email") != "alice@acme.test" || member(data.Get("profile"), "passwordHash") != core.Undefined {
		t.Errorf("profile = %s", stringify(data.Get("profile")))
	}
	consents := data.Get("consents").([]any)
	if len(consents) != 1 || member(consents[0], "purpose") != "marketing-email" || member(consents[0], "granted") != true {
		t.Errorf("export consents = %s", stringify(data.Get("consents")))
	}
	if data.Get("format") != "better-iam.privacy-export" || data.Get("scope") != "full" || !truthy(data.Get("activity")) || download.Get("sha256") != Hash(core.CanonicalJSON(data)) {
		t.Errorf("export = %s", stringify(download))
	}
	if exports := s.find("privacyExports", core.NewObject("tenantId", s.tenantID)); len(exports) != 1 || exports[0].Get("downloads") != 1.0 {
		t.Errorf("exports = %s", stringify(pvList(exports)))
	}
	// Another member cannot download it.
	bob := s.person("bob")
	_, err = call(s.api.DownloadExport, s.token(bob), s.body("requestId", requestID))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	// The subject hears back; staff notes stay internal.
	s.dispatch()
	var update *core.Object
	for _, message := range s.messages("privacy-request-update") {
		if message.To == "alice@acme.test" {
			update = core.NewObject()
			for key, value := range message.Payload {
				update.Set(key, value)
			}
		}
	}
	if update == nil || update.Get("event") != "completed" || update.Get("exportReady") != "true" || update.Get("account") != "true" {
		t.Errorf("update = %s", stringify(update))
	}
	// Downloads are audited by who downloaded.
	if events := s.find("audit", core.NewObject("tenantId", s.tenantID, "action", "privacy:export:download")); len(events) != 1 || member(events[0].Get("metadata"), "by") != "subject" {
		t.Errorf("download audit = %s", stringify(pvList(events)))
	}
	// The export lapses after the export lifetime.
	s.advance(15 * pvDay)
	_, err = call(s.api.DownloadExport, s.token(s.alice), s.body("requestId", requestID))
	expectError(t, err, "NOT_FOUND", "The export has expired; file a new request")
}

func TestPrivacyErasesAPersonAfterTheLegalHoldIsReleased(t *testing.T) {
	s := newPrivacyScenario(t)
	s.decide(s.aliceToken, "marketing-email", 1, true, "evidence", "Signed up at the conference booth")
	hold := s.ok(call(s.api.PlaceHold, s.adminToken, s.body("subject", s.aliceSubject(), "reason", "Litigation 2026-17")))
	expectJSON(t, "hold members", hold.Keys(), `["id","tenantId","subject","identityId","reason","placedBy","placedAt"]`)
	holds := s.many(call(s.api.ListHolds, s.adminToken, s.body()))
	if len(holds) != 1 || holds[0].Get("active") != true {
		t.Errorf("holds = %s", stringify(pvList(holds)))
	}
	// No path deletes a held person.
	_, err := call(s.iam.API.Identities.Delete, s.adminToken, s.body("identityId", s.aliceID))
	s.refused(err, "LEGAL_HOLD")
	request := s.submit(s.aliceToken, "type", "erasure", "details", "Please delete my account.")
	requestID := jsString(request.Get("id"))
	_, err = s.fulfil(s.adminToken, requestID)
	expectError(t, err, "LEGAL_HOLD", "This subject is under a legal hold; release it or reject the request as exempt")
	if got := s.ok(call(s.api.GetRequest, s.adminToken, s.body("requestId", requestID))); got.Get("legalHold") != true || got.Get("restricted") != false || got.Get("subjectName") != "alice@acme.test" {
		t.Errorf("get request = %s", stringify(got))
	}
	expectJSON(t, "released", s.ok(call(s.api.ReleaseHold, s.adminToken, s.body("holdId", hold.Get("id")))), `{"released":true}`)
	done := s.ok(s.fulfil(s.adminToken, requestID))
	actions := stringify(done.Get("actions"))
	if done.Get("status") != "completed" || !strings.Contains(actions, `"account-deleted"`) || !strings.Contains(actions, `"account-details-erased"`) || !strings.Contains(actions, `"history-redacted:1"`) {
		t.Errorf("done = %s", stringify(done))
	}
	if done.Has("details") || done.Get("redacted") != true {
		t.Errorf("done redaction = %s", stringify(done))
	}
	tombstone, err := s.iam.Store.Get(context.Background(), "identities", s.aliceID)
	if err != nil || tombstone.Get("status") != "deleted" || tombstone.Get("name") != "Erased person" || tombstone.Has("deletedEmail") {
		t.Errorf("tombstone = %s %v", stringify(tombstone), err)
	}
	history := s.many(call(s.api.History, s.adminToken, s.body("subject", s.aliceSubject())))
	if len(history) != 1 || history[0].Get("redacted") != true || history[0].Has("evidence") {
		t.Errorf("history = %s", stringify(pvList(history)))
	}
	if events := s.find("audit", core.NewObject("tenantId", s.tenantID, "action", "privacy:erasure")); len(events) != 1 ||
		events[0].Get("resourceId") != s.aliceID || stringify(events[0].Get("metadata")) != `{"requestId":"`+requestID+`","subjectKind":"account"}` {
		t.Errorf("erasure audit = %s", stringify(pvList(events)))
	}
	// The person heard back at their old address before it was erased.
	s.dispatch()
	heard := false
	for _, message := range s.messages("privacy-request-update") {
		if message.To == "alice@acme.test" && message.Payload["type"] == "erasure" {
			heard = true
		}
	}
	if !heard {
		t.Error("the erased person was told at their old address")
	}
}

func TestPrivacyRestrictsWithdrawsOnObjectionAndExtendsByRegulation(t *testing.T) {
	s := newPrivacyScenario(t)
	s.decide(s.aliceToken, "marketing-email", 1, true)
	restriction := s.submit(s.aliceToken, "type", "restriction")
	s.ok(s.fulfil(s.adminToken, jsString(restriction.Get("id"))))
	if got := s.check(s.adminToken, s.aliceSubject(), "marketing-email"); got.Get("allowed") != false || got.Get("reason") != "RESTRICTED" {
		t.Errorf("marketing = %s", stringify(got))
	}
	if got := s.check(s.adminToken, s.aliceSubject(), "billing"); got.Get("allowed") != false || got.Get("reason") != "RESTRICTED" {
		t.Errorf("billing = %s", stringify(got))
	}
	if restrictions := s.many(call(s.api.ListRestrictions, s.adminToken, s.body())); len(restrictions) != 1 || restrictions[0].Get("identityId") != s.aliceID {
		t.Errorf("restrictions = %s", stringify(pvList(restrictions)))
	}
	expectJSON(t, "lifted", s.ok(call(s.api.LiftRestriction, s.adminToken, s.body("subject", s.aliceSubject()))), `{"lifted":true}`)
	_, err := call(s.api.LiftRestriction, s.adminToken, s.body("subject", s.aliceSubject()))
	expectError(t, err, "NOT_FOUND", "No restriction for this subject")
	if got := s.check(s.adminToken, s.aliceSubject(), "marketing-email"); got.Get("allowed") != true {
		t.Errorf("marketing after lift = %s", stringify(got))
	}

	objection := s.submit(s.aliceToken, "type", "objection", "regulation", "lgpd")
	// LGPD allows no extension; GDPR adds two months once.
	_, err = call(s.api.ExtendRequest, s.adminToken, s.body("requestId", objection.Get("id"), "reason", "Complex"))
	expectError(t, err, "CONFLICT", "lgpd allows no extension")
	done := s.ok(s.fulfil(s.adminToken, jsString(objection.Get("id"))))
	expectJSON(t, "objection actions", done.Get("actions"), `["consents-withdrawn:3"]`)
	if got := s.check(s.adminToken, s.aliceSubject(), "marketing-email"); got.Get("reason") != "CONSENT_WITHDRAWN" {
		t.Errorf("marketing after objection = %s", stringify(got))
	}
	if got := s.check(s.adminToken, s.aliceSubject(), "product-analytics"); got.Get("reason") != "OBJECTED" {
		t.Errorf("analytics after objection = %s", stringify(got))
	}
	if got := s.check(s.adminToken, s.aliceSubject(), "billing"); got.Get("allowed") != true {
		t.Errorf("billing after objection = %s", stringify(got))
	}

	access := s.submit(s.aliceToken, "type", "portability")
	extended := s.ok(call(s.api.ExtendRequest, s.adminToken, s.body("requestId", access.Get("id"), "reason", "Data spread over several systems")))
	if jsNumber(extended.Get("dueAt"))-jsNumber(access.Get("dueAt")) != 60*pvDay || extended.Get("extensionReason") != "Data spread over several systems" {
		t.Errorf("extended = %s", stringify(extended))
	}
	_, err = call(s.api.ExtendRequest, s.adminToken, s.body("requestId", access.Get("id"), "reason", "Again"))
	expectError(t, err, "CONFLICT", "This request was already extended")
	// Rectification needs a note saying what changed.
	fix := s.submit(s.aliceToken, "type", "rectification", "details", "My name is spelled wrong.")
	noted := s.ok(call(s.api.AddNote, s.adminToken, s.body("requestId", fix.Get("id"), "note", "internal")))
	if events := noted.Get("events").([]any); member(events[len(events)-1], "what") != "note" {
		t.Errorf("noted = %s", stringify(noted))
	}
	_, err = s.fulfil(s.adminToken, jsString(fix.Get("id")))
	expectError(t, err, "INVALID_INPUT", "Describe what was corrected in the note")
	assigned := s.ok(call(s.api.AssignRequest, s.adminToken, s.body("requestId", fix.Get("id"), "assigneeId", s.adminID)))
	if assigned.Get("assigneeId") != s.adminID {
		t.Errorf("assigned = %s", stringify(assigned))
	}
	mine := s.ok(call(s.api.Mine, s.aliceToken, s.body()))
	for _, item := range mine.Get("requests").([]any) {
		view := item.(*core.Object)
		if view.Get("id") != fix.Get("id") {
			continue
		}
		if view.Has("assigneeId") {
			t.Errorf("the subject's view keeps the assignment internal: %s", stringify(view))
		}
		for _, event := range view.Get("events").([]any) {
			if what := member(event, "what"); what == "note" || what == "assigned" || member(event, "by") != "organization" {
				t.Errorf("the subject's view keeps staff notes internal: %s", stringify(view.Get("events")))
			}
		}
	}
	unassigned := s.ok(call(s.api.AssignRequest, s.adminToken, s.body("requestId", fix.Get("id"), "assigneeId", nil)))
	if unassigned.Has("assigneeId") {
		t.Errorf("unassigned = %s", stringify(unassigned))
	}
	rectified := s.ok(s.fulfil(s.adminToken, jsString(fix.Get("id")), "note", "Name corrected"))
	if stringify(rectified.Get("actions")) != `["rectified"]` {
		t.Errorf("rectified = %s", stringify(rectified))
	}
	// Cancelling a closed request is refused; an open one can be withdrawn.
	_, err = call(s.api.CancelMyRequest, s.aliceToken, s.body("requestId", fix.Get("id")))
	expectError(t, err, "INVALID_TRANSITION", "This request is already closed")
	cancelled := s.ok(call(s.api.CancelMyRequest, s.aliceToken, s.body("requestId", access.Get("id"))))
	if cancelled.Get("status") != "cancelled" {
		t.Errorf("cancelled = %s", stringify(cancelled))
	}
}

func TestPrivacyPublicRequestsConfirmedByEmailAndLapsing(t *testing.T) {
	s := newPrivacyScenario(t)
	_, err := call0(s.api.SubmitPublic, s.body("type", "access", "email", "alice@acme.test"))
	expectError(t, err, "NOT_FOUND", "Not found")
	s.ok(call(s.api.UpdateSettings, s.adminToken, s.body("publicIntake", true, "contactEmail", "dpo@acme.test")))
	submitted := s.ok(call0(s.api.SubmitPublic, s.body("type", "access", "email", "Alice@Acme.test", "name", "Alice")))
	if submitted.Get("status") != "pending-verification" || !strings.HasPrefix(jsString(submitted.Get("number")), "DSR-") {
		t.Errorf("submitted = %s", stringify(submitted))
	}
	s.dispatch()
	verifications := s.messages("privacy-request-verify")
	if len(verifications) != 1 || verifications[0].To != "alice@acme.test" {
		t.Fatalf("verify = %+v", verifications)
	}
	requestID, token := verifications[0].Payload["requestId"], verifications[0].Payload["token"]
	_, err = call0(s.api.ConfirmPublic, s.body("requestId", requestID, "token", "wrong"))
	expectError(t, err, "CONFIRMATION_INVALID", "This confirmation link is invalid or has expired")
	confirmed := s.ok(call0(s.api.ConfirmPublic, s.body("requestId", requestID, "token", token)))
	if confirmed.Get("status") != "open" || !truthy(confirmed.Get("dueAt")) {
		t.Errorf("confirmed = %s", stringify(confirmed))
	}
	listed := s.ok(call(s.api.GetRequest, s.adminToken, s.body("requestId", requestID)))
	if listed.Get("identityId") != s.aliceID || listed.Get("subject") != "identity:"+s.aliceID || listed.Get("channel") != "public" ||
		member(listed.Get("verification"), "status") != "verified" || member(listed.Get("verification"), "method") != "email-link" || listed.Has("tokenHash") {
		t.Errorf("listed = %s", stringify(listed))
	}
	// The token is single-use.
	_, err = call0(s.api.ConfirmPublic, s.body("requestId", requestID, "token", token))
	expectError(t, err, "CONFIRMATION_INVALID", "This confirmation link is invalid or has expired")
	if events := s.find("audit", core.NewObject("tenantId", s.tenantID, "action", "privacy:request:verify")); len(events) != 1 ||
		events[0].Get("actorId") != "public-intake" || stringify(events[0].Get("metadata")) != `{"number":"`+jsString(submitted.Get("number"))+`","method":"email-link","linked":true}` {
		t.Errorf("verify audit = %s", stringify(pvList(events)))
	}

	// An unconfirmed request lapses after seven days.
	s.ok(call0(s.api.SubmitPublic, s.body("type", "opt-out", "email", "stranger@example.test")))
	s.advance(8 * pvDay)
	run, err := s.iam.Privacy.SendDeadlineReminders(context.Background(), s.body())
	skipUnported(t, err)
	if err != nil || run.Get("lapsed") != 1.0 {
		t.Fatalf("run = %s %v", stringify(run), err)
	}
	owner := s.token(s.admin)
	cancelled := s.ok(call(s.api.ListRequests, owner, s.body("status", "cancelled")))
	if cancelled.Get("total") != 1.0 || member(cancelled.Get("requests").([]any)[0], "closedBy") != "deployment-operator" {
		t.Errorf("cancelled = %s", stringify(cancelled))
	}
}

func TestPrivacyRemindsHandlersBeforeTheDeadlineAndWhenOverdue(t *testing.T) {
	s := newPrivacyScenario(t)
	s.ok(call(s.api.UpdateSettings, s.adminToken, s.body("contactEmail", "dpo@acme.test")))
	request := s.submit(s.aliceToken, "type", "access")
	requestID := jsString(request.Get("id"))
	job := func() *core.Object {
		t.Helper()
		run, err := s.iam.Privacy.SendDeadlineReminders(context.Background(), s.body())
		skipUnported(t, err)
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	expectJSON(t, "none due", job().Get("reminded"), `[]`)
	s.advance(24 * pvDay)
	expectJSON(t, "due soon", job().Get("reminded"), `[{"tenantId":"`+s.tenantID+`","requestId":"`+requestID+`","kind":"due-soon"}]`)
	expectJSON(t, "once", job().Get("reminded"), `[]`)
	s.advance(7 * pvDay)
	expectJSON(t, "overdue", job().Get("reminded"), `[{"tenantId":"`+s.tenantID+`","requestId":"`+requestID+`","kind":"overdue"}]`)
	owner := s.token(s.admin)
	overdue := s.ok(call(s.api.ListRequests, owner, s.body("overdue", true)))
	if requests := overdue.Get("requests").([]any); len(requests) != 1 || member(requests[0], "id") != requestID || member(requests[0], "overdue") != true {
		t.Errorf("overdue = %s", stringify(overdue))
	}
	summary := s.ok(call(s.api.Summary, owner, s.body()))
	if queue := summary.Get("requests").(*core.Object); queue.Get("open") != 1.0 || queue.Get("overdue") != 1.0 || member(queue.Get("byType"), "access") != 1.0 {
		t.Errorf("summary = %s", stringify(summary))
	}
	s.dispatch()
	var flags []string
	for _, message := range s.messages("privacy-request-due") {
		flags = append(flags, message.Payload["overdue"])
	}
	if strings.Join(flags, ",") != "false,true" {
		t.Errorf("due messages = %v", flags)
	}
	if events := s.find("audit", core.NewObject("tenantId", s.tenantID, "action", "privacy:request:overdue")); len(events) != 1 || events[0].Get("actorId") != "deployment-operator" {
		t.Errorf("overdue audit = %s", stringify(pvList(events)))
	}
}

// privacyHandler seeds bob, who handles privacy requests but may not read the directory or the audit log.
func (s *privacyScenario) privacyHandler() (*core.Object, string) {
	s.t.Helper()
	bob := s.person("bob")
	s.role("role-privacy-handler", "Privacy handler", false, "iam:privacy:read", "iam:privacy:handle")
	s.bind("binding-privacy-handler", "role-privacy-handler", "identity", jsString(bob.Get("id")), adminAuthority)
	return bob, s.token(bob)
}

func TestPrivacyPublicRequestsNamingAnIdentifierStayUnverified(t *testing.T) {
	s := newPrivacyScenario(t)
	s.ok(call(s.api.UpdateSettings, s.adminToken, s.body("publicIntake", true)))
	s.ok(call0(s.api.SubmitPublic, s.body("type", "erasure", "email", "attacker@example.test", "externalId", "cus_42")))
	s.dispatch()
	verify := s.messages("privacy-request-verify")
	if len(verify) != 1 {
		t.Fatalf("verify = %+v", verify)
	}
	requestID := verify[0].Payload["requestId"]
	confirmed := s.ok(call0(s.api.ConfirmPublic, s.body("requestId", requestID, "token", verify[0].Payload["token"])))
	if confirmed.Get("status") != "pending-verification" {
		t.Errorf("confirmed = %s", stringify(confirmed))
	}
	_, err := s.fulfil(s.adminToken, requestID)
	expectError(t, err, "INVALID_TRANSITION", "Verify who is asking before fulfilling the request")
	// A confirmed address does not lapse as unconfirmed.
	s.advance(8 * pvDay)
	run, err := s.iam.Privacy.SendDeadlineReminders(context.Background(), s.body())
	skipUnported(t, err)
	if err != nil || run.Get("lapsed") != 0.0 {
		t.Errorf("run = %s %v", stringify(run), err)
	}
}

func TestPrivacyErasedApplicationSubjectStaysSuppressed(t *testing.T) {
	s := newPrivacyScenario(t)
	s.ok(call(s.api.Record, s.adminToken, s.body("subject", core.NewObject("externalId", "cus_7"), "purposeKey", "data-sharing", "granted", false)))
	request := s.ok(call(s.api.CreateRequest, s.adminToken, s.body("type", "erasure", "subject", core.NewObject("externalId", "cus_7"),
		"verified", core.NewObject("method", "Signed-in customer portal"))))
	if request.Get("status") != "open" || request.Get("externalId") != "cus_7" || request.Get("channel") != "staff" ||
		member(request.Get("verification"), "verifiedBy") != s.adminID {
		t.Errorf("request = %s", stringify(request))
	}
	done := s.ok(s.fulfil(s.adminToken, jsString(request.Get("id"))))
	expectJSON(t, "erasure actions", done.Get("actions"), `["consents-deleted:1","history-redacted:1"]`)
	got := s.check(s.adminToken, core.NewObject("externalId", "cus_7"), "data-sharing")
	if got.Get("allowed") != false || got.Get("reason") != "ERASED" {
		t.Errorf("check = %s", stringify(got))
	}
}

func TestPrivacyHandlersNeedDirectoryRightsAndRefusalsAreAudited(t *testing.T) {
	s := newPrivacyScenario(t)
	_, token := s.privacyHandler()
	request := s.submit(s.aliceToken, "type", "access")
	requestID := jsString(request.Get("id"))
	// Bob may handle requests but not read Alice's account.
	_, err := s.fulfil(token, requestID)
	s.refused(err, "ACCESS_DENIED")
	s.ok(s.fulfil(s.adminToken, requestID))
	_, err = call(s.api.DownloadExport, token, s.body("requestId", requestID))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	denied := false
	for _, event := range s.find("audit", core.NewObject("tenantId", s.tenantID, "action", "iam:identities:read")) {
		if event.Get("outcome") == "deny" {
			denied = true
		}
	}
	if !denied {
		t.Error("the refused directory read is audited")
	}
	// Audiences list people by ID only without directory rights.
	audience := s.ok(call(s.api.Audience, token, s.body("purposeKey", "data-sharing")))
	subjects := audience.Get("subjects").([]any)
	if len(subjects) == 0 {
		t.Fatal("audience lists people")
	}
	for _, subject := range subjects {
		if member(subject, "email") != core.Undefined || member(subject, "name") != core.Undefined {
			t.Errorf("audience without directory rights = %s", stringify(audience))
		}
	}
}

func TestPrivacyExportsLeaveActivityOutWithoutAuditRights(t *testing.T) {
	s := newPrivacyScenario(t)
	bob, token := s.privacyHandler()
	// Bob may also read people, but still not the audit log.
	s.role("role-directory-reader", "Directory reader", false, "iam:identities:read")
	s.bind("binding-directory-reader", "role-directory-reader", "identity", jsString(bob.Get("id")), adminAuthority)
	request := s.submit(s.aliceToken, "type", "access")
	token = s.signIn(bob, true)
	s.ok(s.fulfil(token, jsString(request.Get("id"))))
	download := s.ok(call(s.api.DownloadExport, s.aliceToken, s.body("requestId", request.Get("id"))))
	data := download.Get("data").(*core.Object)
	if data.Has("activity") || data.Get("activityOmitted") != true {
		t.Errorf("export activity = %s", stringify(data))
	}
}

func TestPrivacyEmailRequestsNeedALinkedSubject(t *testing.T) {
	s := newPrivacyScenario(t)
	request := s.ok(call(s.api.CreateRequest, s.adminToken, s.body("type", "erasure", "requesterEmail", "alice.personal@example.test")))
	if request.Get("status") != "pending-verification" || !strings.HasPrefix(jsString(request.Get("subject")), "email:") {
		t.Errorf("request = %s", stringify(request))
	}
	requestID := jsString(request.Get("id"))
	_, err := call(s.api.CreateRequest, s.adminToken, s.body("type", "erasure"))
	expectError(t, err, "INVALID_INPUT", "Name the subject or the requester’s email")
	verified := s.ok(call(s.api.VerifyRequest, s.adminToken, s.body("requestId", requestID, "method", "Video call")))
	if verified.Get("status") != "open" || member(verified.Get("verification"), "method") != "Video call" {
		t.Errorf("verified = %s", stringify(verified))
	}
	_, err = call(s.api.VerifyRequest, s.adminToken, s.body("requestId", requestID, "method", "Again"))
	expectError(t, err, "INVALID_TRANSITION", "Only unverified requests can be verified")
	_, err = s.fulfil(s.adminToken, requestID)
	expectError(t, err, "INVALID_INPUT", "Link the request to an account or an application subject (linkRequest), or decline it as no-data")
	linked := s.ok(call(s.api.LinkRequest, s.adminToken, s.body("requestId", requestID, "subject", s.aliceSubject(), "note", "Same person, second address")))
	if linked.Get("identityId") != s.aliceID || linked.Get("subject") != "identity:"+s.aliceID {
		t.Errorf("linked = %s", stringify(linked))
	}
	_, err = call(s.api.LinkRequest, s.adminToken, s.body("requestId", requestID, "subject", s.aliceSubject()))
	expectError(t, err, "CONFLICT", "This request is already linked to its subject")
	s.ok(s.fulfil(s.adminToken, requestID))
	var deletion *core.Object
	for _, event := range s.find("audit", core.NewObject("tenantId", s.tenantID, "action", "identity:delete")) {
		if event.Get("resourceId") == s.aliceID {
			deletion = event
		}
	}
	if deletion == nil || stringify(deletion.Get("metadata")) != `{"kind":"user","erasure":true}` {
		t.Errorf("identity:delete = %s", stringify(deletion))
	}
	// Another email-only request can be declined as holding no data.
	other := s.ok(call(s.api.CreateRequest, s.adminToken, s.body("type", "access", "requesterEmail", "stranger@example.test")))
	rejected := s.ok(call(s.api.RejectRequest, s.adminToken, s.body("requestId", other.Get("id"), "reason", "no-data")))
	if rejected.Get("status") != "rejected" || rejected.Get("rejectionReason") != "no-data" {
		t.Errorf("rejected = %s", stringify(rejected))
	}
	listed := s.ok(call(s.api.ListRequests, s.adminToken, s.body()))
	if listed.Get("total") != 2.0 {
		t.Errorf("listed = %s", stringify(listed))
	}
}

func TestPrivacyImportsNeedVersionsAndModeChangesANewVersion(t *testing.T) {
	s := newPrivacyScenario(t)
	_, err := call(s.api.Record, s.adminToken, s.body("subject", core.NewObject("externalId", "cus_1"), "purposeKey", "marketing-email",
		"granted", true, "source", "import", "recordedAt", s.now()-pvDay))
	expectError(t, err, "INVALID_INPUT", "Imports must state the purpose version decided on")
	_, err = call(s.api.UpdatePurpose, s.adminToken, s.body("purposeId", s.marketing.Get("id"), "mode", "opt-out"))
	expectError(t, err, "INVALID_INPUT", "Changing the legal basis or consent mode is a material change: publish it with newVersion")
	changed := s.ok(call(s.api.UpdatePurpose, s.adminToken, s.body("purposeId", s.marketing.Get("id"), "mode", "opt-out", "newVersion", true)))
	if changed.Get("mode") != "opt-out" || changed.Get("version") != 2.0 {
		t.Errorf("changed = %s", stringify(changed))
	}
	// Decided purposes are archived rather than deleted.
	s.decide(s.aliceToken, "marketing-email", 2, false)
	_, err = call(s.api.DeletePurpose, s.adminToken, s.body("purposeId", s.marketing.Get("id")))
	expectError(t, err, "RESOURCE_IN_USE", "Decisions are recorded for this purpose; archive it instead so the proof is kept")
	archived := s.ok(call(s.api.UpdatePurpose, s.adminToken, s.body("purposeId", s.marketing.Get("id"), "archived", true, "retentionDays", 365.0)))
	if archived.Get("archived") != true || archived.Get("retentionDays") != 365.0 {
		t.Errorf("archived = %s", stringify(archived))
	}
	_, err = call(s.api.Decide, s.aliceToken, s.body("purposeKey", "marketing-email", "version", 2.0, "granted", true))
	expectError(t, err, "CONFLICT", "Purpose marketing-email is archived")
}

// call0 runs a public API method (no credential) with a body.
func call0[T, O any](method func(context.Context, In[T]) (Out[O], error), body *core.Object) (any, error) {
	out, err := method(context.Background(), Input[T](body))
	return out.Value, err
}
