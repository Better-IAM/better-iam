package server

// Tests of privacy.go (packages/server/src/privacy.ts): the processing decision of every legal basis, consent
// receipts (byte-compatible with the TypeScript signatures), subject resolution, request numbers and deadlines,
// validators, legal holds on people and organizations, and `principal.consents` in policies. These are the module
// behaviors tests/privacy.test.ts asserts through the privacy API (ported in api_privacy.go), checked here at the
// module level and through the identities and tenants APIs that call into it.

import (
	"context"
	"regexp"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const privacyDay = int64(86_400_000)

// privacyInsert writes records in a transaction.
func privacyInsert(t *testing.T, store core.IamStore, collection string, records ...*core.Object) {
	t.Helper()
	err := store.Transaction(context.Background(), func(ctx context.Context, tx core.IamStore) error {
		for _, record := range records {
			if _, err := tx.Insert(ctx, collection, record); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func privacyReason(t *testing.T, purpose, consent *core.Object, restricted any, now int64) string {
	t.Helper()
	state := must(ConsentState(purpose, consent, restricted, now))
	reason := jsString(state.Get("reason"))
	allowed := state.Get("allowed") == true
	switch reason {
	case "CONSENT_GIVEN", "NOT_OPTED_OUT", "LEGITIMATE_INTERESTS", "LEGAL_BASIS":
		if !allowed {
			t.Errorf("%s should be allowed", reason)
		}
	default:
		if allowed {
			t.Errorf("%s should be refused", reason)
		}
	}
	return reason
}

func TestPrivacyConsentStateCoversEveryBasis(t *testing.T) {
	now := int64(1_767_272_400_000)
	marketing := obj(t, `{"id":"p1","key":"marketing-email","legalBasis":"consent","mode":"opt-in","version":1,"reconsentOnVersion":true,"archived":false}`)
	analytics := obj(t, `{"id":"p2","key":"product-analytics","legalBasis":"legitimate-interests","mode":"opt-out","version":1,"reconsentOnVersion":true,"archived":false}`)
	sale := obj(t, `{"id":"p3","key":"data-sharing","legalBasis":"consent","mode":"opt-out","version":1,"reconsentOnVersion":true,"archived":false}`)
	billing := obj(t, `{"id":"p4","key":"billing","legalBasis":"contract","mode":"opt-in","version":1,"reconsentOnVersion":true,"archived":false}`)
	legal := obj(t, `{"id":"p5","key":"tax","legalBasis":"legal-obligation","mode":"opt-in","version":1,"reconsentOnVersion":true,"archived":false}`)
	granted := obj(t, `{"purposeId":"p1","granted":true,"purposeVersion":1}`)
	withdrawn := obj(t, `{"purposeId":"p1","granted":false,"purposeVersion":1}`)

	cases := []struct {
		name       string
		purpose    *core.Object
		consent    *core.Object
		restricted any
		want       string
	}{
		{"opt-in without a record", marketing, nil, false, "NO_CONSENT"},
		{"opt-in granted", marketing, granted, false, "CONSENT_GIVEN"},
		{"opt-in withdrawn", marketing, withdrawn, false, "CONSENT_WITHDRAWN"},
		{"legitimate interests without a record", analytics, nil, false, "LEGITIMATE_INTERESTS"},
		{"legitimate interests objected", analytics, withdrawn, false, "OBJECTED"},
		{"opt-out without a record", sale, nil, false, "NOT_OPTED_OUT"},
		{"opt-out opted out", sale, withdrawn, false, "CONSENT_WITHDRAWN"},
		{"contract", billing, nil, false, "LEGAL_BASIS"},
		{"restricted consent", marketing, granted, true, "RESTRICTED"},
		{"erased opt-out", sale, nil, "erased", "ERASED"},
		{"restricted contract", billing, nil, true, "RESTRICTED"},
		{"restricted legal obligation", legal, nil, true, "LEGAL_BASIS"},
	}
	for _, c := range cases {
		if got := privacyReason(t, c.purpose, c.consent, c.restricted, now); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}

	// Lifetime: the grant lapses at expiresAt.
	lapsing := obj(t, `{"purposeId":"p1","granted":true,"purposeVersion":1}`).Set("expiresAt", float64(now+365*privacyDay))
	if got := privacyReason(t, marketing, lapsing, false, now+364*privacyDay); got != "CONSENT_GIVEN" {
		t.Errorf("before the lifetime: %s", got)
	}
	if got := privacyReason(t, marketing, lapsing, false, now+365*privacyDay); got != "CONSENT_EXPIRED" {
		t.Errorf("at the lifetime: %s", got)
	}

	// Versions: a new version outdates older grants unless the purpose keeps them.
	v2 := marketing.Spread(core.NewObject("version", 2.0))
	if got := privacyReason(t, v2, granted, false, now); got != "CONSENT_OUTDATED" {
		t.Errorf("new version: %s", got)
	}
	if got := privacyReason(t, v2.Spread(core.NewObject("reconsentOnVersion", false)), granted, false, now); got != "CONSENT_GIVEN" {
		t.Errorf("kept grants: %s", got)
	}

	// Archived purposes are refused before anything else.
	if got := privacyReason(t, billing.Spread(core.NewObject("archived", true)), nil, false, now); got != "PURPOSE_ARCHIVED" {
		t.Errorf("archived: %s", got)
	}

	if !must(Decidable(marketing)) || !must(Decidable(analytics)) || must(Decidable(billing)) || must(Decidable(legal)) {
		t.Error("decidable is consent and legitimate interests only")
	}
}

func TestPrivacyRestrictionState(t *testing.T) {
	if must(RestrictionState(nil)) != false {
		t.Error("no restriction")
	}
	if must(RestrictionState(obj(t, `{"subject":"identity:a"}`))) != true {
		t.Error("ordinary restriction")
	}
	if must(RestrictionState(obj(t, `{"subject":"external:a","erased":true}`))) != "erased" {
		t.Error("erasure marker")
	}
}

func TestPrivacyReceiptsMatchTheTypeScriptSignature(t *testing.T) {
	event := obj(t, `{"id":"e1","tenantId":"t1","receiptId":"rcpt_1","purposeId":"p1","purposeKey":"marketing-email",
		"purposeName":"Marketing email","legalBasis":"consent","purposeVersion":2,"subject":"identity:alice","identityId":"alice",
		"granted":true,"source":"self","method":"banner","evidence":"form v3","ip":"203.0.113.9","recordedAt":1767272400000,"recordedBy":"alice"}`)
	receipt := must(ReceiptFromEvent("deployment-secret-1", event))
	want := `{"version":1,"receiptId":"rcpt_1","tenantId":"t1","subject":"identity:alice","purpose":{"key":"marketing-email","name":"Marketing email","version":2,"legalBasis":"consent"},"granted":true,"recordedAt":1767272400000,"source":"self","method":"banner","signature":"LmETYNuClYpCedBbffkm3OK85Bb0X7jMx1sM2Eo6Fy4"}`
	if text, _, _ := core.Stringify(receipt); text != want {
		t.Fatalf("receipt\n got %s\nwant %s", text, want)
	}
	// The current or a previous secret verifies; another secret or any change does not.
	if !must(ReceiptSignatureValid([]string{"deployment-secret-2", "deployment-secret-1"}, receipt)) {
		t.Error("previous secret refused")
	}
	if must(ReceiptSignatureValid([]string{"deployment-secret-2"}, receipt)) {
		t.Error("another secret accepted")
	}
	tampered := receipt.Spread(core.NewObject("granted", false))
	if must(ReceiptSignatureValid([]string{"deployment-secret-1"}, tampered)) {
		t.Error("tampered receipt accepted")
	}
	unsigned := receipt.Spread(core.NewObject("signature", 5.0))
	if must(ReceiptSignatureValid([]string{"deployment-secret-1"}, unsigned)) {
		t.Error("non-string signature accepted")
	}
	// Without a method the member is left out.
	event.Set("method", core.Undefined)
	if must(ReceiptFromEvent("deployment-secret-1", event)).Has("method") {
		t.Error("empty method kept")
	}
}

func TestPrivacyEmailSubjectIsKeyedAndCaseInsensitive(t *testing.T) {
	got := must(EmailSubject("deployment-secret-1", "Bob@Example.TEST"))
	if got != "email:5639a9a480af3a9ac7e56b13c0372f8b1202c1967cd2ff8274093250cc06aaae" {
		t.Errorf("email subject %s", got)
	}
	if must(EmailSubject("deployment-secret-1", "bob@example.test")) != got {
		t.Error("case changes the subject")
	}
	if must(EmailSubject("deployment-secret-2", "bob@example.test")) == got {
		t.Error("the secret does not key the subject")
	}
	if must(IdentitySubject("alice")) != "identity:alice" {
		t.Error("identity subject")
	}
}

func TestPrivacyResolveSubject(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	privacyInsert(t, store, "identities",
		identity("alice", "t1"),
		identity("gone", "t1", "status", "deleted"),
		identity("robot", "t1", "kind", "service"),
		identity("other", "t2"),
	)
	resolve := func(value any, allowDeleted bool) (*core.Object, error) {
		return ResolveSubject(ctx, store, "t1", value, allowDeleted)
	}
	_, err := resolve(nil, false)
	expectError(t, err, "INVALID_INPUT", "subject must name an identityId or an externalId")
	_, err = resolve([]any{}, false)
	expectError(t, err, "INVALID_INPUT", "subject must name an identityId or an externalId")
	_, err = resolve(obj(t, `{}`), false)
	expectError(t, err, "INVALID_INPUT", "subject must name exactly one of identityId or externalId")
	_, err = resolve(obj(t, `{"identityId":"alice","externalId":"cus_1"}`), false)
	expectError(t, err, "INVALID_INPUT", "subject must name exactly one of identityId or externalId")
	_, err = resolve(obj(t, `{"externalId":" cus_1"}`), false)
	expectError(t, err, "INVALID_INPUT", "Invalid externalId")
	_, err = resolve(obj(t, `{"identityId":"other"}`), false)
	expectError(t, err, "NOT_FOUND", "Identity not found")
	_, err = resolve(obj(t, `{"identityId":"gone"}`), false)
	expectError(t, err, "NOT_FOUND", "Identity not found")
	_, err = resolve(obj(t, `{"identityId":"robot"}`), false)
	expectError(t, err, "INVALID_INPUT", "Only people are data subjects")

	external := must(resolve(obj(t, `{"externalId":"cus_1"}`), false))
	if text, _, _ := core.Stringify(external); text != `{"key":"external:cus_1","externalId":"cus_1"}` {
		t.Errorf("external subject %s", text)
	}
	person := must(resolve(obj(t, `{"identityId":"alice"}`), false))
	if person.Get("key") != "identity:alice" || person.Get("identityId") != "alice" || member(person.Get("identity"), "id") != "alice" {
		t.Errorf("identity subject %v", person)
	}
	if deleted := must(resolve(obj(t, `{"identityId":"gone"}`), true)); deleted.Get("key") != "identity:gone" {
		t.Errorf("allowDeleted %v", deleted)
	}
}

func TestPrivacyRequestNumbersAndDeadlines(t *testing.T) {
	pattern := regexp.MustCompile(`^DSR-[0-9A-HJKMNP-TV-Z]{8}$`)
	seen := map[string]bool{}
	for range 50 {
		number := must(RequestNumber())
		if !pattern.MatchString(number) {
			t.Fatalf("request number %s", number)
		}
		seen[number] = true
	}
	if len(seen) < 45 {
		t.Error("request numbers repeat")
	}

	window := func(regulation string, settings string) string {
		text, _, _ := core.Stringify(must(ResponseWindow(regulation, obj(t, settings))))
		return text
	}
	if got := window("gdpr", `{}`); got != `{"responseDays":30,"extensionDays":60}` {
		t.Errorf("gdpr %s", got)
	}
	if got := window("ccpa", `{"responseDays":{"ccpa":20}}`); got != `{"responseDays":20,"extensionDays":45}` {
		t.Errorf("shortened ccpa %s", got)
	}
	// An internal window never extends the statutory one.
	if got := window("lgpd", `{"responseDays":{"lgpd":40}}`); got != `{"responseDays":15,"extensionDays":0}` {
		t.Errorf("lgpd %s", got)
	}
	if _, err := ResponseWindow("unknown", core.NewObject()); err == nil {
		t.Error("an unknown regulation has no window")
	}

	now := int64(1_000_000)
	overdue := func(record string) bool { return must(RequestOverdue(obj(t, record), now)) }
	if !overdue(`{"status":"open","dueAt":1000000}`) || overdue(`{"status":"open","dueAt":1000001}`) ||
		overdue(`{"status":"open"}`) || overdue(`{"status":"completed","dueAt":1}`) || overdue(`{"status":"pending-verification","dueAt":1}`) {
		t.Error("overdue is open with a past deadline")
	}
}

func TestPrivacyValidators(t *testing.T) {
	if must(Prose("Line one\n\tline two\r\n", "description", 5000)) == "" {
		t.Error("prose with line breaks refused")
	}
	for _, value := range []any{"", "   ", "bell\a", "nul\x00", "del\x7f", 5.0, nil} {
		_, err := Prose(value, "description", 5000)
		expectError(t, err, "INVALID_INPUT", "Invalid description")
	}
	_, err := Prose("abcdef", "note", 5)
	expectError(t, err, "INVALID_INPUT", "Invalid note")

	for _, key := range []string{"marketing-email", "a", "product.analytics_v2"} {
		if must(PurposeKey(key)) != key {
			t.Errorf("purpose key %s", key)
		}
	}
	for _, key := range []string{"Marketing", "1st", "-x", "has space", "émail"} {
		_, err := PurposeKey(key)
		expectError(t, err, "INVALID_INPUT", "Purpose keys use lowercase letters, digits, dots, underscores or hyphens")
	}
	_, err = PurposeKey("")
	expectError(t, err, "INVALID_INPUT", "Invalid purposeKey")

	if must(OneOf("ccpa", stringsOf(Regulations), "regulation")) != "ccpa" {
		t.Error("oneOf")
	}
	_, err = OneOf("hipaa", stringsOf(Regulations), "regulation")
	expectError(t, err, "INVALID_INPUT", "regulation must be one of gdpr, uk-gdpr, ccpa, lgpd, pipeda, other")
	_, err = OneOf(1.0, stringsOf(LegalBases), "legalBasis")
	expectError(t, err, "INVALID_INPUT", "legalBasis must be one of consent, contract, legal-obligation, vital-interests, public-task, legitimate-interests")

	if must(Days(365.0, "retentionDays", 0)) != 365 || must(Days(3650.0, "retentionDays", 0)) != 3650 {
		t.Error("days")
	}
	for _, value := range []any{0.0, 3651.0, 1.5, "30"} {
		_, err := Days(value, "retentionDays", 0)
		expectError(t, err, "INVALID_INPUT", "Invalid retentionDays")
	}
	_, err = Days(91.0, "extensionDays", 90)
	expectError(t, err, "INVALID_INPUT", "Invalid extensionDays")

	_, err = ExternalSubjectID("cus_1 ")
	expectError(t, err, "INVALID_INPUT", "Invalid externalId")
	if settings := must(PrivacySettings(context.Background(), newStore(t), "t1")); func() string {
		text, _, _ := core.Stringify(settings)
		return text
	}() != `{"id":"privacy:t1","tenantId":"t1","defaultRegulation":"gdpr","publicIntake":false,"exportLifetimeDays":14,"updatedAt":0}` {
		t.Errorf("default settings %v", settings)
	}
}

func TestPrivacyHoldsAndReleasedRecords(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	now := int64(10 * privacyDay)
	insert := func(collection string, records ...*core.Object) {
		t.Helper()
		privacyInsert(t, store, collection, records...)
	}
	insert("tenants",
		obj(t, `{"id":"org","tenantId":"org","parentId":"root","name":"Org","type":"organization","status":"active"}`),
		obj(t, `{"id":"proj","tenantId":"proj","parentId":"org","name":"Project","type":"project","status":"active"}`),
		obj(t, `{"id":"other","tenantId":"other","parentId":"root","name":"Other","type":"organization","status":"active"}`),
	)
	alice := identity("alice", "proj")
	robot := identity("robot", "proj", "kind", "service")
	insert("identities", alice, robot)

	if hold := must(ActiveHold(ctx, store, "proj", "identity:alice", now)); hold != nil {
		t.Fatal("hold before one is placed")
	}
	if err := AssertNoLegalHold(ctx, store, alice, now); err != nil {
		t.Fatal(err)
	}
	insert("privacyHolds",
		obj(t, `{"id":"h-lapsed","tenantId":"proj","subject":"identity:alice","reason":"Old case","placedBy":"o","placedAt":0}`).Set("expiresAt", float64(now)),
		obj(t, `{"id":"h-live","tenantId":"proj","subject":"identity:alice","reason":"Litigation","placedBy":"o","placedAt":0}`).Set("expiresAt", float64(now+privacyDay)),
		obj(t, `{"id":"h-robot","tenantId":"proj","subject":"identity:robot","reason":"Litigation","placedBy":"o","placedAt":0}`),
	)
	if hold := must(ActiveHold(ctx, store, "proj", "identity:alice", now)); hold == nil || hold.Get("id") != "h-live" {
		t.Fatalf("active hold %v", hold)
	}
	expectError(t, AssertNoLegalHold(ctx, store, alice, now), "LEGAL_HOLD", "This person is under a legal hold; release the hold before deleting them")
	if status := iamError(t, AssertNoLegalHold(ctx, store, alice, now)).Status; status != 409 {
		t.Errorf("status %d", status)
	}
	// Service accounts are not data subjects.
	if err := AssertNoLegalHold(ctx, store, robot, now); err != nil {
		t.Errorf("service account hold: %v", err)
	}
	// The hold lapses with its expiry.
	if err := AssertNoLegalHold(ctx, store, alice, now+privacyDay); err != nil {
		t.Errorf("lapsed hold: %v", err)
	}

	// The organization above the project is held too; an unrelated one is not.
	tenantHold := "People in this organization are under a legal hold; release the holds before deleting it"
	expectError(t, AssertNoTenantLegalHold(ctx, store, "org", now, 8), "LEGAL_HOLD", tenantHold)
	expectError(t, AssertNoTenantLegalHold(ctx, store, "proj", now, 8), "LEGAL_HOLD", tenantHold)
	if err := AssertNoTenantLegalHold(ctx, store, "other", now, 8); err != nil {
		t.Errorf("unrelated organization: %v", err)
	}
	// Depth limits the subtree.
	if err := AssertNoTenantLegalHold(ctx, store, "org", now, 0); err != nil {
		t.Errorf("depth 0: %v", err)
	}
	if err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "privacyHolds", "h-robot")
	}); err != nil {
		t.Fatal(err)
	}
	if err := AssertNoTenantLegalHold(ctx, store, "org", now+privacyDay, 8); err != nil {
		t.Errorf("after the holds lapsed: %v", err)
	}

	// Releasing a deleted person's records removes decisions and restrictions, and keeps the history.
	insert("privacyConsents",
		obj(t, `{"id":"c1","tenantId":"proj","subject":"identity:alice","purposeId":"p1","granted":true}`),
		obj(t, `{"id":"c2","tenantId":"proj","subject":"identity:bob","purposeId":"p1","granted":true}`),
	)
	insert("privacyRestrictions", obj(t, `{"id":"r1","tenantId":"proj","subject":"identity:alice","restrictedAt":0,"restrictedBy":"o"}`))
	insert("privacyConsentEvents", obj(t, `{"id":"ev1","tenantId":"proj","subject":"identity:alice","purposeId":"p1","granted":true}`))
	if restriction := must(RestrictionOf(ctx, store, "proj", "identity:alice")); restriction == nil {
		t.Fatal("restriction not found")
	}
	if consents := must(ConsentsOf(ctx, store, "proj", "identity:alice")); len(consents) != 1 || consents["p1"].Get("id") != "c1" {
		t.Fatalf("consents %v", consents)
	}
	if err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		return ReleasePrivacyRecords(ctx, tx, alice)
	}); err != nil {
		t.Fatal(err)
	}
	if consents := must(ConsentsOf(ctx, store, "proj", "identity:alice")); len(consents) != 0 {
		t.Error("consents kept")
	}
	if restriction := must(RestrictionOf(ctx, store, "proj", "identity:alice")); restriction != nil {
		t.Error("restriction kept")
	}
	if bob := must(ConsentsOf(ctx, store, "proj", "identity:bob")); len(bob) != 1 {
		t.Error("another person's consent removed")
	}
	if history := must(store.Find(ctx, "privacyConsentEvents", core.NewObject("tenantId", "proj"), nil)); len(history) != 1 {
		t.Error("history removed")
	}
}

func TestPrivacyConsentContext(t *testing.T) {
	store := newStore(t)
	ctx := context.Background()
	now := int64(1_000)
	for _, purpose := range []string{
		`{"id":"p1","tenantId":"t1","key":"marketing-email","legalBasis":"consent","mode":"opt-in","version":1,"reconsentOnVersion":true,"archived":false}`,
		`{"id":"p2","tenantId":"t1","key":"product-analytics","legalBasis":"legitimate-interests","mode":"opt-out","version":1,"reconsentOnVersion":true,"archived":false}`,
		`{"id":"p3","tenantId":"t1","key":"data-sharing","legalBasis":"consent","mode":"opt-out","version":1,"reconsentOnVersion":true,"archived":false}`,
		`{"id":"p4","tenantId":"t1","key":"billing","legalBasis":"contract","mode":"opt-in","version":1,"reconsentOnVersion":true,"archived":false}`,
		`{"id":"p5","tenantId":"t1","key":"archived-news","legalBasis":"consent","mode":"opt-out","version":1,"reconsentOnVersion":true,"archived":true}`,
	} {
		privacyInsert(t, store, "privacyPurposes", obj(t, purpose))
	}
	alice := identity("alice", "t1")
	consents := func(person *core.Object, tenantID string) string {
		text, _, _ := core.Stringify(must(ConsentContext(ctx, store, tenantID, person, now)))
		return text
	}
	if got := consents(alice, "t1"); got != `{"principal.consents":["data-sharing","product-analytics"]}` {
		t.Errorf("defaults %s", got)
	}
	for _, consent := range []string{
		`{"id":"c1","tenantId":"t1","subject":"identity:alice","purposeId":"p1","granted":true,"purposeVersion":1}`,
		`{"id":"c3","tenantId":"t1","subject":"identity:alice","purposeId":"p3","granted":false,"purposeVersion":1}`,
	} {
		privacyInsert(t, store, "privacyConsents", obj(t, consent))
	}
	if got := consents(alice, "t1"); got != `{"principal.consents":["marketing-email","product-analytics"]}` {
		t.Errorf("after decisions %s", got)
	}
	// Service accounts, and people looked at from another tenant, have none.
	if got := consents(identity("robot", "t1", "kind", "service"), "t1"); got != `{"principal.consents":[]}` {
		t.Errorf("service account %s", got)
	}
	if got := consents(alice, "t2"); got != `{"principal.consents":[]}` {
		t.Errorf("other tenant %s", got)
	}
	// A restriction (even an erasure marker) holds back every decidable purpose.
	privacyInsert(t, store, "privacyRestrictions", obj(t, `{"id":"r1","tenantId":"t1","subject":"identity:alice","erased":true,"restrictedAt":0,"restrictedBy":"o"}`))
	if got := consents(alice, "t1"); got != `{"principal.consents":[]}` {
		t.Errorf("restricted %s", got)
	}
}

// TestPrivacyConsentsInPolicies ports "exposes principal.consents to policies": a role conditioned on a consent
// allows only while the person's grant is live.
func TestPrivacyConsentsInPolicies(t *testing.T) {
	f := newFlagFixture(t, nil)
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	statement := obj(t, `{"effect":"allow","actions":["documents:read"],"resources":["*"],"conditions":{"ArrayContains":{"principal.consents":["marketing-email"]}}}`)
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		if _, err := tx.Insert(ctx, "privacyPurposes", core.NewObject("id", "purpose-marketing", "tenantId", f.tenantID,
			"key", "marketing-email", "name", "Marketing email", "description", "Product news and offers by email.",
			"legalBasis", "consent", "mode", "opt-in", "version", 1.0, "dataCategories", []any{"contact"},
			"reconsentOnVersion", true, "archived", false, "createdAt", f.now(), "updatedAt", f.now())); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "policies", core.NewObject("id", "policy-newsletter", "tenantId", f.tenantID, "name", "Newsletter reader",
			"document", core.NewObject("version", 1.0, "statements", []any{statement}), "version", 1.0, "authorityId", f.authorityID)); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "roles", core.NewObject("id", "role-newsletter", "tenantId", f.tenantID, "name", "Newsletter reader",
			"policyIds", []any{"policy-newsletter"}, "authorityId", f.authorityID)); err != nil {
			return err
		}
		_, err := tx.Insert(ctx, "bindings", core.NewObject("id", "binding-newsletter", "tenantId", f.tenantID, "subjectType", "identity",
			"subjectId", aliceID, "roleId", "role-newsletter", "authorityId", f.authorityID))
		return err
	})
	aliceCred := f.signInID(aliceID, false)
	canRead := func() bool {
		t.Helper()
		decision, err := f.iam.Authorize(context.Background(), AuthorizationRequest{Credential: aliceCred, TenantID: f.tenantID,
			Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "d1"}})
		if err != nil {
			t.Fatal(err)
		}
		return decision.Allowed
	}
	decide := func(granted bool) {
		f.transact(func(ctx context.Context, tx core.IamStore) error {
			consent := core.NewObject("id", "consent-alice", "tenantId", f.tenantID, "purposeId", "purpose-marketing",
				"purposeKey", "marketing-email", "subject", "identity:"+aliceID, "identityId", aliceID, "granted", granted,
				"purposeVersion", 1.0, "source", "self", "recordedAt", f.now(), "recordedBy", aliceID, "receiptId", ID())
			existing, err := tx.Get(ctx, "privacyConsents", "consent-alice")
			if err != nil {
				return err
			}
			if existing != nil {
				_, err = tx.Put(ctx, "privacyConsents", consent)
			} else {
				_, err = tx.Insert(ctx, "privacyConsents", consent)
			}
			return err
		})
	}
	if canRead() {
		t.Error("allowed without consent")
	}
	decide(true)
	if !canRead() {
		t.Error("denied after the grant")
	}
	decide(false)
	if canRead() {
		t.Error("allowed after the withdrawal")
	}
}

// TestPrivacyLegalHoldsBlockDeletion ports "refuses to delete an organization while someone in it is under a legal
// hold" and the identity side of "erases a person after the legal hold is released".
func TestPrivacyLegalHoldsBlockDeletion(t *testing.T) {
	f := newFlagFixture(t, nil)
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, "privacyHolds", core.NewObject("id", "hold-alice", "tenantId", f.tenantID,
			"subject", "identity:"+aliceID, "identityId", aliceID, "reason", "Litigation", "placedBy", f.ownerID, "placedAt", f.now()))
		return err
	})
	deleteAlice := func() error {
		_, err := f.iam.API.Identities.Delete(context.Background(), f.ownerCred,
			Input[apitypes.IdentitiesDeleteInput](core.NewObject("tenantId", f.tenantID, "identityId", aliceID)))
		return err
	}
	deleteTenant := func() (Out[apitypes.TenantsSetStatusOutput], error) {
		return f.iam.API.Tenants.SetStatus(context.Background(), f.rootCred,
			Input[apitypes.TenantsSetStatusInput](core.NewObject("tenantId", f.tenantID, "status", "deleted")))
	}
	expectError(t, deleteAlice(), "LEGAL_HOLD", "This person is under a legal hold; release the hold before deleting them")
	_, err := deleteTenant()
	expectError(t, err, "LEGAL_HOLD", "People in this organization are under a legal hold; release the holds before deleting it")

	f.transact(func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "privacyHolds", "hold-alice")
	})
	// With the hold released the hold check passes; identity deletion itself continues into guests.ts, which another
	// unit ports, so only its NOT_IMPLEMENTED stub is tolerated here.
	if err := deleteAlice(); err != nil && iamError(t, err).Code != "NOT_IMPLEMENTED" {
		t.Fatalf("delete after release: %v", err)
	}
	out, err := deleteTenant()
	if err != nil {
		t.Fatalf("delete organization after release: %v", err)
	}
	if status := member(core.Normalize(out.Value), "status"); status != "deleted" {
		t.Errorf("organization status %v", status)
	}
}
