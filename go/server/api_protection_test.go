package server

// Data protection by tokenization, after tests/protection.test.ts and tests/protection-security.test.ts. The value
// handling (tokenization.ts) and the KMS keys (kms.ts) are ported by other units: steps that reach one of their stubs
// end the test with a skip. Input validation, the guard's tenant refusals, listing and the retention sweep run here
// on seeded records.

import (
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const protectionTestDay = 86_400_000.0

func TestProtectionValidatesInputBeforeAnythingElse(t *testing.T) {
	f := newTrustOrg(t, nil)
	api := f.iam.API.Protection
	for _, values := range []any{core.Undefined, items(), "4242424242424242", make([]any, 101)} {
		pairs := []any{"tenantId", f.tenantID, "profile", "cards"}
		if !isUndefined(values) {
			pairs = append(pairs, "values", values)
		}
		_, err := api.Tokenize(f.ctx, f.owner, Input[apitypes.ProtectionTokenizeInput](body(pairs...)))
		expectError(t, err, "INVALID_INPUT", "values must list 1 to 100 entries")
	}
	detokenize := func(pairs ...any) error {
		_, err := api.Detokenize(f.ctx, f.owner, Input[apitypes.ProtectionDetokenizeInput](body(append([]any{"tenantId", f.tenantID, "profile", "cards"}, pairs...)...)))
		return err
	}
	expectError(t, detokenize("tokens", items(), "purpose", "support"), "INVALID_INPUT", "tokens must list 1 to 100 entries")
	for _, token := range []any{42.0, "", "tok\x01en", strings.Repeat("t", 4097)} {
		expectError(t, detokenize("tokens", items(token), "purpose", "support"), "INVALID_INPUT", "Every token must be a string")
	}
	expectError(t, detokenize("tokens", items("tok_1"), "purpose", "Not A Purpose"), "INVALID_INPUT",
		"purpose is a short lowercase name, such as payment-processing or fraud-review")
	expectError(t, detokenize("tokens", items("tok_1")), "INVALID_INPUT", "Invalid purpose")
	expectError(t, detokenize("tokens", items("tok_1"), "purpose", strings.Repeat("p", 65)), "INVALID_INPUT", "Invalid purpose")
	_, err := api.Mask(f.ctx, f.owner, Input[apitypes.ProtectionMaskInput](body("tenantId", f.tenantID, "profile", "cards", "tokens", "tok_1")))
	expectError(t, err, "INVALID_INPUT", "tokens must list 1 to 100 entries")
	deleteTokens := func(pairs ...any) error {
		_, err := api.DeleteTokens(f.ctx, f.owner, Input[apitypes.ProtectionDeleteTokensInput](body(append([]any{"tenantId", f.tenantID, "profile", "cards"}, pairs...)...)))
		return err
	}
	expectError(t, deleteTokens(), "INVALID_INPUT", "Name either tokens or values")
	expectError(t, deleteTokens("tokens", items("tok_1"), "values", items("4242424242424242")), "INVALID_INPUT", "Name either tokens or values")
	expectError(t, deleteTokens("values", items()), "INVALID_INPUT", "values must list 1 to 100 entries")
	// Validation comes before authentication.
	_, err = api.Tokenize(f.ctx, core.CredentialInput{Token: "nope"}, Input[apitypes.ProtectionTokenizeInput](body("tenantId", f.tenantID, "profile", "cards")))
	expectCode(t, err, "INVALID_INPUT")
	_, err = api.Tokenize(f.ctx, core.CredentialInput{Token: "nope"}, Input[apitypes.ProtectionTokenizeInput](body("tenantId", f.tenantID, "profile", "cards", "values", items("x"))))
	expectCode(t, err, "UNAUTHENTICATED")
}

func TestProtectionRefusesOtherTenantsBeforeAnyLookup(t *testing.T) {
	f := newTrustOrg(t, nil)
	_, outsider := f.organization("Beta", "owner@beta.test")
	_, err := f.iam.API.Protection.GetProfile(f.ctx, outsider, Input[apitypes.ProtectionGetProfileInput](body("tenantId", f.tenantID, "profile", "cards")))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	var refused *core.Object
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if event.Get("action") == "iam:protection:read" && event.Get("outcome") == "deny" {
			refused = event
		}
	}
	if refused == nil || refused.Get("resourceId") != "protection" || stringify(refused.Get("metadata")) != `{"reason":"tenant"}` {
		t.Fatalf("refusal = %s", stringify(refused))
	}
	// A tenant ID that is not a string fails the guard's text() check once the caller is known.
	_, err = f.iam.API.Protection.GetProfile(f.ctx, f.owner, Input[apitypes.ProtectionGetProfileInput](body("tenantId", 42.0, "profile", "cards")))
	expectError(t, err, "INVALID_INPUT", "Invalid tenantId")
}

func TestProtectionListsNoProfilesForAnEmptyTenant(t *testing.T) {
	f := newTrustOrg(t, nil)
	listed := answer(f.iam.API.Protection.ListProfiles(f.ctx, f.owner, Input[apitypes.ProtectionListProfilesInput](body("tenantId", f.tenantID))))
	if stringify(listed) != "[]" {
		t.Fatalf("listed = %s", stringify(listed))
	}
	var event *core.Object
	for _, item := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if item.Get("action") == "iam:protection:read" {
			event = item
		}
	}
	if event == nil || event.Get("outcome") != "allow" || event.Get("resourceId") != "protection" || stringify(event.Get("metadata")) != `{"listed":0}` {
		t.Fatalf("event = %s", stringify(event))
	}
}

// seedProtectionProfile seeds a profile record as protection.createProfile stores it.
func seedProtectionProfile(f *trustOrg, tenantID, name string, pairs ...any) *core.Object {
	f.t.Helper()
	profile := core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", "name:"+name, "name", name, "dataType", "email",
		"format", "format-preserving", "deterministic", false, "keyId", ID(), "mask", "email", "lookupKeyWrapped", "wrapped",
		"tokens", 0.0, "createdAt", f.now(), "createdBy", f.ownerID, "updatedAt", f.now())
	for index := 0; index+1 < len(pairs); index += 2 {
		profile.Set(pairs[index].(string), pairs[index+1])
	}
	f.seed("protectionProfiles", profile)
	return profile
}

// seedProtectedTokens seeds count token records of a profile created at createdAt.
func seedProtectedTokens(f *trustOrg, profile *core.Object, count int, createdAt float64) {
	f.t.Helper()
	records := make([]*core.Object, count)
	for index := range records {
		token := "tok_" + ID()
		records[index] = core.NewObject("id", ID(), "tenantId", profile.Get("tenantId"), "uniqueKey", ID(),
			"profileId", profile.Get("id"), "token", token, "fingerprint", ID(), "wrapped", "wrapped", "sealed", "sealed",
			"createdAt", createdAt, "createdBy", f.ownerID)
	}
	f.seed("protectionTokens", records...)
}

func TestProtectionSweepDeletesTokensPastRetention(t *testing.T) {
	f := newTrustOrg(t, nil)
	beta, _ := f.organization("Beta", "owner@beta.test")
	emails := seedProtectionProfile(f, f.tenantID, "emails", "retentionDays", 30.0, "tokens", 3.0)
	seedProtectedTokens(f, emails, 2, f.now())
	f.advance(int64(10 * protectionTestDay))
	seedProtectedTokens(f, emails, 1, f.now())
	kept := seedProtectionProfile(f, f.tenantID, "cards", "dataType", "card", "tokens", 1.0)
	seedProtectedTokens(f, kept, 1, f.now())
	foreign := seedProtectionProfile(f, beta, "emails", "retentionDays", 1.0, "tokens", 1.0)
	seedProtectedTokens(f, foreign, 1, f.now())

	// Nothing is old enough yet: the profiles with a retention are swept, nothing is deleted or audited.
	swept, err := f.iam.Protection.Sweep(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stringify(swept) != `{"deleted":0,"profiles":2}` {
		t.Fatalf("swept = %s", stringify(swept))
	}
	f.advance(int64(21 * protectionTestDay))
	// Only the named tenant's profiles are swept when a tenant is given.
	swept, err = f.iam.Protection.Sweep(f.ctx, core.NewObject("tenantId", f.tenantID))
	if err != nil {
		t.Fatal(err)
	}
	if stringify(swept) != `{"deleted":2,"profiles":1}` {
		t.Fatalf("swept = %s", stringify(swept))
	}
	if remaining := f.find("protectionTokens", core.NewObject("profileId", emails.Get("id"))); len(remaining) != 1 {
		t.Fatalf("remaining = %d", len(remaining))
	}
	if f.record("protectionProfiles", jsString(emails.Get("id"))).Get("tokens") != 1.0 {
		t.Fatal("token counter not decremented")
	}
	var event *core.Object
	for _, item := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if item.Get("action") == "protection:retention-sweep" {
			event = item
		}
	}
	if event == nil || event.Get("actorId") != "deployment-operator" || event.Get("resourceId") != "protection/emails" ||
		event.Get("outcome") != "allow" || stringify(event.Get("metadata")) != `{"deleted":2,"retentionDays":30}` {
		t.Fatalf("event = %s", stringify(event))
	}
	swept, err = f.iam.Protection.Sweep(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stringify(swept) != `{"deleted":1,"profiles":2}` {
		t.Fatalf("swept = %s", stringify(swept))
	}
	if len(f.find("protectionTokens", core.NewObject("profileId", kept.Get("id")))) != 1 {
		t.Fatal("a profile without retention lost tokens")
	}
	_, err = f.iam.Protection.Sweep(f.ctx, core.NewObject("tenantId", 42.0))
	expectError(t, err, "INVALID_INPUT", "Invalid tenantId")
}

func TestProtectionSweepPagesThroughLargeProfiles(t *testing.T) {
	f := newTrustOrg(t, nil)
	profile := seedProtectionProfile(f, f.tenantID, "emails", "retentionDays", 1.0, "tokens", 1201.0)
	seedProtectedTokens(f, profile, 1200, f.now())
	f.advance(int64(2 * protectionTestDay))
	seedProtectedTokens(f, profile, 1, f.now())
	swept, err := f.iam.Protection.Sweep(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stringify(swept) != `{"deleted":1200,"profiles":1}` {
		t.Fatalf("swept = %s", stringify(swept))
	}
	if f.record("protectionProfiles", jsString(profile.Get("id"))).Get("tokens") != 1.0 {
		t.Fatal("token counter not decremented")
	}
}

func TestProtectionTokenizesCardNumbers(t *testing.T) {
	f := newTrustOrg(t, nil)
	api := f.iam.API.Protection
	profile, err := api.CreateProfile(f.ctx, f.owner, Input[apitypes.ProtectionCreateProfileInput](body(
		"tenantId", f.tenantID, "name", "cards", "dataType", "card", "deterministic", true)))
	trustSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	summary := profile.Value.(*core.Object)
	if summary.Get("format") != "format-preserving" || summary.Get("mask") != "last4" || summary.Get("deterministic") != true {
		t.Fatalf("profile = %s", stringify(summary))
	}
	cards := items("4242 4242 4242 4242", "5555-5555-5555-4444", "4242424242424242")
	tokenized, err := api.Tokenize(f.ctx, f.owner, Input[apitypes.ProtectionTokenizeInput](body("tenantId", f.tenantID, "profile", "cards", "values", cards)))
	trustSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	tokens := tokenized.Value.(*core.Object).Get("tokens").([]any)
	if len(tokens) != 3 || tokens[0] != tokens[2] {
		t.Fatalf("tokens = %v", tokens)
	}
	again := answerObject(api.Tokenize(f.ctx, f.owner, Input[apitypes.ProtectionTokenizeInput](body("tenantId", f.tenantID, "profile", "cards", "values", items("4242424242424242")))))
	if stringify(again) != stringify(core.NewObject("tokens", items(tokens[0]))) {
		t.Fatalf("again = %s", stringify(again))
	}
	detokenized := answerObject(api.Detokenize(f.ctx, f.owner, Input[apitypes.ProtectionDetokenizeInput](body("tenantId", f.tenantID,
		"profile", "cards", "tokens", append(append([]any{}, tokens...), "0000000000004242"), "purpose", "payment-processing"))))
	if stringify(detokenized) != `{"values":["4242424242424242","5555555555554444","4242424242424242",null]}` {
		t.Fatalf("detokenized = %s", stringify(detokenized))
	}
	masked := answerObject(api.Mask(f.ctx, f.owner, Input[apitypes.ProtectionMaskInput](body("tenantId", f.tenantID, "profile", "cards", "tokens", items(tokens[1])))))
	if stringify(masked) != `{"values":["************4444"]}` {
		t.Fatalf("masked = %s", stringify(masked))
	}
	_, err = api.Tokenize(f.ctx, f.owner, Input[apitypes.ProtectionTokenizeInput](body("tenantId", f.tenantID, "profile", "cards", "values", items("4242424242424241"))))
	expectCode(t, err, "INVALID_INPUT")
	text := stringify(f.find("audit", core.NewObject("tenantId", f.tenantID)))
	if strings.Contains(text, "4242424242424242") || strings.Contains(text, jsString(tokens[1])) {
		t.Fatal("values or tokens reached the audit trail")
	}
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if event.Get("action") == "iam:protection:detokenize" {
			metadata := event.Get("metadata").(*core.Object)
			if metadata.Get("purpose") != "payment-processing" || metadata.Get("count") != 4.0 || metadata.Get("found") != 2.0 {
				t.Fatalf("detokenize metadata = %s", stringify(metadata))
			}
		}
	}
}

func TestProtectionCreateProfileValidation(t *testing.T) {
	f := newTrustOrg(t, nil)
	api := f.iam.API.Protection
	create := func(pairs ...any) error {
		_, err := api.CreateProfile(f.ctx, f.owner, Input[apitypes.ProtectionCreateProfileInput](body(append([]any{"tenantId", f.tenantID}, pairs...)...)))
		return err
	}
	err := create("name", "cards", "dataType", "iban")
	trustSkipOnStub(t, err)
	expectError(t, err, "INVALID_INPUT", "dataType must be one of card, ssn, email, phone, generic")
	expectError(t, create("name", "cards", "dataType", "card", "format", "short"), "INVALID_INPUT", "format must be random or format-preserving")
	expectError(t, create("name", "cards", "dataType", "card", "deterministic", "yes"), "INVALID_INPUT", "deterministic must be true or false")
	err = create("name", "ssns", "dataType", "ssn", "deterministic", false)
	trustSkipOnStub(t, err)
	expectError(t, err, "INVALID_INPUT", "Format-preserving ssn tokens keep the last four digits and have few random ones left, so these profiles must be deterministic (or use random tokens)")
	expectError(t, create("name", "cards", "dataType", "card", "retentionDays", 0.0), "INVALID_INPUT", "Invalid retentionDays")
	expectError(t, create("name", "cards", "dataType", "card", "description", ""), "INVALID_INPUT", "Invalid description")
}
