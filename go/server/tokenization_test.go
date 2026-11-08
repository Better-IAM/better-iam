package server

// Value handling of data protection (tokenization.ts), after tests/protection.test.ts and
// tests/protection-security.test.ts: normalization, tokens, masks and sealing. The API-level steps that need a KMS
// key run in api_protection_test.go.

import (
	"crypto/rand"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// tokenizationCard is a card number with a valid Luhn check digit.
func tokenizationCard(prefix string) string {
	for check := 0; check < 10; check++ {
		digits := prefix + strconv.Itoa(check)
		if luhnValid(digits) {
			return digits
		}
	}
	panic("unreachable")
}

func TestTokenizationNormalizesEachDataType(t *testing.T) {
	cases := []struct{ dataType, value, want string }{
		{"card", "4242 4242 4242 4242", "4242424242424242"},
		{"card", "5555-5555-5555-4444", "5555555555554444"},
		{"ssn", "123456789", "123-45-6789"},
		{"ssn", "123 45 6789", "123-45-6789"},
		{"email", "  Jane.Doe@Example.com ", "jane.doe@example.com"},
		{"phone", "+1 (415) 555-0199", "+14155550199"},
		{"generic", "josé garcia", "josé garcia"},
		{"generic", "tab\tand\nnewline", "tab\tand\nnewline"},
	}
	for _, item := range cases {
		got, err := NormalizeValue(item.dataType, item.value)
		if err != nil || got != item.want {
			t.Fatalf("NormalizeValue(%s, %q) = %q, %v; want %q", item.dataType, item.value, got, err, item.want)
		}
	}
	composed := must(NormalizeValue("generic", "josé garcia"))
	if composed != must(NormalizeValue("generic", "josé garcia")) {
		t.Fatal("composed and decomposed spellings differ")
	}
	refusals := []struct{ dataType, value, message string }{
		{"card", "4242424242424241", "Not a valid card number"},
		{"card", "42424242", "Not a valid card number"},
		{"ssn", "12345678", "Not a valid social security number"},
		{"email", "a\u0001b@acme.test", "Not a valid email address"},
		{"email", "jane@", "Not a valid email address"},
		{"email", "a‮b@acme.test", "Not a valid email address"},
		{"email", core.FromUTF16([]uint16{'a', 0xd800, '@', 'b', '.', 'c'}), "Not a valid email address"},
		{"phone", "12345", "Not a valid phone number"},
	}
	for _, item := range refusals {
		_, err := NormalizeValue(item.dataType, item.value)
		expectError(t, err, "INVALID_INPUT", item.message)
	}
	generic := "Values are 1 to 4096 characters of well-formed text without control or bidirectional formatting characters"
	for _, value := range []string{
		"key-" + core.FromUTF16([]uint16{0xd800}),
		"key-" + core.FromUTF16([]uint16{0xdc00}) + "x",
		"abc\u007fdef", "pay\u0085", "‮evil", "", strings.Repeat("x", 4097),
	} {
		_, err := NormalizeValue("generic", value)
		expectError(t, err, "INVALID_INPUT", generic)
	}
	// A paired surrogate is a character, not a lone surrogate.
	if got, err := NormalizeValue("generic", "emoji \U0001F600"); err != nil || got != "emoji \U0001F600" {
		t.Fatalf("astral character refused: %q, %v", got, err)
	}
	_, err := NormalizeValue("card", 4242.0)
	expectError(t, err, "INVALID_INPUT", "Every value must be a string")
}

func TestTokenizationKeepsEachDataTypeRecognizable(t *testing.T) {
	shapes := []struct {
		dataType, format, value string
		shape                   *regexp.Regexp
	}{
		{"card", "format-preserving", "4242424242424242", regexp.MustCompile(`^\d{12}4242$`)},
		{"ssn", "format-preserving", "123-45-6789", regexp.MustCompile(`^9\d\d-\d\d-6789$`)},
		{"email", "format-preserving", "jane.doe@example.com", regexp.MustCompile(`^[a-z0-9]{16}@example\.com$`)},
		{"phone", "format-preserving", "+14155550199", regexp.MustCompile(`^\+\d{7}0199$`)},
		{"generic", "random", "patient allergic to penicillin", regexp.MustCompile(`^tok_[0-9A-Za-z]{22}$`)},
		{"generic", "format-preserving", "DE89-3704-0044-0532-0130-00", regexp.MustCompile(`^[A-Z]{2}\d{2}-\d{4}-\d{4}-\d{4}-\d{4}-\d{2}$`)},
		{"generic", "format-preserving", "Иван Петров ACCT-1234-5678", regexp.MustCompile(`^[A-Z][a-z]{3} [A-Z][a-z]{5} [A-Z]{4}-\d{4}-\d{4}$`)},
		{"generic", "format-preserving", "١٢٣٤٥٦٧٨٩٠١٢", regexp.MustCompile(`^\d{12}$`)},
	}
	for _, item := range shapes {
		for range 20 {
			token := must(NewToken(item.dataType, item.format, item.value))
			if !item.shape.MatchString(token) || token == item.value {
				t.Fatalf("%s token %q does not match %s", item.dataType, token, item.shape)
			}
			if item.dataType == "card" && luhnValid(token) {
				t.Fatalf("card token %q passes the Luhn check", token)
			}
		}
	}
	// Area 9XX with a group no ITIN uses: never a valid SSN or ITIN.
	for index := range 100 {
		value := "123-45-" + strings.Repeat("0", 4-len(strconv.Itoa(index))) + strconv.Itoa(index)
		token := must(NewToken("ssn", "format-preserving", value))
		group, _ := strconv.Atoi(token[4:6])
		if (group >= 50 && group <= 65) || (group >= 70 && group <= 88) || group == 90 || group == 91 || group == 92 || group >= 94 || group == 0 {
			t.Fatalf("ssn token %q uses an ITIN group", token)
		}
	}
	if !must(FormatPreservingSpace("card", "1")) || must(FormatPreservingSpace("generic", "AB-12")) ||
		!must(FormatPreservingSpace("generic", "DE89-3704-0044-0532-0130-00")) {
		t.Fatal("format-preserving space")
	}
	if !must(NeedsDeterministic("ssn", "format-preserving")) || !must(NeedsDeterministic("phone", "format-preserving")) ||
		must(NeedsDeterministic("ssn", "random")) || must(NeedsDeterministic("card", "format-preserving")) {
		t.Fatal("needsDeterministic")
	}
}

func TestTokenizationNeverLetsAMaskRevealMostOfAValue(t *testing.T) {
	short := tokenizationCard("42424242424")
	long := tokenizationCard("424242424242424")
	cases := []struct{ dataType, style, value, want string }{
		{"card", "last4", "5555555555554444", "************4444"},
		{"card", "first6last4", "5555555555554444", "555555******4444"},
		{"card", "first6last4", short, "********" + short[len(short)-4:]},
		{"card", "first6last4", long, "424242******" + long[len(long)-4:]},
		{"card", "last4", long, "************" + long[len(long)-4:]},
		{"ssn", "last4", "123-45-6789", "***-**-6789"},
		{"email", "email", "jane.doe@example.com", "j***@example.com"},
		{"email", "email", "abc@example.com", "****@example.com"},
		{"phone", "last4", "+14155550199", "+*******0199"},
		{"phone", "last4", "5550199", "****199"},
		{"generic", "full", "patient allergic to penicillin", "******* ******** ** **********"},
		{"generic", "last4", "abcdefgh", "****efgh"},
	}
	for _, item := range cases {
		if got := must(MaskValue(item.dataType, item.style, item.value)); got != item.want {
			t.Fatalf("MaskValue(%s, %s, %q) = %q; want %q", item.dataType, item.style, item.value, got, item.want)
		}
	}
	names := "Иван Петров, José García, 山田太郎"
	masked := must(MaskValue("generic", "full", names))
	if regexp.MustCompile(`[\p{L}\p{N}]`).MatchString(masked) || len(core.CodePoints(masked)) != len(core.CodePoints(names)) {
		t.Fatalf("mask %q shows letters or changes length", masked)
	}
	// A card style on a social security number would show all nine digits.
	_, err := MaskStyle("ssn", "first6last4", "style")
	expectError(t, err, "INVALID_INPUT", "style must be one of last4, full for ssn values")
	_, err = MaskStyle("card", 1.0, "")
	expectError(t, err, "INVALID_INPUT", "mask must be one of last4, first6last4, full for card values")
	if must(MaskStyle("email", "email", "mask")) != "email" {
		t.Fatal("email mask")
	}
}

func TestTokenizationSealsValuesBoundToTheirToken(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealed := must(SealValue(key, "t1", "p1", "tok_a", "4242424242424242"))
	record := core.NewObject("tenantId", "t1", "profileId", "p1", "token", "tok_a", "sealed", sealed)
	if must(OpenValue(key, record)) != "4242424242424242" {
		t.Fatal("open")
	}
	for _, altered := range []*core.Object{
		record.Spread(core.NewObject("token", "tok_b")),
		record.Spread(core.NewObject("tenantId", "t2")),
		record.Spread(core.NewObject("sealed", sealed[:len(sealed)-2]+"AA")),
		record.Spread(core.NewObject("sealed", "short")),
	} {
		_, err := OpenValue(key, altered)
		expectError(t, err, "KEY_MATERIAL_UNAVAILABLE", "A stored value cannot be opened")
	}
	_, err := OpenValue(make([]byte, 32), record)
	expectError(t, err, "KEY_MATERIAL_UNAVAILABLE", "A stored value cannot be opened")

	first := must(TokenizationFingerprint(key, "value"))
	if first != must(TokenizationFingerprint(key, "value")) || first == must(TokenizationFingerprint(key, "other")) || len(first) != 43 {
		t.Fatal("fingerprint")
	}
	tokenKey := must(TokenKey("p1", "tok_a"))
	if !strings.HasPrefix(tokenKey, "token:p1:") || len(tokenKey) != len("token:p1:")+43 {
		t.Fatalf("token key %q", tokenKey)
	}
	// The SHA-256 of "abc", base64url.
	if must(TokenKey("p", "abc")) != "token:p:ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		t.Fatal("token key digest")
	}
	if stringify(must(LookupContext("p1"))) != `{"protection":"p1","use":"lookup"}` {
		t.Fatal("lookup context")
	}
}

func TestTokenizationNamesAndSummarizesProfiles(t *testing.T) {
	if must(ProfileName("cards-2")) != "cards-2" {
		t.Fatal("profile name")
	}
	for _, name := range []any{"Cards", "2cards", "cards_x", strings.Repeat("a", 65)} {
		_, err := ProfileName(name)
		expectCode(t, err, "INVALID_INPUT")
	}
	_, err := ProfileName("Cards")
	expectError(t, err, "INVALID_INPUT", "Profile names are lowercase letters, digits and hyphens, starting with a letter")
	_, err = ProfileName(42.0)
	expectError(t, err, "INVALID_INPUT", "Invalid profile")
	profile := core.NewObject("id", "p1", "tenantId", "t1", "uniqueKey", "name:cards", "name", "cards", "description", "Cards",
		"dataType", "card", "format", "format-preserving", "deterministic", true, "keyId", "k1", "mask", "last4",
		"retentionDays", 30.0, "lookupKeyWrapped", "secret", "createdAt", 1.0, "createdBy", "u1", "updatedAt", 2.0)
	want := `{"id":"p1","tenantId":"t1","name":"cards","dataType":"card","format":"format-preserving","deterministic":true,` +
		`"keyId":"k1","mask":"last4","tokens":0,"createdAt":1,"createdBy":"u1","updatedAt":2,"description":"Cards","retentionDays":30}`
	if got := stringify(must(SummarizeProfile(profile))); got != want {
		t.Fatalf("summary %s", got)
	}
}
