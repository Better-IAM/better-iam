package server

// Port of packages/server/src/tokenization.ts: data protection by tokenization (like Skyflow, VGS or Google DLP
// de-identification). Sensitive values (card numbers, national identifiers, email addresses, phone numbers, free
// text) are replaced by tokens that are safe to store and pass around. The values themselves are encrypted under a
// tenant KMS key, and turning a token back into its value is decided by policy per profile and purpose. The API
// lives in api_protection.go.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Better-IAM/better-iam/go/core"
	"golang.org/x/text/unicode/norm"
)

// MaxBatch is tokenization.ts MAX_BATCH.
const MaxBatch = 100

// MaxProfilesPerTenant is tokenization.ts MAX_PROFILES_PER_TENANT.
const MaxProfilesPerTenant = 100

// maxGenericLength is tokenization.ts MAX_GENERIC_LENGTH.
const maxGenericLength = 4096

// DataTypes is tokenization.ts dataTypes.
var DataTypes = []string{"card", "ssn", "email", "phone", "generic"}

// DefaultMask is tokenization.ts defaultMask: the mask a data type gets when none is named.
var DefaultMask = struct {
	Card    string
	Ssn     string
	Email   string
	Phone   string
	Generic string
}{"last4", "last4", "email", "last4", "full"}

// MaskStyles is tokenization.ts maskStyles: the masks each data type may use (a style meant for one kind of value can
// reveal most of another).
var MaskStyles = map[string][]string{
	"card":    {"last4", "first6last4", "full"},
	"ssn":     {"last4", "full"},
	"email":   {"email", "full"},
	"phone":   {"last4", "full"},
	"generic": {"full", "last4"},
}

// ProtectionActions is tokenization.ts protectionActions.
var ProtectionActions = struct {
	Read       string
	Manage     string
	Tokenize   string
	Detokenize string
	Mask       string
	Delete     string
}{"iam:protection:read", "iam:protection:manage", "iam:protection:tokenize", "iam:protection:detokenize", "iam:protection:mask", "iam:protection:delete"}

var profileNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// ProfileName (tokenization.ts profileName) validates a profile name.
func ProfileName(value any) (result string, err error) {
	name, err := Text(value, "profile", 64)
	if err != nil {
		return "", err
	}
	if !profileNamePattern.MatchString(name) {
		return "", invalidInput("Profile names are lowercase letters, digits and hyphens, starting with a letter")
	}
	return name, nil
}

// SummarizeProfile (tokenization.ts summarizeProfile) is the public form of a profile record.
func SummarizeProfile(profile *core.Object) (result *core.Object, err error) {
	tokens := profile.Get("tokens")
	if nullish(tokens) {
		tokens = 0.0
	}
	summary := core.NewObject(
		"id", profile.Get("id"),
		"tenantId", profile.Get("tenantId"),
		"name", profile.Get("name"),
		"dataType", profile.Get("dataType"),
		"format", profile.Get("format"),
		"deterministic", profile.Get("deterministic"),
		"keyId", profile.Get("keyId"),
		"mask", profile.Get("mask"),
		"tokens", tokens,
		"createdAt", profile.Get("createdAt"),
		"createdBy", profile.Get("createdBy"),
		"updatedAt", profile.Get("updatedAt"),
	)
	if description := profile.Get("description"); !isUndefined(description) {
		summary.Set("description", description)
	}
	if retention := profile.Get("retentionDays"); !isUndefined(retention) {
		summary.Set("retentionDays", retention)
	}
	return summary, nil
}

// MaskStyle (tokenization.ts maskStyle) validates a mask style for a data type; name defaults to "mask".
func MaskStyle(typeValue string, value any, name string) (result string, err error) {
	if name == "" {
		name = "mask"
	}
	styles, known := MaskStyles[typeValue]
	if !known {
		return "", &core.TypeError{Message: "Cannot read properties of undefined (reading 'includes')"}
	}
	style, isString := value.(string)
	if !isString || !containsString(styles, style) {
		return "", invalidInput(name + " must be one of " + strings.Join(styles, ", ") + " for " + typeValue + " values")
	}
	return style, nil
}

// NeedsDeterministic (tokenization.ts needsDeterministic): Format-preserving `ssn` and `phone` tokens keep the last
// four digits, leaving few random ones (10,000 tokens per last four of a social security number): issuing a new
// token on every call would use them up, so these profiles are deterministic.
func NeedsDeterministic(typeValue string, format string) (result bool, err error) {
	return format == "format-preserving" && (typeValue == "ssn" || typeValue == "phone"), nil
}

// ---------------------------------------------------------------------------------------------------------------
// Values

// luhnValid is the Luhn check over a string of ASCII digits.
func luhnValid(digits string) bool {
	sum := 0
	for index := 0; index < len(digits); index++ {
		digit := int(digits[len(digits)-1-index] - '0')
		if index%2 == 1 {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}

// tokenizationControl is CONTROL: control characters other than tab and line feed, DEL and the C1 range included.
func tokenizationControl(s string) bool {
	for _, r := range s {
		if r <= 0x08 || (r >= 0x0b && r <= 0x1f) || (r >= 0x7f && r <= 0x9f) {
			return true
		}
	}
	return false
}

// tokenizationBidi is BIDI: bidirectional formatting controls, which make text display as something other than
// what it is.
func tokenizationBidi(s string) bool {
	for _, r := range s {
		if r == 0x061c || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return true
		}
	}
	return false
}

// loneSurrogate is LONE_SURROGATE: an unpaired surrogate (a WTF-8 surrogate sequence; a high one directly followed
// by a low one is a pair, as JavaScript reads it). Storage turns each into U+FFFD, so different values would share a
// token.
func loneSurrogate(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != 0xED || s[i+1] < 0xA0 {
			continue
		}
		if s[i+1] <= 0xAF && i+5 < len(s) && s[i+3] == 0xED && s[i+4] >= 0xB0 && s[i+4] <= 0xBF {
			i += 5
			continue
		}
		return true
	}
	return false
}

// stripCharacters is value.replace(/[...]/g, ”): drops JavaScript whitespace and the given ASCII characters.
func stripCharacters(value string, extra string) string {
	var b strings.Builder
	for _, piece := range core.CodePoints(value) {
		if len(piece) == 1 && strings.IndexByte(extra, piece[0]) >= 0 {
			continue
		}
		if r, ok := codePointRune(piece); ok && isJSWhitespace(r) {
			continue
		}
		b.WriteString(piece)
	}
	return b.String()
}

// isJSWhitespace is the JavaScript \s class.
func isJSWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

var (
	cardDigitsPattern  = regexp.MustCompile(`^[0-9]{12,19}$`)
	ssnDigitsPattern   = regexp.MustCompile(`^[0-9]{9}$`)
	phoneDigitsPattern = regexp.MustCompile(`^\+?[0-9]{7,15}$`)
	tokenEmailPattern  = regexp.MustCompile(`^[^` + jsWhitespace + `@<>()\[\],;:"\\]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$`)
)

// NormalizeValue (tokenization.ts normalizeValue): Validates and normalizes a value for its data type: card numbers
// to their digits (12 to 19, Luhn-valid), US social security numbers to `NNN-NN-NNNN`, email addresses to NFC
// lowercase, phone numbers to `+digits` or digits (7 to 15, compared as written, so give them in E.164), and
// anything else to NFC (up to 4096 characters of well-formed text without control or bidirectional formatting
// characters; tab and line feed are allowed).
func NormalizeValue(typeValue string, value any) (result string, err error) {
	text, isString := value.(string)
	if !isString {
		return "", invalidInput("Every value must be a string")
	}
	invalid := func(what string) error { return invalidInput("Not a valid " + what) }
	switch typeValue {
	case "card":
		digits := stripCharacters(text, "-")
		if !cardDigitsPattern.MatchString(digits) || !luhnValid(digits) {
			return "", invalid("card number")
		}
		return digits, nil
	case "ssn":
		digits := stripCharacters(text, "-")
		if !ssnDigitsPattern.MatchString(digits) {
			return "", invalid("social security number")
		}
		return digits[:3] + "-" + digits[3:5] + "-" + digits[5:], nil
	case "email":
		if loneSurrogate(text) {
			return "", invalid("email address")
		}
		email := core.JSLower(norm.NFC.String(core.JSTrim(text)))
		if utf16Len(email) > 254 || tokenizationControl(email) || tokenizationBidi(email) || !tokenEmailPattern.MatchString(email) {
			return "", invalid("email address")
		}
		return email, nil
	case "phone":
		compact := stripCharacters(text, "().-")
		if !phoneDigitsPattern.MatchString(compact) {
			return "", invalid("phone number")
		}
		return compact, nil
	case "generic":
		refuse := func() error {
			return invalidInput("Values are 1 to " + strconv.Itoa(maxGenericLength) +
				" characters of well-formed text without control or bidirectional formatting characters")
		}
		if loneSurrogate(text) || tokenizationControl(text) || tokenizationBidi(text) {
			return "", refuse()
		}
		normalized := norm.NFC.String(text)
		if normalized == "" || utf16Len(normalized) > maxGenericLength {
			return "", refuse()
		}
		return normalized, nil
	}
	return "", nil
}

// ---------------------------------------------------------------------------------------------------------------
// Tokens

const (
	tokenBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	tokenLower  = "abcdefghijklmnopqrstuvwxyz"
	tokenUpper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	tokenDigits = "0123456789"
)

// cryptoRandomInt is crypto.randomInt(max): a uniform draw from [0, max).
func cryptoRandomInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return int(n.Int64())
}

// pick draws length characters of an ASCII alphabet.
func pick(alphabet string, length int) string {
	if length <= 0 {
		return ""
	}
	out := make([]byte, length)
	for index := range out {
		out[index] = alphabet[cryptoRandomInt(len(alphabet))]
	}
	return string(out)
}

func randomDigits(length int) string { return pick(tokenDigits, length) }

// codePointRune is the code point of one element of core.CodePoints (an unpaired surrogate is none of the classes).
func codePointRune(piece string) (rune, bool) {
	if len(piece) == 3 && piece[0] == 0xED && piece[1] >= 0xA0 {
		return 0, false
	}
	r, _ := utf8.DecodeRuneInString(piece)
	return r, true
}

// maskable is MASKABLE: letters and digits of any script (what masks hide and format-preserving tokens replace).
func maskable(piece string) bool {
	r, ok := codePointRune(piece)
	return ok && unicode.In(r, unicode.L, unicode.M, unicode.N)
}

// letter is LETTER (/[\p{L}\p{M}]/u).
func letter(piece string) bool {
	r, ok := codePointRune(piece)
	return ok && unicode.In(r, unicode.L, unicode.M)
}

// capital is CAPITAL (/[\p{Lu}\p{Lt}]/u).
func capital(piece string) bool {
	r, ok := codePointRune(piece)
	return ok && unicode.In(r, unicode.Lu, unicode.Lt)
}

// numeral is /\p{N}/u.
func numeral(piece string) bool {
	r, ok := codePointRune(piece)
	return ok && unicode.In(r, unicode.N)
}

// ssnTokenGroups are the group digits no SSN or ITIN has with a 9XX area (ITIN groups are 50-65, 70-88, 90-92 and
// 94-99).
var ssnTokenGroups = func() []string {
	var groups []string
	for group := 0; group < 100; group++ {
		if (group >= 1 && group <= 49) || (group >= 66 && group <= 69) || group == 89 || group == 93 {
			text := strconv.Itoa(group)
			if len(text) < 2 {
				text = "0" + text
			}
			groups = append(groups, text)
		}
	}
	return groups
}()

// lastFour is value.slice(-4) over ASCII text.
func lastFour(value string) string {
	if len(value) <= 4 {
		return value
	}
	return value[len(value)-4:]
}

func formatPreserving(typeValue string, value string) string {
	switch typeValue {
	case "card":
		return randomDigits(len(value)-4) + lastFour(value)
	case "ssn":
		return "9" + randomDigits(2) + "-" + ssnTokenGroups[cryptoRandomInt(len(ssnTokenGroups))] + "-" + lastFour(value)
	case "email":
		return pick(tokenLower+tokenDigits, 16) + "@" + value[strings.LastIndex(value, "@")+1:]
	case "phone":
		plus := ""
		if strings.HasPrefix(value, "+") {
			plus = "+"
		}
		body := value[len(plus):]
		return plus + randomDigits(len(body)-4) + lastFour(body)
	case "generic":
		var b strings.Builder
		for _, character := range core.CodePoints(value) {
			switch {
			case capital(character):
				b.WriteString(pick(tokenUpper, 1))
			case letter(character):
				b.WriteString(pick(tokenLower, 1))
			case numeral(character):
				b.WriteString(randomDigits(1))
			default:
				b.WriteString(character)
			}
		}
		return b.String()
	}
	return "undefined"
}

// NewToken (tokenization.ts newToken): A new token for a normalized value; never the value itself. Random tokens are
// `tok_` and 22 base62 characters (131 bits). Format-preserving tokens keep what systems validate or display: -
// card: the same length and last four digits, but failing the Luhn check, so a token is never a card number; - ssn:
// `9XX-`, group digits outside the ITIN ranges and the last four digits, so a token is never an SSN or ITIN; -
// email: a random local part at the same domain; - phone: the same length, leading `+` and last four digits; -
// generic: the same length in characters, each letter (of any script) replaced by an ASCII letter (capitals by
// capitals), each digit by a digit, the rest kept.
func NewToken(typeValue string, format string, value string) (result string, err error) {
	if format == "random" {
		return "tok_" + pick(tokenBase62, 22), nil
	}
	for {
		candidate := formatPreserving(typeValue, value)
		if candidate != value && (typeValue != "card" || !luhnValid(candidate)) {
			return candidate, nil
		}
	}
}

// FormatPreservingSpace (tokenization.ts formatPreservingSpace): Format-preserving generic tokens need enough random
// positions to be unguessable and unique.
func FormatPreservingSpace(typeValue string, value string) (result bool, err error) {
	if typeValue != "generic" {
		return true, nil
	}
	count := 0
	for _, character := range core.CodePoints(value) {
		if maskable(character) {
			count++
		}
	}
	return count >= 12, nil
}

// TokenKey (tokenization.ts tokenKey): Where a token is unique: its profile, by hash (a format-preserving token can
// be long).
func TokenKey(profileID string, token string) (result string, err error) {
	digest := sha256.Sum256(utf8Bytes(token))
	return "token:" + profileID + ":" + base64url(digest[:]), nil
}

// MaskValue (tokenization.ts maskValue): A masked form of a normalized value, for display. A mask never shows more
// than half of a value's letters and digits, except the first six and last four digits of a card number of 15 or
// more digits (what PCI DSS allows showing); on a shorter card number `first6last4` shows the last four only.
// Letters and digits of every script are hidden.
func MaskValue(typeValue string, style string, value string) (result string, err error) {
	characters := core.CodePoints(value)
	total := 0
	for _, character := range characters {
		if maskable(character) {
			total++
		}
	}
	half := total / 2
	hide := func(keepStart, keepEnd int, capped bool) string {
		if capped && keepStart+keepEnd > half {
			keepStart = 0
			keepEnd = min(keepEnd, half)
		}
		seen := 0
		var b strings.Builder
		for _, character := range characters {
			if !maskable(character) {
				b.WriteString(character)
				continue
			}
			position := seen
			seen++
			if position < keepStart || position >= total-keepEnd {
				b.WriteString(character)
			} else {
				b.WriteByte('*')
			}
		}
		return b.String()
	}
	switch style {
	case "last4":
		return hide(0, 4, true), nil
	case "first6last4":
		if typeValue == "card" && total >= 15 {
			return hide(6, 4, false), nil
		}
		return hide(0, 4, true), nil
	case "email":
		at := strings.LastIndex(value, "@")
		if at < 1 {
			return hide(0, 0, true), nil
		}
		local := core.CodePoints(value[:at])
		first := "*"
		if len(local) >= 4 {
			first = local[0]
		}
		// The first character only when most of the local part stays hidden.
		return first + "***@" + value[at+1:], nil
	case "full":
		return hide(0, 0, true), nil
	}
	return "undefined", nil
}

// TokenizationFingerprint (tokenization.ts fingerprint): HMAC-SHA256 of the value under the lookup key, base64url.
func TokenizationFingerprint(key []byte, value string) (result string, err error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(utf8Bytes(value))
	return base64url(mac.Sum(nil)), nil
}

// LookupContext (tokenization.ts lookupContext): The encryption context of a profile's lookup key (batch data keys
// are bound to `{ protection }` alone).
func LookupContext(profileID string) (result *core.Object, err error) {
	return core.NewObject("protection", profileID, "use", "lookup"), nil
}

// protectionAad is the additional data a stored value is bound to.
func protectionAad(tenantID, profileID, token string) []byte {
	return utf8Bytes("protection:" + tenantID + ":" + profileID + ":" + token)
}

// SealValue (tokenization.ts sealValue): AES-256-GCM under the batch data key, bound to tenant, profile and token;
// base64url(iv | tag | ciphertext).
func SealValue(dataKey []byte, tenantID string, profileID string, token string, value string) (result string, err error) {
	if len(dataKey) != 32 {
		return "", errors.New("Invalid key length")
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, utf8Bytes(value), protectionAad(tenantID, profileID, token))
	ciphertext, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	out := make([]byte, 0, len(sealed)+12)
	out = append(out, iv...)
	out = append(out, tag...)
	out = append(out, ciphertext...)
	return base64url(out), nil
}

// OpenValue (tokenization.ts openValue): Opens a stored value; a record that fails authentication was altered in
// storage.
func OpenValue(dataKey []byte, record *core.Object) (result string, err error) {
	unavailable := core.NewIamError("KEY_MATERIAL_UNAVAILABLE", "A stored value cannot be opened", 500)
	sealed, isString := record.Get("sealed").(string)
	if !isString || len(dataKey) != 32 {
		return "", unavailable
	}
	bytes := nodeBase64Decode(sealed)
	if len(bytes) < 28 {
		return "", unavailable
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", unavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", unavailable
	}
	combined := append(append([]byte(nil), bytes[28:]...), bytes[12:28]...)
	aad := protectionAad(jsString(record.Get("tenantId")), jsString(record.Get("profileId")), jsString(record.Get("token")))
	plain, err := gcm.Open(nil, bytes[:12], combined, aad)
	if err != nil {
		return "", unavailable
	}
	return decodeUTF8(plain), nil
}
