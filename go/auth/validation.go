package auth

// Port of packages/auth/src/validation.ts. Values are `unknown` in TypeScript (request bodies), so the validators
// take any value of the core model.

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Better-IAM/better-iam/go/core"
)

// Text requires a nonempty string of at most max UTF-16 code units (512 when max is 0).
func Text(value any, field string, max ...int) (string, error) {
	limit := 512
	if len(max) > 0 {
		limit = max[0]
	}
	s, ok := value.(string)
	if !ok || s == "" || core.UTF16Len(s) > limit {
		return "", core.NewIamError("INVALID_INPUT", field+" must be a nonempty string of at most "+strconv.Itoa(limit)+" characters")
	}
	return s, nil
}

// controlCharacter reports C0, DEL and C1 controls and the Unicode line/paragraph separators.
func controlCharacter(r rune) bool {
	return r <= 0x1f || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029
}

// replaceControls replaces every control character (controlCharacter) with a space.
func replaceControls(s string) string {
	if !strings.ContainsFunc(s, controlCharacter) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := decodeWTF8(s, i)
		if controlCharacter(r) {
			b.WriteByte(' ')
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// decodeWTF8 decodes one code point (an unpaired surrogate as its unit value) at s[i].
func decodeWTF8(s string, i int) (rune, int) {
	c := s[i]
	if c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2]&0xC0 == 0x80 {
		return 0xD000 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F), 3
	}
	return utf8.DecodeRuneInString(s[i:])
}

// DisplayName is a display name: control and line-separator characters become spaces, so a name (from sign-up, an
// invitation, or an identity provider) can never break an email header or forge a line in a message.
func DisplayName(value any, max ...int) (string, error) {
	limit := 256
	if len(max) > 0 {
		limit = max[0]
	}
	name, err := Text(value, "name", limit)
	if err != nil {
		return "", err
	}
	return Text(core.JSTrim(replaceControls(name)), "name", limit)
}

// Email normalizes (trim, lowercase) and validates an email address.
func Email(value any) (string, error) {
	text, err := Text(value, "email", 254)
	if err != nil {
		return "", err
	}
	normalized := core.JSLower(core.JSTrim(text))
	if !emailShape(normalized) {
		return "", core.NewIamError("INVALID_INPUT", "Invalid email")
	}
	return normalized, nil
}

// emailShape is /^[^\s@]+@[^\s@]+\.[^\s@]+$/.
func emailShape(s string) bool {
	for _, r := range runes(s) {
		if jsSpace(r) {
			return false
		}
	}
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || strings.Contains(domain, "@") {
		return false
	}
	for index := 1; index < len(domain)-1; index++ {
		if domain[index] == '.' {
			return true
		}
	}
	return false
}

var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// Phone validates an E.164 phone number.
func Phone(value any) (string, error) {
	normalized, err := Text(value, "phone", 16)
	if err != nil {
		return "", err
	}
	if !phonePattern.MatchString(normalized) {
		return "", core.NewIamError("INVALID_INPUT", "Phone must use E.164 format")
	}
	return normalized, nil
}

// Password requires a string of 12 to 1024 characters.
func Password(value any) (string, error) {
	result, err := Text(value, "password", 1024)
	if err != nil {
		return "", err
	}
	if core.UTF16Len(result) < 12 {
		return "", core.NewIamError("WEAK_PASSWORD", "Password must contain at least 12 characters")
	}
	return result, nil
}

// PublicIdentity is the identity without its password hash.
func PublicIdentity(identity *core.Object) *core.Object {
	safe := identity.Spread()
	safe.Delete("passwordHash")
	return safe
}

// PublicSession is a session without its secret-derived fields: tokenHash, and uniqueKey, which holds the same
// hash.
func PublicSession(session *core.Object) *core.Object {
	safe := session.Spread()
	safe.Delete("tokenHash")
	safe.Delete("uniqueKey")
	return safe
}
