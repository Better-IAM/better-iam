package auth

// Port of packages/auth/src/password-policy.ts.

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/Better-IAM/better-iam/go/core"
)

// PasswordCheckContext is what a custom password rule sees besides the password.
type PasswordCheckContext struct {
	TenantID string
	// Identity holds id, email and name (when known).
	Identity *core.Object
}

// PasswordPolicyOptions is the deployment-wide password screening; tenant rules (authPolicy.password*) add to it.
type PasswordPolicyOptions struct {
	// BlockCommonPasswords rejects well-known, keyboard-walk, sequential and low-variety passwords (default true).
	BlockCommonPasswords *bool
	// IsBreached returns true when the password appears in a breach corpus; PwnedPasswords provides a k-anonymity
	// Have I Been Pwned client.
	IsBreached func(ctx context.Context, password string) (bool, error)
	// Check is a custom rule: return a message to reject the password, or "" to accept it.
	Check func(ctx context.Context, password string, context PasswordCheckContext) (string, error)
}

var commonPasswords = map[string]bool{}

func init() {
	for _, password := range []string{
		"password1234", "password12345", "password123456", "passw0rd1234", "p@ssw0rd1234", "p@ssword1234",
		"password!123", "passwordpassword", "iloveyou1234", "letmein12345", "welcome12345", "welcome123456",
		"changeme1234", "changeme12345", "administrator", "admin1234567", "adminadmin123", "football1234",
		"baseball1234", "princess1234", "sunshine1234", "superman1234", "trustno11234", "monkey123456",
		"dragon123456", "master123456", "correcthorsebatterystaple", "correct horse battery staple",
		"thequickbrownfox", "letmeinletmein", "secretpassword", "mypassword123", "default12345", "computer1234",
		"internet1234", "whatever1234", "starwars1234", "pokemon12345", "summer2024!!", "winter2024!!",
		"spring2025!!", "autumn2025!!",
	} {
		commonPasswords[password] = true
	}
}

var passwordSequences = []string{
	"01234567890123456789",
	"abcdefghijklmnopqrstuvwxyz",
	"qwertyuiopasdfghjklzxcvbnm",
	"qwertzuiopasdfghjklyxcvbnm",
	"azertyuiopqsdfghjklmwxcvbn",
	"1qaz2wsx3edc4rfv5tgb6yhn",
	"!@#$%^&*()_+",
}

// CharacterClasses counts the classes a password uses: lowercase, uppercase, digit, and everything else (ASCII
// ranges, as the TypeScript regular expressions).
func CharacterClasses(password string) int {
	var lower, upper, digit, other bool
	for _, r := range runes(password) {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	count := 0
	for _, used := range []bool{lower, upper, digit, other} {
		if used {
			count++
		}
	}
	return count
}

// IsCommonPassword is the built-in weak-password screen: common passwords, keyboard walks and sequences, and low
// variety.
func IsCommonPassword(password string) bool {
	lower := core.JSLower(password)
	if commonPasswords[lower] {
		return true
	}
	var stripped strings.Builder
	for _, unit := range core.ToUTF16(lower) {
		if (unit >= 'a' && unit <= 'z') || (unit >= '0' && unit <= '9') || unit == ' ' {
			stripped.WriteByte(byte(unit))
		}
	}
	if commonPasswords[stripped.String()] {
		return true
	}
	distinct := map[string]bool{}
	for _, point := range core.CodePoints(lower) {
		distinct[point] = true
	}
	if len(distinct) < 5 {
		return true
	}
	length := core.UTF16Len(lower)
	for _, sequence := range passwordSequences {
		times := (length*2+len(sequence)-1)/len(sequence) + 1
		forward := strings.Repeat(sequence, times)
		reversed := []byte(forward)
		for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
			reversed[i], reversed[j] = reversed[j], reversed[i]
		}
		if strings.Contains(forward, lower) || strings.Contains(string(reversed), lower) {
			return true
		}
	}
	return false
}

// personalTokens are the pieces of the identity (email local part, name words) at least four characters long.
func personalTokens(identity *core.Object) []string {
	tokens := map[string]bool{}
	if email, ok := identity.String("email"); ok {
		local, _, _ := strings.Cut(email, "@")
		local = core.JSLower(local)
		if local != "" {
			tokens[local] = true
			for _, part := range splitBy(local, func(r rune) bool {
				return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
			}) {
				tokens[part] = true
			}
		}
	}
	if name, ok := identity.String("name"); ok {
		for _, part := range splitBy(core.JSLower(name), func(r rune) bool {
			return !(unicode.IsLetter(r) || unicode.In(r, unicode.Nd, unicode.Nl, unicode.No))
		}) {
			tokens[part] = true
		}
	}
	var out []string
	for token := range tokens {
		if core.UTF16Len(token) >= 4 {
			out = append(out, token)
		}
	}
	return out
}

// splitBy is String#split with a /[class]+/ separator: empty pieces at the ends are kept.
func splitBy(s string, separator func(r rune) bool) []string {
	var parts []string
	var current strings.Builder
	inSeparator := false
	for i := 0; i < len(s); {
		r, size := decodeWTF8(s, i)
		if separator(r) {
			if !inSeparator {
				parts = append(parts, current.String())
				current.Reset()
			}
			inSeparator = true
		} else {
			inSeparator = false
			current.WriteString(s[i : i+size])
		}
		i += size
	}
	return append(parts, current.String())
}

// AssertPasswordRules enforces the synchronous rules (tenant length, character classes, personal information, the
// built-in screen). policy is the tenant's authPolicy object (or nil); identity holds email and name (or nil).
// History, breach, and custom checks run in the auth service because they are asynchronous or need storage.
func AssertPasswordRules(password string, policy *core.Object, options *PasswordPolicyOptions, identity *core.Object) error {
	if minimum, ok := num(policy, "minPasswordLength"); ok && float64(core.UTF16Len(password)) < minimum {
		return core.NewIamError("WEAK_PASSWORD", "Password must contain at least "+core.NumberString(minimum)+" characters in this organization")
	}
	if classes, ok := num(policy, "passwordMinClasses"); ok && float64(CharacterClasses(password)) < classes {
		return core.NewIamError("WEAK_PASSWORD", "Password must mix at least "+core.NumberString(classes)+" of: lowercase, uppercase, digits, symbols")
	}
	if flag(policy, "passwordRejectPersonalInfo") && identity != nil {
		lower := core.JSLower(password)
		for _, token := range personalTokens(identity) {
			if strings.Contains(lower, token) {
				return core.NewIamError("WEAK_PASSWORD", "Password must not contain your name or email address")
			}
		}
	}
	block := true
	if options != nil && options.BlockCommonPasswords != nil {
		block = *options.BlockCommonPasswords
	}
	if block && IsCommonPassword(password) {
		return core.NewIamError("WEAK_PASSWORD", "Password is too common or predictable")
	}
	return nil
}

// PwnedPasswordsOptions configures PwnedPasswords.
type PwnedPasswordsOptions struct {
	// Threshold is the minimum breach count that rejects a password (default 1).
	Threshold *float64
	// FailClosed rejects (PASSWORD_CHECK_UNAVAILABLE, 503) instead of accepting when the service is unreachable.
	FailClosed bool
	// TimeoutMs bounds each request (default 3000).
	TimeoutMs int64
	// Endpoint defaults to https://api.pwnedpasswords.com/range/.
	Endpoint string
	// Client performs the request (default http.DefaultClient).
	Client *http.Client
}

// PwnedPasswords is a Have I Been Pwned "range" client (k-anonymity): it hashes the password with SHA-1, sends only
// the first five hex characters, and matches the returned suffixes locally. Network failures accept the password
// unless FailClosed.
func PwnedPasswords(options PwnedPasswordsOptions) func(ctx context.Context, password string) (bool, error) {
	threshold := 1.0
	if options.Threshold != nil {
		threshold = *options.Threshold
	}
	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = "https://api.pwnedpasswords.com/range/"
	}
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}
	client := options.Client
	if client == nil {
		client = http.DefaultClient
	}
	timeout := options.TimeoutMs
	if timeout == 0 {
		timeout = 3_000
	}
	return func(ctx context.Context, password string) (bool, error) {
		digest := sha1.Sum(utf8Bytes(password))
		hexDigest := strings.ToUpper(hex.EncodeToString(digest[:]))
		prefix, suffix := hexDigest[:5], hexDigest[5:]
		found, err := func() (bool, error) {
			ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+prefix, nil)
			if err != nil {
				return false, err
			}
			request.Header.Set("add-padding", "true")
			response, err := client.Do(request)
			if err != nil {
				return false, err
			}
			defer response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode > 299 {
				return false, errors.New("HTTP " + response.Status)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				return false, err
			}
			for _, line := range strings.Split(decodeUTF8(body), "\n") {
				line = core.JSTrim(strings.TrimSuffix(line, "\r"))
				candidate, count, hasCount := strings.Cut(line, ":")
				if before, _, cut := strings.Cut(count, ":"); cut {
					count = before
				}
				if strings.ToUpper(candidate) == suffix && hasCount && jsNumber(count) >= threshold {
					return true, nil
				}
			}
			return false, nil
		}()
		if err != nil {
			if options.FailClosed {
				return false, core.NewIamError("PASSWORD_CHECK_UNAVAILABLE", "Password screening is unavailable", 503)
			}
			return false, nil
		}
		return found, nil
	}
}
