package auth

// The auth-owned vectors of spec/vectors (generated from the TypeScript implementation): tokens, sealed secrets,
// password hashes, TOTP, and challenge digests.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

func input(c spectest.Case, key string) any { return c.Input.Get(key) }

func inputString(c spectest.Case, key string) string {
	value, _ := c.Input.Get(key).(string)
	return value
}

func outputObject(c spectest.Case) *core.Object {
	value, _ := c.Output.(*core.Object)
	return value
}

var tokenShape = regexp.MustCompile(`^biam_(ses|key|rol|sts|dlg)_[A-Za-z0-9_-]{49}$`)

func TestTokenVectors(t *testing.T) {
	file := spectest.Load(t, "tokens")
	checked := 0
	for _, c := range file.Cases {
		switch {
		case strings.HasPrefix(c.Name, "new ") && strings.Contains(c.Name, " token"):
			kind := inputString(c, "type")
			token, err := NewCredentialToken(kind)
			if spectest.IsError(c.Output) {
				spectest.Check(t, c, spectest.Outcome(token, err))
				checked++
				continue
			}
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			expected := outputObject(c)
			// The random body differs; the format, checksum and hash of the recorded token must reproduce.
			if len(token) != 58 || !tokenShape.MatchString(token) || !strings.HasPrefix(token, "biam_"+kind+"_") {
				t.Errorf("%s: malformed token %q", c.Name, token)
			}
			if parsed, ok := ParseCredentialToken(token); !ok || parsed != kind {
				t.Errorf("%s: fresh token does not parse", c.Name)
			}
			recorded := str(expected, "token")
			if check := credentialTokenCheck(str(expected, "body")); check != str(expected, "check") || str(expected, "body")+check != recorded {
				t.Errorf("%s: checksum %q, expected %q", c.Name, check, str(expected, "check"))
			}
			if HashToken(recorded) != str(expected, "hash") {
				t.Errorf("%s: hash mismatch", c.Name)
			}
			if parsed, ok := ParseCredentialToken(recorded); !ok || parsed != kind {
				t.Errorf("%s: recorded token does not parse", c.Name)
			}
			checked++
		case strings.HasPrefix(c.Name, "parse "):
			value, isString := input(c, "value").(string)
			var got any = core.Undefined
			if isString {
				if kind, ok := ParseCredentialToken(value); ok {
					got = core.NewObject("type", kind)
				}
			}
			spectest.Check(t, c, got)
			checked++
		case strings.HasPrefix(c.Name, "checksum of "):
			token := inputString(c, "token")
			check := credentialTokenCheck(token[:len(token)-6])
			kind, ok := ParseCredentialToken(token)
			var parsed any = core.Undefined
			if ok {
				parsed = core.NewObject("type", kind)
			}
			spectest.Check(t, c, core.NewObject("check", check, "parsed", parsed))
			checked++
		case strings.HasPrefix(c.Name, "hashToken "):
			hash := HashToken(inputString(c, "value"))
			spectest.Check(t, c, core.NewObject("authHashToken", hash, "serverHash", hash))
			checked++
		case c.Name == "newToken":
			token := NewToken()
			recorded, _ := c.Output.(string)
			if len(token) != len(recorded) || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(token) {
				t.Errorf("newToken %q does not match the shape of %q", token, recorded)
			}
			checked++
		case strings.HasPrefix(c.Name, "newId"):
			prefix := inputString(c, "prefix")
			var id string
			if prefix == "" {
				id = NewID()
				prefix = "id"
			} else {
				id = NewID(prefix)
			}
			recorded, _ := c.Output.(string)
			if !regexp.MustCompile(`^`+prefix+`_[A-Za-z0-9_-]{22}$`).MatchString(id) || len(id) != len(recorded) {
				t.Errorf("%s: %q does not match the shape of %q", c.Name, id, recorded)
			}
			checked++
		}
	}
	// Server-owned cases (server id/token, sameHash, offerToken/offerIdOf) are run by the server port.
	if checked != 34 {
		t.Errorf("checked %d token cases, expected 34", checked)
	}
	if CredentialTokenScanPattern != str(file.Notes, "credentialTokenScanPattern") {
		t.Error("credentialTokenScanPattern differs")
	}
	kinds, _ := file.Notes.Object("credentialTokenKinds")
	if kinds.Len() != len(CredentialTokenKinds) {
		t.Error("credentialTokenKinds differ")
	}
	kinds.Entries(func(key string, value any) bool {
		if CredentialTokenKinds[key] != value {
			t.Errorf("credentialTokenKinds[%s] = %q, expected %v", key, CredentialTokenKinds[key], value)
		}
		return true
	})
}

func secretsOf(value any) ([]string, bool) {
	switch v := value.(type) {
	case string:
		return []string{v}, true
	case []any:
		out := make([]string, len(v))
		for index, item := range v {
			out[index], _ = item.(string)
		}
		return out, true
	}
	return nil, false
}

func TestSecretVectors(t *testing.T) {
	for _, c := range spectest.Load(t, "secrets").Cases {
		context := []string{}
		if value, ok := input(c, "context").(string); ok {
			context = []string{value}
		}
		switch {
		case strings.HasPrefix(c.Name, "seal "):
			expected := outputObject(c)
			value, secret := inputString(c, "value"), inputString(c, "secret")
			key := sha256.Sum256(utf8Bytes(secret))
			if hex.EncodeToString(key[:]) != str(expected, "key") {
				t.Errorf("%s: key mismatch", c.Name)
			}
			iv, _ := base64.RawURLEncoding.DecodeString(str(expected, "iv"))
			if sealed := sealWithIV(value, secret, contextOf(context), iv); sealed != str(expected, "sealed") {
				t.Errorf("%s: sealed %q, expected %q", c.Name, sealed, str(expected, "sealed"))
			}
			if str(expected, "aad") != contextOf(context) {
				t.Errorf("%s: aad mismatch", c.Name)
			}
			if opened, ok := OpenSecret(EncryptSecret(value, secret, context...), []string{secret}, context...); !ok || opened.Value != value {
				t.Errorf("%s: round trip failed", c.Name)
			}
		case strings.HasPrefix(c.Name, "open "):
			secrets, _ := secretsOf(input(c, "secrets"))
			value, isString := input(c, "value").(string)
			var got any = core.Undefined
			if isString {
				if opened, ok := OpenSecret(value, secrets, context...); ok {
					got = core.NewObject("value", opened.Value, "index", opened.Index)
				}
			}
			spectest.Check(t, c, got)
		case strings.HasPrefix(c.Name, "decrypt "):
			secrets, _ := secretsOf(input(c, "secrets"))
			value, err := DecryptSecret(inputString(c, "value"), secrets, context...)
			spectest.Check(t, c, spectest.Outcome(value, err))
		default:
			t.Errorf("unhandled case %s", c.Name)
		}
	}
}

func TestPasswordVectors(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 at the production cost")
	}
	for _, c := range spectest.Load(t, "passwords").Cases {
		if strings.HasPrefix(c.Name, "verify") {
			ok, err := VerifyPassword(inputString(c, "phc"), inputString(c, "password"))
			spectest.Check(t, c, spectest.Outcome(ok, err))
			continue
		}
		params := DefaultArgon2Params
		if options, ok := input(c, "options").(*core.Object); ok {
			if kind := str(options, "type"); kind != "" {
				params.Type = kind
			}
			if value, ok := num(options, "memoryCost"); ok {
				params.MemoryCost = uint32(value)
			}
			if value, ok := num(options, "timeCost"); ok {
				params.TimeCost = uint32(value)
			}
			if value, ok := num(options, "parallelism"); ok {
				params.Parallelism = uint8(value)
			}
		}
		phc, _ := c.Output.(string)
		if expected := outputObject(c); expected != nil {
			phc = str(expected, "phc")
		}
		fields := strings.Split(phc, "$")
		salt, err := base64.RawStdEncoding.DecodeString(fields[4])
		if err != nil {
			t.Fatal(err)
		}
		got, err := HashPasswordWith(inputString(c, "password"), params, salt)
		if err != nil || got != phc {
			t.Errorf("%s: %q (%v), expected %q", c.Name, got, err, phc)
		}
		if ok, err := VerifyPassword(phc, inputString(c, "password")); !ok || err != nil {
			t.Errorf("%s: does not verify (%v)", c.Name, err)
		}
	}
}

const vectorSecret = "test-secret-32-characters-minimum-better-iam"

func TestTotpVectors(t *testing.T) {
	for _, c := range spectest.Load(t, "totp").Cases {
		secret := inputString(c, "secret")
		switch {
		case strings.HasPrefix(c.Name, "generateSecret"):
			generated := GenerateTotpSecret(20)
			recorded, _ := c.Output.(string)
			decoded, err := base32Decode(generated)
			if err != nil || len(generated) != len(recorded) || len(decoded) != 20 {
				t.Fatalf("generateSecret: %q", generated)
			}
			for _, b := range decoded {
				if b >= 0x80 {
					t.Fatalf("generateSecret keeps the high bit clear: %x", decoded)
				}
			}
			recordedBytes, _ := base32Decode(recorded)
			if base32Encode(recordedBytes) != recorded {
				t.Errorf("base32 round trip of %q", recorded)
			}
		case strings.HasPrefix(c.Name, "generate "):
			epoch, _ := num(c.Input, "epoch")
			code, err := GenerateTotp(secret, int64(epoch))
			spectest.Check(t, c, spectest.Outcome(code, err))
		case strings.HasPrefix(c.Name, "checkDelta"):
			epoch, _ := num(c.Input, "epoch")
			delta, ok, err := TotpCheckDelta(inputString(c, "code"), secret, int64(epoch), 1)
			var got any = nil
			if ok {
				got = float64(delta)
			}
			spectest.Check(t, c, spectest.Outcome(got, err))
		case strings.HasPrefix(c.Name, "keyuri"):
			spectest.Check(t, c, TotpKeyURI(inputString(c, "account"), inputString(c, "issuer"), secret))
		case strings.HasPrefix(c.Name, "checkTotp"):
			now, _ := num(c.Input, "now")
			lastUsed, _ := num(c.Input, "lastUsedStep")
			service := &Service{now: func() int64 { return int64(now) }, Secrets: []string{vectorSecret}}
			record := core.NewObject("identityId", "idn_01", "encryptedSecret", EncryptSecret(secret, vectorSecret, "mfa:idn_01"), "lastUsedStep", lastUsed)
			step, err := service.checkTotp(record, inputString(c, "code"))
			spectest.Check(t, c, spectest.Outcome(step, err))
		default:
			t.Errorf("unhandled case %s", c.Name)
		}
	}
}

func TestDerivationVectors(t *testing.T) {
	checked := 0
	for _, c := range spectest.Load(t, "derivations").Cases {
		if !strings.HasPrefix(c.Name, "digestChallenge") {
			continue // assertion keys, privacy subjects, fingerprints, nonces: server-owned
		}
		service := &Service{options: Options{Secret: inputString(c, "secret")}}
		spectest.Check(t, c, service.DigestChallenge(inputString(c, "tenantId"), inputString(c, "token")))
		checked++
	}
	if checked != 3 {
		t.Errorf("checked %d digestChallenge cases", checked)
	}
}
