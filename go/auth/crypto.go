package auth

// Port of packages/auth/src/crypto.ts: identifiers, opaque tokens, token hashes, prefixed credential tokens and
// sealed (AES-256-GCM) values. Every format is byte-compatible with the TypeScript implementation.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// randomBytes is crypto.randomBytes.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("better-iam: crypto/rand failed: " + err.Error())
	}
	return b
}

// NewID is `${prefix}_${randomBytes(16).toString('base64url')}`; the prefix defaults to "id".
func NewID(prefix ...string) string {
	p := "id"
	if len(prefix) > 0 {
		p = prefix[0]
	}
	return p + "_" + base64url(randomBytes(16))
}

// NewToken is 32 random bytes as base64url (43 characters).
func NewToken() string { return base64url(randomBytes(32)) }

// HashToken is the lowercase hex SHA-256 of the UTF-8 token.
func HashToken(token string) string {
	digest := sha256.Sum256(utf8Bytes(token))
	return hex.EncodeToString(digest[:])
}

// CredentialTokenType is the type part of a prefixed credential token: ses (user and impersonation sessions), key
// (API keys), rol (role sessions, including web identity), sts (session tokens) and dlg (delegated agent sessions).
type CredentialTokenType = string

// CredentialTokenKinds maps each credential token type to the session kind it must resolve to; the stored kind
// stays authoritative.
var CredentialTokenKinds = map[CredentialTokenType]string{
	"ses": "user",
	"key": "api-key",
	"rol": "role",
	"sts": "session-token",
	"dlg": "delegated",
}

// CredentialTokenScanPattern is a pattern secret scanners can use to find better-iam credential tokens in text. It
// needs lookbehind support (Go's regexp has none); without it, use `biam_(ses|key|rol|sts|dlg)_[A-Za-z0-9_-]{49}`
// with explicit boundary rules.
const CredentialTokenScanPattern = `(?<![A-Za-z0-9_-])biam_(?:ses|key|rol|sts|dlg)_[A-Za-z0-9_-]{49}(?![A-Za-z0-9_-])`

var credentialTokenPattern = regexp.MustCompile(`^biam_(ses|key|rol|sts|dlg)_([A-Za-z0-9_-]{43})([A-Za-z0-9_-]{6})$`)

// credentialTokenCheck is the base64url of the big-endian CRC-32 (IEEE, as zlib computes it) of the token body.
func credentialTokenCheck(body string) string {
	var check [4]byte
	binary.BigEndian.PutUint32(check[:], crc32.ChecksumIEEE(utf8Bytes(body)))
	return base64url(check[:])
}

// NewCredentialToken returns a new opaque credential token: `biam_<type>_` + 43 random base64url characters + a
// 6-character CRC-32 checksum (58 characters in all). The checksum lets scanners and the server reject garbage
// early; it authenticates nothing.
func NewCredentialToken(tokenType CredentialTokenType) (string, error) {
	if _, ok := CredentialTokenKinds[tokenType]; !ok {
		return "", core.NewIamError("INVALID_INPUT", "Unknown credential token type")
	}
	body := "biam_" + tokenType + "_" + NewToken()
	return body + credentialTokenCheck(body), nil
}

// mustCredentialToken is NewCredentialToken for the built-in types.
func mustCredentialToken(tokenType CredentialTokenType) string {
	token, err := NewCredentialToken(tokenType)
	if err != nil {
		panic(err)
	}
	return token
}

// ParseCredentialToken parses a prefixed credential token: its type when the shape and checksum match. The type
// is a routing hint only; authorization always uses the stored session.
func ParseCredentialToken(value string) (CredentialTokenType, bool) {
	match := credentialTokenPattern.FindStringSubmatch(value)
	if match == nil {
		return "", false
	}
	body := value[:len(value)-6]
	if credentialTokenCheck(body) != match[3] {
		return "", false
	}
	return match[1], true
}

// DefaultSealContext is the additional data sealed values use when no context is given.
const DefaultSealContext = "better-iam"

func sealKey(secret string) []byte {
	key := sha256.Sum256(utf8Bytes(secret))
	return key[:]
}

func contextOf(context []string) string {
	if len(context) > 0 {
		return context[0]
	}
	return DefaultSealContext
}

// EncryptSecret seals a value with AES-256-GCM: key SHA-256(secret), a random 96-bit IV, the context as additional
// data; the result is base64url(iv).base64url(tag).base64url(ciphertext). The application secret must be a
// high-entropy, stable secret. The context defaults to "better-iam".
func EncryptSecret(value, secret string, context ...string) string {
	return sealWithIV(value, secret, contextOf(context), randomBytes(12))
}

// sealWithIV is EncryptSecret with a given IV (vectors only).
func sealWithIV(value, secret, context string, iv []byte) string {
	block, err := aes.NewCipher(sealKey(secret))
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	sealed := gcm.Seal(nil, iv, utf8Bytes(value), utf8Bytes(context))
	ciphertext, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	return base64url(iv) + "." + base64url(tag) + "." + base64url(ciphertext)
}

// OpenedSecret is what OpenSecret returns: the value, and the index of the secret that authenticated it (0 is the
// current secret; higher indexes are previous ones kept during a rotation).
type OpenedSecret struct {
	Value string `json:"value"`
	Index int    `json:"index"`
}

// OpenSecret opens a sealed value with the first of secrets that authenticates it; false when none does. Only
// exactly what EncryptSecret writes is accepted: three parts, a 96-bit IV and a full 128-bit tag.
func OpenSecret(value string, secrets []string, context ...string) (OpenedSecret, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return OpenedSecret{}, false
	}
	iv, tag, encrypted := nodeBase64Decode(parts[0]), nodeBase64Decode(parts[1]), nodeBase64Decode(parts[2])
	if len(iv) != 12 || len(tag) != 16 {
		return OpenedSecret{}, false
	}
	aad := utf8Bytes(contextOf(context))
	sealed := append(append([]byte(nil), encrypted...), tag...)
	for index, secret := range secrets {
		block, err := aes.NewCipher(sealKey(secret))
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		plain, err := gcm.Open(nil, iv, sealed, aad)
		if err != nil {
			continue
		}
		return OpenedSecret{Value: decodeUTF8(plain), Index: index}, true
	}
	return OpenedSecret{}, false
}

// DecryptSecret opens a sealed value with the current secret or, during a rotation, a previous one; it fails with
// INVALID_SEALED_VALUE.
func DecryptSecret(value string, secrets []string, context ...string) (string, error) {
	opened, ok := OpenSecret(value, secrets, context...)
	if !ok {
		return "", core.NewIamError("INVALID_SEALED_VALUE", "Invalid sealed value")
	}
	return opened.Value, nil
}
