package auth

// The parts of otplib 12 (authenticator preset: thirty-two base32 keys, HMAC-SHA1, 6 digits, 30-second steps) the
// MFA service uses: generateSecret, generate, checkDelta with a window, and keyuri. Quirks are kept on purpose, so
// secrets and codes are interchangeable with the TypeScript implementation: generateSecret clears the high bit of
// every random byte (the plugin encodes through an ASCII string), and keys shorter than the digest are padded by
// repetition.

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
)

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// thirty-two's decode table, indexed by character code - 0x30.
var base32Table = [...]byte{
	0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
}

// base32Encode is thirty-two's encode with the padding removed (otplib's keyEncoder).
func base32Encode(plain []byte) string {
	var out strings.Builder
	shift := 0
	for i := 0; i < len(plain); {
		current := int(plain[i])
		var digit int
		if shift > 3 {
			digit = current & (0xff >> shift)
			shift = (shift + 5) % 8
			next := 0
			if i+1 < len(plain) {
				next = int(plain[i+1])
			}
			digit = digit<<shift | next>>(8-shift)
			i++
		} else {
			digit = (current >> (8 - (shift + 5))) & 0x1f
			shift = (shift + 5) % 8
			if shift == 0 {
				i++
			}
		}
		out.WriteByte(base32Alphabet[digit])
	}
	return out.String()
}

// base32Decode is thirty-two's decode: case-insensitive, stopping at '='; characters past 'z' are an error.
func base32Decode(encoded string) ([]byte, error) {
	data := utf8Bytes(encoded)
	out := make([]byte, 0, (len(data)*5+7)/8)
	shift := 0
	plainChar := 0
	for _, c := range data {
		if c == '=' {
			break
		}
		index := int(c) - 0x30
		if index >= len(base32Table) {
			return nil, errors.New("Invalid input - it is not base32 encoded string")
		}
		digit := 0 // a character below '0' reads undefined in JavaScript, which bitwise operators treat as 0
		if index >= 0 {
			digit = int(base32Table[index])
		}
		if shift <= 3 {
			shift = (shift + 5) % 8
			if shift == 0 {
				plainChar |= digit
				out = append(out, byte(plainChar))
				plainChar = 0
			} else {
				plainChar |= 0xff & (digit << (8 - shift))
			}
		} else {
			shift = (shift + 5) % 8
			plainChar |= 0xff & (digit >> shift)
			out = append(out, byte(plainChar))
			plainChar = 0xff & (digit << (8 - shift))
		}
	}
	return out, nil
}

// GenerateTotpSecret is authenticator.generateSecret(bytes): random bytes with the high bit cleared, base32.
func GenerateTotpSecret(bytes int) string {
	key := randomBytes(bytes)
	for index := range key {
		key[index] &= 0x7f
	}
	return base32Encode(key)
}

// totpKey is otplib's HMAC key for SHA-1: the decoded secret, repeated up to 20 hex characters when shorter.
func totpKey(secret string) ([]byte, error) {
	decoded, err := base32Decode(secret)
	if err != nil {
		return nil, err
	}
	hexSecret := hex.EncodeToString(decoded)
	if len(hexSecret) < 20 {
		repeated := strings.Repeat(hexSecret, 20-len(hexSecret))
		key, _ := hex.DecodeString(repeated[:len(repeated)-len(repeated)%2])
		if len(key) > 20 {
			key = key[:20]
		}
		return key, nil
	}
	return decoded, nil
}

func hotp(key []byte, counter uint64) string {
	mac := hmac.New(sha1.New, key)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0xf
	binaryCode := int64(digest[offset]&0x7f)<<24 | int64(digest[offset+1])<<16 | int64(digest[offset+2])<<8 | int64(digest[offset+3])
	code := strconv.FormatInt(binaryCode%1_000_000, 10)
	for len(code) < 6 {
		code = "0" + code
	}
	return code
}

func totpCounter(epoch float64) uint64 {
	return uint64(math.Floor(epoch / 30 / 1000))
}

// GenerateTotp is authenticator.generate(secret) at epoch milliseconds.
func GenerateTotp(secret string, epoch int64) (string, error) {
	key, err := totpKey(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, totpCounter(float64(epoch))), nil
}

func validToken(token string) bool {
	if token == "" {
		return false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return false
		}
	}
	return true
}

// TotpCheckDelta is authenticator.checkDelta(token, secret) with { epoch, window }: 0 for the current step, -n for
// n steps back, +n for n steps ahead (the past is tried before the future); false when no step in the window
// matches.
func TotpCheckDelta(token, secret string, epoch int64, window int) (int, bool, error) {
	key, err := totpKey(secret)
	if err != nil {
		return 0, false, err
	}
	check := func(at float64) bool {
		return validToken(token) && token == hotp(key, totpCounter(at))
	}
	if check(float64(epoch)) {
		return 0, true, nil
	}
	for i := 1; i <= window; i++ {
		if check(float64(epoch) - float64(i)*30_000) {
			return -i, true, nil
		}
	}
	for i := 1; i <= window; i++ {
		if check(float64(epoch) + float64(i)*30_000) {
			return i, true, nil
		}
	}
	return 0, false, nil
}

// TotpKeyURI is authenticator.keyuri(account, issuer, secret).
func TotpKeyURI(account, issuer, secret string) string {
	label := issuer
	if label == "" {
		label = account
	}
	uri := "otpauth://totp/" + encodeURIComponent(label) + ":" + encodeURIComponent(account) + "?secret=" + secret +
		"&period=30&digits=6&algorithm=SHA1"
	if issuer != "" {
		uri += "&issuer=" + encodeURIComponent(issuer)
	}
	return uri
}
