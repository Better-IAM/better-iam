package server

// Test-only JWT helpers (tests/support/jwt-keys.ts), so tests can play an external identity provider or forge IAM
// session JWTs without depending on the code under test. Names carry the `sts` prefix.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// stsTestKey is a generated signing key pair.
type stsTestKey struct {
	kid        string
	alg        string
	privateJwk *core.Object
	publicJwk  *core.Object
	private    crypto.Signer
}

func stsPad(value *big.Int, size int) string { return base64url(value.FillBytes(make([]byte, size))) }

// stsGenerateKey generates a fresh key pair for EdDSA, ES256, ES384, RS256 or PS256 (RSA keys are 2048 bits; bits
// overrides it).
func stsGenerateKey(t *testing.T, alg, kid string, bits ...int) *stsTestKey {
	t.Helper()
	key := &stsTestKey{kid: kid, alg: alg}
	var material, public *core.Object
	switch alg {
	case "EdDSA":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key.private = priv
		public = core.NewObject("crv", "Ed25519", "x", base64url(pub), "kty", "OKP")
		material = core.NewObject("crv", "Ed25519", "d", base64url(priv.Seed()), "x", base64url(pub), "kty", "OKP")
	case "ES256", "ES384":
		curve, size, crv := elliptic.P256(), 32, "P-256"
		if alg == "ES384" {
			curve, size, crv = elliptic.P384(), 48, "P-384"
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key.private = priv
		public = core.NewObject("kty", "EC", "x", stsPad(priv.X, size), "y", stsPad(priv.Y, size), "crv", crv)
		material = core.NewObject("kty", "EC", "x", stsPad(priv.X, size), "y", stsPad(priv.Y, size), "crv", crv,
			"d", stsPad(priv.D, size))
	default:
		size := 2048
		if len(bits) > 0 {
			size = bits[0]
		}
		priv, err := rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			t.Fatal(err)
		}
		priv.Precompute()
		key.private = priv
		n := base64url(priv.N.Bytes())
		e := base64url(big.NewInt(int64(priv.E)).Bytes())
		public = core.NewObject("kty", "RSA", "n", n, "e", e)
		material = core.NewObject("kty", "RSA", "n", n, "e", e, "d", base64url(priv.D.Bytes()),
			"p", base64url(priv.Primes[0].Bytes()), "q", base64url(priv.Primes[1].Bytes()),
			"dp", base64url(priv.Precomputed.Dp.Bytes()), "dq", base64url(priv.Precomputed.Dq.Bytes()),
			"qi", base64url(priv.Precomputed.Qinv.Bytes()))
	}
	key.privateJwk = material.Set("kid", kid).Set("alg", alg)
	key.publicJwk = public.Set("kid", kid).Set("alg", alg).Set("use", "sig")
	return key
}

// with is a copy of a JWK with members replaced (core.Undefined removes one).
func stsWith(jwk *core.Object, pairs ...any) *core.Object {
	copied := jwk.Clone()
	for i := 0; i+1 < len(pairs); i += 2 {
		if isUndefined(pairs[i+1]) {
			copied.Delete(pairs[i].(string))
		} else {
			copied.Set(pairs[i].(string), pairs[i+1])
		}
	}
	return copied
}

func stsEncode(t *testing.T, value any) string {
	t.Helper()
	text, _, err := core.Stringify(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64url([]byte(text))
}

// stsSigner is a key for stsSignJwt: a test key, an HS256 secret, or alg none.
type stsSigner struct {
	key    *stsTestKey
	alg    string
	secret string
}

// stsSignJwt signs a compact JWT. The header defaults to { alg, typ: 'JWT', kid } for the key; header pairs override it
// (core.Undefined removes the member), and the signature always uses the key's real algorithm.
func stsSignJwt(t *testing.T, signer stsSigner, payload *core.Object, header ...any) string {
	t.Helper()
	alg := signer.alg
	if signer.key != nil {
		alg = signer.key.alg
	}
	base := core.NewObject("alg", alg, "typ", "JWT")
	if signer.key != nil {
		base.Set("kid", signer.key.kid)
	}
	merged := stsWith(base, header...)
	input := stsEncode(t, merged) + "." + stsEncode(t, payload)
	var signature []byte
	switch {
	case alg == "none":
	case alg == "HS256":
		mac := hmac.New(sha256.New, []byte(signer.secret))
		mac.Write([]byte(input))
		signature = mac.Sum(nil)
	case signer.key != nil:
		switch private := signer.key.private.(type) {
		case ed25519.PrivateKey:
			signature = ed25519.Sign(private, []byte(input))
		case *ecdsa.PrivateKey:
			size := (private.Curve.Params().BitSize + 7) / 8
			var digest []byte
			if size == 32 {
				sum := sha256.Sum256([]byte(input))
				digest = sum[:]
			} else {
				sum := sha512.Sum384([]byte(input))
				digest = sum[:]
			}
			r, s, err := ecdsa.Sign(rand.Reader, private, digest)
			if err != nil {
				t.Fatal(err)
			}
			signature = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
		case *rsa.PrivateKey:
			sum := sha256.Sum256([]byte(input))
			var err error
			if signer.key.alg == "PS256" {
				signature, err = rsa.SignPSS(rand.Reader, private, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: 32})
			} else {
				signature, err = rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, sum[:])
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return input + "." + base64url(signature)
}

// stsDecodeJwt decodes a compact JWT without verifying it.
func stsDecodeJwt(t *testing.T, token string) (*core.Object, *core.Object) {
	t.Helper()
	parts := strings.Split(token, ".")
	header := parse(t, string(nodeBase64Decode(parts[0]))).(*core.Object)
	payload := parse(t, string(nodeBase64Decode(parts[1]))).(*core.Object)
	return header, payload
}

// stsTamper rewrites the payload (merging the pairs) while keeping the original header and signature.
func stsTamper(t *testing.T, token string, pairs ...any) string {
	t.Helper()
	parts := strings.Split(token, ".")
	_, payload := stsDecodeJwt(t, token)
	return parts[0] + "." + stsEncode(t, stsWith(payload, pairs...)) + "." + parts[2]
}

func stsSame(t *testing.T, got, want any) {
	t.Helper()
	gotText, _, _ := core.Stringify(got)
	wantText, _, _ := core.Stringify(want)
	if gotText != wantText {
		t.Fatalf("got %s, want %s", gotText, wantText)
	}
}

func TestSjwtBase64urlDecoding(t *testing.T) {
	for _, value := range []string{"QQ", "QR", "QUI", "QUJD"} {
		if _, err := sjwtDecode(value); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}
	for _, value := range []string{"Q", "QUJDR", "a+b", "a/b"} {
		if _, err := sjwtDecode(value); err == nil {
			t.Fatalf("%s decoded", value)
		}
	}
	// Unused trailing bits are ignored, as atob ignores them.
	a, _ := sjwtDecode("QQ")
	b, _ := sjwtDecode("QR")
	if string(a) != "A" || string(b) != "A" {
		t.Fatalf("got %q %q", a, b)
	}
}
