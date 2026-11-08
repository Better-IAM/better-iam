package oauth

// Signing, private key import, JWK thumbprints (RFC 7638), the EmbeddedJWK resolver and the decode helpers that the
// authorization server, the resource server verifier and the SSF transmitter need from `jose`.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// joseSigner is an imported private signing key.
type joseSigner struct {
	key crypto.Signer
	kty string
}

func bigMember(jwk *core.Object, name string) (*big.Int, bool) {
	data, ok := joseMember(jwk.Get(name))
	if !ok || len(data) == 0 {
		return nil, false
	}
	return new(big.Int).SetBytes(data), true
}

// joseImportPrivate is importJWK for a private JWK (RSA, EC or Ed25519).
func joseImportPrivate(jwk *core.Object) (*joseSigner, error) {
	invalid := joseFail("TypeError", "Invalid keyData")
	switch str(jwk, "kty") {
	case "RSA":
		public, err := joseRSAPublic(jwk)
		if err != nil {
			return nil, err
		}
		d, okD := bigMember(jwk, "d")
		p, okP := bigMember(jwk, "p")
		q, okQ := bigMember(jwk, "q")
		if !okD || !okP || !okQ {
			return nil, invalid
		}
		private := &rsa.PrivateKey{PublicKey: *public, D: d, Primes: []*big.Int{p, q}}
		if err := private.Validate(); err != nil {
			return nil, invalid
		}
		private.Precompute()
		return &joseSigner{key: private, kty: "RSA"}, nil
	case "EC":
		public, err := joseECPoint(jwk)
		if err != nil {
			return nil, err
		}
		d, ok := bigMember(jwk, "d")
		if !ok || d.Sign() == 0 || d.Cmp(public.Curve.Params().N) >= 0 {
			return nil, invalid
		}
		return &joseSigner{key: &ecdsa.PrivateKey{PublicKey: *public, D: d}, kty: "EC"}, nil
	case "OKP":
		if jwk.Get("crv") != "Ed25519" {
			return nil, invalid
		}
		seed, ok := joseMember(jwk.Get("d"))
		if !ok || len(seed) != ed25519.SeedSize {
			return nil, invalid
		}
		return &joseSigner{key: ed25519.NewKeyFromSeed(seed), kty: "OKP"}, nil
	}
	return nil, invalid
}

// joseImportPublic imports a public JWK for an algorithm (importJWK with alg).
func joseImportPublic(jwk *core.Object, alg string) (*josePublicKey, error) {
	entry, err := joseJwsAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	if jwk.Get("kty") != entry.kty {
		return nil, joseFail("JOSENotSupported", `Invalid or unsupported JWK "alg" (Algorithm) Parameter value`)
	}
	switch entry.kty {
	case "RSA":
		public, err := joseRSAPublic(jwk)
		if err != nil {
			return nil, err
		}
		return &josePublicKey{key: public, rsaBits: public.N.BitLen()}, nil
	case "EC":
		if jwk.Get("crv") != entry.crv {
			return nil, joseFail("TypeError", "Invalid keyData")
		}
		public, err := joseECPoint(jwk)
		if err != nil {
			return nil, err
		}
		return &josePublicKey{key: public}, nil
	case "OKP":
		x, ok := joseMember(jwk.Get("x"))
		if jwk.Get("crv") != "Ed25519" || !ok || len(x) != ed25519.PublicKeySize {
			return nil, joseFail("TypeError", "Invalid keyData")
		}
		return &josePublicKey{key: ed25519.PublicKey(x)}, nil
	}
	return nil, joseFail("JOSENotSupported", "unsupported key type")
}

// joseSignCompact signs a JWS over JSON.stringify(header) and JSON.stringify(payload).
func joseSignCompact(header, payload *core.Object, signer *joseSigner, alg string) (string, error) {
	entry, err := joseJwsAlgorithm(alg)
	if err != nil {
		return "", err
	}
	if entry.kty != signer.kty {
		return "", joseFail("TypeError", "CryptoKey does not support this operation")
	}
	input := b64url(utf8Bytes(stringify(header))) + "." + b64url(utf8Bytes(stringify(payload)))
	var signature []byte
	switch private := signer.key.(type) {
	case ed25519.PrivateKey:
		signature = ed25519.Sign(private, []byte(input))
	case *ecdsa.PrivateKey:
		digest := entry.hash.New()
		digest.Write([]byte(input))
		r, s, err := ecdsa.Sign(rand.Reader, private, digest.Sum(nil))
		if err != nil {
			return "", err
		}
		size := (private.Curve.Params().BitSize + 7) / 8
		signature = make([]byte, 2*size)
		r.FillBytes(signature[:size])
		s.FillBytes(signature[size:])
	case *rsa.PrivateKey:
		if entry.minRsaBits > 0 && private.N.BitLen() < entry.minRsaBits {
			return "", joseFail("TypeError", alg+" requires key modulusLength to be 2048 bits or larger")
		}
		digest := entry.hash.New()
		digest.Write([]byte(input))
		if entry.pss {
			signature, err = rsa.SignPSS(rand.Reader, private, entry.hash, digest.Sum(nil), &rsa.PSSOptions{SaltLength: entry.hash.Size(), Hash: entry.hash})
		} else {
			signature, err = rsa.SignPKCS1v15(rand.Reader, private, entry.hash, digest.Sum(nil))
		}
		if err != nil {
			return "", err
		}
	default:
		return "", joseFail("JOSENotSupported", "alg "+alg+" is not supported")
	}
	return input + "." + b64url(signature), nil
}

// joseThumbprint is calculateJwkThumbprint(jwk, 'sha256').
func joseThumbprint(jwk *core.Object) (string, error) {
	var components *core.Object
	switch str(jwk, "kty") {
	case "RSA":
		components = core.NewObject("e", jwk.Get("e"), "kty", "RSA", "n", jwk.Get("n"))
	case "EC":
		components = core.NewObject("crv", jwk.Get("crv"), "kty", "EC", "x", jwk.Get("x"), "y", jwk.Get("y"))
	case "OKP":
		components = core.NewObject("crv", jwk.Get("crv"), "kty", "OKP", "x", jwk.Get("x"))
	case "AKP":
		components = core.NewObject("alg", jwk.Get("alg"), "kty", "AKP", "pub", jwk.Get("pub"))
	case "oct":
		components = core.NewObject("k", jwk.Get("k"), "kty", "oct")
	default:
		return "", joseFail("JOSENotSupported", `"kty" (Key Type) Parameter missing or unsupported`)
	}
	var failed bool
	components.Entries(func(key string, value any) bool {
		if _, ok := value.(string); !ok {
			failed = true
		}
		return true
	})
	if failed {
		return "", joseFail("TypeError", "JWK members must be strings")
	}
	return sha256B64URL(stringify(components)), nil
}

// joseEmbeddedJWK is jose's EmbeddedJWK resolver: the verification key is the header's own public `jwk`.
func joseEmbeddedJWK(_ context.Context, header *core.Object) (*josePublicKey, error) {
	jwk, ok := header.Get("jwk").(*core.Object)
	if !ok || jwk == nil {
		return nil, joseFail("JWSInvalid", `"jwk" (JSON Web Key) Header Parameter must be a JSON object`)
	}
	if truthy(jwk.Get("d")) || truthy(jwk.Get("priv")) || str(jwk, "kty") == "oct" {
		return nil, joseFail("JWSInvalid", `"jwk" (JSON Web Key) Header Parameter must be a public key`)
	}
	return joseImportPublic(jwk, str(header, "alg"))
}

// joseDecodePayload is decodeJwt: the payload of a compact JWT, unverified.
func joseDecodePayload(token string) (*core.Object, error) {
	parts := strings.Split(token, ".")
	if len(parts) == 5 {
		return nil, joseFail("JWTInvalid", "Only JWTs using Compact JWS serialization can be decoded")
	}
	if len(parts) != 3 {
		return nil, joseFail("JWTInvalid", "Invalid JWT")
	}
	if parts[1] == "" {
		return nil, joseFail("JWTInvalid", "JWTs must contain a payload")
	}
	data, err := joseDecode(parts[1])
	if err != nil {
		return nil, joseFail("JWTInvalid", "Failed to base64url decode the payload")
	}
	parsed, err := joseJSON(data)
	if err != nil {
		return nil, joseFail("JWTInvalid", "Failed to parse the decoded payload as JSON")
	}
	payload, ok := parsed.(*core.Object)
	if !ok || payload == nil {
		return nil, joseFail("JWTInvalid", "Invalid JWT Claims Set")
	}
	return payload, nil
}

// publicJWK strips the private members of a JWK (d, p, q, dp, dq, qi, k).
func publicJWK(key *core.Object) *core.Object {
	out := core.NewObject()
	key.Entries(func(name string, value any) bool {
		switch name {
		case "d", "p", "q", "dp", "dq", "qi", "k", "oth", "priv":
		default:
			out.SetRaw(name, core.CloneValue(value))
		}
		return true
	})
	return out
}

// staticKeyResolver resolves every header to one key.
func staticKeyResolver(key *josePublicKey) joseResolver {
	return func(context.Context, *core.Object) (*josePublicKey, error) { return key, nil }
}
