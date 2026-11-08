package oauth

// The provider keystore (oidc-provider helpers/initialize_keystore.js, keystore.js) and the server challenge that
// derives DPoP nonces (helpers/challenge.js).

import (
	"crypto/hkdf"
	"crypto/sha256"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

type providerKey struct {
	jwk    *core.Object
	kid    string
	alg    string
	use    string
	kty    string
	crv    string
	ops    []string
	signer *joseSigner
}

type providerKeys struct {
	keys []*providerKey
	// public is the JWKS endpoint's document.
	public *core.Object
}

func jwkSignatureAlgorithms(jwk *core.Object) []string {
	use := jwk.Get("use")
	if use != "sig" && !isUndefined(use) {
		return nil
	}
	var available []string
	switch str(jwk, "kty") {
	case "RSA":
		available = []string{"PS256", "PS384", "PS512", "RS256", "RS384", "RS512"}
	case "EC":
		switch str(jwk, "crv") {
		case "P-256":
			available = []string{"ES256"}
		case "P-384":
			available = []string{"ES384"}
		case "P-521":
			available = []string{"ES512"}
		}
	case "OKP":
		if str(jwk, "crv") == "Ed25519" {
			available = []string{"EdDSA", "Ed25519"}
		}
	}
	if alg, ok := jwk.Get("alg").(string); ok && alg != "" {
		if contains(available, alg) {
			return []string{alg}
		}
		return nil
	}
	return available
}

func calculateKid(jwk *core.Object) string {
	var components *core.Object
	switch str(jwk, "kty") {
	case "RSA":
		components = core.NewObject("e", jwk.Get("e"), "kty", "RSA", "n", jwk.Get("n"))
	case "EC":
		components = core.NewObject("crv", jwk.Get("crv"), "kty", "EC", "x", jwk.Get("x"), "y", jwk.Get("y"))
	case "OKP":
		components = core.NewObject("crv", jwk.Get("crv"), "kty", "OKP", "x", jwk.Get("x"))
	default:
		return ""
	}
	return sha256B64URL(stringify(components))
}

func keystoreError(message string) error { return &core.TypeError{Message: message} }

// newProviderKeys registers the configured signing keys (registerKey).
func newProviderKeys(list []any) (*providerKeys, error) {
	store := &providerKeys{}
	kids := map[string]bool{}
	publicKeys := []any{}
	for index, value := range list {
		input, ok := value.(*core.Object)
		if !ok || input == nil {
			return nil, keystoreError("only RSA, EC, OKP, or AKP keys should be part of jwks configuration (index " + itoa(index) + ")")
		}
		jwk := input.Clone()
		kty := str(jwk, "kty")
		if kty != "RSA" && kty != "EC" && kty != "OKP" {
			return nil, keystoreError("only RSA, EC, OKP, or AKP keys should be part of jwks configuration (index " + itoa(index) + ")")
		}
		if isUndefined(jwk.Get("kid")) || jwk.Get("kid") == nil {
			jwk.Set("kid", calculateKid(jwk))
		}
		checkString := func(property string) error {
			if text, ok := jwk.Get(property).(string); !ok || text == "" {
				return keystoreError("jwks.keys[" + itoa(index) + "]." + property + " configuration must be a non-empty string")
			}
			return nil
		}
		if err := checkString("kid"); err != nil {
			return nil, err
		}
		if kids[str(jwk, "kid")] {
			return nil, keystoreError(`jwks.keys configuration must not contain duplicate "kid" values`)
		}
		kids[str(jwk, "kid")] = true
		required := map[string][]string{"OKP": {"crv", "x", "d"}, "EC": {"crv", "x", "y", "d"}, "RSA": {"e", "n", "d", "p", "q", "dp", "dq", "qi"}}[kty]
		for _, property := range required {
			if err := checkString(property); err != nil {
				return nil, err
			}
		}
		algs := jwkSignatureAlgorithms(jwk)
		if len(algs) == 1 && str(jwk, "alg") != algs[0] {
			jwk.Set("alg", algs[0])
		}
		if len(algs) > 0 && str(jwk, "use") != "sig" {
			jwk.Set("use", "sig")
		}
		if x5c, ok := jwk.Get("x5c").([]any); !ok || len(x5c) == 0 {
			jwk.Delete("x5c")
		}
		if len(algs) == 0 {
			return nil, keystoreError("jwks.keys[" + itoa(index) + "] is of no use given the other configuration, remove it")
		}
		signer, err := joseImportPrivate(jwk)
		if err != nil {
			return nil, err
		}
		key := &providerKey{jwk: jwk, kid: str(jwk, "kid"), alg: str(jwk, "alg"), use: str(jwk, "use"), kty: kty,
			crv: str(jwk, "crv"), ops: stringList(jwk.Get("key_ops")), signer: signer}
		store.keys = append(store.keys, key)
		public := core.NewObject("kty", kty, "use", jwk.Get("use"))
		if ops, ok := jwk.Get("key_ops").([]any); ok {
			public.Set("key_ops", core.CloneValue(ops))
		}
		public.Set("kid", jwk.Get("kid"))
		public.Set("alg", jwk.Get("alg"))
		for _, member := range []string{"crv", "e", "n", "x", "x5c", "y"} {
			if value := jwk.Get(member); !isUndefined(value) {
				public.Set(member, core.CloneValue(value))
			}
		}
		publicKeys = append(publicKeys, public)
	}
	store.public = core.NewObject("keys", publicKeys)
	return store, nil
}

func ktyOfAlg(alg string) string {
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return "RSA"
	case strings.HasPrefix(alg, "ES"):
		return "EC"
	case strings.HasPrefix(alg, "Ed"):
		return "OKP"
	case strings.HasPrefix(alg, "HS"):
		return "oct"
	}
	return ""
}

func crvOfAlg(alg string) string {
	switch alg {
	case "ES256":
		return "P-256"
	case "ES384":
		return "P-384"
	case "ES512":
		return "P-521"
	case "EdDSA", "Ed25519":
		return "Ed25519"
	}
	return ""
}

// selectForSign is keystore.selectForSign({ alg, use: 'sig' }).
func (s *providerKeys) selectForSign(alg string) *providerKey {
	kty, crv := ktyOfAlg(alg), crvOfAlg(alg)
	var best *providerKey
	bestScore := -1
	for _, key := range s.keys {
		if key.kty != kty || (key.alg != "" && key.alg != alg) || (key.use != "" && key.use != "sig") ||
			(crv != "" && key.crv != crv) || (key.ops != nil && !contains(key.ops, "sign")) {
			continue
		}
		score := 0
		if key.alg != "" {
			score++
		}
		if key.use != "" {
			score++
		}
		if score > bestScore {
			best, bestScore = key, score
		}
	}
	return best
}

// selectForVerify returns the candidate verification keys for a header (keystore.selectForVerify).
func (s *providerKeys) selectForVerify(alg string, kid any) []*providerKey {
	kty, crv := ktyOfAlg(alg), crvOfAlg(alg)
	var out []*providerKey
	for _, key := range s.keys {
		if key.kty != kty {
			continue
		}
		if text, ok := kid.(string); ok && text != key.kid {
			continue
		}
		if (key.alg != "" && key.alg != alg) || (key.use != "" && key.use != "sig") || (crv != "" && key.crv != crv) ||
			(key.ops != nil && !contains(key.ops, "verify")) {
			continue
		}
		out = append(out, key)
	}
	return out
}

// publicVerificationSet is the provider's public keys as a local JWKS (for token exchange).
func (s *providerKeys) publicVerificationSet() *joseLocalSet {
	keys := make([]*core.Object, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, publicJWK(key.jwk))
	}
	return &joseLocalSet{keys: keys}
}

// sign is helpers/jwt.js sign(payload, key, alg, { typ, fields: { kid } }).
func (s *providerKeys) sign(payload *core.Object, alg, typ string) (string, error) {
	key := s.selectForSign(alg)
	if key == nil {
		return "", keystoreError("resolved Resource Server jwt configuration has no corresponding key in the provider's keystore")
	}
	header := core.NewObject("alg", alg)
	if typ != "" {
		header.Set("typ", typ)
	}
	header.Set("kid", key.kid)
	return joseSignCompact(header, payload, key.signer, alg)
}

// serverChallenge is helpers/challenge.js: HKDF-derived values for 60-second steps, valid for two steps around now.
type serverChallenge struct {
	secret []byte
	info   string
	now    func() int64
}

func newServerChallenge(secret []byte, info string, now func() int64) *serverChallenge {
	return &serverChallenge{secret: secret, info: info, now: now}
}

const challengeStep = 60

// challengeOKWindow is CHALLENGE_OK_WINDOW (five steps).
const challengeOKWindow = challengeStep * 5

func (c *serverChallenge) compute(step int64) string {
	salt := make([]byte, 8)
	value := step
	for i := 7; i >= 0; i-- {
		salt[i] = byte(value & 0xff)
		value >>= 8
	}
	out, err := hkdf.Key(sha256.New, c.secret, salt, c.info, 32)
	if err != nil {
		return ""
	}
	return b64url(out)
}

func (c *serverChallenge) window() []string {
	step := epoch(c.now()) / challengeStep
	return []string{c.compute(step - 2), c.compute(step - 1), c.compute(step), c.compute(step + 1), c.compute(step + 2)}
}

func (c *serverChallenge) nextChallenge() string { return c.window()[3] }

func (c *serverChallenge) checkChallenge(challenge string) bool {
	matched := false
	for _, value := range c.window() {
		if constantEquals(value, challenge) {
			matched = true
		}
	}
	return matched
}
