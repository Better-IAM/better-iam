// Package a2a is the Go port of @better-iam/a2a: Agent2Agent (A2A) support with IAM-attested agent cards, card
// verification and discovery, offline verification of delegation tokens, and authorization for A2A servers.
package a2a

// Port of packages/a2a/src/cards.ts: the agent card helpers. Verification of cards Better IAM attested
// (`agents.signCard`), discovery of a remote agent's card, and an attestor that keeps an agent's own card signed.
// Cards, JWKS and attestations are model values (*core.Object), as JSON carries them.

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// AgentAttestationURI is the URI of the attestation extension Better IAM adds to every card it signs.
const AgentAttestationURI = "urn:better-iam:a2a:attestation:v1"

// AgentCardErrorReason is why a card was refused: malformed, unsigned, untrusted-key, signature, attestation,
// expired, issuer, tenant, endpoint or fetch.
type AgentCardErrorReason = string

// AgentCardError is why an agent card was refused by VerifyAgentCard or DiscoverAgent: Reason is unsigned,
// untrusted-key, signature, attestation, expired, issuer, tenant, endpoint, malformed or fetch.
type AgentCardError struct {
	Reason  AgentCardErrorReason
	Message string
}

func (e *AgentCardError) Error() string { return e.Message }

// Name is the JavaScript error name.
func (e *AgentCardError) Name() string { return "AgentCardError" }

func cardError(reason AgentCardErrorReason, message string) *AgentCardError {
	return &AgentCardError{Reason: reason, Message: message}
}

// AgentAttestation is what Better IAM attests about an agent (the params of the attestation extension), read from
// a verified card. Params holds the extension's params exactly as the card carries them.
type AgentAttestation struct {
	Issuer       string
	TenantID     string
	Organization string
	AgentID      string
	AgentName    string
	IssuedAt     string
	ExpiresAt    string
	Params       *core.Object
}

// VerifiedAgentCard is a card VerifyAgentCard accepted.
type VerifiedAgentCard struct {
	Card        *core.Object
	Attestation AgentAttestation
	// Kid is the kid of the key that verified the card.
	Kid string
}

// Fetcher makes the outbound requests (fetch): *http.Client satisfies it. VerifyAgentCard, DiscoverAgent and
// VerifyDelegationToken pass every request through it.
type Fetcher interface {
	Do(request *http.Request) (*http.Response, error)
}

// FetchFunc adapts a function to Fetcher. A FetchFunc is not comparable, so key sets it fetched are cached for one
// verification only; give a pointer type (such as *http.Client) to share the cache across verifications.
type FetchFunc func(request *http.Request) (*http.Response, error)

// Do calls the function.
func (f FetchFunc) Do(request *http.Request) (*http.Response, error) { return f(request) }

var errRedirect = errors.New("unexpected redirect")

// defaultFetcher is globalThis.fetch with `redirect: 'error'`.
var defaultFetcher Fetcher = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}

// JwksSource is a trusted deployment's card keys: its JWKS URL (a2a.jwksUrl) or its JWKS (iam.A2a.Jwks()).
type JwksSource struct {
	URL  string
	Keys *core.Object
}

// JwksURL is a JwksSource fetched from a URL.
func JwksURL(url string) JwksSource { return JwksSource{URL: url} }

// JwksKeys is a JwksSource given as a JWKS.
func JwksKeys(jwks *core.Object) JwksSource { return JwksSource{Keys: jwks} }

func (s JwksSource) isURL() bool { return s.Keys == nil }

// VerifyAgentCardOptions configures VerifyAgentCard.
type VerifyAgentCardOptions struct {
	// TrustedIssuers are the Better IAM deployments you trust, by attestation issuer. The card is checked only with
	// the keys of the issuer it names, so one trusted deployment cannot vouch in another's name. The safest choice when
	// you trust more than one deployment; otherwise give Keys, KeysFunc or TrustedJwksURLs. nil means not given.
	TrustedIssuers map[string]JwksSource
	// Keys are the card keys of a Better IAM deployment you trust (iam.A2a.Jwks()).
	Keys *core.Object
	// KeysFunc returns the JWKS for a signature's kid and jku (nil when the signature names none); it takes precedence
	// over Keys.
	KeysFunc func(ctx context.Context, kid string, jku *string) (*core.Object, error)
	// TrustedJwksURLs are JWKS URLs you trust (a2a.jwksUrl of those deployments). A signature is checked only when its
	// jku is exactly one of them; the key set is fetched and cached for JwksCacheSeconds (fetched again, at most every
	// 30 seconds, when a signature names a key it does not have).
	TrustedJwksURLs []string
	// Issuers are the attestation issuers you accept; nil accepts any whose key verifies.
	Issuers []string
	// TenantID accepts only agents attested for this tenant (organization).
	TenantID *string
	// Origin requires the card's url to be on this origin (discovery passes the origin it fetched from).
	Origin *string
	// ClockToleranceSeconds is the allowed clock difference in seconds (nil: 60).
	ClockToleranceSeconds *float64
	// JwksCacheSeconds is how long fetched key sets are kept, in seconds (nil: 300).
	JwksCacheSeconds *float64
	// Now is epoch milliseconds (nil: the system clock).
	Now func() float64
	// Fetch makes the key set requests (nil: an http.Client that refuses redirects).
	Fetch Fetcher
}

var base64URLPattern = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

// fromBase64URL is the strict base64url decoding shared with delegation_tokens.go (atob after the alphabet check).
func fromBase64URL(value string) ([]byte, error) {
	if !base64URLPattern.MatchString(value) {
		return nil, cardError("malformed", "Invalid base64url")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, &core.TypeError{Message: "The string to be decoded is not correctly encoded."}
	}
	return decoded, nil
}

func toBase64URL(bytes []byte) string { return base64.RawURLEncoding.EncodeToString(bytes) }

// plain is a non-array object.
func plain(value any) (*core.Object, bool) {
	object, ok := value.(*core.Object)
	return object, ok && object != nil
}

// decodeJSONPart is JSON.parse(new TextDecoder().decode(fromBase64Url(part))).
func decodeJSONPart(part string) (any, error) {
	bytes, err := fromBase64URL(part)
	if err != nil {
		return nil, err
	}
	return core.ParseJSONString(textDecode(bytes))
}

// jwkBytes is Buffer.from(value, 'base64') as WebCrypto's JWK import reads a key member; ok is false when the member
// is not a string.
func jwkBytes(value any) ([]byte, bool) {
	text, ok := value.(string)
	if !ok {
		return nil, false
	}
	return nodeBase64Decode(text), true
}

// verifySignature checks a JWS signature (EdDSA over Ed25519, or ES256 over P-256) with a public JWK, as WebCrypto
// does: false for a key that does not import, an algorithm the key does not have, or a signature that does not
// verify.
func verifySignature(jwk *core.Object, alg string, signingInput, signature []byte) bool {
	kty, crv := jwk.Get("kty"), jwk.Get("crv")
	if alg == "EdDSA" && kty == "OKP" && crv == "Ed25519" {
		x, ok := jwkBytes(jwk.Get("x"))
		if !ok || len(x) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(x), signingInput, signature)
	}
	if alg == "ES256" && kty == "EC" && crv == "P-256" {
		x, okX := jwkBytes(jwk.Get("x"))
		// The material carries y only when it is truthy; a P-256 key without it does not import.
		yValue := jwk.Get("y")
		if text, isString := yValue.(string); !isString || text == "" {
			return false
		}
		y, okY := jwkBytes(yValue)
		if !okX || !okY || len(x) > 32 || len(y) > 32 || len(signature) != 64 {
			return false
		}
		point := make([]byte, 65)
		point[0] = 4
		copy(point[1+32-len(x):33], x)
		copy(point[33+32-len(y):], y)
		if _, err := ecdh.P256().NewPublicKey(point); err != nil {
			return false
		}
		key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(point[1:33]), Y: new(big.Int).SetBytes(point[33:])}
		digest := sha256.Sum256(signingInput)
		return ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	}
	return false
}

// attestationOf reads the card's one Better IAM attestation.
func attestationOf(card *core.Object) (AgentAttestation, error) {
	var extensions []any
	if capabilities, ok := plain(card.Get("capabilities")); ok {
		switch value := capabilities.Get("extensions").(type) {
		case nil, core.UndefinedType:
		case []any:
			extensions = value
		default:
			return AgentAttestation{}, &core.TypeError{Message: "(card.capabilities?.extensions ?? []).filter is not a function"}
		}
	}
	var found []*core.Object
	for _, item := range extensions {
		if object, ok := plain(item); ok && object.Get("uri") == AgentAttestationURI {
			found = append(found, object)
		}
	}
	if len(found) != 1 {
		return AgentAttestation{}, cardError("attestation", "The card carries no Better IAM attestation")
	}
	params, ok := plain(found[0].Get("params"))
	if !ok {
		return AgentAttestation{}, cardError("attestation", "The card carries no Better IAM attestation")
	}
	fields := map[string]string{}
	for _, field := range []string{"issuer", "tenantId", "organization", "agentId", "agentName", "issuedAt", "expiresAt"} {
		text, isString := params.Get(field).(string)
		if !isString {
			return AgentAttestation{}, cardError("attestation", "The attestation has no "+field)
		}
		fields[field] = text
	}
	if params.Get("sponsored") != true {
		return AgentAttestation{}, cardError("attestation", "The attestation does not state a sponsor")
	}
	return AgentAttestation{
		Issuer: fields["issuer"], TenantID: fields["tenantId"], Organization: fields["organization"], AgentID: fields["agentId"],
		AgentName: fields["agentName"], IssuedAt: fields["issuedAt"], ExpiresAt: fields["expiresAt"], Params: params,
	}, nil
}

// jwksCacheEntry is a fetched key set.
type jwksCacheEntry struct {
	jwks      *core.Object
	until     float64
	fetchedAt float64
}

// jwksCaches are the fetched key sets by URL, shared by every verification that fetches keys with the same fetcher
// (a comparable one; see FetchFunc).
var (
	jwksCachesMu sync.Mutex
	jwksCaches   = map[any]map[string]jwksCacheEntry{}
)

// jwksCache is the key set cache of a fetcher: shared when the fetcher is comparable, otherwise a cache for this
// verification only.
type jwksCache struct {
	shared  any
	entries map[string]jwksCacheEntry
}

func newJwksCache(fetcher Fetcher) *jwksCache {
	if fetcher != nil && reflect.TypeOf(fetcher).Comparable() {
		return &jwksCache{shared: fetcher}
	}
	return &jwksCache{entries: map[string]jwksCacheEntry{}}
}

func (c *jwksCache) get(url string) (jwksCacheEntry, bool) {
	if c.shared == nil {
		entry, ok := c.entries[url]
		return entry, ok
	}
	jwksCachesMu.Lock()
	defer jwksCachesMu.Unlock()
	entry, ok := jwksCaches[c.shared][url]
	return entry, ok
}

func (c *jwksCache) set(url string, entry jwksCacheEntry) {
	if c.shared == nil {
		if len(c.entries) > 64 {
			clear(c.entries)
		}
		c.entries[url] = entry
		return
	}
	jwksCachesMu.Lock()
	defer jwksCachesMu.Unlock()
	entries := jwksCaches[c.shared]
	if entries == nil {
		if len(jwksCaches) > 64 {
			clear(jwksCaches)
		}
		entries = map[string]jwksCacheEntry{}
		jwksCaches[c.shared] = entries
	}
	if len(entries) > 64 {
		clear(entries)
	}
	entries[url] = entry
}

// fetchJwks is a JWKS from url, cached for cacheSeconds. With fresh (a signature named a key the cached set lacks),
// a set older than 30 seconds is fetched again, so a newly activated key verifies without waiting out the cache.
func fetchJwks(ctx context.Context, url string, fetcher Fetcher, cache *jwksCache, now, cacheSeconds float64, fresh bool) (*core.Object, error) {
	if cached, ok := cache.get(url); ok && cached.until > now && !(fresh && now-cached.fetchedAt > 30_000) {
		return cached.jwks, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &core.TypeError{Message: "Failed to parse URL from " + url}
	}
	request.Header.Set("accept", "application/jwk-set+json, application/json")
	response, err := fetcher.Do(request)
	if err != nil {
		return nil, err
	}
	text, err := boundedText(response, 256*1024)
	if err != nil {
		return nil, err
	}
	parsed, err := core.ParseJSONString(text)
	if err != nil {
		return nil, err
	}
	object, ok := plain(parsed)
	keys, isArray := []any(nil), false
	if ok {
		keys, isArray = object.Get("keys").([]any)
	}
	if !isArray {
		return nil, cardError("untrusted-key", url+" is not a JWKS")
	}
	jwks := core.NewObject("keys", keys)
	cache.set(url, jwksCacheEntry{jwks: jwks, until: now + cacheSeconds*1000, fetchedAt: now})
	return jwks, nil
}

// boundedText is the response body as text, refused when the status is not 2xx or the body is larger than maxBytes.
func boundedText(response *http.Response, maxBytes int64) (string, error) {
	if response.Body != nil {
		defer response.Body.Close()
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		where := "The server"
		if response.Request != nil && response.Request.URL != nil && response.Request.URL.String() != "" {
			where = response.Request.URL.String()
		}
		return "", cardError("fetch", where+" answered "+strconv.Itoa(response.StatusCode))
	}
	if response.Body == nil || response.Body == http.NoBody {
		return "", nil
	}
	bytes, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(bytes)) > maxBytes {
		return "", cardError("fetch", "The response is larger than "+strconv.FormatInt(maxBytes, 10)+" bytes")
	}
	return textDecode(bytes), nil
}

// pickKey is the first key of a JWKS with this kid, usable for alg and not an encryption key. It fails (like the
// TypeScript find over a non-array or a null entry) for a set that is not a JWKS.
func pickKey(jwks *core.Object, kid, alg string) (*core.Object, error) {
	if jwks == nil {
		return nil, nil
	}
	keys, ok := jwks.Get("keys").([]any)
	if !ok {
		return nil, &core.TypeError{Message: "jwks.keys.find is not a function"}
	}
	for _, item := range keys {
		if item == nil || core.IsUndefined(item) {
			return nil, &core.TypeError{Message: "Cannot read properties of null (reading 'kid')"}
		}
		key, ok := plain(item)
		if !ok {
			continue
		}
		keyAlg := key.Get("alg")
		if key.Get("kid") == kid && (core.IsUndefined(keyAlg) || keyAlg == alg) && key.Get("use") != "enc" {
			return key, nil
		}
	}
	return nil, nil
}

func nowOf(now func() float64) float64 {
	if now != nil {
		return now()
	}
	return float64(time.Now().UnixMilli())
}

func numberOr(value *float64, fallback float64) float64 {
	if value == nil {
		return fallback
	}
	return *value
}

func fetcherOr(fetcher Fetcher) Fetcher {
	if fetcher == nil {
		return defaultFetcher
	}
	return fetcher
}

// urlOrigin is new URL(value).origin: scheme://host[:port] for the special schemes, "null" otherwise.
func urlOrigin(value string) (string, error) {
	parsed, err := auth.ParseFetchURL(value)
	if err != nil {
		return "", &core.TypeError{Message: "Invalid URL"}
	}
	switch parsed.Protocol {
	case "http:", "https:", "ws:", "wss:", "ftp:":
	default:
		return "null", nil
	}
	origin := parsed.Protocol + "//" + parsed.Hostname
	if parsed.Port != "" {
		origin += ":" + parsed.Port
	}
	return origin, nil
}

// VerifyAgentCard verifies that card was signed by a trusted Better IAM deployment and that its attestation is
// current: one of the card's signatures verifies over the canonical card (RFC 8785, without signatures) with a
// trusted key, the card carries exactly one attestation, it is neither expired nor from the future, and it matches
// Issuers, TenantID and Origin when given. It fails with an *AgentCardError otherwise (a *core.TypeError for invalid
// options).
func VerifyAgentCard(ctx context.Context, card any, options VerifyAgentCardOptions) (*VerifiedAgentCard, error) {
	if options.TrustedIssuers == nil && options.Keys == nil && options.KeysFunc == nil && len(options.TrustedJwksURLs) == 0 {
		return nil, &core.TypeError{Message: "verifyAgentCard needs trustedIssuers, keys or trustedJwksUrls"}
	}
	object, ok := plain(core.Normalize(card))
	if !ok {
		return nil, cardError("malformed", "Not an agent card")
	}
	if _, isString := object.Get("url").(string); !isString {
		return nil, cardError("malformed", "Not an agent card")
	}
	if _, isString := object.Get("name").(string); !isString {
		return nil, cardError("malformed", "Not an agent card")
	}
	signatures, isArray := object.Get("signatures").([]any)
	if !isArray || len(signatures) == 0 {
		return nil, cardError("unsigned", "The card is not signed")
	}
	now := nowOf(options.Now)
	fetcher := fetcherOr(options.Fetch)
	cache := newJwksCache(fetcher)
	cacheSeconds := numberOr(options.JwksCacheSeconds, 300)
	// With TrustedIssuers the keys are the named issuer's: read the (not yet verified) issuer first; the signature
	// check below then binds the card to that issuer's keys.
	var issuerKeys *JwksSource
	if options.TrustedIssuers != nil {
		claimed, err := attestationOf(object)
		if err != nil {
			return nil, err
		}
		source, trusted := options.TrustedIssuers[claimed.Issuer]
		if !trusted {
			return nil, cardError("issuer", "The card was attested by "+claimed.Issuer+", which is not trusted")
		}
		issuerKeys = &source
	}
	keysFor := func(kid string, jku *string, fresh bool) (*core.Object, error) {
		if issuerKeys != nil {
			if issuerKeys.isURL() {
				return fetchJwks(ctx, issuerKeys.URL, fetcher, cache, now, cacheSeconds, fresh)
			}
			return issuerKeys.Keys, nil
		}
		if options.KeysFunc != nil {
			return options.KeysFunc(ctx, kid, jku)
		}
		if options.Keys != nil {
			return options.Keys, nil
		}
		if jku != nil && *jku != "" {
			for _, trusted := range options.TrustedJwksURLs {
				if trusted == *jku {
					return fetchJwks(ctx, *jku, fetcher, cache, now, cacheSeconds, fresh)
				}
			}
		}
		return nil, nil
	}
	unsigned := object.Spread()
	unsigned.Delete("signatures")
	canonical, err := core.CanonicalizeJSON(unsigned)
	if err != nil {
		return nil, cardError("malformed", "The card is not plain JSON")
	}
	payload := toBase64URL(utf8Bytes(canonical))
	verifiedKid := ""
	sawTrustedKey := false
	if len(signatures) > 8 {
		signatures = signatures[:8]
	}
	for _, item := range signatures {
		entry, ok := plain(item)
		if !ok {
			continue
		}
		protected, okProtected := entry.Get("protected").(string)
		signaturePart, okSignature := entry.Get("signature").(string)
		if !okProtected || !okSignature {
			continue
		}
		decoded, err := decodeJSONPart(protected)
		if err != nil {
			continue
		}
		// Only plain detached card signatures (typ JOSE, never another JWT type signed with the same keys): no
		// critical extensions, no unencoded payloads.
		header, ok := plain(decoded)
		if !ok || header.Get("typ") != "JOSE" || !core.IsUndefined(header.Get("crit")) || !core.IsUndefined(header.Get("b64")) {
			continue
		}
		alg, _ := header.Get("alg").(string)
		kid, kidIsString := header.Get("kid").(string)
		var jku *string
		if text, isString := header.Get("jku").(string); isString {
			jku = &text
		}
		if (alg != "EdDSA" && alg != "ES256") || !kidIsString {
			continue
		}
		// A key the (cached) set lacks may have been activated since: look once more with a fresh set.
		jwk, err := func() (*core.Object, error) {
			jwks, err := keysFor(kid, jku, false)
			if err != nil {
				return nil, err
			}
			key, err := pickKey(jwks, kid, alg)
			if err != nil || key != nil {
				return key, err
			}
			jwks, err = keysFor(kid, jku, true)
			if err != nil {
				return nil, err
			}
			return pickKey(jwks, kid, alg)
		}()
		if err != nil {
			var refused *AgentCardError
			if errors.As(err, &refused) && refused.Reason == "fetch" {
				return nil, err
			}
			jwk = nil
		}
		if jwk == nil {
			continue
		}
		sawTrustedKey = true
		signature, err := fromBase64URL(signaturePart)
		if err != nil {
			continue
		}
		if verifySignature(jwk, alg, utf8Bytes(protected+"."+payload), signature) {
			verifiedKid = kid
			break
		}
	}
	if verifiedKid == "" {
		if sawTrustedKey {
			return nil, cardError("signature", "The card signature does not verify")
		}
		return nil, cardError("untrusted-key", "The card is not signed with a trusted key")
	}
	attestation, err := attestationOf(object)
	if err != nil {
		return nil, err
	}
	// A NaN or infinite tolerance (or clock) would make both time checks below false and accept any attestation.
	toleranceSeconds := numberOr(options.ClockToleranceSeconds, 60)
	if math.IsNaN(toleranceSeconds) || math.IsInf(toleranceSeconds, 0) || toleranceSeconds < 0 || toleranceSeconds > 300 ||
		math.IsNaN(now) || math.IsInf(now, 0) {
		return nil, &core.TypeError{Message: "clockToleranceSeconds must be 0 to 300 seconds and now a finite time"}
	}
	tolerance := toleranceSeconds * 1000
	issuedAt := parseDate(attestation.IssuedAt)
	expiresAt := parseDate(attestation.ExpiresAt)
	if math.IsNaN(issuedAt) || math.IsInf(issuedAt, 0) || math.IsNaN(expiresAt) || math.IsInf(expiresAt, 0) {
		return nil, cardError("attestation", "The attestation times are invalid")
	}
	if issuedAt > now+tolerance {
		return nil, cardError("attestation", "The attestation is not valid yet")
	}
	if expiresAt <= now-tolerance {
		return nil, cardError("expired", "The attestation has expired")
	}
	if options.Issuers != nil && !contains(options.Issuers, attestation.Issuer) {
		return nil, cardError("issuer", "The card was attested by "+attestation.Issuer)
	}
	if options.TenantID != nil && attestation.TenantID != *options.TenantID {
		return nil, cardError("tenant", "The agent belongs to another organization")
	}
	if options.Origin != nil {
		origin, err := urlOrigin(object.Get("url").(string))
		hasOrigin := err == nil
		expected, err := urlOrigin(*options.Origin)
		if err != nil {
			return nil, err
		}
		if !hasOrigin || origin != expected {
			return nil, cardError("endpoint", "The card describes an agent on another origin")
		}
	}
	return &VerifiedAgentCard{Card: object, Attestation: attestation, Kid: verifiedKid}, nil
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// DiscoverAgentOptions configures DiscoverAgent.
type DiscoverAgentOptions struct {
	VerifyAgentCardOptions
	// MaxBytes is the largest accepted card in bytes (0: 256 KiB).
	MaxBytes int64
	// TimeoutMs is the timeout of the card request in milliseconds (0: 5000).
	TimeoutMs int64
}

// DiscoverAgent fetches a remote agent's card (url itself when its path ends in .json, otherwise
// /.well-known/agent-card.json on its origin) and verifies it with VerifyAgentCard, requiring the card's url to be on
// the origin it was fetched from. Call it only with agent addresses you chose: it makes an outbound request.
func DiscoverAgent(ctx context.Context, url string, options DiscoverAgentOptions) (*VerifiedAgentCard, error) {
	target, err := auth.ParseFetchURL(url)
	if err != nil {
		return nil, &core.TypeError{Message: "Invalid URL"}
	}
	if target.Protocol != "https:" && target.Protocol != "http:" {
		return nil, cardError("fetch", "Agent cards are fetched over http(s)")
	}
	origin, _ := urlOrigin(target.Href)
	location := target.Href
	if !strings.HasSuffix(target.EscapedPath(), ".json") {
		location = origin + "/.well-known/agent-card.json"
	}
	fetcher := fetcherOr(options.Fetch)
	timeout := options.TimeoutMs
	if timeout == 0 {
		timeout = 5000
	}
	maxBytes := options.MaxBytes
	if maxBytes == 0 {
		maxBytes = 256 * 1024
	}
	text, err := func() (string, error) {
		ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			return "", err
		}
		request.Header.Set("accept", "application/json")
		response, err := fetcher.Do(request)
		if err != nil {
			return "", err
		}
		return boundedText(response, maxBytes)
	}()
	if err != nil {
		var refused *AgentCardError
		if errors.As(err, &refused) {
			return nil, err
		}
		return nil, cardError("fetch", "Could not fetch "+location)
	}
	card, err := core.ParseJSONString(text)
	if err != nil {
		return nil, cardError("malformed", location+" is not JSON")
	}
	verify := options.VerifyAgentCardOptions
	if verify.Origin == nil {
		verify.Origin = &origin
	}
	return VerifyAgentCard(ctx, card, verify)
}

// SignedCard is a card Better IAM signed (agents.signCard): the card and when its attestation expires (epoch ms).
type SignedCard struct {
	Card      *core.Object
	ExpiresAt float64
}

// CardAttestorOptions configures CreateCardAttestor.
type CardAttestorOptions struct {
	// Card is the card to have attested (without signatures).
	Card *core.Object
	// CardFunc builds the card instead (it takes precedence over Card).
	CardFunc func(ctx context.Context) (*core.Object, error)
	// Sign signs a card through Better IAM, for example with iam.API.Agents.SignCard and the agent's key.
	Sign func(ctx context.Context, card *core.Object) (SignedCard, error)
	// RefreshShare re-signs once less than this share of the attestation's lifetime is left (nil: 0.2).
	RefreshShare *float64
	// Now is epoch milliseconds (nil: the system clock).
	Now func() float64
}

// attestorFlight is one signing request concurrent calls share.
type attestorFlight struct {
	done chan struct{}
	card *core.Object
	err  error
}

// CreateCardAttestor keeps an agent's own card attested: it returns a function that yields the signed card, signing
// on first use and again when the attestation nears its end. Concurrent calls share one signing request; when
// re-signing fails while the previous card is still valid, that card is returned.
func CreateCardAttestor(options CardAttestorOptions) func(ctx context.Context) (*core.Object, error) {
	share := numberOr(options.RefreshShare, 0.2)
	type signedState struct {
		card                *core.Object
		signedAt, expiresAt float64
	}
	var (
		mu      sync.Mutex
		current *signedState
		pending *attestorFlight
	)
	sign := func(ctx context.Context) (*core.Object, error) {
		base := options.Card
		var err error
		if options.CardFunc != nil {
			base, err = options.CardFunc(ctx)
		}
		if err == nil {
			signedAt := nowOf(options.Now)
			var signed SignedCard
			signed, err = options.Sign(ctx, base)
			if err == nil {
				mu.Lock()
				current = &signedState{card: signed.Card, signedAt: signedAt, expiresAt: signed.ExpiresAt}
				mu.Unlock()
				return signed.Card, nil
			}
		}
		mu.Lock()
		previous := current
		mu.Unlock()
		if previous != nil && previous.expiresAt > nowOf(options.Now) {
			return previous.card, nil
		}
		return nil, err
	}
	refresh := func(ctx context.Context) (*core.Object, error) {
		mu.Lock()
		if flight := pending; flight != nil {
			mu.Unlock()
			<-flight.done
			return flight.card, flight.err
		}
		flight := &attestorFlight{done: make(chan struct{})}
		pending = flight
		mu.Unlock()
		flight.card, flight.err = sign(ctx)
		mu.Lock()
		if pending == flight {
			pending = nil
		}
		mu.Unlock()
		close(flight.done)
		return flight.card, flight.err
	}
	return func(ctx context.Context) (*core.Object, error) {
		mu.Lock()
		state := current
		mu.Unlock()
		if state == nil {
			return refresh(ctx)
		}
		left := state.expiresAt - nowOf(options.Now)
		if left <= (state.expiresAt-state.signedAt)*share {
			return refresh(ctx)
		}
		return state.card, nil
	}
}
