package server

// Port of tests/web-identity-verifier.test.ts: external token verification with static and fetched keys, key
// caching, claim flattening, trust conditions and the provider/trust validators (web-identity.ts).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	wiTestIssuer   = "https://token.actions.githubusercontent.com"
	wiTestAudience = "https://iam.example.com"
	wiTestJwksURI  = "https://token.actions.githubusercontent.com/.well-known/jwks"
)

type wiKeys struct {
	rsa, rsaPss, ec, ed, other *stsTestKey
}

var (
	wiKeysOnce sync.Once
	wiKeysSet  *wiKeys
)

func webIdentityTestKeys(t *testing.T) *wiKeys {
	wiKeysOnce.Do(func() {
		wiKeysSet = &wiKeys{rsa: stsGenerateKey(t, "RS256", "rsa-1"), rsaPss: stsGenerateKey(t, "PS256", "pss-1"),
			ec: stsGenerateKey(t, "ES256", "ec-1"), ed: stsGenerateKey(t, "EdDSA", "ed-1"), other: stsGenerateKey(t, "RS256", "rsa-2")}
	})
	return wiKeysSet
}

type wiSetup struct {
	mu        sync.Mutex
	clock     float64
	fetched   []string
	documents map[string]any
	verifier  *WebIdentityVerifier
}

func (s *wiSetup) fetchedList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.fetched...)
}

func newWebIdentitySetup(adjust func(options *WebIdentityVerifierOptions)) *wiSetup {
	s := &wiSetup{clock: float64(time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC).UnixMilli()), documents: map[string]any{}}
	options := &WebIdentityVerifierOptions{
		JwksCacheSeconds: 600, FetchTimeoutMs: 5000, MaxJwksBytes: 65536,
		Now: func() float64 {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.clock
		},
		FetchJSON: func(ctx context.Context, u *auth.FetchURL) (any, error) {
			s.mu.Lock()
			s.fetched = append(s.fetched, u.Href)
			s.mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			s.mu.Lock()
			defer s.mu.Unlock()
			document, ok := s.documents[u.Href]
			if !ok {
				return nil, errors.New("not found")
			}
			return core.CloneValue(document), nil
		},
	}
	if adjust != nil {
		adjust(options)
	}
	s.verifier = CreateWebIdentityVerifier(options)
	return s
}

func (s *wiSetup) advance(ms float64) {
	s.mu.Lock()
	s.clock += ms
	s.mu.Unlock()
}

func (s *wiSetup) now() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clock
}

func (s *wiSetup) set(url string, document any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if document == nil {
		delete(s.documents, url)
	} else {
		s.documents[url] = document
	}
}

func wiProvider(keys *wiKeys, pairs ...any) *core.Object {
	return stsWith(core.NewObject("id", "provider-1", "issuer", wiTestIssuer,
		"audiences", []any{wiTestAudience, "sts.amazonaws.com"},
		"jwks", core.NewObject("keys", []any{keys.rsa.publicJwk, keys.rsaPss.publicJwk, keys.ec.publicJwk, keys.ed.publicJwk}),
		"algorithms", stringsOf(WebIdentityAlgorithms), "maxTokenLifetimeSeconds", 3600.0,
		"clockToleranceSeconds", 30.0, "updatedAt", 1.0), pairs...)
}

func wiPayload(clock float64, pairs ...any) *core.Object {
	iat := math.Floor(clock / 1000)
	return stsWith(core.NewObject("iss", wiTestIssuer, "sub", "repo:acme/api:ref:refs/heads/main", "aud", wiTestAudience,
		"iat", iat, "nbf", iat, "exp", iat+300, "jti", "jti-1", "repository", "acme/api", "repository_owner", "acme",
		"ref", "refs/heads/main"), pairs...)
}

func wiFailure(t *testing.T, err error) string {
	t.Helper()
	failure, ok := err.(*WebIdentityFailure)
	if !ok {
		t.Fatalf("expected a WebIdentityFailure, got %v", err)
	}
	return failure.Reason
}

func TestWebIdentityStaticKeys(t *testing.T) {
	keys := webIdentityTestKeys(t)
	ctx := context.Background()
	for _, key := range []*stsTestKey{keys.rsa, keys.rsaPss, keys.ec, keys.ed} {
		s := newWebIdentitySetup(nil)
		token := stsSignJwt(t, stsSigner{key: key}, wiPayload(s.now()))
		verified, err := s.verifier.Verify(ctx, wiProvider(keys), token)
		if err != nil {
			t.Fatalf("%s: %v", key.alg, err)
		}
		iat := math.Floor(s.now() / 1000)
		if verified.Get("issuer") != wiTestIssuer || verified.Get("subject") != "repo:acme/api:ref:refs/heads/main" ||
			verified.Get("audience") != wiTestAudience || verified.Get("jti") != "jti-1" || verified.Get("issuedAt") != iat ||
			verified.Get("expiresAt") != iat+300 {
			t.Fatalf("%s: got %s", key.alg, core.MustStringify(verified))
		}
		context := verified.Get("context").(*core.Object)
		if context.Get("token.sub") != "repo:acme/api:ref:refs/heads/main" || context.Get("token.repository") != "acme/api" {
			t.Fatalf("got %s", core.MustStringify(context))
		}
		if len(s.fetchedList()) != 0 {
			t.Fatal("fetched keys for a static provider")
		}
	}
}

func TestWebIdentityAudienceArray(t *testing.T) {
	keys := webIdentityTestKeys(t)
	s := newWebIdentitySetup(nil)
	token := stsSignJwt(t, stsSigner{key: keys.rsa}, wiPayload(s.now(), "aud", []any{"other", "sts.amazonaws.com"}))
	verified := must(s.verifier.Verify(context.Background(), wiProvider(keys), token))
	if verified.Get("audience") != "sts.amazonaws.com" {
		t.Fatalf("got %v", verified.Get("audience"))
	}
}

func TestWebIdentityTypes(t *testing.T) {
	keys := webIdentityTestKeys(t)
	ctx := context.Background()
	s := newWebIdentitySetup(nil)
	body := wiPayload(s.now())
	for _, typ := range []any{core.Undefined, "JWT", "jwt", "application/jwt"} {
		if _, err := s.verifier.Verify(ctx, wiProvider(keys), stsSignJwt(t, stsSigner{key: keys.rsa}, body, "typ", typ)); err != nil {
			t.Fatalf("%v: %v", typ, err)
		}
	}
	for _, typ := range []any{"biam-session+jwt", "at+jwt", "application/at+jwt", "dpop+jwt", 7.0} {
		_, err := s.verifier.Verify(ctx, wiProvider(keys), stsSignJwt(t, stsSigner{key: keys.rsa}, body, "typ", typ))
		if wiFailure(t, err) != "type" {
			t.Fatalf("%v accepted", typ)
		}
	}
}

func TestWebIdentityRefusals(t *testing.T) {
	keys := webIdentityTestKeys(t)
	ctx := context.Background()
	s := newWebIdentitySetup(nil)
	clock := s.now()
	now := math.Floor(clock / 1000)
	rsa := stsSigner{key: keys.rsa}
	good := stsSignJwt(t, rsa, wiPayload(clock))
	cases := []struct {
		name, token, reason string
		changes             []any
	}{
		{"HS256", stsSignJwt(t, stsSigner{alg: "HS256", secret: "secret"}, wiPayload(clock)), "algorithm", nil},
		{"alg none", stsSignJwt(t, stsSigner{alg: "none"}, wiPayload(clock)), "algorithm", nil},
		{"an alg the provider does not allow", good, "algorithm", []any{"algorithms", []any{"ES256"}}},
		{"an unknown kid", stsSignJwt(t, stsSigner{key: keys.other}, wiPayload(clock)), "unknown-key", nil},
		{"a tampered payload", stsTamper(t, good, "sub", "repo:evil/api"), "signature", nil},
		{"a wrong issuer", stsSignJwt(t, rsa, wiPayload(clock, "iss", "https://evil")), "issuer", nil},
		{"a wrong audience", stsSignJwt(t, rsa, wiPayload(clock, "aud", "other")), "audience", nil},
		{"an expired token", stsSignJwt(t, rsa, wiPayload(clock, "iat", now-400, "exp", now-60)), "expired", nil},
		{"a future nbf", stsSignJwt(t, rsa, wiPayload(clock, "nbf", now+120)), "not-yet-valid", nil},
		{"a future iat", stsSignJwt(t, rsa, wiPayload(clock, "iat", now+120, "exp", now+300)), "not-yet-valid", nil},
		{"a token older than the provider allows", stsSignJwt(t, rsa, wiPayload(clock, "iat", now-3700, "exp", now+300)), "too-old", nil},
		{"a lifetime over the cap", stsSignJwt(t, rsa, wiPayload(clock, "exp", now+3601)), "lifetime", nil},
		{"a missing sub", stsSignJwt(t, rsa, wiPayload(clock, "sub", core.Undefined)), "claims", nil},
		{"a missing exp", stsSignJwt(t, rsa, wiPayload(clock, "exp", core.Undefined)), "claims", nil},
		{"a long sub", stsSignJwt(t, rsa, wiPayload(clock, "sub", strings.Repeat("x", 513))), "claims", nil},
		{"a numeric sub", stsSignJwt(t, rsa, wiPayload(clock, "sub", 42.0)), "claims", nil},
		{"a numeric jti", stsSignJwt(t, rsa, wiPayload(clock, "jti", 42.0)), "claims", nil},
		{"garbage", "not a token", "malformed", nil},
		{"an oversized token", good + strings.Repeat("A", 8192), "malformed", nil},
		{"IAM's own issuer", good, "issuer", []any{"issuer", "http://localhost:3000/api/iam"}},
	}
	withSelf := newWebIdentitySetup(func(options *WebIdentityVerifierOptions) { options.SelfIssuer = "http://localhost:3000/api/iam" })
	for _, c := range cases {
		target := s.verifier
		if len(c.changes) > 0 && c.changes[0] == "issuer" {
			target = withSelf.verifier
		}
		_, err := target.Verify(ctx, wiProvider(keys, c.changes...), c.token)
		if got := wiFailure(t, err); got != c.reason {
			t.Fatalf("%s: got %s, want %s", c.name, got, c.reason)
		}
	}
}

func TestWebIdentityIgnoresUnusableStaticKeys(t *testing.T) {
	keys := webIdentityTestKeys(t)
	s := newWebIdentitySetup(nil)
	weak := stsGenerateKey(t, "RS256", "weak", 1024)
	token := stsSignJwt(t, stsSigner{key: weak}, wiPayload(s.now()))
	weakJwk := stsWith(weak.publicJwk, "use", core.Undefined)
	_, err := s.verifier.Verify(context.Background(), wiProvider(keys, "jwks", core.NewObject("keys", []any{weakJwk, keys.ec.publicJwk})), token)
	if wiFailure(t, err) != "unknown-key" {
		t.Fatal("expected unknown-key")
	}
}

func TestWebIdentityFetchesAndCachesKeys(t *testing.T) {
	keys := webIdentityTestKeys(t)
	ctx := context.Background()
	s := newWebIdentitySetup(nil)
	s.set(wiTestJwksURI, core.NewObject("keys", []any{keys.rsa.publicJwk}))
	config := wiProvider(keys, "jwks", core.Undefined, "jwksUri", wiTestJwksURI)
	rsa := stsSigner{key: keys.rsa}
	must(s.verifier.Verify(ctx, config, stsSignJwt(t, rsa, wiPayload(s.now()))))
	must(s.verifier.Verify(ctx, config, stsSignJwt(t, rsa, wiPayload(s.now(), "jti", "jti-2"))))
	if strings.Join(s.fetchedList(), ",") != wiTestJwksURI {
		t.Fatalf("got %v", s.fetchedList())
	}
	s.advance(601_000)
	must(s.verifier.Verify(ctx, config, stsSignJwt(t, rsa, wiPayload(s.now()))))
	if len(s.fetchedList()) != 2 {
		t.Fatalf("got %v", s.fetchedList())
	}
}

func TestWebIdentitySingleFlight(t *testing.T) {
	keys := webIdentityTestKeys(t)
	s := newWebIdentitySetup(nil)
	s.set(wiTestJwksURI, core.NewObject("keys", []any{keys.rsa.publicJwk}))
	config := wiProvider(keys, "jwks", core.Undefined, "jwksUri", wiTestJwksURI)
	token := stsSignJwt(t, stsSigner{key: keys.rsa}, wiPayload(s.now()))
	var wait sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			_, errs[i] = s.verifier.Verify(context.Background(), config, token)
		}(i)
	}
	wait.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(s.fetchedList()) != 1 {
		t.Fatalf("got %v", s.fetchedList())
	}
}

func TestWebIdentityDiscovery(t *testing.T) {
	keys := webIdentityTestKeys(t)
	ctx := context.Background()
	discovery := wiTestIssuer + "/.well-known/openid-configuration"
	s := newWebIdentitySetup(nil)
	s.set(discovery, core.NewObject("issuer", wiTestIssuer, "jwks_uri", wiTestJwksURI))
	s.set(wiTestJwksURI, core.NewObject("keys", []any{keys.ec.publicJwk}))
	verified := must(s.verifier.Verify(ctx, wiProvider(keys, "jwks", core.Undefined), stsSignJwt(t, stsSigner{key: keys.ec}, wiPayload(s.now()))))
	if verified.Get("subject") != "repo:acme/api:ref:refs/heads/main" || strings.Join(s.fetchedList(), ",") != discovery+","+wiTestJwksURI {
		t.Fatalf("got %v", s.fetchedList())
	}

	// A discovery document for another issuer is refused, and the failure is cached for 30 seconds.
	s = newWebIdentitySetup(nil)
	s.set(discovery, core.NewObject("issuer", "https://evil.example", "jwks_uri", wiTestJwksURI))
	s.set(wiTestJwksURI, core.NewObject("keys", []any{keys.ec.publicJwk}))
	config := wiProvider(keys, "jwks", core.Undefined)
	token := stsSignJwt(t, stsSigner{key: keys.ec}, wiPayload(s.now()))
	for i := 0; i < 2; i++ {
		if _, err := s.verifier.Verify(ctx, config, token); wiFailure(t, err) != "jwks-unavailable" {
			t.Fatal("expected jwks-unavailable")
		}
	}
	if strings.Join(s.fetchedList(), ",") != discovery {
		t.Fatalf("got %v", s.fetchedList())
	}
	s.set(discovery, core.NewObject("issuer", wiTestIssuer, "jwks_uri", wiTestJwksURI))
	s.advance(31_000)
	must(s.verifier.Verify(ctx, config, stsSignJwt(t, stsSigner{key: keys.ec}, wiPayload(s.now()))))
	if strings.Join(s.fetchedList(), ",") != discovery+","+discovery+","+wiTestJwksURI {
		t.Fatalf("got %v", s.fetchedList())
	}

	// A discovery jwks_uri that breaks the URL rules is refused.
	s = newWebIdentitySetup(nil)
	s.set(discovery, core.NewObject("issuer", wiTestIssuer, "jwks_uri", "http://token.actions.githubusercontent.com/jwks"))
	if _, err := s.verifier.Verify(ctx, wiProvider(keys, "jwks", core.Undefined), token); wiFailure(t, err) != "jwks-unavailable" {
		t.Fatal("expected jwks-unavailable")
	}
	if strings.Join(s.fetchedList(), ",") != discovery {
		t.Fatalf("got %v", s.fetchedList())
	}
}

func TestWebIdentityUnknownKidCooldown(t *testing.T) {
	keys := webIdentityTestKeys(t)
	ctx := context.Background()
	s := newWebIdentitySetup(nil)
	s.set(wiTestJwksURI, core.NewObject("keys", []any{keys.rsa.publicJwk}))
	config := wiProvider(keys, "jwks", core.Undefined, "jwksUri", wiTestJwksURI)
	must(s.verifier.Verify(ctx, config, stsSignJwt(t, stsSigner{key: keys.rsa}, wiPayload(s.now()))))
	// The IdP rotates in a new key; within the cooldown the unknown kid is refused without a fetch.
	s.set(wiTestJwksURI, core.NewObject("keys", []any{keys.rsa.publicJwk, keys.other.publicJwk}))
	s.advance(10_000)
	if _, err := s.verifier.Verify(ctx, config, stsSignJwt(t, stsSigner{key: keys.other}, wiPayload(s.now()))); wiFailure(t, err) != "unknown-key" {
		t.Fatal("expected unknown-key")
	}
	if len(s.fetchedList()) != 1 {
		t.Fatalf("got %v", s.fetchedList())
	}
	s.advance(21_000)
	must(s.verifier.Verify(ctx, config, stsSignJwt(t, stsSigner{key: keys.other}, wiPayload(s.now()))))
	if len(s.fetchedList()) != 2 {
		t.Fatalf("got %v", s.fetchedList())
	}
	// A kid the IdP never published is refused, and the cooldown stops a refetch storm.
	stranger := stsGenerateKey(t, "RS256", "stranger")
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := s.verifier.Verify(ctx, config, stsSignJwt(t, stsSigner{key: stranger}, wiPayload(s.now()))); wiFailure(t, err) != "unknown-key" {
			t.Fatal("expected unknown-key")
		}
	}
	if len(s.fetchedList()) != 2 {
		t.Fatalf("got %v", s.fetchedList())
	}
}

func TestWebIdentityCooldownWhileFailing(t *testing.T) {
	keys := webIdentityTestKeys(t)
	ctx := context.Background()
	s := newWebIdentitySetup(nil)
	s.set(wiTestJwksURI, core.NewObject("keys", []any{keys.rsa.publicJwk}))
	config := wiProvider(keys, "jwks", core.Undefined, "jwksUri", wiTestJwksURI)
	must(s.verifier.Verify(ctx, config, stsSignJwt(t, stsSigner{key: keys.rsa}, wiPayload(s.now()))))
	// The JWKS endpoint goes down while the cached keys are still fresh but older than the cooldown.
	s.set(wiTestJwksURI, nil)
	s.advance(31_000)
	stranger := stsGenerateKey(t, "RS256", "stranger")
	reasons := []string{}
	for attempt := 0; attempt < 3; attempt++ {
		_, err := s.verifier.Verify(ctx, config, stsSignJwt(t, stsSigner{key: stranger}, wiPayload(s.now())))
		reasons = append(reasons, wiFailure(t, err))
		s.advance(5_000)
	}
	if strings.Join(reasons, ",") != "jwks-unavailable,unknown-key,unknown-key" {
		t.Fatalf("got %v", reasons)
	}
	// One refetch attempt, not one per token.
	if len(s.fetchedList()) != 2 {
		t.Fatalf("got %v", s.fetchedList())
	}
	// Tokens with a known kid keep verifying from the cache meanwhile.
	must(s.verifier.Verify(ctx, config, stsSignJwt(t, stsSigner{key: keys.rsa}, wiPayload(s.now()))))
	if len(s.fetchedList()) != 2 {
		t.Fatalf("got %v", s.fetchedList())
	}
	// Once the cooldown after the failed attempt has run out, an unknown kid may refetch again.
	s.set(wiTestJwksURI, core.NewObject("keys", []any{keys.rsa.publicJwk, stranger.publicJwk}))
	s.advance(30_000)
	must(s.verifier.Verify(ctx, config, stsSignJwt(t, stsSigner{key: stranger}, wiPayload(s.now()))))
	if len(s.fetchedList()) != 3 {
		t.Fatalf("got %v", s.fetchedList())
	}
}

func TestWebIdentityForgetsKeys(t *testing.T) {
	keys := webIdentityTestKeys(t)
	ctx := context.Background()
	s := newWebIdentitySetup(nil)
	s.set(wiTestJwksURI, core.NewObject("keys", []any{keys.rsa.publicJwk}))
	config := wiProvider(keys, "jwks", core.Undefined, "jwksUri", wiTestJwksURI)
	token := stsSignJwt(t, stsSigner{key: keys.rsa}, wiPayload(s.now()))
	must(s.verifier.Verify(ctx, config, token))
	must(s.verifier.Verify(ctx, stsWith(config, "updatedAt", 2.0), token))
	if len(s.fetchedList()) != 2 {
		t.Fatalf("got %v", s.fetchedList())
	}
	_ = s.verifier.Forget("provider-1")
	must(s.verifier.Verify(ctx, stsWith(config, "updatedAt", 2.0), token))
	if len(s.fetchedList()) != 3 {
		t.Fatalf("got %v", s.fetchedList())
	}
}

func TestWebIdentityFiltersFetchedKeys(t *testing.T) {
	keys := webIdentityTestKeys(t)
	ctx := context.Background()
	s := newWebIdentitySetup(nil)
	s.set(wiTestJwksURI, core.NewObject("keys", []any{keys.rsa.privateJwk.Clone(), stsWith(keys.ec.publicJwk, "use", "enc"),
		core.NewObject("kty", "oct", "k", "c2VjcmV0", "kid", "hmac")}))
	config := wiProvider(keys, "jwks", core.Undefined, "jwksUri", wiTestJwksURI)
	if _, err := s.verifier.Verify(ctx, config, stsSignJwt(t, stsSigner{key: keys.rsa}, wiPayload(s.now()))); wiFailure(t, err) != "jwks-unavailable" {
		t.Fatal("expected jwks-unavailable")
	}
	// A failing transport is jwks-unavailable too.
	s = newWebIdentitySetup(nil)
	if _, err := s.verifier.Verify(ctx, config, stsSignJwt(t, stsSigner{key: keys.rsa}, wiPayload(s.now()))); wiFailure(t, err) != "jwks-unavailable" {
		t.Fatal("expected jwks-unavailable")
	}
}

func TestWebIdentityFlattenClaims(t *testing.T) {
	many := []any{}
	for i := 0; i < 65; i++ {
		many = append(many, float64(i))
	}
	payload := core.NewObject(
		"sub", "system:serviceaccount:ci:deployer", "aud", []any{"a", "b"}, "exp", 1.0, "admin", false,
		"kubernetes.io", core.NewObject("namespace", "ci",
			"serviceaccount", core.NewObject("name", "deployer", "uid", "u-1", "deeper", core.NewObject("tooDeep", true)),
			"pod", nil),
		"long", strings.Repeat("x", 1025), "exactly", strings.Repeat("y", 1024), "mixed", []any{"a", core.NewObject("b", 1.0)},
		"many", many, "bad key", "v", "__proto__", "polluted", "nan", math.NaN(),
	)
	stsSame(t, FlattenClaims(payload), core.NewObject(
		"token.sub", "system:serviceaccount:ci:deployer", "token.aud", []any{"a", "b"}, "token.exp", 1.0, "token.admin", false,
		"token.kubernetes.io.namespace", "ci", "token.kubernetes.io.serviceaccount.name", "deployer",
		"token.kubernetes.io.serviceaccount.uid", "u-1", "token.exactly", strings.Repeat("y", 1024),
	))
	wide := core.NewObject()
	for i := 0; i < 200; i++ {
		wide.Set(fmt.Sprintf("c%d", i), float64(i))
	}
	flattened := FlattenClaims(wide)
	if flattened.Len() != 128 || flattened.Get("token.c127") != 127.0 || flattened.Has("token.c128") {
		t.Fatalf("got %d keys", flattened.Len())
	}
}

func TestWebIdentityConditions(t *testing.T) {
	conditions := obj(t, `{"StringLike":{"token.sub":"repo:acme/api:*"},"StringEquals":{"token.aud":"https://iam.example.com","token.repository_owner":"acme"}}`)
	validated := must(WebIdentityConditions(conditions))
	stsSame(t, validated, conditions)
	if validated == conditions {
		t.Fatal("expected a copy")
	}
	for _, text := range []string{
		`{"StringEquals":{"token.repository_owner":"acme"}}`,
		`{"StringLike":{"token.sub":"*"}}`,
		`{"StringLike":{"token.sub":"?repo:acme/api"}}`,
		`{"StringLike":{"token.sub":["repo:acme/api:*","*"]}}`,
		`{"StringEquals":{"token.sub":""}}`,
		`{"StringNotEquals":{"token.sub":"repo:evil/api"}}`,
		`{"StringEqualsIgnoreCase":{"token.sub":"repo:acme"}}`,
	} {
		_, err := WebIdentityConditions(obj(t, text))
		known := iamError(t, err)
		if known.Code != "WEAK_TRUST_CONDITIONS" || known.Status != 400 {
			t.Fatalf("%s: got %s %d", text, known.Code, known.Status)
		}
	}
	entries := `"token.sub":"repo:a"`
	for i := 0; i < 20; i++ {
		entries += fmt.Sprintf(`,"token.c%d":"v"`, i)
	}
	for _, value := range []any{
		obj(t, `{"StringEquals":{"principal.id":"x","token.sub":"repo:a"}}`),
		obj(t, `{"StringEquals":{"token.sub":"repo:${principal.id}"}}`),
		obj(t, `{"StringEquals":{`+entries+`}}`),
		parse(t, `[{"StringEquals":{"token.sub":"repo:acme/api:ref:refs/heads/main"}}]`),
		obj(t, `{"StringEquals":"token.sub"}`),
	} {
		_, err := WebIdentityConditions(value)
		if iamError(t, err).Code != "INVALID_INPUT" {
			t.Fatalf("%s: got %v", core.MustStringify(value), err)
		}
	}
	for _, text := range []string{
		`{"StringEquals":{"token.sub":"repo:acme/api:ref:refs/heads/main"},"Regex":{"token.sub":".*"}}`,
		`{"StringEquals":{"token.sub":"repo:acme/api:ref:refs/heads/main"},"NumericEquals":{"token.run_number":"one"}}`,
	} {
		_, err := WebIdentityConditions(obj(t, text))
		if iamError(t, err).Code != "INVALID_POLICY" {
			t.Fatalf("%s: got %v", text, err)
		}
	}
}

func TestMatchWebIdentityConditions(t *testing.T) {
	context := FlattenClaims(obj(t, `{"sub":"repo:acme/api:ref:refs/heads/main","repository_owner":"acme","groups":["deployers","ci"],"run_number":7}`))
	conditions := obj(t, `{"StringLike":{"token.sub":"repo:acme/api:*"},"StringEquals":{"token.repository_owner":"acme"},"ArrayContains":{"token.groups":"deployers"},"NumericGreaterThan":{"token.run_number":5}}`)
	stsSame(t, must(MatchWebIdentityConditions(conditions, context, "trust-1")), core.NewObject("matched", true, "failed", []any{}))
	failing := conditions.Clone()
	failing.Set("StringEquals", obj(t, `{"token.repository_owner":"evil","token.environment":"prod"}`))
	failing.Set("Exists", obj(t, `{"token.environment":true}`))
	stsSame(t, must(MatchWebIdentityConditions(failing, context, "trust-1")), core.NewObject("matched", false,
		"failed", []any{"StringEquals:token.repository_owner", "StringEquals:token.environment", "Exists:token.environment"}))
}

func TestWebIdentityValidators(t *testing.T) {
	keys := webIdentityTestKeys(t)
	local := WebIdentityIssuerOptions{}
	if must(WebIdentityIssuer(wiTestIssuer, local)) != wiTestIssuer || must(WebIdentityIssuer("https://gitlab.example.com/", local)) != "https://gitlab.example.com/" ||
		must(WebIdentityIssuer("http://localhost:9000", WebIdentityIssuerOptions{AllowInsecureLocalhost: true})) != "http://localhost:9000" {
		t.Fatal("expected valid issuers")
	}
	for _, value := range []any{"http://idp.example.com", "http://localhost:9000", "https://user:pass@idp.example.com",
		"https://idp.example.com/?tenant=1", "https://idp.example.com/#x", "idp.example.com",
		"https://idp.example.com/" + strings.Repeat("a", 512), 42.0} {
		if _, err := WebIdentityIssuer(value, local); iamError(t, err).Code != "INVALID_INPUT" {
			t.Fatalf("%v accepted", value)
		}
	}
	self := "https://iam.example.com/api/iam"
	expectContains(t, func() error {
		_, err := WebIdentityIssuer("https://iam.example.com/api/iam/", WebIdentityIssuerOptions{SelfIssuer: &self})
		return err
	}(), "own issuer")
	expectContains(t, func() error {
		_, err := WebIdentityIssuer(wiTestIssuer, WebIdentityIssuerOptions{AllowedIssuers: []string{"https://gitlab.com"}})
		return err
	}(), "allowedIssuers")
	if must(WebIdentityIssuer(wiTestIssuer, WebIdentityIssuerOptions{AllowedIssuers: []string{wiTestIssuer}})) != wiTestIssuer {
		t.Fatal("expected the allowed issuer")
	}

	strict := core.NewObject("allowInsecureLocalhost", false)
	for value, options := range map[string]*core.Object{
		"https://idp.example.com/jwks": strict, "https://idp.example.com:443/jwks": strict,
		"http://127.0.0.1:9000/jwks": core.NewObject("allowInsecureLocalhost", true),
	} {
		if must(WebIdentityJwksURI(value, options)) != value {
			t.Fatalf("%s refused", value)
		}
	}
	for _, value := range []string{"http://idp.example.com/jwks", "https://idp.example.com:8443/jwks", "https://user@idp.example.com/jwks",
		"https://idp.example.com/jwks#k", "https://10.0.0.1/jwks", "https://[::1]/jwks", "/jwks"} {
		if _, err := WebIdentityJwksURI(value, strict); iamError(t, err).Code != "INVALID_INPUT" {
			t.Fatalf("%s accepted", value)
		}
	}

	validated := must(WebIdentityKeys(core.NewObject("keys", []any{stsWith(keys.rsa.publicJwk, "ext", true), keys.ec.publicJwk, keys.ed.publicJwk})))
	list := validated.Get("keys").([]any)
	if len(list) != 3 {
		t.Fatalf("got %d keys", len(list))
	}
	stsSame(t, list[0], core.NewObject("kty", "RSA", "kid", "rsa-1", "alg", "RS256", "use", "sig", "n", keys.rsa.publicJwk.Get("n"),
		"e", keys.rsa.publicJwk.Get("e")))
	weak := stsGenerateKey(t, "RS256", "weak", 1024).publicJwk
	many := []any{}
	for i := 0; i < 21; i++ {
		many = append(many, keys.ec.publicJwk)
	}
	// secp256k1 is not an accepted curve.
	p256k := core.NewObject("kty", "EC", "crv", "secp256k1", "x", keys.ec.publicJwk.Get("x"), "y", keys.ec.publicJwk.Get("y"))
	for _, value := range []any{
		core.NewObject("keys", []any{}), core.NewObject("keys", many), core.NewObject("keys", []any{keys.rsa.privateJwk}),
		core.NewObject("keys", []any{weak}), core.NewObject("keys", []any{p256k}),
		core.NewObject("keys", []any{stsWith(keys.ec.publicJwk, "use", "enc")}),
		core.NewObject("keys", []any{stsWith(keys.ec.publicJwk, "alg", "HS256")}),
		core.NewObject("keys", []any{core.NewObject("kty", "oct", "k", "c2VjcmV0")}),
		[]any{keys.ec.publicJwk}, core.Undefined,
	} {
		if _, err := WebIdentityKeys(value); iamError(t, err).Code != "INVALID_INPUT" {
			t.Fatalf("%s accepted", core.MustStringify(value))
		}
	}

	if strings.Join(must(WebIdentityWebIdentityAlgorithms(core.Undefined)), ",") != "RS256,ES256" ||
		strings.Join(must(WebIdentityWebIdentityAlgorithms([]any{"EdDSA", "EdDSA", "PS256"})), ",") != "EdDSA,PS256" {
		t.Fatal("unexpected algorithms")
	}
	for _, value := range []any{[]any{}, []any{"HS256"}, []any{"none"}, []any{"ES512"}, "RS256"} {
		if _, err := WebIdentityWebIdentityAlgorithms(value); iamError(t, err).Code != "INVALID_INPUT" {
			t.Fatalf("%v accepted", value)
		}
	}
	if strings.Join(must(WebIdentityAudiences([]any{"sts.amazonaws.com", "sts.amazonaws.com", "api"})), ",") != "sts.amazonaws.com,api" {
		t.Fatal("unexpected audiences")
	}
	eleven := []any{}
	for i := 0; i < 11; i++ {
		eleven = append(eleven, fmt.Sprintf("a%d", i))
	}
	for _, value := range []any{[]any{}, []any{""}, []any{strings.Repeat("x", 257)}, eleven} {
		if _, err := WebIdentityAudiences(value); iamError(t, err).Code != "INVALID_INPUT" {
			t.Fatalf("%v accepted", value)
		}
	}
	for _, value := range []string{"token.repository_owner", "token.kubernetes.io.namespace"} {
		if must(WebIdentityClaimName(value)) != value {
			t.Fatalf("%s refused", value)
		}
	}
	for _, value := range []any{"repository_owner", "token.", "principal.id", "token.a b", 42.0} {
		if _, err := WebIdentityClaimName(value); iamError(t, err).Code != "INVALID_INPUT" {
			t.Fatalf("%v accepted", value)
		}
	}
}

func TestWebIdentityReplayIDs(t *testing.T) {
	sha := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
	byJti := must(WebIdentityReplayID("provider-1", "jti-1", "h.p.sig-a"))
	if len(byJti) != 64 || must(WebIdentityReplayID("provider-1", "jti-1", "h.q.sig-b")) != byJti ||
		must(WebIdentityReplayID("provider-2", "jti-1", "h.p.sig-a")) == byJti {
		t.Fatal("unexpected jti replay ids")
	}
	byToken := must(WebIdentityReplayID("provider-1", "", "h.p.sig-a"))
	if byToken == byJti || must(WebIdentityReplayID("provider-1", "", "h.p.sig-other")) != byToken ||
		must(WebIdentityReplayID("provider-1", "", "h.q.sig-a")) == byToken || strings.Contains(byToken, "h.p") {
		t.Fatal("unexpected token replay ids")
	}
	if byJti != sha("wi\nprovider-1\njti:jti-1") || byToken != sha("wi\nprovider-1\ntok:"+sha("h.p")) {
		t.Fatal("unexpected formula")
	}
}

func TestWebIdentityReplayIDMalleability(t *testing.T) {
	key := stsGenerateKey(t, "ES256", "malleable")
	token := stsSignJwt(t, stsSigner{key: key}, core.NewObject("iss", "https://idp.example.test", "aud", "better-iam",
		"sub", "repo:acme/app:ref:refs/heads/main", "iat", 1_800_000_000.0, "exp", 1_800_000_300.0))
	parts := strings.Split(token, ".")
	raw := nodeBase64Decode(parts[2])
	n, _ := new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
	s := new(big.Int).SetBytes(raw[32:])
	flipped := append(append([]byte{}, raw[:32]...), new(big.Int).Sub(n, s).FillBytes(make([]byte, 32))...)
	malleated := parts[0] + "." + parts[1] + "." + base64url(flipped)
	if malleated == token {
		t.Fatal("expected a different spelling")
	}
	set := must(sjwtNewLocalSet(core.NewObject("keys", []any{key.publicJwk})))
	for _, value := range []string{token, malleated} {
		header := must(sjwtDecodeProtectedHeader(value))
		public := must(set.resolve(context.Background(), header))
		pieces := strings.Split(value, ".")
		if !sjwtVerifySignature(sjwtAlgorithms["ES256"], public, nodeBase64Decode(pieces[2]), []byte(pieces[0]+"."+pieces[1])) {
			t.Fatal("expected both spellings to verify")
		}
	}
	if must(WebIdentityReplayID("p", "", malleated)) != must(WebIdentityReplayID("p", "", token)) {
		t.Fatal("malleated signature changed the replay id")
	}
}
