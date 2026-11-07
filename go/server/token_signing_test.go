package server

// Port of tests/session-token-signing.test.ts: the session token signer (token-signing.ts) and the offline verifier
// (session-tokens.ts).

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

const signingTestIssuer = "http://localhost:3000/api/iam"

type signingFixture struct {
	t       *testing.T
	clock   atomic.Int64
	ed      *stsTestKey
	ec      *stsTestKey
	retired *stsTestKey
}

func newSigningFixture(t *testing.T) *signingFixture {
	f := &signingFixture{t: t, ed: stsGenerateKey(t, "EdDSA", "ed-1"), ec: stsGenerateKey(t, "ES256", "ec-1"),
		retired: stsGenerateKey(t, "EdDSA", "ed-old")}
	f.clock.Store(time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC).UnixMilli())
	return f
}

func (f *signingFixture) now() int64 { return f.clock.Load() }

// signer builds a signer over [ed, ec] with the options adjusted.
func (f *signingFixture) signer(adjust func(options *SessionTokenSigningOptions)) *SessionTokenSigner {
	f.t.Helper()
	options := &SessionTokenSigningOptions{SigningKeys: []*core.Object{f.ed.privateJwk, f.ec.privateJwk}}
	if adjust != nil {
		adjust(options)
	}
	result, err := CreateSessionTokenSigner(options, signingTestIssuer, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	if result == nil {
		f.t.Fatal("expected a signer")
	}
	return result
}

// claims is the default claims with members replaced (core.Undefined removes one).
func (f *signingFixture) claims(pairs ...any) *core.Object {
	iat := math.Floor(float64(f.now()) / 1000)
	base := core.NewObject("iss", signingTestIssuer, "aud", signingTestIssuer, "sub", "identity-1", "tid", "tenant-1",
		"sid", "session-1", "jti", "session-1", "iat", iat, "nbf", iat, "exp", iat+900, "auth_time", iat-60,
		"kind", "role", "mfa", true, "role", "role-1", "trust", "trust-1")
	return stsWith(base, pairs...)
}

func signingReason(t *testing.T, err error) string {
	t.Helper()
	known, ok := err.(*SessionTokenError)
	if !ok {
		t.Fatalf("expected a SessionTokenError, got %v", err)
	}
	return known.Reason
}

func (f *signingFixture) sign(signer *SessionTokenSigner, claims *core.Object) string {
	f.t.Helper()
	token, err := signer.Sign(context.Background(), claims)
	if err != nil {
		f.t.Fatal(err)
	}
	return token
}

func TestSessionTokenSignerConfiguration(t *testing.T) {
	f := newSigningFixture(t)
	if result, err := CreateSessionTokenSigner(nil, signingTestIssuer, f.now); result != nil || err != nil {
		t.Fatal("expected nil when sts.jwt is not configured")
	}
	many := func(key *core.Object, prefix string, count int) []*core.Object {
		keys := []*core.Object{}
		for i := 0; i < count; i++ {
			keys = append(keys, stsWith(key, "kid", fmt.Sprintf("%s%d", prefix, i)))
		}
		return keys
	}
	ed, ec, retired := f.ed.privateJwk, f.ec.privateJwk, f.retired
	cases := []struct {
		name    string
		options SessionTokenSigningOptions
		message string
	}{
		{"no signing keys", SessionTokenSigningOptions{SigningKeys: []*core.Object{}}, "sts.jwt.signingKeys"},
		{"more than ten signing keys", SessionTokenSigningOptions{SigningKeys: many(ed, "k", 11)}, "sts.jwt.signingKeys"},
		{"an RSA key", SessionTokenSigningOptions{SigningKeys: []*core.Object{stsGenerateKey(t, "RS256", "rsa").privateJwk}}, "sts.jwt.signingKeys"},
		{"an ES384 key", SessionTokenSigningOptions{SigningKeys: []*core.Object{stsGenerateKey(t, "ES384", "p384").privateJwk}}, "sts.jwt.signingKeys"},
		{"a key without alg", SessionTokenSigningOptions{SigningKeys: []*core.Object{stsWith(ed, "alg", core.Undefined)}}, "signingKeys"},
		{"a public signing key", SessionTokenSigningOptions{SigningKeys: []*core.Object{f.ed.publicJwk}}, "must be private keys"},
		{"a bad kid", SessionTokenSigningOptions{SigningKeys: []*core.Object{stsWith(ed, "kid", "has space")}}, "kid"},
		{"a missing kid", SessionTokenSigningOptions{SigningKeys: []*core.Object{stsWith(ed, "kid", core.Undefined)}}, "kid"},
		{"use enc", SessionTokenSigningOptions{SigningKeys: []*core.Object{stsWith(ed, "use", "enc")}}, "use 'sig'"},
		{"key_ops without sign", SessionTokenSigningOptions{SigningKeys: []*core.Object{stsWith(ed, "key_ops", []any{"verify"})}}, "key_ops"},
		{"a key whose public part does not match", SessionTokenSigningOptions{SigningKeys: []*core.Object{stsWith(ed, "x", retired.publicJwk.Get("x"))}}, "not a valid EdDSA key"},
		{"duplicate kids", SessionTokenSigningOptions{SigningKeys: []*core.Object{ed, stsWith(ec, "kid", "ed-1")}}, "more than once"},
		{"a kid reused by a verification key", SessionTokenSigningOptions{SigningKeys: []*core.Object{ed}, VerificationKeys: []*core.Object{stsWith(retired.publicJwk, "kid", "ed-1")}}, "more than once"},
		{"a private verification key", SessionTokenSigningOptions{SigningKeys: []*core.Object{ed}, VerificationKeys: []*core.Object{retired.privateJwk}}, "sts.jwt.verificationKeys must contain public keys only"},
		{"more than ten verification keys", SessionTokenSigningOptions{SigningKeys: []*core.Object{ed}, VerificationKeys: many(retired.publicJwk, "v", 11)}, "sts.jwt.verificationKeys"},
		{"an unknown activeKeyId", SessionTokenSigningOptions{SigningKeys: []*core.Object{ed}, ActiveKeyID: str("ed-old")}, "sts.jwt.activeKeyId"},
		{"maxLifetimeSeconds 299", SessionTokenSigningOptions{SigningKeys: []*core.Object{ed}, MaxLifetimeSeconds: float(299)}, "maxLifetime"},
		{"maxLifetimeSeconds 43201", SessionTokenSigningOptions{SigningKeys: []*core.Object{ed}, MaxLifetimeSeconds: float(43201)}, "maxLifetime"},
		{"a bad audience", SessionTokenSigningOptions{SigningKeys: []*core.Object{ed}, Audiences: []string{"-bad"}}, "sts.jwt.audiences"},
		{"an issuer with a query", SessionTokenSigningOptions{SigningKeys: []*core.Object{ed}, Issuer: str("https://iam.example.com/?x=1")}, "sts.jwt.issuer"},
		{"a relative issuer", SessionTokenSigningOptions{SigningKeys: []*core.Object{ed}, Issuer: str("/api/iam")}, "sts.jwt.issuer"},
	}
	for _, c := range cases {
		options := c.options
		_, err := CreateSessionTokenSigner(&options, signingTestIssuer, f.now)
		known := iamError(t, err)
		if known.Code != "INVALID_CONFIG" || !strings.Contains(known.Message, c.message) {
			t.Fatalf("%s: got %s %q", c.name, known.Code, known.Message)
		}
	}
}

func TestSessionTokenSignerDefaults(t *testing.T) {
	f := newSigningFixture(t)
	result := f.signer(func(options *SessionTokenSigningOptions) {
		options.Audiences = []string{"billing-api", signingTestIssuer, "billing-api"}
	})
	if result.Issuer != signingTestIssuer || strings.Join(result.Audiences, ",") != signingTestIssuer+",billing-api" ||
		result.MaxLifetimeSeconds != 3600 {
		t.Fatalf("got %s %v %v", result.Issuer, result.Audiences, result.MaxLifetimeSeconds)
	}
}

func TestSessionTokenSignerPublicJwks(t *testing.T) {
	f := newSigningFixture(t)
	result := f.signer(func(options *SessionTokenSigningOptions) {
		options.VerificationKeys = []*core.Object{f.retired.publicJwk}
	})
	jwks := must(result.PublicJwks())
	keys := jwks.Get("keys").([]any)
	kids := []string{}
	for _, item := range keys {
		key := item.(*core.Object)
		kids = append(kids, key.Get("kid").(string))
		if key.Get("use") != "sig" {
			t.Fatal("use must be sig")
		}
		for _, member := range key.Keys() {
			if !containsString([]string{"kty", "crv", "x", "y", "kid", "alg", "use"}, member) {
				t.Fatalf("unexpected member %s", member)
			}
		}
	}
	if strings.Join(kids, ",") != "ed-1,ec-1,ed-old" {
		t.Fatalf("got %v", kids)
	}
	stsSame(t, keys[0], core.NewObject("kty", "OKP", "crv", "Ed25519", "x", f.ed.publicJwk.Get("x"), "kid", "ed-1",
		"alg", "EdDSA", "use", "sig"))
	second := keys[1].(*core.Object)
	if second.Get("kty") != "EC" || second.Get("crv") != "P-256" || second.Get("y") != f.ec.publicJwk.Get("y") || second.Get("alg") != "ES256" {
		t.Fatal("unexpected EC key")
	}
	text, _, _ := core.Stringify(keys)
	if strings.Contains(text, f.ed.privateJwk.Get("d").(string)) {
		t.Fatal("leaked the private key")
	}
	// The returned set is a copy.
	keys[0].(*core.Object).Set("kid", "changed")
	if must(result.PublicJwks()).Get("keys").([]any)[0].(*core.Object).Get("kid") != "ed-1" {
		t.Fatal("the set is not a copy")
	}
}

func TestSessionTokenSigningRoundTrips(t *testing.T) {
	f := newSigningFixture(t)
	for _, c := range [][2]string{{"EdDSA", "ed-1"}, {"ES256", "ec-1"}} {
		alg, kid := c[0], c[1]
		result := f.signer(func(options *SessionTokenSigningOptions) { options.ActiveKeyID = str(kid) })
		token := f.sign(result, f.claims())
		if !LooksLikeJwt(token) {
			t.Fatal("not a JWT")
		}
		header, payload := stsDecodeJwt(t, token)
		stsSame(t, header, core.NewObject("alg", alg, "kid", kid, "typ", SessionTokenType))
		stsSame(t, payload, f.claims())
		stsSame(t, must(result.Verify(context.Background(), token, "")), f.claims())

		// A key whose metadata lists sign and verify key_ops signs too.
		key := f.ed
		if alg == "ES256" {
			key = f.ec
		}
		withOps := f.signer(func(options *SessionTokenSigningOptions) {
			options.SigningKeys = []*core.Object{stsWith(key.privateJwk, "use", "sig", "key_ops", []any{"sign", "verify"}, "ext", true)}
			options.ActiveKeyID = str(kid)
		})
		token = f.sign(withOps, f.claims())
		header, _ = stsDecodeJwt(t, token)
		stsSame(t, header, core.NewObject("alg", alg, "kid", kid, "typ", SessionTokenType))
		stsSame(t, must(withOps.Verify(context.Background(), token, "")), f.claims())
	}
}

func TestSessionTokenSignerAudiences(t *testing.T) {
	f := newSigningFixture(t)
	ctx := context.Background()
	result := f.signer(func(options *SessionTokenSigningOptions) { options.Audiences = []string{"billing-api"} })
	token := f.sign(result, f.claims("aud", []any{signingTestIssuer, "billing-api"}))
	verified := must(result.Verify(ctx, token, "billing-api"))
	stsSame(t, verified.Get("aud"), []any{signingTestIssuer, "billing-api"})
	downstream := f.sign(result, f.claims("aud", "billing-api"))
	if _, err := result.Verify(ctx, downstream, ""); signingReason(t, err) != "audience" {
		t.Fatal("expected audience")
	}
	if _, err := result.Verify(ctx, token, "other-api"); signingReason(t, err) != "audience" {
		t.Fatal("expected audience")
	}
	// Unknown claims are dropped from the result.
	extra := f.sign(result, f.claims("extra", "x"))
	if must(result.Verify(ctx, extra, "")).Has("extra") {
		t.Fatal("kept an unknown claim")
	}
}

func TestSessionTokenVerificationRefusals(t *testing.T) {
	f := newSigningFixture(t)
	ctx := context.Background()
	result := f.signer(func(options *SessionTokenSigningOptions) { options.MaxLifetimeSeconds = float(900) })
	good := f.sign(result, f.claims())
	now := math.Floor(float64(f.now()) / 1000)
	ed := stsSigner{key: f.ed}
	cases := []struct {
		name, token, reason string
	}{
		{"tampered payload", stsTamper(t, good, "sub", "identity-2"), "signature"},
		{"alg none without a signature", stsSignJwt(t, stsSigner{alg: "none"}, f.claims(), "typ", SessionTokenType, "kid", "ed-1"), "malformed"},
		{"alg none with a fake signature", stsSignJwt(t, stsSigner{alg: "none"}, f.claims(), "typ", SessionTokenType, "kid", "ed-1") + "AAAA", "algorithm"},
		{"HS256 keyed with the public x", stsSignJwt(t, stsSigner{alg: "HS256", secret: f.ed.publicJwk.Get("x").(string)}, f.claims(), "typ", SessionTokenType, "kid", "ed-1"), "algorithm"},
		{"the alg swapped on a kid", stsSignJwt(t, ed, f.claims(), "typ", SessionTokenType, "alg", "ES256"), "algorithm"},
		{"a JWT typ", stsSignJwt(t, ed, f.claims(), "typ", "JWT"), "type"},
		{"an at+jwt typ", stsSignJwt(t, ed, f.claims(), "typ", "at+jwt"), "type"},
		{"no typ", stsSignJwt(t, ed, f.claims(), "typ", core.Undefined), "type"},
		{"an unknown kid", stsSignJwt(t, stsSigner{key: f.retired}, f.claims(), "typ", SessionTokenType), "unknown-key"},
		{"no kid", stsSignJwt(t, ed, f.claims(), "typ", SessionTokenType, "kid", core.Undefined), "unknown-key"},
		{"a wrong issuer", f.sign(result, f.claims("iss", "https://evil.example")), "issuer"},
		{"a wrong audience", f.sign(result, f.claims("aud", "https://evil.example")), "audience"},
		{"an expired token", f.sign(result, f.claims("exp", now-10)), "expired"},
		{"a future nbf", f.sign(result, f.claims("nbf", now+60)), "not-yet-valid"},
		{"a lifetime over the cap", f.sign(result, f.claims("exp", now+901)), "lifetime"},
		{"a user kind", f.sign(result, f.claims("kind", "user")), "kind"},
		{"an api-key kind", f.sign(result, f.claims("kind", "api-key")), "kind"},
		{"a missing tid", f.sign(result, f.claims("tid", core.Undefined)), "claims"},
		{"a jti that is not the sid", f.sign(result, f.claims("jti", "other")), "claims"},
		{"a non-boolean mfa", f.sign(result, f.claims("mfa", "yes")), "claims"},
		{"a numeric role", f.sign(result, f.claims("role", 7.0)), "claims"},
		{"a garbage string", "not-a-jwt", "malformed"},
		{"a header that is not JSON", "aaaa.bbbb.cccc", "malformed"},
		{"an oversized token", good + strings.Repeat("A", 4096), "too-large"},
	}
	for _, c := range cases {
		_, err := result.Verify(ctx, c.token, "")
		if got := signingReason(t, err); got != c.reason {
			t.Fatalf("%s: got %s, want %s", c.name, got, c.reason)
		}
	}
}

func TestSessionTokenClockSkew(t *testing.T) {
	f := newSigningFixture(t)
	ctx := context.Background()
	result := f.signer(nil)
	token := f.sign(result, f.claims("exp", math.Floor(float64(f.now())/1000)+60))
	f.clock.Add(63_000)
	if _, err := result.Verify(ctx, token, ""); err != nil {
		t.Fatal(err)
	}
	f.clock.Add(3_000)
	if _, err := result.Verify(ctx, token, ""); signingReason(t, err) != "expired" {
		t.Fatal("expected expired")
	}
}

func TestSessionTokenKeyRotation(t *testing.T) {
	f := newSigningFixture(t)
	ctx := context.Background()
	before, err := CreateSessionTokenSigner(&SessionTokenSigningOptions{SigningKeys: []*core.Object{f.retired.privateJwk}}, signingTestIssuer, f.now)
	if err != nil {
		t.Fatal(err)
	}
	token := f.sign(before, f.claims())
	during := f.signer(func(options *SessionTokenSigningOptions) {
		options.VerificationKeys = []*core.Object{f.retired.publicJwk}
	})
	if must(during.Verify(ctx, token, "")).Get("sid") != "session-1" {
		t.Fatal("expected the retired key to verify")
	}
	header, _ := stsDecodeJwt(t, f.sign(during, f.claims()))
	if header.Get("kid") != "ed-1" {
		t.Fatal("expected the active key")
	}
	// Removing the kid from both lists revokes its tokens.
	if _, err := f.signer(nil).Verify(ctx, token, ""); signingReason(t, err) != "unknown-key" {
		t.Fatal("expected unknown-key")
	}
}

// serveJwks serves a JWKS on 127.0.0.1 and counts the requests.
func serveJwks(t *testing.T, body func() any) (string, *atomic.Int64, func()) {
	t.Helper()
	hits := &atomic.Int64{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("content-type", "application/json")
		text, _, _ := core.Stringify(body())
		_, _ = w.Write([]byte(text))
	})}
	go func() { _ = server.Serve(listener) }()
	closed := false
	stop := func() {
		if !closed {
			closed = true
			_ = server.Close()
		}
	}
	t.Cleanup(stop)
	url := fmt.Sprintf("http://%s/api/iam/.well-known/jwks.json", listener.Addr().String())
	return url, hits, stop
}

func TestSessionTokenVerifierRemoteJwks(t *testing.T) {
	f := newSigningFixture(t)
	ctx := context.Background()
	keys := []any{f.ed.publicJwk}
	url, hits, _ := serveJwks(t, func() any { return core.NewObject("keys", keys) })
	verifier, err := CreateSessionTokenVerifier(&SessionTokenVerifierOptions{Issuer: signingTestIssuer, Audience: signingTestIssuer,
		JWKS: url, Now: f.now, CooldownSeconds: float(0)})
	if err != nil {
		t.Fatal(err)
	}
	first := must(CreateSessionTokenSigner(&SessionTokenSigningOptions{SigningKeys: []*core.Object{f.ed.privateJwk}}, signingTestIssuer, f.now))
	if must(verifier.Verify(ctx, f.sign(first, f.claims()))).Get("kind") != "role" {
		t.Fatal("expected a role token")
	}
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
	must(verifier.Verify(ctx, f.sign(first, f.claims())))
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
	// A new kid appears at the JWKS route; the verifier refetches once.
	keys = []any{f.ed.publicJwk, f.ec.publicJwk}
	second := must(CreateSessionTokenSigner(&SessionTokenSigningOptions{SigningKeys: []*core.Object{f.ec.privateJwk}}, signingTestIssuer, f.now))
	must(verifier.Verify(ctx, f.sign(second, f.claims())))
	if hits.Load() != 2 {
		t.Fatalf("hits %d", hits.Load())
	}
}

func TestSessionTokenVerifierUnreachableJwks(t *testing.T) {
	f := newSigningFixture(t)
	url, _, stop := serveJwks(t, func() any { return core.NewObject("keys", []any{}) })
	stop()
	verifier := must(CreateSessionTokenVerifier(&SessionTokenVerifierOptions{Issuer: signingTestIssuer, Audience: signingTestIssuer, JWKS: url, Now: f.now}))
	_, err := verifier.Verify(context.Background(), f.sign(f.signer(nil), f.claims()))
	if signingReason(t, err) != "jwks" {
		t.Fatal("expected jwks")
	}
}

func TestSessionTokenVerifierOptions(t *testing.T) {
	f := newSigningFixture(t)
	jwks := must(f.signer(nil).PublicJwks())
	typeError := func(options *SessionTokenVerifierOptions) {
		t.Helper()
		_, err := CreateSessionTokenVerifier(options)
		if _, ok := err.(*core.TypeError); !ok {
			t.Fatalf("expected a TypeError, got %v", err)
		}
	}
	typeError(&SessionTokenVerifierOptions{Issuer: signingTestIssuer, Audience: signingTestIssuer, JWKS: "http://iam.example.com/jwks"})
	typeError(&SessionTokenVerifierOptions{Issuer: signingTestIssuer, Audience: []string{}, JWKS: jwks})
	typeError(&SessionTokenVerifierOptions{Issuer: signingTestIssuer, Audience: signingTestIssuer, JWKS: jwks, ClockToleranceSeconds: float(61)})
	typeError(&SessionTokenVerifierOptions{Issuer: signingTestIssuer, Audience: signingTestIssuer, JWKS: jwks, Algorithms: []string{"RS256"}})
}

func TestSessionTokenVerifierAudiencesAlgorithmsKinds(t *testing.T) {
	f := newSigningFixture(t)
	ctx := context.Background()
	result := f.signer(func(options *SessionTokenSigningOptions) { options.Audiences = []string{"billing-api"} })
	verifier := must(CreateSessionTokenVerifier(&SessionTokenVerifierOptions{Issuer: signingTestIssuer,
		Audience: []string{"billing-api", "reports-api"}, JWKS: must(result.PublicJwks()), Algorithms: []string{"ES256"},
		Kinds: []string{"session-token"}, Now: f.now}))
	ecSigner := f.signer(func(options *SessionTokenSigningOptions) {
		options.ActiveKeyID = str("ec-1")
		options.Audiences = []string{"billing-api"}
	})
	token := f.sign(ecSigner, f.claims("aud", "billing-api", "kind", "session-token"))
	if must(verifier.Verify(ctx, token)).Get("kind") != "session-token" {
		t.Fatal("expected a session token")
	}
	if _, err := verifier.Verify(ctx, f.sign(result, f.claims("aud", "billing-api"))); signingReason(t, err) != "algorithm" {
		t.Fatal("expected algorithm")
	}
	if _, err := verifier.Verify(ctx, f.sign(ecSigner, f.claims("aud", "billing-api"))); signingReason(t, err) != "kind" {
		t.Fatal("expected kind")
	}
}

func TestSessionTokenVerifyRequest(t *testing.T) {
	f := newSigningFixture(t)
	ctx := context.Background()
	result := f.signer(nil)
	verifier := must(CreateSessionTokenVerifier(&SessionTokenVerifierOptions{Issuer: signingTestIssuer, Audience: signingTestIssuer,
		JWKS: must(result.PublicJwks()), Now: f.now}))
	token := f.sign(result, f.claims())
	for _, header := range []string{"bearer " + token, "BEARER " + token, "Bearer " + token} {
		if must(verifier.VerifyRequest(ctx, http.Header{"Authorization": {header}})).Get("sid") != "session-1" {
			t.Fatal("expected the session")
		}
	}
	for _, headers := range []http.Header{{}, {"Authorization": {"Basic " + token}}, {"Authorization": {"Bearer  " + token}}} {
		_, err := verifier.VerifyRequest(ctx, headers)
		if signingReason(t, err) != "malformed" {
			t.Fatal("expected malformed")
		}
	}
}

func TestSessionTokenErrorShape(t *testing.T) {
	f := newSigningFixture(t)
	_, err := f.signer(nil).Verify(context.Background(), "not-a-jwt", "")
	known, ok := err.(*SessionTokenError)
	if !ok || known.Code() != "INVALID_SESSION_TOKEN" || known.Status() != 401 || known.Reason != "malformed" {
		t.Fatalf("got %v", err)
	}
	if strings.Join(SessionTokenAlgorithms, ",") != "EdDSA,ES256" {
		t.Fatal("unexpected algorithms")
	}
	if LooksLikeJwt("a.b") || LooksLikeJwt(42.0) || LooksLikeJwt("biam_ses_abc") {
		t.Fatal("looksLikeJwt accepted a non-JWT")
	}
	data, _ := json.Marshal(known.Error())
	if string(data) != `"The session token is invalid or expired"` {
		t.Fatalf("got %s", data)
	}
}
