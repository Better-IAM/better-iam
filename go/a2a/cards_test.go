package a2a

// Port of the agent card parts of tests/a2a.test.ts (IAM-attested A2A agent cards: verification, discovery and the
// attestor), plus ES256 cards and key set fetching.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

func baseCard(url string) *core.Object {
	if url == "" {
		url = "https://agents.acme.test/a2a"
	}
	return core.NewObject(
		"protocolVersion", "0.3.0", "name", "Triage", "description", "Sorts incoming requests", "url", url,
		"version", "1.2.0", "capabilities", core.NewObject("streaming", true),
		"defaultInputModes", []any{"text/plain"}, "defaultOutputModes", []any{"text/plain"},
		"skills", []any{
			core.NewObject("id", "summarize", "name", "Summarize", "description", "Summarizes a document", "tags", []any{"docs"}),
			core.NewObject("id", "purge", "name", "Purge", "description", "Deletes archived documents", "tags", []any{"docs"}),
		},
	)
}

type cardFixture struct {
	*orgFixture
	agentID string
	token   string
}

func newCardFixture(t *testing.T) *cardFixture {
	t.Helper()
	f := newOrgFixture(t, func(options *server.BetterIamOptions) {
		options.A2a = &server.A2aOptions{SigningKeys: []*core.Object{cardKey(t, "card-1")}, JwksURL: str("https://iam.acme.test/a2a/jwks.json")}
	})
	agentID, token := f.agentKey("name", "Triage agent", "url", "https://agents.acme.test/triage", "model", "claude-sonnet-5",
		"provider", "Anthropic", "protocols", []any{"a2a"})
	return &cardFixture{orgFixture: f, agentID: agentID, token: token}
}

// sign is agents.signCard with the agent's own key (or another token).
func (f *cardFixture) sign(card *core.Object, token string) (*core.Object, error) {
	if token == "" {
		token = f.token
	}
	signed, _, err := callErr(f.orgFixture, f.iam.API.Agents.SignCard, core.CredentialInput{Token: token}, "agentId", f.agentID, "card", card)
	return signed, err
}

func (f *cardFixture) jwks() *core.Object {
	f.t.Helper()
	return must(f.iam.A2a.Jwks())
}

func TestVerifiesCardsAttestedByTheDeployment(t *testing.T) {
	f := newCardFixture(t)
	card := baseCard("")
	card.Set("provider", core.NewObject("organization", "Somebody else", "url", "https://acme.test"))
	card.Set("capabilities", core.NewObject("streaming", true, "extensions", []any{
		core.NewObject("uri", AgentAttestationURI, "params", core.NewObject("agentId", "forged")),
		core.NewObject("uri", "https://example.test/ext/traceability", "required", false),
	}))
	card.Set("signatures", []any{core.NewObject("protected", "forged", "signature", "forged")})
	signed, err := f.sign(card, "")
	if err != nil {
		t.Fatal(err)
	}
	result := signed.Get("card").(*core.Object)
	keys := f.jwks()
	verified, err := VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{Keys: keys, TenantID: &f.tenantID,
		Issuers: []string{"http://localhost:3000/api/iam"}, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Kid != "card-1" || verified.Attestation.AgentID != f.agentID || verified.Attestation.Issuer != "http://localhost:3000/api/iam" ||
		verified.Attestation.TenantID != f.tenantID || verified.Attestation.AgentName != "Triage agent" ||
		must(core.CanonicalizeJSON(verified.Attestation.Params)) != must(core.CanonicalizeJSON(signed.Get("attestation"))) {
		t.Fatalf("verified = %+v %s %s", verified, core.MustStringify(verified.Attestation.Params), core.MustStringify(signed.Get("attestation")))
	}

	// Any change breaks the signature; an expired attestation, another tenant or unknown keys are refused.
	tampered := result.Spread(core.NewObject("skills", append(append([]any{}, result.Get("skills").([]any)...), core.NewObject("id", "x"))))
	_, err = VerifyAgentCard(f.ctx, tampered, VerifyAgentCardOptions{Keys: keys, Now: f.now})
	expectReason(t, err, "signature")
	_, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{Keys: keys, Now: func() float64 { return f.now() + 3*3600_000 }})
	expectReason(t, err, "expired")
	_, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{Keys: keys, TenantID: str("other"), Now: f.now})
	expectReason(t, err, "tenant")
	stranger := cardKey(t, "card-1")
	stranger.Delete("d")
	_, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{Keys: core.NewObject("keys", []any{stranger}), Now: f.now})
	expectReason(t, err, "signature")
	_, err = VerifyAgentCard(f.ctx, result.Spread(core.NewObject("signatures", []any{})), VerifyAgentCardOptions{Keys: keys, Now: f.now})
	expectReason(t, err, "unsigned")
	_, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{Keys: keys, Issuers: []string{"https://iam.other.test"}, Now: f.now})
	expectReason(t, err, "issuer")
	_, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{Keys: keys, Origin: str("https://elsewhere.test"), Now: f.now})
	expectReason(t, err, "endpoint")
	if _, err := VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{Keys: keys, Origin: str("https://AGENTS.acme.test:443/x"), Now: f.now}); err != nil {
		t.Fatalf("the same origin should verify: %v", err)
	}
	_, err = VerifyAgentCard(f.ctx, "not a card", VerifyAgentCardOptions{Keys: keys})
	expectReason(t, err, "malformed")
	_, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{})
	var typeError *core.TypeError
	if !errors.As(err, &typeError) || typeError.Message != "verifyAgentCard needs trustedIssuers, keys or trustedJwksUrls" {
		t.Fatalf("error = %v", err)
	}
	_, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{Keys: keys, Now: f.now, ClockToleranceSeconds: float(301)})
	if !errors.As(err, &typeError) || typeError.Message != "clockToleranceSeconds must be 0 to 300 seconds and now a finite time" {
		t.Fatalf("error = %v", err)
	}

	// Keys fetched from a trusted JWKS URL (the signature's jku) verify too; other URLs are never fetched.
	var fetched []string
	fetcher := FetchFunc(func(request *http.Request) (*http.Response, error) {
		fetched = append(fetched, request.URL.String())
		if request.Header.Get("accept") != "application/jwk-set+json, application/json" {
			t.Errorf("accept = %s", request.Header.Get("accept"))
		}
		return f.iam.A2a.JwksResponse()
	})
	verified, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{TrustedJwksURLs: []string{"https://iam.acme.test/a2a/jwks.json"}, Fetch: fetcher, Now: f.now})
	if err != nil || verified.Kid != "card-1" {
		t.Fatalf("verified = %+v %v", verified, err)
	}
	_, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{TrustedJwksURLs: []string{"https://iam.other.test/jwks.json"}, Fetch: fetcher, Now: f.now})
	expectReason(t, err, "untrusted-key")
	if strings.Join(fetched, " ") != "https://iam.acme.test/a2a/jwks.json" {
		t.Fatalf("fetched = %v", fetched)
	}
	// A key function sees the signature's kid and jku.
	verified, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{Now: f.now, KeysFunc: func(_ context.Context, kid string, jku *string) (*core.Object, error) {
		if kid != "card-1" || jku == nil || *jku != "https://iam.acme.test/a2a/jwks.json" {
			t.Errorf("keys for %s %v", kid, jku)
		}
		return keys, nil
	}})
	if err != nil || verified.Kid != "card-1" {
		t.Fatalf("verified = %+v %v", verified, err)
	}
	// A key server that fails refuses the card; one that answers no JWKS leaves the card unverified.
	failing := FetchFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("down")), Request: request}, nil
	})
	_, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{TrustedJwksURLs: []string{"https://iam.acme.test/a2a/jwks.json"}, Fetch: failing, Now: f.now})
	expectReason(t, err, "fetch")
	if err.Error() != "https://iam.acme.test/a2a/jwks.json answered 503" {
		t.Fatalf("message = %s", err)
	}
	notJwks := FetchFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"keys":"none"}`))}, nil
	})
	_, err = VerifyAgentCard(f.ctx, result, VerifyAgentCardOptions{TrustedJwksURLs: []string{"https://iam.acme.test/a2a/jwks.json"}, Fetch: notJwks, Now: f.now})
	expectReason(t, err, "untrusted-key")
}

func float(value float64) *float64 { return &value }

func TestDirectoryEntriesAreSignedCards(t *testing.T) {
	f := newCardFixture(t)
	if _, err := f.sign(baseCard(""), ""); err != nil {
		t.Fatal(err)
	}
	f.memberIdentity("alice")
	_, entries, err := callErr(f.orgFixture, f.iam.API.Agents.Directory, f.signIn("alice"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory = %v %v", entries, err)
	}
	verified, err := VerifyAgentCard(f.ctx, member(entries[0], "card"), VerifyAgentCardOptions{Keys: f.jwks(), Now: f.now})
	if err != nil || verified.Attestation.AgentID != f.agentID {
		t.Fatalf("verified = %+v %v", verified, err)
	}
}

// signedCard is the card a signing answer carries, as the attestor wants it.
func signedCard(t *testing.T, signed *core.Object) SignedCard {
	t.Helper()
	return SignedCard{Card: signed.Get("card").(*core.Object), ExpiresAt: signed.Get("expiresAt").(float64)}
}

func TestAttestorKeepsTheServedCardAttestedAndCallersDiscoverIt(t *testing.T) {
	f := newCardFixture(t)
	signings := 0
	attested := CreateCardAttestor(CardAttestorOptions{
		Card: baseCard(""),
		Sign: func(_ context.Context, card *core.Object) (SignedCard, error) {
			signings++
			signed, err := f.sign(card, "")
			if err != nil {
				return SignedCard{}, err
			}
			return signedCard(t, signed), nil
		},
		Now: f.now,
	})
	gate := CreateGate(GateOptions{Iam: Server(f.iam), TenantID: f.tenantID, Message: Rule{Public: true}, CardFunc: attested})
	fetcher := FetchFunc(func(request *http.Request) (*http.Response, error) {
		return gate.Serve(request, func(*http.Request, *Caller) (*http.Response, error) {
			return newResponse(500, http.Header{}, []byte("unexpected")), nil
		})
	})
	discovered, err := DiscoverAgent(f.ctx, "https://agents.acme.test", DiscoverAgentOptions{VerifyAgentCardOptions: VerifyAgentCardOptions{
		Keys: f.jwks(), TenantID: &f.tenantID, Now: f.now, Fetch: fetcher,
	}})
	if err != nil || discovered.Attestation.AgentID != f.agentID {
		t.Fatalf("discovered = %+v %v", discovered, err)
	}
	if _, err := attested(f.ctx); err != nil {
		t.Fatal(err)
	}
	if signings != 1 {
		t.Fatalf("signings = %d", signings)
	}
	// Re-signed once less than a fifth of the hour is left.
	f.advance(50 * 60_000)
	if _, err := attested(f.ctx); err != nil {
		t.Fatal(err)
	}
	if signings != 2 {
		t.Fatalf("signings = %d", signings)
	}
	_, err = DiscoverAgent(f.ctx, "https://impostor.test", DiscoverAgentOptions{VerifyAgentCardOptions: VerifyAgentCardOptions{
		Keys: f.jwks(), Now: f.now, Fetch: fetcher,
	}})
	expectReason(t, err, "endpoint")
	_, err = DiscoverAgent(f.ctx, "ftp://agents.acme.test", DiscoverAgentOptions{VerifyAgentCardOptions: VerifyAgentCardOptions{Keys: f.jwks()}})
	expectReason(t, err, "fetch")
	broken := FetchFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") })
	_, err = DiscoverAgent(f.ctx, "https://agents.acme.test/card.json", DiscoverAgentOptions{VerifyAgentCardOptions: VerifyAgentCardOptions{
		Keys: f.jwks(), Fetch: broken,
	}})
	expectReason(t, err, "fetch")
	if err.Error() != "Could not fetch https://agents.acme.test/card.json" {
		t.Fatalf("message = %s", err)
	}

	// TrustedIssuers binds keys to the issuer a card names: the right keys under another issuer's name do not count.
	issuer := discovered.Attestation.Issuer
	verified, err := VerifyAgentCard(f.ctx, discovered.Card, VerifyAgentCardOptions{TrustedIssuers: map[string]JwksSource{issuer: JwksKeys(f.jwks())}, Now: f.now})
	if err != nil || verified.Attestation.Issuer != issuer {
		t.Fatalf("verified = %+v %v", verified, err)
	}
	_, err = VerifyAgentCard(f.ctx, discovered.Card, VerifyAgentCardOptions{
		TrustedIssuers: map[string]JwksSource{"https://iam.other.test/api/iam": JwksKeys(f.jwks())}, Now: f.now})
	expectReason(t, err, "issuer")

	// An attestor whose card builder fails recovers once the builder does.
	broke := true
	flaky := CreateCardAttestor(CardAttestorOptions{
		CardFunc: func(context.Context) (*core.Object, error) {
			if broke {
				return nil, errors.New("not ready")
			}
			return baseCard(""), nil
		},
		Sign: func(_ context.Context, card *core.Object) (SignedCard, error) {
			signed, err := f.sign(card, "")
			if err != nil {
				return SignedCard{}, err
			}
			return signedCard(t, signed), nil
		},
		Now: f.now,
	})
	if _, err := flaky(f.ctx); err == nil || err.Error() != "not ready" {
		t.Fatalf("error = %v", err)
	}
	broke = false
	card, err := flaky(f.ctx)
	if err != nil || card.Get("name") != "Triage" {
		t.Fatalf("card = %v %v", card, err)
	}
}

func TestAttestorSharesOneSigningAndFallsBackToAValidCard(t *testing.T) {
	now := 1_000_000.0
	calls := 0
	release := make(chan struct{})
	fail := false
	attested := CreateCardAttestor(CardAttestorOptions{
		Card: core.NewObject("name", "A", "url", "https://a.test"),
		Sign: func(_ context.Context, card *core.Object) (SignedCard, error) {
			calls++
			<-release
			if fail {
				return SignedCard{}, errors.New("down")
			}
			return SignedCard{Card: card.Spread(core.NewObject("n", float64(calls))), ExpiresAt: now + 100_000}, nil
		},
		Now: func() float64 { return now },
	})
	results := make(chan *core.Object, 2)
	for range 2 {
		go func() { results <- must(attested(context.Background())) }()
	}
	close(release)
	first, second := <-results, <-results
	if first != second || calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	// Re-signing fails while the previous card is valid: that card is answered; once it expired, the failure.
	fail = true
	now += 90_000
	if card, err := attested(context.Background()); err != nil || card != first {
		t.Fatalf("card = %v %v", card, err)
	}
	now += 20_000
	if _, err := attested(context.Background()); err == nil || err.Error() != "down" {
		t.Fatalf("error = %v", err)
	}
}

// es256Card signs a card (with an attestation) with a P-256 key: the JWS and the public JWKS.
func es256Card(t *testing.T, now float64, header *core.Object) (*core.Object, *core.Object, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	key.X.FillBytes(raw[:32])
	key.Y.FillBytes(raw[32:])
	jwk := core.NewObject("kty", "EC", "crv", "P-256", "x", base64.RawURLEncoding.EncodeToString(raw[:32]),
		"y", base64.RawURLEncoding.EncodeToString(raw[32:]), "kid", "ec-1", "alg", "ES256")
	card := baseCard("")
	card.Set("capabilities", core.NewObject("extensions", []any{core.NewObject("uri", AgentAttestationURI, "params", core.NewObject(
		"issuer", "https://iam.example.test", "tenantId", "tnt_1", "organization", "Example", "agentId", "agt_1", "agentName", "Agent",
		"sponsored", true, "delegable", false, "issuedAt", isoTime(now), "expiresAt", isoTime(now+3600_000)))}))
	canonical := must(core.CanonicalizeJSON(card))
	protected := base64.RawURLEncoding.EncodeToString([]byte(core.MustStringify(header)))
	digest := sha256.Sum256([]byte(protected + "." + base64.RawURLEncoding.EncodeToString([]byte(canonical))))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	card.Set("signatures", []any{core.NewObject("protected", protected, "signature", base64.RawURLEncoding.EncodeToString(signature))})
	return card, core.NewObject("keys", []any{jwk}), key
}

// isoTime is new Date(ms).toISOString().
func isoTime(ms float64) string {
	return time.UnixMilli(int64(ms)).UTC().Format("2006-01-02T15:04:05.000Z")
}

func TestVerifiesES256CardsAndRefusesOtherSignatureForms(t *testing.T) {
	now := 1_767_225_600_000.0
	header := core.NewObject("alg", "ES256", "kid", "ec-1", "typ", "JOSE")
	card, jwks, _ := es256Card(t, now, header)
	clock := func() float64 { return now }
	verified, err := VerifyAgentCard(context.Background(), card, VerifyAgentCardOptions{Keys: jwks, Now: clock, Issuers: []string{"https://iam.example.test"}})
	if err != nil || verified.Kid != "ec-1" || verified.Attestation.Organization != "Example" {
		t.Fatalf("verified = %+v %v", verified, err)
	}
	// Not yet valid beyond the tolerance, expired within it, a key for another algorithm, or a JWT-typed signature.
	_, err = VerifyAgentCard(context.Background(), card, VerifyAgentCardOptions{Keys: jwks, Now: func() float64 { return now - 61_000 }})
	expectReason(t, err, "attestation")
	if _, err := VerifyAgentCard(context.Background(), card, VerifyAgentCardOptions{Keys: jwks, Now: func() float64 { return now + 3600_000 + 59_000 }}); err != nil {
		t.Fatalf("within the tolerance: %v", err)
	}
	wrongAlg := jwks.Get("keys").([]any)[0].(*core.Object).Spread(core.NewObject("alg", "EdDSA"))
	_, err = VerifyAgentCard(context.Background(), card, VerifyAgentCardOptions{Keys: core.NewObject("keys", []any{wrongAlg}), Now: clock})
	expectReason(t, err, "untrusted-key")
	encryption := jwks.Get("keys").([]any)[0].(*core.Object).Spread(core.NewObject("use", "enc"))
	_, err = VerifyAgentCard(context.Background(), card, VerifyAgentCardOptions{Keys: core.NewObject("keys", []any{encryption}), Now: clock})
	expectReason(t, err, "untrusted-key")
	for _, other := range []*core.Object{
		core.NewObject("alg", "ES256", "kid", "ec-1", "typ", "JWT"),
		core.NewObject("alg", "ES256", "kid", "ec-1", "typ", "JOSE", "crit", []any{"b64"}),
		core.NewObject("alg", "ES256", "kid", "ec-1", "typ", "JOSE", "b64", false),
		core.NewObject("alg", "RS256", "kid", "ec-1", "typ", "JOSE"),
	} {
		signed, keys, _ := es256Card(t, now, other)
		_, err = VerifyAgentCard(context.Background(), signed, VerifyAgentCardOptions{Keys: keys, Now: clock})
		expectReason(t, err, "untrusted-key")
	}
	// A card without an attestation, or with two, is refused once its signature verifies.
	_, err = VerifyAgentCard(context.Background(), card, VerifyAgentCardOptions{TrustedIssuers: map[string]JwksSource{"https://iam.example.test": JwksKeys(jwks)},
		Now: clock, TenantID: str("tnt_2")})
	expectReason(t, err, "tenant")
	stripped := card.Spread(core.NewObject("capabilities", core.NewObject()))
	_, err = VerifyAgentCard(context.Background(), stripped, VerifyAgentCardOptions{Keys: jwks, Now: clock})
	expectReason(t, err, "signature")
	_, err = VerifyAgentCard(context.Background(), stripped, VerifyAgentCardOptions{TrustedIssuers: map[string]JwksSource{}, Now: clock})
	expectReason(t, err, "attestation")
}
