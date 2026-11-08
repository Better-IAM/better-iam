package a2a

// Port of the @better-iam/a2a parts of tests/delegation-tokens.test.ts (offline verification of issued tokens, hand-off
// chains, the agent-side token cache) and the verify cases of spec/vectors/delegation-tokens.json.

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
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
	"github.com/Better-IAM/better-iam/go/spectest"
)

func TestDelegationTokenVerifyVectors(t *testing.T) {
	file := spectest.Load(t, "delegation-tokens")
	issuer := "https://iam.example.com/api/iam"
	key := file.Notes.Get("key").(*core.Object).Spread()
	key.Delete("d")
	jwks := core.NewObject("keys", []any{key})
	ran := 0
	for _, c := range file.Cases {
		if !strings.HasPrefix(c.Name, "verify ") {
			continue
		}
		now, _ := c.Input.Number("now")
		options := VerifyDelegationTokenOptions{Audience: c.Input.Get("audience").(string), TrustedIssuers: map[string]JwksSource{issuer: JwksKeys(jwks)},
			Now: func() float64 { return now }}
		if tenant, ok := c.Input.String("tenantId"); ok {
			options.TenantID = &tenant
		}
		summary, err := VerifyDelegationToken(context.Background(), c.Input.Get("token").(string), options)
		var got any
		var refused *DelegationTokenError
		switch {
		case errors.As(err, &refused):
			got = core.NewObject("$error", core.NewObject("name", "DelegationTokenError", "reason", refused.Reason, "message", refused.Message))
		default:
			got = spectest.Outcome(summary, err)
		}
		spectest.Check(t, c, got)
		ran++
	}
	if ran != 10 {
		t.Fatalf("ran %d verify cases", ran)
	}
}

const (
	calendar = "https://calendar.example.com"
	files    = "https://files.docs.example.com"
)

type tokenFixture struct {
	*orgFixture
	aliceID      string
	aliceSession core.CredentialInput
	assistantID  string
	assistant    core.CredentialInput
	researcherID string
	researcher   core.CredentialInput
}

func newTokenFixture(t *testing.T) *tokenFixture {
	t.Helper()
	f := newOrgFixture(t, func(options *server.BetterIamOptions) {
		options.A2a = &server.A2aOptions{SigningKeys: []*core.Object{cardKey(t, "card-1")}, JwksURL: str("https://iam.acme.test/jwks")}
	})
	alice := f.memberIdentity("alice")
	tf := &tokenFixture{orgFixture: f, aliceID: alice.Get("id").(string)}
	var token string
	tf.assistantID, token = f.agentKey("name", "Assistant", "tokenAudiences", []any{calendar, "https://*.docs.example.com"})
	tf.assistant = core.CredentialInput{Token: token}
	tf.researcherID, token = f.agentKey("name", "Researcher", "tokenAudiences", []any{"https://*.docs.example.com"})
	tf.researcher = core.CredentialInput{Token: token}
	role := call(f, f.iam.API.Roles.Create, f.owner, "name", "Editor", "document", core.NewObject("version", 1.0, "statements", []any{
		core.NewObject("effect", "allow", "actions", []any{"documents:read", "documents:write"}, "resources", []any{"document/*"}),
	}))
	call(f, f.iam.API.Bindings.Create, f.owner, "roleId", role.Get("id"), "subjectType", "identity", "subjectId", tf.aliceID)
	tf.aliceSession = f.signIn("alice")
	return tf
}

// actFor grants an agent a delegation from alice and assumes it: the delegation and the delegated session.
func (f *tokenFixture) actFor(agentID string, agent core.CredentialInput, grant ...any) (*core.Object, core.CredentialInput) {
	f.t.Helper()
	if len(grant) == 0 {
		grant = []any{"scopes", []any{"documents:read", "documents:write"}}
	}
	delegation := call(f.orgFixture, f.iam.API.Delegations.Grant, f.aliceSession, append([]any{"agentId", agentID}, grant...)...)
	acting := call(f.orgFixture, f.iam.API.Delegations.Assume, agent, "delegationId", delegation.Get("id"))
	return delegation, core.CredentialInput{Token: acting.Get("token").(string)}
}

func claimsOf(t *testing.T, token string) *core.Object {
	t.Helper()
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	return parseObject(t, string(payload))
}

func TestVerifiesIssuedDelegationTokensOffline(t *testing.T) {
	f := newTokenFixture(t)
	delegation, session := f.actFor(f.assistantID, f.assistant)
	issued := call(f.orgFixture, f.iam.API.Delegations.IssueToken, session, "audience", calendar)
	token := issued.Get("token").(string)
	issuer := issued.Get("issuer").(string)
	jwks := must(f.iam.A2a.Jwks())
	trusted := func(options VerifyDelegationTokenOptions) VerifyDelegationTokenOptions {
		if options.Audience == "" {
			options.Audience = calendar
		}
		if options.TrustedIssuers == nil {
			options.TrustedIssuers = map[string]JwksSource{issuer: JwksKeys(jwks)}
		}
		if options.Now == nil {
			options.Now = f.now
		}
		return options
	}

	// The service verifies it offline with the deployment's published keys.
	verified, err := VerifyDelegationToken(f.ctx, token, trusted(VerifyDelegationTokenOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	if verified.PersonID != f.aliceID || verified.AgentID != f.assistantID || strings.Join(verified.Chain, ",") != f.assistantID ||
		verified.TenantID != f.tenantID || verified.DelegationID != delegation.Get("id") ||
		strings.Join(verified.Scopes, " ") != "documents:read documents:write" || verified.TokenID != issued.Get("tokenId") {
		t.Fatalf("verified = %+v", verified)
	}
	expect := func(want string, token string, options VerifyDelegationTokenOptions) {
		t.Helper()
		_, err := VerifyDelegationToken(f.ctx, token, trusted(options))
		expectReason(t, err, want)
	}
	expect("audience", token, VerifyDelegationTokenOptions{Audience: files})
	expect("tenant", token, VerifyDelegationTokenOptions{TenantID: str("another-tenant")})
	expect("untrusted-key", token, VerifyDelegationTokenOptions{TrustedIssuers: map[string]JwksSource{issuer: JwksKeys(core.NewObject("keys", []any{}))}})
	expect("issuer", token, VerifyDelegationTokenOptions{TrustedIssuers: map[string]JwksSource{"https://other.example": JwksKeys(core.NewObject("keys", []any{}))}})
	expect("expired", token, VerifyDelegationTokenOptions{Now: func() float64 { return f.now() + 10*60_000 }})
	parts := strings.Split(token, ".")
	claims := claimsOf(t, token)
	claims.Set("sub", "someone-else")
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(core.MustStringify(claims))) + "." + parts[2]
	expect("signature", forged, VerifyDelegationTokenOptions{})
	seen := map[string]bool{}
	once := func(_ context.Context, id string, _ float64) (bool, error) {
		if seen[id] {
			return false, nil
		}
		seen[id] = true
		return true, nil
	}
	if _, err := VerifyDelegationToken(f.ctx, token, trusted(VerifyDelegationTokenOptions{Replay: once})); err != nil {
		t.Fatal(err)
	}
	expect("replay", token, VerifyDelegationTokenOptions{Replay: once})
	expect("malformed", strings.Repeat("a", 16_385), VerifyDelegationTokenOptions{})
	expect("malformed", parts[0]+"."+parts[1], VerifyDelegationTokenOptions{})
	expect("malformed", parts[0]+"."+parts[1]+".a", VerifyDelegationTokenOptions{})

	// Keys fetched from the issuer's JWKS URL verify too; a key server that fails or answers no JWKS refuses.
	fetched := 0
	fetcher := FetchFunc(func(*http.Request) (*http.Response, error) {
		fetched++
		return f.iam.A2a.JwksResponse()
	})
	if _, err := VerifyDelegationToken(f.ctx, token, trusted(VerifyDelegationTokenOptions{
		TrustedIssuers: map[string]JwksSource{issuer: JwksURL("https://iam.acme.test/jwks")}, Fetch: fetcher})); err != nil || fetched != 1 {
		t.Fatalf("fetched %d: %v", fetched, err)
	}
	failing := FetchFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 500, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})
	expect("fetch", token, VerifyDelegationTokenOptions{TrustedIssuers: map[string]JwksSource{issuer: JwksURL("https://iam.acme.test/jwks")}, Fetch: failing})
	notJwks := FetchFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`[]`))}, nil
	})
	expect("untrusted-key", token, VerifyDelegationTokenOptions{TrustedIssuers: map[string]JwksSource{issuer: JwksURL("https://iam.acme.test/jwks")}, Fetch: notJwks})
	_, err = VerifyDelegationToken(f.ctx, token, VerifyDelegationTokenOptions{Audience: calendar})
	var typeError *core.TypeError
	if !errors.As(err, &typeError) || typeError.Message != "verifyDelegationToken needs audience and trustedIssuers" {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifiesHandOffChains(t *testing.T) {
	f := newTokenFixture(t)
	_, session := f.actFor(f.assistantID, f.assistant, "scopes", []any{"documents:read", "documents:write"},
		"handoff", core.NewObject("agents", []any{f.researcherID}))
	handoff := call(f.orgFixture, f.iam.API.Delegations.Handoff, session, "agentId", f.researcherID, "scopes", []any{"documents:read"})
	researching := call(f.orgFixture, f.iam.API.Delegations.Assume, f.researcher, "delegationId", handoff.Get("id"))
	issued := call(f.orgFixture, f.iam.API.Delegations.IssueToken, core.CredentialInput{Token: researching.Get("token").(string)}, "audience", files)
	claims := claimsOf(t, issued.Get("token").(string))
	if core.MustStringify(claims.Get("act")) != `{"sub":"`+f.researcherID+`","act":{"sub":"`+f.assistantID+`"}}` {
		t.Fatalf("act = %s", core.MustStringify(claims.Get("act")))
	}
	verified, err := VerifyDelegationToken(f.ctx, issued.Get("token").(string), VerifyDelegationTokenOptions{Audience: files,
		TrustedIssuers: map[string]JwksSource{issued.Get("issuer").(string): JwksKeys(must(f.iam.A2a.Jwks()))}, Now: f.now})
	if err != nil || verified.AgentID != f.researcherID || strings.Join(verified.Chain, ",") != f.assistantID+","+f.researcherID ||
		verified.PersonID != f.aliceID {
		t.Fatalf("verified = %+v %v", verified, err)
	}
}

func TestVerifiesES256DelegationTokens(t *testing.T) {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	raw := make([]byte, 64)
	key.X.FillBytes(raw[:32])
	key.Y.FillBytes(raw[32:])
	jwks := core.NewObject("keys", []any{core.NewObject("kty", "EC", "crv", "P-256", "x", base64.RawURLEncoding.EncodeToString(raw[:32]),
		"y", base64.RawURLEncoding.EncodeToString(raw[32:]), "kid", "ec-1", "alg", "ES256", "use", "sig")})
	now := 1_767_225_600_000.0
	claims := core.NewObject("iss", "https://iam.example.test", "sub", "idn_1", "aud", calendar, "iat", now/1000, "nbf", now/1000,
		"exp", now/1000+300, "jti", "dtk_1", "tenant_id", "tnt_1", "delegation_id", "dlg_1", "act", core.NewObject("sub", "agt_1"),
		"scope", "documents:read")
	sign := func(header *core.Object) string {
		input := base64.RawURLEncoding.EncodeToString([]byte(core.MustStringify(header))) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(core.MustStringify(claims)))
		digest := sha256.Sum256([]byte(input))
		r, s := must2(ecdsa.Sign(rand.Reader, key, digest[:]))
		signature := make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		return input + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	options := VerifyDelegationTokenOptions{Audience: calendar, TrustedIssuers: map[string]JwksSource{"https://iam.example.test": JwksKeys(jwks)},
		Now: func() float64 { return now }}
	verified, err := VerifyDelegationToken(context.Background(), sign(core.NewObject("alg", "ES256", "kid", "ec-1", "typ", core.DelegationTokenType)), options)
	if err != nil || verified.PersonID != "idn_1" || verified.AgentID != "agt_1" {
		t.Fatalf("verified = %+v %v", verified, err)
	}
	for header, reason := range map[string]string{
		`{"alg":"ES256","kid":"ec-1","typ":"JOSE"}`:                               "type",
		`{"alg":"ES256","kid":"ec-1","typ":"biam-delegation+jwt","crit":["exp"]}`: "malformed",
		`{"alg":"HS256","kid":"ec-1","typ":"biam-delegation+jwt"}`:                "malformed",
		`{"alg":"ES256","kid":"ec-2","typ":"biam-delegation+jwt"}`:                "untrusted-key",
		`{"alg":"EdDSA","kid":"ec-1","typ":"biam-delegation+jwt"}`:                "untrusted-key",
	} {
		_, err := VerifyDelegationToken(context.Background(), sign(parseObject(t, header)), options)
		expectReason(t, err, reason)
	}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func TestDelegationTokenCacheIssuesOnceAndRefreshes(t *testing.T) {
	var mu sync.Mutex
	now := 1_000_000.0
	issued := 0
	release := make(chan struct{})
	tokenFor := CreateDelegationTokenCache(DelegationTokenCacheOptions{
		Now: func() float64 {
			mu.Lock()
			defer mu.Unlock()
			return now
		},
		Issue: func(_ context.Context, audience string, scopes []string) (IssuedDelegationToken, error) {
			<-release
			mu.Lock()
			defer mu.Unlock()
			issued++
			return IssuedDelegationToken{Token: audience + "|" + strings.Join(scopes, ",") + "|" + string(rune('0'+issued)), ExpiresAt: now + 300_000}, nil
		},
	})
	results := make(chan string, 2)
	for range 2 {
		go func() { results <- must(tokenFor(context.Background(), calendar, nil)) }()
	}
	close(release)
	first, second := <-results, <-results
	if first != second {
		t.Fatalf("tokens %s %s", first, second)
	}
	if got := must(tokenFor(context.Background(), calendar, []string{"b", "a"})); got != calendar+"|b,a|2" {
		t.Fatalf("token = %s", got)
	}
	if got := must(tokenFor(context.Background(), calendar, []string{"a", "b"})); got != calendar+"|b,a|2" {
		t.Fatalf("token = %s", got)
	}
	mu.Lock()
	now += 250_000
	mu.Unlock()
	if got := must(tokenFor(context.Background(), calendar, nil)); got != calendar+"||3" {
		t.Fatalf("token = %s", got)
	}
	if issued != 3 {
		t.Fatalf("issued = %d", issued)
	}
	// A failed issue is answered to every caller and not cached.
	failing := CreateDelegationTokenCache(DelegationTokenCacheOptions{Issue: func(context.Context, string, []string) (IssuedDelegationToken, error) {
		return IssuedDelegationToken{}, errors.New("refused")
	}})
	if _, err := failing(context.Background(), calendar, nil); err == nil || err.Error() != "refused" {
		t.Fatalf("error = %v", err)
	}
}

func TestDelegationTokensNeedTheA2aOption(t *testing.T) {
	f := newOrgFixture(t, nil)
	f.memberIdentity("alice")
	f.grantDocuments(must(f.iam.Authenticate(f.ctx, f.signIn("alice"))).Identity.Get("id").(string), "documents:read")
	agentID, token := f.agentKey("name", "Assistant", "tokenAudiences", []any{calendar})
	delegation := call(f, f.iam.API.Delegations.Grant, f.signIn("alice"), "agentId", agentID, "scopes", []any{"documents:read"})
	acting := call(f, f.iam.API.Delegations.Assume, core.CredentialInput{Token: token}, "delegationId", delegation.Get("id"))
	_, _, err := callErr(f, f.iam.API.Delegations.IssueToken, core.CredentialInput{Token: acting.Get("token").(string)}, "audience", calendar)
	expectCode(t, err, "FEATURE_DISABLED")
}
