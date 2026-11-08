package server

// The parts of tests/web-identity.test.ts that stand on web-identity-exchange.ts alone: the feature flag and input
// shape, the uniform refusal with its deny audits, the per-trust rate limit before any lookup, and the dry run
// (trust.evaluateWebIdentity) with the stored state it reports. Issuance itself runs through temporary-credentials.ts
// and is covered by the conformance traces.

import (
	"context"
	"math"
	"sort"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const (
	wiExchangeIssuer   = "https://token.actions.example.test"
	wiExchangeAudience = "https://acme.example"
	wiExchangeSubject  = "repo:acme/app:ref:refs/heads/main"
)

type wiExchangeFixture struct {
	*kernel
	key *stsTestKey
	api *WebIdentityStsAPI
}

func newWebIdentityExchange(t *testing.T, enabled bool, adjust func(options *StsWebIdentityOptions)) *wiExchangeFixture {
	t.Helper()
	k := newKernel(t, func(options *BetterIamOptions) {
		web := &StsWebIdentityOptions{Enabled: flag(enabled)}
		if adjust != nil {
			adjust(web)
		}
		options.Sts = &StsOptions{WebIdentity: web}
	})
	if enabled {
		k.server.WebIdentity = CreateWebIdentityVerifier(&WebIdentityVerifierOptions{JwksCacheSeconds: 600, FetchTimeoutMs: 5000,
			MaxJwksBytes: 65536, Now: func() float64 { return float64(k.clock.Load()) }, SelfIssuer: "http://localhost:3000/api/iam"})
	}
	f := &wiExchangeFixture{kernel: k, key: webIdentityTestKeys(t).rsa, api: CreateWebIdentityStsAPI(k.server)}
	k.tenantTree()
	k.insert("grantAuthorities",
		core.NewObject("id", "auth-1", "tenantId", "org", "revoked", false, "ceiling", nil, "createdAt", 1.0),
	)
	k.insert("roles", core.NewObject("id", "role-1", "tenantId", "org", "name", "Deployer", "authorityId", "auth-1",
		"document", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"]}]}`), "createdAt", 1.0))
	k.insert("identities", identity("svc-1", "org", "kind", "service"))
	k.insert("oidcProviders", core.NewObject("id", "provider-1", "tenantId", "org", "name", "GitHub Actions", "issuer", wiExchangeIssuer,
		"audiences", []any{wiExchangeAudience}, "jwks", core.NewObject("keys", []any{webIdentityUsableKey(f.key.publicJwk)}),
		"algorithms", []any{"RS256", "ES256"}, "maxTokenLifetimeSeconds", 3600.0, "clockToleranceSeconds", 30.0,
		"replayProtection", "single-use", "enabled", true, "authorityId", "auth-1", "createdAt", 1.0, "createdBy", "owner",
		"updatedAt", 1.0))
	k.insert("trusts", core.NewObject("id", "trust-1", "tenantId", "org", "kind", "web-identity", "roleId", "role-1",
		"providerId", "provider-1", "sourceIdentityId", "svc-1", "sourceTenantId", "org", "revoked", false,
		"authorityId", "auth-1", "conditions", obj(t, `{"StringEquals":{"token.sub":"`+wiExchangeSubject+`","token.repository_owner":"acme"}}`),
		"sourceIdentityClaim", "token.actor", "createdAt", 1.0))
	return f
}

func (f *wiExchangeFixture) token(t *testing.T, pairs ...any) string {
	iat := math.Floor(float64(f.clock.Load()) / 1000)
	return stsSignJwt(t, stsSigner{key: f.key}, stsWith(core.NewObject("iss", wiExchangeIssuer, "aud", wiExchangeAudience,
		"sub", wiExchangeSubject, "iat", iat, "exp", iat+300, "jti", ID(), "repository", "acme/app", "repository_owner", "acme",
		"actor", "octocat"), pairs...))
}

func (f *wiExchangeFixture) exchange(token string, pairs ...any) error {
	input := stsWith(core.NewObject("tenantId", "org", "trustId", "trust-1", "webIdentityToken", token, "sessionName", "ci-run"), pairs...)
	_, err := f.api.AssumeRoleWithWebIdentity(context.Background(), input)
	return err
}

func (f *wiExchangeFixture) denials(t *testing.T) []*core.Object {
	t.Helper()
	found, err := f.store.Find(context.Background(), "audit", core.NewObject("action", webIdentityAuditAction), nil)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(found, func(i, j int) bool { return jsNumber(found[i].Get("sequence")) < jsNumber(found[j].Get("sequence")) })
	return found
}

func TestWebIdentityExchangeNeedsTheFeature(t *testing.T) {
	f := newWebIdentityExchange(t, false, nil)
	expectError(t, f.exchange(f.token(t)), "FEATURE_DISABLED", "Web identity federation is not enabled")
	_, err := EvaluateWebIdentity(context.Background(), f.server, core.NewObject("trust", core.NewObject(), "provider", core.NewObject(), "token", "x"))
	expectError(t, err, "FEATURE_DISABLED", "Web identity federation is not enabled")
}

func TestWebIdentityExchangeInputShape(t *testing.T) {
	f := newWebIdentityExchange(t, true, nil)
	token := f.token(t)
	_, err := f.api.AssumeRoleWithWebIdentity(context.Background(), nil)
	expectError(t, err, "INVALID_INPUT", "Expected an object")
	expectError(t, f.exchange(token, "tenantId", 7.0), "INVALID_INPUT", "Invalid tenantId")
	expectError(t, f.exchange(token, "trustId", ""), "INVALID_INPUT", "Invalid trustId")
	expectError(t, f.exchange("not a token"), "INVALID_INPUT", "webIdentityToken must be a compact JWT of at most 8192 characters")
	expectError(t, f.exchange(token, "sessionName", "x"), "INVALID_INPUT", "sessionName must be 2-64 letters, digits or +=,.@_- characters")
	expectError(t, f.exchange(token, "durationSeconds", "900"), "INVALID_INPUT", "durationSeconds must be a number")
	expectError(t, f.exchange(token, "durationSeconds", nil), "INVALID_INPUT", "durationSeconds must be a number")
	expectError(t, f.exchange(token, "policy", []any{}), "INVALID_INPUT", "policy must be a policy document")
	expectError(t, f.exchange(token, "format", 1.0), "INVALID_INPUT", "format must be 'opaque' or 'jwt'")
	expectError(t, f.exchange(token, "audience", "x"), "INVALID_INPUT", "audience must be a list")
}

func TestWebIdentityExchangeRefusesUniformly(t *testing.T) {
	f := newWebIdentityExchange(t, true, nil)
	// An unknown trust is refused like every other failure, without an audit.
	expectError(t, f.exchange(f.token(t), "trustId", "trust-unknown"), "WEB_IDENTITY_REJECTED", "The web identity token was not accepted")
	if len(f.denials(t)) != 0 {
		t.Fatal("audited an unknown trust")
	}
	// An unverified token is audited without its claims.
	expectError(t, f.exchange(stsTamper(t, f.token(t), "sub", "repo:evil/app")), "WEB_IDENTITY_REJECTED", "The web identity token was not accepted")
	denials := f.denials(t)
	if len(denials) != 1 {
		t.Fatalf("got %d denials", len(denials))
	}
	stsSame(t, denials[0].Get("metadata"), core.NewObject("trustId", "trust-1", "providerId", "provider-1", "reason", "signature"))
	if denials[0].Get("actorId") != "svc-1" || denials[0].Get("resourceId") != "role-1" || denials[0].Get("outcome") != "deny" {
		t.Fatalf("got %s", core.MustStringify(denials[0]))
	}
	// A verified token that misses the conditions is audited with its issuer and subject.
	expectError(t, f.exchange(f.token(t, "repository_owner", "evil")), "WEB_IDENTITY_REJECTED", "The web identity token was not accepted")
	denials = f.denials(t)
	stsSame(t, denials[len(denials)-1].Get("metadata"), core.NewObject("trustId", "trust-1", "providerId", "provider-1",
		"reason", "conditions", "issuer", wiExchangeIssuer, "subject", wiExchangeSubject))
	// A missing source identity claim refuses the token.
	expectError(t, f.exchange(f.token(t, "actor", core.Undefined)), "WEB_IDENTITY_REJECTED", "The web identity token was not accepted")
	denials = f.denials(t)
	if member(denials[len(denials)-1].Get("metadata"), "reason") != "source-identity" {
		t.Fatalf("got %s", core.MustStringify(denials[len(denials)-1]))
	}
	// A revoked trust and a disabled provider are refused before the token is looked at, without an audit.
	before := len(f.denials(t))
	must(0, f.tx(func(ctx context.Context, tx core.IamStore) error {
		provider, _ := tx.Get(ctx, "oidcProviders", "provider-1")
		provider.Set("enabled", false)
		_, err := tx.Put(ctx, "oidcProviders", provider)
		return err
	}))
	expectError(t, f.exchange(f.token(t)), "WEB_IDENTITY_REJECTED", "The web identity token was not accepted")
	if len(f.denials(t)) != before {
		t.Fatal("audited a disabled provider")
	}
}

func TestWebIdentityExchangeRateLimit(t *testing.T) {
	f := newWebIdentityExchange(t, true, func(options *StsWebIdentityOptions) { options.MaxExchangesPerWindow = float(2) })
	for i := 0; i < 2; i++ {
		expectError(t, f.exchange(f.token(t), "trustId", "trust-unknown"), "WEB_IDENTITY_REJECTED", "The web identity token was not accepted")
	}
	err := f.exchange(f.token(t), "trustId", "trust-unknown")
	if iamError(t, err).Code != "RATE_LIMITED" {
		t.Fatalf("got %v", err)
	}
}

func TestEvaluateWebIdentity(t *testing.T) {
	f := newWebIdentityExchange(t, true, nil)
	ctx := context.Background()
	load := func() (*core.Object, *core.Object) {
		trust, _ := f.store.Get(ctx, "trusts", "trust-1")
		provider, _ := f.store.Get(ctx, "oidcProviders", "provider-1")
		return trust, provider
	}
	evaluate := func(token string) *core.Object {
		trust, provider := load()
		return must(EvaluateWebIdentity(ctx, f.server, core.NewObject("trust", trust, "provider", provider, "token", token)))
	}
	token := f.token(t, "jti", "jti-1")
	_, payload := stsDecodeJwt(t, token)
	evaluation := evaluate(token)
	stsSame(t, evaluation, core.NewObject("verified", true,
		"claims", core.NewObject("iss", wiExchangeIssuer, "sub", wiExchangeSubject, "aud", wiExchangeAudience,
			"iat", payload.Get("iat"), "exp", payload.Get("exp"), "jti", "jti-1"),
		"conditions", core.NewObject("matched", true, "failed", []any{}), "sourceIdentity", "octocat"))
	// The dry run redeems nothing.
	if replays, _ := f.store.Find(ctx, "webIdentityReplays", core.NewObject(), nil); len(replays) != 0 {
		t.Fatal("recorded a replay")
	}
	stsSame(t, evaluate(f.token(t, "repository_owner", "evil")).Get("conditions"),
		core.NewObject("matched", false, "failed", []any{"StringEquals:token.repository_owner"}))
	if evaluate("a.b.c").Get("reason") != "malformed" || evaluate(stsTamper(t, token, "sub", "x")).Get("reason") != "signature" {
		t.Fatal("expected verification failures")
	}

	// Stored state that would refuse the exchange, in the exchange's order.
	must(0, f.tx(func(ctx context.Context, tx core.IamStore) error {
		authority, _ := tx.Get(ctx, "grantAuthorities", "auth-1")
		authority.Set("revoked", true)
		_, err := tx.Put(ctx, "grantAuthorities", authority)
		return err
	}))
	if reason := evaluate(token).Get("reason"); reason != "role" {
		t.Fatalf("got %v", reason)
	}
	must(0, f.tx(func(ctx context.Context, tx core.IamStore) error {
		trust, _ := tx.Get(ctx, "trusts", "trust-1")
		trust.Set("revoked", true)
		_, err := tx.Put(ctx, "trusts", trust)
		return err
	}))
	// A revoked trust comes before the token's own problems.
	if reason := evaluate("a.b.c").Get("reason"); reason != "trust" {
		t.Fatalf("got %v", reason)
	}
}

func TestEvaluateWebIdentityIssuerPin(t *testing.T) {
	f := newWebIdentityExchange(t, true, func(options *StsWebIdentityOptions) {
		options.AllowedIssuers = []string{"https://gitlab.example.com"}
	})
	ctx := context.Background()
	trust, _ := f.store.Get(ctx, "trusts", "trust-1")
	provider, _ := f.store.Get(ctx, "oidcProviders", "provider-1")
	evaluation := must(EvaluateWebIdentity(ctx, f.server, core.NewObject("trust", trust, "provider", provider, "token", f.token(t))))
	stsSame(t, evaluation, core.NewObject("verified", false, "reason", "issuer"))
}
