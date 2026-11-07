package server

// A2A agent card tests, after tests/a2a.test.ts: signing an agent's card with an attestation that verifies against
// the deployment's card keys, refusing endpoints off the agent's registered origin and token claims, who may ask for a
// signature, the tenant's agent directory, the option off and invalid keys at construction, plus the card signer's
// compact JWTs and delegation token verification. Steps that reach another unit's stub skip until it is ported.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// cardJwk is a fresh private Ed25519 card key.
func cardJwk(t *testing.T, kid string) *core.Object {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return core.NewObject("crv", "Ed25519", "d", base64url(private.Seed()), "x", base64url(public), "kty", "OKP",
		"kid", kid, "alg", "EdDSA", "use", "sig")
}

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

type a2aFixture struct {
	*agentsFixture
	agent  *core.Object
	token  string
	tenant *core.Object
}

func newA2aFixture(t *testing.T, lifetime float64) *a2aFixture {
	t.Helper()
	f := newAgentsFixture(t, func(options *BetterIamOptions) {
		options.A2a = &A2aOptions{SigningKeys: []*core.Object{cardJwk(t, "card-1")}, JwksURL: str("https://iam.acme.test/a2a/jwks.json")}
		if lifetime != 0 {
			options.A2a.CardLifetimeSeconds = &lifetime
		}
	})
	agent := f.createAgent("name", "Triage agent", "url", "https://agents.acme.test/triage", "model", "claude-sonnet-5",
		"provider", "Anthropic", "protocols", []any{"a2a"})
	token := f.key(jsString(agent.Get("id")))
	tenant, err := f.iam.Store.Get(context.Background(), "tenants", f.tenantID)
	if err != nil || tenant == nil {
		t.Fatalf("tenant: %v", err)
	}
	return &a2aFixture{agentsFixture: f, agent: agent, token: token, tenant: tenant}
}

// sign asks for a card signature with a token (the agent's own key by default).
func (f *a2aFixture) sign(card *core.Object, token string) (*core.Object, error) {
	f.t.Helper()
	if token == "" {
		token = f.token
	}
	value, err := agentsCall(f.agentsFixture, f.iam.API.Agents.SignCard, core.CredentialInput{Token: token}, "agentId", f.agent.Get("id"), "card", card)
	if err != nil {
		return nil, err
	}
	return value.(*core.Object), nil
}

// verifyCard checks a signed card's detached JWS against the deployment's card keys: the canonical card without its
// signatures, signed by a published key.
func verifyCard(t *testing.T, card *core.Object, keys *core.Object) bool {
	t.Helper()
	signatures, _ := card.Get("signatures").([]any)
	if len(signatures) != 1 {
		return false
	}
	unsigned := card.Spread()
	unsigned.Delete("signatures")
	canonical, err := core.CanonicalizeJSON(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	protected := jsString(member(signatures[0], "protected"))
	signature, err := base64.RawURLEncoding.DecodeString(jsString(member(signatures[0], "signature")))
	if err != nil {
		return false
	}
	header, err := sjwtParseHeader(protected, "JWSInvalid", "invalid")
	if err != nil {
		return false
	}
	list, _ := keys.Get("keys").([]any)
	for _, key := range list {
		if member(key, "kid") != header.Get("kid") {
			continue
		}
		public, err := base64.RawURLEncoding.DecodeString(jsString(member(key, "x")))
		if err != nil {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(public), []byte(protected+"."+base64url([]byte(canonical))), signature)
	}
	return false
}

func TestA2aSignsCardWithAttestation(t *testing.T) {
	f := newA2aFixture(t, 0)
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
	organization := f.tenant.Get("name")
	// The provider is the organization at the agent's registered origin, whatever the card claimed.
	expectJSON(t, "provider", result.Get("provider"), `{"organization":"`+jsString(organization)+`","url":"https://agents.acme.test"}`)
	if list, _ := result.Get("signatures").([]any); len(list) != 1 {
		t.Fatalf("signatures = %s", stringify(result.Get("signatures")))
	}
	uris := []string{}
	for _, item := range member(result.Get("capabilities"), "extensions").([]any) {
		uris = append(uris, jsString(member(item, "uri")))
	}
	if strings.Join(uris, " ") != "https://example.test/ext/traceability "+AgentAttestationURI {
		t.Fatalf("extensions = %v", uris)
	}
	now := f.now()
	issuer := "http://localhost:3000" + f.iam.Context.Config.BasePath
	expectJSON(t, "attestation", signed.Get("attestation"), `{"issuer":"`+issuer+`","tenantId":"`+f.tenantID+`","organization":"`+jsString(organization)+
		`","agentId":"`+jsString(f.agent.Get("id"))+`","agentName":"Triage agent","sponsored":true,"delegable":true,"model":"claude-sonnet-5","provider":"anthropic","protocols":["a2a"],"issuedAt":"`+
		isoString(now)+`","expiresAt":"`+isoString(now+3600_000)+`"}`)
	if signed.Get("expiresAt") != now+3600_000 {
		t.Fatalf("expiresAt = %v", signed.Get("expiresAt"))
	}
	header, err := sjwtParseHeader(jsString(member(result.Get("signatures").([]any)[0], "protected")), "JWSInvalid", "invalid")
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, "header", header, `{"alg":"EdDSA","kid":"card-1","typ":"JOSE","jku":"https://iam.acme.test/a2a/jwks.json"}`)

	keys, err := f.iam.A2a.Jwks()
	if err != nil {
		t.Fatal(err)
	}
	list := keys.Get("keys").([]any)
	if len(list) != 1 || member(list[0], "kid") != "card-1" || member(list[0], "kty") != "OKP" || member(list[0], "use") != "sig" ||
		!isUndefined(member(list[0], "d")) {
		t.Fatalf("jwks = %s", stringify(keys))
	}
	if !verifyCard(t, result, keys) {
		t.Fatal("the signed card should verify against the deployment keys")
	}
	// Any change breaks the signature; other keys do not verify it.
	tampered := result.Spread(core.NewObject("skills", append(append([]any{}, result.Get("skills").([]any)...), core.NewObject("id", "x"))))
	if verifyCard(t, tampered, keys) {
		t.Fatal("a tampered card should not verify")
	}
	stranger := cardJwk(t, "card-1")
	stranger.Delete("d")
	if verifyCard(t, result, core.NewObject("keys", []any{stranger})) {
		t.Fatal("another key should not verify the card")
	}

	// The published JWKS response.
	response, err := f.iam.A2a.JwksResponse()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 || response.Header.Get("content-type") != "application/jwk-set+json" ||
		response.Header.Get("cache-control") != "public, max-age=300" || response.Header.Get("access-control-allow-origin") != "*" ||
		string(body) != stringify(keys) {
		t.Fatalf("jwks response = %d %v %s", response.StatusCode, response.Header, body)
	}

	// The directory entry and the audit event.
	stored, err := f.iam.Store.Get(context.Background(), "agentCards", jsString(f.agent.Get("id")))
	if err != nil || stored == nil || stored.Get("signedAt") != now || stringify(stored.Get("card")) != stringify(result) {
		t.Fatalf("agentCards = %v %v", stored, err)
	}
	events := f.audits("agent:card-sign")
	if len(events) != 1 || events[0].Get("actorId") != f.agent.Get("id") || events[0].Get("resourceId") != f.agent.Get("id") ||
		stringify(events[0].Get("metadata")) != `{"url":"https://agents.acme.test/a2a","expiresAt":`+stringify(now+3600_000)+`}` {
		t.Fatalf("agent:card-sign = %s", stringify(events))
	}
	// Signing again replaces the entry.
	if _, err := f.sign(baseCard(""), ""); err != nil {
		t.Fatal(err)
	}
	if cards, _ := f.iam.Store.Find(context.Background(), "agentCards", core.NewObject("tenantId", f.tenantID), nil); len(cards) != 1 {
		t.Fatalf("agentCards = %d", len(cards))
	}
}

func TestA2aAttestsOnlyRegisteredEndpoints(t *testing.T) {
	f := newA2aFixture(t, 0)
	_, err := f.sign(baseCard("https://elsewhere.test/a2a"), "")
	agentsExpectCode(t, err, "INVALID_INPUT")
	expectError(t, err, "INVALID_INPUT", "card.url must be on the agent's registered origin https://agents.acme.test (set the agent's url)")
	side := baseCard("")
	side.Set("additionalInterfaces", []any{core.NewObject("url", "https://elsewhere.test/grpc", "transport", "GRPC")})
	_, err = f.sign(side, "")
	expectContains(t, err, "additionalInterfaces[0].url")
	newer := baseCard("")
	newer.Set("supportedInterfaces", []any{core.NewObject("url", "https://elsewhere.test/a2a")})
	_, err = f.sign(newer, "")
	expectContains(t, err, "supportedInterfaces[0].url")
	bad := baseCard("")
	bad.Set("supportedInterfaces", []any{"https://agents.acme.test/a2a"})
	_, err = f.sign(bad, "")
	expectError(t, err, "INVALID_INPUT", "card.supportedInterfaces[0] must be an object")
	claims := baseCard("")
	claims.Set("iss", "https://evil.test")
	claims.Set("aud", "x")
	_, err = f.sign(claims, "")
	expectError(t, err, "INVALID_INPUT", "An agent card may not carry the token claims iss, aud")
	single := baseCard("")
	single.Set("scope", "documents:read")
	_, err = f.sign(single, "")
	expectError(t, err, "INVALID_INPUT", "An agent card may not carry the token claim scope")
	nameless := baseCard("")
	nameless.Set("name", "   ")
	_, err = f.sign(nameless, "")
	expectError(t, err, "INVALID_INPUT", "card.name must be 1-256 characters")
	extensions := baseCard("")
	extensions.Set("capabilities", core.NewObject("extensions", "none"))
	_, err = f.sign(extensions, "")
	expectError(t, err, "INVALID_INPUT", "card.capabilities.extensions must be an array")
	_, err = agentsCall(f.agentsFixture, f.iam.API.Agents.SignCard, core.CredentialInput{Token: f.token}, "agentId", f.agent.Get("id"), "card", "not a card")
	expectError(t, err, "INVALID_INPUT", "card must be an A2A agent card object")

	// A key whose scopes limit it cannot attest the agent, even its own.
	scoped := f.key(jsString(f.agent.Get("id")), "scopes", []any{"documents:read"})
	_, err = f.sign(baseCard(""), scoped)
	agentsExpectCode(t, err, "ACCESS_DENIED")

	// The owner (an administrator) may sign; another agent's key may not.
	signed, err := agentsCall(f.agentsFixture, f.iam.API.Agents.SignCard, f.owner, "agentId", f.agent.Get("id"), "card", baseCard(""))
	if err != nil || member(member(signed, "attestation"), "agentId") != f.agent.Get("id") {
		t.Fatalf("owner signCard = %v %v", signed, err)
	}
	other := f.createAgent("name", "Other", "url", "https://agents.acme.test/other")
	otherKey := f.key(jsString(other.Get("id")))
	_, err = f.sign(baseCard(""), otherKey)
	agentsExpectCode(t, err, "ACCESS_DENIED")

	// A sponsor signs their own agent's card; an agent without a registered url cannot be attested.
	samID, sam := f.member("sam@example.test", "Sam")
	unregistered := f.createAgent("name", "Unregistered", "sponsorId", samID)
	_, err = agentsCall(f.agentsFixture, f.iam.API.Agents.SignCard, sam, "agentId", unregistered.Get("id"), "card", baseCard(""))
	expectError(t, err, "INVALID_INPUT", "Register the agent’s url before signing its card")
	mustAgents(f.agentsFixture, f.iam.API.Agents.Update, f.owner, "agentId", unregistered.Get("id"), "url", "https://agents.acme.test/sam")
	if _, err := agentsCall(f.agentsFixture, f.iam.API.Agents.SignCard, sam, "agentId", unregistered.Get("id"), "card", baseCard("")); err != nil {
		t.Fatalf("the sponsor should sign: %v", err)
	}

	// A suspended agent is neither attested nor able to ask.
	mustAgents(f.agentsFixture, f.iam.API.Agents.Suspend, f.owner, "agentId", f.agent.Get("id"))
	_, err = agentsCall(f.agentsFixture, f.iam.API.Agents.SignCard, f.owner, "agentId", f.agent.Get("id"), "card", baseCard(""))
	expectError(t, err, "INVALID_IDENTITY", "The agent is not in good standing")
	_, err = f.sign(baseCard(""), f.token)
	if known := agentsExpectCode(t, err, "UNAUTHENTICATED"); known.Status != 401 {
		t.Fatalf("status = %d", known.Status)
	}
}

func TestA2aDirectory(t *testing.T) {
	f := newA2aFixture(t, 0)
	if _, err := f.sign(baseCard(""), ""); err != nil {
		t.Fatal(err)
	}
	helper := f.createAgent("name", "Helper", "url", "https://helper.acme.test", "protocols", []any{"mcp"})
	helperKey := f.key(jsString(helper.Get("id")))
	if _, err := agentsCall(f.agentsFixture, f.iam.API.Agents.SignCard, core.CredentialInput{Token: helperKey}, "agentId", helper.Get("id"), "card",
		core.NewObject("name", "Helper", "url", "https://helper.acme.test/a2a", "skills", []any{core.NewObject("id", "translate", "name", "Translate", "tags", []any{"language"})})); err != nil {
		t.Fatal(err)
	}
	_, alice := f.member("alice@example.test", "Alice")
	names := func(credential core.CredentialInput, members ...any) string {
		t.Helper()
		list := mustAgentList(f.agentsFixture, f.iam.API.Agents.Directory, credential, members...)
		out := []string{}
		for _, entry := range list {
			out = append(out, jsString(member(entry, "name")))
		}
		return strings.Join(out, ",")
	}
	if got := names(alice); got != "Helper,Triage agent" {
		t.Fatalf("directory = %s", got)
	}
	// Entries are the signed cards themselves, ready to verify.
	entries := mustAgentList(f.agentsFixture, f.iam.API.Agents.Directory, alice)
	keys, _ := f.iam.A2a.Jwks()
	if !verifyCard(t, member(entries[1], "card").(*core.Object), keys) || member(entries[1], "agentId") != f.agent.Get("id") {
		t.Fatalf("entry = %s", stringify(entries[1]))
	}
	if got := names(alice, "skill", "summarize"); got != "Triage agent" {
		t.Fatalf("by skill = %s", got)
	}
	if got := names(alice, "skill", "language"); got != "Helper" {
		t.Fatalf("by tag = %s", got)
	}
	if got := names(alice, "protocol", "A2A"); got != "Triage agent" {
		t.Fatalf("by protocol = %s", got)
	}
	// Agents find each other too.
	if got := names(core.CredentialInput{Token: helperKey}); got != "Helper,Triage agent" {
		t.Fatalf("directory for an agent = %s", got)
	}
	// Attestations that expire leave the directory.
	f.advance(2 * 3600_000)
	later := f.signInAgain(mustIdentityID(t, f, "alice@example.test"))
	if got := names(later); got != "" {
		t.Fatalf("directory after expiry = %s", got)
	}
	// Suspended agents leave the directory; deleted agents' entries go.
	f.advance(-2 * 3600_000)
	f.refreshOwner()
	mustAgents(f.agentsFixture, f.iam.API.Agents.Suspend, f.owner, "agentId", helper.Get("id"))
	if got := names(alice); got != "Triage agent" {
		t.Fatalf("directory with a suspended agent = %s", got)
	}
}

// mustIdentityID is the ID of the identity with an email.
func mustIdentityID(t *testing.T, f *a2aFixture, email string) string {
	t.Helper()
	found, err := f.iam.Store.Find(context.Background(), "identities", core.NewObject("email", email), nil)
	if err != nil || len(found) != 1 {
		t.Fatalf("identity %s: %v", email, err)
	}
	return jsString(found[0].Get("id"))
}

func TestA2aOffAndInvalidKeys(t *testing.T) {
	f := newAgentsFixture(t, nil)
	if f.iam.A2a.Enabled {
		t.Fatal("a2a should be off without the option")
	}
	keys, _ := f.iam.A2a.Jwks()
	expectJSON(t, "jwks", keys, `{"keys":[]}`)
	agent := f.createAgent("name", "Plain", "url", "https://agents.acme.test")
	_, err := agentsCall(f, f.iam.API.Agents.SignCard, f.owner, "agentId", agent.Get("id"), "card", baseCard(""))
	expectError(t, err, "FEATURE_DISABLED", "Agent card signing is not enabled (a2a option)")
	_, err = f.iam.A2a.VerifyDelegationToken(context.Background(), "x.y.z", core.NewObject("audience", "https://api.example.com"))
	expectError(t, err, "FEATURE_DISABLED", "Delegation tokens need the a2a option")

	construct := func(options *A2aOptions) error {
		_, err := New(&BetterIamOptions{Database: newStore(t), Secret: testSecret, BaseURL: "http://localhost:3000", A2a: options})
		return err
	}
	publicOnly := cardJwk(t, "public")
	publicOnly.Delete("d")
	expectError(t, construct(&A2aOptions{SigningKeys: []*core.Object{publicOnly}}), "INVALID_CONFIG", "a2a.signingKeys must contain private keys")
	expectError(t, construct(&A2aOptions{SigningKeys: []*core.Object{cardJwk(t, "k")}, CardLifetimeSeconds: float(10)}), "INVALID_CONFIG",
		"a2a.cardLifetimeSeconds must be an integer from 300 to 604800")
	expectError(t, construct(&A2aOptions{}), "INVALID_CONFIG", "a2a.signingKeys must contain 1 to 10 keys")
	expectError(t, construct(&A2aOptions{SigningKeys: []*core.Object{cardJwk(t, "k"), cardJwk(t, "k")}}), "INVALID_CONFIG", "a2a.kid k is used more than once")
	expectError(t, construct(&A2aOptions{SigningKeys: []*core.Object{cardJwk(t, "k")}, ActiveKeyID: str("other")}), "INVALID_CONFIG",
		"a2a.activeKeyId must name one of the signing keys")
	expectError(t, construct(&A2aOptions{SigningKeys: []*core.Object{cardJwk(t, "k")}, VerificationKeys: []*core.Object{cardJwk(t, "old")}}), "INVALID_CONFIG",
		"a2a.verificationKeys must contain public keys only")
	expectError(t, construct(&A2aOptions{SigningKeys: []*core.Object{cardJwk(t, "k")}, JwksURL: str("https://user:pass@iam.test/jwks")}), "INVALID_CONFIG",
		"a2a.jwksUrl must be an absolute http(s) URL without credentials")
	mismatched := cardJwk(t, "k")
	mismatched.Set("x", cardJwk(t, "other").Get("x"))
	expectError(t, construct(&A2aOptions{SigningKeys: []*core.Object{mismatched}}), "INVALID_CONFIG", "a2a.signingKeys key k is not a valid EdDSA key")
	wrong := cardJwk(t, "k")
	wrong.Set("alg", "ES256")
	expectError(t, construct(&A2aOptions{SigningKeys: []*core.Object{wrong}}), "INVALID_CONFIG",
		"a2a.signingKeys keys must be kty OKP/crv Ed25519/alg EdDSA or kty EC/crv P-256/alg ES256")
}

func TestA2aCardSignerJwtsAndDelegationTokens(t *testing.T) {
	f := newA2aFixture(t, 0)
	signer, err := CardSigner(f.iam.Context)
	if err != nil || signer == nil {
		t.Fatalf("signer = %v %v", signer, err)
	}
	nowSeconds := f.now() / 1000
	claims := core.NewObject("iss", signer.Issuer, "sub", "person-1", "aud", "https://api.example.com", "jti", "token-1",
		"tenant_id", f.tenantID, "delegation_id", "delegation-1", "iat", nowSeconds, "nbf", nowSeconds, "exp", nowSeconds+300,
		"act", core.NewObject("sub", "agent-1"), "scope", "documents:read")
	token, err := signer.SignJwt(context.Background(), claims, core.DelegationTokenType)
	if err != nil {
		t.Fatal(err)
	}
	header, _ := sjwtDecodeProtectedHeader(token)
	expectJSON(t, "header", header, `{"alg":"EdDSA","kid":"card-1","typ":"biam-delegation+jwt","jku":"https://iam.acme.test/a2a/jwks.json"}`)
	verified, err := signer.VerifyJwt(context.Background(), token, core.DelegationTokenType)
	if err != nil || stringify(verified) != stringify(claims) {
		t.Fatalf("VerifyJwt = %v %v", verified, err)
	}
	// Another type, a changed payload or a card-type token do not verify.
	if other, _ := signer.VerifyJwt(context.Background(), token, "JOSE"); other != nil {
		t.Fatal("another typ should not verify")
	}
	parts := strings.Split(token, ".")
	forged := parts[0] + "." + base64url([]byte(`{"sub":"someone-else"}`)) + "." + parts[2]
	if other, _ := signer.VerifyJwt(context.Background(), forged, core.DelegationTokenType); other != nil {
		t.Fatal("a changed payload should not verify")
	}
	if other, _ := signer.VerifyJwt(context.Background(), "not a token", core.DelegationTokenType); other != nil {
		t.Fatal("garbage should not verify")
	}

	summary, err := f.iam.A2a.VerifyDelegationToken(context.Background(), token, core.NewObject("audience", "https://api.example.com", "tenantId", f.tenantID))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Get("personId") != "person-1" || summary.Get("agentId") != "agent-1" || stringify(summary.Get("scopes")) != `["documents:read"]` ||
		summary.Get("expiresAt") != (nowSeconds+300)*1000 {
		t.Fatalf("summary = %s", stringify(summary))
	}
	_, err = f.iam.A2a.VerifyDelegationToken(context.Background(), token, core.NewObject("audience", "https://other.example.com"))
	expectError(t, err, "DELEGATION_TOKEN_INVALID", "The token is for another audience")
	_, err = f.iam.A2a.VerifyDelegationToken(context.Background(), forged, core.NewObject("audience", "https://api.example.com"))
	expectError(t, err, "DELEGATION_TOKEN_INVALID", "The delegation token does not verify")
	_, err = f.iam.A2a.VerifyDelegationToken(context.Background(), strings.Repeat("a", 16_385), core.NewObject("audience", "https://api.example.com"))
	expectError(t, err, "DELEGATION_TOKEN_INVALID", "Not a delegation token")
	// A replay check refuses a token seen before.
	seen := map[string]bool{}
	replay := DelegationTokenReplay(func(_ context.Context, tokenID string, _ float64) (bool, error) {
		if seen[tokenID] {
			return false, nil
		}
		seen[tokenID] = true
		return true, nil
	})
	options := core.NewObject("audience", "https://api.example.com").SetRaw("replay", replay)
	if _, err := f.iam.A2a.VerifyDelegationToken(context.Background(), token, options); err != nil {
		t.Fatal(err)
	}
	_, err = f.iam.A2a.VerifyDelegationToken(context.Background(), token, options)
	expectError(t, err, "DELEGATION_TOKEN_INVALID", "The delegation token was used before")
	// Live verification needs the record kept at issue time.
	_, err = f.iam.A2a.VerifyDelegationToken(context.Background(), token, core.NewObject("audience", "https://api.example.com", "live", true))
	expectError(t, err, "DELEGATION_TOKEN_INVALID", "What the delegation token stands on is no longer in place")
}
