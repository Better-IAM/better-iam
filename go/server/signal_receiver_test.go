package server

// Port of tests/signals-receiver.test.ts: the Shared Signals receiver (signal-receiver.ts) and the `signals` API group
// (api/signals.ts). Organizations and people are seeded with the directory fixture (the identities API group is ported
// separately); SETs are signed with the test keys of session_jose_test.go. The first TypeScript test drives the
// receiver with @better-iam/oauth's transmitter, which has no Go port: TestSignalsReceiverAcceptsAnotherOrganizationsTransmitter
// sends the same events (verification, then session-revoked over a federation link) signed with the transmitter's
// kind of key.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	sigCAEP     = "https://schemas.openid.net/secevent/caep/event-type/"
	sigRISC     = "https://schemas.openid.net/secevent/risc/event-type/"
	sigSSF      = "https://schemas.openid.net/secevent/ssf/event-type/"
	sigIssuer   = "https://idp.example.test"
	sigAudience = "https://rp.example.test/signals"
)

func sigUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

type sigFixture struct {
	*directoryFixture
	tenantID  string
	ownerCred core.CredentialInput
	ownerID   string
}

func newSignalsFixture(t *testing.T, mutate func(options *BetterIamOptions)) *sigFixture {
	t.Helper()
	f := &sigFixture{directoryFixture: newDirectoryFixture(t, mutate)}
	f.tenantID, f.ownerCred = f.organization("Acme", "owner@acme.test")
	owners := f.find("identities", core.NewObject("tenantId", f.tenantID, "owner", true))
	f.ownerID = jsString(owners[0].Get("id"))
	return f
}

func insecureLocalhost(options *BetterIamOptions) {
	options.Signals = &SignalsOptions{AllowInsecureLocalhost: flag(true)}
}

func (f *sigFixture) seconds() float64 { return math.Floor(f.now() / 1000) }

// member creates a person of the tenant ({name}@acme.test).
func (f *sigFixture) member(name string) *core.Object {
	return f.identityAt(f.tenantID, name+"@acme.test", name)
}

// identityAt creates an identity with a given email in a tenant.
func (f *sigFixture) identityAt(tenantID, email, name string) *core.Object {
	f.t.Helper()
	var identity *core.Object
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		created, err := f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{TenantID: tenantID, Email: email, Name: name})
		identity = created
		return err
	})
	return identity
}

func (f *sigFixture) signIn(identity *core.Object) core.CredentialInput {
	return f.issue(f.record("identities", jsString(identity.Get("id"))), false)
}

func (f *sigFixture) signedOut(credential core.CredentialInput) bool {
	_, err := f.iam.Context.Principals.Authenticate(f.ctx, credential)
	if err == nil {
		return false
	}
	known, ok := asIamError(err)
	return ok && known.Status == 401
}

func (f *sigFixture) api() *SignalsAPI { return f.iam.API.Signals }

func sigOut[T any](out Out[T], err error) *core.Object {
	if err != nil {
		panic("unexpected error: " + err.Error())
	}
	object, _ := out.Value.(*core.Object)
	return object
}

func (f *sigFixture) createSource(credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	out, err := f.api().CreateSource(f.ctx, credential, Input[apitypes.SignalsCreateSourceInput](input))
	object, _ := out.Value.(*core.Object)
	return object, err
}

func (f *sigFixture) getSource(credential core.CredentialInput, tenantID, sourceID string) *core.Object {
	f.t.Helper()
	return sigOut(f.api().GetSource(f.ctx, credential, Input[apitypes.SignalsGetSourceInput](body("tenantId", tenantID, "sourceId", sourceID))))
}

func (f *sigFixture) updateSource(credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	out, err := f.api().UpdateSource(f.ctx, credential, Input[apitypes.SignalsUpdateSourceInput](input))
	object, _ := out.Value.(*core.Object)
	return object, err
}

func (f *sigFixture) listEvents(credential core.CredentialInput, input *core.Object) *core.Object {
	f.t.Helper()
	merged := core.NewObject("tenantId", f.tenantID).Spread(input)
	return sigOut(f.api().ListEvents(f.ctx, credential, Input[apitypes.SignalsListEventsInput](merged)))
}

func (f *sigFixture) getEvent(credential core.CredentialInput, tenantID, eventID string) (*core.Object, error) {
	out, err := f.api().GetEvent(f.ctx, credential, Input[apitypes.SignalsGetEventInput](body("tenantId", tenantID, "eventId", eventID)))
	object, _ := out.Value.(*core.Object)
	return object, err
}

func (f *sigFixture) audit(tenantID, action string) []*core.Object {
	f.t.Helper()
	found := []*core.Object{}
	for _, entry := range f.find("audit", core.NewObject("tenantId", tenantID)) {
		if entry.Get("action") == action {
			found = append(found, entry)
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		return jsNumber(coalesce(found[i].Get("sequence"), 0.0)) < jsNumber(coalesce(found[j].Get("sequence"), 0.0))
	})
	return found
}

// link writes a federation link as federation.ts writes it on sign-in: natural key [connectionId, issuer, subject].
func (f *sigFixture) link(tenantID, connectionID, issuer, subject, identityID string) {
	f.t.Helper()
	key, _, _ := core.Stringify([]any{connectionID, issuer, subject})
	f.seed("externalIdentities", core.NewObject("id", sigUUID(), "tenantId", tenantID, "uniqueKey", key, "identityId", identityID,
		"providerId", connectionID, "issuer", issuer, "subject", subject))
}

// linkScim writes a user provisioned through a SCIM connection, the IdP's user id as externalId.
func (f *sigFixture) linkScim(connectionID, identityID, externalID string) {
	f.t.Helper()
	f.seed("scimUsers", core.NewObject("id", sigUUID(), "tenantId", f.tenantID, "connectionId", connectionID,
		"identityId", identityID, "userName", externalID+"@idp.example.test", "externalId", externalID, "displayName", externalID,
		"active", true, "version", 1.0, "createdAt", f.now(), "updatedAt", f.now()))
}

// sigEvent is the `events` claim (one event) and, when given, the RFC 9493 `sub_id`.
func sigEvent(eventType string, claims *core.Object, subject *core.Object) *core.Object {
	if claims == nil {
		claims = core.NewObject()
	}
	event := core.NewObject("events", core.NewObject(eventType, claims))
	if subject != nil {
		event.Set("sub_id", subject)
	}
	return event
}

// securityEvent is a compact SET for sigIssuer and sigAudience, issued now with a fresh jti unless claims say otherwise
// (core.Undefined removes a claim).
func (f *sigFixture) securityEvent(signer stsSigner, claims *core.Object, header ...any) string {
	f.t.Helper()
	payload := core.NewObject("iss", sigIssuer, "aud", sigAudience, "iat", f.seconds(), "jti", sigUUID())
	claims.Entries(func(key string, value any) bool {
		if isUndefined(value) {
			payload.Delete(key)
		} else {
			payload.Set(key, value)
		}
		return true
	})
	return stsSignJwt(f.t, signer, payload, append([]any{"typ", "secevent+jwt"}, header...)...)
}

type sigPushOptions struct {
	token    *string
	noToken  bool
	mimeType string
	url      string
	method   string
}

type sigPushSource struct {
	f        *sigFixture
	key      *stsTestKey
	created  *core.Object
	sourceID string
	pushURL  string
	token    string
}

func (p *sigPushSource) sign(claims *core.Object, header ...any) string {
	return p.f.securityEvent(stsSigner{key: p.key}, claims, header...)
}

func (p *sigPushSource) signWith(signer stsSigner, claims *core.Object, header ...any) string {
	return p.f.securityEvent(signer, claims, header...)
}

func (p *sigPushSource) push(set string, options ...sigPushOptions) *Response {
	option := sigPushOptions{}
	if len(options) > 0 {
		option = options[0]
	}
	token := p.token
	if option.token != nil {
		token = *option.token
	}
	if option.noToken {
		token = ""
	}
	method := option.method
	if method == "" {
		method = http.MethodPost
	}
	headers := map[string]string{"content-type": "application/secevent+jwt", "accept": "application/json"}
	if option.mimeType != "" {
		headers["content-type"] = option.mimeType
	}
	if token != "" {
		headers["authorization"] = "Bearer " + token
	}
	url := p.pushURL
	if option.url != "" {
		url = option.url
	}
	if method == http.MethodGet {
		set = ""
	}
	return p.f.fetch(method, url, headers, set)
}

// pushSource is a push source of Acme for sigIssuer with static keys.
func (f *sigFixture) pushSource(input *core.Object) *sigPushSource {
	f.t.Helper()
	key := stsGenerateKey(f.t, "RS256", "idp-1")
	base := core.NewObject("tenantId", f.tenantID, "name", "Upstream IdP", "issuer", sigIssuer, "audiences", items(sigAudience),
		"jwks", core.NewObject("keys", items(key.publicJwk)), "delivery", "push")
	if input != nil {
		base = base.Spread(input)
	}
	created, err := f.createSource(f.ownerSignIn(f.tenantID), base)
	if err != nil {
		f.t.Fatalf("createSource: %v", err)
	}
	source, _ := created.Get("source").(*core.Object)
	return &sigPushSource{f: f, key: key, created: created, sourceID: jsString(source.Get("id")),
		pushURL: jsString(created.Get("pushUrl")), token: jsString(coalesce(created.Get("pushToken"), ""))}
}

func sigJSON(t *testing.T, response *Response) *core.Object {
	t.Helper()
	parsed, err := core.ParseJSON(response.Body)
	if err != nil {
		t.Fatalf("invalid JSON %q: %v", response.Body, err)
	}
	object, _ := parsed.(*core.Object)
	return object
}

func sigStatus(t *testing.T, response *Response, status int) {
	t.Helper()
	if response.Status != status {
		t.Fatalf("status %d (want %d): %s", response.Status, status, response.Body)
	}
}

// refused expects an RFC 8935 refusal.
func sigRefused(t *testing.T, response *Response, status int, code string) {
	t.Helper()
	sigStatus(t, response, status)
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control %q", response.Header.Get("Cache-Control"))
	}
	answer := sigJSON(t, response)
	if answer.Get("err") != code || answer.Len() != 2 {
		t.Fatalf("answer %s (want err %s)", response.Body, code)
	}
	if _, ok := answer.Get("description").(string); !ok {
		t.Fatalf("description missing: %s", response.Body)
	}
}

// sigMatches is toMatchObject: objects match a subset of their members, arrays element by element.
func sigMatches(got, want any) bool {
	switch expected := want.(type) {
	case *core.Object:
		actual, ok := got.(*core.Object)
		if !ok || actual == nil {
			return false
		}
		matched := true
		expected.Entries(func(key string, value any) bool {
			matched = actual.Has(key) && sigMatches(actual.Get(key), value)
			return matched
		})
		return matched
	case []any:
		actual, ok := got.([]any)
		if !ok || len(actual) != len(expected) {
			return false
		}
		for index := range expected {
			if !sigMatches(actual[index], expected[index]) {
				return false
			}
		}
		return true
	}
	left, _, _ := core.Stringify(got)
	right, _, _ := core.Stringify(want)
	return left == right
}

// sigExpect checks members as toMatchObject does; a key prefixed with "=" must equal its value exactly (toEqual).
func sigExpect(t *testing.T, object *core.Object, pairs ...any) {
	t.Helper()
	for index := 0; index+1 < len(pairs); index += 2 {
		key := pairs[index].(string)
		exact := strings.HasPrefix(key, "=")
		key = strings.TrimPrefix(key, "=")
		got, _, _ := core.Stringify(core.Normalize(object.Get(key)))
		want, _, _ := core.Stringify(core.Normalize(pairs[index+1]))
		if (exact && got != want) || (!exact && !sigMatches(core.Normalize(object.Get(key)), core.Normalize(pairs[index+1]))) {
			full, _, _ := core.Stringify(object)
			t.Fatalf("%s = %s, want %s (in %s)", key, got, want, full)
		}
	}
}

func sigObjects(value any) []*core.Object {
	list, _ := value.([]any)
	objects := make([]*core.Object, len(list))
	for index, item := range list {
		objects[index], _ = item.(*core.Object)
	}
	return objects
}

func sigReceive(t *testing.T, f *sigFixture, sourceID, set string) *core.Object {
	t.Helper()
	receipt, err := f.iam.Signals.Receive(f.ctx, sourceID, set)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	return receipt
}

func TestSignalsReceiverAcceptsAnotherOrganizationsTransmitter(t *testing.T) {
	f := newSignalsFixture(t, insecureLocalhost)
	betaID, _ := f.organization("Beta", "owner@beta.test")
	const transmitter = "https://id.acme.example.test/oidc"
	const betaAudience = "https://beta.example.test/signals"
	signing := stsGenerateKey(t, "ES256", "acme-ssf")
	betaOwner := f.ownerSignIn(betaID)
	created, err := f.createSource(betaOwner, body("tenantId", betaID, "name", "Acme identity provider", "issuer", transmitter,
		"audiences", items(betaAudience), "jwks", body("keys", items(signing.publicJwk)), "delivery", "push",
		"subjects", body("connectionIds", items("acme-oidc")), "actions", body("session-revoked", "revoke-sessions")))
	if err != nil {
		t.Fatal(err)
	}
	sourceID := jsString(member(created.Get("source"), "id"))
	if created.Get("pushUrl") != "http://localhost:3000/api/iam/signals/push/"+sourceID {
		t.Fatalf("push url %v", created.Get("pushUrl"))
	}
	if !regexp.MustCompile(`^[\w-]{43}$`).MatchString(jsString(created.Get("pushToken"))) {
		t.Fatalf("push token %v", created.Get("pushToken"))
	}
	source := &sigPushSource{f: f, key: signing, created: created, sourceID: sourceID, pushURL: jsString(created.Get("pushUrl")),
		token: jsString(created.Get("pushToken"))}
	set := func(claims *core.Object) string {
		return stsSignJwt(t, stsSigner{key: signing}, core.NewObject("iss", transmitter, "aud", betaAudience, "iat", f.seconds(),
			"jti", sigUUID()).Spread(claims), "typ", "secevent+jwt")
	}

	// The stream's verification event is accepted and noted on the source.
	sigStatus(t, source.push(set(sigEvent(sigSSF+"verification", body("state", "hello"), nil))), 202)
	if member(f.getSource(betaOwner, betaID, sourceID), "lastVerifiedAt") != f.now() {
		t.Fatal("lastVerifiedAt not recorded")
	}
	f.advance(1000)

	// Alice works in both organizations; Beta's account is linked to Acme's through Beta's Acme connection.
	aliceAtAcme := f.member("alice")
	aliceAtBeta := f.identityAt(betaID, "alice@beta.test", "Alice")
	f.link(betaID, "acme-oidc", transmitter, jsString(aliceAtAcme.Get("id")), jsString(aliceAtBeta.Get("id")))
	betaSession := f.signIn(aliceAtBeta)

	sigStatus(t, source.push(set(sigEvent(sigCAEP+"session-revoked", body("initiating_entity", "admin"),
		body("format", "iss_sub", "iss", transmitter, "sub", aliceAtAcme.Get("id"))).Set("txn", "txn-1"))), 202)
	if !f.signedOut(betaSession) {
		t.Fatal("the Beta session survived")
	}
	page := sigOut(f.api().ListEvents(f.ctx, betaOwner, Input[apitypes.SignalsListEventsInput](body("tenantId", betaID))))
	if page.Get("total") != 2.0 {
		t.Fatalf("total %v", page.Get("total"))
	}
	events := sigObjects(page.Get("events"))
	if events[0].Get("eventType") != "session-revoked" || events[0].Get("status") != "applied" ||
		events[1].Get("eventType") != "verification" || events[1].Get("status") != "recorded" {
		t.Fatalf("events %s", stringify(events))
	}
	revocation := events[0]
	sigExpect(t, revocation, "sourceId", sourceID, "identityId", aliceAtBeta.Get("id"),
		"subject", body("format", "iss_sub", "iss", transmitter, "sub", aliceAtAcme.Get("id")),
		"claims", body("initiating_entity", "admin"), "txn", "txn-1")
	var received *core.Object
	for _, entry := range f.audit(betaID, "signal:received") {
		if member(entry.Get("metadata"), "eventType") == "session-revoked" {
			received = entry
		}
	}
	sigExpect(t, received, "actorId", "signal:"+sourceID, "resourceId", aliceAtBeta.Get("id"), "outcome", "allow",
		"metadata", body("sourceId", sourceID, "eventType", "session-revoked", "jti", revocation.Get("jti"), "status", "applied",
			"identityId", aliceAtBeta.Get("id")))
	revokes := f.audit(betaID, "signal:revoke-sessions")
	if len(revokes) != 1 {
		t.Fatalf("revocations %d", len(revokes))
	}
	sigExpect(t, revokes[0], "=metadata", body("sourceId", sourceID, "eventType", "session-revoked", "jti", revocation.Get("jti"), "revoked", 1.0))
	if len(f.audit(betaID, "identity:revoke-sessions")) != 0 {
		t.Fatal("the receiver audited identity:revoke-sessions")
	}
}

func TestSignalsReceiverRefusesTokensThatFailVerification(t *testing.T) {
	f := newSignalsFixture(t, nil)
	p := f.pushSource(nil)
	disabled := func() *core.Object {
		return sigEvent(sigRISC+"account-disabled", nil, body("format", "opaque", "id", "someone"))
	}
	with := func(pairs ...any) *core.Object { return disabled().Spread(core.NewObject(pairs...)) }
	now := f.seconds()

	// Addressed elsewhere, or from someone else.
	sigRefused(t, p.push(p.sign(with("aud", "https://another.example.test"))), 400, "invalid_audience")
	sigRefused(t, p.push(p.sign(with("aud", core.Undefined))), 400, "invalid_audience")
	sigRefused(t, p.push(p.sign(with("iss", "https://evil.example.test"))), 400, "invalid_issuer")
	// Keys and algorithms: only the source's keys, only its algorithms, never keys named by the token.
	sigRefused(t, p.push(p.signWith(stsSigner{key: stsGenerateKey(t, "ES384", "idp-1")}, disabled())), 400, "invalid_key")
	sigRefused(t, p.push(p.signWith(stsSigner{alg: "HS256", secret: "shared-secret"}, disabled())), 400, "invalid_key")
	sigRefused(t, p.push(p.signWith(stsSigner{key: stsGenerateKey(t, "RS256", "idp-1")}, disabled())), 400, "invalid_key")
	sigRefused(t, p.push(p.signWith(stsSigner{key: stsGenerateKey(t, "RS256", "idp-2")}, disabled())), 400, "invalid_key")
	sigRefused(t, p.push(stsTamper(t, p.sign(disabled()), "jti", "forged")), 400, "invalid_key")
	sigRefused(t, p.push(p.signWith(stsSigner{alg: "none"}, disabled())), 400, "invalid_request")
	for _, header := range [][]any{
		{"jwk", p.key.publicJwk},
		{"jku", "https://idp.example.test/keys"},
		{"x5u", "https://idp.example.test/cert.pem"},
		{"x5c", items("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA")},
		{"crit", items("exp"), "exp", now + 60},
	} {
		sigRefused(t, p.push(p.sign(disabled(), header...)), 400, "invalid_request")
	}
	// The token type.
	sigRefused(t, p.push(p.sign(disabled(), "typ", "JWT")), 400, "invalid_request")
	sigRefused(t, p.push(p.sign(disabled(), "typ", core.Undefined)), 400, "invalid_request")
	// Claims: no nonce (ID tokens), exactly one event, a readable subject, a sane age.
	sigRefused(t, p.push(p.sign(with("nonce", "n-0S6_WzA2Mj"))), 400, "invalid_request")
	sigRefused(t, p.push(p.sign(with("events", body(sigRISC+"account-disabled", body(), sigRISC+"account-purged", body())))), 400, "invalid_request")
	sigRefused(t, p.push(p.sign(with("events", body()))), 400, "invalid_request")
	sigRefused(t, p.push(p.sign(with("events", core.Undefined))), 400, "invalid_request")
	sigRefused(t, p.push(p.sign(with("sub_id", body("format", "email", "email", "not-an-address")))), 400, "invalid_request")
	sigRefused(t, p.push(p.sign(with("sub", "someone-else", "sub_id", body("format", "iss_sub", "iss", sigIssuer, "sub", "someone")))), 400, "invalid_request")
	sigRefused(t, p.push(p.sign(with("iat", now-8*86_400))), 400, "invalid_request")
	sigRefused(t, p.push(p.sign(with("iat", now+600))), 400, "invalid_request")
	sigRefused(t, p.push(p.sign(with("exp", now-600))), 400, "invalid_request")
	sigRefused(t, p.push(p.sign(with("nbf", now+600))), 400, "invalid_request")
	sigRefused(t, p.push(strings.Repeat("a", 17_000)+".b.c"), 400, "invalid_request")
	sigRefused(t, p.push("not a token"), 400, "invalid_request")

	// The transport: bearer token, media type, size, method, stream.
	wrong := "not-the-token"
	sigRefused(t, p.push(p.sign(disabled()), sigPushOptions{token: &wrong}), 401, "authentication_failed")
	anonymous := p.push(p.sign(disabled()), sigPushOptions{noToken: true})
	sigStatus(t, anonymous, 401)
	if anonymous.Header.Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("www-authenticate %q", anonymous.Header.Get("WWW-Authenticate"))
	}
	sigRefused(t, p.push(p.sign(disabled()), sigPushOptions{mimeType: "application/json"}), 415, "invalid_request")
	sigRefused(t, p.push(p.sign(disabled()), sigPushOptions{mimeType: "application/jwt"}), 415, "invalid_request")
	sigRefused(t, p.push(strings.Repeat("x", 70_000)), 413, "invalid_request")
	sigRefused(t, p.push(p.sign(disabled()), sigPushOptions{url: "http://localhost:3000/api/iam/signals/push/" + sigUUID()}), 404, "invalid_request")
	get := p.push("", sigPushOptions{method: http.MethodGet})
	sigStatus(t, get, 405)
	if get.Header.Get("Allow") != "POST" {
		t.Fatalf("allow %q", get.Header.Get("Allow"))
	}

	// Nothing refused was recorded; the latest refusal is noted on the source.
	if f.listEvents(f.ownerCred, nil).Get("total") != 0.0 {
		t.Fatal("a refused event was recorded")
	}
	lastError, _ := f.getSource(f.ownerCred, f.tenantID, p.sourceID).Get("lastError").(*core.Object)
	if lastError == nil || lastError.Get("at") != f.now() || !strings.HasPrefix(jsString(lastError.Get("message")), "Refused an event: ") {
		t.Fatalf("lastError %s", stringify(lastError))
	}

	// Accepted: an audience list naming this receiver, the issuer with a trailing slash, the media type spelling of
	// typ, a token days old (a transmitter's queue) or a little ahead of this clock.
	for _, set := range []string{
		p.sign(with("aud", items("https://another.example.test", sigAudience))),
		p.sign(with("iss", sigIssuer+"/")),
		p.sign(disabled(), "typ", "application/secevent+jwt"),
		p.sign(with("iat", now-6*86_400)),
		p.sign(with("iat", now+120)),
	} {
		answer := p.push(set)
		sigStatus(t, answer, 202)
		if answer.Header.Get("Cache-Control") != "no-store" || len(answer.Body) != 0 {
			t.Fatalf("accepted answer %v %q", answer.Header, answer.Body)
		}
	}
	// An event type the receiver does not know is kept, and ignored.
	sigStatus(t, p.push(p.sign(sigEvent("https://example.test/event-type/custom", body("detail", 1.0), nil))), 202)
	page := f.listEvents(f.ownerCred, nil)
	if page.Get("total") != 6.0 {
		t.Fatalf("total %v", page.Get("total"))
	}
	unknown := 0
	for _, entry := range sigObjects(page.Get("events")) {
		switch entry.Get("eventType") {
		case "unknown":
			unknown++
			sigExpect(t, entry, "status", "ignored", "reason", "unsupported-event", "eventUri", "https://example.test/event-type/custom",
				"claims", body("detail", 1.0))
		case "account-disabled":
			sigExpect(t, entry, "status", "unmatched", "reason", "no-match")
		}
	}
	if unknown != 1 {
		t.Fatalf("unknown events %d", unknown)
	}
}

func TestSignalsReceiverTriesEachKeyWithoutKid(t *testing.T) {
	f := newSignalsFixture(t, nil)
	retired := stsGenerateKey(t, "RS256", "")
	current := stsGenerateKey(t, "RS256", "")
	withoutKid := func(key *stsTestKey) *core.Object { return stsWith(key.publicJwk, "kid", core.Undefined) }
	p := f.pushSource(body("jwks", body("keys", items(withoutKid(retired), withoutKid(current)))))
	verification := func() *core.Object { return sigEvent(sigSSF+"verification", body("state", "no-kid"), nil) }
	sigStatus(t, p.push(p.signWith(stsSigner{key: current}, verification(), "kid", core.Undefined)), 202)
	sigStatus(t, p.push(p.signWith(stsSigner{key: retired}, verification(), "kid", core.Undefined)), 202)
	stranger := p.push(p.signWith(stsSigner{key: stsGenerateKey(t, "RS256", "")}, verification(), "kid", core.Undefined))
	sigStatus(t, stranger, 400)
	if sigJSON(t, stranger).Get("err") != "invalid_key" {
		t.Fatalf("answer %s", stranger.Body)
	}
	if f.listEvents(f.ownerCred, nil).Get("total") != 2.0 {
		t.Fatal("expected two events")
	}
}

func TestSignalsReceiverEndsSessionsOnlyForConfiguredEventTypes(t *testing.T) {
	f := newSignalsFixture(t, nil)
	p := f.pushSource(body("subjects", body("scimConnectionIds", items("okta-scim")),
		"actions", body("session-revoked", "revoke-sessions", "credential-compromise", "record")))
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	f.linkScim("okta-scim", aliceID, "00u-alice")
	first := f.signIn(alice)
	second := f.signIn(alice)
	aliceSubject := body("format", "iss_sub", "iss", sigIssuer, "sub", "00u-alice")

	// Recorded only: the sessions stay.
	sigStatus(t, p.push(p.sign(sigEvent(sigRISC+"credential-compromise", body("credential_type", "password"), aliceSubject))), 202)
	if f.signedOut(first) {
		t.Fatal("a recorded event ended a session")
	}
	revocation := p.sign(sigEvent(sigCAEP+"session-revoked", body("event_timestamp", f.seconds(), "initiating_entity", "policy"), aliceSubject))
	sigStatus(t, p.push(revocation), 202)
	if !f.signedOut(first) || !f.signedOut(second) {
		t.Fatal("sessions survived the revocation")
	}
	revokes := f.audit(f.tenantID, "signal:revoke-sessions")
	if len(revokes) != 1 || member(revokes[0].Get("metadata"), "revoked") != 2.0 || member(revokes[0].Get("metadata"), "sourceId") != p.sourceID {
		t.Fatalf("revocations %s", stringify(revokes))
	}

	// The same event again (a transmitter retrying): accepted, nothing happens twice.
	again := f.signIn(alice)
	sigStatus(t, p.push(revocation), 202)
	if f.signedOut(again) {
		t.Fatal("a duplicate ended sessions again")
	}
	sigExpect(t, sigReceive(t, f, p.sourceID, revocation), "duplicate", true, "status", "applied", "identityId", aliceID)
	if len(f.audit(f.tenantID, "signal:revoke-sessions")) != 1 || len(f.audit(f.tenantID, "signal:received")) != 2 {
		t.Fatal("a duplicate was processed again")
	}
	page := f.listEvents(f.ownerCred, nil)
	statuses := pluck(sigObjects(page.Get("events")), "status")
	sort.Strings(statuses)
	if strings.Join(statuses, ",") != "applied,recorded" {
		t.Fatalf("statuses %v", statuses)
	}
	for _, entry := range sigObjects(page.Get("events")) {
		if entry.Get("status") == "applied" {
			sigExpect(t, entry, "eventType", "session-revoked", "identityId", aliceID, "eventTimestamp", f.seconds()*1000,
				"claims", body("initiating_entity", "policy"))
		}
	}

	// A root administrator is never signed out by an organization's source.
	bob := f.member("bob")
	bobID := jsString(bob.Get("id"))
	f.linkScim("okta-scim", bobID, "00u-bob")
	f.signIn(bob)
	f.patch("identities", bobID, body("rootAdmin", true))
	protected := sigReceive(t, f, p.sourceID, p.sign(sigEvent(sigCAEP+"session-revoked", nil, body("format", "opaque", "id", "00u-bob"))))
	sigExpect(t, protected, "status", "ignored", "identityId", bobID, "duplicate", false)
	stored, err := f.getEvent(f.ownerCred, f.tenantID, jsString(protected.Get("eventId")))
	if err != nil {
		t.Fatal(err)
	}
	sigExpect(t, stored, "status", "ignored", "reason", "protected")
	if len(f.find("sessions", body("identityId", bobID))) != 1 {
		t.Fatal("the root administrator's session ended")
	}

	// An event about someone not mapped yet can be reprocessed once the mapping exists; the action runs then.
	dan := f.member("dan")
	danID := jsString(dan.Get("id"))
	danSession := f.signIn(dan)
	early := sigReceive(t, f, p.sourceID, p.sign(sigEvent(sigCAEP+"session-revoked", nil, body("format", "opaque", "id", "00u-dan"))))
	sigExpect(t, early, "status", "unmatched")
	f.linkScim("okta-scim", danID, "00u-dan")
	owner := f.ownerSignIn(f.tenantID)
	reprocessed := sigOut(f.api().Reprocess(f.ctx, owner, Input[apitypes.SignalsReprocessInput](body("tenantId", f.tenantID, "eventId", early.Get("eventId")))))
	sigExpect(t, reprocessed, "status", "applied", "identityId", danID, "reprocessedBy", f.ownerID)
	if !f.signedOut(danSession) {
		t.Fatal("the reprocessed revocation did not end the session")
	}
	reprocesses := f.audit(f.tenantID, "signal:reprocess")
	if len(reprocesses) != 1 {
		t.Fatalf("reprocess audits %d", len(reprocesses))
	}
	sigExpect(t, reprocesses[0], "=metadata", body("sourceId", p.sourceID, "eventType", "session-revoked",
		"jti", member(reprocesses[0].Get("metadata"), "jti"), "previousStatus", "unmatched", "status", "applied", "identityId", danID))
	// Threat detection sees it with the identity now.
	seen := 0
	for _, entry := range f.audit(f.tenantID, "signal:received") {
		if member(entry.Get("metadata"), "identityId") == danID {
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("signal:received for dan %d", seen)
	}
	_, err = f.api().Reprocess(f.ctx, owner, Input[apitypes.SignalsReprocessInput](body("tenantId", f.tenantID, "eventId", early.Get("eventId"))))
	expectError(t, err, "INVALID_TRANSITION", "Only unmatched and failed events can be reprocessed")
}

func TestSignalsReceiverAcceptsLegacyRiscEvents(t *testing.T) {
	f := newSignalsFixture(t, nil)
	google := stsGenerateKey(t, "RS256", "google-2026")
	const googleIssuer = "https://accounts.google.com/"
	const client = "1234-web.apps.googleusercontent.com"
	const person = "110169484474386276334"
	owner := f.ownerSignIn(f.tenantID)
	created, err := f.createSource(owner, body("tenantId", f.tenantID, "name", "Google", "issuer", googleIssuer, "audiences", items(client),
		"jwks", body("keys", items(google.publicJwk)), "delivery", "push", "pushToken", false,
		"subjects", body("connectionIds", items("google")), "actions", body("sessions-revoked", "revoke-sessions")))
	if err != nil {
		t.Fatal(err)
	}
	sigExpect(t, created.Get("source").(*core.Object), "issuer", "https://accounts.google.com", "requireTyp", true, "hasPushToken", false)
	if !isUndefined(created.Get("pushToken")) {
		t.Fatal("a push token was issued")
	}
	sourceID := jsString(member(created.Get("source"), "id"))
	paula := f.member("paula")
	// Google ID tokens name the issuer without the trailing slash its RISC events use.
	f.link(f.tenantID, "google", "https://accounts.google.com", person, jsString(paula.Get("id")))
	session := f.signIn(paula)

	// Google's shape: no typ, OAuth client ids as audiences, the subject inside the event (`subject_type`).
	risc := func(eventType string, claims *core.Object, header ...any) string {
		if len(header) == 0 {
			header = []any{"typ", core.Undefined}
		}
		return stsSignJwt(t, stsSigner{key: google}, body("iss", googleIssuer, "aud", items(client, "5678-android.apps.googleusercontent.com"),
			"iat", f.seconds(), "jti", sigUUID(), "events", body(sigRISC+eventType, claims)), header...)
	}
	post := func(set string) *Response {
		return f.fetch(http.MethodPost, jsString(created.Get("pushUrl")), map[string]string{"content-type": "application/secevent+jwt"}, set)
	}
	revoked := risc("sessions-revoked", body("subject", body("subject_type", "iss-sub", "iss", googleIssuer, "sub", person)))
	strict := post(revoked)
	sigStatus(t, strict, 400)
	if sigJSON(t, strict).Get("err") != "invalid_request" {
		t.Fatalf("answer %s", strict.Body)
	}
	if _, err := f.updateSource(owner, body("tenantId", f.tenantID, "sourceId", sourceID, "requireTyp", false)); err != nil {
		t.Fatal(err)
	}
	sigStatus(t, post(revoked), 202)
	if !f.signedOut(session) {
		t.Fatal("the session survived")
	}
	events := sigObjects(f.listEvents(f.ownerCred, body("eventType", "sessions-revoked")).Get("events"))
	sigExpect(t, events[0], "status", "applied", "identityId", paula.Get("id"),
		"subject", body("format", "iss_sub", "iss", googleIssuer, "sub", person), "claims", body())

	// Google's verification event lives under the RISC namespace.
	sigStatus(t, post(risc("verification", body("state", "check-1"))), 202)
	if f.getSource(owner, f.tenantID, sourceID).Get("lastVerifiedAt") != f.now() {
		t.Fatal("lastVerifiedAt not recorded")
	}
	// A plain JWT typ passes; other token types (an access token) never do.
	sigStatus(t, post(risc("account-credential-change-required", body(), "typ", "JWT")), 202)
	sigStatus(t, post(risc("account-credential-change-required", body(), "typ", "at+jwt")), 400)
}

func TestSignalsReceiverMapsSubjectsToPeopleOfTheSourceOrganization(t *testing.T) {
	f := newSignalsFixture(t, nil)
	betaID, _ := f.organization("Beta", "owner@beta.test")
	p := f.pushSource(body("issuer", sigIssuer+"/", "subjects", body("matchEmail", true, "connectionIds", items("okta-oidc"),
		"scimConnectionIds", items("okta-scim"))))
	receive := func(subject *core.Object) *core.Object {
		t.Helper()
		return sigReceive(t, f, p.sourceID, p.sign(sigEvent(sigRISC+"account-disabled", nil, subject)))
	}
	alice := f.member("alice")
	bob := f.member("bob")
	carol := f.member("carol")
	dave := f.identityAt(f.tenantID, "dave@other.test", "Dave")

	// Email: only at a domain the organization proved it controls.
	sigExpect(t, receive(body("format", "email", "email", "alice@acme.test")), "status", "unmatched")
	claim := sigOut(f.iam.API.Domains.Add(f.ctx, f.ownerCred, Input[apitypes.DomainsAddInput](body("tenantId", f.tenantID, "domain", "acme.test"))))
	record := claim.Get("dnsRecord").(*core.Object)
	f.setDNS(jsString(record.Get("name")), []string{jsString(record.Get("value"))})
	verified := sigOut(f.iam.API.Domains.Verify(f.ctx, f.ownerCred, Input[apitypes.DomainsVerifyInput](body("tenantId", f.tenantID, "domainId", claim.Get("id")))))
	sigExpect(t, verified, "verified", true)
	sigExpect(t, receive(body("format", "email", "email", "Alice@ACME.test")), "status", "recorded", "identityId", alice.Get("id"))
	sigExpect(t, receive(body("format", "account", "uri", "acct:alice@acme.test")), "identityId", alice.Get("id"))
	sigExpect(t, receive(body("format", "email", "email", "dave@other.test")), "status", "unmatched")
	// Someone of another organization with an address at the domain is never matched.
	f.identityAt(betaID, "erin@acme.test", "Erin")
	sigExpect(t, receive(body("format", "email", "email", "erin@acme.test")), "status", "unmatched")

	// iss_sub: a federation link of a configured connection, for the source's issuer in either spelling.
	f.link(f.tenantID, "okta-oidc", sigIssuer, "00u-bob", jsString(bob.Get("id")))
	for _, iss := range []string{sigIssuer, sigIssuer + "/"} {
		sigExpect(t, receive(body("format", "iss_sub", "iss", iss, "sub", "00u-bob")), "status", "recorded", "identityId", bob.Get("id"))
	}
	// Not another issuer's subject, not a link of a connection the source does not name, not another organization's
	// link.
	f.link(f.tenantID, "okta-oidc", "https://other-idp.example.test", "00u-bob", jsString(bob.Get("id")))
	sigExpect(t, receive(body("format", "iss_sub", "iss", "https://other-idp.example.test", "sub", "00u-bob")), "status", "unmatched")
	f.link(f.tenantID, "saml-partner", sigIssuer, "00u-dave", jsString(dave.Get("id")))
	sigExpect(t, receive(body("format", "iss_sub", "iss", sigIssuer, "sub", "00u-dave")), "status", "unmatched")
	frank := f.identityAt(betaID, "frank@beta.test", "Frank")
	f.link(betaID, "okta-oidc", sigIssuer, "00u-frank", jsString(frank.Get("id")))
	sigExpect(t, receive(body("format", "iss_sub", "iss", sigIssuer, "sub", "00u-frank")), "status", "unmatched")

	// SCIM externalId: as iss_sub, opaque, a complex subject's user, or one alias among others.
	f.linkScim("okta-scim", jsString(carol.Get("id")), "00u-carol")
	for _, subject := range []*core.Object{
		body("format", "iss_sub", "iss", sigIssuer, "sub", "00u-carol"),
		body("format", "opaque", "id", "00u-carol"),
		body("format", "complex", "user", body("format", "opaque", "id", "00u-carol"), "session", body("format", "opaque", "id", "sid-1")),
		body("format", "aliases", "identifiers", items(body("format", "phone_number", "phone_number", "+15555550100"),
			body("format", "opaque", "id", "00u-carol"))),
	} {
		sigExpect(t, receive(subject), "status", "recorded", "identityId", carol.Get("id"))
	}
	f.linkScim("other-scim", jsString(dave.Get("id")), "00u-dave-2")
	sigExpect(t, receive(body("format", "opaque", "id", "00u-dave-2")), "status", "unmatched")
	// Subjects that name no person, and no subject at all.
	sigExpect(t, receive(body("format", "complex", "session", body("format", "opaque", "id", "sid-1"))), "status", "unmatched")
	anonymous := receive(nil)
	stored, err := f.getEvent(f.ownerCred, f.tenantID, jsString(anonymous.Get("eventId")))
	if err != nil {
		t.Fatal(err)
	}
	sigExpect(t, stored, "status", "unmatched", "reason", "no-subject")

	// Turning email matching off stops email matches; the rest of the mapping stays.
	if _, err := f.updateSource(f.ownerSignIn(f.tenantID), body("tenantId", f.tenantID, "sourceId", p.sourceID,
		"subjects", body("matchEmail", false))); err != nil {
		t.Fatal(err)
	}
	sigExpect(t, receive(body("format", "email", "email", "alice@acme.test")), "status", "unmatched")
	sigExpect(t, receive(body("format", "opaque", "id", "00u-carol")), "identityId", carol.Get("id"))
	if total := f.listEvents(f.ownerCred, body("identityId", carol.Get("id"))).Get("total"); total != 5.0 {
		t.Fatalf("carol's events %v", total)
	}
}

func TestSignalsReceiverAuditsEveryReceivedEvent(t *testing.T) {
	f := newSignalsFixture(t, nil)
	p := f.pushSource(body("subjects", body("scimConnectionIds", items("okta-scim"))))
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	f.linkScim("okta-scim", aliceID, "00u-alice")
	subject := body("format", "opaque", "id", "00u-alice")
	receive := func(eventType string, claims *core.Object, about *core.Object) *core.Object {
		return sigReceive(t, f, p.sourceID, p.sign(sigEvent(eventType, claims, about)))
	}
	compromise := receive(sigRISC+"credential-compromise", body("credential_type", "password",
		"reason_admin", body("de", "In einem Datenleck gefunden", "en", "Found in a breach corpus"),
		"reason_user", body("en", "Your password appeared in a breach")), subject)
	receive(sigCAEP+"risk-level-change", body("current_level", "high", "previous_level", "low",
		"risk_reason", "PASSWORD_FOUND_IN_DATA_BREACH", "principal", "USER"), subject)
	receive(sigRISC+"account-disabled", body("reason", "hijacking", "reason_admin", strings.Repeat("x", 300)), body("format", "opaque", "id", "nobody"))
	trail := f.audit(f.tenantID, "signal:received")
	if len(trail) != 3 {
		t.Fatalf("signal:received %d", len(trail))
	}
	about := func(eventType string) *core.Object {
		for _, entry := range trail {
			if member(entry.Get("metadata"), "eventType") == eventType {
				return entry
			}
		}
		t.Fatalf("no %s", eventType)
		return nil
	}
	stored, err := f.getEvent(f.ownerCred, f.tenantID, jsString(compromise.Get("eventId")))
	if err != nil {
		t.Fatal(err)
	}
	sigExpect(t, about("credential-compromise"), "actorId", "signal:"+p.sourceID, "resourceId", aliceID, "outcome", "allow",
		"=metadata", body("sourceId", p.sourceID, "eventType", "credential-compromise", "jti", stored.Get("jti"), "status", "recorded",
			"identityId", aliceID, "reasonAdmin", "Found in a breach corpus", "credentialType", "password"))
	risk := about("risk-level-change")
	sigExpect(t, risk, "=metadata", body("sourceId", p.sourceID, "eventType", "risk-level-change", "jti", member(risk.Get("metadata"), "jti"),
		"status", "recorded", "identityId", aliceID, "currentLevel", "HIGH"))
	unmatched := about("account-disabled")
	sigExpect(t, unmatched, "resourceId", "signals/sources/"+p.sourceID,
		"=metadata", body("sourceId", p.sourceID, "eventType", "account-disabled", "jti", member(unmatched.Get("metadata"), "jti"),
			"status", "unmatched", "reasonAdmin", strings.Repeat("x", 256)))
}

// sigListen is a local HTTP server playing an upstream identity provider or an RFC 8936 poll endpoint.
func sigListen(t *testing.T, handle func(request *http.Request, body string, w http.ResponseWriter)) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		handle(r, string(data), w)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func sigReply(w http.ResponseWriter, status int, value any) {
	text, _, _ := core.Stringify(core.Normalize(value))
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, text)
}

func TestSignalsReceiverDiscoversKeysAndAnswers503WhileUnavailable(t *testing.T) {
	f := newSignalsFixture(t, insecureLocalhost)
	key := stsGenerateKey(t, "EdDSA", "edge-1")
	var mu sync.Mutex
	keysStatus, discoveries := 500, 0
	var base string
	base = sigListen(t, func(request *http.Request, _ string, w http.ResponseWriter) {
		mu.Lock()
		defer mu.Unlock()
		switch request.URL.Path {
		case "/.well-known/ssf-configuration/tenant":
			discoveries++
			sigReply(w, 200, body("spec_version", "1_0", "issuer", base+"/tenant", "jwks_uri", base+"/keys",
				"delivery_methods_supported", items("urn:ietf:rfc:8935")))
		case "/.well-known/ssf-configuration/impostor":
			sigReply(w, 200, body("issuer", "https://someone-else.example.test", "jwks_uri", base+"/keys"))
		case "/keys":
			if keysStatus == 200 {
				sigReply(w, 200, body("keys", items(key.publicJwk)))
			} else {
				sigReply(w, keysStatus, body("error", "unavailable"))
			}
		default:
			sigReply(w, 404, body())
		}
	})
	owner := f.ownerSignIn(f.tenantID)
	create := func(path string) *core.Object {
		created, err := f.createSource(owner, body("tenantId", f.tenantID, "name", path, "issuer", base+"/"+path, "audiences", items("rp"),
			"delivery", "push", "pushToken", false))
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	post := func(url, set string) *Response {
		return f.fetch(http.MethodPost, url, map[string]string{"content-type": "application/secevent+jwt"}, set)
	}
	verification := func(issuer string, signer *stsTestKey) string {
		return stsSignJwt(t, stsSigner{key: signer}, body("iss", issuer, "aud", "rp", "iat", f.seconds(), "jti", sigUUID(),
			"events", body(sigSSF+"verification", body())), "typ", "secevent+jwt")
	}
	tenant := create("tenant")
	tenantURL := jsString(tenant.Get("pushUrl"))

	// The key set answers 500: a temporary refusal, so the transmitter delivers again.
	unavailable := post(tenantURL, verification(base+"/tenant", key))
	sigStatus(t, unavailable, 503)
	if unavailable.Header.Get("Retry-After") != "30" || sigJSON(t, unavailable).Get("err") != "invalid_key" {
		t.Fatalf("answer %v %s", unavailable.Header, unavailable.Body)
	}
	// Once it answers: accepted; the discovery document was read once.
	mu.Lock()
	keysStatus = 200
	mu.Unlock()
	sigStatus(t, post(tenantURL, verification(base+"/tenant", key)), 202)
	sigStatus(t, post(tenantURL, verification(base+"/tenant", key)), 202)
	mu.Lock()
	if discoveries != 1 {
		t.Fatalf("discoveries %d", discoveries)
	}
	mu.Unlock()
	// A key the fetched set does not have yet (a transmitter that just rotated) is retried later too.
	rotated := post(tenantURL, verification(base+"/tenant", stsGenerateKey(t, "EdDSA", "edge-2")))
	sigStatus(t, rotated, 503)
	if sigJSON(t, rotated).Get("err") != "invalid_key" {
		t.Fatalf("answer %s", rotated.Body)
	}

	// A discovery document naming another issuer is not trusted.
	impostor := create("impostor")
	sigStatus(t, post(jsString(impostor.Get("pushUrl")), verification(base+"/impostor", key)), 503)
	lastError := member(f.getSource(owner, f.tenantID, jsString(member(impostor.Get("source"), "id"))).Get("lastError"), "message")
	if !strings.Contains(jsString(lastError), "could not be obtained") {
		t.Fatalf("lastError %v", lastError)
	}

	// Key URLs on private addresses are refused at registration (only loopback is allowed here).
	for _, jwksURI := range []string{"https://10.0.0.8/keys", "https://169.254.169.254/latest/keys"} {
		_, err := f.createSource(owner, body("tenantId", f.tenantID, "name", "Internal", "issuer", "https://internal.example.test",
			"audiences", items("rp"), "jwksUri", jwksURI, "delivery", "push"))
		expectErrorPrefix(t, err, "INVALID_INPUT", "jwksUri")
	}
	_, err := f.iam.Signals.Receive(f.ctx, sigUUID(), "x.y.z")
	expectError(t, err, "NOT_FOUND", "Signal source not found")
}

type sigPollRequest struct {
	authorization string
	contentType   string
	body          *core.Object
}

type sigPollReply struct {
	status int
	body   any
}

func TestSignalsReceiverPollsAnRfc8936Transmitter(t *testing.T) {
	f := newSignalsFixture(t, insecureLocalhost)
	key := stsGenerateKey(t, "ES256", "poll-1")
	var mu sync.Mutex
	requests := []sigPollRequest{}
	replies := []sigPollReply{}
	base := sigListen(t, func(request *http.Request, text string, w http.ResponseWriter) {
		if request.URL.Path != "/poll" || request.Method != http.MethodPost {
			sigReply(w, 404, body())
			return
		}
		mu.Lock()
		parsed, _ := core.ParseJSONString(text)
		object, _ := parsed.(*core.Object)
		requests = append(requests, sigPollRequest{request.Header.Get("authorization"), request.Header.Get("content-type"), object})
		next := sigPollReply{status: 200, body: body("sets", body(), "moreAvailable", false)}
		if len(replies) > 0 {
			next, replies = replies[0], replies[1:]
		}
		mu.Unlock()
		if next.status == 0 {
			next.status = 200
		}
		if next.body == nil {
			next.body = body()
		}
		sigReply(w, next.status, next.body)
	})
	queue := func(entries ...sigPollReply) {
		mu.Lock()
		defer mu.Unlock()
		replies = append(replies, entries...)
	}
	sent := func(index int) sigPollRequest {
		mu.Lock()
		defer mu.Unlock()
		if index < 0 {
			index += len(requests)
		}
		return requests[index]
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(requests)
	}
	polled := func(jti string) string {
		return f.securityEvent(stsSigner{key: key}, sigEvent(sigRISC+"account-disabled", nil, body("format", "opaque", "id", "nobody")).Set("jti", jti))
	}
	owner := f.ownerSignIn(f.tenantID)
	created, err := f.createSource(owner, body("tenantId", f.tenantID, "name", "Poller", "issuer", sigIssuer, "audiences", items(sigAudience),
		"jwks", body("keys", items(key.publicJwk)), "delivery", "poll",
		"poll", body("endpoint", base+"/poll", "token", "poll-secret-token", "maxEvents", 10.0)))
	if err != nil {
		t.Fatal(err)
	}
	sourceID := jsString(member(created.Get("source"), "id"))
	source := func() *core.Object { return f.getSource(f.ownerCred, f.tenantID, sourceID) }
	if !isUndefined(created.Get("pushUrl")) || !isUndefined(created.Get("pushToken")) {
		t.Fatal("a poll source got push settings")
	}
	sigExpect(t, created.Get("source").(*core.Object), "poll", body("endpoint", base+"/poll", "maxEvents", 10.0, "pendingAcks", 0.0))
	// The poll token is stored sealed and never shown.
	if strings.Contains(stringify(created), "poll-secret-token") || strings.Contains(stringify(f.record("signalSources", sourceID)), "poll-secret-token") {
		t.Fatal("the poll token leaked")
	}
	// A poll source takes no pushes.
	sigStatus(t, f.fetch(http.MethodPost, "http://localhost:3000/api/iam/signals/push/"+sourceID,
		map[string]string{"content-type": "application/secevent+jwt"}, polled("pushed")), 404)

	pollAll := func(input *core.Object) *core.Object {
		t.Helper()
		result, err := f.iam.Signals.Poll(f.ctx, input)
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		return result
	}
	result := func(sources, received, acknowledged, errors float64) *core.Object {
		return body("sources", sources, "received", received, "acknowledged", acknowledged, "errors", errors)
	}

	// One run: two requests (moreAvailable), the second acknowledging what the first returned.
	queue(sigPollReply{body: body("sets", body("a", polled("a"), "b", polled("b")), "moreAvailable", true)},
		sigPollReply{body: body("sets", body("c", polled("c"), "bad", "x.y.z", "mismatched", polled("other")))})
	stsSame(t, pollAll(nil), result(1, 3, 2, 0))
	first := sent(0)
	if first.authorization != "Bearer poll-secret-token" || first.contentType != "application/json" {
		t.Fatalf("request %+v", first)
	}
	stsSame(t, first.body, body("maxEvents", 10.0, "returnImmediately", true, "ack", items()))
	stsSame(t, sent(1).body, body("maxEvents", 10.0, "returnImmediately", true, "ack", items("a", "b")))
	poll := source().Get("poll").(*core.Object)
	sigExpect(t, poll, "pendingAcks", 1.0, "lastPolledAt", f.now())

	// The transmitter fails: acknowledgements and errors wait for the next run.
	queue(sigPollReply{status: 500, body: body()})
	stsSame(t, sigOut(f.api().Poll(f.ctx, owner, Input[apitypes.SignalsPollInput](body("tenantId", f.tenantID, "sourceId", sourceID)))), result(1, 0, 0, 1))
	third := sent(2).body
	sigExpect(t, third, "maxEvents", 10.0, "returnImmediately", true, "ack", items("c"))
	setErrs := third.Get("setErrs").(*core.Object)
	if strings.Join(setErrs.Keys(), ",") != "bad,mismatched" || member(setErrs.Get("bad"), "err") != "invalid_request" ||
		member(setErrs.Get("mismatched"), "err") != "invalid_request" {
		t.Fatalf("setErrs %s", stringify(setErrs))
	}
	current := source()
	if member(current.Get("lastError"), "message") != "The poll endpoint answered 500" || member(current.Get("poll"), "pendingAcks") != 1.0 {
		t.Fatalf("source %s", stringify(current))
	}

	// A redelivered event is acknowledged again but recorded once.
	queue(sigPollReply{body: body("sets", body("a", polled("a")), "moreAvailable", false)})
	stsSame(t, pollAll(body("sourceId", sourceID)), result(1, 0, 1, 0))
	stsSame(t, sent(3).body, body("maxEvents", 10.0, "returnImmediately", true, "ack", items("c"), "setErrs", setErrs))

	// More than a run's worth: at most five requests per source per run.
	for index := 0; index < 8; index++ {
		jti := "e" + string(rune('0'+index))
		queue(sigPollReply{body: body("sets", body(jti, polled(jti)), "moreAvailable", true)})
	}
	before := count()
	stsSame(t, pollAll(nil), result(1, 5, 5, 0))
	if count()-before != 5 {
		t.Fatalf("requests %d", count()-before)
	}
	stsSame(t, sent(before).body.Get("ack"), items("a"))
	stsSame(t, sent(-1).body.Get("ack"), items("e3"))
	if total := f.listEvents(f.ownerCred, body("sourceId", sourceID)).Get("total"); total != 8.0 {
		t.Fatalf("events %v", total)
	}
	mu.Lock()
	replies = nil
	mu.Unlock()

	// Disabled sources are not polled; push sources cannot be.
	if _, err := f.updateSource(owner, body("tenantId", f.tenantID, "sourceId", sourceID, "status", "disabled")); err != nil {
		t.Fatal(err)
	}
	stsSame(t, pollAll(nil), result(0, 0, 0, 0))
	_, err = f.api().Poll(f.ctx, owner, Input[apitypes.SignalsPollInput](body("tenantId", f.tenantID, "sourceId", sourceID)))
	expectError(t, err, "INVALID_TRANSITION", "The source is disabled")
	push, err := f.createSource(owner, body("tenantId", f.tenantID, "name", "Pusher", "issuer", "https://push.example.test",
		"audiences", items(sigAudience), "jwks", body("keys", items(key.publicJwk)), "delivery", "push"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.api().Poll(f.ctx, owner, Input[apitypes.SignalsPollInput](body("tenantId", f.tenantID, "sourceId", member(push.Get("source"), "id"))))
	expectError(t, err, "INVALID_INPUT", "This source receives its events by push")
	// A new poll endpoint needs its token again.
	_, err = f.updateSource(owner, body("tenantId", f.tenantID, "sourceId", sourceID, "poll", body("endpoint", base+"/poll/v2")))
	expectError(t, err, "INVALID_INPUT", "A new poll endpoint needs its token again")
	moved, err := f.updateSource(owner, body("tenantId", f.tenantID, "sourceId", sourceID, "poll", body("endpoint", base+"/poll/v2", "token", "another-token")))
	if err != nil {
		t.Fatal(err)
	}
	sigExpect(t, moved.Get("poll").(*core.Object), "endpoint", base+"/poll/v2", "pendingAcks", 0.0)
}

func TestSignalsReceiverLeavesPolledEventsUnacknowledgedWhileKeysAreMissing(t *testing.T) {
	f := newSignalsFixture(t, insecureLocalhost)
	key := stsGenerateKey(t, "PS256", "poll-2")
	var mu sync.Mutex
	keysStatus := 503
	acks := []string{}
	set := f.securityEvent(stsSigner{key: key}, sigEvent(sigRISC+"account-enabled", nil, nil).Set("jti", "k1"))
	base := sigListen(t, func(request *http.Request, text string, w http.ResponseWriter) {
		mu.Lock()
		defer mu.Unlock()
		if request.URL.Path == "/keys" {
			if keysStatus == 200 {
				sigReply(w, 200, body("keys", items(key.publicJwk)))
			} else {
				sigReply(w, keysStatus, body())
			}
			return
		}
		parsed, _ := core.ParseJSONString(text)
		object := parsed.(*core.Object)
		acks = append(acks, stringify(core.NewObject("ack", object.Get("ack"), "setErrs", object.Get("setErrs"))))
		// Unacknowledged events come back until acknowledged.
		if strings.Contains(stringify(object.Get("ack")), `"k1"`) {
			sigReply(w, 200, body("sets", body()))
		} else {
			sigReply(w, 200, body("sets", body("k1", set)))
		}
	})
	created, err := f.createSource(f.ownerSignIn(f.tenantID), body("tenantId", f.tenantID, "name", "Poller", "issuer", sigIssuer,
		"audiences", items(sigAudience), "jwksUri", base+"/keys", "algorithms", items("PS256"), "delivery", "poll",
		"poll", body("endpoint", base+"/poll", "token", "poll-token")))
	if err != nil {
		t.Fatal(err)
	}
	poll := func() *core.Object {
		result, err := f.iam.Signals.Poll(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	stsSame(t, poll(), body("sources", 1.0, "received", 0.0, "acknowledged", 0.0, "errors", 1.0))
	mu.Lock()
	keysStatus = 200
	mu.Unlock()
	stsSame(t, poll(), body("sources", 1.0, "received", 1.0, "acknowledged", 0.0, "errors", 0.0))
	sigExpect(t, poll(), "received", 0.0, "acknowledged", 1.0)
	// Neither acknowledged nor reported as an error while the keys were missing.
	mu.Lock()
	got := strings.Join(acks, "|")
	mu.Unlock()
	if got != `{"ack":[]}|{"ack":[]}|{"ack":["k1"]}` {
		t.Fatalf("acks %s", got)
	}
	events := sigObjects(f.listEvents(f.ownerCred, body("sourceId", member(created.Get("source"), "id"))).Get("events"))
	if len(events) != 1 {
		t.Fatalf("events %d", len(events))
	}
	sigExpect(t, events[0], "jti", "k1", "eventType", "account-enabled", "status", "unmatched")
}

func TestSignalsReceiverReSealsThePollTokenWhenTheSecretRotates(t *testing.T) {
	f := newSignalsFixture(t, insecureLocalhost)
	key := stsGenerateKey(t, "ES256", "poll-3")
	var mu sync.Mutex
	authorizations := []string{}
	base := sigListen(t, func(request *http.Request, _ string, w http.ResponseWriter) {
		mu.Lock()
		authorizations = append(authorizations, request.Header.Get("authorization"))
		mu.Unlock()
		if request.Header.Get("authorization") != "Bearer rotating-poll-token" {
			sigReply(w, 401, body())
			return
		}
		sigReply(w, 200, body("sets", body(), "moreAvailable", false))
	})
	created, err := f.createSource(f.ownerSignIn(f.tenantID), body("tenantId", f.tenantID, "name", "Poller", "issuer", sigIssuer,
		"audiences", items(sigAudience), "jwks", body("keys", items(key.publicJwk)), "delivery", "poll",
		"poll", body("endpoint", base+"/poll", "token", "rotating-poll-token")))
	if err != nil {
		t.Fatal(err)
	}
	const newSecret = "a-new-deployment-secret-with-32-characters!!"
	deployment := func(secret string, previous ...string) *BetterIam {
		t.Helper()
		iam, err := New(&BetterIamOptions{Database: f.iam.Store, Secret: secret, PreviousSecrets: previous, BaseURL: directoryOrigin,
			Signals: &SignalsOptions{AllowInsecureLocalhost: flag(true)}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(iam.Close)
		return iam
	}
	poll := func(iam *BetterIam) *core.Object {
		t.Helper()
		result, err := iam.Signals.Poll(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	// During the rotation the token still opens with the previous secret, and is re-sealed.
	during := deployment(newSecret, f.iam.Context.Options.Secret)
	sigExpect(t, poll(during), "sources", 1.0, "errors", 0.0)
	rotation, err := during.RotateSecrets(f.ctx, SecretRotationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rotation.Resealed.Get("signalSources") != 1.0 {
		t.Fatalf("resealed %s", stringify(rotation.Resealed))
	}
	// The old deployment can no longer open it; the new secret alone can.
	sigExpect(t, poll(f.iam), "sources", 1.0, "errors", 1.0)
	message := member(f.getSource(f.ownerCred, f.tenantID, jsString(member(created.Get("source"), "id"))).Get("lastError"), "message")
	if !strings.Contains(jsString(message), "sealed with a secret that is gone") {
		t.Fatalf("lastError %v", message)
	}
	sigExpect(t, poll(deployment(newSecret)), "sources", 1.0, "errors", 0.0)
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(authorizations, ",") != "Bearer rotating-poll-token,Bearer rotating-poll-token" {
		t.Fatalf("authorizations %v", authorizations)
	}
}

func TestSignalsAPIGuardsAndValidates(t *testing.T) {
	f := newSignalsFixture(t, insecureLocalhost)
	betaID, _ := f.organization("Beta", "owner@beta.test")
	key := stsGenerateKey(t, "RS256", "api-1")
	owner := f.ownerSignIn(f.tenantID)
	base := func() *core.Object {
		return body("tenantId", f.tenantID, "name", "IdP", "issuer", sigIssuer, "audiences", items(sigAudience),
			"jwks", body("keys", items(key.publicJwk)), "delivery", "push")
	}
	created, err := f.createSource(owner, base())
	if err != nil {
		t.Fatal(err)
	}
	sourceID := jsString(member(created.Get("source"), "id"))
	pushToken := jsString(created.Get("pushToken"))

	// The push token is shown once; views never carry it, its hash or a sealed token.
	view := f.getSource(f.ownerCred, f.tenantID, sourceID)
	sigExpect(t, view, "hasPushToken", true, "requireTyp", true, "status", "active", "algorithms", items("RS256", "ES256", "PS256", "EdDSA"),
		"subjects", body("connectionIds", items(), "matchEmail", false, "scimConnectionIds", items()), "actions", body(),
		"pushUrl", created.Get("pushUrl"), "createdBy", f.ownerID)
	if view.Has("pushTokenHash") || strings.Contains(stringify(view), pushToken) {
		t.Fatal("the view carries the push token")
	}
	listed := answer(f.api().ListSources(f.ctx, f.ownerCred, Input[apitypes.SignalsListSourcesInput](body("tenantId", f.tenantID))))
	stsSame(t, listed, items(view))

	// People without the permission, and other organizations, are refused.
	_, eve := f.person(f.tenantID, "eve")
	_, err = f.api().ListSources(f.ctx, eve, Input[apitypes.SignalsListSourcesInput](body("tenantId", f.tenantID)))
	expectStatusCode(t, err, "ACCESS_DENIED")
	_, err = f.api().ListEvents(f.ctx, eve, Input[apitypes.SignalsListEventsInput](body("tenantId", f.tenantID)))
	expectStatusCode(t, err, "ACCESS_DENIED")
	_, err = f.createSource(eve, base().Spread(body("issuer", "https://eve.example.test")))
	expectStatusCode(t, err, "ACCESS_DENIED")
	betaOwner := f.ownerSignIn(betaID)
	_, err = f.api().GetSource(f.ctx, betaOwner, Input[apitypes.SignalsGetSourceInput](body("tenantId", f.tenantID, "sourceId", sourceID)))
	expectStatusCode(t, err, "ACCESS_DENIED")
	_, err = f.api().GetSource(f.ctx, betaOwner, Input[apitypes.SignalsGetSourceInput](body("tenantId", betaID, "sourceId", sourceID)))
	expectStatusCode(t, err, "NOT_FOUND")
	_, err = f.api().DeleteSource(f.ctx, betaOwner, Input[apitypes.SignalsDeleteSourceInput](body("tenantId", betaID, "sourceId", sourceID)))
	expectStatusCode(t, err, "NOT_FOUND")

	// Input validation.
	poll := func(pairs ...any) *core.Object {
		return body("endpoint", "https://idp.example.test/poll", "token", "poll-token").Spread(core.NewObject(pairs...))
	}
	elevenAudiences, sixAliases := items(), items()
	for index := 0; index < 11; index++ {
		elevenAudiences = append(elevenAudiences, "aud-"+string(rune('a'+index)))
	}
	for index := 0; index < 6; index++ {
		sixAliases = append(sixAliases, "https://alias"+string(rune('0'+index))+".example.test")
	}
	for _, input := range []*core.Object{
		body("issuer", "http://idp.example.test"),
		body("issuer", "https://idp.example.test/?tenant=1"),
		body("issuer", "not a url"),
		body("name", ""),
		body("audiences", items()),
		body("audiences", elevenAudiences),
		body("algorithms", items("HS256")),
		body("algorithms", items("none")),
		body("algorithms", items()),
		body("jwks", body("keys", items(key.privateJwk))),
		body("jwks", body("keys", items())),
		body("jwksUri", "https://idp.example.test/keys"),
		body("jwks", core.Undefined, "jwksUri", "https://10.1.2.3/keys"),
		body("jwks", core.Undefined, "jwksUri", "http://keys.example.test/jwks"),
		body("delivery", "email"),
		body("delivery", "poll"),
		body("delivery", "poll", "poll", poll("token", "has a space")),
		body("delivery", "poll", "poll", poll("maxEvents", 0.0)),
		body("delivery", "poll", "poll", poll("endpoint", "https://192.168.1.10/poll")),
		body("delivery", "poll", "poll", poll("extra", true)),
		body("delivery", "poll", "poll", poll(), "pushToken", true),
		body("poll", poll()),
		body("subjects", body("emails", true)),
		body("subjects", body("matchEmail", "yes")),
		body("subjects", body("connectionIds", "okta")),
		body("actions", body("verification", "revoke-sessions")),
		body("actions", body("session-revoked", "disable")),
		body("actions", body("made-up", "record")),
		body("requireTyp", "no"),
		body("issuerAliases", items("http://alias.example.test")),
		body("issuerAliases", sixAliases),
	} {
		merged := base().Spread(body("issuer", "https://new.example.test"))
		input.Entries(func(key string, value any) bool {
			if isUndefined(value) {
				merged.Delete(key)
			} else {
				merged.Set(key, value)
			}
			return true
		})
		_, err := f.createSource(owner, merged)
		if known, ok := asIamError(err); !ok || known.Code != "INVALID_INPUT" {
			t.Fatalf("%s: %v", stringify(input), err)
		}
	}

	// One source per issuer (trailing slashes aside), twenty per organization; another organization has its own.
	_, err = f.createSource(owner, base().Spread(body("issuer", sigIssuer+"/")))
	expectStatusCode(t, err, "CONFLICT")
	for index := 1; index < 20; index++ {
		if _, err := f.createSource(owner, base().Spread(body("issuer", "https://idp"+jsString(float64(index))+".example.test", "pushToken", false))); err != nil {
			t.Fatal(err)
		}
	}
	_, err = f.createSource(owner, base().Spread(body("issuer", "https://idp20.example.test")))
	expectStatusCode(t, err, "LIMIT_EXCEEDED")
	if _, err := f.createSource(betaOwner, base().Spread(body("tenantId", betaID))); err != nil {
		t.Fatal(err)
	}

	// Updates: the issuer, delivery and push token cannot change here; an update must change something.
	update := func(input *core.Object, credential core.CredentialInput) (*core.Object, error) {
		return f.updateSource(credential, body("tenantId", f.tenantID, "sourceId", sourceID).Spread(input))
	}
	for _, input := range []*core.Object{
		body("issuer", "https://other.example.test"),
		body("delivery", "poll"),
		body("pushToken", true),
		body(),
		body("name", "IdP"),
		body("poll", body("maxEvents", 5.0)),
		body("status", "paused"),
		body("jwksUri", "https://idp.example.test/keys"),
	} {
		_, err := update(input, owner)
		if known, ok := asIamError(err); !ok || known.Code != "INVALID_INPUT" {
			t.Fatalf("%s: %v", stringify(input), err)
		}
	}

	// A session past its recent sign-in may read but not change.
	f.advance(6 * 60_000)
	_, err = update(body("name", "Renamed"), owner)
	expectStatusCode(t, err, "RECENT_AUTH_REQUIRED")
	_, err = f.api().RotatePushToken(f.ctx, owner, Input[apitypes.SignalsRotatePushTokenInput](body("tenantId", f.tenantID, "sourceId", sourceID)))
	expectStatusCode(t, err, "RECENT_AUTH_REQUIRED")
	if sources := answer(f.api().ListSources(f.ctx, owner, Input[apitypes.SignalsListSourcesInput](body("tenantId", f.tenantID)))); len(sources.([]any)) != 20 {
		t.Fatalf("sources %d", len(sources.([]any)))
	}
	fresh := f.ownerSignIn(f.tenantID)

	// Rotating the push token: the old one stops working at once.
	push := func(secret string) *Response {
		headers := map[string]string{"content-type": "application/secevent+jwt"}
		if secret != "" {
			headers["authorization"] = "Bearer " + secret
		}
		return f.fetch(http.MethodPost, jsString(created.Get("pushUrl")), headers,
			f.securityEvent(stsSigner{key: key}, sigEvent(sigSSF+"verification", body("state", "x"), nil)))
	}
	sigStatus(t, push(pushToken), 202)
	rotated := sigOut(f.api().RotatePushToken(f.ctx, fresh, Input[apitypes.SignalsRotatePushTokenInput](body("tenantId", f.tenantID, "sourceId", sourceID))))
	newToken := jsString(rotated.Get("pushToken"))
	if newToken == pushToken || newToken == "" {
		t.Fatal("the push token did not change")
	}
	sigStatus(t, push(pushToken), 401)
	sigStatus(t, push(newToken), 202)

	// Disabled, a source's pushes answer 404 until it is enabled again.
	disabled, err := update(body("status", "disabled"), fresh)
	if err != nil {
		t.Fatal(err)
	}
	sigExpect(t, disabled, "status", "disabled")
	sigStatus(t, push(newToken), 404)
	enabled, err := update(body("status", "active", "name", "Renamed IdP", "audiences", items(sigAudience, "https://rp2.example.test"),
		"subjects", body("matchEmail", true), "actions", body("credential-compromise", "revoke-sessions")), fresh)
	if err != nil {
		t.Fatal(err)
	}
	sigExpect(t, enabled, "status", "active", "name", "Renamed IdP", "actions", body("credential-compromise", "revoke-sessions"), "updatedBy", f.ownerID)
	sigExpect(t, enabled.Get("subjects").(*core.Object), "matchEmail", true, "connectionIds", items())
	sigStatus(t, push(newToken), 202)
	updates := f.audit(f.tenantID, "signal:source-update")
	sigExpect(t, updates[len(updates)-1], "=metadata", body("changed", items("name", "audiences", "subjects", "actions", "status")))

	// Received events: paged, filtered, one at a time, not across organizations.
	page := sigOut(f.api().ListEvents(f.ctx, fresh, Input[apitypes.SignalsListEventsInput](body("tenantId", f.tenantID, "sourceId", sourceID,
		"eventType", "verification", "limit", 2.0))))
	events := sigObjects(page.Get("events"))
	if page.Get("total") != 3.0 || len(events) != 2 {
		t.Fatalf("page %s", stringify(page))
	}
	eventID := jsString(events[0].Get("id"))
	one, err := f.getEvent(fresh, f.tenantID, eventID)
	if err != nil {
		t.Fatal(err)
	}
	stsSame(t, one, events[0])
	_, err = f.getEvent(betaOwner, betaID, eventID)
	expectStatusCode(t, err, "NOT_FOUND")
	for _, input := range []*core.Object{body("status", "odd"), body("eventType", "made-up"), body("limit", 0.0), body("offset", -1.0)} {
		_, err := f.api().ListEvents(f.ctx, fresh, Input[apitypes.SignalsListEventsInput](body("tenantId", f.tenantID).Spread(input)))
		expectStatusCode(t, err, "INVALID_INPUT")
	}
	// Only unmatched and failed events can be reprocessed.
	_, err = f.api().Reprocess(f.ctx, fresh, Input[apitypes.SignalsReprocessInput](body("tenantId", f.tenantID, "eventId", eventID)))
	expectStatusCode(t, err, "INVALID_TRANSITION")

	// Over HTTP as well.
	over := f.post("http://localhost:3000", "signals/listSources", stringify(body("tenantId", f.tenantID)),
		map[string]string{"authorization": "Bearer " + fresh.Token})
	sigStatus(t, over, 200)
	data, _ := sigJSON(t, over).Get("data").([]any)
	if len(data) != 20 || strings.Contains(stringify(data), newToken) {
		t.Fatalf("data %d", len(data))
	}

	// Deleted: pushes answer 404; its events stay until the retention sweep.
	stsSame(t, sigOut(f.api().DeleteSource(f.ctx, fresh, Input[apitypes.SignalsDeleteSourceInput](body("tenantId", f.tenantID, "sourceId", sourceID)))),
		body("deleted", true))
	sigStatus(t, push(newToken), 404)
	if total := f.listEvents(f.ownerCred, body("sourceId", sourceID)).Get("total"); total != 3.0 {
		t.Fatalf("events after deletion %v", total)
	}
	for _, action := range []string{"signal:source-create", "signal:source-update", "signal:source-rotate", "signal:source-delete"} {
		if len(f.audit(f.tenantID, action)) == 0 {
			t.Fatalf("no %s audit", action)
		}
	}
}

func expectStatusCode(t *testing.T, err error, code string) {
	t.Helper()
	known, ok := asIamError(err)
	if !ok || known.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func TestSignalsServeACustomPushPath(t *testing.T) {
	path := "/ssf/push"
	f := newSignalsFixture(t, func(options *BetterIamOptions) { options.Signals = &SignalsOptions{PushPath: &path} })
	p := f.pushSource(nil)
	if p.pushURL != "http://localhost:3000/ssf/push/"+p.sourceID {
		t.Fatalf("push url %s", p.pushURL)
	}
	sigStatus(t, p.push(p.sign(sigEvent(sigSSF+"verification", nil, nil))), 202)
	moved := p.push(p.sign(sigEvent(sigSSF+"verification", nil, nil)), sigPushOptions{url: "http://localhost:3000/api/iam/signals/push/" + p.sourceID})
	if moved.Status == 202 {
		t.Fatal("the default push path still answers")
	}
	if f.listEvents(f.ownerCred, nil).Get("total") != 1.0 {
		t.Fatal("expected one event")
	}
}

func TestSignalsTurnUpstreamReportsIntoThreatDetections(t *testing.T) {
	f := newSignalsFixture(t, nil)
	p := f.pushSource(body("subjects", body("scimConnectionIds", items("okta-scim"))))
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	f.linkScim("okta-scim", aliceID, "00u-alice")
	aliceSubject := body("format", "iss_sub", "iss", sigIssuer, "sub", "00u-alice")
	if _, err := f.iam.DetectThreats(f.ctx, body("tenantId", f.tenantID)); err != nil {
		if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
			t.Skipf("threat detection is not ported yet: %v", err)
		}
		t.Fatal(err)
	}
	for _, signal := range []*core.Object{
		sigEvent(sigRISC+"credential-compromise", body("credential_type", "password"), aliceSubject),
		sigEvent(sigCAEP+"risk-level-change", body("current_level", "LOW"), aliceSubject),
		sigEvent(sigCAEP+"session-revoked", body("event_timestamp", f.seconds()), aliceSubject),
		sigEvent(sigCAEP+"risk-level-change", body("current_level", "MEDIUM"), aliceSubject),
	} {
		sigStatus(t, p.push(p.sign(signal)), 202)
	}
	if _, err := f.iam.DetectThreats(f.ctx, body("tenantId", f.tenantID)); err != nil {
		t.Fatal(err)
	}
	detections := sigOut(f.iam.API.Threats.ListDetections(f.ctx, f.ownerCred, Input[apitypes.ThreatsListDetectionsInput](
		body("tenantId", f.tenantID, "ruleId", "upstream-signal"))))
	rows := []string{}
	for _, entry := range sigObjects(detections.Get("detections")) {
		rows = append(rows, jsString(entry.Get("severity"))+","+jsString(entry.Get("identityId"))+","+jsString(member(entry.Get("metadata"), "eventType")))
	}
	sort.Strings(rows)
	if strings.Join(rows, "|") != "high,"+aliceID+",credential-compromise|medium,"+aliceID+",risk-level-change" {
		t.Fatalf("detections %v", rows)
	}
	risk := sigOut(f.iam.API.Threats.GetRisk(f.ctx, f.ownerCred, Input[apitypes.ThreatsGetRiskInput](body("tenantId", f.tenantID, "identityId", aliceID))))
	sigExpect(t, risk, "level", "high")
}

func TestSignalsBindASourceToOneOrganizationThroughTheTenantClaim(t *testing.T) {
	f := newSignalsFixture(t, nil)
	// A Better IAM transmitter signs every organization's events with one issuer and key.
	p := f.pushSource(body("tenantClaim", "org-acme"))
	verification := func(pairs ...any) string {
		return p.sign(sigEvent(sigSSF+"verification", nil, nil).Spread(core.NewObject(pairs...)))
	}
	sigStatus(t, p.push(verification("tenant_id", "org-acme")), 202)
	for _, claims := range [][]any{{"tenant_id", "org-other"}, {}, {"tenant_id", 42.0}} {
		refused := p.push(verification(claims...))
		sigStatus(t, refused, 400)
		if sigJSON(t, refused).Get("err") != "invalid_audience" {
			t.Fatalf("answer %s", refused.Body)
		}
	}
	if f.listEvents(f.ownerCred, nil).Get("total") != 1.0 {
		t.Fatal("expected one event")
	}
	owner := f.ownerSignIn(f.tenantID)
	if f.getSource(owner, f.tenantID, p.sourceID).Get("tenantClaim") != "org-acme" {
		t.Fatal("tenantClaim not shown")
	}
	// Clearing the binding accepts SETs without the claim again.
	cleared, err := f.updateSource(owner, body("tenantId", f.tenantID, "sourceId", p.sourceID, "tenantClaim", nil))
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Has("tenantClaim") {
		t.Fatal("tenantClaim still set")
	}
	sigStatus(t, p.push(verification()), 202)
}

// TestSignalsReceiverHelpers covers the private helpers the tests above reach only partly.
func TestSignalsReceiverHelpers(t *testing.T) {
	if signalEventKey("https://idp.example.test/", "j1") != signalEventKey("https://idp.example.test", "j1") {
		t.Fatal("the event key depends on a trailing slash")
	}
	if signalIssuerKey(strings.Repeat("a", 600)) != "issuer#sha256:"+Hash(strings.Repeat("a", 600)) {
		t.Fatal("long issuers are keyed by their hash")
	}
	claims := core.NewObject("big", strings.Repeat("y", 5000), "small", "ok", "__proto__", "x")
	stored := signalStoredClaims(claims)
	if stored.Get("_truncated") != true || stored.Get("small") != "ok" || utf16Len(jsString(stored.Get("big"))) != 256 || stored.Has("__proto__") {
		t.Fatalf("stored claims %s", stringify(stored))
	}
	if text, _ := signalLocalized(body("de", "Hallo")); text != "Hallo" {
		t.Fatal("a language map without English falls back to its first string")
	}
	if signalUpper("straße") != "STRASSE" {
		t.Fatalf("upper %s", signalUpper("straße"))
	}
}
