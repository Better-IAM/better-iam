package saml

// Port of tests/saml.test.ts: SAML SP security and shared replay state.

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const (
	assertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	protocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
)

type responseChanges struct{ issuer, audience, destination, expires string }

func makeResponse(t *testing.T, key keyPair, requestID string, changes responseChanges) string {
	now := iso(nowMs())
	expires := changes.expires
	if expires == "" {
		expires = iso(nowMs() + 120000)
	}
	issuer := changes.issuer
	if issuer == "" {
		issuer = "https://idp.test"
	}
	audience := changes.audience
	if audience == "" {
		audience = "https://iam.test/sp"
	}
	destination := changes.destination
	if destination == "" {
		destination = "https://iam.test/saml/callback"
	}
	assertion := `<saml:Assertion xmlns:saml="` + assertionNS + `" ID="_` + randomUUID() + `" Version="2.0" IssueInstant="` + now + `"><saml:Issuer>` + issuer + `</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">stable-user-subject</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="` + requestID + `" Recipient="https://iam.test/saml/callback" NotOnOrAfter="` + expires + `"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="` + iso(nowMs()-1000) + `" NotOnOrAfter="` + expires + `"><saml:AudienceRestriction><saml:Audience>` + audience + `</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="` + now + `" SessionIndex="session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>same@example.test</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`
	signedAssertion := sign(t, assertion, "Assertion", key)
	response := `<samlp:Response xmlns:samlp="` + protocolNS + `" xmlns:saml="` + assertionNS + `" ID="_` + randomUUID() + `" Version="2.0" IssueInstant="` + now + `" Destination="` + destination + `" InResponseTo="` + requestID + `"><saml:Issuer>https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` + signedAssertion + `</samlp:Response>`
	return sign(t, response, "Response", key)
}

type spFixture struct {
	t         *testing.T
	store     core.IamStore
	service   *SamlService
	keys      keyPair
	mu        sync.Mutex
	completed []*core.Object
}

func (f *spFixture) complete(ctx context.Context, input *core.Object) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.completed = append(f.completed, input)
	return core.NewObject("authenticated", true), nil
}

func newSPFixture(t *testing.T) *spFixture {
	f := &spFixture{t: t, store: newTestStore(t), keys: generate(t, "test.idp")}
	insertTenants(t, f.store, "a")
	f.service = must(CreateSamlService(SamlConfigOptions{
		Store: f.store,
		Connections: []SamlConnection{{
			ID: "enterprise", TenantID: "a", EntryPoint: "https://idp.test/login", IdpIssuer: "https://idp.test",
			IdpCertificates: []string{f.keys.cert}, EntityID: "https://iam.test/sp", CallbackURL: "https://iam.test/saml/callback",
			PrivateKey: f.keys.private, PublicCertificate: f.keys.cert,
			MapAttributes: func(profile *core.Object) *core.Object {
				if email, ok := profile.Get("email").(string); ok {
					return core.NewObject("mail", email)
				}
				return nil
			},
		}},
		CompleteAuthentication: f.complete,
	}))
	return f
}

type started struct {
	*BeginResult
	requestID string
}

func (f *spFixture) begin(id string) started {
	f.t.Helper()
	result := must(f.service.Begin(context.Background(), id, nil, nil))
	requestID, _ := requestIDOf(f.t, result.URL)
	return started{result, requestID}
}

func TestSamlValidatesRealSignedResponsesAndRejectsConcurrentReplay(t *testing.T) {
	f := newSPFixture(t)
	state := f.begin("enterprise")
	input := CallbackInput{RelayState: state.RelayState, Binding: state.Binding,
		SamlResponse: b64(makeResponse(t, f.keys, state.requestID, responseChanges{}))}
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = f.service.Callback(context.Background(), "enterprise", input)
		}(i)
	}
	wg.Wait()
	succeeded := 0
	for _, err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("expected one success, got %d (%v)", succeeded, results)
	}
	if len(f.completed) != 1 {
		t.Fatalf("completed %d", len(f.completed))
	}
	got := core.MustStringify(f.completed[0])
	want := `{"tenantId":"a","providerId":"enterprise","issuer":"https://idp.test","subject":"stable-user-subject","email":"same@example.test","emailVerified":false,"attributes":{"mail":"same@example.test"}}`
	if got != want {
		t.Fatalf("completed %s", got)
	}
	if !f.completed[0].Has("name") || !core.IsUndefined(f.completed[0].Get("name")) {
		t.Fatal("name should be present and undefined")
	}
	for _, collection := range []string{"samlRequests", "samlRelays"} {
		if records := must(f.store.Find(context.Background(), collection, nil, nil)); len(records) != 0 {
			t.Fatalf("%s left %d records", collection, len(records))
		}
	}
}

func TestSamlRequiresBrowserBindingAndRejectsForgedOrModifiedAssertions(t *testing.T) {
	f := newSPFixture(t)
	state := f.begin("enterprise")
	xml := makeResponse(t, f.keys, state.requestID, responseChanges{})
	input := CallbackInput{RelayState: state.RelayState, Binding: state.Binding, SamlResponse: b64(xml)}
	forged := input
	forged.Binding = "forged"
	if _, err := f.service.Callback(context.Background(), "enterprise", forged); err == nil {
		t.Fatal("forged binding accepted")
	}
	modified := input
	modified.SamlResponse = b64(strings.Replace(xml, "same@example.test", "attacker@example.test", 1))
	if _, err := f.service.Callback(context.Background(), "enterprise", modified); err == nil {
		t.Fatal("modified assertion accepted")
	}
	if len(f.completed) != 0 {
		t.Fatal("completed a forged sign-in")
	}
	result := must(f.service.Callback(context.Background(), "enterprise", input))
	if core.MustStringify(result) != `{"authenticated":true}` {
		t.Fatalf("result %v", result)
	}
}

func TestSamlRejectsWrongDestinationIssuerAudienceAndExpiredAssertion(t *testing.T) {
	f := newSPFixture(t)
	for _, change := range []responseChanges{
		{destination: "https://evil.test/callback"},
		{issuer: "https://evil.test"},
		{audience: "https://another-sp.test"},
		{expires: iso(nowMs() - 300000)},
	} {
		state := f.begin("enterprise")
		_, err := f.service.Callback(context.Background(), "enterprise", CallbackInput{RelayState: state.RelayState,
			Binding: state.Binding, SamlResponse: b64(makeResponse(t, f.keys, state.requestID, change))})
		if err == nil {
			t.Fatalf("accepted %+v", change)
		}
	}
	if len(f.completed) != 0 {
		t.Fatal("completed")
	}
}

func TestSamlDoesNotAcceptUnsolicitedAndScopesCacheToTheConnection(t *testing.T) {
	f := newSPFixture(t)
	if _, err := f.service.Callback(context.Background(), "enterprise", CallbackInput{RelayState: "unsolicited", Binding: "unsolicited",
		SamlResponse: b64(makeResponse(t, f.keys, "_unsolicited", responseChanges{}))}); err == nil {
		t.Fatal("unsolicited accepted")
	}
	ctx := context.Background()
	a := CreateSamlCache(f.store, "a", "connection-one", "")
	b := CreateSamlCache(f.store, "a", "connection-two", "")
	if err := a.SaveAsync(ctx, "_request", "now"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := b.GetAsync(ctx, "_request"); ok {
		t.Fatal("cache leaked across connections")
	}
	if value, ok, _ := a.GetAsync(ctx, "_request"); !ok || value != "now" {
		t.Fatalf("got %q %v", value, ok)
	}
	if _, _, err := a.RemoveAsync(ctx, "_request"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := a.GetAsync(ctx, "_request"); ok {
		t.Fatal("removed value still present")
	}
}

func TestSamlDecryptsEncryptedSignedAssertionsAndSupportsCertificateRollover(t *testing.T) {
	f := newSPFixture(t)
	old := generate(t, "old.idp")
	f.service = must(CreateSamlService(SamlConfigOptions{
		Store: f.store,
		Connections: []SamlConnection{{
			ID: "enterprise", TenantID: "a", EntryPoint: "https://idp.test/login", IdpIssuer: "https://idp.test",
			IdpCertificates: []string{old.cert, f.keys.cert}, EntityID: "https://iam.test/sp", CallbackURL: "https://iam.test/saml/callback",
			PrivateKey: f.keys.private, PublicCertificate: f.keys.cert, DecryptionPrivateKey: f.keys.private,
			DecryptionCertificate: f.keys.cert, RequireEncryptedAssertions: true,
		}},
		CompleteAuthentication: f.complete,
	}))
	state := f.begin("enterprise")
	doc := must(ParseXML(makeResponse(t, f.keys, state.requestID, responseChanges{})))
	root := doc.DocumentElement()
	assertion := root.ElementsByTagNameNS(assertionNS, "Assertion")[0]
	encrypted := encryptElement(t, assertion.String(), f.keys)
	wrapper := must(ParseXML(`<saml:EncryptedAssertion xmlns:saml="` + assertionNS + `">` + encrypted + `</saml:EncryptedAssertion>`))
	root.InsertBefore(wrapper.DocumentElement(), assertion)
	root.RemoveChild(assertion)
	for _, child := range root.ChildElements(isLocal("Signature")) {
		root.RemoveChild(child)
	}
	xml := sign(t, root.String(), "Response", f.keys)
	result := must(f.service.Callback(context.Background(), "enterprise", CallbackInput{RelayState: state.RelayState,
		Binding: state.Binding, SamlResponse: b64(xml)}))
	if core.MustStringify(result) != `{"authenticated":true}` {
		t.Fatalf("result %v", result)
	}
	if len(f.completed) != 1 {
		t.Fatal("not completed")
	}
}

func TestSamlGeneratesSignedMetadataAndRejectsXMLEntities(t *testing.T) {
	f := newSPFixture(t)
	metadata := must(f.service.Metadata("enterprise"))
	for _, want := range []string{"Signature", "https://iam.test/saml/callback", `WantAssertionsSigned="true"`} {
		if !strings.Contains(metadata, want) {
			t.Fatalf("metadata lacks %s: %s", want, metadata)
		}
	}
	request := "_request"
	if err := ValidateSamlEnvelope(`<!DOCTYPE a [<!ENTITY x SYSTEM "file:///secrets">]><a/>`, "https://iam.test/saml/callback", &request, false); err == nil {
		t.Fatal("entities accepted")
	}
	err := ValidateSamlEnvelope(makeResponse(t, f.keys, "_request", responseChanges{}), "https://iam.test/saml/callback", &request, true)
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("expected the encryption requirement, got %v", err)
	}
	// The signed metadata verifies with the SP certificate.
	doc := must(ParseXML(metadata))
	verified, err := getVerifiedXml(metadata, doc.DocumentElement(), []string{f.keys.cert})
	if err != nil || verified == "" {
		t.Fatalf("metadata signature does not verify: %v", err)
	}
}
