package saml

// Port of tests/saml-connections.test.ts (tenant-managed SAML connections) and tests/security-saml.test.ts (SAML
// response checks).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func idpMetadata(certificates []string, extra string) string {
	keys := ""
	for _, certificate := range certificates {
		keys += `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + bare(certificate) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
	}
	return `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.test"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + keys + extra + `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/logout"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.test/post"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/login"/></md:IDPSSODescriptor></md:EntityDescriptor>`
}

// managedResponse is a signed IdP response for a managed connection's ACS URL and SP entity ID ("" requestID: an
// unsolicited one).
func managedResponse(t *testing.T, requestID *string, acs, audience string, key keyPair) string {
	answers := ""
	if requestID != nil {
		answers = ` InResponseTo="` + *requestID + `"`
	}
	now := iso(nowMs())
	expires := iso(nowMs() + 120000)
	assertion := `<saml:Assertion xmlns:saml="` + assertionNS + `" ID="_` + randomUUID() + `" Version="2.0" IssueInstant="` + now + `"><saml:Issuer>https://idp.test</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">employee-42</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData` + answers + ` Recipient="` + acs + `" NotOnOrAfter="` + expires + `"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="` + iso(nowMs()-1000) + `" NotOnOrAfter="` + expires + `"><saml:AudienceRestriction><saml:Audience>` + audience + `</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="` + now + `" SessionIndex="session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>ada@acme.test</saml:AttributeValue></saml:Attribute><saml:Attribute Name="dept"><saml:AttributeValue>finance</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`
	document := `<samlp:Response xmlns:samlp="` + protocolNS + `" xmlns:saml="` + assertionNS + `" ID="_` + randomUUID() + `" Version="2.0" IssueInstant="` + now + `" Destination="` + acs + `"` + answers + `><saml:Issuer>https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` + sign(t, assertion, "Assertion", key) + `</samlp:Response>`
	return b64(sign(t, document, "Response", key))
}

type managedFixture struct {
	t         *testing.T
	store     core.IamStore
	service   *SamlService
	idp, next keyPair
	sp        keyPair
	completed []*core.Object
	denied    []string
}

var admin = core.CredentialInput{Token: "admin"}

func (f *managedFixture) principal(context.Context, core.CredentialInput) (*Principal, error) {
	return &Principal{Identity: core.NewObject("id", "admin-a", "tenantId", "a"),
		Session: core.NewObject("id", "session", "kind", "user", "authenticatedAt", float64(nowMs()))}, nil
}

func (f *managedFixture) complete(_ context.Context, input *core.Object) (any, error) {
	f.completed = append(f.completed, input)
	return core.NewObject("signedIn", input.Get("subject")), nil
}

func newManagedFixture(t *testing.T) *managedFixture {
	f := &managedFixture{t: t, store: newTestStore(t), idp: generate(t, "idp.test"), next: generate(t, "next.idp.test"), sp: generate(t, "iam.test")}
	insertTenants(t, f.store, "a", "b")
	f.service = must(CreateSamlService(SamlConfigOptions{
		Store: f.store,
		Connections: []SamlConnection{{ID: "static", TenantID: "a", EntryPoint: "https://idp.test/login", IdpIssuer: "https://idp.test",
			IdpCertificates: []string{f.idp.cert}, EntityID: "https://iam.test/static", CallbackURL: "https://iam.test/static/callback",
			PrivateKey: f.sp.private, PublicCertificate: f.sp.cert}},
		ServiceProvider: &SamlServiceProvider{BaseURL: "https://iam.test", PrivateKey: f.sp.private, PublicCertificate: f.sp.cert},
		Authenticate:    f.principal,
		Authorize: func(_ context.Context, credential core.CredentialInput, action string, _ core.ResourceRef) error {
			if credential.Token != "admin" {
				f.denied = append(f.denied, action)
				return core.NewIamError("ACCESS_DENIED", "Forbidden", 403)
			}
			return nil
		},
		CompleteAuthentication: f.complete,
	}))
	return f
}

func request(method, target string, body string, headers map[string]string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	return r
}

func form(values map[string]string) string {
	params := &searchParams{}
	for _, key := range []string{"SAMLResponse", "RelayState"} {
		if value, ok := values[key]; ok {
			params.Set(key, value)
		}
	}
	return params.String()
}

func TestSamlParsesIdpMetadataRedirectEndpointsAndSigningCertificatesOnly(t *testing.T) {
	f := newManagedFixture(t)
	parsed := must(ParseIdpMetadata(idpMetadata([]string{f.idp.cert, f.next.cert},
		`<md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>`+bare(f.sp.cert)+`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)))
	if parsed.EntityID != "https://idp.test" || parsed.EntryPoint != "https://idp.test/login" || parsed.SingleLogoutURL != "https://idp.test/logout" {
		t.Fatalf("parsed %+v", parsed)
	}
	if len(parsed.Certificates) != 2 || !strings.Contains(parsed.Certificates[0], "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("certificates %v", parsed.Certificates)
	}
	if _, err := ParseIdpMetadata(`<!DOCTYPE x [<!ENTITY a "b">]><x/>`); err == nil || !strings.Contains(err.Error(), "Unsafe") {
		t.Fatalf("expected Unsafe, got %v", err)
	}
	soap := regexp.MustCompile(`HTTP-Redirect" Location="https://idp.test/login`).ReplaceAllString(idpMetadata([]string{f.idp.cert}, ""), `SOAP" Location="https://idp.test/login`)
	if _, err := ParseIdpMetadata(soap); err == nil || !strings.Contains(err.Error(), "HTTP-Redirect") {
		t.Fatalf("expected HTTP-Redirect, got %v", err)
	}
	broken := strings.Replace(idpMetadata([]string{f.idp.cert}, ""), bare(f.idp.cert), "bm90IGEgY2VydA==", 1)
	if _, err := ParseIdpMetadata(broken); err == nil || !strings.Contains(err.Error(), "X.509") {
		t.Fatalf("expected X.509, got %v", err)
	}
}

func TestSamlCreatesAConnectionFromMetadataAndSignsMembersInThroughItsACS(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	created := must(f.service.CreateConnection(ctx, admin, core.NewObject("tenantId", "a", "id", "acme", "name", "Acme Okta",
		"metadataXml", idpMetadata([]string{f.idp.cert}, ""), "trustedEmailDomains", []any{"ACME.test"},
		"attributeMapping", core.NewObject("department", "dept"))))
	for key, want := range map[string]any{"id": "acme", "tenantId": "a", "name": "Acme Okta", "enabled": true,
		"entryPoint": "https://idp.test/login", "idpIssuer": "https://idp.test", "entityId": "https://iam.test/saml/acme/metadata",
		"acsUrl": "https://iam.test/saml/acme/acs", "loginUrl": "https://iam.test/saml/acme/login"} {
		if created.Get(key) != want {
			t.Fatalf("%s = %v, want %v", key, created.Get(key), want)
		}
	}
	if core.MustStringify(created.Get("trustedEmailDomains")) != `["acme.test"]` {
		t.Fatalf("domains %v", created.Get("trustedEmailDomains"))
	}
	certificate := created.Get("certificates").([]any)[0].(*core.Object)
	if certificate.Get("expired") != false || !regexp.MustCompile(`^[0-9A-F:]+$`).MatchString(certificate.Get("fingerprint256").(string)) {
		t.Fatalf("certificate %v", core.MustStringify(certificate))
	}
	if certificate.Get("subject") != "CN=idp.test" {
		t.Fatalf("subject %v", certificate.Get("subject"))
	}

	// SP metadata is served for the managed connection.
	served := f.service.Handle(request("GET", "https://iam.test/saml/acme/metadata", "", nil))
	if served == nil || served.Status != 200 || !strings.Contains(string(served.Body), "https://iam.test/saml/acme/acs") {
		t.Fatalf("metadata %+v", served)
	}
	if metadata := must(f.service.GetMetadata(ctx, "acme")); !strings.Contains(metadata, `WantAssertionsSigned="true"`) {
		t.Fatal("metadata lacks WantAssertionsSigned")
	}

	// Browser flow: login redirect sets the binding cookie, the IdP posts back to the ACS URL.
	login := f.service.Handle(request("GET", "https://iam.test/saml/acme/login", "", nil))
	if login == nil || login.Status != 302 {
		t.Fatalf("login %+v", login)
	}
	location := must(url.Parse(login.Header.Get("Location")))
	if location.Scheme+"://"+location.Host+location.Path != "https://idp.test/login" {
		t.Fatalf("location %v", location)
	}
	requestID, authnRequest := requestIDOf(t, location.String())
	if !strings.Contains(authnRequest, `AssertionConsumerServiceURL="https://iam.test/saml/acme/acs"`) {
		t.Fatalf("request %s", authnRequest)
	}
	cookie := strings.Split(login.Header.Get("Set-Cookie"), ";")[0]
	posted := f.service.Handle(request("POST", "https://iam.test/saml/acme/acs", form(map[string]string{
		"SAMLResponse": managedResponse(t, &requestID, str(created, "acsUrl"), str(created, "entityId"), f.idp),
		"RelayState":   location.Query().Get("RelayState"),
	}), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie}))
	if posted == nil || posted.Status != 200 || string(posted.Body) != `{"signedIn":"employee-42"}` {
		t.Fatalf("posted %d %s", posted.Status, posted.Body)
	}
	if len(f.completed) != 1 {
		t.Fatal("not completed")
	}
	input := f.completed[0]
	// Links are keyed by a random provider key of this very connection, never by its reusable ID.
	if !regexp.MustCompile(`^saml:acme:[A-Za-z0-9_-]{16}$`).MatchString(str(input, "providerId")) {
		t.Fatalf("providerId %v", input.Get("providerId"))
	}
	for key, want := range map[string]any{"tenantId": "a", "issuer": "https://idp.test", "subject": "employee-42",
		"email": "ada@acme.test", "emailVerified": true} {
		if input.Get(key) != want {
			t.Fatalf("%s = %v", key, input.Get(key))
		}
	}
	if core.MustStringify(input.Get("attributes")) != `{"department":"finance"}` {
		t.Fatalf("attributes %v", input.Get("attributes"))
	}
	if !auditActions(t, f.store, "a")["iam:saml:CreateConnection"] {
		t.Fatal("no create audit event")
	}
}

func auditActions(t *testing.T, store core.IamStore, tenantID string) map[string]bool {
	actions := map[string]bool{}
	for _, event := range must(store.Find(context.Background(), "audit", core.NewObject("tenantId", tenantID), nil)) {
		actions[str(event, "action")] = true
	}
	return actions
}

func TestSamlRollsOverCertificatesDisablesAndDeletesConnectionsWithinTheTenant(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	must(f.service.CreateConnection(ctx, admin, core.NewObject("tenantId", "a", "id", "acme", "name", "Acme",
		"entryPoint", "https://idp.test/login", "idpIssuer", "https://idp.test", "idpCertificates", []any{f.idp.cert})))
	begin := func() started {
		result := must(f.service.Begin(ctx, "acme", nil, nil))
		id, _ := requestIDOf(t, result.URL)
		return started{result, id}
	}
	acs, audience := "https://iam.test/saml/acme/acs", "https://iam.test/saml/acme/metadata"
	// An assertion signed by the next IdP key fails until the rollover lists it.
	state := begin()
	if _, err := f.service.Callback(ctx, "acme", CallbackInput{RelayState: state.RelayState, Binding: state.Binding,
		SamlResponse: managedResponse(t, &state.requestID, acs, audience, f.next)}); err == nil {
		t.Fatal("next key accepted before rollover")
	}
	rolled := must(f.service.UpdateConnection(ctx, admin, core.NewObject("tenantId", "a", "connectionId", "acme",
		"idpCertificates", []any{f.idp.cert, f.next.cert})))
	if len(rolled.Get("certificates").([]any)) != 2 {
		t.Fatal("rollover did not list both certificates")
	}
	state = begin()
	result := must(f.service.Callback(ctx, "acme", CallbackInput{RelayState: state.RelayState, Binding: state.Binding,
		SamlResponse: managedResponse(t, &state.requestID, acs, audience, f.next)}))
	if core.MustStringify(result) != `{"signedIn":"employee-42"}` {
		t.Fatalf("result %v", result)
	}

	// Disabled connections stop new sign-ins; listing still shows them.
	must(f.service.UpdateConnection(ctx, admin, core.NewObject("tenantId", "a", "connectionId", "acme", "enabled", false)))
	if _, err := f.service.Begin(ctx, "acme", nil, nil); statusOf(err) != 404 {
		t.Fatalf("begin on a disabled connection: %v", err)
	}
	if response := f.service.Handle(request("GET", "https://iam.test/saml/acme/login", "", nil)); response.Status != 404 {
		t.Fatalf("login status %d", response.Status)
	}
	listed := must(f.service.ListConnections(ctx, admin, "a"))
	if len(listed) != 1 || listed[0].Get("id") != "acme" || listed[0].Get("enabled") != false {
		t.Fatalf("listed %v", listed)
	}

	// Other tenants and callers without permission see nothing.
	if _, err := f.service.GetConnection(ctx, admin, "b", "acme"); statusOf(err) != 404 {
		t.Fatalf("other tenant: %v", err)
	}
	if _, err := f.service.UpdateConnection(ctx, core.CredentialInput{Token: "member"}, core.NewObject("tenantId", "a",
		"connectionId", "acme", "name", "Mine")); statusOf(err) != 403 {
		t.Fatalf("member update: %v", err)
	}
	if !contains(f.denied, "iam:saml:connections:update") {
		t.Fatal("update not denied")
	}

	if err := f.service.DeleteConnection(ctx, admin, "a", "acme"); err != nil {
		t.Fatal(err)
	}
	if listed := must(f.service.ListConnections(ctx, admin, "a")); len(listed) != 0 {
		t.Fatal("connection not deleted")
	}
	if _, err := f.service.GetMetadata(ctx, "acme"); statusOf(err) != 404 {
		t.Fatalf("metadata after delete: %v", err)
	}
	actions := auditActions(t, f.store, "a")
	for _, action := range []string{"iam:saml:CreateConnection", "iam:saml:UpdateConnection", "iam:saml:DeleteConnection"} {
		if !actions[action] {
			t.Fatalf("missing audit %s", action)
		}
	}
}

func TestSamlAcceptsIdpInitiatedSignInOnlyWhenEnabledOncePerAssertion(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	created := must(f.service.CreateConnection(ctx, admin, core.NewObject("tenantId", "a", "id", "portal", "name", "Portal",
		"metadataXml", idpMetadata([]string{f.idp.cert}, ""), "allowIdpInitiated", true)))
	if created.Get("allowIdpInitiated") != true {
		t.Fatal("allowIdpInitiated not set")
	}
	post := func(samlResponse, relayState string) *Response {
		values := map[string]string{"SAMLResponse": samlResponse}
		if relayState != "" {
			values["RelayState"] = relayState
		}
		return f.service.Handle(request("POST", "https://iam.test/saml/portal/acs", form(values),
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"}))
	}
	acs, entity := str(created, "acsUrl"), str(created, "entityId")
	unsolicited := managedResponse(t, nil, acs, entity, f.idp)
	accepted := post(unsolicited, "https://app.example/dashboard")
	if accepted.Status != 200 || string(accepted.Body) != `{"signedIn":"employee-42"}` {
		t.Fatalf("accepted %d %s", accepted.Status, accepted.Body)
	}
	// The same assertion cannot be replayed, and responses to requests still need their browser binding.
	if post(unsolicited, "").Status != 401 {
		t.Fatal("replay accepted")
	}
	forged := "_forged"
	if post(managedResponse(t, &forged, acs, entity, f.idp), "x").Status != 401 {
		t.Fatal("unbound solicited response accepted")
	}
	// Other audiences and signers are refused like SP-initiated responses.
	if post(managedResponse(t, nil, acs, "https://elsewhere.test", f.idp), "").Status != 401 {
		t.Fatal("other audience accepted")
	}
	if post(managedResponse(t, nil, acs, entity, f.next), "").Status != 401 {
		t.Fatal("other signer accepted")
	}
	if len(f.completed) != 1 {
		t.Fatalf("completed %d", len(f.completed))
	}

	// Turning it off refuses unsolicited responses again.
	must(f.service.UpdateConnection(ctx, admin, core.NewObject("tenantId", "a", "connectionId", "portal", "allowIdpInitiated", false)))
	if post(managedResponse(t, nil, acs, entity, f.idp), "").Status != 401 {
		t.Fatal("unsolicited accepted after turning it off")
	}
	if _, err := f.service.IdpInitiated(ctx, "portal", managedResponse(t, nil, acs, entity, f.idp)); codeOf(err) != "SAML_INVALID" {
		t.Fatalf("idpInitiated: %v", err)
	}
	if len(f.completed) != 1 {
		t.Fatal("completed after turning it off")
	}
}

func TestSamlValidatesConnectionInput(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	base := func(extra ...any) *core.Object {
		input := core.NewObject("tenantId", "a", "name", "Acme", "entryPoint", "https://idp.test/login",
			"idpIssuer", "https://idp.test", "idpCertificates", []any{f.idp.cert})
		for i := 0; i < len(extra); i += 2 {
			input.SetRaw(extra[i].(string), extra[i+1])
		}
		return input
	}
	must(f.service.CreateConnection(ctx, admin, base("id", "taken")))
	for _, c := range []struct {
		input *core.Object
		code  string
	}{
		{base("id", "taken"), "CONFLICT"},
		{base("id", "static"), "CONFLICT"},
		{base("id", "Not Valid"), "INVALID_INPUT"},
		{base("entryPoint", "http://idp.test/login"), "INVALID_INPUT"},
		{base("idpCertificates", []any{}), "INVALID_INPUT"},
		{base("idpCertificates", []any{"not a certificate"}), "INVALID_INPUT"},
		{base("trustedEmailDomains", []any{"*.acme.test"}), "INVALID_INPUT"},
		{base("attributeMapping", core.NewObject("bad name", "x")), "INVALID_INPUT"},
		{base("requireEncryptedAssertions", true), "INVALID_INPUT"},
		{base("name", "", "metadataXml", core.Undefined), "INVALID_INPUT"},
		{base("metadataXml", "<!DOCTYPE x><x/>"), "INVALID_INPUT"},
	} {
		if _, err := f.service.CreateConnection(ctx, admin, c.input); codeOf(err) != c.code {
			t.Fatalf("%s: got %v, want %s", core.MustStringify(c.input), err, c.code)
		}
	}
	// Configured connections keep their fixed URLs and are not managed through the API.
	if _, err := f.service.GetConnection(ctx, admin, "a", "static"); statusOf(err) != 404 {
		t.Fatalf("static: %v", err)
	}
	if metadata := must(f.service.Metadata("static")); !strings.Contains(metadata, "https://iam.test/static/callback") {
		t.Fatal("static metadata lacks the callback")
	}
	_, err := CreateSamlService(SamlConfigOptions{Store: f.store,
		ServiceProvider:        &SamlServiceProvider{BaseURL: "http://iam.test", PrivateKey: "x", PublicCertificate: "y"},
		CompleteAuthentication: f.complete})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS error, got %v", err)
	}
}

func TestSamlPassesTrustScimProvisionedGatedAsATrustChange(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	var trustChanges []string
	trusting := must(CreateSamlService(SamlConfigOptions{
		Store:           f.store,
		ServiceProvider: &SamlServiceProvider{BaseURL: "https://iam.test", PrivateKey: f.sp.private, PublicCertificate: f.sp.cert},
		Authenticate:    f.principal,
		Authorize:       func(context.Context, core.CredentialInput, string, core.ResourceRef) error { return nil },
		AssertTrustChange: func(_ context.Context, _ core.CredentialInput, _, providerID string) error {
			trustChanges = append(trustChanges, providerID)
			return nil
		},
		CompleteAuthentication: f.complete,
	}))
	created := must(trusting.CreateConnection(ctx, admin, core.NewObject("tenantId", "a", "id", "okta", "name", "Okta",
		"metadataXml", idpMetadata([]string{f.idp.cert}, ""), "trustedEmailDomains", []any{"acme.test"})))
	if created.Get("trustScimProvisioned") != false || !strings.HasPrefix(str(created, "providerId"), "saml:okta:") {
		t.Fatalf("created %v", core.MustStringify(created))
	}
	if len(trustChanges) != 1 || trustChanges[0] != str(created, "providerId") {
		t.Fatalf("trust changes %v", trustChanges)
	}
	// Trusting SCIM-provisioned accounts widens what the connection can sign in to; narrowing does not.
	scim := must(trusting.UpdateConnection(ctx, admin, core.NewObject("tenantId", "a", "connectionId", "okta",
		"trustScimProvisioned", []any{"scim-1", "scim-1"})))
	if core.MustStringify(scim.Get("trustScimProvisioned")) != `["scim-1"]` || len(trustChanges) != 2 {
		t.Fatalf("scim %v, changes %v", scim.Get("trustScimProvisioned"), trustChanges)
	}
	must(trusting.UpdateConnection(ctx, admin, core.NewObject("tenantId", "a", "connectionId", "okta", "trustScimProvisioned", true)))
	if len(trustChanges) != 3 {
		t.Fatal("true is a trust change")
	}
	must(trusting.UpdateConnection(ctx, admin, core.NewObject("tenantId", "a", "connectionId", "okta", "trustScimProvisioned", []any{"scim-1"})))
	if len(trustChanges) != 3 {
		t.Fatal("narrowing is not a trust change")
	}
	if _, err := trusting.UpdateConnection(ctx, admin, core.NewObject("tenantId", "a", "connectionId", "okta", "trustScimProvisioned", "yes")); codeOf(err) != "INVALID_INPUT" {
		t.Fatalf("yes: %v", err)
	}

	login := trusting.Handle(request("GET", "https://iam.test/saml/okta/login", "", nil))
	location := must(url.Parse(login.Header.Get("Location")))
	requestID, _ := requestIDOf(t, location.String())
	trusting.Handle(request("POST", "https://iam.test/saml/okta/acs", form(map[string]string{
		"SAMLResponse": managedResponse(t, &requestID, str(created, "acsUrl"), str(created, "entityId"), f.idp),
		"RelayState":   location.Query().Get("RelayState"),
	}), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Cookie": strings.Split(login.Header.Get("Set-Cookie"), ";")[0]}))
	last := f.completed[len(f.completed)-1]
	if last.Get("providerId") != created.Get("providerId") || last.Get("emailVerified") != true ||
		core.MustStringify(last.Get("trustScimProvisioned")) != `["scim-1"]` {
		t.Fatalf("completed %v", core.MustStringify(last))
	}
	_, err := CreateSamlService(SamlConfigOptions{Store: f.store, Connections: []SamlConnection{{ID: "bad", TenantID: "a",
		EntryPoint: "https://idp.test/login", IdpIssuer: "https://idp.test", IdpCertificates: []string{f.idp.cert},
		EntityID: "https://iam.test/bad", CallbackURL: "https://iam.test/bad/callback", PrivateKey: f.sp.private,
		PublicCertificate: f.sp.cert, TrustScimProvisioned: []any{42.0}}}, CompleteAuthentication: f.complete})
	if err == nil || !strings.Contains(err.Error(), "trustScimProvisioned") {
		t.Fatalf("expected trustScimProvisioned error, got %v", err)
	}
}

func TestSamlAsksTheHostToRedirectAfterSignIn(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	var outcome any = core.NewObject("token", "session-token", "session", core.NewObject("expiresAt", float64(nowMs()+60_000)))
	redirecting := must(CreateSamlService(SamlConfigOptions{
		Store:           f.store,
		ServiceProvider: &SamlServiceProvider{BaseURL: "https://iam.test", PrivateKey: f.sp.private, PublicCertificate: f.sp.cert},
		Authenticate: func(context.Context, core.CredentialInput) (*Principal, error) {
			return nil, core.NewIamError("UNAUTHENTICATED", "No", 401)
		},
		Authorize:      func(context.Context, core.CredentialInput, string, core.ResourceRef) error { return nil },
		TrustedOrigins: []string{"https://app.example.test"},
		AfterSignIn:    ptr("https://app.example.test/home"),
		MfaURL:         ptr("/mfa"),
		ErrorURL:       ptr("/login?sso=1"),
		CompleteAuthentication: func(_ context.Context, input *core.Object) (any, error) {
			f.completed = append(f.completed, input)
			if err, ok := outcome.(error); ok {
				return nil, err
			}
			return outcome, nil
		},
	}))
	created := must(f.service.CreateConnection(ctx, admin, core.NewObject("tenantId", "a", "id", "acme", "name", "Acme",
		"metadataXml", idpMetadata([]string{f.idp.cert}, ""))))
	signIn := func(query string) *Response {
		login := redirecting.Handle(request("GET", "https://iam.test/saml/acme/login"+query, "", nil))
		if login.Status != 302 {
			t.Fatalf("login %d %s", login.Status, login.Body)
		}
		location := must(url.Parse(login.Header.Get("Location")))
		requestID, _ := requestIDOf(t, location.String())
		return redirecting.Handle(request("POST", "https://iam.test/saml/acme/acs", form(map[string]string{
			"SAMLResponse": managedResponse(t, &requestID, str(created, "acsUrl"), str(created, "entityId"), f.idp),
			"RelayState":   location.Query().Get("RelayState"),
		}), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Cookie": strings.Split(login.Header.Get("Set-Cookie"), ";")[0]}))
	}
	// A session: the JSON stays (the host turns it into a 303 with the cookie), the hint names the page.
	plain := signIn("")
	if plain.Status != 200 || plain.Header.Get(redirectHeader) != "https://app.example.test/home" || !strings.Contains(string(plain.Body), `"token":"session-token"`) {
		t.Fatalf("plain %d %v %s", plain.Status, plain.Header, plain.Body)
	}
	if back := signIn("?returnTo=%2Finvoices%3Fpage%3D2"); back.Header.Get(redirectHeader) != "/invoices?page=2" {
		t.Fatalf("returnTo hint %q", back.Header.Get(redirectHeader))
	}

	// MFA: the challenge goes in the fragment, to the MFA page, with returnTo.
	outcome = core.NewObject("mfaRequired", true, "challenge", "challenge-1", "enrollmentRequired", false)
	target := signIn("?returnTo=/reports").Header.Get(redirectHeader)
	if !strings.HasPrefix(target, "/mfa#") {
		t.Fatalf("mfa target %q", target)
	}
	fragment := parseSearchParams(strings.SplitN(target, "#", 2)[1])
	if core.MustStringify(pairsObject(fragment)) != `{"tenantId":"a","mfaRequired":"true","challenge":"challenge-1","enrollmentRequired":"false","returnTo":"/reports"}` {
		t.Fatalf("fragment %v", fragment.pairs)
	}

	// Failures go to the error page with the host's code; the JSON body stays generic.
	outcome = core.NewIamError("ACCOUNT_LINK_REQUIRED", "Link first", 409)
	failed := signIn("")
	if failed.Status != 401 || failed.Header.Get(redirectHeader) != "/login?sso=1&error=ACCOUNT_LINK_REQUIRED" || string(failed.Body) != `{"error":"SAML_INVALID"}` {
		t.Fatalf("failed %d %v %s", failed.Status, failed.Header, failed.Body)
	}

	// returnTo must be a path on this site.
	for _, bad := range []string{"https://evil.test/", "//evil.test", "/\\evil.test", "relative"} {
		response := redirecting.Handle(request("GET", "https://iam.test/saml/acme/login?returnTo="+url.QueryEscape(bad), "", nil))
		if response.Status != 400 {
			t.Fatalf("%s: status %d", bad, response.Status)
		}
	}
	// Without afterSignIn nothing changes: no hint.
	if login := f.service.Handle(request("GET", "https://iam.test/saml/acme/login?returnTo=/x", "", nil)); login.Status != 302 {
		t.Fatalf("plain login %d", login.Status)
	}

	options := func() SamlConfigOptions {
		return SamlConfigOptions{Store: f.store, CompleteAuthentication: f.complete,
			ServiceProvider: &SamlServiceProvider{BaseURL: "https://iam.test", PrivateKey: f.sp.private, PublicCertificate: f.sp.cert}}
	}
	for _, c := range []struct {
		mutate func(*SamlConfigOptions)
		want   string
	}{
		{func(o *SamlConfigOptions) { o.AfterSignIn = ptr("https://evil.test/") }, "afterSignIn"},
		{func(o *SamlConfigOptions) { o.AfterSignIn = ptr("//evil.test/") }, "afterSignIn"},
		{func(o *SamlConfigOptions) { o.MfaURL = ptr("/mfa") }, "need afterSignIn"},
	} {
		o := options()
		c.mutate(&o)
		if _, err := CreateSamlService(o); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("expected %q, got %v", c.want, err)
		}
	}
	o := options()
	o.AfterSignIn = ptr("https://iam.test/welcome")
	if _, err := CreateSamlService(o); err != nil {
		t.Fatal(err)
	}
}

func pairsObject(params *searchParams) *core.Object {
	object := core.NewObject()
	for _, pair := range params.pairs {
		object.Set(pair[0], pair[1])
	}
	return object
}

// --- tests/security-saml.test.ts ------------------------------------------------------------------------------------

type responseOptions struct {
	requestID       *string
	acs, audience   string
	issuedAgoMs     int64
	noConditionTime bool
	injectEncrypted bool
}

func securityResponse(t *testing.T, key keyPair, options responseOptions) string {
	answers := ""
	if options.requestID != nil {
		answers = ` InResponseTo="` + *options.requestID + `"`
	}
	issued := nowMs() - options.issuedAgoMs
	instant := iso(issued)
	expires := iso(issued + 120000)
	conditions := `<saml:Conditions NotBefore="` + iso(issued-1000) + `" NotOnOrAfter="` + expires + `">`
	if options.noConditionTime {
		conditions = "<saml:Conditions>"
	}
	assertion := `<saml:Assertion xmlns:saml="` + assertionNS + `" ID="_` + randomUUID() + `" Version="2.0" IssueInstant="` + instant + `"><saml:Issuer>https://idp.test</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">employee-42</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData` + answers + ` Recipient="` + options.acs + `" NotOnOrAfter="` + expires + `"/></saml:SubjectConfirmation></saml:Subject>` + conditions + `<saml:AudienceRestriction><saml:Audience>` + options.audience + `</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="` + instant + `" SessionIndex="s"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>`
	document := `<samlp:Response xmlns:samlp="` + protocolNS + `" xmlns:saml="` + assertionNS + `" ID="_` + randomUUID() + `" Version="2.0" IssueInstant="` + instant + `" Destination="` + options.acs + `"` + answers + `><saml:Issuer>https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` + sign(t, assertion, "Assertion", key) + `</samlp:Response>`
	signed := sign(t, document, "Response", key)
	if options.injectEncrypted {
		// The Response signature is the first </Signature>; the enveloped transform excludes its contents.
		signed = strings.Replace(signed, "</Signature>", `<Object><saml:EncryptedAssertion xmlns:saml="`+assertionNS+`"/></Object></Signature>`, 1)
	}
	return b64(signed)
}

func newSecurityFixture(t *testing.T, clock *atomic.Int64) (*managedFixture, *SamlService) {
	f := &managedFixture{t: t, store: newTestStore(t), idp: generate(t, "idp.test"), sp: generate(t, "iam.test")}
	insertTenants(t, f.store, "a")
	service := must(CreateSamlService(SamlConfigOptions{
		Store: f.store,
		ServiceProvider: &SamlServiceProvider{BaseURL: "https://iam.test", PrivateKey: f.sp.private, PublicCertificate: f.sp.cert,
			DecryptionPrivateKey: f.sp.private, DecryptionCertificate: f.sp.cert},
		Authenticate: f.principal,
		Authorize: func(_ context.Context, credential core.CredentialInput, _ string, _ core.ResourceRef) error {
			if credential.Token != "admin" {
				return core.NewIamError("ACCESS_DENIED", "no", 403)
			}
			return nil
		},
		CompleteAuthentication: f.complete,
		Now:                    func() int64 { return clock.Load() },
	}))
	return f, service
}

func TestSamlAcceptsAnIdpInitiatedAssertionWithoutConditionTimesOnlyWhileFreshAndOnce(t *testing.T) {
	clock := &atomic.Int64{}
	clock.Store(nowMs())
	f, service := newSecurityFixture(t, clock)
	ctx := context.Background()
	connection := must(service.CreateConnection(ctx, admin, core.NewObject("tenantId", "a", "id", "portal", "name", "Portal",
		"metadataXml", idpMetadata([]string{f.idp.cert}, ""), "allowIdpInitiated", true)))
	post := func(samlResponse string) int {
		return service.Handle(request("POST", "https://iam.test/saml/portal/acs", form(map[string]string{"SAMLResponse": samlResponse}),
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"})).Status
	}
	timeless := responseOptions{acs: str(connection, "acsUrl"), audience: str(connection, "entityId"), noConditionTime: true}
	// A day-old one is refused outright.
	old := timeless
	old.issuedAgoMs = 86400000
	if post(securityResponse(t, f.idp, old)) != 401 {
		t.Fatal("day-old assertion accepted")
	}
	// A fresh one works once; replaying it fails now, after the single-use record lapses, and a month later.
	fresh := securityResponse(t, f.idp, timeless)
	if status := post(fresh); status != 200 {
		t.Fatalf("fresh assertion: %d", status)
	}
	if post(fresh) != 401 {
		t.Fatal("replay accepted")
	}
	clock.Add(11 * 60_000)
	if post(fresh) != 401 {
		t.Fatal("replay accepted after the single-use record lapsed")
	}
	clock.Add(30 * 86400_000)
	if post(fresh) != 401 {
		t.Fatal("replay accepted a month later")
	}
	if len(f.completed) != 1 {
		t.Fatalf("completed %d", len(f.completed))
	}
}

func TestSamlIsNotFooledByAnEmptyEncryptedAssertionHiddenInTheSignature(t *testing.T) {
	clock := &atomic.Int64{}
	clock.Store(nowMs())
	f, service := newSecurityFixture(t, clock)
	ctx := context.Background()
	connection := must(service.CreateConnection(ctx, admin, core.NewObject("tenantId", "a", "id", "enc", "name", "Enc",
		"metadataXml", idpMetadata([]string{f.idp.cert}, ""), "requireEncryptedAssertions", true)))
	for _, inject := range []bool{false, true} {
		state := must(service.Begin(ctx, "enc", nil, nil))
		requestID, _ := requestIDOf(t, state.URL)
		_, err := service.Callback(ctx, "enc", CallbackInput{RelayState: state.RelayState, Binding: state.Binding,
			SamlResponse: securityResponse(t, f.idp, responseOptions{requestID: &requestID, acs: str(connection, "acsUrl"),
				audience: str(connection, "entityId"), injectEncrypted: inject})})
		if err == nil || !strings.Contains(err.Error(), "encrypted assertion is required") {
			t.Fatalf("inject=%v: %v", inject, err)
		}
	}
	if len(f.completed) != 0 {
		t.Fatal("completed")
	}
}
