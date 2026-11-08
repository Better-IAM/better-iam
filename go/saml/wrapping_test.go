package saml

// Signature-wrapping and comment-injection defenses: what the TypeScript package gets from node-saml and xml-crypto
// (exactly one enveloped signature per signed node, a unique referenced ID that is the signature's parent, the
// identity read only from the canonical signed XML) must hold in the port.

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const (
	wrapACS      = "https://iam.test/saml/acme/acs"
	wrapAudience = "https://iam.test/saml/acme/metadata"
)

func wrapAssertion(id, nameID, answers string) string {
	now := iso(nowMs())
	later := iso(nowMs() + 120000)
	return `<saml:Assertion xmlns:saml="` + assertionNS + `" ID="` + id + `" Version="2.0" IssueInstant="` + now + `"><saml:Issuer>https://idp.test</saml:Issuer><saml:Subject><saml:NameID>` + nameID + `</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData` + answers + ` Recipient="` + wrapACS + `" NotOnOrAfter="` + later + `"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="` + iso(nowMs()-1000) + `" NotOnOrAfter="` + later + `"><saml:AudienceRestriction><saml:Audience>` + wrapAudience + `</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>`
}

func wrapResponse(id, inner string) string {
	return `<samlp:Response xmlns:samlp="` + protocolNS + `" xmlns:saml="` + assertionNS + `" ID="` + id + `" Version="2.0" IssueInstant="` + iso(nowMs()) + `" Destination="` + wrapACS + `" InResponseTo="_fixture"><saml:Issuer>https://idp.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` + inner + `</samlp:Response>`
}

func validator(key keyPair) *nodeSaml {
	return &nodeSaml{options: samlOptions{
		entryPoint: "https://idp.test/login", issuer: wrapAudience, idpIssuer: "https://idp.test", callbackURL: wrapACS,
		audience: wrapAudience, idpCert: []string{key.cert}, privateKey: key.private, publicCert: key.cert,
		validateAlways: true, cache: &memoryCache{saved: map[string]string{"_fixture": isoString(nowMs())}},
		generateUniqueID: func() string { return "_x" }, now: nowMs,
	}}
}

func validate(t *testing.T, key keyPair, xml string) (*core.Object, error) {
	t.Helper()
	request := "_fixture"
	if err := ValidateSamlEnvelope(xml, wrapACS, &request, false); err != nil {
		return nil, err
	}
	result, err := validator(key).validatePostResponse(context.Background(), b64(xml))
	if err != nil {
		return nil, err
	}
	return result.profile, nil
}

func signedPair(t *testing.T, key keyPair, nameID string) string {
	assertion := sign(t, wrapAssertion("_good", nameID, ` InResponseTo="_fixture"`), "Assertion", key)
	return sign(t, wrapResponse("_response", assertion), "Response", key)
}

func TestSamlReadsTheIdentityFromTheCanonicalSignedXMLSoCommentsCannotTruncateIt(t *testing.T) {
	key := generate(t, "idp.test")
	// The IdP signed `admin@x.test<!---->.evil.test`: canonicalization drops the comment, so the subject is the whole
	// text, never the part before the comment.
	profile, err := validate(t, key, signedPair(t, key, "admin@x.test<!---->.evil.test"))
	if err != nil {
		t.Fatal(err)
	}
	if profile.Get("nameID") != "admin@x.test.evil.test" {
		t.Fatalf("nameID %v", profile.Get("nameID"))
	}
	// Inserting a comment after signing changes nothing that was signed, and still yields the signed text.
	xml := strings.Replace(signedPair(t, key, "admin@x.test.evil.test"), "admin@x.test.evil.test", "admin@x.test<!-- injected -->.evil.test", 1)
	profile, err = validate(t, key, xml)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Get("nameID") != "admin@x.test.evil.test" {
		t.Fatalf("nameID after comment injection %v", profile.Get("nameID"))
	}
}

func TestSamlRefusesSignatureWrapping(t *testing.T) {
	key := generate(t, "idp.test")
	attacker := generate(t, "attacker.test")
	good := signedPair(t, key, "employee-1")
	signedAssertion := sign(t, wrapAssertion("_good", "employee-1", ` InResponseTo="_fixture"`), "Assertion", key)
	forged := wrapAssertion("_forged", "admin", ` InResponseTo="_fixture"`)
	cases := map[string]string{
		// A second, unsigned assertion next to the signed one.
		"extra assertion": strings.Replace(good, "<samlp:Status>", forged+"<samlp:Status>", 1),
		// The signed assertion hidden in the Response signature's Object, a forged one in its place.
		"assertion moved into the signature": sign(t, wrapResponse("_response", forged), "Response", key),
		// The forged assertion carries the signed one's ID.
		"duplicate ID": strings.Replace(good, "<samlp:Status>", strings.Replace(forged, `ID="_forged"`, `ID="_good"`, 1)+"<samlp:Status>", 1),
		// The Response signature references the assertion instead of its parent.
		"signature of another node": strings.Replace(sign(t, wrapResponse("_response", signedAssertion), "Response", key), `URI="#_response"`, `URI="#_good"`, 1),
		// Signed by a key the connection does not trust.
		"untrusted signer": signedPair(t, attacker, "employee-1"),
		// No Response signature at all.
		"unsigned response": wrapResponse("_response", signedAssertion),
		// An unsigned assertion in a signed Response.
		"unsigned assertion": sign(t, wrapResponse("_response", wrapAssertion("_good", "admin", ` InResponseTo="_fixture"`)), "Response", key),
	}
	// The signed assertion moved inside an extension of a forged Response.
	cases["assertion moved into the signature"] = strings.Replace(cases["assertion moved into the signature"], "</SignatureValue>",
		"</SignatureValue><Object>"+signedAssertion+"</Object>", 1)
	for name, xml := range cases {
		profile, err := validate(t, key, xml)
		if err == nil {
			t.Fatalf("%s: accepted, nameID %v", name, profile.Get("nameID"))
		}
	}
	// Too many transforms is refused outright.
	tooMany := strings.Replace(good, `<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`,
		`<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`, 1)
	if _, err := validate(t, key, tooMany); err == nil || !strings.Contains(err.Error(), "too many transforms") {
		t.Fatalf("too many transforms: %v", err)
	}
	// The untouched pair is accepted.
	if profile, err := validate(t, key, good); err != nil || profile.Get("nameID") != "employee-1" {
		t.Fatalf("good: %v %v", profile, err)
	}
}

func TestSamlRefusesXMLThatIsNotAPlainDocument(t *testing.T) {
	request := "_r"
	for _, xml := range []string{
		`<!DOCTYPE r [<!ENTITY e "x">]><samlp:Response xmlns:samlp="` + protocolNS + `"/>`,
		`<samlp:Response xmlns:samlp="` + protocolNS + `" Destination="` + wrapACS + `" InResponseTo="_r">&unknown;</samlp:Response>`,
		`<samlp:Response xmlns:samlp="` + protocolNS + `" Destination="` + wrapACS + `" InResponseTo="_r" InResponseTo="_r"/>`,
		`<samlp:Response xmlns:samlp="` + protocolNS + `" Destination="` + wrapACS + `" InResponseTo="_r"><a></samlp:Response>`,
		`<Response xmlns="urn:other" Destination="` + wrapACS + `" InResponseTo="_r"/>`,
	} {
		if err := ValidateSamlEnvelope(xml, wrapACS, &request, false); codeOf(err) != "SAML_INVALID" {
			t.Fatalf("%s: %v", xml, err)
		}
	}
	if err := ValidateSamlEnvelope(`<samlp:Response xmlns:samlp="`+protocolNS+`" Destination="`+wrapACS+`" InResponseTo="_r"/>`, wrapACS, &request, false); err != nil {
		t.Fatal(err)
	}
}

func TestSamlSignsTheRedirectBindingRequest(t *testing.T) {
	key := generate(t, "iam.test")
	s := &nodeSaml{options: samlOptions{entryPoint: "https://idp.test/login?tenant=a b", issuer: wrapAudience, callbackURL: wrapACS,
		privateKey: key.private, validateAlways: true, cache: &memoryCache{saved: map[string]string{}},
		generateUniqueID: func() string { return "_request" }, now: nowMs}}
	location, err := s.authorizeURL(context.Background(), "relay state&more")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(location)
	if !strings.HasPrefix(location, "https://idp.test/login?tenant=a+b&SAMLRequest=") {
		t.Fatalf("location %s", location)
	}
	query := parsed.Query()
	signed := querystringStringify([][2]string{{"SAMLRequest", query.Get("SAMLRequest")}, {"RelayState", query.Get("RelayState")}, {"SigAlg", query.Get("SigAlg")}})
	signature, _ := base64.StdEncoding.DecodeString(query.Get("Signature"))
	digest := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(&key.key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("redirect signature does not verify: %v", err)
	}
	if _, _, err := (&memoryCache{saved: s.options.cache.(*memoryCache).saved}).GetAsync(context.Background(), "_request"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.options.cache.(*memoryCache).saved["_request"]; !ok {
		t.Fatal("the request ID was not cached")
	}
	_, request := requestIDOf(t, location)
	want := `<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_request" Version="2.0" IssueInstant="`
	if !strings.HasPrefix(request, want) || !strings.Contains(request, `Destination="https://idp.test/login?tenant=a b"`) {
		t.Fatalf("request %s", request)
	}
}
