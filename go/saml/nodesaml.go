package saml

// Port of the parts of @node-saml/node-saml 5.1.0's SAML class the TypeScript package uses, with the options it
// passes: the signed HTTP-Redirect AuthnRequest URL, signed service-provider metadata, and validatePostResponseAsync
// (InResponseTo against the cache, the Response and assertion signatures, decryption, timestamps, audience and the
// profile built from the signed assertion).

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"math"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	defaultIdentifierFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	passwordProtected       = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	metadataNamespace       = "urn:oasis:names:tc:SAML:2.0:metadata"
)

// CacheProvider is node-saml's CacheProvider: the request IDs a response may answer. A missing value is ok=false.
type CacheProvider interface {
	SaveAsync(ctx context.Context, key, value string) error
	GetAsync(ctx context.Context, key string) (value string, ok bool, err error)
	RemoveAsync(ctx context.Context, key string) (value string, ok bool, err error)
}

// samlOptions are the node-saml options the service builds for a connection.
type samlOptions struct {
	entryPoint       string
	issuer           string
	idpIssuer        string
	callbackURL      string
	audience         string
	idpCert          []string
	privateKey       string
	publicCert       string
	decryptionPvk    string
	validateAlways   bool
	cache            CacheProvider
	generateUniqueID func() string
	now              func() int64
}

const (
	requestIDExpirationPeriodMs = 600_000
	maxAssertionAgeMs           = 300_000
	acceptedClockSkewMs         = 30_000
)

type nodeSaml struct{ options samlOptions }

// result is node-saml's { profile, loggedOut }.
type result struct {
	profile   *core.Object
	assertion string
	loggedOut bool
}

func (s *nodeSaml) mustValidateInResponseTo(hasInResponseTo bool) bool {
	return s.options.validateAlways
}

// authorizeRequest is generateAuthorizeRequestAsync(isPassive=false, isHttpPostBinding=false): the AuthnRequest XML
// as xmlbuilder writes it, after saving its ID in the cache.
func (s *nodeSaml) authorizeRequest(ctx context.Context) (string, error) {
	if s.options.entryPoint == "" {
		return "", errors.New("entryPoint is required")
	}
	id := s.options.generateUniqueID()
	instant := isoString(s.options.now())
	if s.mustValidateInResponseTo(true) {
		if err := s.options.cache.SaveAsync(ctx, id, instant); err != nil {
			return "", err
		}
	}
	var out strings.Builder
	out.WriteString(`<?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`)
	out.WriteString(` ID="` + encodeC14nAttr(id) + `" Version="2.0" IssueInstant="` + encodeC14nAttr(instant) + `"`)
	out.WriteString(` ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Destination="` + encodeC14nAttr(s.options.entryPoint) + `"`)
	out.WriteString(` AssertionConsumerServiceURL="` + encodeC14nAttr(s.options.callbackURL) + `">`)
	out.WriteString(`<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` + encodeC14nText(s.options.issuer) + `</saml:Issuer>`)
	out.WriteString(`<samlp:NameIDPolicy xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AllowCreate="true" Format="` + defaultIdentifierFormat + `"/>`)
	out.WriteString(`<samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">`)
	out.WriteString(`<saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` + passwordProtected + `</saml:AuthnContextClassRef>`)
	out.WriteString(`</samlp:RequestedAuthnContext></samlp:AuthnRequest>`)
	return out.String(), nil
}

// authorizeURL is getAuthorizeUrlAsync(relayState, undefined, {}): the deflated, signed HTTP-Redirect URL.
func (s *nodeSaml) authorizeURL(ctx context.Context, relayState string) (string, error) {
	request, err := s.authorizeRequest(ctx)
	if err != nil {
		return "", err
	}
	var compressed bytes.Buffer
	writer, _ := flate.NewWriter(&compressed, flate.DefaultCompression)
	_, _ = writer.Write([]byte(request))
	_ = writer.Close()
	encoded := base64.StdEncoding.EncodeToString(compressed.Bytes())
	target, err := auth.ParseFetchURL(s.options.entryPoint)
	if err != nil {
		return "", errors.New("Invalid URL")
	}
	message := [][2]string{{"SAMLRequest", encoded}}
	if relayState != "" {
		message = append(message, [2]string{"RelayState", relayState})
	}
	if s.options.privateKey != "" {
		message = append(message, [2]string{"SigAlg", algRsaSha256})
		pemKey, err := keyInfoToPem(s.options.privateKey, "PRIVATE KEY", "privateKey")
		if err != nil {
			return "", err
		}
		key, err := parsePrivateKey(pemKey)
		if err != nil {
			return "", err
		}
		raw, err := signBytes(key, crypto.SHA256, []byte(querystringStringify(message)))
		if err != nil {
			return "", err
		}
		message = append(message, [2]string{"Signature", base64.StdEncoding.EncodeToString(raw)})
	}
	params := parseSearchParams(target.RawQuery)
	for _, pair := range message {
		params.Set(pair[0], pair[1])
	}
	return urlWithSearch(target.URL, params.String()), nil
}

var pemHeader = regexp.MustCompile(`-----BEGIN [A-Z ]{1,48}-----\n?`)
var pemFooter = regexp.MustCompile(`-----END [A-Z ]{1,48}-----\n?`)

// stripPemHeaderAndFooter is node-saml's stripPemHeaderAndFooter.
func stripPemHeaderAndFooter(certificate string) string {
	certificate = strings.ReplaceAll(strings.ReplaceAll(certificate, "\r\n", "\n"), "\r", "\n")
	certificate = replaceFirst(pemHeader, certificate)
	return replaceFirst(pemFooter, certificate)
}

func replaceFirst(pattern *regexp.Regexp, value string) string {
	if location := pattern.FindStringIndex(value); location != nil {
		return value[:location[0]] + value[location[1]:]
	}
	return value
}

// serviceProviderMetadata is generateServiceProviderMetadata(decryptionCert, publicCerts) with signMetadata: the
// metadata xmlbuilder pretty-prints, signed with an enveloped signature prepended to EntityDescriptor.
func (s *nodeSaml) serviceProviderMetadata(decryptionCert string, publicCert string) (string, error) {
	if s.options.decryptionPvk != "" {
		if decryptionCert == "" {
			return "", errors.New("Missing decryptionCert while generating metadata for decrypting service provider")
		}
	} else {
		decryptionCert = ""
	}
	if s.options.privateKey != "" && publicCert == "" {
		return "", errors.New("Missing publicCert while generating metadata for signing service provider messages")
	}
	signing := s.options.privateKey != ""
	var out strings.Builder
	out.WriteString("<?xml version=\"1.0\"?>\n")
	out.WriteString(`<EntityDescriptor xmlns="` + metadataNamespace + `" xmlns:ds="` + dsigNamespace + `" entityID="` + encodeC14nAttr(s.options.issuer) + `" ID="` + encodeC14nAttr(s.options.generateUniqueID()) + `">` + "\n")
	authnSigned := "false"
	if signing {
		authnSigned = "true"
	}
	out.WriteString(`  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="` + authnSigned + `" WantAssertionsSigned="true">` + "\n")
	keyInfo := func(certificate string) {
		out.WriteString("      <ds:KeyInfo>\n        <ds:X509Data>\n          <ds:X509Certificate>" + encodeC14nText(stripPemHeaderAndFooter(certificate)) + "</ds:X509Certificate>\n        </ds:X509Data>\n      </ds:KeyInfo>\n")
	}
	if signing {
		out.WriteString("    <KeyDescriptor use=\"signing\">\n")
		keyInfo(publicCert)
		out.WriteString("    </KeyDescriptor>\n")
	}
	if decryptionCert != "" {
		out.WriteString("    <KeyDescriptor use=\"encryption\">\n")
		keyInfo(decryptionCert)
		for _, algorithm := range []string{algAes256Gcm, algAes128Gcm, algAes256Cbc, algAes128Cbc} {
			out.WriteString("      <EncryptionMethod Algorithm=\"" + algorithm + "\"/>\n")
		}
		out.WriteString("    </KeyDescriptor>\n")
	}
	out.WriteString("    <NameIDFormat>" + defaultIdentifierFormat + "</NameIDFormat>\n")
	out.WriteString(`    <AssertionConsumerService index="1" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + encodeC14nAttr(s.options.callbackURL) + `"/>` + "\n")
	out.WriteString("  </SPSSODescriptor>\n</EntityDescriptor>")
	if !signing {
		return out.String(), nil
	}
	isEntity := func(n *Node) bool { return n.Local == "EntityDescriptor" && n.NamespaceURI == metadataNamespace }
	return computeSignature(out.String(), signOptions{
		references: func(doc *Node) []*Node { return doc.Descendants(isEntity) },
		location: func(doc *Node) *Node {
			if found := doc.Descendants(isEntity); len(found) > 0 {
				return found[0]
			}
			return nil
		},
		action:             "prepend",
		privateKey:         s.options.privateKey,
		signatureAlgorithm: algRsaSha256,
		digestAlgorithm:    algSha256,
	})
}

// keyInfosAsPem is getKeyInfosAsPem.
func (s *nodeSaml) keyInfosAsPem() ([]string, error) {
	pems := make([]string, len(s.options.idpCert))
	for i, certificate := range s.options.idpCert {
		pem, err := keyInfoToPem(certificate, "CERTIFICATE", "idpCert["+itoa(i)+"]")
		if err != nil {
			return nil, err
		}
		pems[i] = pem
	}
	return pems, nil
}

func isLocal(name string) func(*Node) bool { return func(n *Node) bool { return n.Local == name } }

// signedAssertion is getSignedAssertion: the assertion inside the verified XML, decrypted when it is encrypted.
func (s *nodeSaml) signedAssertion(signedXML string) (string, bool, error) {
	doc, err := ParseXML(signedXML)
	if err != nil {
		return "", false, err
	}
	root := doc.DocumentElement()
	switch root.Local {
	case "Response":
		if assertions := root.ChildElements(isLocal("Assertion")); len(assertions) == 1 {
			return assertions[0].String(), true, nil
		}
		if encrypted := root.ChildElements(isLocal("EncryptedAssertion")); len(encrypted) == 1 {
			if s.options.decryptionPvk == "" {
				return "", false, errors.New("No decryption key for encrypted SAML response")
			}
			decrypted, err := decryptXML(encrypted[0].String(), s.options.decryptionPvk)
			if err != nil {
				return "", false, err
			}
			decryptedDoc, err := ParseXML(decrypted)
			if err != nil {
				return "", false, err
			}
			if decryptedDoc.DocumentElement().Local != "Assertion" {
				return "", false, errors.New("Invalid EncryptedAssertion content")
			}
			return decryptedDoc.DocumentElement().String(), true, nil
		}
	case "Assertion":
		return root.String(), true, nil
	}
	return "", false, nil
}

// validatePostResponse is validatePostResponseAsync({ SAMLResponse }).
func (s *nodeSaml) validatePostResponse(ctx context.Context, samlResponse string) (*result, error) {
	inResponseTo := ""
	value, err := s.validatePostResponseInner(ctx, samlResponse, &inResponseTo)
	if err != nil {
		if s.mustValidateInResponseTo(inResponseTo != "") {
			if _, _, removeErr := s.options.cache.RemoveAsync(ctx, inResponseTo); removeErr != nil {
				return nil, removeErr
			}
		}
		return nil, err
	}
	return value, nil
}

func (s *nodeSaml) validatePostResponseInner(ctx context.Context, samlResponse string, inResponseTo *string) (*result, error) {
	xml := decodeUTF8(nodeBase64(samlResponse))
	doc, err := ParseXML(xml)
	if err != nil {
		return nil, err
	}
	root := doc.DocumentElement()
	if root.Local == "Response" {
		value, present := root.LookupAttribute("InResponseTo")
		if present {
			*inResponseTo = value
		}
		if err := s.validateInResponseTo(ctx, *inResponseTo); err != nil {
			return nil, err
		}
	} else if err := s.validateInResponseTo(ctx, ""); err != nil {
		return nil, err
	}
	pemFiles, err := s.keyInfosAsPem()
	if err != nil {
		return nil, err
	}
	responseVerified, err := getVerifiedXml(xml, root, pemFiles)
	if err != nil {
		return nil, err
	}
	validSignature := responseVerified != ""
	if !validSignature {
		return nil, errors.New("Invalid document signature")
	}
	var assertions, encryptedAssertions []*Node
	if root.Local == "Response" {
		assertions = root.ChildElements(isLocal("Assertion"))
		encryptedAssertions = root.ChildElements(isLocal("EncryptedAssertion"))
	}
	if len(assertions)+len(encryptedAssertions) > 1 {
		return nil, errors.New("Invalid signature: multiple assertions")
	}
	if len(assertions) == 1 {
		verified, err := getVerifiedXml(xml, assertions[0], pemFiles)
		if err != nil {
			return nil, err
		}
		if verified == "" {
			return nil, errors.New("Invalid signature")
		}
	}
	if len(encryptedAssertions) == 1 {
		if s.options.decryptionPvk == "" {
			return nil, errors.New("No decryption key for encrypted SAML response")
		}
		decrypted, err := decryptXML(encryptedAssertions[0].String(), s.options.decryptionPvk)
		if err != nil {
			return nil, err
		}
		decryptedDoc, err := ParseXML(decrypted)
		if err != nil {
			return nil, err
		}
		decryptedRoot := decryptedDoc.DocumentElement()
		if decryptedRoot.Local != "Assertion" {
			return nil, errors.New("Invalid EncryptedAssertion content")
		}
		verified, err := getVerifiedXml(decrypted, decryptedRoot, pemFiles)
		if err != nil {
			return nil, err
		}
		if verified == "" {
			return nil, errors.New("Invalid signature from encrypted assertion")
		}
	}
	if len(assertions)+len(encryptedAssertions) == 1 {
		assertion, ok, err := s.signedAssertion(responseVerified)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("Cannot obtain assertion from signed data")
		}
		return s.processValidlySignedAssertion(ctx, assertion, *inResponseTo)
	}
	return s.unsignedOutcome(xml, validSignature)
}

// unsignedOutcome is the xml2js fallback for responses without an assertion: a status error, NoPassive, a logout
// response, or "Missing SAML assertion".
func (s *nodeSaml) unsignedOutcome(xml string, validSignature bool) (*result, error) {
	parsed, err := xml2jsRoot(xml)
	if err != nil {
		return nil, err
	}
	response := parsed.Get("Response")
	if !core.IsUndefined(response) {
		if object, ok := response.(*core.Object); !ok || !object.Has("Assertion") {
			status := member(response, "Status")
			if truthy(status) {
				statusCode := member(first(status), "StatusCode")
				if truthy(statusCode) && member(member(first(statusCode), "$"), "Value") == "urn:oasis:names:tc:SAML:2.0:status:Responder" {
					nested := member(first(statusCode), "StatusCode")
					if truthy(nested) && member(member(first(nested), "$"), "Value") == "urn:oasis:names:tc:SAML:2.0:status:NoPassive" {
						if !validSignature {
							return nil, errors.New("Invalid signature: NoPassive")
						}
						return &result{}, nil
					}
				}
				if truthy(statusCode) {
					if value, ok := member(member(first(statusCode), "$"), "Value").(string); ok && value != "" {
						msgType := value[strings.LastIndexByte(value, ':')+1:]
						if msgType != "Success" {
							msg := "unspecified"
							if message := member(first(status), "StatusMessage"); truthy(message) {
								if text, ok := member(first(message), "_").(string); ok && text != "" {
									msg = text
								}
							} else if inner := member(first(statusCode), "StatusCode"); truthy(inner) {
								if innerValue, ok := member(member(first(inner), "$"), "Value").(string); ok {
									msg = innerValue[strings.LastIndexByte(innerValue, ':')+1:]
								}
							}
							return nil, errors.New("SAML provider returned " + msgType + " error: " + msg)
						}
					}
				}
			}
		}
		return nil, errors.New("Missing SAML assertion")
	}
	if !validSignature {
		return nil, errors.New("Invalid signature: No response found")
	}
	if !core.IsUndefined(parsed.Get("LogoutResponse")) {
		return &result{loggedOut: true}, nil
	}
	return nil, errors.New("Unknown SAML response message")
}

// validateInResponseTo is validateInResponseTo(inResponseTo) ("" for null).
func (s *nodeSaml) validateInResponseTo(ctx context.Context, inResponseTo string) error {
	if !s.mustValidateInResponseTo(inResponseTo != "") {
		return nil
	}
	if inResponseTo == "" {
		return errors.New("InResponseTo is missing from response")
	}
	_, ok, err := s.options.cache.GetAsync(ctx, inResponseTo)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("InResponseTo is not valid")
	}
	return nil
}

// dateStringToTimestamp is node-saml's dateStringToTimestamp (value nil: undefined).
func dateStringToTimestamp(value any, label string) (float64, error) {
	text, isString := value.(string)
	ms := math.NaN()
	if isString {
		ms = dateParse(text)
	}
	if math.IsNaN(ms) {
		shown := "undefined"
		if isString {
			shown = text
		} else if value != nil && !core.IsUndefined(value) {
			shown = core.MustStringify(value)
		}
		return 0, errors.New("Error parsing " + label + ": '" + shown + "' is not a valid date")
	}
	return ms, nil
}

// calcMaxAgeAssertionTime is calcMaxAgeAssertionTime(maxAssertionAgeMs, notOnOrAfter, issueInstant).
func calcMaxAgeAssertionTime(notOnOrAfter, issueInstant any) (float64, error) {
	notOnOrAfterMs, err := dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter")
	if err != nil {
		return 0, err
	}
	issueInstantMs, err := dateStringToTimestamp(issueInstant, "IssueInstant")
	if err != nil {
		return 0, err
	}
	maxAssertionTimeMs := issueInstantMs + maxAssertionAgeMs
	if maxAssertionTimeMs < notOnOrAfterMs {
		return maxAssertionTimeMs, nil
	}
	return notOnOrAfterMs, nil
}

// checkTimestampsValidityError is checkTimestampsValidityError(nowMs, notBefore, notOnOrAfter, maxTimeLimitMs).
func checkTimestampsValidityError(nowMs float64, notBefore, notOnOrAfter any, maxTimeLimitMs float64) error {
	if truthy(notBefore) {
		notBeforeMs, err := dateStringToTimestamp(notBefore, "NotBefore")
		if err != nil {
			return err
		}
		if nowMs+acceptedClockSkewMs < notBeforeMs {
			return errors.New("SAML assertion not yet valid")
		}
	}
	if truthy(notOnOrAfter) {
		notOnOrAfterMs, err := dateStringToTimestamp(notOnOrAfter, "NotOnOrAfter")
		if err != nil {
			return err
		}
		if nowMs-acceptedClockSkewMs >= notOnOrAfterMs {
			return errors.New("SAML assertion expired: clocks skewed too much")
		}
	}
	if maxTimeLimitMs != 0 && !math.IsNaN(maxTimeLimitMs) {
		if nowMs-acceptedClockSkewMs >= maxTimeLimitMs {
			return errors.New("SAML assertion expired: assertion too old")
		}
	}
	return nil
}

var errTypeError = errors.New("Cannot read properties of undefined")

// processValidlySignedAssertion is processValidlySignedAssertionAsync(xml, samlResponseXml, inResponseTo).
func (s *nodeSaml) processValidlySignedAssertion(ctx context.Context, xml string, inResponseTo string) (*result, error) {
	nowMs := float64(s.options.now())
	profile := core.NewObject()
	parsed, err := xml2jsRoot(xml)
	if err != nil {
		return nil, err
	}
	assertion := parsed.Get("Assertion")
	if core.IsUndefined(assertion) {
		return nil, errTypeError
	}
	issueInstant := func() (any, error) {
		attrs := member(assertion, "$")
		if core.IsUndefined(attrs) {
			return nil, errTypeError
		}
		return member(attrs, "IssueInstant"), nil
	}
	if issuer := member(assertion, "Issuer"); truthy(issuer) && truthy(member(first(issuer), "_")) {
		profile.Set("issuer", member(first(issuer), "_"))
	}
	if inResponseTo != "" {
		profile.Set("inResponseTo", inResponseTo)
	}
	if statement := member(assertion, "AuthnStatement"); truthy(statement) {
		attrs := member(first(statement), "$")
		if truthy(attrs) && truthy(member(attrs, "SessionIndex")) {
			profile.Set("sessionIndex", member(attrs, "SessionIndex"))
		}
	}
	var subjectConfirmation any = core.Undefined
	var confirmData any = core.Undefined
	var subjectConfirmations any = core.Undefined
	if subject := member(assertion, "Subject"); truthy(subject) {
		if nameID := member(first(subject), "NameID"); truthy(nameID) && truthy(member(first(nameID), "_")) {
			profile.Set("nameID", member(first(nameID), "_"))
			if attrs := member(first(nameID), "$"); truthy(attrs) && truthy(member(attrs, "Format")) {
				profile.Set("nameIDFormat", member(attrs, "Format"))
				profile.SetRaw("nameQualifier", member(attrs, "NameQualifier"))
				profile.SetRaw("spNameQualifier", member(attrs, "SPNameQualifier"))
			}
		}
		subjectConfirmations = member(first(subject), "SubjectConfirmation")
		if list, ok := subjectConfirmations.([]any); ok {
			for _, candidate := range list {
				data := first(member(candidate, "SubjectConfirmationData"))
				attrs := member(data, "$")
				if !truthy(attrs) {
					continue
				}
				instant, err := issueInstant()
				if err != nil {
					return nil, err
				}
				maxTime, err := calcMaxAgeAssertionTime(member(attrs, "NotOnOrAfter"), instant)
				if err != nil {
					return nil, err
				}
				if checkTimestampsValidityError(nowMs, member(attrs, "NotBefore"), member(attrs, "NotOnOrAfter"), maxTime) == nil {
					subjectConfirmation = candidate
					confirmData = data
					break
				}
			}
		} else if !core.IsUndefined(subjectConfirmations) && subjectConfirmations != nil {
			return nil, errors.New("subjectConfirmations?.find is not a function")
		}
	}
	if s.mustValidateInResponseTo(inResponseTo != "") {
		if !core.IsUndefined(subjectConfirmation) {
			if attrs := member(confirmData, "$"); truthy(attrs) {
				subjectInResponseTo := member(attrs, "InResponseTo")
				if inResponseTo != "" && truthy(subjectInResponseTo) && subjectInResponseTo != inResponseTo {
					if _, _, err := s.options.cache.RemoveAsync(ctx, inResponseTo); err != nil {
						return nil, err
					}
					return nil, errors.New("InResponseTo does not match subjectInResponseTo")
				} else if truthy(subjectInResponseTo) {
					key, _ := subjectInResponseTo.(string)
					found := false
					value, ok, err := s.options.cache.GetAsync(ctx, key)
					if err != nil {
						return nil, err
					}
					if ok {
						createdAt := dateParse(value)
						if nowMs < createdAt+requestIDExpirationPeriodMs {
							found = true
						}
					}
					if _, _, err := s.options.cache.RemoveAsync(ctx, inResponseTo); err != nil {
						return nil, err
					}
					if !found {
						return nil, errors.New("SubjectInResponseTo is not valid")
					}
				}
			}
		} else if !core.IsUndefined(subjectConfirmations) {
			return nil, errors.New("No valid subject confirmation found among those available in the SAML assertion")
		} else if _, _, err := s.options.cache.RemoveAsync(ctx, inResponseTo); err != nil {
			return nil, err
		}
	}
	conditionsList := member(assertion, "Conditions")
	var conditions any
	if truthy(conditionsList) {
		conditions = first(conditionsList)
	}
	if list, ok := conditionsList.([]any); ok && len(list) > 1 {
		return nil, errors.New("Unable to process multiple conditions in SAML assertion")
	}
	if truthy(conditions) && truthy(member(conditions, "$")) {
		attrs := member(conditions, "$")
		instant, err := issueInstant()
		if err != nil {
			return nil, err
		}
		maxTime, err := calcMaxAgeAssertionTime(member(attrs, "NotOnOrAfter"), instant)
		if err != nil {
			return nil, err
		}
		if err := checkTimestampsValidityError(nowMs, member(attrs, "NotBefore"), member(attrs, "NotOnOrAfter"), maxTime); err != nil {
			return nil, err
		}
	}
	if conditions == nil {
		return nil, errors.New("Cannot read properties of null (reading 'AudienceRestriction')")
	}
	if err := checkAudienceValidityError(s.options.audience, member(conditions, "AudienceRestriction")); err != nil {
		return nil, err
	}
	if statements, ok := member(assertion, "AttributeStatement").([]any); ok {
		var attributes []any
		for _, statement := range statements {
			if list, ok := member(statement, "Attribute").([]any); ok {
				attributes = append(attributes, list...)
			}
		}
		if len(attributes) > 0 {
			profileAttributes := core.NewObject()
			for _, attribute := range attributes {
				object, isObject := attribute.(*core.Object)
				if !isObject || !object.Has("AttributeValue") {
					continue
				}
				attrs := object.Get("$")
				if core.IsUndefined(attrs) {
					return nil, errTypeError
				}
				name := "undefined"
				if text, ok := member(attrs, "Name").(string); ok {
					name = text
				}
				values, _ := object.Get("AttributeValue").([]any)
				var value any
				if len(values) == 1 {
					value = attributeValue(values[0])
				} else {
					mapped := make([]any, len(values))
					for i, item := range values {
						mapped[i] = attributeValue(item)
					}
					value = mapped
				}
				profileAttributes.SetRaw(name, value)
				if profile.Has(name) {
					continue
				}
				profile.SetRaw(name, value)
			}
			profile.Set("attributes", profileAttributes)
		}
	}
	const mailOID = "urn:oid:0.9.2342.19200300.100.1.3"
	if !truthy(profile.Get("mail")) && truthy(profile.Get(mailOID)) {
		profile.SetRaw("mail", profile.Get(mailOID))
	}
	if !truthy(profile.Get("email")) && truthy(profile.Get("mail")) {
		profile.SetRaw("email", profile.Get("mail"))
	}
	return &result{profile: profile, assertion: xml}, nil
}

// attributeValue is node-saml's attrValueMapper.
func attributeValue(value any) any {
	switch v := value.(type) {
	case string:
		if v == "" {
			return core.Undefined
		}
		return v
	case *core.Object:
		for _, key := range v.Keys() {
			if key != "_" && key != "$" {
				return v
			}
		}
		return v.Get("_")
	}
	return core.Undefined
}

// checkAudienceValidityError is checkAudienceValidityError(expectedAudience, audienceRestrictions).
func checkAudienceValidityError(expected string, restrictions any) error {
	list, _ := restrictions.([]any)
	if len(list) < 1 {
		return errors.New("SAML assertion has no AudienceRestriction")
	}
	for _, restriction := range list {
		audiences, _ := member(restriction, "Audience").([]any)
		if len(audiences) == 0 || !truthy(member(audiences[0], "_")) {
			return errors.New("SAML assertion AudienceRestriction has no Audience value")
		}
		matched := false
		var received []string
		for _, audience := range audiences {
			text, _ := member(audience, "_").(string)
			received = append(received, text)
			if member(audience, "_") == expected {
				matched = true
			}
		}
		if !matched {
			return errors.New("SAML assertion audience mismatch. Expected: " + expected + " Received: " + strings.Join(received, ", "))
		}
	}
	return nil
}
