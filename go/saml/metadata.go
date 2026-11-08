package saml

// Port of packages/saml/src/metadata.ts: IdP metadata import, certificate normalization and the certificate details
// administrators watch during rollover.

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"regexp"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

const redirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

// IdpMetadata is what a service provider needs from an identity provider's SAML metadata.
type IdpMetadata struct {
	EntityID string `json:"entityId"`
	// EntryPoint is the HTTP-Redirect single sign-on endpoint.
	EntryPoint string `json:"entryPoint"`
	// Certificates are the PEM signing certificates, in document order (several during certificate rollover).
	Certificates []string `json:"certificates"`
	// SingleLogoutURL is the HTTP-Redirect single logout endpoint, when published ("" otherwise).
	SingleLogoutURL string `json:"singleLogoutUrl,omitempty"`
}

// CertificateInfo is what administrators need to watch certificate rollover.
type CertificateInfo struct {
	Fingerprint256 string `json:"fingerprint256"`
	Subject        string `json:"subject"`
	NotBefore      string `json:"notBefore"`
	NotAfter       string `json:"notAfter"`
	Expired        bool   `json:"expired"`
}

func (c CertificateInfo) object() *core.Object {
	return core.NewObject("fingerprint256", c.Fingerprint256, "subject", c.Subject, "notBefore", c.NotBefore,
		"notAfter", c.NotAfter, "expired", c.Expired)
}

var pemMarkers = regexp.MustCompile(`-----(BEGIN|END) CERTIFICATE-----`)
var base64Body = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
var jsSpaces = regexp.MustCompile(`[\s\x0b\x{feff}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]+`)

func invalidCertificate() error {
	return core.NewIamError("INVALID_INPUT", "IdP certificates must be X.509 certificates.")
}

// NormalizeCertificate normalizes a PEM or bare base64 DER certificate to PEM, rejecting anything that is not a
// parseable X.509 certificate (normalizeCertificate; value is String()-converted as TypeScript does).
func NormalizeCertificate(value any) (string, error) {
	body := jsSpaces.ReplaceAllString(pemMarkers.ReplaceAllString(jsString(value), ""), "")
	if body == "" || core.UTF16Len(body) > 16_384 || !base64Body.MatchString(body) {
		return "", invalidCertificate()
	}
	var lines []string
	for rest := body; rest != ""; {
		n := 64
		if len(rest) < n {
			n = len(rest)
		}
		lines = append(lines, rest[:n])
		rest = rest[n:]
	}
	text := "-----BEGIN CERTIFICATE-----\n" + strings.Join(lines, "\n") + "\n-----END CERTIFICATE-----"
	if _, err := parseCertificate(text); err != nil {
		return "", invalidCertificate()
	}
	return text, nil
}

func parseCertificate(text string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, invalidCertificate()
	}
	return x509.ParseCertificate(block.Bytes)
}

// CertificateDetails is certificateInfo(pem) at time now (milliseconds).
func CertificateDetails(text string, now int64) (CertificateInfo, error) {
	certificate, err := parseCertificate(text)
	if err != nil {
		return CertificateInfo{}, err
	}
	sum := sha256.Sum256(certificate.Raw)
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	pairs := make([]string, 0, len(sum))
	for i := 0; i < len(hexed); i += 2 {
		pairs = append(pairs, hexed[i:i+2])
	}
	notBefore := certificate.NotBefore.UTC().Truncate(time.Second)
	notAfter := certificate.NotAfter.UTC().Truncate(time.Second)
	return CertificateInfo{
		Fingerprint256: strings.Join(pairs, ":"),
		Subject:        distinguishedName(certificate.RawSubject),
		NotBefore:      isoString(notBefore.UnixMilli()),
		NotAfter:       isoString(notAfter.UnixMilli()),
		Expired:        notAfter.UnixMilli() <= now,
	}, nil
}

var shortNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
	"2.5.4.5": "serialNumber", "2.5.4.9": "street", "2.5.4.12": "title", "2.5.4.42": "GN", "2.5.4.4": "SN",
	"2.5.4.43": "initials", "2.5.4.44": "generationQualifier", "2.5.4.46": "dnQualifier", "2.5.4.65": "pseudonym",
	"2.5.4.17": "postalCode", "2.5.4.15": "businessCategory", "0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1": "UID", "1.2.840.113549.1.9.1": "emailAddress",
}

// distinguishedName is X509Certificate#subject: one `type=value` line per attribute in certificate order, values
// escaped as RFC 2253 asks.
func distinguishedName(raw []byte) string {
	var sequence pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &sequence); err != nil {
		return ""
	}
	var lines []string
	for _, rdn := range sequence {
		var parts []string
		for _, attribute := range rdn {
			name, ok := shortNames[attribute.Type.String()]
			if !ok {
				name = attribute.Type.String()
			}
			value, _ := attribute.Value.(string)
			if value == "" {
				if text, isText := attribute.Value.(interface{ String() string }); isText {
					value = text.String()
				}
			}
			parts = append(parts, name+"="+escapeRFC2253(value))
		}
		lines = append(lines, strings.Join(parts, " + "))
	}
	return strings.Join(lines, "\n")
}

func escapeRFC2253(value string) string {
	var out strings.Builder
	runes := []rune(value)
	for i, r := range runes {
		switch {
		case strings.ContainsRune(",+\"\\<>;", r):
			out.WriteString("\\" + string(r))
		case i == 0 && (r == '#' || r == ' '), i == len(runes)-1 && r == ' ':
			out.WriteString("\\" + string(r))
		case r < 0x20 || r == 0x7f:
			out.WriteString("\\" + strings.ToUpper(hex.EncodeToString([]byte{byte(r)})))
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// unsafeXML is /<!DOCTYPE|<!ENTITY/i.
var unsafeXML = regexp.MustCompile(`(?i)<!DOCTYPE|<!ENTITY`)

// ParseIdpMetadata reads entity ID, redirect-binding SSO/SLO endpoints, and signing certificates from IdP metadata.
// The document must describe exactly one identity provider; DTDs and entities are refused. Metadata signatures are
// not checked: import metadata only from a source you trust. xml is the value as given (anything but a string is
// refused).
func ParseIdpMetadata(xml any) (*IdpMetadata, error) {
	text, ok := xml.(string)
	if !ok || core.UTF16Len(text) > 512*1024 || unsafeXML.MatchString(text) {
		return nil, core.NewIamError("INVALID_INPUT", "Unsafe or oversized SAML metadata.")
	}
	doc, err := ParseXML(text)
	var descriptors []*Node
	if err == nil {
		descriptors = doc.ElementsByTagNameNS(metadataNamespace, "IDPSSODescriptor")
	}
	if err != nil || len(descriptors) != 1 {
		return nil, core.NewIamError("INVALID_INPUT", "Metadata must describe exactly one identity provider.")
	}
	idp := descriptors[0]
	entityID := ""
	if entity := idp.Parent; entity != nil && entity.Type == ElementNode && entity.Local == "EntityDescriptor" && entity.NamespaceURI == metadataNamespace {
		entityID = entity.Attribute("entityID")
	}
	if entityID == "" {
		return nil, core.NewIamError("INVALID_INPUT", "The identity provider has no entityID.")
	}
	endpoint := func(name string) string {
		for _, service := range idp.ElementsByTagNameNS(metadataNamespace, name) {
			if service.Attribute("Binding") == redirectBinding {
				return service.Attribute("Location")
			}
		}
		return ""
	}
	entryPoint := endpoint("SingleSignOnService")
	if entryPoint == "" {
		return nil, core.NewIamError("INVALID_INPUT", "The identity provider has no HTTP-Redirect sign-on endpoint.")
	}
	var certificates []string
	for _, key := range idp.ElementsByTagNameNS(metadataNamespace, "KeyDescriptor") {
		if use := key.Attribute("use"); use != "" && use != "signing" {
			continue
		}
		for _, certificate := range key.ElementsByTagNameNS(dsigNamespace, "X509Certificate") {
			normalized, err := NormalizeCertificate(certificate.TextContent())
			if err != nil {
				return nil, err
			}
			if !contains(certificates, normalized) {
				certificates = append(certificates, normalized)
			}
		}
	}
	if len(certificates) == 0 {
		return nil, core.NewIamError("INVALID_INPUT", "The identity provider publishes no signing certificate.")
	}
	return &IdpMetadata{EntityID: entityID, EntryPoint: entryPoint, Certificates: certificates, SingleLogoutURL: endpoint("SingleLogoutService")}, nil
}

// jsString is String(value) for the model values.
func jsString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return "null"
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return core.NumberString(v)
	case []any:
		parts := make([]string, len(v))
		for i, item := range v {
			if item == nil || core.IsUndefined(item) {
				continue
			}
			parts[i] = jsString(item)
		}
		return strings.Join(parts, ",")
	case []string:
		return strings.Join(v, ",")
	case *core.Object:
		return "[object Object]"
	}
	if core.IsUndefined(value) {
		return "undefined"
	}
	return ""
}
