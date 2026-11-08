package server

// Port of packages/server/src/pki.ts: a private certificate authority for workload identity (like AWS Private CA,
// step-ca or a SPIFFE server): tenant certificate authorities whose signing keys are KMS keys, certificates issued
// from PKCS#10 requests with every name decided by policy, SPIFFE workload certificates (SVIDs) for the caller's own
// identity, revocation, CRLs and chain verification for mTLS. The API lives in api_pki.go; the X.509 encoding in
// x509.go.
//
// Records: `pkiAuthorities` (PkiAuthority: uniqueKey `name:{lowercase name}`, name, type, parentId?, subject,
// subjectDer, subjectKeyId, keyId, keyVersion, algorithm, certificatePem, serialNumber, notBefore, notAfter,
// pathLength?, state, trustDomain?, crlUrl?, permitted?, maxValiditySeconds, defaultValiditySeconds, revision,
// crlNumber, crl?, createdAt, createdBy, updatedAt) and `pkiCertificates` (PkiCertificate: uniqueKey `serial:{hex}`,
// authorityId, serialNumber, commonName?, names, keyType, usage, notBefore, notAfter, certificatePem, fingerprint,
// identityId?, spiffeId?, subordinateId?, status, revokedAt?, revocationReason?, revokedBy?, issuedAt, issuedBy).

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// MaxAuthoritiesPerTenant is pki.ts MAX_AUTHORITIES_PER_TENANT.
const MaxAuthoritiesPerTenant = 50

// MaxLeafValiditySeconds is pki.ts MAX_LEAF_VALIDITY_SECONDS: leaf certificates never outlive 825 days, the
// CA/Browser Forum's old ceiling.
const MaxLeafValiditySeconds = 71280000

// PkiActions is pki.ts pkiActions.
var PkiActions = struct {
	Create  string
	Read    string
	Update  string
	Issue   string
	Request string
	Revoke  string
}{"iam:pki:create", "iam:pki:read", "iam:pki:update", "iam:pki:issue", "iam:pki:request", "iam:pki:revoke"}

// defined is `value !== undefined`.
func defined(value any) bool { return !isUndefined(value) }

// SummarizeAuthority (pki.ts summarizeAuthority): the AuthoritySummary of a stored authority.
func SummarizeAuthority(authority *core.Object) (result *core.Object, err error) {
	subject, _ := authority.Get("subject").(*core.Object)
	var subjectCopy *core.Object
	if subject != nil {
		subjectCopy = subject.Spread()
	} else {
		subjectCopy = core.NewObject()
	}
	summary := core.NewObject(
		"id", authority.Get("id"),
		"tenantId", authority.Get("tenantId"),
		"name", authority.Get("name"),
		"type", authority.Get("type"),
	)
	summary.SetRaw("subject", subjectCopy)
	for _, key := range []string{"keyId", "keyVersion", "algorithm", "certificatePem", "serialNumber", "notBefore", "notAfter",
		"state", "maxValiditySeconds", "defaultValiditySeconds", "createdAt", "createdBy"} {
		summary.SetRaw(key, authority.Get(key))
	}
	for _, key := range []string{"parentId", "pathLength", "trustDomain", "crlUrl"} {
		if value := authority.Get(key); defined(value) {
			summary.SetRaw(key, value)
		}
	}
	if permitted := authority.Get("permitted"); defined(permitted) {
		summary.SetRaw("permitted", core.CloneValue(permitted))
	}
	return summary, nil
}

// certificateStatus is the summary status: revoked, expired (notAfter passed) or valid.
func certificateStatus(certificate *core.Object, now int64) string {
	if certificate.Get("status") == "revoked" {
		return "revoked"
	}
	if jsNumber(certificate.Get("notAfter")) <= float64(now) {
		return "expired"
	}
	return "valid"
}

// SummarizeCertificate (pki.ts summarizeCertificate): the CertificateSummary of a stored certificate.
func SummarizeCertificate(certificate *core.Object, now int64) (result *core.Object, err error) {
	summary := core.NewObject()
	for _, key := range []string{"id", "tenantId", "authorityId", "serialNumber"} {
		summary.SetRaw(key, certificate.Get(key))
	}
	summary.SetRaw("names", core.CloneValue(certificate.Get("names")))
	for _, key := range []string{"keyType", "usage", "notBefore", "notAfter", "fingerprint"} {
		summary.SetRaw(key, certificate.Get(key))
	}
	summary.Set("status", certificateStatus(certificate, now))
	for _, key := range []string{"issuedAt", "issuedBy", "certificatePem"} {
		summary.SetRaw(key, certificate.Get(key))
	}
	for _, key := range []string{"commonName", "identityId", "spiffeId", "subordinateId", "revokedAt", "revocationReason"} {
		if value := certificate.Get(key); defined(value) {
			summary.SetRaw(key, value)
		}
	}
	return summary, nil
}

// AuthorityAttributes (pki.ts authorityAttributes): The attributes an authority presents to policies
// (`resource.{name}`).
func AuthorityAttributes(authority *core.Object) (result *core.Object, err error) {
	attributes := core.NewObject()
	attributes.SetRaw("authorityId", authority.Get("id"))
	attributes.SetRaw("authorityName", authority.Get("name"))
	attributes.SetRaw("authorityType", authority.Get("type"))
	attributes.SetRaw("authorityState", authority.Get("state"))
	if trustDomain := authority.Get("trustDomain"); truthy(trustDomain) {
		attributes.SetRaw("trustDomain", trustDomain)
	}
	return attributes, nil
}

// authorityAttributesOf is AuthorityAttributes without the (never failing) error.
func authorityAttributesOf(authority *core.Object) *core.Object {
	attributes, _ := AuthorityAttributes(authority)
	return attributes
}

var countryCode = regexp.MustCompile(`^[A-Z]{2}$`)

// DistinguishedName (pki.ts distinguishedName): A distinguished name: `commonName` required for authorities, every
// part within X.520 bounds.
func DistinguishedName(value any, requireCommonName bool) (result *core.Object, err error) {
	if isUndefined(value) && !requireCommonName {
		return core.NewObject(), nil
	}
	input, ok := value.(*core.Object)
	if !ok || input == nil {
		return nil, invalidInput("subject must be an object")
	}
	allowed := []string{"commonName", "organization", "organizationalUnit", "locality", "state", "country"}
	for _, key := range input.Keys() {
		if !containsString(allowed, key) {
			return nil, invalidInput("Unknown subject field " + key)
		}
	}
	part := func(key string, max int) (string, error) {
		item := input.Get(key)
		if isUndefined(item) {
			return "", nil
		}
		text, err := Text(item, "subject."+key, max)
		if err != nil {
			return "", err
		}
		return core.JSTrim(text), nil
	}
	name := core.NewObject()
	commonName, err := part("commonName", 64)
	if err != nil {
		return nil, err
	}
	if commonName != "" {
		name.Set("commonName", commonName)
	} else if requireCommonName {
		return nil, invalidInput("subject.commonName is required")
	}
	for _, entry := range []struct {
		key string
		max int
	}{{"organization", 64}, {"organizationalUnit", 64}, {"locality", 128}, {"state", 128}} {
		value, err := part(entry.key, entry.max)
		if err != nil {
			return nil, err
		}
		if value != "" {
			name.Set(entry.key, value)
		}
	}
	country, err := part("country", 2)
	if err != nil {
		return nil, err
	}
	if country != "" {
		if !countryCode.MatchString(country) {
			return nil, invalidInput("subject.country must be a two-letter ISO code")
		}
		name.Set("country", country)
	}
	return name, nil
}

var trustDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,253}[a-z0-9])?$`)

// TrustDomain (pki.ts trustDomain): a SPIFFE trust domain in lowercase ("" when value is undefined).
func TrustDomain(value any) (result string, err error) {
	if isUndefined(value) {
		return "", nil
	}
	text, err := Text(value, "trustDomain", 255)
	if err != nil {
		return "", err
	}
	domain := core.JSLower(text)
	if !trustDomainPattern.MatchString(domain) {
		return "", invalidInput("trustDomain must be lowercase letters, digits, dots, hyphens or underscores")
	}
	return domain, nil
}

// HttpURL (pki.ts httpUrl): an http(s) URL as the URL parser writes it ("" when value is undefined).
func HttpURL(value any, name string) (result string, err error) {
	if isUndefined(value) {
		return "", nil
	}
	raw, err := Text(value, name, 2048)
	if err != nil {
		return "", err
	}
	parsed, parseErr := auth.ParseFetchURL(raw)
	if parseErr != nil {
		return "", invalidInput(name + " must be an http(s) URL")
	}
	if parsed.Protocol != "http:" && parsed.Protocol != "https:" {
		return "", invalidInput(name + " must be an http(s) URL")
	}
	return parsed.Href, nil
}

var (
	permittedName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	leadingDot    = regexp.MustCompile(`^\.`)
	wildcardLabel = regexp.MustCompile(`^\*\.`)
)

// PermittedNames (pki.ts permittedNames): Name constraints: DNS suffixes (`example.internal`, matching it and its
// subdomains) and URI hosts. nil when value is undefined or names nothing.
func PermittedNames(value any) (result *core.Object, err error) {
	if isUndefined(value) {
		return nil, nil
	}
	input, ok := value.(*core.Object)
	if !ok || input == nil {
		return nil, invalidInput("permitted must be an object")
	}
	list := func(key string) ([]string, error) {
		items := input.Get(key)
		if isUndefined(items) {
			return nil, nil
		}
		array, ok := items.([]any)
		if !ok || len(array) > 50 {
			return nil, invalidInput("permitted." + key + " must list at most 50 names")
		}
		names := make([]string, len(array))
		for index, item := range array {
			text, err := Text(item, "permitted."+key, 253)
			if err != nil {
				return nil, err
			}
			name := replaceFirst(leadingDot, core.JSLower(text), "")
			if !permittedName.MatchString(name) {
				return nil, invalidInput("Invalid permitted name " + name)
			}
			names[index] = name
		}
		return names, nil
	}
	dnsNames, err := list("dnsNames")
	if err != nil {
		return nil, err
	}
	uriHosts, err := list("uriHosts")
	if err != nil {
		return nil, err
	}
	if len(dnsNames) == 0 && len(uriHosts) == 0 {
		return nil, nil
	}
	result = core.NewObject()
	if len(dnsNames) > 0 {
		result.Set("dnsNames", stringsOf(dnsNames))
	}
	if len(uriHosts) > 0 {
		result.Set("uriHosts", stringsOf(uriHosts))
	}
	return result, nil
}

func withinSuffix(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

// NamesPermitted (pki.ts namesPermitted): Checks names against the name constraints of an authority and every
// authority above it. A constraint list applies to its kind of name only: DNS names against `dnsNames`, URI hosts
// against `uriHosts`. A common name that looks like a host name counts as a DNS name, because TLS clients still fall
// back to it.
func NamesPermitted(chain []*core.Object, names *core.Object, commonName string) (result bool, err error) {
	set := sanSetOf(names)
	hostLike := []string{}
	if commonName != "" && DnsName.MatchString(core.JSLower(commonName)) {
		hostLike = append(hostLike, core.JSLower(commonName))
	}
	for _, authority := range chain {
		permitted, ok := authority.Get("permitted").(*core.Object)
		if !ok || permitted == nil {
			continue
		}
		suffixesOf := func(key string) ([]string, bool) {
			items, ok := permitted.Get(key).([]any)
			if !ok {
				return nil, false
			}
			out := make([]string, len(items))
			for index, item := range items {
				out[index] = jsString(item)
			}
			return out, true
		}
		matches := func(host string, suffixes []string) bool {
			for _, suffix := range suffixes {
				if withinSuffix(host, suffix) {
					return true
				}
			}
			return false
		}
		if suffixes, ok := suffixesOf("dnsNames"); ok {
			for _, name := range append(append([]string{}, set.dnsNames...), hostLike...) {
				if !matches(replaceFirst(wildcardLabel, name, ""), suffixes) {
					return false, nil
				}
			}
		}
		if suffixes, ok := suffixesOf("uriHosts"); ok {
			for _, uri := range set.uris {
				parsed, err := auth.ParseFetchURL(uri)
				if err != nil {
					return false, errors.New("Invalid URL")
				}
				host := core.JSLower(parsed.Hostname)
				if !matches(host, suffixes) {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

// AuthorityChain (pki.ts authorityChain): The authority and its parents up to the root.
func AuthorityChain(ctx context.Context, tx core.IamStore, authority *core.Object) (result []*core.Object, err error) {
	chain := []*core.Object{authority}
	current := authority
	for truthy(current.Get("parentId")) {
		parent, err := tx.Get(ctx, "pkiAuthorities", jsString(current.Get("parentId")))
		if err != nil {
			return nil, err
		}
		if parent == nil || !jsStrictEqual(parent.Get("tenantId"), authority.Get("tenantId")) || len(chain) > 10 {
			return nil, core.NewIamError("INVALID_HIERARCHY", "The authority chain is broken", 500)
		}
		chain = append(chain, parent)
		current = parent
	}
	return chain, nil
}

// AssertAuthorityUsable (pki.ts assertAuthorityUsable): Usable for signing: active, within its validity, and every
// authority above it active too.
func AssertAuthorityUsable(chain []*core.Object, now int64) (err error) {
	for _, authority := range chain {
		if authority.Get("state") != "active" {
			return core.NewIamError("AUTHORITY_UNAVAILABLE", "The certificate authority "+jsString(authority.Get("name"))+" is "+jsString(authority.Get("state")), 409)
		}
		if jsNumber(authority.Get("notAfter")) <= float64(now) {
			return core.NewIamError("AUTHORITY_UNAVAILABLE", "The certificate authority "+jsString(authority.Get("name"))+" has expired", 409)
		}
	}
	return nil
}

// FindAuthority (pki.ts findAuthority): the tenant's authority, or NOT_FOUND.
func FindAuthority(ctx context.Context, tx core.IamStore, tenantID string, authorityID any) (result *core.Object, err error) {
	id, err := Text(authorityID, "authorityId")
	if err != nil {
		return nil, err
	}
	authority, err := tx.Get(ctx, "pkiAuthorities", id)
	if err != nil {
		return nil, err
	}
	if authority == nil || authority.Get("tenantId") != tenantID {
		return nil, core.NewIamError("NOT_FOUND", "Certificate authority not found", 404)
	}
	return authority, nil
}

// AuthoritySigner (pki.ts authoritySigner): The signature an authority's KMS key makes over `data`, audited on the
// key as used by `pki` (with the principal, when one is given, as `use.principal`).
func AuthoritySigner(ctx context.Context, server *ServerContext, tx core.IamStore, authority *core.Object) (result func(context.Context, []byte, *Principal) ([]byte, error), err error) {
	return func(ctx context.Context, data []byte, principal *Principal) ([]byte, error) {
		use := core.NewObject("via", "pki")
		if principal != nil {
			use.SetRaw("principal", principal)
		}
		return KmsSignFor(ctx, server, tx, jsString(authority.Get("tenantId")), jsString(authority.Get("keyId")),
			jsNumber(authority.Get("keyVersion")), jsString(authority.Get("algorithm")), data, use)
	}, nil
}

// signWithAuthority signs data with an authority's key.
func signWithAuthority(ctx context.Context, server *ServerContext, tx core.IamStore, authority *core.Object, data []byte, principal *Principal) ([]byte, error) {
	signer, err := AuthoritySigner(ctx, server, tx, authority)
	if err != nil {
		return nil, err
	}
	return signer(ctx, data, principal)
}

const (
	crlLifetimeMs = 24 * 3_600_000
	crlRefreshMs  = 12 * 3_600_000
)

// CurrentCrl (pki.ts currentCrl): The authority's current CRL (DER), rebuilt when a certificate was revoked since
// the last one or half its lifetime has passed. Lists every revoked certificate that has not expired yet. The result
// holds `der` ([]byte), `thisUpdate`, `nextUpdate` and `crlNumber` (and `revision` when the cached one is served).
func CurrentCrl(ctx context.Context, server *ServerContext, tx core.IamStore, authority *core.Object) (result *core.Object, err error) {
	now := float64(server.Now())
	if cached, ok := authority.Get("crl").(*core.Object); ok && cached != nil &&
		jsStrictEqual(cached.Get("revision"), authority.Get("revision")) && now < jsNumber(cached.Get("thisUpdate"))+crlRefreshMs {
		der := core.NewObject()
		der.SetRaw("der", nodeBase64Decode(jsString(cached.Get("der"))))
		return cached.Spread(der), nil
	}
	found, err := tx.Find(ctx, "pkiCertificates", core.NewObject(
		"tenantId", authority.Get("tenantId"),
		"authorityId", authority.Get("id"),
		"status", "revoked",
	), nil)
	if err != nil {
		return nil, err
	}
	live := []*core.Object{}
	for _, certificate := range found {
		if jsNumber(certificate.Get("notAfter")) > now {
			live = append(live, certificate)
		}
	}
	sort.SliceStable(live, func(i, j int) bool {
		return jsLess(live[i].Get("serialNumber"), live[j].Get("serialNumber"))
	})
	revoked := make([]any, len(live))
	for index, certificate := range live {
		entry := core.NewObject("serialNumber", certificate.Get("serialNumber"), "revokedAt", coalesce(certificate.Get("revokedAt"), now))
		if reason := certificate.Get("revocationReason"); truthy(reason) {
			entry.SetRaw("reason", reason)
		}
		revoked[index] = entry
	}
	crlNumber := jsNumber(authority.Get("crlNumber")) + 1
	algorithm := jsString(authority.Get("algorithm"))
	spec := core.NewObject()
	spec.SetRaw("issuer", nodeBase64Decode(jsString(authority.Get("subjectDer"))))
	spec.Set("thisUpdate", now)
	spec.Set("nextUpdate", now+crlLifetimeMs)
	spec.Set("crlNumber", crlNumber)
	spec.SetRaw("authorityKeyId", nodeHexDecode(jsString(authority.Get("subjectKeyId"))))
	spec.SetRaw("revoked", revoked)
	tbs, err := TbsCertList(spec, algorithm)
	if err != nil {
		return nil, err
	}
	signature, err := signWithAuthority(ctx, server, tx, authority, tbs, nil)
	if err != nil {
		return nil, err
	}
	der, err := SignedStructure(tbs, algorithm, signature)
	if err != nil {
		return nil, err
	}
	crl := core.NewObject(
		"der", base64.StdEncoding.EncodeToString(der),
		"thisUpdate", now,
		"nextUpdate", now+crlLifetimeMs,
		"revision", authority.Get("revision"),
		"crlNumber", crlNumber,
	)
	if _, err := tx.Put(ctx, "pkiAuthorities", authority.Spread(core.NewObject("crlNumber", crlNumber, "crl", crl))); err != nil {
		return nil, err
	}
	result = core.NewObject()
	result.SetRaw("der", der)
	result.Set("thisUpdate", now)
	result.Set("nextUpdate", now+crlLifetimeMs)
	result.Set("crlNumber", crlNumber)
	return result, nil
}

// sanList is pki.ts sanList: the DNS or URI entries of a certificate's subjectAltName text.
func sanList(certificate *x509Certificate, prefix string) []any {
	out := []any{}
	for _, entry := range strings.Split(certificate.subjectAltNameText(), ", ") {
		if strings.HasPrefix(entry, prefix+":") {
			out = append(out, entry[len(prefix)+1:])
		}
	}
	return out
}

var (
	pemCertificates = regexp.MustCompile(`-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----`)
	leadingZeros    = regexp.MustCompile(`^0+`)
)

// stripLeadingZeros is `.replace(/^0+(?=.)/, ”)`: leading zeros, keeping the last character.
func stripLeadingZeros(value string) string {
	location := leadingZeros.FindStringIndex(value)
	if location == nil {
		return value
	}
	end := location[1]
	if end == len(value) {
		end--
	}
	return value[end:]
}

func certificateInvalid(message string) *core.IamError {
	return core.NewIamError("CERTIFICATE_INVALID", message, 401)
}

// VerifyCertificateChain (pki.ts verifyCertificateChain): Verifies a client or server certificate chain (leaf first,
// PEM concatenated or as a list) against one tenant's certificate authorities: every signature, path length,
// validity period, authority state and revocation, and for a workload certificate the standing of the identity it
// names. For mTLS: a server that terminates TLS passes the peer's certificate and gets the identity behind a
// workload certificate. options: `tenantId` (required), `usage` (`server` or `client`) and `at`.
func VerifyCertificateChain(ctx context.Context, server *ServerContext, chain any, options *core.Object) (result *core.Object, err error) {
	// Trust is per tenant: without a tenant, one organization's authority could vouch for another's names.
	tenantID, err := Text(options.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	entries, isList := chain.([]any)
	if list, ok := chain.([]string); ok {
		entries, isList = stringsOf(list), true
	}
	if !isList {
		entries = []any{chain}
	}
	pems := []string{}
	for _, entry := range entries {
		text, ok := entry.(string)
		if !ok {
			return nil, errors.New("entry.match is not a function")
		}
		pems = append(pems, pemCertificates.FindAllString(text, -1)...)
	}
	if len(pems) > 10 {
		pems = pems[:10]
	}
	if len(pems) == 0 {
		return nil, certificateInvalid("No certificate was presented")
	}
	leaf, err := parseCertificatePem(pems[0])
	if err != nil {
		return nil, certificateInvalid("The certificate cannot be read")
	}
	now := float64(server.Now())
	if at := options.Get("at"); !nullish(at) {
		now = jsNumber(at)
	}
	serialNumber := stripLeadingZeros(core.JSLower(leaf.serialNumber()))
	usage := options.Get("usage")
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		found, err := tx.Find(ctx, "pkiCertificates", core.NewObject("tenantId", tenantID, "uniqueKey", "serial:"+serialNumber), nil)
		if err != nil {
			return nil, err
		}
		var record *core.Object
		for _, candidate := range found {
			der, _ := CertificateDer(jsString(candidate.Get("certificatePem")))
			if string(der) == string(leaf.raw) {
				record = candidate
				break
			}
		}
		if record == nil {
			return nil, certificateInvalid("The certificate was not issued here")
		}
		if record.Get("status") == "revoked" {
			return nil, certificateInvalid("The certificate has been revoked")
		}
		if record.Get("usage") == "ca" {
			return nil, certificateInvalid("A CA certificate cannot authenticate")
		}
		if truthy(usage) && record.Get("usage") != "both" && !jsStrictEqual(record.Get("usage"), usage) {
			return nil, certificateInvalid("The certificate is not for " + jsString(usage) + " use")
		}
		if leaf.notBefore > now || leaf.notAfter <= now {
			return nil, certificateInvalid("The certificate is not valid at this time")
		}
		authority, err := tx.Get(ctx, "pkiAuthorities", jsString(record.Get("authorityId")))
		if err != nil {
			return nil, err
		}
		if authority == nil || !jsStrictEqual(authority.Get("tenantId"), record.Get("tenantId")) {
			return nil, certificateInvalid("The issuing authority is gone")
		}
		// Walk the stored chain (not whatever the client sent): each link must verify, be live, and allow the number
		// of authorities below it (its path length).
		links, err := AuthorityChain(ctx, tx, authority)
		if err != nil {
			return nil, err
		}
		child := leaf
		for index, link := range links {
			issuer, err := parseCertificatePem(jsString(link.Get("certificatePem")))
			if err != nil {
				return nil, err
			}
			issuerKey, err := issuer.publicKey()
			if err != nil {
				return nil, err
			}
			if !child.checkIssued(issuer) || !child.verify(issuerKey) {
				return nil, certificateInvalid("The certificate chain does not verify")
			}
			if link.Get("state") != "active" || jsNumber(link.Get("notAfter")) <= now || jsNumber(link.Get("notBefore")) > now+60_000 {
				return nil, certificateInvalid("An issuing authority is not active")
			}
			if pathLength := link.Get("pathLength"); defined(pathLength) && float64(index) > jsNumber(pathLength) {
				return nil, certificateInvalid("The chain exceeds a path length")
			}
			child = issuer
		}
		rootKey, err := child.publicKey()
		if err != nil {
			return nil, err
		}
		if !child.verify(rootKey) {
			return nil, certificateInvalid("The root does not verify")
		}
		// A workload certificate is only as good as the identity it names.
		if identityID := record.Get("identityId"); truthy(identityID) {
			identity, err := tx.Get(ctx, "identities", jsString(identityID))
			if err != nil {
				return nil, err
			}
			if identity == nil || !jsStrictEqual(identity.Get("tenantId"), record.Get("tenantId")) || identity.Get("status") != "active" ||
				server.IdentityExpired(identity) || truthy(member(identity.Get("agent"), "suspended")) {
				return nil, certificateInvalid("The identity it names is no longer active")
			}
		}
		verified := core.NewObject()
		for _, key := range []string{"tenantId", "authorityId", "serialNumber", "fingerprint"} {
			verified.SetRaw(key, record.Get(key))
		}
		verified.Set("subject", leaf.subjectText())
		verified.Set("dnsNames", sanList(leaf, "DNS"))
		verified.Set("uris", sanList(leaf, "URI"))
		verified.SetRaw("notAfter", record.Get("notAfter"))
		if spiffe := record.Get("spiffeId"); truthy(spiffe) {
			verified.SetRaw("spiffeId", spiffe)
		}
		if identityID := record.Get("identityId"); truthy(identityID) {
			verified.SetRaw("identityId", identityID)
		}
		return verified, nil
	})
}

// SpkiOf (pki.ts spkiOf): The DER SubjectPublicKeyInfo of a KMS key version's public key.
func SpkiOf(publicKeyPem string) (result []byte, err error) {
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		return nil, errors.New("Invalid public key")
	}
	var key any
	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case "PRIVATE KEY":
		var private any
		if private, err = x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			key = publicOf(private)
		}
	case "EC PRIVATE KEY":
		var private any
		if private, err = x509.ParseECPrivateKey(block.Bytes); err == nil {
			key = publicOf(private)
		}
	case "RSA PRIVATE KEY":
		var private any
		if private, err = x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			key = publicOf(private)
		}
	default:
		err = errors.New("Unsupported key format")
	}
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(key)
}

// publicOf is the public half of a private key.
func publicOf(private any) any {
	if signer, ok := private.(interface{ Public() any }); ok {
		return signer.Public()
	}
	return nil
}

// CertificatePem (pki.ts certificatePem): the PEM of a DER certificate.
func CertificatePem(der []byte) (result string, err error) {
	return Pem("CERTIFICATE", der)
}

// CrlPem (pki.ts crlPem): the PEM of a DER CRL.
func CrlPem(der []byte) (result string, err error) {
	return Pem("X509 CRL", der)
}

// AlgorithmForSpec (pki.ts algorithmForSpec): The X.509 signature algorithm a KMS signing key uses for certificates.
func AlgorithmForSpec(spec string) (result string, err error) {
	switch {
	case spec == "ecc-p256":
		return "ES256", nil
	case spec == "ecc-p384":
		return "ES384", nil
	case spec == "ed25519":
		return "EdDSA", nil
	case strings.HasPrefix(spec, "rsa-"):
		return "RS256", nil
	}
	return "", invalidInput("A certificate authority needs an ECDSA, Ed25519 or RSA signing key")
}

// hexOf is Buffer#toString('hex').
func hexOf(bytes []byte) string { return hex.EncodeToString(bytes) }

// infinity is JavaScript Infinity.
var infinity = math.Inf(1)
