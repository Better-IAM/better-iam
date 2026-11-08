package server

// The private certificate authority (pki.go, api_pki.go), after tests/pki.test.ts and tests/pki-security.test.ts.
// Signing goes through KMS (kms.go, another unit): authorities and certificates are seeded here the way
// createAuthority and issueCertificate store them, signed with test keys, so every decision, refusal, read,
// revocation and verification runs; the TypeScript flows that create authorities and issue certificates through KMS
// are ported as well and end with a skip while a step reaches a KMS stub.

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// pkiOrg is an organization with a seeded root (path length 1) and an issuing intermediate (trust domain acme.test,
// name constraints internal/localhost and acme.test, a CRL URL), as tests/pki.test.ts `authorities` creates them.
type pkiOrg struct {
	*trustOrg
	root, issuing             *core.Object
	rootAuthority, issuingKey *testAuthority
}

func newPkiOrg(t *testing.T) *pkiOrg {
	t.Helper()
	f := &pkiOrg{trustOrg: newTrustOrg(t, nil)}
	one := 1.0
	f.rootAuthority = makeTestAuthority(t, "Acme Root CA", nil, &one, nil, f.now())
	f.root = f.seedAuthority(f.tenantID, "Acme Root", f.rootAuthority, nil, &one, "", "", nil)
	permitted := core.NewObject("dnsNames", items("internal", "localhost"), "uriHosts", items("acme.test"))
	zero := 0.0
	f.advance(1)
	f.issuingKey = makeTestAuthority(t, "Acme Workload CA", f.rootAuthority, &zero, permitted, f.now())
	f.issuing = f.seedAuthority(f.tenantID, "Acme Workloads", f.issuingKey, f.root, &zero, "acme.test", "https://pki.acme.test/crl/workloads.crl", permitted)
	return f
}

// seedAuthority stores an authority (and, under a parent, its certificate) as createAuthority does.
func (f *pkiOrg) seedAuthority(tenantID, name string, made *testAuthority, parent *core.Object, pathLength *float64, trustDomain, crlURL string, permitted *core.Object) *core.Object {
	f.t.Helper()
	read := must(parseCertificateDer(made.der))
	subject := core.NewObject("commonName", strings.TrimPrefix(read.subjectText(), "CN="))
	authorityID := ID()
	keyID := f.seedAuthorityKey(tenantID, authorityID, made)
	authority := core.NewObject(
		"id", authorityID, "tenantId", tenantID, "uniqueKey", "name:"+core.JSLower(name), "name", name,
		"type", map[bool]string{true: "intermediate", false: "root"}[parent != nil], "subject", subject,
		"subjectDer", base64.StdEncoding.EncodeToString(made.subjectDer), "subjectKeyId", hexOf(made.keyID),
		"keyId", keyID, "keyVersion", 1.0, "algorithm", made.algorithm, "certificatePem", made.pem,
		"serialNumber", made.serial, "notBefore", f.now()-pkiClockSkewMs, "notAfter", made.notAfter, "state", "active",
		"maxValiditySeconds", 90.0*86_400, "defaultValiditySeconds", 86_400.0, "revision", 0.0, "crlNumber", 0.0,
		"createdAt", f.now(), "createdBy", f.ownerID, "updatedAt", f.now(),
	)
	if parent != nil {
		authority.Set("parentId", parent.Get("id"))
	}
	if pathLength != nil {
		authority.Set("pathLength", *pathLength)
	}
	if trustDomain != "" {
		authority.Set("trustDomain", trustDomain)
	}
	if crlURL != "" {
		authority.Set("crlUrl", crlURL)
	}
	if permitted != nil {
		authority.Set("permitted", permitted)
	}
	f.seed("pkiAuthorities", authority)
	if parent != nil {
		f.seed("pkiCertificates", core.NewObject(
			"id", ID(), "tenantId", tenantID, "uniqueKey", "serial:"+made.serial, "authorityId", parent.Get("id"),
			"serialNumber", made.serial, "commonName", subject.Get("commonName"), "names", sanSet{}.object(),
			"keyType", "ecc-p256", "usage", "ca", "notBefore", f.now()-pkiClockSkewMs, "notAfter", made.notAfter,
			"certificatePem", made.pem, "fingerprint", must(Sha256Fingerprint(made.der)), "subordinateId", authority.Get("id"),
			"status", "valid", "issuedAt", f.now(), "issuedBy", f.ownerID,
		))
	}
	return authority
}

// seedAuthorityKey stores the authority's test key as a KMS key managed by pki (version 1), as createAuthority's
// CreateServiceKey does, so signing through KmsSignFor uses the key the seeded certificate certifies.
func (f *pkiOrg) seedAuthorityKey(tenantID, authorityID string, made *testAuthority) string {
	f.t.Helper()
	keyID := ID()
	privateDer := must(x509.MarshalPKCS8PrivateKey(made.key))
	publicDer := must(x509.MarshalPKIXPublicKey(made.key.Public()))
	f.seed("kmsKeys", core.NewObject(
		"id", keyID, "tenantId", tenantID, "description", "Certificate authority", "keySpec", "ecc-p256",
		"keyUsage", "sign", "state", "enabled", "currentVersion", 1.0, "tags", core.NewObject(),
		"managedBy", "pki", "managedId", authorityID, "createdAt", f.now(), "createdBy", f.ownerID, "updatedAt", f.now(),
	))
	f.seed("kmsKeyVersions", core.NewObject(
		"id", ID(), "tenantId", tenantID, "uniqueKey", keyID+":1", "keyId", keyID, "version", 1.0, "wrapper", "secret",
		"materialSealed", auth.EncryptSecret(kmsPem("PRIVATE KEY", privateDer), f.iam.Context.Options.Secret, kmsVersionContext(keyID, 1)),
		"publicKeyPem", kmsPem("PUBLIC KEY", publicDer), "createdAt", f.now(), "origin", "create",
	))
	return keyID
}

// seedLeaf issues a leaf under the issuing authority as issue does, and stores its record.
func (f *pkiOrg) seedLeaf(key crypto.Signer, commonName string, names *core.Object, usage string, pairs ...any) *core.Object {
	f.t.Helper()
	notAfter := f.now() + 3_600_000
	der, serial := makeTestLeaf(f.t, f.issuingKey, key, commonName, names, usage, f.now(), notAfter, "https://pki.acme.test/crl/workloads.crl")
	record := core.NewObject(
		"id", ID(), "tenantId", f.tenantID, "uniqueKey", "serial:"+serial, "authorityId", f.issuing.Get("id"),
		"serialNumber", serial, "names", names, "keyType", "ecc-p256", "usage", usage,
		"notBefore", f.now()-pkiClockSkewMs, "notAfter", notAfter, "certificatePem", must(CertificatePem(der)),
		"fingerprint", must(Sha256Fingerprint(der)), "status", "valid", "issuedAt", f.now(), "issuedBy", f.ownerID,
	)
	if commonName != "" {
		record.Set("commonName", commonName)
	}
	for index := 0; index+1 < len(pairs); index += 2 {
		record.Set(pairs[index].(string), pairs[index+1])
	}
	f.seed("pkiCertificates", record)
	return record
}

func (f *pkiOrg) issueCertificate(credential core.CredentialInput, pairs ...any) (*core.Object, error) {
	out, err := f.iam.API.Pki.IssueCertificate(f.ctx, credential, Input[apitypes.PkiIssueCertificateInput](body(append([]any{"tenantId", f.tenantID, "authorityId", f.issuing.Get("id")}, pairs...)...)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

// memberWith is a member holding one inline role (tests/pki-security.test.ts memberWith).
func (f *pkiOrg) memberWith(name string, statements ...*core.Object) (*core.Object, core.CredentialInput) {
	f.t.Helper()
	person, credential := f.person(f.tenantID, name)
	f.bind(f.tenantID, f.role(f.tenantID, name+" pki", statements...), "identity", jsString(person.Get("id")))
	return person, credential
}

// pkiAudit is the tenant's audit events of an action.
func (f *pkiOrg) pkiAudit(action string) []*core.Object {
	events := []*core.Object{}
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if event.Get("action") == action {
			events = append(events, event)
		}
	}
	// In the order they were written.
	sort.SliceStable(events, func(i, j int) bool { return jsNumber(events[i].Get("sequence")) < jsNumber(events[j].Get("sequence")) })
	return events
}

// skipOnKms ends the test with a skip when a step reached another unit's NOT_IMPLEMENTED stub (KMS signing).
func skipOnKms(t *testing.T, err error) {
	t.Helper()
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
		t.Skip("blocked by a stub of another unit: " + known.Message)
	}
}

func TestPkiValidatesInputBeforeTheEnvelope(t *testing.T) {
	f := newPkiOrg(t)
	api := f.iam.API.Pki
	nobody := core.CredentialInput{Token: "biam_ses_not-a-real-token"}
	create := func(pairs ...any) error {
		_, err := api.CreateAuthority(f.ctx, nobody, Input[apitypes.PkiCreateAuthorityInput](body(append([]any{"tenantId", f.tenantID}, pairs...)...)))
		return err
	}
	subject := core.NewObject("commonName", "Acme")
	expectError(t, create("subject", subject), "INVALID_INPUT", "Invalid name")
	expectError(t, create("name", strings.Repeat("n", 129), "subject", subject), "INVALID_INPUT", "Invalid name")
	expectError(t, create("name", "A", "type", "leaf", "subject", subject), "INVALID_INPUT", "type must be root or intermediate")
	expectError(t, create("name", "A", "type", "intermediate", "subject", subject), "INVALID_INPUT", "An intermediate authority needs a parentId; a root has none")
	expectError(t, create("name", "A", "type", "root", "parentId", "x", "subject", subject), "INVALID_INPUT", "An intermediate authority needs a parentId; a root has none")
	expectError(t, create("name", "A"), "INVALID_INPUT", "subject must be an object")
	expectError(t, create("name", "A", "subject", core.NewObject("email", "a@b")), "INVALID_INPUT", "Unknown subject field email")
	expectError(t, create("name", "A", "subject", core.NewObject("organization", "Acme")), "INVALID_INPUT", "subject.commonName is required")
	expectError(t, create("name", "A", "subject", core.NewObject("commonName", "  ")), "INVALID_INPUT", "Invalid subject.commonName")
	expectError(t, create("name", "A", "subject", core.NewObject("commonName", "A", "country", "us")), "INVALID_INPUT", "subject.country must be a two-letter ISO code")
	expectError(t, create("name", "A", "subject", core.NewObject("commonName", "A", "country", "USA")), "INVALID_INPUT", "Invalid subject.country")
	// With a keyId, no key spec is parsed (that is KMS's), so the remaining checks run here.
	keyed := func(pairs ...any) error {
		return create(append([]any{"name", "A", "subject", subject, "keyId", "key"}, pairs...)...)
	}
	expectError(t, keyed("pathLength", 11.0), "INVALID_INPUT", "Invalid pathLength")
	expectError(t, keyed("trustDomain", "acme test"), "INVALID_INPUT", "trustDomain must be lowercase letters, digits, dots, hyphens or underscores")
	expectError(t, keyed("crlUrl", "ftp://pki.acme.test/crl"), "INVALID_INPUT", "crlUrl must be an http(s) URL")
	expectError(t, keyed("crlUrl", "not a url"), "INVALID_INPUT", "crlUrl must be an http(s) URL")
	expectError(t, keyed("permitted", items("internal")), "INVALID_INPUT", "permitted must be an object")
	expectError(t, keyed("permitted", core.NewObject("dnsNames", "internal")), "INVALID_INPUT", "permitted.dnsNames must list at most 50 names")
	expectError(t, keyed("permitted", core.NewObject("uriHosts", items("bad host"))), "INVALID_INPUT", "Invalid permitted name bad host")
	expectError(t, keyed("maxValiditySeconds", 825.0*86_400+1), "INVALID_INPUT", "Invalid maxValiditySeconds")
	expectError(t, keyed("maxValiditySeconds", 3600.0, "defaultValiditySeconds", 7200.0), "INVALID_INPUT", "Invalid defaultValiditySeconds")
	// Valid input reaches authentication.
	expectCode(t, keyed("trustDomain", "Acme.Test", "permitted", core.NewObject("dnsNames", items(".Internal"))), "UNAUTHENTICATED")

	_, err := api.IssueCertificate(f.ctx, nobody, Input[apitypes.PkiIssueCertificateInput](body("tenantId", f.tenantID, "usage", "mail")))
	expectError(t, err, "INVALID_INPUT", "usage must be server, client or both")
	for _, reason := range []any{"certificateHold", "lost", 1.0} {
		_, err = api.RevokeCertificate(f.ctx, nobody, Input[apitypes.PkiRevokeCertificateInput](body("tenantId", f.tenantID, "serialNumber", "ab", "reason", reason)))
		expectError(t, err, "INVALID_INPUT", "Unknown revocation reason")
	}
	_, err = api.UpdateAuthority(f.ctx, nobody, Input[apitypes.PkiUpdateAuthorityInput](body("tenantId", f.tenantID, "authorityId", "x", "state", "revoked")))
	expectError(t, err, "INVALID_INPUT", "state must be active or disabled")
	_, err = api.ListCertificates(f.ctx, nobody, Input[apitypes.PkiListCertificatesInput](body("tenantId", f.tenantID, "limit", 0.0)))
	expectError(t, err, "INVALID_INPUT", "Invalid limit")
}

func TestPkiRefusesOtherTenantsBeforeAnyLookup(t *testing.T) {
	f := newPkiOrg(t)
	_, outsider := f.organization("Beta", "owner@beta.test")
	_, err := f.iam.API.Pki.GetAuthority(f.ctx, outsider, Input[apitypes.PkiGetAuthorityInput](body("tenantId", f.tenantID, "authorityId", f.issuing.Get("id"))))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	events := f.pkiAudit("iam:pki:read")
	if len(events) != 1 || events[0].Get("resourceId") != "pki" || stringify(events[0].Get("metadata")) != `{"reason":"tenant"}` {
		t.Fatalf("refusal = %s", stringify(events))
	}
	_, err = f.iam.API.Pki.GetAuthority(f.ctx, f.owner, Input[apitypes.PkiGetAuthorityInput](body("tenantId", f.tenantID, "authorityId", "missing")))
	expectError(t, err, "NOT_FOUND", "Certificate authority not found")
	_, err = f.iam.API.Pki.GetAuthority(f.ctx, f.owner, Input[apitypes.PkiGetAuthorityInput](body("tenantId", f.tenantID, "authorityId", 42.0)))
	expectError(t, err, "INVALID_INPUT", "Invalid authorityId")
}

func TestPkiReadsAuthoritiesCertificatesAndTheTrustBundle(t *testing.T) {
	f := newPkiOrg(t)
	api := f.iam.API.Pki
	listed := answerList(api.ListAuthorities(f.ctx, f.owner, Input[apitypes.PkiListAuthoritiesInput](body("tenantId", f.tenantID))))
	if strings.Join(pluck(listed, "name"), ",") != "Acme Root,Acme Workloads" {
		t.Fatalf("listed = %v", pluck(listed, "name"))
	}
	issuing := answerObject(api.GetAuthority(f.ctx, f.owner, Input[apitypes.PkiGetAuthorityInput](body("tenantId", f.tenantID, "authorityId", f.issuing.Get("id")))))
	want := `{"id":"` + jsString(f.issuing.Get("id")) + `","tenantId":"` + f.tenantID + `","name":"Acme Workloads","type":"intermediate","subject":{"commonName":"Acme Workload CA"},` +
		`"keyId":"` + jsString(f.issuing.Get("keyId")) + `","keyVersion":1,"algorithm":"ES256","certificatePem":` + stringify(f.issuing.Get("certificatePem")) +
		`,"serialNumber":"` + jsString(f.issuing.Get("serialNumber")) + `","notBefore":` + stringify(f.issuing.Get("notBefore")) + `,"notAfter":` + stringify(f.issuing.Get("notAfter")) +
		`,"state":"active","maxValiditySeconds":7776000,"defaultValiditySeconds":86400,"createdAt":` + stringify(f.now()) + `,"createdBy":"` + f.ownerID +
		`","parentId":"` + jsString(f.root.Get("id")) + `","pathLength":0,"trustDomain":"acme.test","crlUrl":"https://pki.acme.test/crl/workloads.crl","permitted":{"dnsNames":["internal","localhost"],"uriHosts":["acme.test"]}}`
	if stringify(issuing) != want {
		t.Fatalf("summary =\n%s\nwant\n%s", stringify(issuing), want)
	}
	// The intermediate's own certificate is recorded under the root, so the root can revoke it.
	underRoot := answerObject(api.ListCertificates(f.ctx, f.owner, Input[apitypes.PkiListCertificatesInput](body("tenantId", f.tenantID, "authorityId", f.root.Get("id")))))
	certificates := underRoot.Get("certificates").([]any)
	if len(certificates) != 1 || member(certificates[0], "usage") != "ca" || member(certificates[0], "subordinateId") != f.issuing.Get("id") || underRoot.Get("total") != 1.0 {
		t.Fatalf("under root = %s", stringify(underRoot))
	}
	// Only roots are trust anchors; intermediates travel in each server's chain.
	bundle := answerObject(api.Bundle(f.ctx, f.owner, Input[apitypes.PkiBundleInput](body("tenantId", f.tenantID))))
	if bundle.Get("authorities") != 1.0 || bundle.Get("pem") != f.root.Get("certificatePem") {
		t.Fatalf("bundle = %s", stringify(bundle))
	}
	if runtime := must(f.iam.Pki.Bundle(f.ctx, f.tenantID)); runtime != bundle.Get("pem") {
		t.Fatalf("runtime bundle = %s", runtime)
	}
	var listedEvent *core.Object
	for _, event := range f.pkiAudit("iam:pki:read") {
		if event.Get("resourceId") == "pki" {
			listedEvent = event
		}
	}
	if listedEvent == nil || stringify(listedEvent.Get("metadata")) != `{"listed":1}` {
		t.Fatalf("listed event = %s", stringify(listedEvent))
	}
	// Certificates by serial number: hex, colons and leading zeros allowed.
	leaf := f.seedLeaf(pkiKey(t, "p256"), "a.internal", sanSet{dnsNames: []string{"a.internal"}}.object(), "server")
	serial := jsString(leaf.Get("serialNumber"))
	var colons []string
	for index := 0; index < len(serial); index += 2 {
		colons = append(colons, strings.ToUpper(serial[index:index+2]))
	}
	got := answerObject(api.GetCertificate(f.ctx, f.owner, Input[apitypes.PkiGetCertificateInput](body("tenantId", f.tenantID, "serialNumber", "00:"+strings.Join(colons, ":")))))
	if got.Get("id") != leaf.Get("id") || got.Get("status") != "valid" || got.Get("commonName") != "a.internal" {
		t.Fatalf("certificate = %s", stringify(got))
	}
	_, err := api.GetCertificate(f.ctx, f.owner, Input[apitypes.PkiGetCertificateInput](body("tenantId", f.tenantID, "serialNumber", "xyz")))
	expectError(t, err, "INVALID_INPUT", "serialNumber must be hexadecimal")
	_, err = api.GetCertificate(f.ctx, f.owner, Input[apitypes.PkiGetCertificateInput](body("tenantId", f.tenantID, "serialNumber", "abcdef")))
	expectError(t, err, "NOT_FOUND", "Certificate not found")
	// Expired certificates read as expired; listing pages newest first.
	f.advance(2 * 3_600_000)
	f.seedLeaf(pkiKey(t, "p256"), "b.internal", sanSet{dnsNames: []string{"b.internal"}}.object(), "both")
	page := answerObject(api.ListCertificates(f.ctx, f.owner, Input[apitypes.PkiListCertificatesInput](body("tenantId", f.tenantID, "authorityId", f.issuing.Get("id"), "limit", 1.0))))
	first := page.Get("certificates").([]any)
	if page.Get("total") != 2.0 || len(first) != 1 || member(first[0], "commonName") != "b.internal" {
		t.Fatalf("page = %s", stringify(page))
	}
	expired := answerObject(api.ListCertificates(f.ctx, f.owner, Input[apitypes.PkiListCertificatesInput](body("tenantId", f.tenantID, "status", "expired"))))
	if expired.Get("total") != 1.0 || member(expired.Get("certificates").([]any)[0], "commonName") != "a.internal" {
		t.Fatalf("expired = %s", stringify(expired))
	}
	offset := answerObject(api.ListCertificates(f.ctx, f.owner, Input[apitypes.PkiListCertificatesInput](body("tenantId", f.tenantID, "offset", 5.0))))
	if stringify(offset.Get("certificates")) != "[]" || offset.Get("total") != 3.0 {
		t.Fatalf("offset = %s", stringify(offset))
	}
}

func TestPkiUpdatesAuthorities(t *testing.T) {
	f := newPkiOrg(t)
	api := f.iam.API.Pki
	update := func(pairs ...any) (*core.Object, error) {
		out, err := api.UpdateAuthority(f.ctx, f.owner, Input[apitypes.PkiUpdateAuthorityInput](body(append([]any{"tenantId", f.tenantID, "authorityId", f.issuing.Get("id")}, pairs...)...)))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	f.advance(1000)
	updated := must(update("state", "disabled", "maxValiditySeconds", 3600.0, "crlUrl", "https://pki.acme.test/new.crl"))
	if updated.Get("state") != "disabled" || updated.Get("maxValiditySeconds") != 3600.0 || updated.Get("defaultValiditySeconds") != 3600.0 || updated.Get("crlUrl") != "https://pki.acme.test/new.crl" {
		t.Fatalf("updated = %s", stringify(updated))
	}
	stored := f.record("pkiAuthorities", jsString(f.issuing.Get("id")))
	if stored.Get("updatedAt") != f.now() || stored.Get("state") != "disabled" {
		t.Fatalf("stored = %s", stringify(stored))
	}
	events := f.pkiAudit("iam:pki:update")
	if stringify(events[len(events)-1].Get("metadata")) != `{"authorityId":"`+jsString(f.issuing.Get("id"))+`","state":"disabled","maxValiditySeconds":3600,"defaultValiditySeconds":3600,"crlUrl":"https://pki.acme.test/new.crl"}` {
		t.Fatalf("metadata = %s", stringify(events[len(events)-1].Get("metadata")))
	}
	// A disabled authority issues nothing.
	_, err := f.issueCertificate(f.owner, "csr", pkiCsr(t, pkiKey(t, "p256"), "dnsNames", items("a.internal")))
	expectError(t, err, "AUTHORITY_UNAVAILABLE", "The certificate authority Acme Workloads is disabled")
	cleared := must(update("state", "active", "crlUrl", nil))
	if cleared.Has("crlUrl") || cleared.Get("state") != "active" {
		t.Fatalf("cleared = %s", stringify(cleared))
	}
	events = f.pkiAudit("iam:pki:update")
	if stringify(events[len(events)-1].Get("metadata")) != `{"authorityId":"`+jsString(f.issuing.Get("id"))+`","state":"active","maxValiditySeconds":3600,"defaultValiditySeconds":3600,"crlUrl":null}` {
		t.Fatalf("metadata = %s", stringify(events[len(events)-1].Get("metadata")))
	}
	_, err = update("defaultValiditySeconds", 7200.0)
	expectError(t, err, "INVALID_INPUT", "Invalid defaultValiditySeconds")
	f.patch("pkiAuthorities", jsString(f.issuing.Get("id")), core.NewObject("state", "revoked"))
	_, err = update("state", "active")
	expectError(t, err, "AUTHORITY_UNAVAILABLE", "A revoked authority cannot change")
}

func TestPkiDecidesEveryNameOnACertificateAndEnforcesNameConstraintsAndSpiffeRules(t *testing.T) {
	f := newPkiOrg(t)
	_, pat := f.memberWith("pat", allow(items("iam:pki:issue"), items("iam/pki/*"), "conditions", core.NewObject(
		"StringLike", core.NewObject("resource.name", items("*.payments.internal", "payments.internal")),
		"NumericLessThanEquals", core.NewObject("resource.validitySeconds", 86400.0),
	)))
	csr := func(commonName string, dnsNames ...any) string {
		pairs := []any{}
		if commonName != "" {
			pairs = append(pairs, "subject", core.NewObject("commonName", commonName))
		}
		if len(dnsNames) > 0 {
			pairs = append(pairs, "dnsNames", dnsNames)
		}
		return pkiCsr(t, pkiKey(t, "p256"), pairs...)
	}
	// One name outside the policy refuses the whole certificate.
	_, err := f.issueCertificate(pat, "csr", csr("", "api.payments.internal", "admin.internal"))
	expectError(t, err, "ACCESS_DENIED", "You may not certify admin.internal")
	// Validity is part of the decision too.
	_, err = f.issueCertificate(pat, "csr", csr("", "api.payments.internal"), "validitySeconds", 7.0*86400)
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	// Name constraints bind even the owner: `.internal` and `localhost` only.
	_, err = f.issueCertificate(f.owner, "csr", csr("", "www.example.com"))
	expectError(t, err, "NAME_NOT_PERMITTED", "A requested name is outside the authority's name constraints")
	_, err = f.issueCertificate(f.owner, "csr", pkiCsr(t, pkiKey(t, "p256"), "uris", items("spiffe://other.test/x")))
	expectError(t, err, "NAME_NOT_PERMITTED", "This authority issues SPIFFE IDs only in acme.test")
	_, err = f.issueCertificate(f.owner, "csr", pkiCsr(t, pkiKey(t, "p256"), "uris", items("spiffe://acme.test/a", "https://acme.test/b")))
	expectError(t, err, "INVALID_INPUT", "A SPIFFE certificate carries exactly one URI")
	// Validity beyond the authority's maximum is refused outright.
	_, err = f.issueCertificate(f.owner, "csr", csr("", "a.internal"), "validitySeconds", 400.0*86400)
	expectError(t, err, "INVALID_INPUT", "Invalid validitySeconds")
	// Identity paths are reserved for the identities themselves.
	_, err = f.issueCertificate(f.owner, "csr", pkiCsr(t, pkiKey(t, "p256"), "uris", items("spiffe://acme.test/service/someone-else")))
	expectError(t, err, "NAME_NOT_PERMITTED", "spiffe://acme.test/service/… names an identity; it is issued only to that identity (requestCertificate)")
	// The common name must be one of the alternative names, and name constraints cover it.
	_, err = f.issueCertificate(f.owner, "csr", csr("www.example.com", "api.internal"))
	expectError(t, err, "INVALID_INPUT", "The common name must be one of the subject alternative names")
	_, err = f.issueCertificate(f.owner, "csr", csr("www.example.com"))
	expectError(t, err, "NAME_NOT_PERMITTED", "A requested name is outside the authority's name constraints")
	_, err = f.issueCertificate(f.owner, "csr", csr(""))
	expectError(t, err, "INVALID_INPUT", "A certificate needs a common name or at least one name")
	// Explicit names override the request's; an explicit common name is trimmed.
	_, err = f.issueCertificate(f.owner, "csr", csr("a.internal", "a.internal"), "dnsNames", items("b.internal"), "commonName", " c.internal ")
	expectError(t, err, "INVALID_INPUT", "The common name must be one of the subject alternative names")
	// Refusals after authorization are audited with their reason; the first refusal is the policy's.
	reasons := map[string]int{}
	for _, event := range f.pkiAudit("iam:pki:issue") {
		if event.Get("outcome") == "deny" {
			reasons[jsString(member(event.Get("metadata"), "reason"))]++
		}
	}
	if reasons["refused"] != 1 || reasons["name-not-permitted"] < 3 || reasons["invalid-input"] < 1 {
		t.Fatalf("reasons = %v", reasons)
	}
	// What the policy allows is issued (signing is KMS's).
	issued, err := f.issueCertificate(pat, "csr", csr("api.payments.internal", "api.payments.internal"))
	skipOnKms(t, err)
	if err != nil || !truthy(issued.Get("serialNumber")) {
		t.Fatalf("issued = %v %v", issued, err)
	}
}

func TestPkiRefusesRequestsThatDoNotProveTheKeyAndParsesOnlyForTenantCallers(t *testing.T) {
	f := newPkiOrg(t)
	good := pkiCsr(t, pkiKey(t, "p256"), "dnsNames", items("a.internal"))
	block, _ := pem.Decode([]byte(good))
	block.Bytes[len(block.Bytes)-5] ^= 0xff
	_, err := f.issueCertificate(f.owner, "csr", string(pem.EncodeToMemory(block)))
	expectError(t, err, "INVALID_CSR", "The request signature does not verify with its key")
	_, err = f.issueCertificate(f.owner, "csr", "not a csr")
	expectCode(t, err, "INVALID_CSR")
	events := f.pkiAudit("iam:pki:issue")
	if len(events) != 0 {
		t.Fatalf("a request refused while locating the target is not a decision: %s", stringify(events))
	}
	// A malformed request from someone without a valid credential never reaches the parser.
	_, err = f.issueCertificate(core.CredentialInput{Token: "biam_ses_not-a-real-token"}, "csr", "garbage")
	expectCode(t, err, "UNAUTHENTICATED")
	_, nobody := f.memberWith("nobody")
	_, err = f.issueCertificate(nobody, "csr", pkiCsr(t, pkiKey(t, "p256"), "dnsNames", items("x.internal")))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	denied := f.pkiAudit("iam:pki:issue")
	if len(denied) != 1 || denied[0].Get("outcome") != "deny" || stringify(denied[0].Get("metadata")) != `{"authorityId":"`+jsString(f.issuing.Get("id"))+`"}` {
		t.Fatalf("denied = %s", stringify(denied))
	}
	// RSA requests work too (signing is KMS's).
	_, err = f.issueCertificate(f.owner, "csr", pkiCsr(t, pkiKey(t, "rsa"), "dnsNames", items("rsa.internal")))
	skipOnKms(t, err)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPkiDecidesWildcardNamesAsWildcardsApartFromTheHostsTheyCover(t *testing.T) {
	f := newPkiOrg(t)
	// May certify any single host under .internal except the vault; wildcards are not hosts.
	_, hosts := f.memberWith("hosts",
		allow(items("iam:pki:issue"), items("iam/pki/*"), "conditions", core.NewObject(
			"StringEquals", core.NewObject("resource.nameType", items("dns", "commonName")),
			"StringLike", core.NewObject("resource.name", "*.internal"),
		)),
		core.NewObject("effect", "deny", "actions", items("iam:pki:issue"), "resources", items("iam/pki/*"),
			"conditions", core.NewObject("StringEquals", core.NewObject("resource.name", "vault.internal"))),
	)
	issue := func(dnsNames ...any) error {
		_, err := f.issueCertificate(hosts, "csr", pkiCsr(t, pkiKey(t, "p256"), "dnsNames", dnsNames))
		return err
	}
	expectError(t, issue("vault.internal"), "ACCESS_DENIED", "Access denied")
	// `*.internal` would cover vault.internal: it is decided as nameType `wildcard`, which nothing allowed.
	expectError(t, issue("*.internal"), "ACCESS_DENIED", "Access denied")
	err := issue("api.internal")
	skipOnKms(t, err)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPkiRequestCertificateIsForTheCallersOwnIdentity(t *testing.T) {
	f := newPkiOrg(t)
	api := f.iam.API.Pki
	request := func(credential core.CredentialInput, authorityID any, pairs ...any) error {
		_, err := api.RequestCertificate(f.ctx, credential, Input[apitypes.PkiRequestCertificateInput](body(append([]any{"tenantId", f.tenantID, "authorityId", authorityID, "csr", pkiCsr(t, pkiKey(t, "p256"))}, pairs...)...)))
		return err
	}
	// Without iam:pki:request, a person gets nothing.
	_, una := f.person(f.tenantID, "una")
	expectError(t, request(una, f.issuing.Get("id")), "ACCESS_DENIED", "Access denied")
	statement := allow(items("iam:pki:request"), items("iam/pki/*"), "conditions", core.NewObject(
		"StringEquals", core.NewObject("resource.identityKind", "user"),
		"StringLike", core.NewObject("resource.name", "spiffe://acme.test/user/*"),
	))
	_, credential := f.memberWith("wren", statement)
	// The authority needs a trust domain.
	expectError(t, request(credential, f.root.Get("id")), "INVALID_INPUT", "This authority has no SPIFFE trust domain")
	expectError(t, request(credential, f.issuing.Get("id"), "validitySeconds", 2.0*86_400), "INVALID_INPUT", "Invalid validitySeconds")
	// A session derived from another never acts in its own right.
	derived, viewing := f.memberWith("vic", statement)
	for _, session := range f.find("sessions", core.NewObject("identityId", derived.Get("id"))) {
		f.patch("sessions", jsString(session.Get("id")), core.NewObject("sourceSessionId", "src"))
	}
	expectError(t, request(viewing, f.issuing.Get("id")), "ACCESS_DENIED", "Workload certificates are issued to your own identity, from your own session or API key")
	err := request(credential, f.issuing.Get("id"))
	skipOnKms(t, err)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPkiVerifiesCertificateChainsAgainstOneTenant(t *testing.T) {
	f := newPkiOrg(t)
	person, _ := f.person(f.tenantID, "job")
	spiffe := "spiffe://acme.test/user/" + jsString(person.Get("id"))
	client := f.seedLeaf(pkiKey(t, "ed25519"), "", sanSet{uris: []string{spiffe}}.object(), "client",
		"identityId", person.Get("id"), "spiffeId", spiffe)
	verify := func(chain any, pairs ...any) (*core.Object, error) {
		return f.iam.Pki.Verify(f.ctx, chain, core.NewObject(append([]any{"tenantId", f.tenantID}, pairs...)...))
	}
	verified := must(verify(jsString(client.Get("certificatePem"))+jsString(f.issuing.Get("certificatePem")), "usage", "client"))
	want := `{"tenantId":"` + f.tenantID + `","authorityId":"` + jsString(f.issuing.Get("id")) + `","serialNumber":"` + jsString(client.Get("serialNumber")) +
		`","fingerprint":"` + jsString(client.Get("fingerprint")) + `","subject":"","dnsNames":[],"uris":["` + spiffe + `"],"notAfter":` + stringify(client.Get("notAfter")) +
		`,"spiffeId":"` + spiffe + `","identityId":"` + jsString(person.Get("id")) + `"}`
	if stringify(verified) != want {
		t.Fatalf("verified =\n%s\nwant\n%s", stringify(verified), want)
	}
	// A list of PEMs works too.
	must(verify(items(client.Get("certificatePem"), f.issuing.Get("certificatePem"))))
	_, err := verify(client.Get("certificatePem"), "usage", "server")
	expectError(t, err, "CERTIFICATE_INVALID", "The certificate is not for server use")
	_, err = f.iam.Pki.Verify(f.ctx, client.Get("certificatePem"), core.NewObject("tenantId", f.root.Get("id")))
	expectError(t, err, "CERTIFICATE_INVALID", "The certificate was not issued here")
	_, err = f.iam.Pki.Verify(f.ctx, client.Get("certificatePem"), nil)
	expectError(t, err, "INVALID_INPUT", "Invalid tenantId")
	_, err = verify("no certificate here")
	expectError(t, err, "CERTIFICATE_INVALID", "No certificate was presented")
	_, err = verify("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
	expectError(t, err, "CERTIFICATE_INVALID", "The certificate cannot be read")
	_, err = verify(f.issuing.Get("certificatePem"))
	expectError(t, err, "CERTIFICATE_INVALID", "A CA certificate cannot authenticate")
	_, err = verify(client.Get("certificatePem"), "at", f.now()+2*3_600_000)
	expectError(t, err, "CERTIFICATE_INVALID", "The certificate is not valid at this time")
	// A certificate whose bytes differ from the stored one (same serial) was not issued here.
	other := f.seedLeaf(pkiKey(t, "p256"), "a.internal", sanSet{dnsNames: []string{"a.internal"}}.object(), "server")
	f.patch("pkiCertificates", jsString(other.Get("id")), core.NewObject("certificatePem", client.Get("certificatePem")))
	_, err = verify(other.Get("certificatePem"))
	expectError(t, err, "CERTIFICATE_INVALID", "The certificate was not issued here")
	// A server certificate: the subject reads as Node prints it, and the alternative names list.
	server := f.seedLeaf(pkiKey(t, "p256"), "localhost", sanSet{dnsNames: []string{"localhost", "api.internal"}, ipAddresses: []string{"127.0.0.1"}}.object(), "server")
	read := must(verify(server.Get("certificatePem"), "usage", "server"))
	if read.Get("subject") != "CN=localhost" || stringify(read.Get("dnsNames")) != `["localhost","api.internal"]` || read.Has("identityId") {
		t.Fatalf("read = %s", stringify(read))
	}
	// A workload certificate is only as good as the identity it names.
	f.patch("identities", jsString(person.Get("id")), core.NewObject("status", "disabled"))
	_, err = verify(client.Get("certificatePem"))
	expectError(t, err, "CERTIFICATE_INVALID", "The identity it names is no longer active")
	// A disabled authority stops its certificates.
	f.patch("pkiAuthorities", jsString(f.issuing.Get("id")), core.NewObject("state", "disabled"))
	_, err = verify(server.Get("certificatePem"))
	expectError(t, err, "CERTIFICATE_INVALID", "An issuing authority is not active")
	// Path lengths are enforced on the stored chain.
	f.patch("pkiAuthorities", jsString(f.issuing.Get("id")), core.NewObject("state", "active"))
	f.patch("pkiAuthorities", jsString(f.root.Get("id")), core.NewObject("pathLength", 0.0))
	_, err = verify(server.Get("certificatePem"))
	expectError(t, err, "CERTIFICATE_INVALID", "The chain exceeds a path length")
	// A stored chain whose certificates do not chain fails.
	f.patch("pkiAuthorities", jsString(f.root.Get("id")), core.NewObject("pathLength", 1.0, "certificatePem", f.issuing.Get("certificatePem")))
	_, err = verify(server.Get("certificatePem"))
	expectError(t, err, "CERTIFICATE_INVALID", "The certificate chain does not verify")
}

func TestPkiRevokesCertificatesAndSubordinateAuthorities(t *testing.T) {
	f := newPkiOrg(t)
	api := f.iam.API.Pki
	person, _ := f.person(f.tenantID, "job")
	leaf := f.seedLeaf(pkiKey(t, "p256"), "a.internal", sanSet{dnsNames: []string{"a.internal"}}.object(), "both", "identityId", person.Get("id"))
	revoke := func(serial any, pairs ...any) (*core.Object, error) {
		out, err := api.RevokeCertificate(f.ctx, f.owner, Input[apitypes.PkiRevokeCertificateInput](body(append([]any{"tenantId", f.tenantID, "serialNumber", serial}, pairs...)...)))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	f.advance(1000)
	revoked := must(revoke(leaf.Get("serialNumber"), "reason", "keyCompromise"))
	if revoked.Get("status") != "revoked" || revoked.Get("revocationReason") != "keyCompromise" || revoked.Get("revokedAt") != f.now() {
		t.Fatalf("revoked = %s", stringify(revoked))
	}
	stored := f.record("pkiCertificates", jsString(leaf.Get("id")))
	if stored.Get("revokedBy") != f.ownerID {
		t.Fatalf("stored = %s", stringify(stored))
	}
	if f.record("pkiAuthorities", jsString(f.issuing.Get("id"))).Get("revision") != 1.0 {
		t.Fatal("the authority's revision did not move")
	}
	// Revocation takes effect for verification at once.
	_, err := f.iam.Pki.Verify(f.ctx, leaf.Get("certificatePem"), core.NewObject("tenantId", f.tenantID))
	expectError(t, err, "CERTIFICATE_INVALID", "The certificate has been revoked")
	_, err = revoke(leaf.Get("serialNumber"))
	expectError(t, err, "CONFLICT", "The certificate is already revoked")
	listed := answerObject(api.ListCertificates(f.ctx, f.owner, Input[apitypes.PkiListCertificatesInput](body("tenantId", f.tenantID, "identityId", person.Get("id")))))
	if listed.Get("total") != 1.0 || member(listed.Get("certificates").([]any)[0], "revocationReason") != "keyCompromise" {
		t.Fatalf("listed = %s", stringify(listed))
	}
	events := f.pkiAudit("iam:pki:revoke")
	if stringify(events[0].Get("metadata")) != `{"authorityId":"`+jsString(f.issuing.Get("id"))+`","serialNumber":"`+jsString(leaf.Get("serialNumber"))+`","reason":"keyCompromise"}` {
		t.Fatalf("metadata = %s", stringify(events[0].Get("metadata")))
	}
	// Revoking an intermediate's certificate revokes it and everything below it.
	second := f.seedAuthority(f.tenantID, "Below", makeTestAuthority(t, "Below", f.issuingKey, nil, nil, f.now()), f.issuing, nil, "", "", nil)
	intermediate := answerObject(api.ListCertificates(f.ctx, f.owner, Input[apitypes.PkiListCertificatesInput](body("tenantId", f.tenantID, "authorityId", f.root.Get("id"))))).Get("certificates").([]any)[0]
	cascade := must(revoke(member(intermediate, "serialNumber")))
	if cascade.Get("revocationReason") != "unspecified" {
		t.Fatalf("cascade = %s", stringify(cascade))
	}
	for _, authority := range []*core.Object{f.issuing, second} {
		if f.record("pkiAuthorities", jsString(authority.Get("id"))).Get("state") != "revoked" {
			t.Fatalf("%s is not revoked", authority.Get("name"))
		}
	}
	events = f.pkiAudit("iam:pki:revoke")
	if member(events[len(events)-1].Get("metadata"), "authoritiesRevoked") != 2.0 || member(events[len(events)-1].Get("metadata"), "subordinateId") != f.issuing.Get("id") {
		t.Fatalf("metadata = %s", stringify(events[len(events)-1].Get("metadata")))
	}
	_, err = f.issueCertificate(f.owner, "csr", pkiCsr(t, pkiKey(t, "p256"), "dnsNames", items("d.internal")))
	expectError(t, err, "AUTHORITY_UNAVAILABLE", "The certificate authority Acme Workloads is revoked")
}

func TestPkiServesCachedRevocationListsAndFallsBack(t *testing.T) {
	f := newPkiOrg(t)
	runtime := f.iam.Pki
	missing := must(runtime.CrlResponse(f.ctx, "missing"))
	if missing.StatusCode != 404 || readBody(t, missing) != "Not found" {
		t.Fatalf("missing = %d", missing.StatusCode)
	}
	// Nothing cached and nothing that can sign (the authority's KMS key is disabled): 503.
	f.seed("kmsKeys", core.NewObject("id", f.issuing.Get("keyId"), "tenantId", f.tenantID, "keySpec", "ecc-p256", "keyUsage", "sign", "state", "disabled", "currentVersion", 1.0))
	unavailable := must(runtime.CrlResponse(f.ctx, jsString(f.issuing.Get("id"))))
	if unavailable.StatusCode != 503 || readBody(t, unavailable) != "Revocation list unavailable" {
		t.Fatalf("unavailable = %d", unavailable.StatusCode)
	}
	// A CRL signed by the authority, cached for its current revision, is served as it is.
	spec := core.NewObject()
	spec.SetRaw("issuer", f.issuingKey.subjectDer)
	spec.Set("thisUpdate", f.now())
	spec.Set("nextUpdate", f.now()+crlLifetimeMs)
	spec.Set("crlNumber", 1.0)
	spec.SetRaw("authorityKeyId", f.issuingKey.keyID)
	spec.SetRaw("revoked", items())
	tbs := must(TbsCertList(spec, "ES256"))
	der := must(SignedStructure(tbs, "ES256", must(signWith(f.issuingKey.key, "ES256", tbs))))
	f.patch("pkiAuthorities", jsString(f.issuing.Get("id")), core.NewObject("crlNumber", 1.0, "crl", core.NewObject(
		"der", base64.StdEncoding.EncodeToString(der), "thisUpdate", f.now(), "nextUpdate", f.now()+crlLifetimeMs, "revision", 0.0, "crlNumber", 1.0)))
	f.advance(3_600_000)
	cached := must(runtime.Crl(f.ctx, jsString(f.issuing.Get("id"))))
	if string(cached.Get("der").([]byte)) != string(der) || cached.Get("crlNumber") != 1.0 || cached.Get("revision") != 0.0 || !strings.HasPrefix(jsString(cached.Get("pem")), "-----BEGIN X509 CRL-----") {
		t.Fatalf("cached = %v", cached.Keys())
	}
	response := must(runtime.CrlResponse(f.ctx, jsString(f.issuing.Get("id"))))
	if response.Header.Get("content-type") != "application/pkix-crl" || response.Header.Get("cache-control") != "public, max-age=41400" || readBody(t, response) != string(der) {
		t.Fatalf("response = %v", response.Header)
	}
	viaAPI := answerObject(f.iam.API.Pki.Crl(f.ctx, f.owner, Input[apitypes.PkiCrlInput](body("tenantId", f.tenantID, "authorityId", f.issuing.Get("id")))))
	if viaAPI.Get("pem") != cached.Get("pem") || viaAPI.Get("crlNumber") != 1.0 || viaAPI.Get("nextUpdate") != f.now()-3_600_000+crlLifetimeMs {
		t.Fatalf("api = %s", stringify(viaAPI))
	}
	// After a revocation the CRL must be rebuilt; while that cannot be signed, the last one is served until it lapses.
	f.patch("pkiAuthorities", jsString(f.issuing.Get("id")), core.NewObject("revision", 1.0))
	stale := must(runtime.CrlResponse(f.ctx, jsString(f.issuing.Get("id"))))
	if stale.StatusCode != 200 || readBody(t, stale) != string(der) {
		t.Fatalf("stale = %d", stale.StatusCode)
	}
	f.advance(crlLifetimeMs)
	lapsed := must(runtime.CrlResponse(f.ctx, jsString(f.issuing.Get("id"))))
	if lapsed.StatusCode != 503 {
		t.Fatalf("lapsed = %d", lapsed.StatusCode)
	}
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPkiCreatesARootAndAnIntermediateThatGoReadsAndVerifies(t *testing.T) {
	f := newTrustOrg(t, nil)
	pki := f.iam.API.Pki
	owner := f.ownerSignIn(f.tenantID)
	create := func(pairs ...any) (*core.Object, error) {
		out, err := pki.CreateAuthority(f.ctx, owner, Input[apitypes.PkiCreateAuthorityInput](body(append([]any{"tenantId", f.tenantID}, pairs...)...)))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	root, err := create("name", "Acme Root", "subject", core.NewObject("commonName", "Acme Root CA", "organization", "Acme", "country", "US"), "pathLength", 1.0)
	skipOnKms(t, err)
	if err != nil {
		t.Fatal(err)
	}
	issuing, err := create("name", "Acme Workloads", "parentId", root.Get("id"), "subject", core.NewObject("commonName", "Acme Workload CA", "organization", "Acme"),
		"trustDomain", "acme.test", "permitted", core.NewObject("dnsNames", items("internal", "localhost"), "uriHosts", items("acme.test")),
		"crlUrl", "https://pki.acme.test/crl/workloads.crl")
	skipOnKms(t, err)
	if err != nil {
		t.Fatal(err)
	}
	rootCert := must(x509.ParseCertificate(must(CertificateDer(jsString(root.Get("certificatePem"))))))
	issuingCert := must(x509.ParseCertificate(must(CertificateDer(jsString(issuing.Get("certificatePem"))))))
	if !rootCert.IsCA || !issuingCert.IsCA || rootCert.Subject.CommonName != "Acme Root CA" || issuingCert.CheckSignatureFrom(rootCert) != nil {
		t.Fatal("Go does not read the chain")
	}
	if issuing.Get("type") != "intermediate" || issuing.Get("parentId") != root.Get("id") || issuing.Get("trustDomain") != "acme.test" || issuing.Get("state") != "active" || issuing.Get("pathLength") != 0.0 {
		t.Fatalf("issuing = %s", stringify(issuing))
	}
	underRoot := answerObject(pki.ListCertificates(f.ctx, owner, Input[apitypes.PkiListCertificatesInput](body("tenantId", f.tenantID, "authorityId", root.Get("id")))))
	if certificates := underRoot.Get("certificates").([]any); len(certificates) != 1 || member(certificates[0], "usage") != "ca" || member(certificates[0], "subordinateId") != issuing.Get("id") {
		t.Fatalf("under root = %s", stringify(underRoot))
	}
	// Path length 1 under the root leaves none below the intermediate.
	_, err = create("name", "Too deep", "parentId", root.Get("id"), "subject", core.NewObject("commonName", "Too deep"), "pathLength", 1.0)
	expectError(t, err, "INVALID_INPUT", "pathLength exceeds what the authorities above allow")
	_, err = create("name", "Deeper", "parentId", issuing.Get("id"), "subject", core.NewObject("commonName", "Deeper"))
	expectError(t, err, "INVALID_INPUT", "An authority above allows no more levels of subordinate authorities (path length)")
	bundle := answerObject(pki.Bundle(f.ctx, owner, Input[apitypes.PkiBundleInput](body("tenantId", f.tenantID))))
	if bundle.Get("authorities") != 1.0 || bundle.Get("pem") != root.Get("certificatePem") {
		t.Fatalf("bundle = %s", stringify(bundle))
	}
	// Another organization cannot claim the trust domain.
	other, globex := f.organization("Globex", "owner@globex.test")
	_, err = pki.CreateAuthority(f.ctx, globex, Input[apitypes.PkiCreateAuthorityInput](body("tenantId", other, "name", "Impostor", "subject", core.NewObject("commonName", "Acme Issuing"), "trustDomain", "acme.test")))
	skipOnKms(t, err)
	expectError(t, err, "CONFLICT", "Another organization uses that trust domain")
	_, err = create("name", "acme root", "subject", core.NewObject("commonName", "Twin"))
	expectError(t, err, "CONFLICT", "A certificate authority with that name exists")
}

func TestPkiIssuesCertificatesThatCompleteAMutualTlsHandshake(t *testing.T) {
	f := newTrustOrg(t, nil)
	pki := f.iam.API.Pki
	owner := f.ownerSignIn(f.tenantID)
	out, err := pki.CreateAuthority(f.ctx, owner, Input[apitypes.PkiCreateAuthorityInput](body("tenantId", f.tenantID, "name", "Root", "subject", core.NewObject("commonName", "Acme Root"), "pathLength", 1.0)))
	skipOnKms(t, err)
	root := answerObject(out, err)
	issuing := answerObject(pki.CreateAuthority(f.ctx, owner, Input[apitypes.PkiCreateAuthorityInput](body("tenantId", f.tenantID, "name", "Issuing", "parentId", root.Get("id"),
		"subject", core.NewObject("commonName", "Acme Issuing"), "trustDomain", "acme.test", "permitted", core.NewObject("dnsNames", items("internal", "localhost"), "uriHosts", items("acme.test"))))))
	issue := func(key crypto.Signer, pairs ...any) *core.Object {
		return answerObject(pki.IssueCertificate(f.ctx, owner, Input[apitypes.PkiIssueCertificateInput](body(append([]any{"tenantId", f.tenantID, "authorityId", issuing.Get("id")}, pairs...)...))))
	}
	serverKey, clientKey := pkiKey(t, "p256"), pkiKey(t, "ed25519")
	server := issue(serverKey, "csr", pkiCsr(t, serverKey, "subject", core.NewObject("commonName", "localhost"), "dnsNames", items("localhost", "api.internal"), "ipAddresses", items("127.0.0.1")), "usage", "server", "validitySeconds", 3600.0)
	client := issue(clientKey, "csr", pkiCsr(t, clientKey, "uris", items("spiffe://acme.test/billing")), "usage", "client")
	if server.Get("chainPem") != issuing.Get("certificatePem") || server.Get("rootPem") != root.Get("certificatePem") {
		t.Fatalf("server = %s", stringify(server))
	}
	pool := x509.NewCertPool()
	clock := func() time.Time { return time.UnixMilli(int64(f.now())) }
	pool.AppendCertsFromPEM([]byte(jsString(root.Get("certificatePem"))))
	pair := func(key crypto.Signer, issued *core.Object) tls.Certificate {
		chain := []byte(jsString(issued.Get("certificatePem")) + jsString(issued.Get("chainPem")))
		certificate := tls.Certificate{PrivateKey: key}
		for block, rest := pem.Decode(chain); block != nil; block, rest = pem.Decode(rest) {
			certificate.Certificate = append(certificate.Certificate, block.Bytes)
		}
		return certificate
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair(serverKey, server)}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, Time: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	seen := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			seen <- err.Error()
			return
		}
		defer connection.Close()
		tlsConnection := connection.(*tls.Conn)
		if err := tlsConnection.Handshake(); err != nil {
			seen <- err.Error()
			return
		}
		seen <- tlsConnection.ConnectionState().PeerCertificates[0].URIs[0].String()
	}()
	connection, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{pair(clientKey, client)}, Time: clock})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_ = connection.Close()
	if peer := <-seen; peer != "spiffe://acme.test/billing" {
		t.Fatalf("peer = %s", peer)
	}
	verified := must(f.iam.Pki.Verify(f.ctx, client.Get("certificatePem"), core.NewObject("tenantId", f.tenantID, "usage", "client")))
	if verified.Get("serialNumber") != client.Get("serialNumber") || stringify(verified.Get("uris")) != `["spiffe://acme.test/billing"]` {
		t.Fatalf("verified = %s", stringify(verified))
	}
}

// pkiWorkload creates a service account holding a role with the statement and an API key for it
// (tests/pki.test.ts and tests/pki-security.test.ts), returning the account and the key's credential.
func (f *pkiOrg) pkiWorkload(statement *core.Object, keyPairs ...any) (*core.Object, core.CredentialInput) {
	f.t.Helper()
	owner := f.ownerSignIn(f.tenantID)
	account := answerObject(f.iam.API.ServiceAccounts.Create(f.ctx, owner, Input[apitypes.ServiceAccountsCreateInput](body("tenantId", f.tenantID, "name", "billing-job"))))
	f.bind(f.tenantID, f.role(f.tenantID, "Workload identity", statement), "identity", jsString(account.Get("id")))
	key := answerObject(f.iam.API.Credentials.Create(f.ctx, owner, Input[apitypes.CredentialsCreateInput](body(append([]any{"tenantId", f.tenantID, "identityId", account.Get("id"), "name", "job"}, keyPairs...)...))))
	return account, core.CredentialInput{Token: jsString(key.Get("token"))}
}

func TestPkiGivesWorkloadsSpiffeCertificatesForTheirOwnIdentityRevocableWithACrl(t *testing.T) {
	f := newPkiOrg(t)
	api := f.iam.API.Pki
	account, key := f.pkiWorkload(allow(items("iam:pki:request"), items("iam/pki/*")))
	out, err := api.RequestCertificate(f.ctx, key, Input[apitypes.PkiRequestCertificateInput](body("tenantId", f.tenantID, "authorityId", f.issuing.Get("id"),
		"csr", pkiCsr(t, pkiKey(t, "p256"), "dnsNames", items("ignored.internal")))))
	skipOnKms(t, err)
	svid := answerObject(out, err)
	spiffe := "spiffe://acme.test/service/" + jsString(account.Get("id"))
	if svid.Get("spiffeId") != spiffe {
		t.Fatalf("svid = %s", stringify(svid))
	}
	certificate := must(x509.ParseCertificate(must(CertificateDer(jsString(svid.Get("certificatePem"))))))
	// An SVID has an empty subject and names the workload only in its URI.
	if len(certificate.URIs) != 1 || certificate.URIs[0].String() != spiffe || len(certificate.DNSNames) != 0 || len(certificate.Subject.Names) != 0 {
		t.Fatalf("certificate = %+v", certificate)
	}
	if certificate.NotAfter.UnixMilli()-int64(f.now()) > 3_600_000 {
		t.Fatalf("notAfter = %v", certificate.NotAfter)
	}
	verified := must(f.iam.Pki.Verify(f.ctx, jsString(svid.Get("certificatePem"))+jsString(svid.Get("chainPem")), core.NewObject("tenantId", f.tenantID)))
	if verified.Get("identityId") != account.Get("id") || verified.Get("spiffeId") != spiffe || verified.Get("tenantId") != f.tenantID {
		t.Fatalf("verified = %s", stringify(verified))
	}
	// Revocation takes effect for verification at once, and lands on the CRL.
	owner := f.ownerSignIn(f.tenantID)
	before := answerObject(api.Crl(f.ctx, owner, Input[apitypes.PkiCrlInput](body("tenantId", f.tenantID, "authorityId", f.issuing.Get("id")))))
	answer(api.RevokeCertificate(f.ctx, owner, Input[apitypes.PkiRevokeCertificateInput](body("tenantId", f.tenantID, "serialNumber", svid.Get("serialNumber"), "reason", "keyCompromise"))))
	_, err = f.iam.Pki.Verify(f.ctx, svid.Get("certificatePem"), core.NewObject("tenantId", f.tenantID))
	expectError(t, err, "CERTIFICATE_INVALID", "The certificate has been revoked")
	after := must(f.iam.Pki.Crl(f.ctx, jsString(f.issuing.Get("id"))))
	if after.Get("crlNumber") != jsNumber(before.Get("crlNumber"))+1 {
		t.Fatalf("crl numbers %v -> %v", before.Get("crlNumber"), after.Get("crlNumber"))
	}
	list := must(x509.ParseRevocationList(after.Get("der").([]byte)))
	if len(list.RevokedCertificateEntries) != 1 || list.RevokedCertificateEntries[0].SerialNumber.Text(16) != strings.TrimLeft(jsString(svid.Get("serialNumber")), "0") || list.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Fatalf("list = %+v", list.RevokedCertificateEntries)
	}
	response := must(f.iam.Pki.CrlResponse(f.ctx, jsString(f.issuing.Get("id"))))
	if response.Header.Get("content-type") != "application/pkix-crl" || readBody(t, response) != string(after.Get("der").([]byte)) {
		t.Fatal("the CRL response is not the CRL")
	}
	// A cached CRL is served until something changes.
	if must(f.iam.Pki.Crl(f.ctx, jsString(f.issuing.Get("id")))).Get("crlNumber") != after.Get("crlNumber") {
		t.Fatal("the cached CRL was rebuilt")
	}
	listed := answerObject(api.ListCertificates(f.ctx, owner, Input[apitypes.PkiListCertificatesInput](body("tenantId", f.tenantID, "identityId", account.Get("id")))))
	if certificates := listed.Get("certificates").([]any); len(certificates) != 1 || member(certificates[0], "status") != "revoked" || member(certificates[0], "revocationReason") != "keyCompromise" {
		t.Fatalf("listed = %s", stringify(listed))
	}
}

func TestPkiKeepsWorkloadCertificatesWithinTheCredentialAndStopsThemWithTheIdentity(t *testing.T) {
	f := newPkiOrg(t)
	api := f.iam.API.Pki
	// Decided on the SPIFFE ID and the caller's kind.
	account, key := f.pkiWorkload(allow(items("iam:pki:request"), items("iam/pki/*"), "conditions", core.NewObject(
		"StringEquals", core.NewObject("resource.identityKind", "service"),
		"StringLike", core.NewObject("resource.name", "spiffe://acme.test/service/*"),
	)), "expiresInSeconds", 30.0*60)
	request := func(validitySeconds float64) (Out[apitypes.PkiRequestCertificateOutput], error) {
		return api.RequestCertificate(f.ctx, key, Input[apitypes.PkiRequestCertificateInput](body("tenantId", f.tenantID, "authorityId", f.issuing.Get("id"),
			"csr", pkiCsr(t, pkiKey(t, "p256")), "validitySeconds", validitySeconds)))
	}
	_, err := request(2 * 86_400)
	expectError(t, err, "INVALID_INPUT", "Invalid validitySeconds")
	out, err := request(86_400)
	skipOnKms(t, err)
	svid := answerObject(out, err)
	// Asked for a day; the API key ends in 30 minutes, so the certificate does too.
	if jsNumber(svid.Get("notAfter")) > f.now()+30*60_000 {
		t.Fatalf("notAfter = %v", svid.Get("notAfter"))
	}
	if must(f.iam.Pki.Verify(f.ctx, svid.Get("certificatePem"), core.NewObject("tenantId", f.tenantID))).Get("identityId") != account.Get("id") {
		t.Fatal("the SVID does not name the account")
	}
	answer(f.iam.API.Identities.SetStatus(f.ctx, f.ownerSignIn(f.tenantID), Input[apitypes.IdentitiesSetStatusInput](body("tenantId", f.tenantID, "identityId", account.Get("id"), "status", "disabled"))))
	_, err = f.iam.Pki.Verify(f.ctx, svid.Get("certificatePem"), core.NewObject("tenantId", f.tenantID))
	expectError(t, err, "CERTIFICATE_INVALID", "The identity it names is no longer active")
}
