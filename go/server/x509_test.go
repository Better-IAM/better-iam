package server

// The X.509 layer (x509.go), after the encoding checks of tests/pki.test.ts and tests/pki-security.test.ts: requests
// built here parse and verify, the parser refuses what does not prove its key, names are canonical, and what the
// encoder writes reads back with Go's crypto/x509 (as the TypeScript tests read it back with Node's X509Certificate).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func pkiKey(t *testing.T, kind string) crypto.Signer {
	t.Helper()
	var key crypto.Signer
	var err error
	switch kind {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// pkiCsr is createCertificateRequest({ privateKey, ...pairs }).
func pkiCsr(t *testing.T, key crypto.Signer, pairs ...any) string {
	t.Helper()
	input := core.NewObject(pairs...)
	input.SetRaw("privateKey", key)
	csr, err := CreateCertificateRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestX509RequestsRoundTripForEveryKeyKind(t *testing.T) {
	for _, kind := range []struct{ name, keyType string }{{"p256", "ecc-p256"}, {"p384", "ecc-p384"}, {"ed25519", "ed25519"}, {"rsa", "rsa-2048"}} {
		key := pkiKey(t, kind.name)
		csr := pkiCsr(t, key, "subject", core.NewObject("commonName", "localhost"), "dnsNames", items("LocalHost", "api.internal", "api.internal"), "ipAddresses", items("127.0.0.1"))
		// Go reads what this writes, and the signature proves the key.
		block, _ := pem.Decode([]byte(csr))
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			t.Fatalf("%s: not a PEM request: %s", kind.name, csr)
		}
		request, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || request.CheckSignature() != nil {
			t.Fatalf("%s: Go cannot read the request: %v", kind.name, err)
		}
		if request.Subject.CommonName != "localhost" || strings.Join(request.DNSNames, ",") != "localhost,api.internal" || request.IPAddresses[0].String() != "127.0.0.1" {
			t.Fatalf("%s: request = %+v", kind.name, request)
		}
		parsed := must(ParseCertificateRequest(csr))
		spki := must(x509.MarshalPKIXPublicKey(key.Public()))
		if parsed.Get("keyType") != kind.keyType || parsed.Get("commonName") != "localhost" || string(parsed.Get("spki").([]byte)) != string(spki) {
			t.Fatalf("%s: parsed = %s", kind.name, stringify(parsed.Spread(core.NewObject("spki", nil, "publicKey", nil))))
		}
		if got := stringify(parsed.Get("names")); got != `{"dnsNames":["localhost","api.internal"],"uris":[],"ipAddresses":["127.0.0.1"],"emails":[]}` {
			t.Fatalf("%s: names = %s", kind.name, got)
		}
	}
	// No names and no subject: an empty request still proves its key.
	parsed := must(ParseCertificateRequest(pkiCsr(t, pkiKey(t, "p256"))))
	if parsed.Has("commonName") || stringify(parsed.Get("names")) != `{"dnsNames":[],"uris":[],"ipAddresses":[],"emails":[]}` {
		t.Fatalf("parsed = %s", stringify(parsed.Get("names")))
	}
	// Base64 DER without the PEM armor is accepted too.
	csr := pkiCsr(t, pkiKey(t, "p256"), "dnsNames", items("a.internal"))
	block, _ := pem.Decode([]byte(csr))
	if must(ParseCertificateRequest(base64.StdEncoding.EncodeToString(block.Bytes))).Get("keyType") != "ecc-p256" {
		t.Fatal("bare base64 DER was not accepted")
	}
}

func TestX509RefusesRequestsThatDoNotProveTheirKey(t *testing.T) {
	good := pkiCsr(t, pkiKey(t, "p256"), "dnsNames", items("a.internal"))
	block, _ := pem.Decode([]byte(good))
	der := append([]byte{}, block.Bytes...)
	der[len(der)-5] ^= 0xff
	tampered := "-----BEGIN CERTIFICATE REQUEST-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END CERTIFICATE REQUEST-----\n"
	_, err := ParseCertificateRequest(tampered)
	expectError(t, err, "INVALID_CSR", "The request signature does not verify with its key")
	_, err = ParseCertificateRequest("not a csr")
	expectError(t, err, "INVALID_CSR", "The certificate request is not valid DER")
	_, err = ParseCertificateRequest(42.0)
	expectError(t, err, "INVALID_CSR", "csr must be a PEM certificate request")
	_, err = ParseCertificateRequest(strings.Repeat("A", 65537))
	expectError(t, err, "INVALID_CSR", "csr must be a PEM certificate request")
	_, err = ParseCertificateRequest("AAAA")
	expectError(t, err, "INVALID_CSR", "The certificate request is not valid DER")
	// Keys outside the accepted kinds are refused by kind, not as unreadable.
	_, err = ParseCertificateRequest(p521Request(t))
	expectError(t, err, "INVALID_CSR", "The requested key must be ECDSA P-256 or P-384, Ed25519, or RSA of 2048 to 8192 bits")
	// An RSA key small enough to forge with is refused too.
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{DNSNames: []string{"a.internal"}}
	smallDer, err := x509.CreateCertificateRequest(rand.Reader, template, small)
	if err != nil {
		t.Skip("this Go refuses 1024-bit RSA keys")
	}
	_, err = ParseCertificateRequest(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: smallDer})))
	expectError(t, err, "INVALID_CSR", "The requested key must be ECDSA P-256 or P-384, Ed25519, or RSA of 2048 to 8192 bits")
}

// p521Request is a P-521 request (signed with ECDSA SHA-512), which Node reads and the CA refuses by key kind.
func p521Request(t *testing.T) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"a.internal"}}, pkiKey(t, "p521"))
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestX509DecidesAndEncodesTheSameCanonicalNames(t *testing.T) {
	names := func(pairs ...any) (*core.Object, error) { return SubjectAltNames(core.NewObject(pairs...)) }
	// Non-ASCII email local parts would be truncated to other bytes when encoded.
	_, err := names("emails", items("ţeo@corp.internal"))
	expectError(t, err, "INVALID_INPUT", "Invalid email address ţeo@corp.internal")
	// Dot segments and non-canonical forms in URIs are refused rather than normalized behind the policy's back.
	_, err = names("uris", items("spiffe://acme.test/team-a/../service/x"))
	expectError(t, err, "INVALID_INPUT", "Invalid SPIFFE ID spiffe://acme.test/team-a/../service/x: spiffe://{trust domain}/{path}, with no dot segments, query or fragment")
	for _, uri := range []string{"https://Acme.test/x", "https://user@acme.test/x", "https://acme.test", "https://acme.test:443/x", "https://acme.test/a/./b", "https://acme.test/a/%2e%2E/b", "https://acme.test/a\\b", "https://acme.test/a b"} {
		_, err = names("uris", items(uri))
		expectError(t, err, "INVALID_INPUT", "Invalid URI "+uri)
	}
	canonical := must(names("uris", items("https://acme.test/x?y=1#z", "spiffe://acme.test/billing", "urn:example:a")))
	if stringify(canonical.Get("uris")) != `["https://acme.test/x?y=1#z","spiffe://acme.test/billing","urn:example:a"]` {
		t.Fatalf("uris = %s", stringify(canonical.Get("uris")))
	}
	// IP addresses are canonical: an IPv4-mapped IPv6 address is the IPv4 address; IPv6 is RFC 5952.
	ips := must(names("ipAddresses", items("::ffff:10.0.0.1", "2001:DB8:0:0:0:0:0:1", "10.0.0.1", "fe80:0:0:1:0:0:0:1")))
	if stringify(ips.Get("ipAddresses")) != `["10.0.0.1","2001:db8::1","fe80:0:0:1::1"]` {
		t.Fatalf("ips = %s", stringify(ips.Get("ipAddresses")))
	}
	for _, ip := range []string{"fe80::1%eth0", "1.2.3", "01.2.3.4", "host"} {
		_, err = names("ipAddresses", items(ip))
		expectError(t, err, "INVALID_INPUT", "Invalid IP address "+ip)
	}
	_, err = names("dnsNames", items("bad_name.internal"))
	expectError(t, err, "INVALID_INPUT", "Invalid DNS name bad_name.internal")
	_, err = names("dnsNames", "a.internal")
	expectError(t, err, "INVALID_INPUT", "dnsNames must be a list of strings")
	_, err = names("uris", items(42.0))
	expectError(t, err, "INVALID_INPUT", "uris must be a list of strings")
	many := make([]any, 101)
	for index := range many {
		many[index] = "h" + core.NumberString(float64(index)) + ".internal"
	}
	_, err = names("dnsNames", many)
	expectError(t, err, "INVALID_INPUT", "At most 100 subject alternative names")
	wildcard := must(names("dnsNames", items("*.Internal"), "emails", items("Ops@Corp.Internal")))
	if stringify(wildcard) != `{"dnsNames":["*.internal"],"uris":[],"ipAddresses":[],"emails":["ops@corp.internal"]}` {
		t.Fatalf("names = %s", stringify(wildcard))
	}
}

func TestX509EncodingPrimitives(t *testing.T) {
	if got := derIntegerNumber(0); string(got) != "\x02\x01\x00" {
		t.Fatalf("integer(0) = % x", got)
	}
	if got := derInteger([]byte{0x00, 0x00, 0x80}); string(got) != "\x02\x02\x00\x80" {
		t.Fatalf("integer(0x80) = % x", got)
	}
	if got := derOID("1.2.840.113549.1.9.14"); string(got) != "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x0e" {
		t.Fatalf("oid = % x", got)
	}
	if oid := must(decodeOID([]byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e})); oid != "1.2.840.113549.1.9.14" {
		t.Fatalf("decoded = %s", oid)
	}
	if got := derNamedBits([]int{0, 5, 6}); string(got) != "\x03\x02\x01\x86" {
		t.Fatalf("named bits = % x", got)
	}
	if got := derNamedBits([]int{0}); string(got) != "\x03\x02\x07\x80" {
		t.Fatalf("named bits = % x", got)
	}
	if got := string(derTime(1_790_000_000_123)); got != "\x17\x0d"+"260921141320Z" {
		t.Fatalf("time = %q", got)
	}
	if got := string(derTime(2_556_144_000_000)); got != "\x18\x0f"+"20510101000000Z" {
		t.Fatalf("time = %q", got)
	}
	if got := derLength(300); string(got) != "\x82\x01\x2c" {
		t.Fatalf("length = % x", got)
	}
	_, err := readDerNode([]byte{0x30, 0x81, 0x05}, 0, -1)
	expectError(t, err, "INVALID_CSR", "The certificate request is not valid DER")
	serial := must(RandomSerial())
	if len(serial) != 32 || serial[0] == '0' || strings.ToLower(serial) != serial {
		t.Fatalf("serial = %s", serial)
	}
	text := must(Pem("TEST", make([]byte, 100)))
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if lines[0] != "-----BEGIN TEST-----" || len(lines[1]) != 64 || lines[len(lines)-1] != "-----END TEST-----" {
		t.Fatalf("pem = %q", text)
	}
	if string(must(CertificateDer("-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n"))) != "\x00\x01\x02" {
		t.Fatal("certificateDer")
	}
	fingerprint := must(Sha256Fingerprint([]byte("abc")))
	if fingerprint != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("fingerprint = %s", fingerprint)
	}
	name := must(EncodeName(core.NewObject("commonName", "Acme Root CA", "organization", "Acme", "country", "US")))
	var parsed struct{}
	_ = parsed
	// C, O, CN in that order, each its own RDN.
	if rdns := mustRDNs(t, name); strings.Join(rdns, "/") != "2.5.4.6=US/2.5.4.10=Acme/2.5.4.3=Acme Root CA" {
		t.Fatalf("name = %v", rdns)
	}
}

// mustRDNs reads a DER name into `oid=value` per RDN.
func mustRDNs(t *testing.T, name []byte) []string {
	t.Helper()
	root := must(readDerNode(name, 0, -1))
	out := []string{}
	for _, rdn := range must(derChildren(name, root)) {
		for _, attribute := range must(derChildren(name, rdn)) {
			pair := must(derChildren(name, attribute))
			value, _, _ := nameValue(name, pair[1])
			out = append(out, must(decodeOID(derContents(name, pair[0])))+"="+value)
		}
	}
	return out
}

// testAuthority is an authority made in a test: its key, record fields and certificate.
type testAuthority struct {
	key        crypto.Signer
	algorithm  string
	subjectDer []byte
	keyID      []byte
	der        []byte
	pem        string
	serial     string
	notAfter   float64
}

// makeTestAuthority signs a CA certificate as createAuthority does (self-signed without a parent).
func makeTestAuthority(t *testing.T, name string, parent *testAuthority, pathLength *float64, permitted *core.Object, now float64) *testAuthority {
	t.Helper()
	key := pkiKey(t, "p256")
	spki := must(x509.MarshalPKIXPublicKey(key.Public()))
	subject := core.NewObject("commonName", name)
	subjectDer := must(EncodeName(subject))
	authority := &testAuthority{key: key, algorithm: "ES256", subjectDer: subjectDer, keyID: must(KeyIdentifier(spki)), serial: must(RandomSerial()), notAfter: now + 3650*pkiDayMs}
	spec := core.NewObject("serialNumber", authority.serial)
	ca := core.NewObject()
	if pathLength != nil {
		ca.Set("pathLength", *pathLength)
	}
	issuerKey := key
	if parent != nil {
		spec.SetRaw("issuer", parent.subjectDer)
		spec.SetRaw("authorityKeyId", parent.keyID)
		if permitted != nil {
			spec.SetRaw("permitted", permitted)
		}
		issuerKey = parent.key
		if parent.notAfter < authority.notAfter {
			authority.notAfter = parent.notAfter
		}
	} else {
		spec.SetRaw("issuer", subjectDer)
	}
	spec.SetRaw("subject", subject)
	spec.SetRaw("spki", spki)
	spec.Set("notBefore", now-pkiClockSkewMs)
	spec.Set("notAfter", authority.notAfter)
	spec.SetRaw("ca", ca)
	tbs := must(TbsCertificate(spec, "ES256"))
	authority.der = must(SignedStructure(tbs, "ES256", must(signWith(issuerKey, "ES256", tbs))))
	authority.pem = must(CertificatePem(authority.der))
	return authority
}

// makeTestLeaf signs a leaf as issue does.
func makeTestLeaf(t *testing.T, issuer *testAuthority, key crypto.Signer, commonName string, names *core.Object, usage string, now, notAfter float64, crlURL string) ([]byte, string) {
	t.Helper()
	spec := core.NewObject("serialNumber", must(RandomSerial()))
	spec.SetRaw("issuer", issuer.subjectDer)
	subject := core.NewObject()
	if commonName != "" {
		subject.Set("commonName", commonName)
	}
	spec.SetRaw("subject", subject)
	spec.SetRaw("spki", must(x509.MarshalPKIXPublicKey(key.Public())))
	spec.Set("notBefore", now-pkiClockSkewMs)
	spec.Set("notAfter", notAfter)
	spec.SetRaw("names", names)
	spec.Set("usage", usage)
	spec.SetRaw("authorityKeyId", issuer.keyID)
	if crlURL != "" {
		spec.Set("crlUrl", crlURL)
	}
	tbs := must(TbsCertificate(spec, issuer.algorithm))
	der := must(SignedStructure(tbs, issuer.algorithm, must(signWith(issuer.key, issuer.algorithm, tbs))))
	return der, jsString(spec.Get("serialNumber"))
}

func TestX509CertificatesReadBackWithGo(t *testing.T) {
	now := 1_790_000_000_000.0
	one := 1.0
	root := makeTestAuthority(t, "Acme Root CA", nil, &one, nil, now)
	permitted := core.NewObject("dnsNames", items("internal", "localhost"), "uriHosts", items("acme.test"))
	issuing := makeTestAuthority(t, "Acme Workload CA", root, nil, permitted, now)
	rootCert := must(x509.ParseCertificate(root.der))
	issuingCert := must(x509.ParseCertificate(issuing.der))
	if !rootCert.IsCA || !issuingCert.IsCA || rootCert.MaxPathLen != 1 || rootCert.Subject.CommonName != "Acme Root CA" {
		t.Fatalf("root = %+v", rootCert)
	}
	if rootCert.CheckSignatureFrom(rootCert) != nil || issuingCert.CheckSignatureFrom(rootCert) != nil {
		t.Fatal("the chain does not verify with Go")
	}
	if strings.Join(issuingCert.PermittedDNSDomains, ",") != "internal,localhost" || strings.Join(issuingCert.PermittedURIDomains, ",") != "acme.test,.acme.test" || !issuingCert.PermittedDNSDomainsCritical {
		t.Fatalf("name constraints = %v %v", issuingCert.PermittedDNSDomains, issuingCert.PermittedURIDomains)
	}
	// The reader agrees: CA, issued by the root, verifying with its key.
	readRoot, readIssuing := must(parseCertificatePem(root.pem)), must(parseCertificatePem(issuing.pem))
	if !readRoot.ca() || !readIssuing.ca() || !readIssuing.checkIssued(readRoot) || !readIssuing.verify(must(readRoot.publicKey())) || !readRoot.verify(must(readRoot.publicKey())) {
		t.Fatal("the reader does not verify the chain")
	}
	if readIssuing.checkIssued(readIssuing) || readIssuing.verify(must(readIssuing.publicKey())) {
		t.Fatal("the intermediate verifies as self-signed")
	}
	if readRoot.subjectText() != "CN=Acme Root CA" {
		t.Fatalf("subject = %q", readRoot.subjectText())
	}
	// A leaf for a server key, for TLS: names, usage and the CRL distribution point are what Go sees too.
	names := must(SubjectAltNames(core.NewObject("dnsNames", items("localhost", "api.internal"), "ipAddresses", items("127.0.0.1"), "uris", items("spiffe://acme.test/billing"))))
	der, serial := makeTestLeaf(t, issuing, pkiKey(t, "rsa"), "localhost", names, "server", now, now+3_600_000, "https://pki.acme.test/crl/workloads.crl")
	leaf := must(x509.ParseCertificate(der))
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(rootCert)
	intermediates.AddCert(issuingCert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "api.internal", Roots: roots, Intermediates: intermediates, CurrentTime: leaf.NotBefore.Add(120_000_000_000), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("Go does not verify the leaf: %v", err)
	}
	if leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment || strings.Join(leaf.CRLDistributionPoints, ",") != "https://pki.acme.test/crl/workloads.crl" {
		t.Fatalf("leaf = %+v", leaf)
	}
	if leaf.SerialNumber.Text(16) != strings.TrimLeft(serial, "0") || leaf.NotAfter.UnixMilli() != int64(now+3_600_000) {
		t.Fatalf("serial %s / %s, notAfter %v", leaf.SerialNumber.Text(16), serial, leaf.NotAfter)
	}
	read := must(parseCertificateDer(der))
	if got := read.subjectAltNameText(); got != "DNS:localhost, DNS:api.internal, URI:spiffe://acme.test/billing, IP Address:127.0.0.1" {
		t.Fatalf("subjectAltName = %q", got)
	}
	if read.ca() || read.notAfter != now+3_600_000 || read.notBefore != now-60_000 || strings.ToLower(read.serialNumber()) != serial {
		t.Fatalf("read = %+v", read)
	}
	// An SVID: an empty subject makes the alternative names critical.
	svidNames := must(SubjectAltNames(core.NewObject("uris", items("spiffe://acme.test/service/abc"))))
	svid, _ := makeTestLeaf(t, issuing, pkiKey(t, "ed25519"), "", svidNames, "both", now, now+3_600_000, "")
	svidCert := must(x509.ParseCertificate(svid))
	var critical bool
	for _, extension := range svidCert.Extensions {
		if extension.Id.String() == x509OIDs.SubjectAltName {
			critical = extension.Critical
		}
	}
	if !critical || len(svidCert.Subject.Names) != 0 || must(parseCertificateDer(svid)).subjectText() != "" {
		t.Fatal("the SVID's names are not critical under an empty subject")
	}
}

func TestX509RevocationListsReadBackWithGo(t *testing.T) {
	now := 1_790_000_000_000.0
	root := makeTestAuthority(t, "Acme Root CA", nil, nil, nil, now)
	spec := core.NewObject()
	spec.SetRaw("issuer", root.subjectDer)
	spec.Set("thisUpdate", now)
	spec.Set("nextUpdate", now+crlLifetimeMs)
	spec.Set("crlNumber", 7.0)
	spec.SetRaw("authorityKeyId", root.keyID)
	spec.SetRaw("revoked", items(
		core.NewObject("serialNumber", "1a2b", "revokedAt", now-1000, "reason", "keyCompromise"),
		core.NewObject("serialNumber", "ff00", "revokedAt", now-2000, "reason", "unspecified"),
	))
	tbs := must(TbsCertList(spec, "ES256"))
	der := must(SignedStructure(tbs, "ES256", must(signWith(root.key, "ES256", tbs))))
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if list.CheckSignatureFrom(must(x509.ParseCertificate(root.der))) != nil {
		t.Fatal("the CRL does not verify")
	}
	if list.Number.Int64() != 7 || len(list.RevokedCertificateEntries) != 2 || list.ThisUpdate.UnixMilli() != int64(now) {
		t.Fatalf("list = %+v", list)
	}
	first, second := list.RevokedCertificateEntries[0], list.RevokedCertificateEntries[1]
	if first.SerialNumber.Cmp(big.NewInt(0x1a2b)) != 0 || first.ReasonCode != 1 || second.ReasonCode != 0 || len(second.Extensions) != 0 {
		t.Fatalf("entries = %+v", list.RevokedCertificateEntries)
	}
	if !strings.HasPrefix(must(CrlPem(der)), "-----BEGIN X509 CRL-----\n") {
		t.Fatal("crlPem")
	}
	// No entries: the list is left out.
	spec.SetRaw("revoked", items())
	empty := must(TbsCertList(spec, "EdDSA"))
	if _, err := x509.ParseRevocationList(must(SignedStructure(empty, "EdDSA", make([]byte, 64)))); err != nil {
		t.Fatalf("empty list: %v", err)
	}
}
