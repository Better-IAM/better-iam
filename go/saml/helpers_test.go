package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/core"
)

// keyPair is selfsigned's { private, cert, public }.
type keyPair struct {
	private string
	cert    string
	public  string
	key     *rsa.PrivateKey
}

var keyCache sync.Map

// generate is selfsigned.generate([{ name: 'commonName', value: name }], { keySize: 2048, algorithm: 'sha256' }).
func generate(t *testing.T, name string) keyPair {
	t.Helper()
	if cached, ok := keyCache.Load(name); ok {
		return cached.(keyPair)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pair := keyPair{
		private: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		cert:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		public:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})),
		key:     key,
	}
	keyCache.Store(name, pair)
	return pair
}

// sign is the tests' xml-crypto signer: an enveloped signature of every element named kind, placed after its Issuer.
func sign(t *testing.T, xml, kind string, key keyPair) string {
	t.Helper()
	signed, err := computeSignature(xml, signOptions{
		references: func(doc *Node) []*Node { return doc.Descendants(isLocal(kind)) },
		location: func(doc *Node) *Node {
			for _, element := range doc.Descendants(isLocal(kind)) {
				if issuers := element.ChildElements(isLocal("Issuer")); len(issuers) > 0 {
					return issuers[0]
				}
			}
			return nil
		},
		action:             "after",
		privateKey:         key.private,
		publicCert:         key.cert,
		signatureAlgorithm: algRsaSha256,
		digestAlgorithm:    algSha256,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// encryptElement is xml-encryption's encrypt with aes256-gcm content and rsa-oaep-mgf1p key transport.
func encryptElement(t *testing.T, content string, key keyPair) string {
	t.Helper()
	symmetric := make([]byte, 32)
	_, _ = rand.Read(symmetric)
	block, _ := aes.NewCipher(symmetric)
	aead, _ := cipher.NewGCM(block)
	iv := make([]byte, 12)
	_, _ = rand.Read(iv)
	sealed := append(iv, aead.Seal(nil, iv, []byte(content), nil)...)
	public := &key.key.PublicKey
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, public, symmetric, nil)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := pemToDer(key.cert)
	return `<xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">` +
		`<xenc:EncryptionMethod Algorithm="` + algAes256Gcm + `"/>` +
		`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">` +
		`<e:EncryptionMethod Algorithm="` + algRsaOaep + `"><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/></e:EncryptionMethod>` +
		`<KeyInfo><X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(der) + `</X509Certificate></X509Data></KeyInfo>` +
		`<e:CipherData><e:CipherValue>` + base64.StdEncoding.EncodeToString(wrapped) + `</e:CipherValue></e:CipherData></e:EncryptedKey></KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(sealed) + `</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>`
}

func b64(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }

func iso(ms int64) string { return isoString(ms) }

func nowMs() int64 { return time.Now().UnixMilli() }

var requestIDPattern = regexp.MustCompile(`\bID="([^"]+)"`)

// requestIDOf inflates the SAMLRequest of an IdP redirect URL and returns its ID.
func requestIDOf(t *testing.T, location string) (string, string) {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(parsed.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	match := requestIDPattern.FindStringSubmatch(string(inflated))
	if match == nil {
		t.Fatalf("no request ID in %s", inflated)
	}
	return match[1], string(inflated)
}

func newTestStore(t *testing.T) core.IamStore {
	t.Helper()
	store, err := sqlite.New(sqlite.Options{Filename: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	return store
}

func insertTenants(t *testing.T, store core.IamStore, ids ...string) {
	t.Helper()
	err := store.Transaction(context.Background(), func(ctx context.Context, tx core.IamStore) error {
		for _, id := range ids {
			if _, err := tx.Insert(ctx, "tenants", core.NewObject("id", id, "tenantId", id, "name", id, "type", "organization",
				"parentId", nil, "status", "active", "createdAt", float64(nowMs()))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func codeOf(err error) string {
	var known *core.IamError
	if errors.As(err, &known) {
		return known.Code
	}
	return ""
}

func statusOf(err error) int {
	var known *core.IamError
	if errors.As(err, &known) {
		return known.Status
	}
	return 0
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func ptr(value string) *string { return &value }

// bare strips PEM armor and whitespace from a certificate.
func bare(pemText string) string {
	return regexp.MustCompile(`-----(BEGIN|END) CERTIFICATE-----|\s`).ReplaceAllString(pemText, "")
}

func containsText(haystack, needle string) bool { return strings.Contains(haystack, needle) }
