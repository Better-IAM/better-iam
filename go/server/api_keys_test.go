package server

// Key management (KMS), after tests/kms.test.ts and tests/kms-security.test.ts. The organization, its members, roles
// and bindings are seeded in the store (roles.create and bindings.create are ported by other units); the keys API
// group and the KMS runtime are called through iam.API.Keys and iam.Kms.

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const kmsTestDay = 86_400_000.0

type kmsFixture struct {
	*trustOrg
	keys *KeysAPI
}

func newKmsFixture(t *testing.T) *kmsFixture {
	t.Helper()
	f := newTrustOrg(t, nil)
	return &kmsFixture{trustOrg: f, keys: f.iam.API.Keys}
}

// kmsCall calls a keys API method with a body that starts with the fixture's tenant.
func kmsCall[I, O any](f *kmsFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, pairs ...any) (any, error) {
	members := append([]any{"tenantId", f.tenantID}, pairs...)
	out, err := method(f.ctx, credential, Input[I](body(members...)))
	return out.Value, err
}

// kmsObject is kmsCall for an object answer that must succeed.
func kmsObject[I, O any](f *kmsFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, pairs ...any) *core.Object {
	f.t.Helper()
	value, err := kmsCall(f, method, credential, pairs...)
	if err != nil {
		f.t.Fatalf("unexpected error: %v", err)
	}
	object, ok := value.(*core.Object)
	if !ok {
		f.t.Fatalf("answer is not an object: %#v", value)
	}
	return object
}

// kmsList is kmsCall for a list answer that must succeed.
func kmsList[I, O any](f *kmsFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, pairs ...any) []*core.Object {
	f.t.Helper()
	value, err := kmsCall(f, method, credential, pairs...)
	if err != nil {
		f.t.Fatalf("unexpected error: %v", err)
	}
	list, ok := value.([]any)
	if !ok {
		f.t.Fatalf("answer is not a list: %#v", value)
	}
	objects := make([]*core.Object, len(list))
	for index, item := range list {
		objects[index] = item.(*core.Object)
	}
	return objects
}

// memberWith is a member holding one role of the statements (none: no role), optionally bound with extra members.
func (f *kmsFixture) memberWith(name string, statements []*core.Object, binding ...any) (string, core.CredentialInput, string) {
	f.t.Helper()
	person, credential := f.person(f.tenantID, name)
	bindingID := ""
	if len(statements) > 0 {
		roleID := f.role(f.tenantID, name+" keys", statements...)
		bindingID = f.bind(f.tenantID, roleID, "identity", jsString(person.Get("id")), binding...)
	}
	return jsString(person.Get("id")), credential, bindingID
}

func (f *kmsFixture) signInAs(identityID string) core.CredentialInput {
	f.t.Helper()
	return f.issue(f.record("identities", identityID), false)
}

// audit is the tenant's audit trail in chain order.
func (f *kmsFixture) audit() []*core.Object {
	events := f.find("audit", core.NewObject("tenantId", f.tenantID))
	sort.SliceStable(events, func(i, j int) bool { return jsNumber(events[i].Get("sequence")) < jsNumber(events[j].Get("sequence")) })
	return events
}

func (f *kmsFixture) auditOf(action string) []*core.Object {
	events := []*core.Object{}
	for _, event := range f.audit() {
		if event.Get("action") == action {
			events = append(events, event)
		}
	}
	return events
}

func kmsStatement(effect string, actions []any, resources []any, conditions *core.Object) *core.Object {
	statement := core.NewObject("effect", effect, "actions", actions, "resources", resources)
	if conditions != nil {
		statement.Set("conditions", conditions)
	}
	return statement
}

var kmsKeyAdmin = []*core.Object{kmsStatement("allow", items("iam:kms:*"), items("iam/kms", "iam/kms/*"), nil)}

func TestKmsEncryptsAndDecryptsUnderAnAliasBoundToTheContext(t *testing.T) {
	f := newKmsFixture(t)
	key := kmsObject(f, f.keys.Create, f.owner, "description", "Customer records", "alias", "alias/customers",
		"tags", core.NewObject("team", "payments"))
	if stringify(key.Get("aliases")) != `["alias/customers"]` || key.Get("keySpec") != "aes-256-gcm" || key.Get("keyUsage") != "encrypt" ||
		key.Get("state") != "enabled" || key.Get("currentVersion") != 1.0 || stringify(key.Get("algorithms")) != "[]" ||
		stringify(key.Get("tags")) != `{"team":"payments"}` {
		t.Fatalf("key = %s", stringify(key))
	}
	if strings.Contains(strings.ToLower(stringify(key)), "material") {
		t.Fatal("the summary names material")
	}
	keyID := jsString(key.Get("id"))
	sealed := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", "alias/customers", "plaintext", "card on file: 4242",
		"encryptionContext", core.NewObject("record", "cus_1"))
	ciphertext := jsString(sealed.Get("ciphertext"))
	if sealed.Get("keyId") != keyID || sealed.Get("keyVersion") != 1.0 || !strings.HasPrefix(ciphertext, "kms1."+keyID+".1.t.") ||
		strings.Contains(ciphertext, "4242") {
		t.Fatalf("sealed = %s", stringify(sealed))
	}
	opened := kmsObject(f, f.keys.Decrypt, f.owner, "ciphertext", ciphertext, "encryptionContext", core.NewObject("record", "cus_1"))
	if stringify(opened) != `{"plaintext":"card on file: 4242","keyId":"`+keyID+`","keyVersion":1}` {
		t.Fatalf("opened = %s", stringify(opened))
	}
	// A different context, or a flipped byte, fails the same way and is audited as a denied decrypt.
	_, err := kmsCall(f, f.keys.Decrypt, f.owner, "ciphertext", ciphertext, "encryptionContext", core.NewObject("record", "cus_2"))
	expectCodeStatus(t, err, "INVALID_CIPHERTEXT", 400)
	at := len(ciphertext) - 12
	flipped := "A"
	if ciphertext[at] == 'A' {
		flipped = "B"
	}
	tampered := ciphertext[:at] + flipped + ciphertext[at+1:]
	_, err = kmsCall(f, f.keys.Decrypt, f.owner, "ciphertext", tampered, "encryptionContext", core.NewObject("record", "cus_1"))
	expectCode(t, err, "INVALID_CIPHERTEXT")
	// Insisting on another key refuses before decrypting.
	other := kmsObject(f, f.keys.Create, f.owner)
	_, err = kmsCall(f, f.keys.Decrypt, f.owner, "ciphertext", ciphertext, "encryptionContext", core.NewObject("record", "cus_1"), "keyId", other.Get("id"))
	expectCode(t, err, "INVALID_CIPHERTEXT")

	allowed, refused := []*core.Object{}, 0
	for _, event := range f.auditOf("iam:kms:decrypt") {
		if event.Get("outcome") == "allow" {
			allowed = append(allowed, event)
		} else if member(event.Get("metadata"), "reason") == "invalid-ciphertext" {
			refused++
		}
	}
	if len(allowed) != 1 || refused != 2 {
		t.Fatalf("allowed %d, refused %d", len(allowed), refused)
	}
	if allowed[0].Get("resourceId") != "kms/"+keyID ||
		stringify(allowed[0].Get("metadata")) != `{"keyId":"`+keyID+`","encryptionContext":{"record":"cus_1"},"keyVersion":1}` {
		t.Fatalf("allowed = %s", stringify(allowed[0]))
	}
	if strings.Contains(stringify(allowed[0]), "4242") {
		t.Fatal("the audit event holds the plaintext")
	}
	// Binary plaintexts come back as base64.
	bytes := kmsRandomBytes(40)
	binary := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintextBase64", base64.StdEncoding.EncodeToString(bytes))
	openedBinary := kmsObject(f, f.keys.Decrypt, f.owner, "ciphertext", binary.Get("ciphertext"))
	if openedBinary.Get("plaintextBase64") != base64.StdEncoding.EncodeToString(bytes) || openedBinary.Has("plaintext") {
		t.Fatalf("binary = %s", stringify(openedBinary))
	}
	// The material is sealed at rest.
	versions := f.find("kmsKeyVersions", core.NewObject("tenantId", f.tenantID))
	for _, version := range versions {
		if _, ok := version.Get("materialSealed").(string); !ok {
			t.Fatalf("version = %s", stringify(version))
		}
	}
	if strings.Contains(stringify(versions), "PRIVATE KEY") {
		t.Fatal("material is stored in the clear")
	}
}

func TestKmsRotatesOnDemandAndOnScheduleWhileOldCiphertextsKeepDecrypting(t *testing.T) {
	f := newKmsFixture(t)
	key := kmsObject(f, f.keys.Create, f.owner, "rotationPeriodDays", 30.0)
	keyID := jsString(key.Get("id"))
	if key.Get("nextRotationAt") != f.now()+30*kmsTestDay {
		t.Fatalf("key = %s", stringify(key))
	}
	first := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", "v1")
	if rotated := kmsObject(f, f.keys.Rotate, f.owner, "keyId", keyID); rotated.Get("currentVersion") != 2.0 {
		t.Fatalf("rotated = %s", stringify(rotated))
	}
	second := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", "v2")
	if second.Get("keyVersion") != 2.0 {
		t.Fatalf("second = %s", stringify(second))
	}
	f.advance(int64(31 * kmsTestDay))
	owner := f.ownerSignIn(f.tenantID)
	maintained := must(f.iam.Kms.Maintain(f.ctx, nil))
	if stringify(maintained) != `{"rotated":[{"tenantId":"`+f.tenantID+`","keyId":"`+keyID+`","keyVersion":3}],"destroyed":[],"grantsRemoved":0}` {
		t.Fatalf("maintained = %s", stringify(maintained))
	}
	// Once rotated, nothing is due until the next period.
	if again := must(f.iam.Kms.Maintain(f.ctx, nil)); stringify(again.Get("rotated")) != "[]" {
		t.Fatalf("again = %s", stringify(again))
	}
	for _, pair := range [][2]any{{first, "v1"}, {second, "v2"}} {
		opened := kmsObject(f, f.keys.Decrypt, owner, "ciphertext", pair[0].(*core.Object).Get("ciphertext"))
		if opened.Get("plaintext") != pair[1] {
			t.Fatalf("opened = %s", stringify(opened))
		}
	}
	versions := kmsList(f, f.keys.ListVersions, owner, "keyId", keyID)
	summary := []string{}
	for _, version := range versions {
		summary = append(summary, stringify(items(version.Get("version"), version.Get("origin"), version.Get("current"))))
	}
	if strings.Join(summary, " ") != `[3,"automatic",true] [2,"rotate",false] [1,"create",false]` {
		t.Fatalf("versions = %v", summary)
	}
	rotatedBySystem := false
	for _, event := range f.auditOf("kms:key-rotate") {
		if event.Get("actorId") == "deployment-operator" {
			rotatedBySystem = true
		}
	}
	if !rotatedBySystem {
		t.Fatal("no kms:key-rotate event")
	}
	// Clearing the period stops automatic rotation.
	manual := kmsObject(f, f.keys.Update, owner, "keyId", keyID, "rotationPeriodDays", nil)
	if manual.Has("rotationPeriodDays") || manual.Has("nextRotationAt") {
		t.Fatalf("manual = %s", stringify(manual))
	}
}

func TestKmsIssuesDataKeysForEnvelopeEncryption(t *testing.T) {
	f := newKmsFixture(t)
	key := kmsObject(f, f.keys.Create, f.owner)
	keyID := jsString(key.Get("id"))
	dataKey := kmsObject(f, f.keys.GenerateDataKey, f.owner, "keyId", keyID, "encryptionContext", core.NewObject("bucket", "invoices"))
	plaintextKey, err := base64.StdEncoding.DecodeString(jsString(dataKey.Get("plaintextBase64")))
	if err != nil || dataKey.Get("bytes") != 32.0 || len(plaintextKey) != 32 {
		t.Fatalf("dataKey = %s", stringify(dataKey))
	}
	// The application encrypts locally with the plaintext key.
	block, err := aes.NewCipher(plaintextKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.NewGCM(block); err != nil {
		t.Fatal(err)
	}
	unwrapped := kmsObject(f, f.keys.Decrypt, f.owner, "ciphertext", dataKey.Get("ciphertext"), "encryptionContext", core.NewObject("bucket", "invoices"))
	if unwrapped.Get("plaintextBase64") != dataKey.Get("plaintextBase64") {
		t.Fatalf("unwrapped = %s", stringify(unwrapped))
	}
	withoutPlaintext := kmsObject(f, f.keys.GenerateDataKey, f.owner, "keyId", keyID, "bytes", 16.0, "includePlaintext", false)
	if withoutPlaintext.Has("plaintextBase64") || withoutPlaintext.Get("bytes") != 16.0 {
		t.Fatalf("withoutPlaintext = %s", stringify(withoutPlaintext))
	}
	_, err = kmsCall(f, f.keys.GenerateDataKey, f.owner, "keyId", keyID, "bytes", 20.0)
	expectError(t, err, "INVALID_INPUT", "bytes must be 16, 24, 32 or 64")
	// Re-encrypting moves a ciphertext to another key and context without exposing the plaintext.
	next := kmsObject(f, f.keys.Create, f.owner)
	moved := kmsObject(f, f.keys.ReEncrypt, f.owner, "ciphertext", dataKey.Get("ciphertext"),
		"sourceEncryptionContext", core.NewObject("bucket", "invoices"), "destinationKeyId", next.Get("id"),
		"destinationEncryptionContext", core.NewObject("bucket", "archive"))
	if moved.Get("keyId") != next.Get("id") || moved.Get("sourceKeyId") != keyID || moved.Get("keyVersion") != 1.0 {
		t.Fatalf("moved = %s", stringify(moved))
	}
	again := kmsObject(f, f.keys.Decrypt, f.owner, "ciphertext", moved.Get("ciphertext"), "encryptionContext", core.NewObject("bucket", "archive"))
	if again.Get("plaintextBase64") != dataKey.Get("plaintextBase64") {
		t.Fatalf("again = %s", stringify(again))
	}
	// Both events of the re-encryption carry the same id.
	decrypts, encrypts := f.auditOf("iam:kms:decrypt"), f.auditOf("iam:kms:encrypt")
	linked := member(decrypts[1].Get("metadata"), "reEncryptId")
	if isUndefined(linked) || !core.StrictEquals(member(encrypts[len(encrypts)-1].Get("metadata"), "reEncryptId"), linked) {
		t.Fatalf("decrypts = %s, encrypts = %s", stringify(decrypts), stringify(encrypts))
	}
}

// kmsOfflineVerify verifies a signature with the published public key, as an offline verifier would.
func kmsOfflineVerify(t *testing.T, publicKeyPem, algorithm string, message, signature []byte, jose bool) bool {
	t.Helper()
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("not an SPKI PEM: %s", publicKeyPem)
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if algorithm == "EdDSA" {
		return ed25519.Verify(public.(ed25519.PublicKey), message, signature)
	}
	hashID := crypto.SHA256
	if strings.HasSuffix(algorithm, "384") {
		hashID = crypto.SHA384
	}
	hasher := hashID.New()
	hasher.Write(message)
	digest := hasher.Sum(nil)
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		if jose {
			size := len(signature) / 2
			return ecdsa.Verify(key, digest, new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:]))
		}
		return ecdsa.VerifyASN1(key, digest, signature)
	case *rsa.PublicKey:
		return rsa.VerifyPSS(key, hashID, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	}
	return false
}

func TestKmsSignsAndVerifiesWithEcdsaEd25519AndRsaKeysOfflineToo(t *testing.T) {
	f := newKmsFixture(t)
	message := "release 1.2.3 sha256:abcdef"
	for _, test := range []struct{ spec, usage, algorithm string }{
		{"ecc-p256", "", "ES256"},
		{"ecc-p384", "", "ES384"},
		{"ed25519", "", "EdDSA"},
		{"rsa-2048", "sign", "PS256"},
	} {
		pairs := []any{"keySpec", test.spec}
		if test.usage != "" {
			pairs = append(pairs, "keyUsage", test.usage)
		}
		key := kmsObject(f, f.keys.Create, f.owner, pairs...)
		keyID := jsString(key.Get("id"))
		if algorithms := key.Get("algorithms").([]any); algorithms[0] != test.algorithm {
			t.Fatalf("%s algorithms = %s", test.spec, stringify(algorithms))
		}
		signed := kmsObject(f, f.keys.Sign, f.owner, "keyId", keyID, "message", message)
		if signed.Get("algorithm") != test.algorithm || signed.Get("format") != "der" {
			t.Fatalf("signed = %s", stringify(signed))
		}
		verified := kmsObject(f, f.keys.Verify, f.owner, "keyId", keyID, "message", message, "signature", signed.Get("signature"))
		if verified.Get("valid") != true || verified.Get("keyVersion") != 1.0 {
			t.Fatalf("verified = %s", stringify(verified))
		}
		if mismatch := kmsObject(f, f.keys.Verify, f.owner, "keyId", keyID, "message", message+"!", "signature", signed.Get("signature")); mismatch.Get("valid") != false {
			t.Fatalf("mismatch = %s", stringify(mismatch))
		}
		// Anyone holding the public key verifies without calling IAM.
		published := kmsObject(f, f.keys.PublicKey, f.owner, "keyId", keyID)
		signature, _ := base64.RawURLEncoding.DecodeString(jsString(signed.Get("signature")))
		if !kmsOfflineVerify(t, jsString(published.Get("publicKeyPem")), test.algorithm, []byte(message), signature, false) {
			t.Fatalf("%s: offline verification failed", test.spec)
		}
		jwk := published.Get("jwk").(*core.Object)
		if jwk.Get("kid") != keyID+".1" || jwk.Get("use") != "sig" {
			t.Fatalf("jwk = %s", stringify(jwk))
		}
		// JOSE-encoded ECDSA signatures verify too.
		if strings.HasPrefix(test.algorithm, "ES") {
			jose := kmsObject(f, f.keys.Sign, f.owner, "keyId", keyID, "message", message, "format", "jose")
			raw, _ := base64.RawURLEncoding.DecodeString(jsString(jose.Get("signature")))
			if !kmsOfflineVerify(t, jsString(published.Get("publicKeyPem")), test.algorithm, []byte(message), raw, true) {
				t.Fatalf("%s: jose verification failed", test.spec)
			}
			if valid := kmsObject(f, f.keys.Verify, f.owner, "keyId", keyID, "message", message, "signature", jose.Get("signature"), "format", "jose"); valid.Get("valid") != true {
				t.Fatalf("jose verify = %s", stringify(valid))
			}
		}
	}
	// Encryption keys cannot sign, signing keys cannot encrypt.
	aesKey := kmsObject(f, f.keys.Create, f.owner)
	_, err := kmsCall(f, f.keys.Sign, f.owner, "keyId", aesKey.Get("id"), "message", message)
	expectError(t, err, "INVALID_INPUT", "This key is for encrypt, not sign")
	_, err = kmsCall(f, f.keys.Create, f.owner, "keySpec", "rsa-2048")
	expectError(t, err, "INVALID_INPUT", "keyUsage is required for rsa-2048 (encrypt or sign)")
}

func TestKmsEncryptsSmallSecretsWithRsaOaepKeys(t *testing.T) {
	f := newKmsFixture(t)
	key := kmsObject(f, f.keys.Create, f.owner, "keySpec", "rsa-2048", "keyUsage", "encrypt")
	keyID := jsString(key.Get("id"))
	sealed := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", "short secret", "encryptionContext", core.NewObject("purpose", "test"))
	if opened := kmsObject(f, f.keys.Decrypt, f.owner, "ciphertext", sealed.Get("ciphertext"), "encryptionContext", core.NewObject("purpose", "test")); opened.Get("plaintext") != "short secret" {
		t.Fatalf("opened = %s", stringify(opened))
	}
	_, err := kmsCall(f, f.keys.Decrypt, f.owner, "ciphertext", sealed.Get("ciphertext"))
	expectCode(t, err, "INVALID_CIPHERTEXT")
	_, err = kmsCall(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", strings.Repeat("x", 300))
	expectError(t, err, "INVALID_INPUT", "rsa-2048 keys encrypt at most 190 bytes; encrypt a data key instead")
	jwk := kmsObject(f, f.keys.PublicKey, f.owner, "keyId", keyID).Get("jwk").(*core.Object)
	if jwk.Get("use") != "enc" || jwk.Get("kty") != "RSA" || jwk.Has("alg") || stringify(jwk.Keys()) != `["kty","n","e","kid","use"]` {
		t.Fatalf("jwk = %s", stringify(jwk))
	}
}

func TestKmsComputesMacsAndSignsAndVerifiesJwts(t *testing.T) {
	f := newKmsFixture(t)
	hmacKey := kmsObject(f, f.keys.Create, f.owner, "keySpec", "hmac-sha256")
	hmacID := jsString(hmacKey.Get("id"))
	mac := kmsObject(f, f.keys.GenerateMac, f.owner, "keyId", hmacID, "message", "webhook body")
	if mac.Get("algorithm") != "HS256" {
		t.Fatalf("mac = %s", stringify(mac))
	}
	if valid := kmsObject(f, f.keys.VerifyMac, f.owner, "keyId", hmacID, "message", "webhook body", "mac", mac.Get("mac")); valid.Get("valid") != true {
		t.Fatalf("valid = %s", stringify(valid))
	}
	if invalid := kmsObject(f, f.keys.VerifyMac, f.owner, "keyId", hmacID, "message", "webhook body.", "mac", mac.Get("mac")); invalid.Get("valid") != false {
		t.Fatalf("invalid = %s", stringify(invalid))
	}

	signer := kmsObject(f, f.keys.Create, f.owner, "keySpec", "ecc-p256", "alias", "alias/tokens")
	signerID := jsString(signer.Get("id"))
	issued := kmsObject(f, f.keys.SignJwt, f.owner, "keyId", "alias/tokens",
		"claims", core.NewObject("sub", "svc_1", "aud", "billing", "iss", "acme"), "expiresInSeconds", 300.0)
	if issued.Get("algorithm") != "ES256" {
		t.Fatalf("issued = %s", stringify(issued))
	}
	token := jsString(issued.Get("token"))
	parts := strings.Split(token, ".")
	header := must(kmsJSONSegment(parts[0], "header"))
	claims := must(kmsJSONSegment(parts[1], "claims"))
	if stringify(header) != `{"alg":"ES256","kid":"`+signerID+`.1","typ":"JWT"}` || jsNumber(claims.Get("exp"))-jsNumber(claims.Get("iat")) != 300 {
		t.Fatalf("header = %s, claims = %s", stringify(header), stringify(claims))
	}
	// The JWKS verifies it offline (JOSE signature encoding).
	jwks := kmsObject(f, f.keys.Jwks, f.owner, "keyId", signerID)
	jwk := jwks.Get("keys").([]any)[0].(*core.Object)
	if jwk.Get("kid") != header.Get("kid") || jwk.Get("alg") != "ES256" || stringify(jwk.Keys()) != `["kty","x","y","crv","kid","use","alg"]` {
		t.Fatalf("jwk = %s", stringify(jwk))
	}
	x, _ := base64.RawURLEncoding.DecodeString(jsString(jwk.Get("x")))
	y, _ := base64.RawURLEncoding.DecodeString(jsString(jwk.Get("y")))
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("offline JWT verification failed")
	}
	verified := kmsObject(f, f.keys.VerifyJwt, f.owner, "token", token, "audience", "billing", "issuer", "acme")
	if verified.Get("valid") != true || member(verified.Get("claims"), "sub") != "svc_1" {
		t.Fatalf("verified = %s", stringify(verified))
	}
	if other := kmsObject(f, f.keys.VerifyJwt, f.owner, "token", token, "audience", "other"); other.Get("valid") != false || other.Get("reason") != "audience" {
		t.Fatalf("other = %s", stringify(other))
	}
	// After rotation the old token still verifies by its kid; a forged one does not.
	kmsObject(f, f.keys.Rotate, f.owner, "keyId", signerID)
	if again := kmsObject(f, f.keys.VerifyJwt, f.owner, "token", token); again.Get("valid") != true {
		t.Fatalf("again = %s", stringify(again))
	}
	forgedClaims := claims.Spread()
	forgedClaims.Set("sub", "admin")
	forged := parts[0] + "." + base64url([]byte(stringify(forgedClaims))) + "." + parts[2]
	if result := kmsObject(f, f.keys.VerifyJwt, f.owner, "token", forged); result.Get("reason") != "signature" {
		t.Fatalf("forged = %s", stringify(result))
	}
	f.advance(10 * 60_000)
	if expired := kmsObject(f, f.keys.VerifyJwt, f.ownerSignIn(f.tenantID), "token", token); expired.Get("reason") != "expired" {
		t.Fatalf("expired = %s", stringify(expired))
	}
	// HMAC keys sign HS256 tokens.
	hs := kmsObject(f, f.keys.SignJwt, f.ownerSignIn(f.tenantID), "keyId", hmacID, "claims", core.NewObject("sub", "x"))
	if hs.Get("algorithm") != "HS256" {
		t.Fatalf("hs = %s", stringify(hs))
	}
	if valid := kmsObject(f, f.keys.VerifyJwt, f.ownerSignIn(f.tenantID), "token", hs.Get("token")); valid.Get("valid") != true {
		t.Fatalf("hs verify = %s", stringify(valid))
	}
}

func TestKmsAuthorizesByKeyTagsAndEncryptionContextAndRefusesOtherTenants(t *testing.T) {
	f := newKmsFixture(t)
	payments := kmsObject(f, f.keys.Create, f.owner, "tags", core.NewObject("team", "payments"))
	research := kmsObject(f, f.keys.Create, f.owner, "tags", core.NewObject("team", "research"))
	aliceID, alice, _ := f.memberWith("alice", []*core.Object{
		kmsStatement("allow", items("iam:kms:encrypt", "iam:kms:decrypt"), items("iam/kms/*"), core.NewObject("StringEquals",
			core.NewObject("resource.tags.team", "payments", "resource.encryptionContext.app", "billing"))),
		kmsStatement("allow", items("iam:kms:read"), items("iam/kms/*"), core.NewObject("StringEquals", core.NewObject("resource.tags.team", "payments"))),
	})
	sealed := kmsObject(f, f.keys.Encrypt, alice, "keyId", payments.Get("id"), "plaintext", "ok", "encryptionContext", core.NewObject("app", "billing"))
	_, err := kmsCall(f, f.keys.Encrypt, alice, "keyId", payments.Get("id"), "plaintext", "no", "encryptionContext", core.NewObject("app", "crm"))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = kmsCall(f, f.keys.Encrypt, alice, "keyId", research.Get("id"), "plaintext", "no", "encryptionContext", core.NewObject("app", "billing"))
	expectCode(t, err, "ACCESS_DENIED")
	if opened := kmsObject(f, f.keys.Decrypt, alice, "ciphertext", sealed.Get("ciphertext"), "encryptionContext", core.NewObject("app", "billing")); opened.Get("plaintext") != "ok" {
		t.Fatalf("opened = %s", stringify(opened))
	}
	// Listing shows only the keys a tag-scoped reader may read.
	listed := kmsObject(f, f.keys.List, alice)
	if ids := pluck(anaObjects(listed.Get("keys")), "id"); len(ids) != 1 || ids[0] != payments.Get("id") || listed.Get("total") != 1.0 {
		t.Fatalf("listed = %s", stringify(listed))
	}
	if all := kmsObject(f, f.keys.List, f.owner); all.Get("total") != 2.0 {
		t.Fatalf("all = %s", stringify(all))
	}
	// Management is a separate permission.
	_, err = kmsCall(f, f.keys.Disable, alice, "keyId", payments.Get("id"))
	expectCode(t, err, "ACCESS_DENIED")
	denied := false
	for _, event := range f.auditOf("iam:kms:update") {
		if event.Get("outcome") == "deny" && event.Get("actorId") == aliceID {
			denied = true
		}
	}
	if !denied {
		t.Fatal("the refused update is not audited")
	}
	// A tag-scoped administrator cannot re-tag a key out of their reach.
	_, admin, _ := f.memberWith("adam", []*core.Object{
		kmsStatement("allow", items("iam:kms:*"), items("iam/kms", "iam/kms/*"), core.NewObject("StringEquals", core.NewObject("resource.tags.team", "payments"))),
	})
	_, err = kmsCall(f, f.keys.Update, admin, "keyId", payments.Get("id"), "tags", core.NewObject("team", "research"))
	expectCode(t, err, "ACCESS_DENIED")
	retagged := kmsObject(f, f.keys.Update, admin, "keyId", payments.Get("id"), "tags", core.NewObject("team", "payments", "env", "prod"))
	if stringify(retagged.Get("tags")) != `{"team":"payments","env":"prod"}` {
		t.Fatalf("retagged = %s", stringify(retagged))
	}
	// And may only create keys carrying their tag.
	_, err = kmsCall(f, f.keys.Create, admin, "tags", core.NewObject("team", "research"))
	expectCode(t, err, "ACCESS_DENIED")
	kmsObject(f, f.keys.Create, admin, "tags", core.NewObject("team", "payments"))

	// Another organization's owner cannot use Acme's keys, even knowing their ids.
	globex, outsider := f.organization("Globex", "owner@globex.test")
	_, err = kmsCall(f, f.keys.Decrypt, outsider, "ciphertext", sealed.Get("ciphertext"), "encryptionContext", core.NewObject("app", "billing"))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = f.keys.Decrypt(f.ctx, outsider, Input[apitypes.KeysDecryptInput](body("tenantId", globex, "ciphertext", sealed.Get("ciphertext"),
		"encryptionContext", core.NewObject("app", "billing"))))
	expectCode(t, err, "NOT_FOUND")
}

func TestKmsDelegatesKeyUseThroughGrantsThatNeverExceedTheGrantor(t *testing.T) {
	f := newKmsFixture(t)
	key := kmsObject(f, f.keys.Create, f.owner)
	keyID := jsString(key.Get("id"))
	sealed := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", "billing data", "encryptionContext", core.NewObject("app", "billing", "record", "7"))
	crm := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", "crm data", "encryptionContext", core.NewObject("app", "crm"))
	bobID, bob, _ := f.memberWith("bob", nil)
	decrypt := func(credential core.CredentialInput, ciphertext any, bound *core.Object) (any, error) {
		return kmsCall(f, f.keys.Decrypt, credential, "ciphertext", ciphertext, "encryptionContext", bound)
	}
	billing := core.NewObject("app", "billing", "record", "7")
	_, err := decrypt(bob, sealed.Get("ciphertext"), billing)
	expectCode(t, err, "ACCESS_DENIED")

	grant := kmsObject(f, f.keys.CreateGrant, f.owner, "keyId", keyID, "granteeType", "identity", "granteeId", bobID,
		"operations", items("decrypt"), "constraints", core.NewObject("encryptionContextSubset", core.NewObject("app", "billing")), "name", "billing worker")
	if stringify(grant.Get("operations")) != `["decrypt"]` || grant.Get("active") != true || grant.Get("name") != "billing worker" {
		t.Fatalf("grant = %s", stringify(grant))
	}
	opened, err := decrypt(bob, sealed.Get("ciphertext"), billing)
	if err != nil || member(opened, "plaintext") != "billing data" {
		t.Fatalf("opened = %v %v", stringify(opened), err)
	}
	var used *core.Object
	for _, event := range f.auditOf("iam:kms:decrypt") {
		if event.Get("actorId") == bobID && event.Get("outcome") == "allow" {
			used = event
		}
	}
	if used == nil || member(used.Get("metadata"), "grantId") != grant.Get("id") {
		t.Fatalf("used = %s", stringify(used))
	}
	// Outside the constraint, or another operation, the grant does not apply.
	_, err = decrypt(bob, crm.Get("ciphertext"), core.NewObject("app", "crm"))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = kmsCall(f, f.keys.Encrypt, bob, "keyId", keyID, "plaintext", "x", "encryptionContext", core.NewObject("app", "billing"))
	expectCode(t, err, "ACCESS_DENIED")
	// Constraints only fit context operations; unknown operations are refused.
	signer := kmsObject(f, f.keys.Create, f.owner, "keySpec", "ed25519")
	_, err = kmsCall(f, f.keys.CreateGrant, f.owner, "keyId", signer.Get("id"), "granteeId", bobID, "operations", items("sign"),
		"constraints", core.NewObject("encryptionContextEquals", core.NewObject("a", "b")))
	expectError(t, err, "INVALID_INPUT", "Encryption context constraints apply only to encrypt, decrypt and generate-data-key grants")
	_, err = kmsCall(f, f.keys.CreateGrant, f.owner, "keyId", signer.Get("id"), "granteeId", bobID, "operations", items("decrypt"))
	expectError(t, err, "INVALID_INPUT", "A sign key's grants may allow read, sign, verify")

	// A grantor with the grant permission but without decrypt cannot hand out decrypt.
	_, carol, _ := f.memberWith("carol", []*core.Object{kmsStatement("allow", items("iam:kms:grant", "iam:kms:encrypt", "iam:kms:read"), items("iam/kms/*"), nil)})
	_, err = kmsCall(f, f.keys.CreateGrant, carol, "keyId", keyID, "granteeId", bobID, "operations", items("decrypt"))
	expectError(t, err, "ACCESS_DENIED", "You may not grant decrypt: you do not hold it")
	if granted := kmsObject(f, f.keys.CreateGrant, carol, "keyId", keyID, "granteeId", bobID, "operations", items("encrypt")); stringify(granted.Get("operations")) != `["encrypt"]` {
		t.Fatalf("granted = %s", stringify(granted))
	}
	// Groups are not grantees.
	_, err = kmsCall(f, f.keys.CreateGrant, f.owner, "keyId", keyID, "granteeType", "group", "granteeId", ID(), "operations", items("decrypt"))
	expectError(t, err, "INVALID_INPUT", "Grants name one identity; grant a group access with a role instead")
	// The grantee's own explicit denies still win over a grant.
	danaID, dana, _ := f.memberWith("dana", []*core.Object{kmsStatement("deny", items("iam:kms:decrypt"), items("iam/kms/*"),
		core.NewObject("StringEquals", core.NewObject("resource.encryptionContext.record", "7")))})
	kmsObject(f, f.keys.CreateGrant, f.owner, "keyId", keyID, "granteeId", danaID, "operations", items("decrypt"))
	if opened, err := decrypt(dana, crm.Get("ciphertext"), core.NewObject("app", "crm")); err != nil || member(opened, "plaintext") != "crm data" {
		t.Fatalf("dana crm = %v %v", stringify(opened), err)
	}
	_, err = decrypt(dana, sealed.Get("ciphertext"), billing)
	expectCode(t, err, "ACCESS_DENIED")

	// The grantee can retire its own grant; others cannot.
	_, err = kmsCall(f, f.keys.RetireGrant, carol, "grantId", grant.Get("id"))
	expectError(t, err, "ACCESS_DENIED", "Only the grantee can retire this grant")
	kmsObject(f, f.keys.RetireGrant, bob, "grantId", grant.Get("id"))
	_, err = decrypt(bob, sealed.Get("ciphertext"), billing)
	expectCode(t, err, "ACCESS_DENIED")
	if retired := f.auditOf("kms:grant-retire"); len(retired) != 1 || stringify(retired[0].Get("metadata")) != `{"grantId":"`+jsString(grant.Get("id"))+`"}` {
		t.Fatalf("retired = %s", stringify(retired))
	}
	grantees := pluck(kmsList(f, f.keys.ListGrants, f.owner, "keyId", keyID), "granteeId")
	sort.Strings(grantees)
	expected := []string{bobID, danaID}
	sort.Strings(expected)
	if stringify(grantees) != stringify(expected) {
		t.Fatalf("grantees = %v", grantees)
	}

	// Lapsed grants stop working and the maintenance job removes them.
	brief := kmsObject(f, f.keys.CreateGrant, f.owner, "keyId", keyID, "granteeType", "identity", "granteeId", bobID,
		"operations", items("decrypt"), "expiresAt", f.now()+60_000)
	f.advance(120_000)
	_, err = decrypt(bob, sealed.Get("ciphertext"), billing)
	expectCode(t, err, "ACCESS_DENIED")
	if maintained := must(f.iam.Kms.Maintain(f.ctx, nil)); maintained.Get("grantsRemoved") != 1.0 {
		t.Fatalf("maintained = %s", stringify(maintained))
	}
	for _, item := range kmsList(f, f.keys.ListGrants, f.owner, "keyId", keyID) {
		if item.Get("id") == brief.Get("id") {
			t.Fatal("the lapsed grant is still listed")
		}
	}
}

func TestKmsDisablesSchedulesDeletionCancelsAndDestroysKeys(t *testing.T) {
	f := newKmsFixture(t)
	key := kmsObject(f, f.keys.Create, f.owner, "alias", "alias/old")
	keyID := jsString(key.Get("id"))
	sealed := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", "soon unreadable")
	kmsObject(f, f.keys.Disable, f.owner, "keyId", keyID)
	_, err := kmsCall(f, f.keys.Decrypt, f.owner, "ciphertext", sealed.Get("ciphertext"))
	expectCodeStatus(t, err, "KEY_STATE_INVALID", 409)
	if refused := f.auditOf("iam:kms:decrypt"); len(refused) == 0 || stringify(refused[len(refused)-1].Get("metadata")) != `{"reason":"key-state"}` {
		t.Fatalf("refused = %s", stringify(refused))
	}
	kmsObject(f, f.keys.Enable, f.owner, "keyId", keyID)
	if opened := kmsObject(f, f.keys.Decrypt, f.owner, "ciphertext", sealed.Get("ciphertext")); opened.Get("plaintext") != "soon unreadable" {
		t.Fatalf("opened = %s", stringify(opened))
	}
	_, err = kmsCall(f, f.keys.ScheduleDeletion, f.owner, "keyId", keyID, "waitingDays", 3.0)
	expectError(t, err, "INVALID_INPUT", "Invalid waitingDays")
	pending := kmsObject(f, f.keys.ScheduleDeletion, f.owner, "keyId", keyID, "waitingDays", 7.0)
	if pending.Get("state") != "pending-deletion" || pending.Get("deletionDate") != f.now()+7*kmsTestDay {
		t.Fatalf("pending = %s", stringify(pending))
	}
	_, err = kmsCall(f, f.keys.Enable, f.owner, "keyId", keyID)
	expectError(t, err, "KEY_STATE_INVALID", "A key that is pending deletion cannot be enabled")
	restored := kmsObject(f, f.keys.CancelDeletion, f.owner, "keyId", keyID)
	if restored.Get("state") != "disabled" || restored.Has("deletionDate") {
		t.Fatalf("restored = %s", stringify(restored))
	}
	kmsObject(f, f.keys.ScheduleDeletion, f.owner, "keyId", keyID, "waitingDays", 7.0)
	f.advance(int64(6 * kmsTestDay))
	if maintained := must(f.iam.Kms.Maintain(f.ctx, nil)); stringify(maintained.Get("destroyed")) != "[]" {
		t.Fatalf("maintained = %s", stringify(maintained))
	}
	f.advance(int64(2 * kmsTestDay))
	if maintained := must(f.iam.Kms.Maintain(f.ctx, nil)); stringify(maintained.Get("destroyed")) != `[{"tenantId":"`+f.tenantID+`","keyId":"`+keyID+`"}]` {
		t.Fatalf("maintained = %s", stringify(maintained))
	}
	owner := f.ownerSignIn(f.tenantID)
	_, err = kmsCall(f, f.keys.Get, owner, "keyId", keyID)
	expectError(t, err, "NOT_FOUND", "Key not found")
	_, err = kmsCall(f, f.keys.Get, owner, "keyId", "alias/old")
	expectCode(t, err, "NOT_FOUND")
	_, err = kmsCall(f, f.keys.Decrypt, owner, "ciphertext", sealed.Get("ciphertext"))
	expectCode(t, err, "NOT_FOUND")
	if versions := f.find("kmsKeyVersions", core.NewObject("tenantId", f.tenantID)); len(versions) != 0 {
		t.Fatalf("versions = %s", stringify(versions))
	}
	if destroyed := f.auditOf("kms:key-destroy"); len(destroyed) != 1 || stringify(destroyed[0].Get("metadata")) != `{"keySpec":"aes-256-gcm","versions":1}` {
		t.Fatalf("destroyed = %s", stringify(destroyed))
	}
}

func TestKmsMovesAliasesBetweenKeysOfTheSameKind(t *testing.T) {
	f := newKmsFixture(t)
	first := kmsObject(f, f.keys.Create, f.owner, "alias", "alias/app")
	second := kmsObject(f, f.keys.Create, f.owner)
	signer := kmsObject(f, f.keys.Create, f.owner, "keySpec", "ecc-p256")
	_, err := kmsCall(f, f.keys.CreateAlias, f.owner, "alias", "alias/app", "keyId", second.Get("id"))
	expectError(t, err, "CONFLICT", "That alias is already in use")
	_, err = kmsCall(f, f.keys.UpdateAlias, f.owner, "alias", "alias/app", "keyId", signer.Get("id"))
	expectError(t, err, "INVALID_INPUT", "An alias can only move to a key of the same kind and usage")
	moved := kmsObject(f, f.keys.UpdateAlias, f.owner, "alias", "alias/app", "keyId", second.Get("id"))
	if moved.Get("keyId") != second.Get("id") || stringify(moved.Keys()) != `["name","keyId","createdAt","updatedAt"]` {
		t.Fatalf("moved = %s", stringify(moved))
	}
	if sealed := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", "alias/app", "plaintext", "x"); sealed.Get("keyId") != second.Get("id") {
		t.Fatalf("sealed = %s", stringify(sealed))
	}
	aliases := kmsList(f, f.keys.ListAliases, f.owner)
	if len(aliases) != 1 || aliases[0].Get("name") != "alias/app" || aliases[0].Get("keyId") != second.Get("id") {
		t.Fatalf("aliases = %s", stringify(aliases))
	}
	if got := kmsObject(f, f.keys.Get, f.owner, "keyId", first.Get("id")); stringify(got.Get("aliases")) != "[]" {
		t.Fatalf("first = %s", stringify(got))
	}
	kmsObject(f, f.keys.DeleteAlias, f.owner, "alias", "alias/app")
	_, err = kmsCall(f, f.keys.Encrypt, f.owner, "keyId", "alias/app", "plaintext", "x")
	expectCode(t, err, "NOT_FOUND")
	_, err = kmsCall(f, f.keys.CreateAlias, f.owner, "alias", "not-an-alias", "keyId", first.Get("id"))
	expectError(t, err, "INVALID_INPUT", "alias must be alias/{name} with letters, digits, slashes, underscores or hyphens")
	_, err = kmsCall(f, f.keys.CreateAlias, f.owner, "alias", "alias/x", "keyId", "alias/app")
	expectError(t, err, "INVALID_INPUT", "keyId must be a key id, not an alias")
}

func TestKmsStopsAGrantOnceItsCreatorLosesTheAccessItPassedOn(t *testing.T) {
	f := newKmsFixture(t)
	key := kmsObject(f, f.keys.Create, f.owner)
	keyID := jsString(key.Get("id"))
	sealed := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", "payroll")
	// Gina's key access lasts an hour; she grants herself and Bob decrypt.
	ginaID, gina, _ := f.memberWith("gina", kmsKeyAdmin, "expiresAt", f.now()+3_600_000)
	bobID, bob, _ := f.memberWith("bob", nil)
	kmsObject(f, f.keys.CreateGrant, gina, "keyId", keyID, "granteeId", ginaID, "operations", items("decrypt"))
	kmsObject(f, f.keys.CreateGrant, gina, "keyId", keyID, "granteeId", bobID, "operations", items("decrypt"))
	open := func(credential core.CredentialInput) (any, error) {
		return kmsCall(f, f.keys.Decrypt, credential, "ciphertext", sealed.Get("ciphertext"))
	}
	if opened, err := open(bob); err != nil || member(opened, "plaintext") != "payroll" {
		t.Fatalf("opened = %v %v", stringify(opened), err)
	}
	f.advance(2 * 3_600_000)
	// Her binding expired: neither her self-grant nor Bob's grant works any more.
	_, err := open(f.signInAs(ginaID))
	expectCode(t, err, "ACCESS_DENIED")
	_, err = open(f.signInAs(bobID))
	expectCode(t, err, "ACCESS_DENIED")

	// Deleting the creator's binding does the same.
	_, hana, hanaBinding := f.memberWith("hana", kmsKeyAdmin)
	ivanID, ivan, _ := f.memberWith("ivan", nil)
	kmsObject(f, f.keys.CreateGrant, hana, "keyId", keyID, "granteeId", ivanID, "operations", items("decrypt"))
	if opened, err := open(ivan); err != nil || member(opened, "plaintext") != "payroll" {
		t.Fatalf("ivan = %v %v", stringify(opened), err)
	}
	f.transact(func(ctx context.Context, tx core.IamStore) error { return tx.Delete(ctx, "bindings", hanaBinding) })
	_, err = open(ivan)
	expectCode(t, err, "ACCESS_DENIED")
}

func TestKmsCarriesTheCreatorsConditionalDeniesIntoEveryUseOfAGrant(t *testing.T) {
	f := newKmsFixture(t)
	key := kmsObject(f, f.keys.Create, f.owner)
	keyID := jsString(key.Get("id"))
	secret := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", "TOP SECRET", "encryptionContext", core.NewObject("class", "secret"))
	internal := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", "internal", "encryptionContext", core.NewObject("class", "internal"))
	_, gina, _ := f.memberWith("gina", append(append([]*core.Object{}, kmsKeyAdmin...), kmsStatement("deny", items("iam:kms:decrypt"), items("iam/kms/*"),
		core.NewObject("StringEquals", core.NewObject("resource.encryptionContext.class", "secret")))))
	bobID, bob, _ := f.memberWith("bob", nil)
	kmsObject(f, f.keys.CreateGrant, gina, "keyId", keyID, "granteeId", bobID, "operations", items("decrypt"))
	if opened := kmsObject(f, f.keys.Decrypt, bob, "ciphertext", internal.Get("ciphertext"), "encryptionContext", core.NewObject("class", "internal")); opened.Get("plaintext") != "internal" {
		t.Fatalf("opened = %s", stringify(opened))
	}
	_, err := kmsCall(f, f.keys.Decrypt, bob, "ciphertext", secret.Get("ciphertext"), "encryptionContext", core.NewObject("class", "secret"))
	expectCode(t, err, "ACCESS_DENIED")
}

func TestKmsAuthorizesAliasNamesSoNobodyCanSquatOnANameOthersRelyOn(t *testing.T) {
	f := newKmsFixture(t)
	key := kmsObject(f, f.keys.Create, f.owner, "tags", core.NewObject("team", "search"))
	_, operator, _ := f.memberWith("keyops", []*core.Object{
		kmsStatement("allow", items("iam:kms:update", "iam:kms:read"), items("iam/kms/*"), nil),
		kmsStatement("deny", items("iam:kms:update"), items("iam/kms/alias/prod-*"), nil),
	})
	_, err := kmsCall(f, f.keys.CreateAlias, operator, "alias", "alias/prod-db", "keyId", key.Get("id"))
	expectError(t, err, "ACCESS_DENIED", "You may not manage the alias alias/prod-db")
	if alias := kmsObject(f, f.keys.CreateAlias, operator, "alias", "alias/dev-db", "keyId", key.Get("id")); alias.Get("name") != "alias/dev-db" {
		t.Fatalf("alias = %s", stringify(alias))
	}
	refused := false
	for _, event := range f.auditOf("iam:kms:update") {
		if event.Get("outcome") == "deny" && member(event.Get("metadata"), "reason") == "refused" {
			refused = true
		}
	}
	if !refused {
		t.Fatal("the refusal is not audited")
	}
}

func TestKmsRefusesTokensWithCriticalHeadersOrMalformedTimes(t *testing.T) {
	f := newKmsFixture(t)
	hmacKey := kmsObject(f, f.keys.Create, f.owner, "keySpec", "hmac-sha256")
	hmacID := jsString(hmacKey.Get("id"))
	sign := func(header, claims *core.Object) string {
		full := core.NewObject("alg", "HS256", "kid", hmacID+".1")
		full.Assign(header)
		signingInput := base64url([]byte(stringify(full))) + "." + base64url([]byte(stringify(claims)))
		mac := kmsObject(f, f.keys.GenerateMac, f.owner, "keyId", hmacID, "message", signingInput)
		return signingInput + "." + jsString(mac.Get("mac"))
	}
	verify := func(token string) *core.Object { return kmsObject(f, f.keys.VerifyJwt, f.owner, "token", token) }
	if result := verify(sign(core.NewObject(), core.NewObject("sub", "ok"))); result.Get("valid") != true {
		t.Fatalf("ok = %s", stringify(result))
	}
	if result := verify(sign(core.NewObject("crit", items("exp")), core.NewObject("sub", "x"))); result.Get("reason") != "header" {
		t.Fatalf("crit = %s", stringify(result))
	}
	if result := verify(sign(core.NewObject(), core.NewObject("exp", "9999999999"))); result.Get("reason") != "claims" {
		t.Fatalf("claims = %s", stringify(result))
	}
	// A MAC spelled with non-canonical trailing bits is not accepted as the same MAC.
	mac := jsString(kmsObject(f, f.keys.GenerateMac, f.owner, "keyId", hmacID, "message", "m").Get("mac"))
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	twin := mac[:len(mac)-1] + string(alphabet[strings.IndexByte(alphabet, mac[len(mac)-1])^1])
	if string(nodeBase64Decode(twin)) == string(nodeBase64Decode(mac)) {
		_, err := kmsCall(f, f.keys.VerifyMac, f.owner, "keyId", hmacID, "message", "m", "mac", twin)
		expectError(t, err, "INVALID_INPUT", "mac must be canonical base64")
	}
	// Malformed tokens are refused before anything is looked up.
	_, err := kmsCall(f, f.keys.VerifyJwt, f.owner, "token", "a.b")
	expectError(t, err, "INVALID_INPUT", "token must be a compact JWS")
	_, err = kmsCall(f, f.keys.VerifyJwt, f.owner, "token", "e30.e30.")
	expectError(t, err, "INVALID_INPUT", "The token has no KMS kid; pass keyId")
	_, err = kmsCall(f, f.keys.VerifyJwt, f.owner, "token", "W10.e30.")
	expectError(t, err, "INVALID_INPUT", "The token header is not valid JSON")
}

func TestKmsLetsPoliciesLimitTheTokensACallerMayMint(t *testing.T) {
	f := newKmsFixture(t)
	signer := kmsObject(f, f.keys.Create, f.owner, "keySpec", "ed25519")
	_, minter, _ := f.memberWith("minter", []*core.Object{
		kmsStatement("allow", items("iam:kms:sign"), items("iam/kms/*"), core.NewObject("Bool", core.NewObject("resource.jwt", true),
			"StringEquals", core.NewObject("resource.jwt.aud", "billing"))),
	})
	if token := kmsObject(f, f.keys.SignJwt, minter, "keyId", signer.Get("id"), "claims", core.NewObject("aud", "billing")); token.Get("algorithm") != "EdDSA" {
		t.Fatalf("token = %s", stringify(token))
	}
	_, err := kmsCall(f, f.keys.SignJwt, minter, "keyId", signer.Get("id"), "claims", core.NewObject("aud", "admin"))
	expectCode(t, err, "ACCESS_DENIED")
	// Raw signatures are not tokens.
	_, err = kmsCall(f, f.keys.Sign, minter, "keyId", signer.Get("id"), "message", "anything")
	expectCode(t, err, "ACCESS_DENIED")
}

func TestKmsNeverLetsAChangeOfTagsOrAliasesOpenAKeyToTheOneMakingIt(t *testing.T) {
	f := newKmsFixture(t)
	key := kmsObject(f, f.keys.Create, f.owner, "tags", core.NewObject("team", "payments"))
	keyID := jsString(key.Get("id"))
	sealed := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", "card on file: 4242")
	_, operator, _ := f.memberWith("keyops", []*core.Object{
		kmsStatement("allow", items("iam:kms:update", "iam:kms:read"), items("iam/kms/*"), nil),
		kmsStatement("allow", items("iam:kms:decrypt"), items("iam/kms/*"), core.NewObject("StringEquals", core.NewObject("resource.tags.team", "search"))),
		kmsStatement("deny", items("iam:kms:decrypt"), items("iam/kms/*"), core.NewObject("ArrayContains", core.NewObject("resource.aliases", "alias/prod-search"))),
	})
	_, err := kmsCall(f, f.keys.Update, operator, "keyId", keyID, "tags", core.NewObject("team", "search"))
	expectError(t, err, "ACCESS_DENIED", "That change would give you iam:kms:decrypt on this key")
	_, err = kmsCall(f, f.keys.Decrypt, operator, "ciphertext", sealed.Get("ciphertext"))
	expectCode(t, err, "ACCESS_DENIED")
	// Tags that open nothing new are fine.
	if updated := kmsObject(f, f.keys.Update, operator, "keyId", keyID, "tags", core.NewObject("team", "payments", "owner", "ops")); stringify(updated.Get("tags")) != `{"team":"payments","owner":"ops"}` {
		t.Fatalf("updated = %s", stringify(updated))
	}
	// A search key under a production alias: dropping the alias would lift the deny.
	search := kmsObject(f, f.keys.Create, f.owner, "tags", core.NewObject("team", "search"), "alias", "alias/prod-search")
	_, err = kmsCall(f, f.keys.DeleteAlias, operator, "alias", "alias/prod-search")
	expectCode(t, err, "ACCESS_DENIED")
	// Moving it away would too; the owner may.
	spare := kmsObject(f, f.keys.Create, f.owner, "tags", core.NewObject("team", "payments"))
	_, err = kmsCall(f, f.keys.UpdateAlias, operator, "alias", "alias/prod-search", "keyId", spare.Get("id"))
	expectCode(t, err, "ACCESS_DENIED")
	kmsObject(f, f.keys.DeleteAlias, f.owner, "alias", "alias/prod-search")
	if got := kmsObject(f, f.keys.Get, operator, "keyId", search.Get("id")); stringify(got.Get("aliases")) != "[]" {
		t.Fatalf("search = %s", stringify(got))
	}
}

func TestKmsAnswersCallersFromOtherTenantsTheSameWhetherAKeyExists(t *testing.T) {
	f := newKmsFixture(t)
	key := kmsObject(f, f.keys.Create, f.owner)
	_, outsider := f.organization("Beta", "owner@beta.test")
	_, existing := kmsCall(f, f.keys.Get, outsider, "keyId", key.Get("id"))
	_, missing := kmsCall(f, f.keys.Get, outsider, "keyId", ID())
	expectError(t, existing, "ACCESS_DENIED", "Access denied")
	expectError(t, missing, "ACCESS_DENIED", "Access denied")
	for _, event := range f.auditOf("iam:kms:read") {
		if event.Get("resourceId") != "kms" || stringify(event.Get("metadata")) != `{"reason":"tenant"}` {
			t.Fatalf("event = %s", stringify(event))
		}
	}
}

func TestKmsNeverShowsPlaintextsDataKeysOrTokensToPlugins(t *testing.T) {
	seen := []string{}
	f := &kmsFixture{trustOrg: newTrustOrg(t, func(options *BetterIamOptions) {
		options.Plugins = []*core.IamPlugin{{ID: "observer", Hooks: &core.PluginHooks{
			AfterOperation: func(ctx context.Context, input core.OperationHookInput) error {
				seen = append(seen, stringify(input.Result))
				return nil
			},
		}}}
	})}
	f.keys = f.iam.API.Keys
	key := kmsObject(f, f.keys.Create, f.owner)
	sealed := kmsObject(f, f.keys.Encrypt, f.owner, "keyId", key.Get("id"), "plaintext", "very secret value")
	kmsObject(f, f.keys.Decrypt, f.owner, "ciphertext", sealed.Get("ciphertext"))
	dataKey := kmsObject(f, f.keys.GenerateDataKey, f.owner, "keyId", key.Get("id"))
	hmacKey := kmsObject(f, f.keys.Create, f.owner, "keySpec", "hmac-sha256")
	token := kmsObject(f, f.keys.SignJwt, f.owner, "keyId", hmacKey.Get("id"), "claims", core.NewObject("sub", "x"))
	everything := strings.Join(seen, "\n")
	for _, secret := range []string{"very secret value", jsString(dataKey.Get("plaintextBase64")), jsString(token.Get("token"))} {
		if strings.Contains(everything, secret) {
			t.Fatalf("a plugin saw %q", secret)
		}
	}
	if !strings.Contains(everything, `"keyVersion":1`) {
		t.Fatalf("seen = %s", everything)
	}
}

func TestKmsProtectsStoredValuesOfAnySizeUnderAnAesKeyOnly(t *testing.T) {
	f := newKmsFixture(t)
	aesKey := kmsObject(f, f.keys.Create, f.owner, "alias", "alias/vault")
	rsaKey := kmsObject(f, f.keys.Create, f.owner, "keySpec", "rsa-2048", "keyUsage", "encrypt")
	server := f.iam.Context
	vault := core.NewObject("via", "vault")
	large := strings.Repeat("x", 200_000) + " and a tail"
	var sealed *core.Object
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		var err error
		sealed, err = KmsEncryptFor(ctx, server, tx, f.tenantID, "alias/vault", large, "secret-1", vault)
		return err
	})
	if sealed.Get("keyId") != aesKey.Get("id") || strings.Contains(jsString(sealed.Get("ciphertext")), "tail") {
		t.Fatalf("sealed = %.200s", stringify(sealed))
	}
	decrypt := func(value *core.Object, bound string) (string, error) {
		return core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (string, error) {
			return KmsDecryptFor(ctx, server, tx, f.tenantID, value, bound, vault)
		})
	}
	if opened, err := decrypt(sealed, "secret-1"); err != nil || opened != large {
		t.Fatalf("opened %d bytes, %v", len(opened), err)
	}
	_, err := decrypt(sealed, "secret-2")
	expectCode(t, err, "INVALID_CIPHERTEXT")
	// The payload cannot be moved under another wrapped data key.
	var other *core.Object
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		var err error
		other, err = KmsEncryptFor(ctx, server, tx, f.tenantID, jsString(aesKey.Get("id")), "other", "secret-1", nil)
		return err
	})
	wrapped := strings.Split(jsString(other.Get("ciphertext")), "~")[0]
	payload := strings.Split(jsString(sealed.Get("ciphertext")), "~")[1]
	_, err = decrypt(core.NewObject("ciphertext", wrapped+"~"+payload), "secret-1")
	expectCode(t, err, "INVALID_CIPHERTEXT")
	_, err = core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return KmsEncryptFor(ctx, server, tx, f.tenantID, jsString(rsaKey.Get("id")), "x", "secret-1", nil)
	})
	expectError(t, err, "INVALID_INPUT", "Only aes-256-gcm keys can protect stored values")
	audited := []string{}
	for _, event := range f.audit() {
		if event.Get("actorId") == "deployment-operator" {
			audited = append(audited, jsString(event.Get("action"))+" "+jsString(member(event.Get("metadata"), "via")))
		}
	}
	if strings.Join(audited, ", ") != "iam:kms:encrypt vault, iam:kms:decrypt vault, iam:kms:encrypt service" {
		t.Fatalf("audited = %v", audited)
	}
}

func TestKmsServiceKeysAndDataKeys(t *testing.T) {
	f := newKmsFixture(t)
	server := f.iam.Context
	var key *core.Object
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		var err error
		key, err = CreateServiceKey(ctx, server, tx, core.NewObject("tenantId", f.tenantID, "keySpec", "aes-256-gcm", "keyUsage", "encrypt",
			"description", "Data protection profile: cards", "tags", core.NewObject("protection-profile", "cards"), "createdBy", f.ownerID,
			"managedBy", "protection", "managedId", "profile-1"))
		return err
	})
	keyID := jsString(key.Get("id"))
	if stringify(key.Keys()) != `["id","tenantId","description","keySpec","keyUsage","state","currentVersion","tags","managedBy","managedId","createdAt","createdBy","updatedAt"]` {
		t.Fatalf("key = %s", stringify(key))
	}
	// The KMS API refuses to use a managed key directly.
	_, err := kmsCall(f, f.keys.Encrypt, f.owner, "keyId", keyID, "plaintext", "x")
	expectError(t, err, "KEY_MANAGED", "This key protects a data protection profile; use the protection API")
	if summary := kmsObject(f, f.keys.Get, f.owner, "keyId", keyID); summary.Get("managedBy") != "protection" || summary.Get("managedId") != "profile-1" {
		t.Fatalf("summary = %s", stringify(summary))
	}
	use := core.NewObject("via", "protection")
	var dataKey []byte
	var wrapped string
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		result, err := KmsDataKeyFor(ctx, server, tx, f.tenantID, keyID, core.NewObject("protection", "profile-1"), use)
		if err != nil {
			return err
		}
		dataKey, wrapped = dataKeyOf(result)
		return nil
	})
	if len(dataKey) != 32 || !strings.HasPrefix(wrapped, "kms1."+keyID+".1.b.") {
		t.Fatalf("data key %d bytes, wrapped %s", len(dataKey), wrapped)
	}
	opened, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) ([]byte, error) {
		return KmsOpenDataKeyFor(ctx, server, tx, f.tenantID, wrapped, core.NewObject("protection", "profile-1"), use)
	})
	if err != nil || string(opened) != string(dataKey) {
		t.Fatalf("opened = %x, %v", opened, err)
	}
	_, err = core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) ([]byte, error) {
		return KmsOpenDataKeyFor(ctx, server, tx, f.tenantID, wrapped, core.NewObject("protection", "profile-2"), use)
	})
	expectError(t, err, "INVALID_CIPHERTEXT", "The ciphertext could not be decrypted with this key and encryption context")
	// Retiring leaves other modules' keys alone and schedules the module's own for deletion once.
	retire := func(managedBy, managedID string) *float64 {
		var date *float64
		f.transact(func(ctx context.Context, tx core.IamStore) error {
			var err error
			date, err = RetireServiceKey(ctx, server, tx, f.tenantID, keyID, managedBy, managedID)
			return err
		})
		return date
	}
	if retire("pki", "profile-1") != nil || retire("protection", "profile-2") != nil {
		t.Fatal("retired a key the module does not manage")
	}
	if date := retire("protection", "profile-1"); date == nil || *date != f.now()+7*kmsTestDay {
		t.Fatalf("date = %v", date)
	}
	if retire("protection", "profile-1") != nil {
		t.Fatal("retired twice")
	}
	if stored := f.record("kmsKeys", keyID); stored.Get("state") != "pending-deletion" {
		t.Fatalf("stored = %s", stringify(stored))
	}
}

func TestKmsSignsForAnotherModuleWithAPinnedVersion(t *testing.T) {
	f := newKmsFixture(t)
	server := f.iam.Context
	key := kmsObject(f, f.keys.Create, f.owner, "keySpec", "ecc-p256")
	keyID := jsString(key.Get("id"))
	data := []byte("tbsCertificate")
	signature, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) ([]byte, error) {
		return KmsSignFor(ctx, server, tx, f.tenantID, keyID, 1, "ES256", data, core.NewObject("via", "pki"))
	})
	if err != nil {
		t.Fatal(err)
	}
	published := kmsObject(f, f.keys.PublicKey, f.owner, "keyId", keyID)
	if !kmsOfflineVerify(t, jsString(published.Get("publicKeyPem")), "ES256", data, signature, false) {
		t.Fatal("the signature does not verify")
	}
	_, err = core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) ([]byte, error) {
		return KmsSignFor(ctx, server, tx, f.tenantID, keyID, 1, "ES384", data, core.NewObject("via", "pki"))
	})
	expectError(t, err, "INVALID_INPUT", "This key does not sign with ES384")
	signs := f.auditOf("iam:kms:sign")
	if len(signs) != 1 || stringify(signs[0].Get("metadata")) != `{"keyVersion":1,"algorithm":"ES256","via":"pki"}` {
		t.Fatalf("signs = %s", stringify(signs))
	}
}

func TestKmsValidatesInputBeforeAnythingElse(t *testing.T) {
	f := newKmsFixture(t)
	nobody := core.CredentialInput{Token: "nope"}
	_, err := kmsCall(f, f.keys.Create, nobody, "keySpec", "des")
	expectError(t, err, "INVALID_INPUT", "keySpec must be one of aes-256-gcm, hmac-sha256, hmac-sha384, hmac-sha512, ecc-p256, ecc-p384, ed25519, rsa-2048, rsa-3072, rsa-4096")
	_, err = kmsCall(f, f.keys.Create, nobody, "keySpec", "ed25519", "keyUsage", "encrypt")
	expectError(t, err, "INVALID_INPUT", "ed25519 keys support keyUsage sign")
	_, err = kmsCall(f, f.keys.Create, nobody, "rotationPeriodDays", 0.0)
	expectError(t, err, "INVALID_INPUT", "Invalid rotationPeriodDays")
	_, err = kmsCall(f, f.keys.Encrypt, nobody, "keyId", "k")
	expectError(t, err, "INVALID_INPUT", "Provide either plaintext or plaintextBase64")
	_, err = kmsCall(f, f.keys.Encrypt, nobody, "keyId", "k", "plaintext", "x", "plaintextBase64", "eA")
	expectError(t, err, "INVALID_INPUT", "Provide either plaintext or plaintextBase64")
	_, err = kmsCall(f, f.keys.Encrypt, nobody, "keyId", "k", "plaintext", strings.Repeat("x", 4097))
	expectError(t, err, "INVALID_INPUT", "plaintext is longer than 4096 bytes")
	_, err = kmsCall(f, f.keys.Decrypt, nobody, "ciphertext", "kms1.x.1.t")
	expectError(t, err, "INVALID_CIPHERTEXT", "The ciphertext is not valid")
	_, err = kmsCall(f, f.keys.List, nobody, "state", "lost")
	expectError(t, err, "INVALID_INPUT", "Invalid state")
	_, err = kmsCall(f, f.keys.Sign, nobody, "keyId", "k", "message", "m", "format", "pem")
	expectError(t, err, "INVALID_INPUT", "format must be der or jose")
	_, err = kmsCall(f, f.keys.Encrypt, nobody, "keyId", "k", "plaintext", "x")
	expectCode(t, err, "UNAUTHENTICATED")
}

func TestKmsHelpers(t *testing.T) {
	tags, err := KeyTags(core.NewObject("team", "payments", "cost:center", "42"))
	if err != nil || stringify(tags) != `{"team":"payments","cost:center":"42"}` {
		t.Fatalf("tags = %s %v", stringify(tags), err)
	}
	_, err = KeyTags(core.NewObject("constructor", "x"))
	expectError(t, err, "INVALID_INPUT", "Invalid tag key constructor")
	_, err = KeyTags(core.NewObject("team", strings.Repeat("x", 257)))
	expectError(t, err, "INVALID_INPUT", "Tag team must be a string of at most 256 characters")
	_, err = KeyTags(nil)
	expectError(t, err, "INVALID_INPUT", "Expected an object")
	_, err = EncryptionContext(core.NewObject("app", ""), "")
	expectError(t, err, "INVALID_INPUT", "encryptionContext values must be non-empty strings of at most 1024 characters")
	_, err = EncryptionContext(core.NewObject("bad key", "x"), "sourceEncryptionContext")
	expectError(t, err, "INVALID_INPUT", "Invalid sourceEncryptionContext key bad key")

	for _, test := range []struct {
		value string
		bytes string
		code  string
	}{
		{"aGk", "hi", ""},
		{"aGk=", "hi", ""},
		{"aGl", "", "mac must be canonical base64"},
		{"a+b/", "k\xe6\xff", ""},
		{"a-b/", "", "mac must be base64"},
		{"!!", "", "mac must be base64"},
	} {
		bytes, err := Base64Bytes(test.value, "mac", 128)
		if test.code != "" {
			expectError(t, err, "INVALID_INPUT", test.code)
		} else if err != nil || string(bytes) != test.bytes {
			t.Fatalf("%s: %q %v", test.value, bytes, err)
		}
	}
	_, err = Base64Bytes(base64url(make([]byte, 9)), "mac", 8)
	expectError(t, err, "INVALID_INPUT", "mac is longer than 8 bytes")

	parsed, err := ParseCiphertext("kms1.abc-1.12.b.AAAA")
	if err != nil || parsed.Get("keyId") != "abc-1" || parsed.Get("version") != 12.0 || parsed.Get("text") != false || parsed.Get("header") != "kms1.abc-1.12.b" {
		t.Fatalf("parsed = %s %v", stringify(parsed), err)
	}
	for _, value := range []any{42.0, "kms2.a.1.t.AAAA", "kms1.a.01.t.AAAA", "kms1.a.1.x.AAAA", "kms1.a.1.t.AAB", "kms1.a.1.t.", "kms1.a_b.1.t.AAAA"} {
		_, err := ParseCiphertext(value)
		expectError(t, err, "INVALID_CIPHERTEXT", "The ciphertext is not valid")
	}
	if kid, _ := ParseKid("key-1.3"); kid == nil || kid.Get("keyId") != "key-1" || kid.Get("version") != 3.0 {
		t.Fatalf("kid = %s", stringify(kid))
	}
	if kid, _ := ParseKid("key-1.0"); kid != nil {
		t.Fatalf("kid = %s", stringify(kid))
	}
	operations, err := GrantOperations(items("decrypt", "encrypt", "decrypt"), "encrypt")
	if err != nil || stringify(operations) != `["decrypt","encrypt"]` {
		t.Fatalf("operations = %v %v", operations, err)
	}
	_, err = GrantOperations(items(), "mac")
	expectError(t, err, "INVALID_INPUT", "operations must list 1-8 grant operations")
	_, err = GrantConstraints(core.NewObject("other", 1.0), []string{"decrypt"})
	expectError(t, err, "INVALID_INPUT", "Unknown grant constraint other")
	_, err = GrantConstraints(core.NewObject(), []string{"decrypt"})
	expectError(t, err, "INVALID_INPUT", "constraints must name an encryption context")
	if !kmsContextSatisfies(core.NewObject("encryptionContextEquals", core.NewObject("a", "1")), core.NewObject("a", "1")) ||
		kmsContextSatisfies(core.NewObject("encryptionContextEquals", core.NewObject("a", "1")), core.NewObject("a", "1", "b", "2")) ||
		!kmsContextSatisfies(core.NewObject("encryptionContextSubset", core.NewObject("a", "1")), core.NewObject("a", "1", "b", "2")) ||
		kmsContextSatisfies(core.NewObject("encryptionContextSubset", core.NewObject("a", "1")), nil) {
		t.Fatal("context constraints")
	}
	algorithms, _ := KeyAlgorithms(core.NewObject("keySpec", "rsa-3072", "keyUsage", "sign"))
	if stringify(algorithms) != `["PS256","PS384","PS512","RS256","RS384","RS512"]` {
		t.Fatalf("algorithms = %v", algorithms)
	}
	if mac, _ := KeyAlgorithms(core.NewObject("keySpec", "hmac-sha512", "keyUsage", "mac")); stringify(mac) != `["HS512"]` {
		t.Fatalf("mac = %v", mac)
	}
	if fingerprint, _ := Fingerprint("pem"); len(fingerprint) != 16 {
		t.Fatalf("fingerprint = %s", fingerprint)
	}
	attributes, _ := KeyAttributes(core.NewObject("id", "k", "keySpec", "aes-256-gcm", "keyUsage", "encrypt", "state", "enabled",
		"tags", core.NewObject("team", "a"), "createdBy", "u"), []string{"alias/b", "alias/a"},
		core.NewObject("context", core.NewObject("z", "1", "a", "2"), "algorithm", "ES256"))
	if stringify(attributes) != `{"keyId":"k","keySpec":"aes-256-gcm","keyUsage":"encrypt","keyState":"enabled","aliases":["alias/a","alias/b"],"createdBy":"u","tags.team":"a","encryptionContextKeys":["a","z"],"encryptionContext.a":"2","encryptionContext.z":"1","algorithm":"ES256"}` {
		t.Fatalf("attributes = %s", stringify(attributes))
	}
}
