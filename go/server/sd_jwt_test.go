package server

// Port of tests/sd-jwt.test.ts: SD-JWT VC issuance, presentation with key binding and verification, the Token
// Status List encoding, and OpenID4VCI holder proofs.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// publicJwkOf is exportJWK(publicKey) reduced to { kty, crv, x, y }.
func publicJwkOf(key *ecdsa.PrivateKey) *core.Object {
	return core.NewObject("kty", "EC", "crv", "P-256",
		"x", base64url(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y", base64url(key.PublicKey.Y.FillBytes(make([]byte, 32))))
}

// expectSdReason requires an *SdJwtError with the reason.
func expectSdReason(t *testing.T, label string, err error, reason string) {
	t.Helper()
	var failed *SdJwtError
	if !errors.As(err, &failed) {
		t.Fatalf("%s: expected SdJwtError %s, got %v", label, reason, err)
	}
	if failed.Reason != reason {
		t.Fatalf("%s: expected reason %s, got %s (%s)", label, reason, failed.Reason, failed.Message)
	}
}

func wallSeconds() float64 { return math.Floor(sdDateNow() / 1000) }

type sdFixture struct {
	issuer *ecdsa.PrivateKey
	holder *ecdsa.PrivateKey
}

func (f *sdFixture) issuerKey(_ context.Context, kid, issuer string) (any, error) {
	if kid == "k1" && issuer == "https://issuer.example" {
		return &f.issuer.PublicKey, nil
	}
	return nil, nil
}

func (f *sdFixture) credential(t *testing.T) *IssuedSdJwt {
	t.Helper()
	issued, err := IssueSdJwt(context.Background(), SdJwtIssueInput{
		Alg: "ES256", Kid: "k1", Key: f.issuer,
		Plain: core.NewObject(
			"iss", "https://issuer.example",
			"vct", "https://issuer.example/types/employee",
			"iat", wallSeconds(),
			"exp", wallSeconds()+3600,
			"cnf", core.NewObject("jwk", publicJwkOf(f.holder)),
			"status", core.NewObject("status_list", core.NewObject("idx", 7, "uri", "https://issuer.example/status/1")),
		),
		Disclosable: core.NewObject("email", "alice@acme.test", "department", "Engineering", "teams", []any{"Platform", "SRE"}),
		Decoys:      2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func disclosureNames(t *testing.T, disclosures []string) []string {
	t.Helper()
	names := []string{}
	for _, item := range disclosures {
		name, _, err := ReadDisclosure(item)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func verifyOptions(f *sdFixture, members ...any) *SdJwtVerifyOptions {
	options := &SdJwtVerifyOptions{IssuerKey: f.issuerKey}
	for index := 0; index+1 < len(members); index += 2 {
		switch members[index] {
		case "audience":
			options.Audience, options.HasAudience = members[index+1], true
		case "nonce":
			options.Nonce, options.HasNonce = members[index+1], true
		case "requireKeyBinding":
			options.RequireKeyBinding = members[index+1]
		}
	}
	return options
}

func TestSdJwtIssuesPresentsAndVerifies(t *testing.T) {
	ctx := context.Background()
	f := &sdFixture{issuer: newP256(t), holder: newP256(t)}
	issued := f.credential(t)
	split := must(SplitSdJwt(issued.SdJwt))
	if names := disclosureNames(t, split.Disclosures); !reflect.DeepEqual(names, []string{"department", "email", "teams"}) {
		t.Fatalf("disclosures: %v", names)
	}
	// The signed payload holds digests (3 claims + 2 decoys), never the values.
	_, payload, err := sdDecodeJwt(issued.Jwt)
	if err != nil {
		t.Fatal(err)
	}
	if digests, _ := payload.Get("_sd").([]any); len(digests) != 5 {
		t.Fatalf("_sd: %v", payload.Get("_sd"))
	}
	if strings.Contains(core.MustStringify(payload), "alice@acme.test") {
		t.Fatal("the payload holds a disclosed value")
	}

	presentation := must(PresentSdJwt(issued.SdJwt, SdJwtPresentOptions{
		Disclose: []string{"email"}, HolderKey: f.holder, Alg: "ES256", Audience: "https://verifier.example", Nonce: "n-123",
	}))
	verified, err := VerifySdJwt(ctx, presentation, verifyOptions(f, "audience", "https://verifier.example", "nonce", "n-123"))
	if err != nil {
		t.Fatal(err)
	}
	if verified.Get("issuer") != "https://issuer.example" || verified.Get("vct") != "https://issuer.example/types/employee" ||
		core.MustStringify(verified.Get("disclosed")) != `["email"]` || verified.Get("keyBound") != true ||
		core.MustStringify(verified.Get("status")) != `{"index":7,"uri":"https://issuer.example/status/1"}` {
		t.Fatalf("verified: %s", core.MustStringify(verified))
	}
	claims := verified.Get("claims").(*core.Object)
	if claims.Get("email") != "alice@acme.test" || claims.Has("department") || claims.Has("_sd") {
		t.Fatalf("claims: %s", core.MustStringify(claims))
	}

	// Wrong audience or nonce, a replayed KB over another selection, a forged disclosure, no key binding.
	_, err = VerifySdJwt(ctx, presentation, verifyOptions(f, "audience", "https://other.example", "nonce", "n-123"))
	expectSdReason(t, "audience", err, "wrong-audience")
	_, err = VerifySdJwt(ctx, presentation, verifyOptions(f, "audience", "https://verifier.example", "nonce", "x"))
	expectSdReason(t, "nonce", err, "wrong-nonce")
	parts := strings.Split(presentation, "~")
	jwt, email, kb := parts[0], parts[1], parts[len(parts)-1]
	department := ""
	for _, item := range split.Disclosures {
		if name, _, _ := ReadDisclosure(item); name == "department" {
			department = item
		}
	}
	_, err = VerifySdJwt(ctx, jwt+"~"+email+"~"+department+"~"+kb, verifyOptions(f))
	expectSdReason(t, "widened", err, "bad-key-binding")
	forged := base64url([]byte(core.MustStringify([]any{"salt", "email", "mallory@evil.test"})))
	_, err = VerifySdJwt(ctx, jwt+"~"+forged+"~", verifyOptions(f, "requireKeyBinding", false))
	expectSdReason(t, "forged", err, "bad-disclosure")
	_, err = VerifySdJwt(ctx, issued.SdJwt, verifyOptions(f))
	expectSdReason(t, "no key binding", err, "key-binding-required")
	// A disclosure may not overwrite a signed claim.
	iss := base64url([]byte(core.MustStringify([]any{"salt", "iss", "https://evil.test"})))
	_, err = VerifySdJwt(ctx, jwt+"~"+iss+"~", verifyOptions(f, "requireKeyBinding", false))
	expectSdReason(t, "iss", err, "bad-disclosure")
	// Unknown issuers and expired credentials.
	unknown := &SdJwtVerifyOptions{IssuerKey: func(context.Context, string, string) (any, error) { return nil, nil }, Audience: "https://verifier.example", HasAudience: true}
	_, err = VerifySdJwt(ctx, presentation, unknown)
	expectSdReason(t, "unknown issuer", err, "unknown-issuer")
	later := sdDateNow() + 7200_000
	maxAge := 10_000.0
	expired := verifyOptions(f)
	expired.Now, expired.MaxKeyBindingAgeSeconds = &later, &maxAge
	_, err = VerifySdJwt(ctx, presentation, expired)
	expectSdReason(t, "expired", err, "expired")
	// The key-binding claims come back for the verifier's own replay bookkeeping.
	binding := verified.Get("keyBinding").(*core.Object)
	if binding.Get("audience") != "https://verifier.example" || binding.Get("nonce") != "n-123" {
		t.Fatalf("keyBinding: %s", core.MustStringify(binding))
	}
}

func TestSdJwtRefusesPrototypeAndStructuralClaimNames(t *testing.T) {
	ctx := context.Background()
	f := &sdFixture{issuer: newP256(t), holder: newP256(t)}
	for _, name := range []string{"__proto__", "constructor", "_sd", "...", "cnf"} {
		_, err := IssueSdJwt(ctx, SdJwtIssueInput{
			Alg: "ES256", Kid: "k1", Key: f.issuer,
			Plain:       core.NewObject("iss", "https://issuer.example", "vct", "x"),
			Disclosable: core.NewObject(name, "value"),
		})
		if err == nil {
			t.Fatalf("%s was issued as a disclosure", name)
		}
	}
	sign := func(payload *core.Object) string {
		token, err := sdJwtSign(core.NewObject("alg", "ES256", "kid", "k1", "typ", "dc+sd-jwt"), payload, f.issuer, "ES256")
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	digest := func(text string) string {
		sum := sha256.Sum256([]byte(text))
		return base64url(sum[:])
	}
	// A disclosure named like the prototype never verifies, even if its digest were signed.
	salt := "c2FsdA"
	disclosure := base64url([]byte(core.MustStringify([]any{salt, "__proto__", core.NewObject("admin", true)})))
	jwt := sign(core.NewObject("iss", "https://issuer.example", "vct", "x", "_sd_alg", "sha-256", "_sd", []any{digest(disclosure)}))
	_, err := VerifySdJwt(ctx, jwt+"~"+disclosure+"~", verifyOptions(f, "requireKeyBinding", false))
	expectSdReason(t, "__proto__", err, "bad-disclosure")
	// Nor does a digest listed twice.
	email := base64url([]byte(core.MustStringify([]any{salt, "email", "a@b.test"})))
	twice := digest(email)
	doubled := sign(core.NewObject("iss", "https://issuer.example", "vct", "x", "_sd_alg", "sha-256", "_sd", []any{twice, twice}))
	_, err = VerifySdJwt(ctx, doubled+"~"+email+"~", verifyOptions(f, "requireKeyBinding", false))
	expectSdReason(t, "doubled", err, "bad-disclosure")
}

func TestSdJwtStatusListsAndHolderProofs(t *testing.T) {
	ctx := context.Background()
	f := &sdFixture{issuer: newP256(t), holder: newP256(t)}
	bytes := make([]byte, 16)
	if err := SetStatusAt(bytes, 0, 2, StatusInvalid); err != nil {
		t.Fatal(err)
	}
	if err := SetStatusAt(bytes, 5, 2, StatusSuspended); err != nil {
		t.Fatal(err)
	}
	if bytes[0] != 0b01 || bytes[1] != 0b1000 {
		t.Fatalf("bytes: %08b %08b", bytes[0], bytes[1])
	}
	token := must(SignStatusList(ctx, StatusListInput{
		URI: "https://issuer.example/status/1", Bytes: bytes, Bits: 2, Alg: "ES256", Kid: "k1", Key: f.issuer,
		IssuedAt: sdDateNow(), ExpiresAt: sdDateNow() + 3600_000, TTLSeconds: 300,
	}))
	bits, raw, err := ReadStatusList(ctx, token, &f.issuer.PublicKey, "https://issuer.example/status/1", nil)
	if err != nil || bits != 2 {
		t.Fatalf("read: %d %v", bits, err)
	}
	statuses := []float64{}
	for _, index := range []float64{0, 5, 6} {
		statuses = append(statuses, must(StatusAt(raw, index, 2)))
	}
	if !reflect.DeepEqual(statuses, []float64{StatusInvalid, StatusSuspended, StatusValid}) {
		t.Fatalf("statuses: %v", statuses)
	}
	_, _, err = ReadStatusList(ctx, token, &f.issuer.PublicKey, "https://issuer.example/status/2", nil)
	expectSdReason(t, "other list", err, "status-unavailable")

	proof, err := sdJwtSign(core.NewObject("alg", "ES256", "typ", "openid4vci-proof+jwt", "jwk", publicJwkOf(f.holder)),
		core.NewObject("aud", "https://issuer.example", "nonce", "c-1", "iat", wallSeconds()), f.holder, "ES256")
	if err != nil {
		t.Fatal(err)
	}
	checked, err := VerifyHolderProof(ctx, proof, HolderProofOptions{Audience: "https://issuer.example"})
	if err != nil {
		t.Fatal(err)
	}
	if checked.Nonce == nil || *checked.Nonce != "c-1" || core.MustStringify(checked.Jwk) != core.MustStringify(publicJwkOf(f.holder)) {
		t.Fatalf("checked: %+v", checked)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(checked.Thumbprint) {
		t.Fatalf("thumbprint: %s", checked.Thumbprint)
	}
	_, err = VerifyHolderProof(ctx, proof, HolderProofOptions{Audience: "https://other.example"})
	expectSdReason(t, "other audience", err, "bad-key-binding")
}
