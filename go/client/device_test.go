package client

// Device prover behavior (packages/client/src/device.ts): proof format, caching, ids, errors, reset and key stores.

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func decodeSegment(t *testing.T, segment string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("segment %q: %v", segment, err)
	}
	return string(raw)
}

func TestDeviceProofsAreES256CompactJWSBoundToTheSession(t *testing.T) {
	now := float64(1_767_225_600_123)
	prover, err := NewDeviceProver(DeviceProverOptions{Now: func() float64 { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	jwk, err := prover.PublicJwk(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || len(jwk.X) != 43 || len(jwk.Y) != 43 {
		t.Fatalf("jwk %+v", jwk)
	}
	kid, _ := prover.KeyID(ctx)
	digest := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + jwk.X + `","y":"` + jwk.Y + `"}`))
	if kid != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatalf("kid %s is not the RFC 7638 thumbprint", kid)
	}
	proof, err := prover.Proof(ctx, "ses_<1>&", "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof %s", proof)
	}
	if header := decodeSegment(t, parts[0]); header != `{"alg":"ES256","typ":"device-proof+jwt","kid":"`+kid+`"}` {
		t.Fatalf("header %s", header)
	}
	if claims := decodeSegment(t, parts[1]); claims != `{"iat":1767225600,"sid":"ses_<1>&","tid":"tenant-1"}` {
		t.Fatalf("claims %s", claims)
	}
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if len(signature) != 64 {
		t.Fatalf("signature length %d", len(signature))
	}
	x, _ := base64.RawURLEncoding.DecodeString(jwk.X)
	y, _ := base64.RawURLEncoding.DecodeString(jwk.Y)
	public := &ecdsa.PublicKey{Curve: prover.active.key.key.Curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	signed := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(public, signed[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("the signature does not verify with the published key")
	}
	without, _ := prover.Proof(ctx, "ses_1")
	if claims := decodeSegment(t, strings.Split(without, ".")[1]); claims != `{"iat":1767225600,"sid":"ses_1"}` {
		t.Fatalf("claims without a tenant %s", claims)
	}
}

func TestDeviceProofsAreReusedForFourMinutesPerSessionAndTenant(t *testing.T) {
	now := float64(1_000_000_000)
	prover, _ := NewDeviceProver(DeviceProverOptions{Now: func() float64 { return now }})
	ctx := context.Background()
	first, _ := prover.Proof(ctx, "ses_1")
	now += 239_999
	if again, _ := prover.Proof(ctx, "ses_1"); again != first {
		t.Fatal("a fresh proof was not reused")
	}
	if other, _ := prover.Proof(ctx, "ses_1", "tenant"); other == first {
		t.Fatal("a proof for another tenant was reused")
	}
	now++
	if renewed, _ := prover.Proof(ctx, "ses_1"); renewed == first {
		t.Fatal("a proof older than four minutes was reused")
	}
	// A clock that moved backwards never reuses a proof from the future.
	now -= 10_000
	future, _ := prover.Proof(ctx, "ses_1")
	now -= 1
	if back, _ := prover.Proof(ctx, "ses_1"); back == future {
		t.Fatal("a proof issued later than now was reused")
	}
	// At most 16 proofs are cached; the oldest is dropped first.
	for index := range 20 {
		if _, err := prover.Proof(ctx, "ses_"+strings.Repeat("x", index+1)); err != nil {
			t.Fatal(err)
		}
	}
	if len(prover.proofs) != maxCachedProofs || len(prover.proofOrder) != maxCachedProofs {
		t.Fatalf("cached %d (%d ordered)", len(prover.proofs), len(prover.proofOrder))
	}
	if _, ok := prover.proofs["ses_x"]; ok {
		t.Fatal("the oldest proof was kept")
	}
	if _, ok := prover.proofs[prover.proofOrder[len(prover.proofOrder)-1]]; !ok {
		t.Fatal("the cache order lost the newest proof")
	}
}

func TestDeviceProverRefusesInvalidIdsOptionsAndClocks(t *testing.T) {
	if _, err := NewDeviceProver(DeviceProverOptions{Algorithm: "RS256"}); err == nil || err.(*IamClientError).Message != "Device proofs support only the ES256 algorithm" {
		t.Fatalf("algorithm: %v", err)
	}
	for _, scope := range []string{"has a space", strings.Repeat("s", 65), "é"} {
		if _, err := NewDeviceProver(DeviceProverOptions{Scope: scope}); err == nil || !strings.Contains(err.Error(), "scope") {
			t.Fatalf("scope %q: %v", scope, err)
		}
	}
	if _, err := NewDeviceProver(DeviceProverOptions{Scope: "identity-1", Algorithm: "ES256"}); err != nil {
		t.Fatal(err)
	}
	prover, _ := NewDeviceProver(DeviceProverOptions{})
	ctx := context.Background()
	for _, tc := range []struct{ session, tenant, message string }{
		{"", "", "sessionId must be 1 to 256 printable characters without spaces"},
		{"has space", "", "sessionId must be 1 to 256 printable characters without spaces"},
		{strings.Repeat("s", 257), "", "sessionId must be 1 to 256 printable characters without spaces"},
		{"ses_1", "bad tenant", "tenantId must be 1 to 256 printable characters without spaces"},
	} {
		var err error
		if tc.tenant == "" {
			_, err = prover.Proof(ctx, tc.session)
		} else {
			_, err = prover.Proof(ctx, tc.session, tc.tenant)
		}
		if failure := clientError(t, err, "INVALID_INPUT", 0); failure.Message != tc.message {
			t.Fatalf("%q: %s", tc.session, failure.Message)
		}
	}
	_, err := prover.Proof(ctx, "ses_1", "")
	clientError(t, err, "INVALID_INPUT", 0)
	broken, _ := NewDeviceProver(DeviceProverOptions{Now: func() float64 { return math.NaN() }})
	_, err = broken.Proof(ctx, "ses_1")
	clientError(t, err, "INVALID_CONFIG", 0)
}

type failingStore struct{ err error }

func (f failingStore) Load(context.Context) (*ecdsa.PrivateKey, error) { return nil, f.err }
func (f failingStore) Save(context.Context, *ecdsa.PrivateKey) error   { return f.err }
func (f failingStore) Clear(context.Context) error                     { return f.err }

func TestDeviceHeadersNeverFailTheRequest(t *testing.T) {
	ctx := context.Background()
	prover, _ := NewDeviceProver(DeviceProverOptions{})
	if headers := prover.Headers(ctx, ""); len(headers) != 0 {
		t.Fatalf("headers without a session %v", headers)
	}
	if headers := prover.Headers(ctx, "ses_1"); !strings.Contains(headers.Get(DeviceProofHeader), ".") {
		t.Fatalf("headers %v", headers)
	}
	storeFailure := errors.New("disk on fire")
	var reported []error
	failing, _ := NewDeviceProver(DeviceProverOptions{Store: failingStore{storeFailure}, OnError: func(err error) {
		reported = append(reported, err)
		panic("hook failure")
	}})
	if headers := failing.Headers(ctx, "ses_1"); len(headers) != 0 {
		t.Fatalf("headers from a failing store %v", headers)
	}
	if headers := failing.Headers(ctx, "bad id"); len(headers) != 0 {
		t.Fatalf("headers for an invalid id %v", headers)
	}
	if len(reported) != 2 || !errors.Is(reported[0], storeFailure) {
		t.Fatalf("reported %v", reported)
	}
	// A failure is not remembered: the key is retried on the next call.
	if failing.active != nil {
		t.Fatal("a failed key was remembered")
	}
}

func TestDeviceProverResetAndKeyStores(t *testing.T) {
	ctx := context.Background()
	store := MemoryKeyStore()
	first, _ := NewDeviceProver(DeviceProverOptions{Store: store})
	kid, _ := first.KeyID(ctx)
	// A second prover on the same store uses the same key.
	second, _ := NewDeviceProver(DeviceProverOptions{Store: store})
	if again, _ := second.KeyID(ctx); again != kid {
		t.Fatal("the stored key was not reused")
	}
	proof, _ := first.Proof(ctx, "ses_1")
	if err := first.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if stored, _ := store.Load(ctx); stored != nil {
		t.Fatal("reset left the key in the store")
	}
	renewed, _ := first.KeyID(ctx)
	if renewed == kid {
		t.Fatal("reset kept the key")
	}
	if next, _ := first.Proof(ctx, "ses_1"); next == proof {
		t.Fatal("reset kept a cached proof")
	}

	path := filepath.Join(t.TempDir(), "keys", "device.pem")
	files, err := FileKeyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FileKeyStore(""); err == nil {
		t.Fatal("FileKeyStore needs a path")
	}
	persisted, _ := NewDeviceProver(DeviceProverOptions{Store: files, Scope: "identity-1"})
	persistedKid, err := persisted.KeyID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reopened, _ := FileKeyStore(path)
	restarted, _ := NewDeviceProver(DeviceProverOptions{Store: reopened, Scope: "identity-1"})
	if again, _ := restarted.KeyID(ctx); again != persistedKid {
		t.Fatal("the file store did not keep the key across provers")
	}
	if err := restarted.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if loaded, err := reopened.Load(ctx); loaded != nil || err != nil {
		t.Fatalf("after reset: %v %v", loaded, err)
	}
	if err := reopened.Clear(ctx); err != nil {
		t.Fatal("clearing a missing file must succeed")
	}
}

func TestDeviceProversOnOneStoreSettleOnOneKey(t *testing.T) {
	ctx := context.Background()
	store := MemoryKeyStore()
	var group sync.WaitGroup
	kids := make([]string, 8)
	for index := range kids {
		group.Add(1)
		go func() {
			defer group.Done()
			prover, _ := NewDeviceProver(DeviceProverOptions{Store: store, Scope: "shared"})
			kids[index], _ = prover.KeyID(ctx)
		}()
	}
	group.Wait()
	for _, kid := range kids {
		if kid != kids[0] || kid == "" {
			t.Fatalf("provers created several keys: %v", kids)
		}
	}
}
