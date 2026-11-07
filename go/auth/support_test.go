package auth

// Test support shared by the ported TypeScript tests: an in-memory SQLite store with the tenant tree of
// tests/auth.test.ts, a controllable clock, a delivery inbox, and a virtual WebAuthn authenticator
// (tests/support/webauthn.ts).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	testSecret   = "test-secret-32-characters-minimum-better-iam"
	testPassword = "test-password-long-enough"
)

type fixture struct {
	t      *testing.T
	ctx    context.Context
	store  core.IamStore
	auth   *Service
	clock  atomic.Int64
	mu     sync.Mutex
	inbox  []DeliveryMessage
	failOn func(DeliveryMessage) error
}

func (f *fixture) now() int64 { return f.clock.Load() }

func (f *fixture) advance(ms int64) { f.clock.Add(ms) }

func (f *fixture) deliver(_ context.Context, message DeliveryMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn != nil {
		if err := f.failOn(message); err != nil {
			return err
		}
	}
	f.inbox = append(f.inbox, message)
	return nil
}

func (f *fixture) messages() []DeliveryMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]DeliveryMessage(nil), f.inbox...)
}

func (f *fixture) lastMessage(template string) DeliveryMessage {
	f.t.Helper()
	messages := f.messages()
	for index := len(messages) - 1; index >= 0; index-- {
		if messages[index].Template == template {
			return messages[index]
		}
	}
	f.t.Fatalf("no %s message in %d delivered", template, len(messages))
	return DeliveryMessage{}
}

func newStore(t *testing.T) core.IamStore {
	t.Helper()
	store, err := sqlite.New(sqlite.Options{Filename: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store
}

// newFixture mirrors the beforeEach of tests/auth.test.ts; configure adjusts the options.
func newFixture(t *testing.T, configure ...func(*Options)) *fixture {
	t.Helper()
	f := &fixture{t: t, ctx: context.Background(), store: newStore(t)}
	f.clock.Store(time.Now().UnixMilli())
	options := Options{
		Store:             f.store,
		Secret:            testSecret,
		BaseURL:           "https://iam.example.com",
		SignUpEnabled:     true,
		SendEmail:         f.deliver,
		SendSms:           f.deliver,
		PasswordlessEmail: true,
		PasswordlessSms:   true,
		Passkeys:          &PasskeyOptions{RPID: "iam.example.com"},
		Now:               f.now,
	}
	for _, apply := range configure {
		apply(&options)
	}
	service, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.auth = service
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		for _, tenant := range [][3]any{{"root", nil, "root"}, {"org", "root", "organization"}, {"sibling", "root", "organization"}, {"project", "org", "project"}} {
			if _, err := tx.Insert(ctx, "tenants", core.NewObject("id", tenant[0], "tenantId", tenant[0], "name", tenant[0], "parentId", tenant[1],
				"type", tenant[2], "status", "active", "createdAt", float64(f.now()))); err != nil {
				return err
			}
		}
		return nil
	})
	t.Cleanup(func() {
		service.SettleBookkeeping()
		_ = f.store.Close(context.Background())
	})
	return f
}

func (f *fixture) tx(fn core.TxFunc) {
	f.t.Helper()
	if err := f.store.Transaction(f.ctx, fn); err != nil {
		f.t.Fatal(err)
	}
}

// identity creates a verified person with testPassword (tests/auth.test.ts identity()).
func (f *fixture) identity(tenantID string, rootAdmin bool, email string) *core.Object {
	f.t.Helper()
	if email == "" {
		email = "same@example.com"
	}
	var created *core.Object
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		created, err = f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{
			TenantID: tenantID, Email: email, Name: "Test User", Password: testPassword, HasPassword: true,
			EmailVerified: true, RootAdmin: rootAdmin,
		})
		return err
	})
	return created
}

func (f *fixture) get(collection, id string) *core.Object {
	f.t.Helper()
	record, err := f.store.Get(f.ctx, collection, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return record
}

func (f *fixture) find(collection string, filter *core.Object) []*core.Object {
	f.t.Helper()
	rows, err := f.store.Find(f.ctx, collection, filter, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return rows
}

func (f *fixture) update(collection, id string, change func(record *core.Object)) {
	f.t.Helper()
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		record, err := tx.Get(ctx, collection, id)
		if err != nil {
			return err
		}
		change(record)
		_, err = tx.Put(ctx, collection, record)
		return err
	})
}

func (f *fixture) dispatch() DispatchResult {
	f.t.Helper()
	result, err := f.auth.DispatchOutbox(f.ctx, 100)
	if err != nil {
		f.t.Fatal(err)
	}
	return result
}

func (f *fixture) totp(secret string) string {
	f.t.Helper()
	code, err := GenerateTotp(secret, f.now())
	if err != nil {
		f.t.Fatal(err)
	}
	return code
}

func (f *fixture) signIn(tenantID, email, password string) *core.Object {
	f.t.Helper()
	result, err := f.auth.SignIn(f.ctx, core.NewObject("tenantId", tenantID, "email", email, "password", password))
	if err != nil {
		f.t.Fatalf("signIn: %v", err)
	}
	return result
}

// session requires a session result (not an MFA challenge) and returns its token.
func session(t *testing.T, result *core.Object) string {
	t.Helper()
	if result == nil || result.Has("mfaRequired") {
		t.Fatalf("expected a session, got %s", core.MustStringify(result))
	}
	return str(result, "token")
}

func challengeOf(t *testing.T, result *core.Object) string {
	t.Helper()
	if result == nil || !isTrue(result, "mfaRequired") {
		t.Fatalf("expected an MFA challenge, got %s", core.MustStringify(result))
	}
	return str(result, "challenge")
}

func token(value string) core.CredentialInput { return core.CredentialInput{Token: value} }

// expectCode fails unless err is an IamError with the code.
func expectCode(t *testing.T, err error, code string) *core.IamError {
	t.Helper()
	var iam *core.IamError
	if !errors.As(err, &iam) || iam.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
	return iam
}

func must[T any](t *testing.T) func(T, error) T {
	return func(value T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
}

// parallel runs fn n times concurrently and returns how many succeeded (Promise.allSettled).
func parallel(n int, fn func() error) int {
	var wg sync.WaitGroup
	var ok atomic.Int32
	for index := 0; index < n; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if fn() == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	return int(ok.Load())
}

// --- virtual authenticator ------------------------------------------------------------------------------------------

// virtualAuthenticator is tests/support/webauthn.ts: a platform authenticator for one relying party producing real
// P-256 registration and assertion responses (user-verified, resident).
type virtualAuthenticator struct {
	credentialID []byte
	key          *ecdsa.PrivateKey
	rpHash       [32]byte
	origin       string
	counter      uint32
}

func newVirtualAuthenticator(rpID, origin string) *virtualAuthenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &virtualAuthenticator{credentialID: id, key: key, rpHash: sha256.Sum256([]byte(rpID)), origin: origin}
}

func (v *virtualAuthenticator) id() string { return base64url(v.credentialID) }

func mustCBOR(value any) []byte {
	encoded, err := cborEncode(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func (v *virtualAuthenticator) register(challenge string) *core.Object {
	cose := newCBORMap()
	cose.set(1.0, 2.0)
	cose.set(3.0, -7.0)
	cose.set(-1.0, 1.0)
	cose.set(-2.0, v.key.X.FillBytes(make([]byte, 32)))
	cose.set(-3.0, v.key.Y.FillBytes(make([]byte, 32)))
	authData := concatBytes(v.rpHash[:], []byte{0x45}, make([]byte, 4), make([]byte, 16), []byte{0, byte(len(v.credentialID))}, v.credentialID, mustCBOR(cose))
	clientData := core.MustStringify(core.NewObject("type", "webauthn.create", "challenge", challenge, "origin", v.origin))
	attestation := newCBORMap()
	attestation.set("fmt", "none")
	attestation.set("attStmt", newCBORMap())
	attestation.set("authData", authData)
	return core.NewObject(
		"id", v.id(), "rawId", v.id(), "type", "public-key", "clientExtensionResults", core.NewObject(),
		"response", core.NewObject(
			"clientDataJSON", base64url([]byte(clientData)),
			"attestationObject", base64url(mustCBOR(attestation)),
			"transports", []any{"internal"},
		),
	)
}

func (v *virtualAuthenticator) assert(challenge, userID string, origin ...string) *core.Object {
	v.counter++
	from := v.origin
	if len(origin) > 0 {
		from = origin[0]
	}
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, v.counter)
	authData := concatBytes(v.rpHash[:], []byte{0x05}, counter)
	clientData := []byte(core.MustStringify(core.NewObject("type", "webauthn.get", "challenge", challenge, "origin", from)))
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(concatBytes(authData, clientHash[:]))
	signature, err := ecdsa.SignASN1(rand.Reader, v.key, digest[:])
	if err != nil {
		panic(err)
	}
	return core.NewObject(
		"id", v.id(), "rawId", v.id(), "type", "public-key", "clientExtensionResults", core.NewObject(),
		"response", core.NewObject(
			"clientDataJSON", base64url(clientData),
			"authenticatorData", base64url(authData),
			"signature", base64url(signature),
			"userHandle", base64url([]byte(userID)),
		),
	)
}

func asError[T error](err error, target *T) bool { return errors.As(err, target) }

func atomicAdd(p *int32) int32 { return atomic.AddInt32(p, 1) }
