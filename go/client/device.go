package client

// Port of packages/client/src/device.ts: registered-device proofs, with crypto/ecdsa in place of WebCrypto.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/Better-IAM/better-iam/go/core"
)

// DeviceProofHeader is the request header that carries a device proof.
const DeviceProofHeader = "x-better-iam-device"

// DeviceKeyStore is where a device keeps its signing key between process restarts. Load returns nil when no key is
// stored.
type DeviceKeyStore interface {
	Load(ctx context.Context) (*ecdsa.PrivateKey, error)
	Save(ctx context.Context, key *ecdsa.PrivateKey) error
	Clear(ctx context.Context) error
}

// DevicePublicJwk is the public half of a device key, as devices.enroll takes it.
type DevicePublicJwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// DeviceProverOptions configure NewDeviceProver.
type DeviceProverOptions struct {
	// Store is where the key lives; MemoryKeyStore() when nil, where the key lasts only as long as the process (use
	// FileKeyStore to keep it across restarts).
	Store DeviceKeyStore
	// Scope keeps a separate key per scope, such as the signed-in identity's id: the server holds each key once across
	// the whole deployment, so a device used with several accounts needs one prover (and key) per account. 1 to 64
	// printable characters without spaces. Key creation is serialized per scope within the process.
	Scope string
	// Algorithm is the signature algorithm; only "ES256" (ECDSA P-256 with SHA-256), the default, is supported.
	Algorithm string
	// Now is the clock, in milliseconds, used for a proof's iat; the system clock when nil. The server accepts proofs
	// issued up to five minutes either side of its own clock; on devices whose clocks drift further, pass one corrected
	// with the server time auth.getSession returns as limits.now.
	Now func() float64
	// OnError is called when Headers could not produce a proof (a key store that failed, an invalid session id).
	// Headers then sends no proof, which the server treats as "no device". A hook that panics is ignored.
	OnError func(err error)
}

const (
	proofType = "device-proof+jwt"
	// proofReuseMs: the server accepts iat within 300 seconds of its clock; reuse leaves a minute of that window.
	proofReuseMs    = 240_000
	maxCachedProofs = 16
	creationLock    = "better-iam:registered-device-key"
)

var (
	// Session and tenant ids are printable ASCII without spaces, which also bounds the proof well below 2048 chars.
	idPattern    = regexp.MustCompile(`^[!-~]{1,256}$`)
	scopePattern = regexp.MustCompile(`^[!-~]{1,64}$`)
	// creationLocks serialize first-time key creation per lock name within the process (navigator.locks).
	creationLocks sync.Map
)

func base64url(bytes []byte) string { return base64.RawURLEncoding.EncodeToString(bytes) }

func usableKey(key *ecdsa.PrivateKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.D != nil && key.X != nil && key.Y != nil
}

func checkID(value, name string) error {
	if !idPattern.MatchString(value) {
		return newError("INVALID_INPUT", name+" must be 1 to 256 printable characters without spaces", 0)
	}
	return nil
}

// MemoryKeyStore keeps the key in memory only: for tests, scripts, and servers that re-enrol after a restart.
func MemoryKeyStore() DeviceKeyStore { return &memoryStore{} }

type memoryStore struct {
	mu      sync.Mutex
	current *ecdsa.PrivateKey
}

func (m *memoryStore) Load(context.Context) (*ecdsa.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current, nil
}

func (m *memoryStore) Save(_ context.Context, key *ecdsa.PrivateKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = key
	return nil
}

func (m *memoryStore) Clear(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = nil
	return nil
}

// FileKeyStore keeps the key in a file (PKCS #8 PEM, readable by its owner only), the persistent store outside
// browsers (where the TypeScript client uses IndexedDB). A missing file loads as no key.
func FileKeyStore(path string) (DeviceKeyStore, error) {
	if path == "" {
		return nil, newError("INVALID_CONFIG", "FileKeyStore needs a file path", 0)
	}
	return &fileStore{path: path}, nil
}

type fileStore struct {
	mu   sync.Mutex
	path string
}

func (f *fileStore) Load(context.Context) (*ecdsa.PrivateKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil
	}
	key, _ := parsed.(*ecdsa.PrivateKey)
	return key, nil
}

func (f *fileStore) Save(_ context.Context, key *ecdsa.PrivateKey) error {
	if key == nil {
		return newError("INVALID_INPUT", "Save takes an ECDSA private key", 0)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	temporary := f.path + ".tmp"
	if err := os.WriteFile(temporary, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, f.path)
}

func (f *fileStore) Clear(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.Remove(f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type activeKey struct {
	key *ecdsa.PrivateKey
	jwk DevicePublicJwk
	kid string
	// header is the encoded protected header, the same for every proof of this key.
	header string
}

type keyFuture struct {
	done chan struct{}
	key  *activeKey
	err  error
}

type cachedProof struct {
	issuedAt float64
	done     chan struct{}
	token    string
	err      error
}

// DeviceProver proves which registered device a request comes from. The device keeps an ECDSA P-256 key it creates
// on first use, enrols the public half once with devices.enroll, and then signs a short-lived proof bound to the
// session it presents. Proofs are compact JWS (ES256, typ device-proof+jwt, kid = the key's RFC 7638 thumbprint)
// over { iat, sid, tid? }, reused for up to four minutes per session id and tenant id. The server reads them from
// x-better-iam-device; a missing or invalid proof only means "no device". devices.enroll needs the request to carry
// a proof made with the key being enrolled, which Headers adds once the session id is known.
//
//	device, _ := client.NewDeviceProver(client.DeviceProverOptions{})
//	var sessionID string
//	c, _ := client.New(client.Options{BaseURL: base, HeadersFunc: func(ctx context.Context) (http.Header, error) {
//		return device.Headers(ctx, sessionID), nil
//	}})
type DeviceProver struct {
	store    DeviceKeyStore
	lockName string
	clock    func() float64
	onError  func(err error)

	mu     sync.Mutex
	active *keyFuture
	// lane runs key creation and reset one at a time, so a reset never races a key that is still being saved.
	lane       sync.Mutex
	proofs     map[string]*cachedProof
	proofOrder []string
}

// NewDeviceProver creates a prover (createDeviceProver). It fails with INVALID_CONFIG for an unsupported algorithm
// or an invalid scope.
func NewDeviceProver(options DeviceProverOptions) (*DeviceProver, error) {
	if options.Algorithm != "" && options.Algorithm != "ES256" {
		return nil, newError("INVALID_CONFIG", "Device proofs support only the ES256 algorithm", 0)
	}
	if options.Scope != "" && !scopePattern.MatchString(options.Scope) {
		return nil, newError("INVALID_CONFIG", "scope must be 1 to 64 printable characters without spaces", 0)
	}
	store := options.Store
	if store == nil {
		store = MemoryKeyStore()
	}
	lockName := creationLock
	if options.Scope != "" {
		lockName += ":" + options.Scope
	}
	clock := options.Now
	if clock == nil {
		clock = func() float64 { return float64(core.NowMillis()) }
	}
	return &DeviceProver{store: store, lockName: lockName, clock: clock, onError: options.OnError, proofs: map[string]*cachedProof{}}, nil
}

func loadOrCreate(ctx context.Context, store DeviceKeyStore) (*ecdsa.PrivateKey, error) {
	stored, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	if usableKey(stored) {
		return stored, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := store.Save(ctx, key); err != nil {
		return nil, err
	}
	return key, nil
}

func describe(key *ecdsa.PrivateKey) (*activeKey, error) {
	if key.Curve != elliptic.P256() {
		return nil, newError("INVALID_CONFIG", "The stored device key is not an EC P-256 key", 0)
	}
	x, y := make([]byte, 32), make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	jwk := DevicePublicJwk{Kty: "EC", Crv: "P-256", X: base64url(x), Y: base64url(y)}
	// RFC 7638: the required members only, in lexicographic order, without whitespace.
	canonical := core.MustStringify(core.NewObject("crv", jwk.Crv, "kty", jwk.Kty, "x", jwk.X, "y", jwk.Y))
	digest := sha256.Sum256([]byte(canonical))
	kid := base64url(digest[:])
	header := base64url([]byte(core.MustStringify(core.NewObject("alg", "ES256", "typ", proofType, "kid", kid))))
	return &activeKey{key: key, jwk: jwk, kid: kid, header: header}, nil
}

func (p *DeviceProver) currentKey(ctx context.Context) (*activeKey, error) {
	p.mu.Lock()
	future := p.active
	if future == nil {
		future = &keyFuture{done: make(chan struct{})}
		p.active = future
		p.mu.Unlock()
		go p.resolveKey(context.WithoutCancel(ctx), future)
	} else {
		p.mu.Unlock()
	}
	select {
	case <-future.done:
		return future.key, future.err
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func (p *DeviceProver) resolveKey(ctx context.Context, future *keyFuture) {
	defer close(future.done)
	defer func() {
		if recovered := recover(); recovered != nil {
			future.err = fmt.Errorf("device key: %v", recovered)
		}
		if future.err != nil {
			// A failure is not remembered: the next call tries again.
			p.mu.Lock()
			if p.active == future {
				p.active = nil
			}
			p.mu.Unlock()
		}
	}()
	p.lane.Lock()
	defer p.lane.Unlock()
	lock, _ := creationLocks.LoadOrStore(p.lockName, &sync.Mutex{})
	creation := lock.(*sync.Mutex)
	creation.Lock()
	key, err := loadOrCreate(ctx, p.store)
	creation.Unlock()
	if err != nil {
		future.err = err
		return
	}
	future.key, future.err = describe(key)
}

func (p *DeviceProver) sign(ctx context.Context, sessionID string, tenantID *string, issuedAt float64) (string, error) {
	key, err := p.currentKey(ctx)
	if err != nil {
		return "", err
	}
	claims := core.NewObject("iat", math.Floor(issuedAt/1000), "sid", sessionID)
	if tenantID != nil {
		claims.Set("tid", *tenantID)
	}
	signingInput := key.header + "." + base64url([]byte(core.MustStringify(claims)))
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key.key, digest[:])
	if err != nil {
		return "", err
	}
	// The JOSE form: r and s as two 32-byte big-endian integers.
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + base64url(signature), nil
}

// PublicJwk is the public key for devices.enroll (EC P-256).
func (p *DeviceProver) PublicJwk(ctx context.Context) (DevicePublicJwk, error) {
	key, err := p.currentKey(ctx)
	if err != nil {
		return DevicePublicJwk{}, err
	}
	return key.jwk, nil
}

// KeyID is the key's RFC 7638 thumbprint (the key id).
func (p *DeviceProver) KeyID(ctx context.Context) (string, error) {
	key, err := p.currentKey(ctx)
	if err != nil {
		return "", err
	}
	return key.kid, nil
}

// Proof is a fresh compact JWS for the session id and, optionally, the tenant id (cached about four minutes per
// pair).
func (p *DeviceProver) Proof(ctx context.Context, sessionID string, tenantID ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := checkID(sessionID, "sessionId"); err != nil {
		return "", err
	}
	var tenant *string
	if len(tenantID) > 0 {
		if err := checkID(tenantID[0], "tenantId"); err != nil {
			return "", err
		}
		tenant = &tenantID[0]
	}
	now := p.clock()
	if math.IsNaN(now) || math.IsInf(now, 0) {
		return "", newError("INVALID_CONFIG", "now() must return milliseconds", 0)
	}
	fresh := func(entry *cachedProof) bool { return entry.issuedAt <= now && now-entry.issuedAt < proofReuseMs }
	// Ids never contain spaces, so the pair maps to one cache key without ambiguity.
	cacheKey := sessionID
	if tenant != nil {
		cacheKey += " " + *tenant
	}
	p.mu.Lock()
	entry := p.proofs[cacheKey]
	if entry == nil || !fresh(entry) {
		kept := p.proofOrder[:0:0]
		for _, key := range p.proofOrder {
			if fresh(p.proofs[key]) {
				kept = append(kept, key)
			} else {
				delete(p.proofs, key)
			}
		}
		for len(kept) >= maxCachedProofs {
			delete(p.proofs, kept[0])
			kept = kept[1:]
		}
		entry = &cachedProof{issuedAt: now, done: make(chan struct{})}
		p.proofs[cacheKey] = entry
		p.proofOrder = append(kept, cacheKey)
		p.mu.Unlock()
		go func() {
			defer close(entry.done)
			entry.token, entry.err = p.sign(context.WithoutCancel(ctx), sessionID, tenant, now)
			if entry.err != nil {
				p.mu.Lock()
				if p.proofs[cacheKey] == entry {
					delete(p.proofs, cacheKey)
					p.removeOrder(cacheKey)
				}
				p.mu.Unlock()
			}
		}()
	} else {
		p.mu.Unlock()
	}
	select {
	case <-entry.done:
		return entry.token, entry.err
	case <-ctx.Done():
		return "", context.Cause(ctx)
	}
}

func (p *DeviceProver) removeOrder(cacheKey string) {
	for index, key := range p.proofOrder {
		if key == cacheKey {
			p.proofOrder = append(p.proofOrder[:index:index], p.proofOrder[index+1:]...)
			return
		}
	}
}

// Headers are the headers for Options.HeadersFunc: x-better-iam-device with a proof once a session id is known. It
// returns no headers while the session id is empty, and when no proof can be made (reported to OnError), so a device
// problem never fails the request itself.
func (p *DeviceProver) Headers(ctx context.Context, sessionID string, tenantID ...string) http.Header {
	headers := http.Header{}
	if sessionID == "" {
		return headers
	}
	proof, err := p.Proof(ctx, sessionID, tenantID...)
	if err != nil {
		if p.onError != nil {
			func() {
				// A hook that panics never fails the request that asked for headers.
				defer func() { _ = recover() }()
				p.onError(err)
			}()
		}
		return headers
	}
	headers.Set(DeviceProofHeader, proof)
	return headers
}

// Reset forgets the key (in memory and in the store) and every cached proof; the next proof uses a new key.
func (p *DeviceProver) Reset(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	p.active = nil
	p.proofs = map[string]*cachedProof{}
	p.proofOrder = nil
	p.mu.Unlock()
	p.lane.Lock()
	defer p.lane.Unlock()
	return p.store.Clear(ctx)
}
