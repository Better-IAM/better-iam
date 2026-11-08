package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

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

func mustParse(t *testing.T, text string) *core.Object {
	t.Helper()
	parsed, err := core.ParseJSONString(text)
	if err != nil {
		t.Fatalf("invalid JSON %q: %v", text, err)
	}
	o, ok := parsed.(*core.Object)
	if !ok {
		t.Fatalf("not an object: %s", text)
	}
	return o
}

func b64(i *big.Int) string { return base64.RawURLEncoding.EncodeToString(i.Bytes()) }

var (
	rsaOnce    sync.Once
	rsaPrivate *core.Object
	rsaPublic  *core.Object
)

// testRSAKey is an RS256 signing key (kid test-key) as a private and a public JWK.
func testRSAKey() (*core.Object, *core.Object) {
	rsaOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		key.Precompute()
		rsaPublic = core.NewObject("kty", "RSA", "n", b64(key.N), "e", b64(big.NewInt(int64(key.E))), "kid", "test-key", "alg", "RS256", "use", "sig")
		rsaPrivate = rsaPublic.Clone()
		rsaPrivate.Set("d", b64(key.D))
		rsaPrivate.Set("p", b64(key.Primes[0]))
		rsaPrivate.Set("q", b64(key.Primes[1]))
		rsaPrivate.Set("dp", b64(key.Precomputed.Dp))
		rsaPrivate.Set("dq", b64(key.Precomputed.Dq))
		rsaPrivate.Set("qi", b64(key.Precomputed.Qinv))
	})
	return rsaPrivate.Clone(), rsaPublic.Clone()
}

// testECKey is a fresh P-256 key as a private and a public JWK.
func testECKey(kid string) (*core.Object, *core.Object) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pad := func(i *big.Int) string {
		buffer := make([]byte, 32)
		i.FillBytes(buffer)
		return base64.RawURLEncoding.EncodeToString(buffer)
	}
	public := core.NewObject("kty", "EC", "crv", "P-256", "x", pad(key.X), "y", pad(key.Y))
	if kid != "" {
		public.Set("kid", kid)
	}
	private := public.Clone()
	private.Set("d", pad(key.D))
	return private, public
}

func signJWT(t *testing.T, privateJWK *core.Object, alg string, header, payload *core.Object) string {
	t.Helper()
	signer, err := joseImportPrivate(privateJWK)
	if err != nil {
		t.Fatal(err)
	}
	full := core.NewObject("alg", alg)
	full.Assign(header)
	token, err := joseSignCompact(full, payload, signer, alg)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func decodePayload(t *testing.T, token string) *core.Object {
	t.Helper()
	payload, err := joseDecodePayload(token)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func randomKey() string {
	buffer := make([]byte, 32)
	_, _ = rand.Read(buffer)
	return base64.StdEncoding.EncodeToString(buffer)
}

func insert(t *testing.T, store core.IamStore, collection string, record *core.Object) {
	t.Helper()
	err := store.Transaction(context.Background(), func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, collection, record)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func update(t *testing.T, store core.IamStore, collection, id string, change func(record *core.Object)) {
	t.Helper()
	err := store.Transaction(context.Background(), func(ctx context.Context, tx core.IamStore) error {
		record, err := tx.Get(ctx, collection, id)
		if err != nil {
			return err
		}
		change(record)
		_, err = tx.Put(ctx, collection, record)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func remove(t *testing.T, store core.IamStore, collection, id string) {
	t.Helper()
	if err := store.Transaction(context.Background(), func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, collection, id)
	}); err != nil {
		t.Fatal(err)
	}
}

// browser is a cookie-carrying client that never follows redirects (the tests' visit()).
type browser struct {
	t       *testing.T
	cookies map[string]string
	order   []string
	client  *http.Client
}

func newBrowser(t *testing.T) *browser {
	return &browser{t: t, cookies: map[string]string{}, client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

type httpResult struct {
	Status int
	Header http.Header
	Body   string
}

func (r *httpResult) JSON(t *testing.T) *core.Object {
	t.Helper()
	return mustParse(t, r.Body)
}

func (b *browser) visit(method, target string, header map[string]string, body string) *httpResult {
	b.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, target, reader)
	if err != nil {
		b.t.Fatal(err)
	}
	for key, value := range header {
		request.Header.Set(key, value)
	}
	if len(b.cookies) > 0 {
		parts := []string{}
		for _, name := range b.order {
			if value, ok := b.cookies[name]; ok {
				parts = append(parts, name+"="+value)
			}
		}
		request.Header.Set("cookie", strings.Join(parts, "; "))
	}
	response, err := b.client.Do(request)
	if err != nil {
		b.t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	for _, cookie := range response.Header.Values("Set-Cookie") {
		part := strings.SplitN(cookie, ";", 2)[0]
		index := strings.Index(part, "=")
		name := part[:index]
		if _, ok := b.cookies[name]; !ok {
			b.order = append(b.order, name)
		}
		b.cookies[name] = part[index+1:]
	}
	return &httpResult{Status: response.StatusCode, Header: response.Header, Body: string(raw)}
}

func fetch(t *testing.T, method, target string, header map[string]string, body string) *httpResult {
	t.Helper()
	return (&browser{t: t, cookies: map[string]string{}, client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}).visit(method, target, header, body)
}

func form(pairs ...string) string {
	values := [][2]string{}
	for index := 0; index+1 < len(pairs); index += 2 {
		values = append(values, [2]string{pairs[index], pairs[index+1]})
	}
	return formEncode(values)
}

const formType = "application/x-www-form-urlencoded"

func resolve(base, location string) string {
	parsed, err := url.Parse(base)
	if err != nil {
		return location
	}
	target, err := parsed.Parse(location)
	if err != nil {
		return location
	}
	return target.String()
}

func expectIamError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var iam *core.IamError
	if !errors.As(err, &iam) {
		t.Fatalf("expected IamError (%d %s), got %v", status, code, err)
	}
	if status != 0 && iam.Status != status {
		t.Fatalf("expected status %d, got %d (%s: %s)", status, iam.Status, iam.Code, iam.Message)
	}
	if code != "" && iam.Code != code {
		t.Fatalf("expected code %s, got %s (%s)", code, iam.Code, iam.Message)
	}
}

// staticPrincipal is an authenticate callback for one principal and one token.
func staticPrincipal(token string, principal func() *auth.Principal) func(ctx context.Context, credential core.CredentialInput) (*auth.Principal, error) {
	return func(_ context.Context, credential core.CredentialInput) (*auth.Principal, error) {
		if credential.Token != token {
			return nil, core.NewIamError("FORBIDDEN", "Forbidden", 403)
		}
		return principal(), nil
	}
}

// providerServer serves a provider with the tests' interaction routes.
type providerServer struct {
	*httptest.Server
	provider   *Provider
	credential func() core.CredentialInput
}

func newProviderServer(t *testing.T) *providerServer {
	ps := &providerServer{}
	ps.credential = func() core.CredentialInput { return core.CredentialInput{Token: "admin"} }
	ps.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/interactions/") {
			if r.Method == http.MethodPost {
				if err := ps.provider.CompleteInteraction(r.Context(), w, r, CompleteInteractionInput{Credential: ps.credential(), Consent: true}); err != nil {
					writeError(w, err)
				}
				return
			}
			details, err := ps.provider.InteractionDetails(r.Context(), r)
			if err != nil {
				writeError(w, err)
				return
			}
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(stringify(toObject(details))))
			return
		}
		ps.provider.Handler(w, r)
	}))
	t.Cleanup(ps.Close)
	return ps
}

func writeError(w http.ResponseWriter, err error) {
	status := 500
	var iam *core.IamError
	if errors.As(err, &iam) {
		status = iam.Status
	} else if e, ok := asOIDC(err); ok {
		status = e.Status
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(err.Error()))
}

// authorize runs an authorization request through consent to the callback and returns the code (and state).
func authorize(t *testing.T, b *browser, origin, authorizeURL string) *url.URL {
	t.Helper()
	result := b.visit("GET", authorizeURL, nil, "")
	redirect := result.Header.Get("location")
	if !strings.Contains(redirect, "/interactions/") {
		t.Fatalf("expected an interaction redirect, got %d %s %s", result.Status, redirect, result.Body)
	}
	b.visit("GET", resolve(origin, redirect), nil, "")
	result = b.visit("POST", resolve(origin, redirect), map[string]string{"origin": origin}, "")
	redirect = result.Header.Get("location")
	for i := 0; i < 5 && !strings.Contains(redirect, "/callback?"); i++ {
		result = b.visit("GET", resolve(origin, redirect), nil, "")
		redirect = result.Header.Get("location")
	}
	parsed, err := url.Parse(resolve(origin, redirect))
	if err != nil || parsed.Query().Get("code") == "" {
		t.Fatalf("no code in %q (%d %s)", redirect, result.Status, result.Body)
	}
	return parsed
}

func pkcePair() (string, string) {
	verifier := randomB64URL(32)
	return verifier, sha256B64URL(verifier)
}
