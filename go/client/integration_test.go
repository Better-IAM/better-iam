package client_test

// The typed client against a real server through its HTTP handler: tests/retry-after.test.ts, the real-server case
// of tests/client-hooks.test.ts, the session store, and a device proof the server accepts for devices.enroll.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/client"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

const baseURL = "http://localhost:3000"

func handlerFetch(iam *server.BetterIam) func(request *http.Request) (*http.Response, error) {
	return func(request *http.Request) (*http.Response, error) {
		response := iam.Handle(request)
		return &http.Response{StatusCode: response.Status, Header: response.Header, Body: io.NopCloser(bytes.NewReader(response.Body))}, nil
	}
}

type world struct {
	t          *testing.T
	ctx        context.Context
	iam        *server.BetterIam
	rootTenant string
	mu         sync.Mutex
	inbox      []auth.DeliveryMessage
}

func newWorld(t *testing.T, mutate func(options *server.BetterIamOptions)) *world {
	t.Helper()
	store, err := sqlite.New(sqlite.Options{Filename: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	w := &world{t: t, ctx: context.Background()}
	options := &server.BetterIamOptions{
		Database: store, Secret: "client-test-secret-with-at-least-32-characters", BaseURL: baseURL,
		Authentication: &auth.Options{SendEmail: func(_ context.Context, message auth.DeliveryMessage) error {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.inbox = append(w.inbox, message)
			return nil
		}},
	}
	if mutate != nil {
		mutate(options)
	}
	iam, err := server.New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iam.Close)
	w.iam = iam
	if err := iam.Initialize(w.ctx); err != nil {
		t.Fatal(err)
	}
	root, err := iam.Bootstrap(w.ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password"))
	if err != nil {
		t.Fatal(err)
	}
	w.rootTenant = root.Get("tenant").(*core.Object).Get("id").(string)
	return w
}

func (w *world) client(options client.Options) *client.Client {
	w.t.Helper()
	options.BaseURL = baseURL
	if options.Fetch == nil {
		options.Fetch = handlerFetch(w.iam)
	}
	c, err := client.New(options)
	if err != nil {
		w.t.Fatal(err)
	}
	return c
}

// rootSession signs the root in and completes MFA enrollment through the client.
func (w *world) rootSession() string {
	w.t.Helper()
	public := w.client(client.Options{})
	challenge, err := public.Auth.SignIn(w.ctx, apitypes.AuthSignInInput{TenantID: w.rootTenant, Email: "root@example.test", Password: "a strong root test password"})
	if err != nil {
		w.t.Fatal(err)
	}
	if challenge.MfaRequired == nil {
		w.t.Fatal("root must require MFA")
	}
	restricted := &client.MfaChallenge{TenantID: w.rootTenant, Challenge: challenge.MfaRequired.Challenge}
	enrollment, err := public.Auth.BeginMfa(w.ctx, restricted)
	if err != nil {
		w.t.Fatal(err)
	}
	code, err := auth.GenerateTotp(enrollment.Secret, core.NowMillis())
	if err != nil {
		w.t.Fatal(err)
	}
	session, err := public.Auth.ConfirmMfa(w.ctx, client.ConfirmMfaInput{Credential: restricted, Code: code})
	if err != nil {
		w.t.Fatal(err)
	}
	if len(session.RecoveryCodes) == 0 {
		w.t.Fatal("MFA enrollment answered no recovery codes")
	}
	return session.Token
}

// organization creates an organization, redeems its owner invitation and answers its id and the owner's token.
func (w *world) organization(rootToken, name string) (string, string) {
	w.t.Helper()
	created, err := w.client(client.Options{Token: rootToken}).Tenants.Create(w.ctx, apitypes.TenantsCreateInput{
		ParentID: w.rootTenant, Name: name, Type: "organization", OwnerEmail: name + "@example.test",
	})
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.iam.Auth.DispatchOutbox(w.ctx, 0); err != nil {
		w.t.Fatal(err)
	}
	var token string
	w.mu.Lock()
	for _, message := range w.inbox {
		if message.TenantID == created.Tenant.ID && message.Template == "owner-invitation" {
			token = message.Payload["token"]
		}
	}
	w.mu.Unlock()
	owner, err := w.client(client.Options{}).Tenants.AcceptInvitation(w.ctx, apitypes.TenantsAcceptInvitationInput{
		TenantID: created.Tenant.ID, Token: token, Name: name + " owner", Password: "a strong tenant owner password",
	})
	if err != nil {
		w.t.Fatal(err)
	}
	if owner.Token == nil {
		w.t.Fatal("unexpected owner MFA")
	}
	return created.Tenant.ID, owner.Token.Token
}

func TestRateLimitResponsesTellCallersWhenToRetryOverHTTPAndThroughTheTypedClient(t *testing.T) {
	attempts, window := int64(2), int64(90_000)
	w := newWorld(t, func(options *server.BetterIamOptions) {
		options.Authentication.RateLimits = &auth.RateLimitOptions{Attempts: &attempts, WindowMs: &window}
	})
	attempt := func() error {
		_, err := w.iam.API.Auth.SignIn(w.ctx, server.Input[apitypes.AuthSignInInput](core.NewObject("tenantId", w.rootTenant, "email", "root@example.test", "password", "no")))
		return err
	}
	for range 2 {
		var refused *core.IamError
		if err := attempt(); !errors.As(err, &refused) || refused.Code != "INVALID_CREDENTIALS" {
			t.Fatalf("expected INVALID_CREDENTIALS, got %v", err)
		}
	}
	var limited *auth.RateLimitedError
	if err := attempt(); !errors.As(err, &limited) || limited.RetryAfterMs != 90_000 {
		t.Fatalf("expected RATE_LIMITED with retryAfterMs 90000, got %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, baseURL+"/api/iam/auth/signIn", strings.NewReader(`{"tenantId":"`+w.rootTenant+`","email":"root@example.test","password":"no"}`))
	request.Header.Set("content-type", "application/json")
	request.Header.Set("x-better-iam", "1")
	response := w.iam.Handle(request)
	if response.Status != 429 || response.Header.Get("Retry-After") != "90" {
		t.Fatalf("HTTP answer %d, Retry-After %q", response.Status, response.Header.Get("Retry-After"))
	}
	if string(response.Body) != `{"error":{"code":"RATE_LIMITED","message":"Too many attempts; try again later","retryAfterMs":90000}}` {
		t.Fatalf("HTTP body %s", response.Body)
	}
	_, err := w.client(client.Options{}).Auth.SignIn(w.ctx, apitypes.AuthSignInInput{TenantID: w.rootTenant, Email: "root@example.test", Password: "no"})
	var refused *client.IamClientError
	if !errors.As(err, &refused) || refused.Code != "RATE_LIMITED" || refused.Status != 429 || refused.RetryAfterMs == nil || *refused.RetryAfterMs != 90_000 {
		t.Fatalf("client refusal %+v", err)
	}
}

func TestClientReportsANetworkBoundSessionPresentedFromElsewhereAgainstARealServer(t *testing.T) {
	w := newWorld(t, func(options *server.BetterIamOptions) {
		options.HTTP = &server.HttpOptions{ClientInfo: func(request *http.Request) *core.SessionClientInfo {
			return &core.SessionClientInfo{IP: request.Header.Get("x-test-ip")}
		}}
	})
	tenantID, ownerToken := w.organization(w.rootSession(), "acme")
	password := "a strong alice test password"
	owner := w.client(client.Options{Token: ownerToken})
	if _, err := owner.Identities.Create(w.ctx, apitypes.IdentitiesCreateInput{TenantID: tenantID, Email: "alice@example.test", Name: "Alice", Password: &password}); err != nil {
		t.Fatal(err)
	}
	signedIn, err := w.client(client.Options{Headers: http.Header{"X-Test-Ip": {"203.0.113.7"}}}).Auth.SignIn(w.ctx, apitypes.AuthSignInInput{TenantID: tenantID, Email: "alice@example.test", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if signedIn.SessionResult == nil {
		t.Fatal("unexpected MFA")
	}
	bind := true
	if _, err := owner.Tenants.SetAuthPolicy(w.ctx, apitypes.TenantsSetAuthPolicyInput{TenantID: tenantID, AuthPolicy: &core.TenantAuthPolicy{BindSessionsToIP: &bind}}); err != nil {
		t.Fatal(err)
	}
	var seen []string
	from := func(ip string) *client.Client {
		return w.client(client.Options{
			Token:             signedIn.SessionResult.Token,
			Headers:           http.Header{"X-Test-Ip": {ip}},
			OnUnauthenticated: func(err *client.IamClientError) { seen = append(seen, err.Code) },
		})
	}
	current, err := from("203.0.113.7").Auth.GetSession(w.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Session.ID != signedIn.SessionResult.Session.ID {
		t.Fatalf("session %s, want %s", current.Session.ID, signedIn.SessionResult.Session.ID)
	}
	_, err = from("198.51.100.9").Auth.GetSession(w.ctx)
	var refused *client.IamClientError
	if !errors.As(err, &refused) || refused.Code != "SESSION_NETWORK_MISMATCH" || refused.Status != 401 {
		t.Fatalf("refusal %v", err)
	}
	if len(seen) != 1 || seen[0] != "SESSION_NETWORK_MISMATCH" {
		t.Fatalf("hook saw %v", seen)
	}
}

func TestSessionStoreFollowsTheServerSession(t *testing.T) {
	w := newWorld(t, nil)
	tenantID, ownerToken := w.organization(w.rootSession(), "storeco")
	token := ownerToken
	c := w.client(client.Options{TokenFunc: func(context.Context) (string, bool, error) { return token, token != "", nil }})
	store := client.NewClientSessionStore(c, client.SessionStoreOptions[apitypes.AuthGetSessionOutput]{})
	if snapshot := store.Snapshot(); snapshot.Status != client.SessionLoading || snapshot.Session != nil || snapshot.UpdatedAt != 0 {
		t.Fatalf("initial snapshot %+v", snapshot)
	}
	var notified int
	var mu sync.Mutex
	unsubscribe := store.Subscribe(func() {
		mu.Lock()
		notified++
		mu.Unlock()
	})
	// Concurrent refreshes share one request.
	var requests int
	var group sync.WaitGroup
	counting := w.client(client.Options{Token: ownerToken, Fetch: func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		requests++
		mu.Unlock()
		return handlerFetch(w.iam)(request)
	}})
	shared := client.NewClientSessionStore(counting, client.SessionStoreOptions[apitypes.AuthGetSessionOutput]{})
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			if snapshot := shared.Refresh(w.ctx); snapshot.Status != client.SessionAuthenticated {
				t.Errorf("shared refresh %+v", snapshot)
			}
		}()
	}
	group.Wait()
	if requests < 1 || requests > 4 {
		t.Fatalf("requests %d", requests)
	}
	snapshot := store.Refresh(w.ctx)
	if snapshot.Status != client.SessionAuthenticated || snapshot.Session == nil || snapshot.Session.Identity.TenantID != tenantID || snapshot.UpdatedAt == 0 {
		t.Fatalf("refreshed %+v", snapshot)
	}
	// Signing out clears the local session and ends the server one.
	if err := store.SignOut(w.ctx); err != nil {
		t.Fatal(err)
	}
	if snapshot := store.Snapshot(); snapshot.Status != client.SessionUnauthenticated || snapshot.Session != nil || snapshot.Error != nil {
		t.Fatalf("signed out %+v", snapshot)
	}
	// The server now refuses the token: unauthenticated, with the server's error kept.
	snapshot = store.Refresh(w.ctx)
	var refused *client.IamClientError
	if snapshot.Status != client.SessionUnauthenticated || snapshot.Session != nil || !errors.As(snapshot.Error, &refused) || refused.Code != "UNAUTHENTICATED" {
		t.Fatalf("after sign-out %+v", snapshot)
	}
	if !client.IsUnauthenticated(snapshot.Error) || client.IsUnauthenticated(errors.New("offline")) || !client.IsUnauthenticated(core.NewIamError("FORBIDDEN", "no", 403)) {
		t.Fatal("IsUnauthenticated")
	}
	// A transport failure keeps the last session and reports an error.
	store.Set(&apitypes.AuthGetSessionOutput{})
	broken := client.NewSessionStore[apitypes.AuthGetSessionOutput](failingSession{}, client.SessionStoreOptions[apitypes.AuthGetSessionOutput]{HasInitial: true, Initial: &apitypes.AuthGetSessionOutput{}})
	if snapshot := broken.Refresh(w.ctx); snapshot.Status != client.SessionError || snapshot.Session == nil || snapshot.Error == nil {
		t.Fatalf("transport failure %+v", snapshot)
	}
	unsubscribe()
	before := notified
	store.Set(nil)
	if notified != before || store.Snapshot().Status != client.SessionUnauthenticated {
		t.Fatal("an unsubscribed listener was notified")
	}
	if before != 4 {
		t.Fatalf("notifications %d", before)
	}
	signedOut := client.NewSessionStore[apitypes.AuthGetSessionOutput](failingSession{}, client.SessionStoreOptions[apitypes.AuthGetSessionOutput]{HasInitial: true})
	if snapshot := signedOut.Snapshot(); snapshot.Status != client.SessionUnauthenticated || snapshot.UpdatedAt == 0 {
		t.Fatalf("initial null %+v", snapshot)
	}
}

type failingSession struct{}

func (failingSession) GetSession(context.Context) (apitypes.AuthGetSessionOutput, error) {
	return apitypes.AuthGetSessionOutput{}, errors.New("network down")
}

func (failingSession) SignOut(context.Context) error { return errors.New("network down") }

func TestDeviceProofsAreAcceptedByTheServerForEnrollment(t *testing.T) {
	w := newWorld(t, nil)
	tenantID, ownerToken := w.organization(w.rootSession(), "deviceco")
	device, err := client.NewDeviceProver(client.DeviceProverOptions{Store: client.MemoryKeyStore()})
	if err != nil {
		t.Fatal(err)
	}
	var sessionID string
	c := w.client(client.Options{Token: ownerToken, HeadersFunc: func(ctx context.Context) (http.Header, error) {
		return device.Headers(ctx, sessionID), nil
	}})
	current, err := c.Auth.GetSession(w.ctx)
	if err != nil {
		t.Fatal(err)
	}
	sessionID = current.Session.ID
	jwk, err := device.PublicJwk(w.ctx)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := c.Devices.Enroll(w.ctx, apitypes.DevicesEnrollInput{TenantID: tenantID, Name: "Work laptop", Platform: "macos", PublicKey: apitypes.DevicePublicKeyInput{
		Kty: &jwk.Kty, Crv: &jwk.Crv, X: &jwk.X, Y: &jwk.Y,
	}})
	if err != nil {
		t.Fatal(err)
	}
	kid, err := device.KeyID(w.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.KeyID != kid {
		t.Fatalf("enrolled key %s, prover key %s", enrolled.KeyID, kid)
	}
	// The same key cannot be enrolled twice.
	_, err = c.Devices.Enroll(w.ctx, apitypes.DevicesEnrollInput{TenantID: tenantID, Name: "Again", Platform: "macos", PublicKey: apitypes.DevicePublicKeyInput{
		Kty: &jwk.Kty, Crv: &jwk.Crv, X: &jwk.X, Y: &jwk.Y,
	}})
	var refused *client.IamClientError
	if !errors.As(err, &refused) || refused.Code != "CONFLICT" {
		t.Fatalf("second enrollment: %v", err)
	}
}
