package oauth

// Port of tests/ssf.test.ts and the Shared Signals part of tests/security-outbound.test.ts. The TypeScript tests
// drive the transmitter through a whole IAM deployment (iam.protocolHost, iam.events); here a protocol host over
// the store stands in for it and the audit events the server would dispatch are published directly, so the tests
// cover this package's behaviour: SETs, subjects, retries, pausing, validation and metadata.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const ssfIssuer = "https://id.example.test/oidc"

type receivedSET struct {
	authorization string
	contentType   string
	set           string
}

type ssfReceiver struct {
	server   *httptest.Server
	mu       sync.Mutex
	received []receivedSET
	status   int
}

func newSSFReceiver(t *testing.T) *ssfReceiver {
	r := &ssfReceiver{status: 202}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		r.mu.Lock()
		r.received = append(r.received, receivedSET{authorization: request.Header.Get("authorization"), contentType: request.Header.Get("content-type"), set: string(body)})
		status := r.status
		r.mu.Unlock()
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(status)
		if status != 202 {
			_, _ = w.Write([]byte(`{"err":"invalid_request","description":"nope"}`))
		}
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *ssfReceiver) url() string { return r.server.URL + "/events" }

func (r *ssfReceiver) refuse(status int) {
	r.mu.Lock()
	r.status = status
	r.mu.Unlock()
}

func (r *ssfReceiver) last() receivedSET {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.received[len(r.received)-1]
}

func (r *ssfReceiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.received)
}

type ssfFixture struct {
	store       core.IamStore
	tenantID    string
	owner       core.CredentialInput
	transmitter *SharedSignalsTransmitter
	publicJWK   *core.Object
	endpoint    *ssfReceiver
	subscribers []func(ctx context.Context, event *core.Object) error
}

// Subscribe makes the fixture an EventSubscriber (iam.events).
func (f *ssfFixture) Subscribe(pattern any, handler func(ctx context.Context, event *core.Object) error) (func(), error) {
	f.subscribers = append(f.subscribers, handler)
	return func() { f.subscribers = nil }, nil
}

// dispatch hands an audit event to the subscribers, as iam.dispatchAuditHooks does.
func (f *ssfFixture) dispatch(t *testing.T, action, actorID, resourceID string) {
	t.Helper()
	event := core.NewObject("id", randomUUID(), "tenantId", f.tenantID, "actorId", actorID, "action", action, "resourceId", resourceID,
		"timestamp", wallNow(), "outcome", "allow")
	for _, handler := range f.subscribers {
		if err := handler(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
}

func newSSFFixture(t *testing.T) *ssfFixture {
	t.Helper()
	store := newTestStore(t)
	now := wallNow()
	f := &ssfFixture{store: store, tenantID: "acme", owner: core.CredentialInput{Token: "owner"}}
	insert(t, store, "tenants", core.NewObject("id", "acme", "tenantId", "acme", "name", "Acme", "type", "organization", "parentId", nil, "status", "active", "createdAt", now))
	for _, name := range []string{"owner", "alice", "bob", "carol"} {
		insert(t, store, "identities", core.NewObject("id", "id-"+name, "tenantId", "acme", "name", name, "kind", "user", "email", name+"@acme.test",
			"emailVerified", name == "owner", "status", "active", "rootAdmin", false, "owner", name == "owner", "createdAt", now))
	}
	signing, public := testRSAKey()
	signing.Set("kid", "ssf-key")
	signing.Delete("use")
	public.Set("kid", "ssf-key")
	f.publicJWK = public
	f.endpoint = newSSFReceiver(t)
	transmitter, err := CreateSharedSignalsTransmitter(SharedSignalsConfig{Store: store, Issuer: ssfIssuer,
		JWKS: core.NewObject("keys", []any{signing}), EncryptionKey: randomKey(), AllowInsecureLocalhost: true,
		Authorize:    ssfAuthorize,
		Authenticate: ssfAuthenticate(store)})
	if err != nil {
		t.Fatal(err)
	}
	f.transmitter = transmitter
	return f
}

func ssfAuthorize(_ context.Context, credential core.CredentialInput, _ string, _ core.ResourceRef) error {
	if credential.Token != "owner" {
		return core.NewIamError("ACCESS_DENIED", "Forbidden", 403)
	}
	return nil
}

func ssfAuthenticate(store core.IamStore) func(ctx context.Context, credential core.CredentialInput) (*auth.Principal, error) {
	return func(ctx context.Context, credential core.CredentialInput) (*auth.Principal, error) {
		identity, err := store.Get(ctx, "identities", "id-"+credential.Token)
		if err != nil || identity == nil {
			return nil, core.NewIamError("UNAUTHENTICATED", "Unauthenticated", 401)
		}
		return &auth.Principal{Identity: identity, Session: core.NewObject("id", "s-"+credential.Token, "kind", "user")}, nil
	}
}

func (f *ssfFixture) decode(t *testing.T, set string) (*core.Object, *core.Object) {
	t.Helper()
	key, err := joseImportPublic(f.publicJWK, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	payload, header, err := joseJwtVerify(context.Background(), set, staticKeyResolver(key), joseVerifyOptions{hasIssuer: true, issuer: ssfIssuer,
		typ: "secevent+jwt", clockTolerance: core.Undefined, maxTokenAge: core.Undefined, currentDate: float64(wallNow())})
	if err != nil {
		t.Fatalf("invalid SET: %v", err)
	}
	return payload, header
}

func strPtr(value string) *string { return &value }

func TestSSFPushesSignedEvents(t *testing.T) {
	f := newSSFFixture(t)
	ctx := context.Background()
	stream, err := f.transmitter.CreateStream(ctx, f.owner, StreamInput{TenantID: f.tenantID, Name: "SIEM", EndpointURL: f.endpoint.url(),
		Authorization: strPtr("Bearer receiver-secret")})
	if err != nil {
		t.Fatal(err)
	}
	if !stream.HasAuthorization || stream.SubjectFormat != "iss_sub" || stream.Pending != 0 || strings.Contains(stringify(toObject(stream)), "receiver-secret") {
		t.Fatalf("unexpected stream %+v", stream)
	}
	verification, err := f.transmitter.VerifyStream(ctx, f.owner, f.tenantID, stream.ID, strPtr("check-123"))
	if err != nil || !verification.Delivered {
		t.Fatalf("unexpected verification %+v %v", verification, err)
	}
	first := f.endpoint.last()
	if first.authorization != "Bearer receiver-secret" || first.contentType != "application/secevent+jwt" {
		t.Fatalf("unexpected delivery %+v", first)
	}
	payload, header := f.decode(t, first.set)
	if str(header, "typ") != "secevent+jwt" || str(header, "kid") != "ssf-key" || str(payload, "aud") != f.endpoint.url() ||
		stringify(obj(payload, "events").Get(ssfEventType+"/verification")) != `{"state":"check-123"}` {
		t.Fatalf("unexpected verification SET %s %s", stringify(header), stringify(payload))
	}
	unsubscribe, _ := f.transmitter.Subscribe(f, nil)
	f.dispatch(t, "identity:revoke-sessions", "id-owner", "id-alice")
	revoked, _ := f.decode(t, f.endpoint.last().set)
	if stringify(revoked.Get("sub_id")) != `{"format":"iss_sub","iss":"`+ssfIssuer+`","sub":"id-alice"}` ||
		str(obj(obj(revoked, "events"), SharedSignalEvents.SessionRevoked), "initiating_entity") != "admin" || str(revoked, "txn") == "" {
		t.Fatalf("unexpected session-revoked SET %s", stringify(revoked))
	}
	f.dispatch(t, "auth:password:change", "id-alice", "id-alice")
	changed, _ := f.decode(t, f.endpoint.last().set)
	claims := obj(obj(changed, "events"), SharedSignalEvents.CredentialChange)
	if str(claims, "credential_type") != "password" || str(claims, "change_type") != "update" || str(claims, "initiating_entity") != "user" {
		t.Fatalf("unexpected credential-change SET %s", stringify(changed))
	}
	deliveries, err := f.transmitter.ListDeliveries(ctx, f.owner, ListDeliveriesInput{TenantID: f.tenantID, StreamID: stream.ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, delivery := range deliveries {
		if delivery.Status != "delivered" {
			t.Fatalf("expected every delivery delivered, got %+v", delivery)
		}
	}
	if deliveries[0].EventType != SharedSignalEvents.CredentialChange {
		t.Fatalf("expected the newest first, got %s", deliveries[0].EventType)
	}
	unsubscribe()
	if !contains(auditActions(t, f.store, f.tenantID), "iam:ssf:CreateStream") {
		t.Fatal("missing CreateStream audit event")
	}
}

func TestSSFFiltersRetriesAndPauses(t *testing.T) {
	f := newSSFFixture(t)
	ctx := context.Background()
	stream, err := f.transmitter.CreateStream(ctx, f.owner, StreamInput{TenantID: f.tenantID, Name: "Credentials only", EndpointURL: f.endpoint.url(),
		Audience: strPtr("https://receiver.example.test"), Events: []string{SharedSignalEvents.CredentialChange}, SubjectFormat: strPtr("email")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.transmitter.Subscribe(f, nil); err != nil {
		t.Fatal(err)
	}
	update(t, f.store, "identities", "id-bob", func(record *core.Object) { record.Set("emailVerified", true) })
	f.endpoint.refuse(500)
	f.dispatch(t, "auth:session:revoke", "id-bob", "id-bob")
	f.dispatch(t, "auth:password:change", "id-bob", "id-bob")
	deliveries, _ := f.transmitter.ListDeliveries(ctx, f.owner, ListDeliveriesInput{TenantID: f.tenantID, StreamID: stream.ID})
	if len(deliveries) != 1 || deliveries[0].Status != "pending" || deliveries[0].Attempts != 1 || deliveries[0].LastError != "HTTP 500: invalid_request nope" {
		t.Fatalf("unexpected deliveries %+v", deliveries)
	}
	if current, _ := f.transmitter.GetStream(ctx, f.owner, f.tenantID, stream.ID); !strings.Contains(current.LastError, "HTTP 500") {
		t.Fatalf("unexpected stream error %q", current.LastError)
	}
	if delivered, failed, err := f.transmitter.Dispatch(ctx, 0); err != nil || delivered != 0 || failed != 0 {
		t.Fatalf("expected nothing due, got %d %d %v", delivered, failed, err)
	}
	f.endpoint.refuse(202)
	err = f.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		records, err := tx.Find(ctx, "ssfDeliveries", core.NewObject("streamId", stream.ID), nil)
		if err != nil {
			return err
		}
		records[0].Set("nextAttemptAt", 0)
		_, err = tx.Put(ctx, "ssfDeliveries", records[0])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if delivered, failed, err := f.transmitter.Dispatch(ctx, 0); err != nil || delivered != 1 || failed != 0 {
		t.Fatalf("expected one delivery, got %d %d %v", delivered, failed, err)
	}
	set, _ := f.decode(t, f.endpoint.last().set)
	if str(set, "aud") != "https://receiver.example.test" || stringify(set.Get("sub_id")) != `{"format":"email","email":"bob@acme.test"}` || str(set, "tenant_id") != f.tenantID {
		t.Fatalf("unexpected SET %s", stringify(set))
	}
	disabled := false
	if _, err := f.transmitter.UpdateStream(ctx, f.owner, UpdateStreamInput{TenantID: f.tenantID, StreamID: stream.ID, Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	before := f.endpoint.count()
	f.dispatch(t, "auth:password:change", "id-bob", "id-bob")
	if f.endpoint.count() != before {
		t.Fatal("a paused stream delivered")
	}
	if current, _ := f.transmitter.GetStream(ctx, f.owner, f.tenantID, stream.ID); current.Pending != 1 {
		t.Fatalf("expected one pending delivery, got %d", current.Pending)
	}
	enabled := true
	if _, err := f.transmitter.UpdateStream(ctx, f.owner, UpdateStreamInput{TenantID: f.tenantID, StreamID: stream.ID, Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	if delivered, failed, err := f.transmitter.Dispatch(ctx, 0); err != nil || delivered != 1 || failed != 0 {
		t.Fatalf("expected the held delivery sent, got %d %d %v", delivered, failed, err)
	}
	if f.endpoint.count() != before+1 {
		t.Fatalf("expected one more SET, got %d", f.endpoint.count()-before)
	}
	if err := f.transmitter.DeleteStream(ctx, f.owner, f.tenantID, stream.ID); err != nil {
		t.Fatal(err)
	}
	if left, _ := f.store.Find(ctx, "ssfDeliveries", core.NewObject("streamId", stream.ID), nil); len(left) != 0 {
		t.Fatalf("expected the queue dropped, got %d", len(left))
	}
}

func TestSSFGuardsValidatesAndServesMetadata(t *testing.T) {
	f := newSSFFixture(t)
	ctx := context.Background()
	_, err := f.transmitter.CreateStream(ctx, core.CredentialInput{Token: "carol"}, StreamInput{TenantID: f.tenantID, Name: "X", EndpointURL: f.endpoint.url()})
	expectIamError(t, err, 403, "")
	for _, change := range []func(input *StreamInput){
		func(input *StreamInput) { input.EndpointURL = "http://receiver.example.test/events" },
		func(input *StreamInput) { input.EndpointURL = "not a url" },
		func(input *StreamInput) { input.Events = []string{"https://example.test/unknown"} },
		func(input *StreamInput) { input.SubjectFormat = strPtr("phone") },
		func(input *StreamInput) { input.Authorization = strPtr("Bearer a\r\nx-injected: 1") },
		func(input *StreamInput) { input.Name = "" },
	} {
		input := StreamInput{TenantID: f.tenantID, Name: "X", EndpointURL: f.endpoint.url()}
		change(&input)
		_, err := f.transmitter.CreateStream(ctx, f.owner, input)
		expectIamError(t, err, 0, "INVALID_INPUT")
	}
	served := f.transmitter.Handler(httptest.NewRequest("GET", "https://id.example.test/.well-known/ssf-configuration/oidc", nil))
	if served == nil {
		t.Fatal("expected the metadata served")
	}
	metadata := mustParse(t, string(served.Body))
	if str(metadata, "spec_version") != "1_0" || str(metadata, "issuer") != ssfIssuer || str(metadata, "jwks_uri") != ssfIssuer+"/jwks" ||
		stringify(metadata.Get("delivery_methods_supported")) != `["urn:ietf:rfc:8935"]` {
		t.Fatalf("unexpected metadata %s", served.Body)
	}
	if f.transmitter.Handler(httptest.NewRequest("GET", "https://id.example.test/other", nil)) != nil {
		t.Fatal("expected other paths left alone")
	}
	_, err = CreateSharedSignalsTransmitter(SharedSignalsConfig{Store: f.store, Issuer: ssfIssuer, JWKS: core.NewObject("keys", []any{f.publicJWK}),
		EncryptionKey: randomKey(), Authorize: ssfAuthorize, Authenticate: ssfAuthenticate(f.store)})
	if err == nil || !strings.Contains(err.Error(), "private signing key") {
		t.Fatalf("expected a private key refusal, got %v", err)
	}
}

func TestSSFReceiversRefusePrivateEndpoints(t *testing.T) {
	f := newSSFFixture(t)
	ctx := context.Background()
	for _, endpoint := range []string{"https://10.0.0.1/events", "https://169.254.169.254/events"} {
		_, err := f.transmitter.CreateStream(ctx, f.owner, StreamInput{TenantID: f.tenantID, Name: "SIEM", EndpointURL: endpoint})
		expectIamError(t, err, 0, "INVALID_INPUT")
	}
	stream, err := f.transmitter.CreateStream(ctx, f.owner, StreamInput{TenantID: f.tenantID, Name: "SIEM", EndpointURL: "https://siem.example.test/events",
		Authorization: strPtr("Bearer receiver-secret")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.transmitter.UpdateStream(ctx, f.owner, UpdateStreamInput{TenantID: f.tenantID, StreamID: stream.ID, EndpointURL: strPtr(f.endpoint.url())})
	expectIamError(t, err, 0, "INVALID_INPUT")
	if _, err := f.transmitter.UpdateStream(ctx, f.owner, UpdateStreamInput{TenantID: f.tenantID, StreamID: stream.ID, EndpointURL: strPtr(f.endpoint.url()), RemoveAuthorization: true}); err != nil {
		t.Fatal(err)
	}
	result, err := f.transmitter.VerifyStream(ctx, f.owner, f.tenantID, stream.ID, nil)
	if err != nil || !result.Delivered {
		t.Fatalf("expected the verification delivered, got %+v %v", result, err)
	}
	if f.endpoint.count() != 1 || f.endpoint.last().authorization != "" {
		t.Fatalf("expected one delivery without authorization, got %+v", f.endpoint.received)
	}
}
