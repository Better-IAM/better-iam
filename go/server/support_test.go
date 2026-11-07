package server

// Test support: an in-memory SQLite store, a kernel A composition (options, config, auth, catalog, context, events)
// wired the way packages/server/src/index.ts wires them, a controllable clock, and model-value helpers.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const testSecret = "kernel-a-test-secret-with-at-least-32-characters"

func newStore(t *testing.T) core.IamStore {
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

// parse parses JSON into a model value (fails the test on invalid JSON).
func parse(t *testing.T, text string) any {
	t.Helper()
	parsed, err := core.ParseJSONString(text)
	if err != nil {
		t.Fatalf("invalid JSON %s: %v", text, err)
	}
	return parsed
}

func obj(t *testing.T, text string) *core.Object {
	t.Helper()
	parsed, ok := parse(t, text).(*core.Object)
	if !ok {
		t.Fatalf("not an object: %s", text)
	}
	return parsed
}

// optionsValue is a minimal options model value (database, secret, localhost baseURL) plus members.
func optionsValue(t *testing.T, members string) *core.Object {
	t.Helper()
	base := obj(t, `{"secret":"`+testSecret+`","baseURL":"http://localhost:3000"}`)
	base.SetRaw("database", Function{})
	if members != "" {
		base.Assign(obj(t, members))
	}
	return base
}

func iamError(t *testing.T, err error) *core.IamError {
	t.Helper()
	var known *core.IamError
	if !errors.As(err, &known) {
		t.Fatalf("expected an IamError, got %v", err)
	}
	return known
}

func expectError(t *testing.T, err error, code, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s %q, got no error", code, message)
	}
	known := iamError(t, err)
	if known.Code != code || known.Message != message {
		t.Fatalf("expected %s %q, got %s %q", code, message, known.Code, known.Message)
	}
}

func expectErrorPrefix(t *testing.T, err error, code, prefix string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s %q..., got no error", code, prefix)
	}
	known := iamError(t, err)
	if known.Code != code || !strings.HasPrefix(known.Message, prefix) {
		t.Fatalf("expected %s %q..., got %s %q", code, prefix, known.Code, known.Message)
	}
}

func expectContains(t *testing.T, err error, fragment string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), fragment) {
		t.Fatalf("expected an error containing %q, got %v", fragment, err)
	}
}

// must returns the result, panicking (which fails the test) on an error.
func must[T any](result T, err error) T {
	if err != nil {
		panic(err)
	}
	return result
}

// kernel is a kernel A composition over an in-memory store.
type kernel struct {
	t       *testing.T
	ctx     context.Context
	store   core.IamStore
	options *BetterIamOptions
	server  *ServerContext
	clock   atomic.Int64
	mu      sync.Mutex
	events  []*core.Object
}

// newKernel composes the kernel; mutate adjusts the options before construction.
func newKernel(t *testing.T, mutate func(options *BetterIamOptions)) *kernel {
	t.Helper()
	k := &kernel{t: t, ctx: context.Background(), store: newStore(t)}
	k.clock.Store(1_767_225_600_000)
	k.options = &BetterIamOptions{Database: k.store, Secret: testSecret, BaseURL: "http://localhost:3000",
		WallClock: func() int64 { return k.clock.Load() }}
	if mutate != nil {
		mutate(k.options)
	}
	config, err := ResolveConfig(k.options)
	if err != nil {
		t.Fatal(err)
	}
	authOptions := auth.Options{}
	if k.options.Authentication != nil {
		authOptions = *k.options.Authentication
	}
	authOptions.Store = k.store
	authOptions.Secret = k.options.Secret
	authOptions.PreviousSecrets = k.options.PreviousSecrets
	authOptions.BaseURL = k.options.BaseURL
	authOptions.TrustedOrigins = k.options.TrustedOrigins
	if authOptions.Now == nil {
		authOptions.Now = func() int64 { return k.clock.Load() }
	}
	var server *ServerContext
	authOptions.OnAudit = func(ctx context.Context, tx core.IamStore, event *core.Object) error {
		return server.Events.FanOut(ctx, tx, event)
	}
	authOptions.DeliverWebhook = func(ctx context.Context, message auth.DeliveryMessage) error {
		return server.Events.DeliverWebhookMessage(ctx, message)
	}
	service, err := auth.New(authOptions)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewCatalog(OptionsValue(k.options), k.options.Plugins, config)
	if err != nil {
		t.Fatal(err)
	}
	server = CreateContext(ContextBase{Options: k.options, Config: config, Store: k.store, Auth: service,
		Plugins: k.options.Plugins, Catalog: catalog, Now: service.Now, Observe: CreateObserver(k.options.Observability)})
	server.Events = CreateEvents(server)
	k.server = server
	return k
}

func (k *kernel) advance(ms int64) { k.clock.Add(ms) }

// insert writes records in one transaction.
func (k *kernel) insert(collection string, records ...*core.Object) {
	k.t.Helper()
	err := k.store.Transaction(k.ctx, func(ctx context.Context, tx core.IamStore) error {
		for _, record := range records {
			if _, err := tx.Insert(ctx, collection, record); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		k.t.Fatal(err)
	}
}

// tx runs fn in a transaction.
func (k *kernel) tx(fn func(ctx context.Context, tx core.IamStore) error) error {
	return k.store.Transaction(k.ctx, fn)
}

// tenantTree inserts root > organization > project tenants: root (rootTenant), org (orgTenant), project.
func (k *kernel) tenantTree() {
	k.insert("tenants",
		core.NewObject("id", "root", "tenantId", "root", "name", "Root", "type", "root", "parentId", nil, "status", "active", "createdAt", 1.0),
		core.NewObject("id", "org", "tenantId", "org", "name", "Acme", "type", "organization", "parentId", "root", "status", "active", "createdAt", 2.0),
		core.NewObject("id", "project", "tenantId", "project", "name", "Web", "type", "project", "parentId", "org", "status", "active", "createdAt", 3.0),
	)
}

// principal is an identity and session (records).
func principalOf(identity, session *core.Object) *Principal {
	return &Principal{Identity: identity, Session: session}
}

func identity(id, tenantID string, members ...any) *core.Object {
	record := core.NewObject("id", id, "tenantId", tenantID, "kind", "user", "name", id, "status", "active",
		"emailVerified", true, "rootAdmin", false, "owner", false, "createdAt", 1.0)
	for index := 0; index+1 < len(members); index += 2 {
		record.Set(members[index].(string), members[index+1])
	}
	return record
}

func session(id, identityID, tenantID, kind string, members ...any) *core.Object {
	record := core.NewObject("id", id, "tenantId", tenantID, "identityId", identityID, "kind", kind, "mfa", false,
		"tokenHash", "h-"+id, "createdAt", 1.0, "expiresAt", 9e15, "lastSeenAt", 1.0, "authenticatedAt", 1.0)
	for index := 0; index+1 < len(members); index += 2 {
		record.Set(members[index].(string), members[index+1])
	}
	return record
}

func float(value float64) *float64 { return &value }
func str(value string) *string     { return &value }
func flag(value bool) *bool        { return &value }

type contextT = context.Context
