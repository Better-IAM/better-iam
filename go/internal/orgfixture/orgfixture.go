// Package orgfixture is the Go port of tests/support/organization.ts organizationFixture for the tests of the
// framework integrations (middleware, mcp): a bootstrapped platform on an in-memory database with one organization
// ("Acme") whose owner accepted the invitation, the documents:read/write catalog, a resolver that answers the reference
// as given, seven-day sessions, and a controllable clock.
package orgfixture

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

const dayMs = int64(86_400_000)

// OwnerPassword is the password of owner@acme.test.
const OwnerPassword = "a strong tenant owner password"

// Fixture is the organization fixture.
type Fixture struct {
	T     *testing.T
	Ctx   context.Context
	IAM   *server.BetterIam
	Store core.IamStore
	// RootID is the platform root tenant.
	RootID         string
	RootCredential core.CredentialInput
	// TenantID is Acme's tenant.
	TenantID string
	// Owner is the owner's session credential and OwnerID their identity.
	Owner   core.CredentialInput
	OwnerID string
	Clock   *atomic.Int64

	mu    sync.Mutex
	inbox []auth.DeliveryMessage
}

// New builds the fixture; mutate adjusts the options before the server is composed.
func New(t *testing.T, mutate func(options *server.BetterIamOptions)) *Fixture {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.New(sqlite.Options{Filename: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	f := &Fixture{T: t, Ctx: ctx, Store: store, Clock: &atomic.Int64{}}
	f.Clock.Store(time.Now().UnixMilli())
	now := func() int64 { return f.Clock.Load() }
	week := 7 * dayMs
	options := &server.BetterIamOptions{
		Database: store, Secret: "organization-fixture-secret-with-32-characters", BaseURL: "http://localhost:3000",
		WallClock:   now,
		Permissions: &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}},
		ResolveResource: func(_ context.Context, reference core.ResourceRef) (*server.ResolvedResource, error) {
			return &server.ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID}, nil
		},
		Authentication: &auth.Options{
			Now: now, SessionLifetimeMs: &week, SessionIdleTimeoutMs: &week,
			SendEmail: func(_ context.Context, message auth.DeliveryMessage) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.inbox = append(f.inbox, message)
				return nil
			},
		},
	}
	if mutate != nil {
		mutate(options)
	}
	iam, err := server.New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iam.Close)
	f.IAM = iam
	if err := iam.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	root := f.must(iam.Bootstrap(ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password")))
	f.RootID, _ = root.Get("tenant").(*core.Object).Get("id").(string)
	challenge := f.must(iam.Auth.SignIn(ctx, core.NewObject("tenantId", f.RootID, "email", "root@example.test", "password", "a strong root test password")))
	if challenge.Get("mfaRequired") != true {
		t.Fatalf("root must require MFA: %s", core.MustStringify(challenge))
	}
	challengeID, _ := challenge.Get("challenge").(string)
	credential := auth.MfaCredential{TenantID: f.RootID, Challenge: challengeID}
	enrollment := f.must(iam.Auth.BeginMfa(ctx, credential))
	secret, _ := enrollment.Get("secret").(string)
	code, err := auth.GenerateTotp(secret, f.Clock.Load())
	if err != nil {
		t.Fatal(err)
	}
	rootSession := f.must(iam.Auth.ConfirmMfa(ctx, auth.ConfirmMfaInput{Credential: credential, Code: code}))
	f.RootCredential = core.CredentialInput{Token: rootSession.Get("token").(string)}
	created := f.Object(iam.API.Tenants.Create(ctx, f.RootCredential, server.Input[apitypes.TenantsCreateInput](core.NewObject(
		"parentId", f.RootID, "name", "Acme", "type", "organization", "ownerEmail", "owner@acme.test",
	))))
	f.TenantID, _ = created.Get("tenant").(*core.Object).Get("id").(string)
	if _, err := iam.Auth.DispatchOutbox(ctx, 100); err != nil {
		t.Fatal(err)
	}
	token := ""
	f.mu.Lock()
	for _, message := range f.inbox {
		if message.TenantID == f.TenantID && message.Template == "owner-invitation" {
			token = message.Payload["token"]
		}
	}
	f.mu.Unlock()
	if token == "" {
		t.Fatal("the owner invitation was not sent")
	}
	owner := f.Object(iam.API.Tenants.AcceptInvitation(ctx, server.Input[apitypes.TenantsAcceptInvitationInput](core.NewObject(
		"tenantId", f.TenantID, "token", token, "name", "Owner", "password", OwnerPassword,
	))))
	ownerToken, ok := owner.Get("token").(string)
	if !ok {
		t.Fatalf("unexpected owner MFA: %s", core.MustStringify(owner))
	}
	f.Owner = core.CredentialInput{Token: ownerToken}
	session := f.Object(iam.API.Auth.GetSession(ctx, f.Owner, server.Input[apitypes.AuthGetSessionInput](nil)))
	f.OwnerID, _ = session.Get("identity").(*core.Object).Get("id").(string)
	return f
}

func (f *Fixture) must(result *core.Object, err error) *core.Object {
	f.T.Helper()
	if err != nil {
		f.T.Fatal(err)
	}
	return result
}

// Value unwraps an API answer (an Out[T]): any error fails the test.
func (f *Fixture) Value(answer any, err error) any {
	f.T.Helper()
	if err != nil {
		f.T.Fatal(err)
	}
	field := reflect.ValueOf(answer).FieldByName("Value")
	if !field.IsValid() {
		f.T.Fatalf("unexpected answer %T", answer)
	}
	return field.Interface()
}

// Object is Value for an answer that is one record.
func (f *Fixture) Object(answer any, err error) *core.Object {
	f.T.Helper()
	result, ok := f.Value(answer, err).(*core.Object)
	if !ok {
		f.T.Fatalf("expected an object answer, got %T", result)
	}
	return result
}

// Items is Value for an answer that is a list of records.
func (f *Fixture) Items(answer any, err error) []*core.Object {
	f.T.Helper()
	list, ok := f.Value(answer, err).([]any)
	if !ok {
		f.T.Fatalf("expected a list answer")
	}
	result := make([]*core.Object, len(list))
	for index, item := range list {
		result[index], _ = item.(*core.Object)
	}
	return result
}

// Member creates a person `{name}@acme.test` with a password, as the owner.
func (f *Fixture) Member(name string) *core.Object {
	f.T.Helper()
	return f.Object(f.IAM.API.Identities.Create(f.Ctx, f.Owner, server.Input[apitypes.IdentitiesCreateInput](core.NewObject(
		"tenantId", f.TenantID, "email", name+"@acme.test", "name", name, "password", "a strong "+name+" password",
	))))
}

// SignIn signs a member in with their password and answers their session token.
func (f *Fixture) SignIn(name string) string {
	f.T.Helper()
	result := f.must(f.IAM.Auth.SignIn(f.Ctx, core.NewObject("tenantId", f.TenantID, "email", name+"@acme.test", "password", "a strong "+name+" password")))
	token, ok := result.Get("token").(string)
	if !ok {
		f.T.Fatalf("unexpected MFA: %s", core.MustStringify(result))
	}
	return token
}

// OwnerSignIn is a fresh, recently authenticated owner session.
func (f *Fixture) OwnerSignIn() core.CredentialInput {
	f.T.Helper()
	result := f.must(f.IAM.Auth.SignIn(f.Ctx, core.NewObject("tenantId", f.TenantID, "email", "owner@acme.test", "password", OwnerPassword)))
	token, ok := result.Get("token").(string)
	if !ok {
		f.T.Fatalf("unexpected owner MFA: %s", core.MustStringify(result))
	}
	return core.CredentialInput{Token: token}
}
