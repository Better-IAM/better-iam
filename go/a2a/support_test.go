package a2a

// Test support: tests/support/organization.ts organizationFixture rebuilt on the server's public API (a bootstrapped
// platform with one organization "Acme" whose owner accepted the invitation, a controllable clock, sessions that
// last seven days), and helpers to call API groups with model-value bodies.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

type orgFixture struct {
	t        *testing.T
	ctx      context.Context
	iam      *server.BetterIam
	clock    *atomic.Int64
	rootID   string
	root     core.CredentialInput
	tenantID string
	owner    core.CredentialInput
	ownerID  string
	mu       sync.Mutex
	inbox    []auth.DeliveryMessage
}

// cardKey is a fresh private Ed25519 card key (a JWK with kid, alg EdDSA, use sig).
func cardKey(t *testing.T, kid string) *core.Object {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return core.NewObject("crv", "Ed25519", "d", base64.RawURLEncoding.EncodeToString(private.Seed()),
		"x", base64.RawURLEncoding.EncodeToString(public), "kty", "OKP", "kid", kid, "alg", "EdDSA", "use", "sig")
}

func str(value string) *string { return &value }

// must answers a value, panicking (failing the test) on an error.
func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func newOrgFixture(t *testing.T, mutate func(options *server.BetterIamOptions)) *orgFixture {
	t.Helper()
	store, err := sqlite.New(sqlite.Options{Filename: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	f := &orgFixture{t: t, ctx: context.Background(), clock: &atomic.Int64{}}
	if err := store.Migrate(f.ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	f.clock.Store(1_767_225_600_000)
	now := func() int64 { return f.clock.Load() }
	week := int64(7 * 86_400_000)
	options := &server.BetterIamOptions{
		Database: store, Secret: "organization-fixture-secret-with-32-characters", BaseURL: "http://localhost:3000",
		Permissions: &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}},
		ResolveResource: func(_ context.Context, reference core.ResourceRef) (*server.ResolvedResource, error) {
			return &server.ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID}, nil
		},
		WallClock: now,
		Authentication: &auth.Options{Now: now, SessionLifetimeMs: &week, SessionIdleTimeoutMs: &week,
			SendEmail: func(_ context.Context, message auth.DeliveryMessage) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.inbox = append(f.inbox, message)
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
	f.iam = iam
	if err := iam.Initialize(f.ctx); err != nil {
		t.Fatal(err)
	}
	root := must(iam.Bootstrap(f.ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password")))
	f.rootID, _ = root.Get("tenant").(*core.Object).Get("id").(string)
	challenge := must(iam.Auth.SignIn(f.ctx, core.NewObject("tenantId", f.rootID, "email", "root@example.test", "password", "a strong root test password")))
	if challenge.Get("mfaRequired") != true {
		t.Fatalf("root must require MFA: %s", core.MustStringify(challenge))
	}
	credential := auth.MfaCredential{TenantID: f.rootID, Challenge: challenge.Get("challenge").(string)}
	enrollment := must(iam.Auth.BeginMfa(f.ctx, credential))
	code := must(auth.GenerateTotp(enrollment.Get("secret").(string), f.clock.Load()))
	session := must(iam.Auth.ConfirmMfa(f.ctx, auth.ConfirmMfaInput{Credential: credential, Code: code}))
	f.root = core.CredentialInput{Token: session.Get("token").(string)}
	created := call(f, iam.API.Tenants.Create, f.root, "parentId", f.rootID, "name", "Acme", "type", "organization", "ownerEmail", "owner@acme.test")
	f.tenantID = member(created, "tenant", "id").(string)
	if _, err := iam.Auth.DispatchOutbox(f.ctx, 0); err != nil {
		t.Fatal(err)
	}
	var token string
	for _, message := range f.inbox {
		if message.TenantID == f.tenantID && message.Template == "owner-invitation" {
			token = message.Payload["token"]
		}
	}
	accepted := must(iam.API.Tenants.AcceptInvitation(f.ctx, server.Input[apitypes.TenantsAcceptInvitationInput](core.NewObject(
		"tenantId", f.tenantID, "token", token, "name", "Owner", "password", "a strong tenant owner password"))))
	model := must(server.ToModel(accepted.Value))
	ownerToken, ok := member(model, "token").(string)
	if !ok {
		t.Fatalf("unexpected owner MFA: %s", core.MustStringify(model))
	}
	f.owner = core.CredentialInput{Token: ownerToken}
	principal := must(iam.Authenticate(f.ctx, f.owner))
	f.ownerID = principal.Identity.Get("id").(string)
	return f
}

func (f *orgFixture) now() float64     { return float64(f.clock.Load()) }
func (f *orgFixture) advance(ms int64) { f.clock.Add(ms) }

// member reads nested members of a model value.
func member(value any, path ...string) any {
	for _, key := range path {
		object, ok := value.(*core.Object)
		if !ok {
			return core.Undefined
		}
		value = object.Get(key)
	}
	return value
}

func body(members ...any) *core.Object { return core.NewObject(members...) }

// callErr invokes an API method with a body (members, plus the fixture's tenantId unless given) and answers its
// model value.
func callErr[I, O any](f *orgFixture, method func(context.Context, core.CredentialInput, server.In[I]) (server.Out[O], error),
	credential core.CredentialInput, members ...any) (*core.Object, []any, error) {
	input := body(members...)
	if !input.Has("tenantId") {
		input = core.NewObject("tenantId", f.tenantID).Assign(input)
	}
	out, err := method(f.ctx, credential, server.Input[I](input))
	if err != nil {
		return nil, nil, err
	}
	model, err := server.ToModel(out.Value)
	if err != nil {
		return nil, nil, err
	}
	switch value := model.(type) {
	case *core.Object:
		return value, nil, nil
	case []any:
		return nil, value, nil
	}
	return nil, nil, nil
}

// call is callErr failing the test on an error.
func call[I, O any](f *orgFixture, method func(context.Context, core.CredentialInput, server.In[I]) (server.Out[O], error),
	credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	object, _, err := callErr(f, method, credential, members...)
	if err != nil {
		f.t.Fatal(err)
	}
	return object
}

// memberIdentity creates the person {name}@acme.test with a password, as the owner.
func (f *orgFixture) memberIdentity(name string) *core.Object {
	f.t.Helper()
	return call(f, f.iam.API.Identities.Create, f.owner, "email", name+"@acme.test", "name", name, "password", "a strong "+name+" password")
}

// signIn signs {name}@acme.test in.
func (f *orgFixture) signIn(name string) core.CredentialInput {
	f.t.Helper()
	result := must(f.iam.Auth.SignIn(f.ctx, core.NewObject("tenantId", f.tenantID, "email", name+"@acme.test", "password", "a strong "+name+" password")))
	token, ok := result.Get("token").(string)
	if !ok {
		f.t.Fatalf("unexpected MFA: %s", core.MustStringify(result))
	}
	return core.CredentialInput{Token: token}
}

// ownerSignIn is a fresh owner session.
func (f *orgFixture) ownerSignIn() core.CredentialInput {
	f.t.Helper()
	result := must(f.iam.Auth.SignIn(f.ctx, core.NewObject("tenantId", f.tenantID, "email", "owner@acme.test", "password", "a strong tenant owner password")))
	return core.CredentialInput{Token: result.Get("token").(string)}
}

// agentKey creates an agent (members of agents.create) and a key for it: its id and token.
func (f *orgFixture) agentKey(members ...any) (string, string) {
	f.t.Helper()
	agent := call(f, f.iam.API.Agents.Create, f.owner, members...)
	id := agent.Get("id").(string)
	key := call(f, f.iam.API.Credentials.Create, f.owner, "identityId", id)
	return id, key.Get("token").(string)
}

// grantDocuments gives a subject a role allowing actions on every document.
func (f *orgFixture) grantDocuments(subjectID string, actions ...string) {
	f.t.Helper()
	list := make([]any, len(actions))
	for index, action := range actions {
		list[index] = action
	}
	role := call(f, f.iam.API.Roles.Create, f.owner, "name", "Docs "+subjectID, "document", core.NewObject("version", 1.0,
		"statements", []any{core.NewObject("effect", "allow", "actions", list, "resources", []any{"document/*"})}))
	call(f, f.iam.API.Bindings.Create, f.owner, "roleId", role.Get("id"), "subjectType", "identity", "subjectId", subjectID)
}

// expectReason checks an *AgentCardError or *DelegationTokenError reason.
func expectReason(t *testing.T, err error, reason string) {
	t.Helper()
	var card *AgentCardError
	var token *DelegationTokenError
	switch {
	case errors.As(err, &card):
		if card.Reason != reason {
			t.Fatalf("reason = %s (%s), want %s", card.Reason, card.Message, reason)
		}
	case errors.As(err, &token):
		if token.Reason != reason {
			t.Fatalf("reason = %s (%s), want %s", token.Reason, token.Message, reason)
		}
	default:
		t.Fatalf("error = %v, want reason %s", err, reason)
	}
}

func expectCode(t *testing.T, err error, code string) *core.IamError {
	t.Helper()
	var known *core.IamError
	if !errors.As(err, &known) || known.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
	return known
}

func parseObject(t *testing.T, text string) *core.Object {
	t.Helper()
	parsed, err := core.ParseJSONString(text)
	if err != nil {
		t.Fatalf("invalid JSON %s: %v", text, err)
	}
	object, ok := parsed.(*core.Object)
	if !ok {
		t.Fatalf("not an object: %s", text)
	}
	return object
}
