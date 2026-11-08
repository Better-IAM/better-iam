package scim

// tests/support/organization.ts organizationFixture for the SCIM tests that run against the IAM server: a bootstrapped
// platform with one active organization ("Acme") and its signed-in owner. Organizations are created with
// `activate: true` instead of redeeming an owner invitation (as go/server/api_tenants_test.go does). A step that
// reaches another unit's NOT_IMPLEMENTED stub skips the rest of the test.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

const fixturePassword = "a strong tenant owner password"

type orgFixture struct {
	t        *testing.T
	ctx      context.Context
	store    core.IamStore
	iam      *server.BetterIam
	clock    *atomic.Int64
	mu       sync.Mutex
	inbox    []auth.DeliveryMessage
	rootID   string
	root     core.CredentialInput
	tenantID string
	owner    core.CredentialInput
}

// requirePorted fails the test on an error, or skips the rest of it when the error is another unit's NOT_IMPLEMENTED
// stub.
func requirePorted(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if known, isKnown := err.(*core.IamError); isKnown && known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
	t.Fatal(err)
}

func newOrgFixture(t *testing.T) *orgFixture {
	t.Helper()
	f := &orgFixture{t: t, ctx: context.Background(), store: newStore(t), clock: &atomic.Int64{}}
	f.clock.Store(time.Now().UnixMilli())
	now := func() int64 { return f.clock.Load() }
	week := int64(7 * 86_400_000)
	iam, err := server.New(&server.BetterIamOptions{
		Database: f.store, Secret: "organization-fixture-secret-with-32-characters", BaseURL: "http://localhost:3000",
		Permissions: &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}},
		ResolveResource: func(_ context.Context, reference core.ResourceRef) (*server.ResolvedResource, error) {
			return &server.ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID}, nil
		},
		Authentication: &auth.Options{Now: now, SessionLifetimeMs: &week, SessionIdleTimeoutMs: &week, SendEmail: func(_ context.Context, message auth.DeliveryMessage) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.inbox = append(f.inbox, message)
			return nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iam.Close)
	f.iam = iam
	requirePorted(t, iam.Initialize(f.ctx))
	root := f.record(iam.Bootstrap(f.ctx, obj("email", "root@example.test", "name", "Root", "password", "a strong root test password")))
	f.rootID = jsString(member(root.Get("tenant"), "id"))
	challenge := f.record(iam.Auth.SignIn(f.ctx, obj("tenantId", f.rootID, "email", "root@example.test", "password", "a strong root test password")))
	credential := auth.MfaCredential{TenantID: f.rootID, Challenge: jsString(challenge.Get("challenge"))}
	enrollment := f.record(iam.Auth.BeginMfa(f.ctx, credential))
	code := f.text(auth.GenerateTotp(jsString(enrollment.Get("secret")), f.clock.Load()))
	session := f.record(iam.Auth.ConfirmMfa(f.ctx, auth.ConfirmMfaInput{Credential: credential, Code: code}))
	f.root = core.CredentialInput{Token: jsString(session.Get("token"))}

	created := f.record(iam.API.Tenants.Create(f.ctx, f.root, server.Input[apitypes.TenantsCreateInput](obj(
		"parentId", f.rootID, "name", "Acme", "type", "organization", "ownerEmail", "owner@acme.test", "activate", true, "ownerName", "Owner",
	))))
	f.tenantID = jsString(member(created.Get("tenant"), "id"))
	ownerID := jsString(member(created.Get("owner"), "id"))
	f.setPassword(ownerID)
	f.owner = f.signIn("owner@acme.test")
	return f
}

func (f *orgFixture) setPassword(identityID string) {
	f.t.Helper()
	requirePorted(f.t, f.store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		realm, err := tx.Get(ctx, "tenants", f.tenantID)
		if err != nil {
			return err
		}
		identity, err := tx.Get(ctx, "identities", identityID)
		if err != nil {
			return err
		}
		if err := f.iam.Auth.SetPassword(ctx, tx, realm, identity, fixturePassword); err != nil {
			return err
		}
		_, err = tx.Put(ctx, "identities", identity)
		return err
	}))
}

func (f *orgFixture) signIn(email string) core.CredentialInput {
	f.t.Helper()
	result := f.record(f.iam.Auth.SignIn(f.ctx, obj("tenantId", f.tenantID, "email", email, "password", fixturePassword)))
	token, isText := result.Get("token").(string)
	if !isText {
		f.t.Fatalf("sign-in did not answer a session: %s", show(result))
	}
	return core.CredentialInput{Token: token}
}

// member creates a person `{name}@acme.test` with a password, as the owner.
func (f *orgFixture) member(name string) *core.Object {
	f.t.Helper()
	return f.record(f.iam.API.Identities.Create(f.ctx, f.owner, server.Input[apitypes.IdentitiesCreateInput](obj(
		"tenantId", f.tenantID, "email", name+"@acme.test", "name", name, "password", fixturePassword,
	))))
}

// hostConfig is `{ ...iam.protocolHost }` for the SCIM service.
func hostConfig(iam *server.BetterIam) Config {
	host := iam.ProtocolHost.(*server.ProtocolHost)
	return Config{
		Store:     host.Store,
		Authorize: host.Authorize,
		Authenticate: func(ctx context.Context, credential core.CredentialInput) (string, error) {
			principal, err := host.Authenticate(ctx, credential)
			if err != nil {
				return "", err
			}
			return jsString(principal.Identity.Get("id")), nil
		},
		ValidateIdentityAttributes: func(attributes *core.Object) (*core.Object, error) {
			return host.ValidateIdentityAttributes(attributes)
		},
		RecordAudit: host.RecordAudit,
		SyncRoleMappings: func(ctx context.Context, tx core.IamStore, input RoleMappingInput) error {
			return host.SyncRoleMappings(ctx, tx, server.RoleMappingSync{
				TenantID: input.TenantID, ConnectionID: input.ConnectionID, GroupID: input.GroupID,
				IdentityIDs: input.IdentityIDs, RoleIDs: input.RoleIDs, Credential: input.Credential,
			})
		},
		IdentityStatusChanged: func(ctx context.Context, tx core.IamStore, input IdentityStatusChange) error {
			return host.IdentityStatusChanged(ctx, tx, input.TenantID, input.ConnectionID, input.IdentityID)
		},
		GroupDeleted: func(ctx context.Context, tx core.IamStore, input GroupDeletion) error {
			return host.GroupDeleted(ctx, tx, input.TenantID, input.ConnectionID, input.GroupID)
		},
	}
}

// hostProvisioning is `{ ...iam.protocolHost }` for the outbound provisioner.
func hostProvisioning(iam *server.BetterIam) ProvisioningConfig {
	config := hostConfig(iam)
	return ProvisioningConfig{Store: config.Store, Authorize: config.Authorize, Authenticate: config.Authenticate, RecordAudit: config.RecordAudit}
}

// directory is a SCIM connection of the fixture's organization.
type directory struct {
	*orgFixture
	service    *Service
	connection connectionCredential
}

func newDirectory(t *testing.T, mutate func(config *Config)) *directory {
	t.Helper()
	f := newOrgFixture(t)
	config := hostConfig(f.iam)
	if mutate != nil {
		mutate(&config)
	}
	service := must(NewService(config))
	connection := credentialOf(f.record(service.CreateConnection(f.ctx, f.owner, CreateConnectionInput{TenantID: f.tenantID, Name: "Directory"})))
	return &directory{orgFixture: f, service: service, connection: connection}
}

func (d *directory) request(resource, method string, body any) answer {
	d.t.Helper()
	return scimCall(d.t, d.service, "https://iam.test", d.connection, resource, method, body, nil)
}

func (d *directory) create(user *core.Object) string {
	d.t.Helper()
	created := d.request("Users", "POST", user)
	if created.status != 201 {
		d.t.Fatalf("create: %d %s", created.status, show(created.body))
	}
	return created.get("id").(string)
}

func (d *directory) put(id string, user *core.Object) answer {
	d.t.Helper()
	response := d.request("Users/"+id, "PUT", user)
	if response.status != 200 {
		d.t.Fatalf("put: %d %s", response.status, show(response.body))
	}
	return response
}

func (d *directory) patch(id string, operations ...*core.Object) answer {
	d.t.Helper()
	response := d.request("Users/"+id, "PATCH", patchOp(operations...))
	if response.status != 200 {
		d.t.Fatalf("patch: %d %s", response.status, show(response.body))
	}
	return response
}

// identityOf is the local identity behind a SCIM user.
func (d *directory) identityOf(id string) *core.Object {
	d.t.Helper()
	link := get(d.t, d.store, "scimUsers", id)
	return get(d.t, d.store, "identities", jsString(link.Get("identityId")))
}

func (d *directory) identityID(id string) string { return jsString(d.identityOf(id).Get("id")) }

func (d *directory) managerOf(id string) any { return d.identityOf(id).Get("managerId") }

func managedBy(id string) *core.Object {
	return obj(EnterpriseSchema, obj("manager", obj("value", id)))
}

func withUser(base *core.Object, extra ...*core.Object) *core.Object {
	return base.Spread(extra...)
}

// record unwraps an answer that is one record (a *core.Object, or a server.Out holding one): another unit's
// NOT_IMPLEMENTED stub skips the rest of the test, any other error fails it.
func (f *orgFixture) record(value any, err error) *core.Object {
	f.t.Helper()
	requirePorted(f.t, err)
	result := value
	switch out := value.(type) {
	case server.Out[apitypes.IdentitiesCreateOutput]:
		result = out.Value
	case server.Out[apitypes.RolesCreateOutput]:
		result = out.Value
	case server.Out[apitypes.TenantsCreateOutput]:
		result = out.Value
	}
	record, _ := result.(*core.Object)
	if record == nil {
		f.t.Fatalf("expected an object answer, got %T", result)
	}
	return record
}

// text unwraps a string answer.
func (f *orgFixture) text(value string, err error) string {
	f.t.Helper()
	requirePorted(f.t, err)
	return value
}
