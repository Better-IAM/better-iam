package server

// Test support for the webhooks, audit, domains, hostnames, reports, resources, and relationships API groups (after
// tests/support/organization.ts and the fixtures of tests/domains.test.ts, tests/custom-hostnames.test.ts,
// tests/reports.test.ts, and tests/relationships.test.ts). Organizations, people, roles, and bindings are seeded in the
// store the way tenants.create / acceptInvitation / identities.create / roles.create / bindings.create write them (those
// API groups are ported separately); the API groups under test are called through iam.API.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const directoryOrigin = "http://localhost:3000"

type directoryFixture struct {
	*iamFixture
	ctx         context.Context
	clock       atomic.Int64
	rootCred    core.CredentialInput
	authorities map[string]string
	mu          sync.Mutex
	dns         map[string][][]string
	lookups     []string
}

// newDirectoryFixture composes a server with a controllable clock and a scripted TXT resolver, and signs the root
// administrator in (with MFA).
func newDirectoryFixture(t *testing.T, mutate func(options *BetterIamOptions)) *directoryFixture {
	t.Helper()
	f := &directoryFixture{ctx: context.Background(), authorities: map[string]string{}, dns: map[string][][]string{}}
	f.clock.Store(1_790_000_000_000)
	now := func() int64 { return f.clock.Load() }
	f.iamFixture = newIam(t, directoryOrigin, func(options *BetterIamOptions) {
		options.WallClock = now
		options.Authentication = &auth.Options{Now: now}
		options.Domains = &DomainOptions{ResolveTxt: func(ctx context.Context, hostname string) ([][]string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.lookups = append(f.lookups, hostname)
			records, ok := f.dns[hostname]
			if !ok {
				return nil, errors.New("ENOTFOUND")
			}
			return records, nil
		}}
		if mutate != nil {
			mutate(options)
		}
	})
	root, err := f.iam.Store.Get(f.ctx, "identities", jsString(member(f.root.Get("identity"), "id")))
	if err != nil {
		t.Fatal(err)
	}
	f.rootCred = f.issue(root, true)
	authorities, err := f.iam.Store.Find(f.ctx, "grantAuthorities", core.NewObject("tenantId", f.rootTenantID()), nil)
	if err != nil || len(authorities) == 0 {
		t.Fatalf("root authority: %v", err)
	}
	f.authorities[f.rootTenantID()] = jsString(authorities[0].Get("id"))
	return f
}

func (f *directoryFixture) advance(ms int64) { f.clock.Add(ms) }

func (f *directoryFixture) now() float64 { return float64(f.clock.Load()) }

func (f *directoryFixture) setDNS(name string, records ...[]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dns[name] = records
}

func (f *directoryFixture) lookupCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.lookups)
}

// transact runs fn in a transaction, failing the test on an error.
func (f *directoryFixture) transact(fn func(ctx context.Context, tx core.IamStore) error) {
	f.t.Helper()
	if err := f.iam.Store.Transaction(f.ctx, fn); err != nil {
		f.t.Fatal(err)
	}
}

// seed writes records (inserting new ones, replacing existing ones).
func (f *directoryFixture) seed(collection string, records ...*core.Object) {
	f.t.Helper()
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		for _, record := range records {
			existing, err := tx.Get(ctx, collection, jsString(record.Get("id")))
			if err != nil {
				return err
			}
			if existing == nil {
				_, err = tx.Insert(ctx, collection, record)
			} else {
				_, err = tx.Put(ctx, collection, record)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// patch merges members into a stored record.
func (f *directoryFixture) patch(collection, id string, members *core.Object) {
	f.t.Helper()
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		record, err := tx.Get(ctx, collection, id)
		if err != nil {
			return err
		}
		_, err = tx.Put(ctx, collection, record.Spread(members))
		return err
	})
}

func (f *directoryFixture) record(collection, id string) *core.Object {
	f.t.Helper()
	record, err := f.iam.Store.Get(f.ctx, collection, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return record
}

func (f *directoryFixture) find(collection string, filter *core.Object) []*core.Object {
	f.t.Helper()
	records, err := f.iam.Store.Find(f.ctx, collection, filter, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return records
}

// issue signs an identity in and returns its credential.
func (f *directoryFixture) issue(identity *core.Object, mfa bool) core.CredentialInput {
	f.t.Helper()
	issued, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.IssueSession(ctx, tx, identity, auth.IssueSessionOptions{Mfa: mfa, Method: "password"})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return core.CredentialInput{Token: jsString(issued.Get("token"))}
}

// organization seeds an active organization under the root with an owner (as an accepted owner invitation leaves
// it) and returns its ID and the owner's credential.
func (f *directoryFixture) organization(name, ownerEmail string, members ...any) (string, core.CredentialInput) {
	f.t.Helper()
	tenantID := ID()
	realm := core.NewObject("id", tenantID, "tenantId", tenantID, "name", name, "type", "organization",
		"parentId", f.rootTenantID(), "status", "active", "createdAt", f.now())
	for index := 0; index+1 < len(members); index += 2 {
		realm.Set(members[index].(string), members[index+1])
	}
	var owner *core.Object
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		if _, err := tx.Insert(ctx, "tenants", realm); err != nil {
			return err
		}
		identity, err := f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: tenantID, Email: ownerEmail, Name: "Owner", Password: "a strong tenant owner password",
			HasPassword: true, Owner: true, EmailVerified: true,
		})
		if err != nil {
			return err
		}
		authority, err := tx.Insert(ctx, "grantAuthorities", core.NewObject(
			"id", ID(), "tenantId", tenantID, "identityId", identity.Get("id"), "ceiling", All(), "revoked", false,
		))
		if err != nil {
			return err
		}
		f.authorities[tenantID] = jsString(authority.Get("id"))
		owner = identity
		return f.iam.Context.OwnerSetup(ctx, tx, realm, identity, authority)
	})
	return tenantID, f.issue(owner, false)
}

// person creates a member of a tenant and signs it in.
func (f *directoryFixture) person(tenantID, name string, members ...any) (*core.Object, core.CredentialInput) {
	f.t.Helper()
	var identity *core.Object
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		created, err := f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: tenantID, Email: name + "@acme.test", Name: name, Password: "a strong " + name + " password",
			HasPassword: true, EmailVerified: true,
		})
		if err != nil {
			return err
		}
		if len(members) > 0 {
			patched := created.Spread()
			for index := 0; index+1 < len(members); index += 2 {
				patched.Set(members[index].(string), members[index+1])
			}
			if created, err = tx.Put(ctx, "identities", patched); err != nil {
				return err
			}
		}
		identity = created
		return nil
	})
	return identity, f.issue(identity, false)
}

// role seeds a policy and a role holding its statements (as roles.create writes them) and returns the role ID.
func (f *directoryFixture) role(tenantID, name string, statements ...*core.Object) string {
	f.t.Helper()
	policyID, roleID := ID(), ID()
	list := make([]any, len(statements))
	for index, statement := range statements {
		list[index] = statement
	}
	authority := f.authorities[tenantID]
	f.seed("policies", core.NewObject("id", policyID, "tenantId", tenantID, "name", name, "document",
		core.NewObject("version", 1.0, "statements", list), "version", 1.0, "authorityId", authority))
	f.seed("roles", core.NewObject("id", roleID, "tenantId", tenantID, "name", name, "policyIds", []any{policyID},
		"authorityId", authority))
	return roleID
}

// bind seeds a binding of a role to a subject under the tenant owner's authority and returns its ID.
func (f *directoryFixture) bind(tenantID, roleID, subjectType, subjectID string, members ...any) string {
	f.t.Helper()
	bindingID := ID()
	binding := core.NewObject("id", bindingID, "tenantId", tenantID, "subjectType", subjectType, "subjectId", subjectID,
		"roleId", roleID, "authorityId", f.authorities[tenantID], "createdAt", f.now())
	for index := 0; index+1 < len(members); index += 2 {
		binding.Set(members[index].(string), members[index+1])
	}
	f.seed("bindings", binding)
	return bindingID
}

// allow is an allow statement over actions and resources.
func allow(actions, resources []any, extra ...any) *core.Object {
	statement := core.NewObject("effect", "allow", "actions", actions, "resources", resources)
	for index := 0; index+1 < len(extra); index += 2 {
		statement.Set(extra[index].(string), extra[index+1])
	}
	return statement
}

func items(values ...any) []any { return values }

// answer returns the model value of an API answer; an error panics, which fails the test with its stack (like must).
func answer[T any](out Out[T], err error) any {
	if err != nil {
		panic(fmt.Sprintf("unexpected error: %v", err))
	}
	return out.Value
}

// answerObject is answer for an object answer.
func answerObject[T any](out Out[T], err error) *core.Object {
	object, ok := answer(out, err).(*core.Object)
	if !ok {
		panic(fmt.Sprintf("answer is not an object: %#v", out.Value))
	}
	return object
}

// answerList is answer for a list answer.
func answerList[T any](out Out[T], err error) []*core.Object {
	list, ok := answer(out, err).([]any)
	if !ok {
		panic(fmt.Sprintf("answer is not a list: %#v", out.Value))
	}
	objects := make([]*core.Object, len(list))
	for index, item := range list {
		objects[index], _ = item.(*core.Object)
	}
	return objects
}

// expectStatus expects an IamError with the HTTP status.
func expectStatus(t *testing.T, err error, status int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected status %d, got no error", status)
	}
	if known := iamError(t, err); known.Status != status {
		t.Fatalf("expected status %d, got %d %s %q", status, known.Status, known.Code, known.Message)
	}
}

// pluck is the member of every object, as strings.
func pluck(objects []*core.Object, key string) []string {
	values := make([]string, len(objects))
	for index, object := range objects {
		values[index] = jsString(object.Get(key))
	}
	return values
}

// stringify is JSON.stringify of a model value.
func stringify(value any) string {
	text, _, _ := core.Stringify(value)
	return text
}

// body is a request body.
func body(pairs ...any) *core.Object { return core.NewObject(pairs...) }

// ownerSignIn issues a fresh session for the tenant's owner (sessions end while the test clock moves on).
func (f *directoryFixture) ownerSignIn(tenantID string) core.CredentialInput {
	f.t.Helper()
	owners := f.find("identities", core.NewObject("tenantId", tenantID, "owner", true))
	if len(owners) == 0 {
		f.t.Fatalf("no owner in %s", tenantID)
	}
	return f.issue(owners[0], false)
}
