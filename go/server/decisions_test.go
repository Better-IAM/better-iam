package server

// Decision engine, operation envelope and principal tests, after tests/access.test.ts, tests/server.test.ts and
// tests/server-security.test.ts: grant paths, ceilings, lapsed authorities, groups, relationships, context keys,
// impersonation, the audit records of the operation envelope, batch and reverse queries, and credential resolution.
// The records are seeded directly in the store (the API groups that write them are ported separately).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

type decisionFixture struct {
	*iamFixture
	tenantID  string
	authority string
}

func newDecisionFixture(t *testing.T, mutate func(options *BetterIamOptions)) *decisionFixture {
	t.Helper()
	f := newIam(t, "http://localhost:3000", func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{
			Actions: []string{"documents:read", "documents:write", "documents:share"},
			ResourceTypes: []core.NamedResourceType{{Name: "project", Definition: core.ResourceTypeDefinition{
				Actions: []string{"documents:read"}, Managed: true, Relations: []string{"viewer"},
				Attributes: []core.NamedAttribute{{Name: "region", Type: "string"}},
			}}},
		}
		options.ResolveResource = func(ctx context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			attributes := core.NewObject("ownerId", "alice")
			if strings.HasPrefix(reference.ID, "secret") {
				attributes.Set("classified", true)
			}
			return &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID, Attributes: attributes}, nil
		}
		if mutate != nil {
			mutate(options)
		}
	})
	fixture := &decisionFixture{iamFixture: f, tenantID: f.rootTenantID(), authority: "authority-1"}
	fixture.seed("grantAuthorities", core.NewObject("id", "authority-1", "tenantId", fixture.tenantID, "identityId", "owner", "ceiling", All(), "revoked", false))
	return fixture
}

func (f *decisionFixture) seed(collection string, records ...*core.Object) {
	f.t.Helper()
	err := f.iam.Store.Transaction(context.Background(), func(ctx context.Context, tx core.IamStore) error {
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
	if err != nil {
		f.t.Fatal(err)
	}
}

func allowStatement(actions, resources string, extra ...any) *core.Object {
	statement := core.NewObject("effect", "allow", "actions", []any{actions}, "resources", []any{resources})
	for index := 0; index+1 < len(extra); index += 2 {
		statement.Set(extra[index].(string), extra[index+1])
	}
	return statement
}

func document(statements ...*core.Object) *core.Object {
	list := make([]any, len(statements))
	for index, statement := range statements {
		list[index] = statement
	}
	return core.NewObject("version", 1.0, "statements", list)
}

// grant binds a role holding document to a subject under the fixture's authority.
func (f *decisionFixture) grant(id, subjectType, subjectID string, doc *core.Object) {
	f.seed("policies", core.NewObject("id", "policy-"+id, "tenantId", f.tenantID, "name", "P "+id, "document", doc, "version", 1.0, "authorityId", f.authority))
	f.seed("roles", core.NewObject("id", "role-"+id, "tenantId", f.tenantID, "name", "R "+id, "policyIds", []any{"policy-" + id}, "authorityId", f.authority))
	f.seed("bindings", core.NewObject("id", "binding-"+id, "tenantId", f.tenantID, "subjectType", subjectType, "subjectId", subjectID, "roleId", "role-"+id, "authorityId", f.authority))
}

// signIn issues a user session for an identity and returns its token.
func (f *decisionFixture) signIn(identity *core.Object, mfa bool) string {
	f.t.Helper()
	issued, err := core.Transact(context.Background(), f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.IssueSession(ctx, tx, identity, auth.IssueSessionOptions{Mfa: mfa, Method: "password"})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return jsString(issued.Get("token"))
}

func (f *decisionFixture) authorize(token, action, resourceType, id string) core.Decision {
	f.t.Helper()
	decision, err := f.iam.Authorize(context.Background(), AuthorizationRequest{
		Credential: core.CredentialInput{Token: token}, TenantID: f.tenantID, Action: action, Resource: ResourceTarget{Type: resourceType, ID: id},
	})
	if err != nil {
		f.t.Fatalf("authorize %s %s/%s: %v", action, resourceType, id, err)
	}
	return decision
}

func (f *decisionFixture) audits(action string) []*core.Object {
	f.t.Helper()
	events, err := f.iam.Store.Find(context.Background(), "audit", core.NewObject("action", action), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return events
}

func TestDecisionsGrantPathsCeilingsAndDenies(t *testing.T) {
	f := newDecisionFixture(t, nil)
	alice := f.createIdentity("alice@example.test", "alice", "a strong alice password")
	aliceID := jsString(alice.Get("id"))
	token := f.signIn(alice, false)
	if decision := f.authorize(token, "documents:read", "document", "readme"); decision.Allowed || decision.Reason != "ACCESS_DENIED" {
		t.Errorf("no grant: %+v", decision)
	}
	f.grant("reader", "identity", aliceID, document(allowStatement("documents:read", "document/*")))
	if decision := f.authorize(token, "documents:read", "document", "readme"); !decision.Allowed || decision.Reason != "allowed" {
		t.Errorf("granted read: %+v", decision)
	}
	if decision := f.authorize(token, "documents:write", "document", "readme"); decision.Allowed {
		t.Errorf("write without a grant: %+v", decision)
	}
	// An action the catalog does not know is refused before the resource is resolved.
	if decision, err := f.iam.Context.Decisions.Decide(context.Background(), f.iam.Store, f.principal(token), AuthorizationRequest{TenantID: f.tenantID, Action: "documents:fly", Resource: ResourceTarget{Type: "document", ID: "x"}}, false); err != nil || decision.Reason != "UNKNOWN_ACTION" {
		t.Errorf("unknown action: %+v %v", decision, err)
	}
	// A deny in any path applies across paths; conditions see the resolver's attributes.
	f.grant("deny", "identity", aliceID, document(core.NewObject("effect", "deny", "actions", []any{"documents:read"}, "resources", []any{"document/*"},
		"conditions", core.NewObject("Bool", core.NewObject("resource.classified", true)))))
	if decision := f.authorize(token, "documents:read", "document", "secret-plan"); decision.Allowed {
		t.Errorf("denied classified: %+v", decision)
	}
	if decision := f.authorize(token, "documents:read", "document", "readme"); !decision.Allowed {
		t.Errorf("deny should only touch classified: %+v", decision)
	}
	// A tenant boundary is a ceiling over every grant.
	root, err := f.iam.Store.Get(context.Background(), "tenants", f.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	f.seed("tenants", root.Spread(core.NewObject("boundary", document(allowStatement("documents:write", "*")))))
	if decision := f.authorize(token, "documents:read", "document", "readme"); decision.Allowed {
		t.Errorf("boundary should cap read: %+v", decision)
	}
	f.seed("tenants", root)
	// A revoked authority takes away what it granted, never what it forbade.
	f.seed("grantAuthorities", core.NewObject("id", "authority-1", "tenantId", f.tenantID, "identityId", "owner", "ceiling", All(), "revoked", true))
	if decision := f.authorize(token, "documents:read", "document", "readme"); decision.Allowed {
		t.Errorf("revoked authority still grants: %+v", decision)
	}
	current := f.principal(token)
	prepared, err := core.Transact(context.Background(), f.iam.Store, func(ctx context.Context, tx core.IamStore) (*PreparedDecision, error) {
		return f.iam.Context.Decisions.PrepareDecision(ctx, tx, current, root, "documents:read")
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Inputs.Paths) != 1 || len(prepared.Inputs.Paths[0].Boundaries) != 0 {
		t.Errorf("lapsed denies should remain as one deny-only path: %+v", prepared.Inputs.Paths)
	}
	// Refusals are audited as deny events of the action; allows of ordinary grants are not.
	if denies := f.audits("documents:read"); len(denies) == 0 || denies[len(denies)-1].Get("outcome") != "deny" {
		t.Errorf("deny audit: %v", denies)
	}
}

func (f *decisionFixture) principal(token string) *Principal {
	f.t.Helper()
	principal, err := f.iam.Authenticate(context.Background(), core.CredentialInput{Token: token})
	if err != nil {
		f.t.Fatal(err)
	}
	return principal
}

func TestDecisionsGroupsRelationshipsAndContextKeys(t *testing.T) {
	f := newDecisionFixture(t, nil)
	alice := f.createIdentity("alice@example.test", "alice", "a strong alice password")
	aliceID := jsString(alice.Get("id"))
	token := f.signIn(alice, false)
	// Through a live group membership; an expired one grants nothing.
	f.seed("groups", core.NewObject("id", "group-1", "tenantId", f.tenantID, "name", "Readers"))
	f.seed("groupMembers", core.NewObject("id", "member-1", "tenantId", f.tenantID, "groupId", "group-1", "identityId", aliceID))
	f.grant("group", "group", "group-1", document(allowStatement("documents:read", "document/*",
		"conditions", core.NewObject("ArrayContains", core.NewObject("principal.groups", "group-1")))))
	if decision := f.authorize(token, "documents:read", "document", "readme"); !decision.Allowed {
		t.Errorf("group grant: %+v", decision)
	}
	f.seed("groupMembers", core.NewObject("id", "member-1", "tenantId", f.tenantID, "groupId", "group-1", "identityId", aliceID, "expiresAt", 1.0))
	if decision := f.authorize(token, "documents:read", "document", "readme"); decision.Allowed {
		t.Errorf("expired membership still grants: %+v", decision)
	}
	// Relationships: a held relation on the resource satisfies a resource.relations condition.
	f.grant("relation", "identity", aliceID, document(allowStatement("documents:share", "document/*",
		"conditions", core.NewObject("ArrayContains", core.NewObject("resource.relations", "editor")))))
	if decision := f.authorize(token, "documents:share", "document", "plan"); decision.Allowed {
		t.Errorf("share without the relation: %+v", decision)
	}
	f.seed("relationships", core.NewObject("id", "tuple-1", "tenantId", f.tenantID, "type", "document", "resourceId", "plan",
		"relation", "editor", "subjectType", "identity", "subjectId", aliceID))
	if decision := f.authorize(token, "documents:share", "document", "plan"); !decision.Allowed {
		t.Errorf("share with the relation: %+v", decision)
	}
	// Server-derived context keys win over identity attributes; a session's request time and kind are present.
	current := f.principal(token)
	prepared, err := core.Transact(context.Background(), f.iam.Store, func(ctx context.Context, tx core.IamStore) (*PreparedDecision, error) {
		root, err := f.iam.Context.Tenant(ctx, tx, f.tenantID)
		if err != nil {
			return nil, err
		}
		return f.iam.Context.Decisions.PrepareDecision(ctx, tx, current, root, "documents:read")
	})
	if err != nil {
		t.Fatal(err)
	}
	context := prepared.Inputs.Context
	for key, want := range map[string]any{
		"principal.id": aliceID, "principal.kind": "user", "principal.sessionKind": "user", "principal.owner": false,
		"principal.rootAdmin": false, "principal.impersonated": false, "principal.delegated": false, "principal.guest": false,
		"principal.pendingAgreements": 0.0, "principal.authMethod": "password",
	} {
		if got := context.Get(key); got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
	for _, key := range []string{"request.time", "principal.sessionId", "principal.tokenIssueTime", "principal.authTime"} {
		if _, ok := context.Get(key).(string); !ok {
			t.Errorf("%s missing: %v", key, context.Get(key))
		}
	}
	if roles, _ := context.Get("principal.roles").([]any); len(roles) != 1 || roles[0] != "role-relation" {
		t.Errorf("principal.roles = %v", context.Get("principal.roles"))
	}
}

func TestDecisionsRootTenantStateAndImpersonation(t *testing.T) {
	f := newDecisionFixture(t, nil)
	ownerID := jsString(member(f.root.Get("identity"), "id"))
	owner, err := f.iam.Store.Get(context.Background(), "identities", ownerID)
	if err != nil {
		t.Fatal(err)
	}
	// The root administrator is root only in an MFA user session (and cannot sign in without one).
	if _, err := core.Transact(context.Background(), f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.IssueSession(ctx, tx, owner, auth.IssueSessionOptions{})
	}); err == nil || !strings.Contains(err.Error(), "Multi-factor") {
		t.Errorf("root session without MFA: %v", err)
	}
	withMfa := f.signIn(owner, true)
	if decision := f.authorize(withMfa, "documents:read", "document", "x"); !decision.Allowed || decision.Reason != "ROOT_OVERRIDE" {
		t.Errorf("root override: %+v", decision)
	}
	if overrides := f.audits("documents:read"); len(overrides) == 0 || overrides[len(overrides)-1].Get("rootOverride") != true {
		t.Errorf("root overrides are audited: %v", overrides)
	}
	// Another tenant's session is refused before the target is read; its record goes to the caller's tenant.
	f.seed("tenants", core.NewObject("id", "other", "tenantId", "other", "name", "Other", "type", "organization", "parentId", f.tenantID, "status", "active", "createdAt", 1.0))
	alice := f.createIdentity("alice@example.test", "alice", "a strong alice password")
	token := f.signIn(alice, false)
	decision, err := f.iam.Authorize(context.Background(), AuthorizationRequest{Credential: core.CredentialInput{Token: token}, TenantID: "other", Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "x"}})
	if err != nil || decision.Allowed || decision.Reason != "ACCESS_DENIED" {
		t.Errorf("other tenant: %+v %v", decision, err)
	}
	refusals := f.audits("documents:read")
	if last := refusals[len(refusals)-1]; last.Get("tenantId") != f.tenantID || member(last.Get("metadata"), "targetTenantId") != "other" {
		t.Errorf("mismatch audit: %v", core.MustStringify(last))
	}
	// An inactive tenant decides nothing.
	f.seed("tenants", core.NewObject("id", "other", "tenantId", "other", "name", "Other", "type", "organization", "parentId", f.tenantID, "status", "suspended", "createdAt", 1.0))
	current := f.principal(token)
	prepared, err := core.Transact(context.Background(), f.iam.Store, func(ctx context.Context, tx core.IamStore) (*PreparedDecision, error) {
		other, err := f.iam.Context.Tenant(ctx, tx, "other")
		if err != nil {
			return nil, err
		}
		return f.iam.Context.Decisions.PrepareDecision(ctx, tx, current, other, "documents:read")
	})
	if err != nil || prepared.Fixed == nil || prepared.Fixed.Reason != "TENANT_INACTIVE" {
		t.Errorf("inactive tenant: %+v %v", prepared, err)
	}
	// "View as" never exceeds the administrator behind it.
	aliceID := jsString(alice.Get("id"))
	f.grant("alice", "identity", aliceID, document(allowStatement("documents:read", "document/*")))
	bob := f.createIdentity("bob@example.test", "bob", "a strong bob password")
	bobToken := f.signIn(bob, false)
	bobPrincipal := f.principal(bobToken)
	root, _ := f.iam.Store.Get(context.Background(), "tenants", f.tenantID)
	f.seed("tenants", root.Spread(core.NewObject("authPolicy", core.NewObject("allowImpersonation", true))))
	impersonation, err := core.Transact(context.Background(), f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.IssueImpersonationSession(ctx, tx, bobPrincipal.Auth(), alice, 600_000)
	})
	if err != nil {
		t.Fatal(err)
	}
	viewAs := jsString(impersonation.Get("token"))
	if decision := f.authorize(viewAs, "documents:read", "document", "x"); decision.Allowed {
		t.Errorf("view-as beyond the administrator: %+v", decision)
	}
	viewer := f.principal(viewAs)
	direct, err := core.Transact(context.Background(), f.iam.Store, func(ctx context.Context, tx core.IamStore) (core.Decision, error) {
		return f.iam.Context.Decisions.Decide(ctx, tx, viewer, AuthorizationRequest{TenantID: f.tenantID, Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "x"}}, false)
	})
	if err != nil || direct.Reason != "IMPERSONATOR_DENIED" {
		t.Errorf("impersonator denied: %+v %v", direct, err)
	}
}

func TestOperationEnvelopeAuditsAndRefuses(t *testing.T) {
	f := newDecisionFixture(t, func(options *BetterIamOptions) { options.AccessUsage = On[AccessUsageOptions]() })
	alice := f.createIdentity("alice@example.test", "alice", "a strong alice password")
	aliceID := jsString(alice.Get("id"))
	token := f.signIn(alice, false)
	credential := core.CredentialInput{Token: token}
	ctx := context.Background()
	ran := false
	_, err := f.iam.Context.Operations.Operation(ctx, credential, f.tenantID, "iam:groups:create", f.tenantID, func(ctx context.Context, call MutationContext) (any, error) {
		ran = true
		return nil, nil
	}, false)
	var known *core.IamError
	if !errors.As(err, &known) || known.Code != "ACCESS_DENIED" || known.Status != 403 || ran {
		t.Errorf("denied operation: %v ran=%v", err, ran)
	}
	if denies := f.audits("iam:groups:create"); len(denies) != 1 || denies[0].Get("outcome") != "deny" || denies[0].Get("actorId") != aliceID {
		t.Errorf("deny audit: %v", denies)
	}
	f.grant("admin", "identity", aliceID, document(allowStatement("iam:groups:*", "iam/*")))
	value, err := f.iam.Context.Operations.Operation(ctx, credential, f.tenantID, "iam:groups:create", f.tenantID, func(ctx context.Context, call MutationContext) (any, error) {
		if call.Tenant.Get("id") != f.tenantID || call.Principal.Identity.Get("id") != aliceID {
			t.Errorf("mutation context: %v %v", call.Tenant, call.Principal.Identity)
		}
		return "created", nil
	}, false)
	if err != nil || value != "created" {
		t.Fatalf("allowed operation: %v %v", value, err)
	}
	if allows := f.audits("iam:groups:create"); len(allows) != 2 || allows[0].Get("outcome") == allows[1].Get("outcome") || truthy(allows[0].Get("rootOverride")) || truthy(allows[1].Get("rootOverride")) {
		t.Errorf("allow audit: %v", allows)
	}
	// A mutation's OperationDenied rolls back and is recorded as a deny in its own transaction.
	_, err = f.iam.Context.Operations.Operation(ctx, credential, f.tenantID, "iam:groups:update", "group-x", func(ctx context.Context, call MutationContext) (any, error) {
		if _, err := call.Tx.Insert(ctx, "groups", core.NewObject("id", "group-x", "tenantId", f.tenantID, "name", "X")); err != nil {
			return nil, err
		}
		return nil, NewOperationDenied("This group is protected")
	}, false)
	if !errors.As(err, &known) || known.Message != "This group is protected" {
		t.Errorf("OperationDenied: %v", err)
	}
	if group, _ := f.iam.Store.Get(ctx, "groups", "group-x"); group != nil {
		t.Error("the refused mutation was not rolled back")
	}
	if denies := f.audits("iam:groups:update"); len(denies) != 1 || denies[0].Get("outcome") != "deny" {
		t.Errorf("OperationDenied audit: %v", denies)
	}
	// Root-only operations refuse everyone else.
	if _, err := f.iam.Context.Operations.Operation(ctx, credential, f.tenantID, "iam:groups:create", f.tenantID, func(context.Context, MutationContext) (any, error) { return nil, nil }, true); !errors.As(err, &known) || known.Code != "ACCESS_DENIED" {
		t.Errorf("root-only: %v", err)
	}
	// An invalid tenant ID is validated where TypeScript validates it.
	if _, err := f.iam.Context.Operations.Operation(ctx, credential, core.Undefined, "iam:groups:create", "x", func(context.Context, MutationContext) (any, error) { return nil, nil }, false); !errors.As(err, &known) || known.Code != "INVALID_INPUT" {
		t.Errorf("undefined tenant: %v", err)
	}
	// Allowed uses are counted after the commit.
	written, err := f.iam.Context.Usage.Flush(ctx)
	if err != nil || written == 0 {
		t.Errorf("usage flush: %d %v", written, err)
	}
	usage, _ := f.iam.Store.Get(ctx, "accessUsage", UsageRecordID(f.tenantID, aliceID, "iam:groups:create"))
	if usage == nil || usage.Get("count") != 1.0 {
		t.Errorf("usage record: %v", usage)
	}
}

func TestAuthorizeManyAndListAccessible(t *testing.T) {
	f := newDecisionFixture(t, nil)
	alice := f.createIdentity("alice@example.test", "alice", "a strong alice password")
	aliceID := jsString(alice.Get("id"))
	token := f.signIn(alice, false)
	credential := core.CredentialInput{Token: token}
	ctx := context.Background()
	var known *core.IamError
	for _, checks := range []any{core.Undefined, []any{}, make([]any, 51)} {
		_, err := f.iam.Context.Operations.AuthorizeMany(ctx, BatchAuthorizationRequest{Credential: credential, TenantID: f.tenantID, ChecksValue: checks})
		if !errors.As(err, &known) || known.Message != "Provide 1-50 authorization checks" {
			t.Errorf("checks %v: %v", checks, err)
		}
	}
	f.grant("reader", "identity", aliceID, document(allowStatement("documents:read", "document/a*"), allowStatement("documents:read", "project/*",
		"conditions", core.NewObject("StringEquals", core.NewObject("resource.region", "eu")))))
	results, err := f.iam.AuthorizeMany(ctx, BatchAuthorizationRequest{Credential: credential, TenantID: f.tenantID, Checks: []AuthorizationCheck{
		{Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "alpha"}},
		{Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "beta"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if text := core.MustStringify(results); text != `{"results":[{"action":"documents:read","resource":{"type":"document","id":"alpha"},"allowed":true,"reason":"allowed"},{"action":"documents:read","resource":{"type":"document","id":"beta"},"allowed":false,"reason":"ACCESS_DENIED"}]}` {
		t.Errorf("authorizeMany = %s", text)
	}
	// The reverse query over registered resources of a managed type, sorted by key, paged.
	for index, region := range []string{"eu", "us", "eu"} {
		id := string(rune('c' - index))
		f.seed("resources", core.NewObject("id", "resource-"+id, "tenantId", f.tenantID, "type", "project", "resourceId", id,
			"uniqueKey", "project/"+id, "attributes", core.NewObject("region", region)))
	}
	listed, err := f.iam.ListAccessible(ctx, AccessibleResourcesRequest{Credential: credential, TenantID: f.tenantID, Action: "documents:read", Type: "project"})
	if err != nil {
		t.Fatal(err)
	}
	resources, _ := listed.Get("resources").([]any)
	if listed.Get("total") != 2.0 || len(resources) != 2 || member(resources[0], "resourceId") != "a" || member(resources[1], "resourceId") != "c" {
		t.Errorf("listAccessible = %s", core.MustStringify(listed))
	}
	paged, err := f.iam.ListAccessible(ctx, AccessibleResourcesRequest{Credential: credential, TenantID: f.tenantID, Action: "documents:read", Type: "project", LimitValue: 1.0, OffsetValue: 1.0})
	if err != nil || paged.Get("total") != 2.0 || len(paged.Get("resources").([]any)) != 1 {
		t.Errorf("paged: %v %v", paged, err)
	}
	if _, err := f.iam.ListAccessible(ctx, AccessibleResourcesRequest{Credential: credential, TenantID: f.tenantID, Action: "documents:fly", Type: "project"}); !errors.As(err, &known) || known.Code != "INVALID_ACTION" {
		t.Errorf("unknown action: %v", err)
	}
	if _, err := f.iam.ListAccessible(ctx, AccessibleResourcesRequest{Credential: credential, TenantID: f.tenantID, Action: "documents:read", Type: "document"}); !errors.As(err, &known) || known.Code != "INVALID_RESOURCE_TYPE" {
		t.Errorf("unmanaged type: %v", err)
	}
	if _, err := f.iam.ListAccessible(ctx, AccessibleResourcesRequest{Credential: credential, TenantID: f.tenantID, Action: "documents:read", Type: "project", LimitValue: 0.0}); !errors.As(err, &known) || known.Code != "INVALID_INPUT" {
		t.Errorf("limit 0: %v", err)
	}
}

func TestPrincipalsResolveApiKeysAndRevocations(t *testing.T) {
	f := newDecisionFixture(t, nil)
	ctx := context.Background()
	f.seed("identities", core.NewObject("id", "svc", "tenantId", f.tenantID, "kind", "service", "name", "Robot", "status", "active", "createdAt", 1.0))
	key := "biam_key_" // a prefixed token needs its checksum: use an opaque legacy token instead
	_ = key
	token := Token() + Token()[:10]
	f.seed("sessions", core.NewObject("id", "key-1", "tenantId", f.tenantID, "identityId", "svc", "kind", "api-key", "tokenHash", Hash(token),
		"createdAt", 1.0, "lastSeenAt", 1.0, "authenticatedAt", 1.0, "expiresAt", 9e15, "mfa", false, "credentialAuthorityId", f.authority))
	principal, err := f.iam.Authenticate(ctx, core.CredentialInput{Token: token})
	if err != nil {
		t.Fatalf("api key: %v", err)
	}
	if principal.Session.Get("kind") != "api-key" || principal.Identity.Get("id") != "svc" {
		t.Errorf("api key principal: %v", principal.Session)
	}
	// Using a key records when it was last used.
	if session, _ := f.iam.Store.Get(ctx, "sessions", "key-1"); jsNumber(session.Get("lastSeenAt")) <= 1 {
		t.Errorf("lastSeenAt not recorded: %v", session.Get("lastSeenAt"))
	}
	// A bearer header works the same; a malformed one never reaches storage.
	if _, err := f.iam.Authenticate(ctx, core.CredentialInput{Headers: map[string][]string{"Authorization": {"bearer " + token}}}); err != nil {
		t.Errorf("bearer header: %v", err)
	}
	var known *core.IamError
	if _, err := f.iam.Authenticate(ctx, core.CredentialInput{Token: "biam_key_" + strings.Repeat("A", 49)}); !errors.As(err, &known) || known.Message != "Invalid credentials" {
		t.Errorf("bad prefixed token: %v", err)
	}
	// Revoking the issuing authority ends the key.
	f.seed("grantAuthorities", core.NewObject("id", "authority-1", "tenantId", f.tenantID, "identityId", "owner", "ceiling", All(), "revoked", true))
	if _, err := f.iam.Authenticate(ctx, core.CredentialInput{Token: token}); !errors.As(err, &known) || known.Message != "Service credential revoked" {
		t.Errorf("revoked authority: %v", err)
	}
	// A disabled identity and an expired key are refused.
	f.seed("grantAuthorities", core.NewObject("id", "authority-1", "tenantId", f.tenantID, "identityId", "owner", "ceiling", All(), "revoked", false))
	f.seed("identities", core.NewObject("id", "svc", "tenantId", f.tenantID, "kind", "service", "name", "Robot", "status", "disabled", "createdAt", 1.0))
	if _, err := f.iam.Authenticate(ctx, core.CredentialInput{Token: token}); !errors.As(err, &known) || known.Message != "Identity disabled" {
		t.Errorf("disabled identity: %v", err)
	}
	f.seed("identities", core.NewObject("id", "svc", "tenantId", f.tenantID, "kind", "service", "name", "Robot", "status", "active", "createdAt", 1.0))
	f.seed("sessions", core.NewObject("id", "key-1", "tenantId", f.tenantID, "identityId", "svc", "kind", "api-key", "tokenHash", Hash(token),
		"createdAt", 1.0, "lastSeenAt", 1.0, "authenticatedAt", 1.0, "expiresAt", 2.0, "mfa", false, "credentialAuthorityId", f.authority))
	if _, err := f.iam.Authenticate(ctx, core.CredentialInput{Token: token}); !errors.As(err, &known) || known.Message != "Credential expired or revoked" {
		t.Errorf("expired key: %v", err)
	}
	// User sessions are re-validated in the transaction: an inactive tenant refuses them.
	alice := f.createIdentity("alice@example.test", "alice", "a strong alice password")
	userToken := f.signIn(alice, false)
	root, _ := f.iam.Store.Get(ctx, "tenants", f.tenantID)
	f.seed("tenants", root.Spread(core.NewObject("status", "suspended")))
	userSession := f.mustSession(userToken)
	_, err = core.Transact(ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*Principal, error) {
		return f.iam.Context.Principals.CurrentPrincipal(ctx, tx, &Principal{Identity: alice, Session: userSession})
	})
	if !errors.As(err, &known) || known.Code != "TENANT_INACTIVE" {
		t.Errorf("inactive tenant: %v", err)
	}
}

func (f *decisionFixture) mustSession(token string) *core.Object {
	f.t.Helper()
	found, err := f.iam.Store.Find(context.Background(), "sessions", core.NewObject("tokenHash", Hash(token)), nil)
	if err != nil || len(found) == 0 {
		f.t.Fatalf("session for token: %v", err)
	}
	return found[0]
}

func TestFiltersPlanMirrorsDecisions(t *testing.T) {
	f := newDecisionFixture(t, nil)
	alice := f.createIdentity("alice@example.test", "alice", "a strong alice password")
	aliceID := jsString(alice.Get("id"))
	token := f.signIn(alice, false)
	f.grant("reader", "identity", aliceID, document(allowStatement("documents:read", "document/public-*")))
	plan, err := f.iam.PlanResources(context.Background(), PlanResourcesRequest{Credential: core.CredentialInput{Token: token}, TenantID: f.tenantID, Action: "documents:read", Type: "document"})
	if err != nil {
		t.Fatal(err)
	}
	if text := core.MustStringify(plan); !strings.Contains(text, `"kind":"conditional"`) || !strings.Contains(text, `"pattern":"public-*"`) {
		t.Errorf("plan = %s", text)
	}
	var known *core.IamError
	if _, err := f.iam.PlanResources(context.Background(), PlanResourcesRequest{Credential: core.CredentialInput{Token: token}, TenantID: f.tenantID, Action: "iam:groups:create", Type: "document"}); !errors.As(err, &known) || known.Message != "Plans cover application actions, not iam:* administration" {
		t.Errorf("iam action: %v", err)
	}
}
