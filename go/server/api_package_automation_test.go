package server

// Tests of api_package_automation.go at the module level: the reconciler's suspension of rules that no longer
// validate (recorded once per transition), the cleanup of issues of packages that are gone, the tenant selection and
// early exits, the rule view administrators see, and the preview's validation. The tests in
// tests/org-birthright.test.ts and tests/security-packages.test.ts drive these through the access package API, which
// belongs to another unit (api_packages.go); the paths that reach its helpers are covered there.

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func automationKernel(t *testing.T) *kernel {
	k := newKernel(t, nil)
	k.tenantTree()
	k.server.Catalog.IdentityAttributes = core.NewObject("department", "string")
	return k
}

func automationFind(t *testing.T, k *kernel, collection string, filter *core.Object) []*core.Object {
	t.Helper()
	found, err := k.store.Find(k.ctx, collection, filter, nil)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func automationPackage(id, name string, rule *core.Object) *core.Object {
	pkg := core.NewObject("id", id, "tenantId", "org", "name", name, "roleIds", []any{}, "groupIds", []any{}, "createdAt", 1.0)
	if rule != nil {
		pkg.Set("autoAssign", rule)
	}
	return pkg
}

func TestReconcileSuspendsInvalidRulesOncePerTransition(t *testing.T) {
	k := automationKernel(t)
	k.insert("identities", identity("usr_owner", "org"), identity("usr_a", "org", "attributes", core.NewObject("department", "eng")))
	rule := obj(t, `{"include":[{"StringEquals":{"principal.gone":"x"}}],"ownerId":"usr_owner","authorityId":"auth_1","revision":1,"updatedAt":1}`)
	k.insert("accessPackages", automationPackage("pkg_1", "Kit", rule))
	options := core.NewObject("tenantId", "org", "trigger", "schedule")
	result, err := ReconcilePackageRules(k.ctx, k.server, options)
	if err != nil {
		t.Fatal(err)
	}
	if got := core.MustStringify(result); got != `{"trigger":"schedule","assigned":0,"refreshed":0,"restored":0,"ending":0,"revoked":0,"stale":0,"failed":[],"suspended":[{"tenantId":"org","packageId":"pkg_1","reason":"invalid-rule","detail":"autoAssign.include[0]: unknown key principal.gone; use principal.id, principal.kind, principal.owner, identity.email, identity.emailDomain, identity.emailVerified, identity.managerId, identity.groups, identity.guest, identity.teams, identity.departments, identity.licenses, or principal.<declared attribute> (department)"}],"braked":[],"skipped":{"inactiveTenants":0,"failedTenants":[]},"truncated":false}` {
		t.Fatalf("result: %s", got)
	}
	issues := automationFind(t, k, "packageRuleIssues", core.NewObject("tenantId", "org"))
	if len(issues) != 1 {
		t.Fatalf("issues: %d", len(issues))
	}
	issue := issues[0]
	if issue.Get("uniqueKey") != "pkg_1:suspended" || issue.Get("kind") != "suspended" || issue.Get("code") != "invalid-rule" ||
		issue.Get("revision") != 1.0 || issue.Get("since") != float64(k.server.Now()) {
		t.Fatalf("issue: %s", core.MustStringify(issue))
	}
	audits := automationFind(t, k, "audit", core.NewObject("tenantId", "org", "action", "package:auto-suspended"))
	if len(audits) != 1 || audits[0].Get("outcome") != "deny" || audits[0].Get("actorId") != "deployment-operator" {
		t.Fatalf("audits: %v", audits)
	}
	metadata, _ := audits[0].Get("metadata").(*core.Object)
	if got := strings.Join(metadata.Keys(), ","); got != "trigger,packageId,packageName,reason,detail" {
		t.Fatalf("metadata members: %s", got)
	}
	// The same problem again: neither the table nor the audit log grows.
	k.advance(1000)
	if _, err := ReconcilePackageRules(k.ctx, k.server, options); err != nil {
		t.Fatal(err)
	}
	if audits := automationFind(t, k, "audit", core.NewObject("tenantId", "org", "action", "package:auto-suspended")); len(audits) != 1 {
		t.Fatalf("audits after a repeat: %d", len(audits))
	}
	if issues := automationFind(t, k, "packageRuleIssues", core.NewObject("tenantId", "org")); len(issues) != 1 || issues[0].Get("since") != issue.Get("since") {
		t.Fatalf("issues after a repeat: %v", issues)
	}
}

func TestReconcileForgetsIssuesOfPackagesThatAreGone(t *testing.T) {
	k := automationKernel(t)
	k.insert("identities", identity("usr_a", "org"))
	k.insert("accessPackages", automationPackage("pkg_plain", "Plain", nil))
	k.insert("packageRuleIssues",
		core.NewObject("id", "iss_gone", "tenantId", "org", "uniqueKey", "pkg_gone:suspended", "packageId", "pkg_gone", "kind", "suspended", "code", "owner-inactive", "message", "x", "revision", 1.0, "since", 1.0),
		core.NewObject("id", "iss_rule", "tenantId", "org", "uniqueKey", "pkg_plain:braked:grants", "packageId", "pkg_plain", "kind", "braked", "code", "grants", "message", "x", "revision", 1.0, "since", 1.0),
		core.NewObject("id", "iss_person", "tenantId", "org", "uniqueKey", "pkg_plain:identity:usr_gone", "packageId", "pkg_plain", "kind", "failed", "identityId", "usr_gone", "code", "ERROR", "message", "x", "revision", 1.0, "since", 1.0),
		core.NewObject("id", "iss_kept", "tenantId", "org", "uniqueKey", "pkg_plain:identity:usr_a", "packageId", "pkg_plain", "kind", "failed", "identityId", "usr_a", "code", "ERROR", "message", "x", "revision", 1.0, "since", 1.0),
	)
	// A scoped run keeps them all.
	if _, err := ReconcilePackageRules(k.ctx, k.server, core.NewObject("tenantId", "org", "trigger", "manual", "identityIds", []any{"usr_a"})); err != nil {
		t.Fatal(err)
	}
	if issues := automationFind(t, k, "packageRuleIssues", core.NewObject("tenantId", "org")); len(issues) != 4 {
		t.Fatalf("issues after a scoped run: %d", len(issues))
	}
	// A full-tenant run forgets the package that is gone, the rule issue of a package without a rule, and the identity
	// that is gone; a failed issue of a present pair stays.
	if _, err := ReconcilePackageRules(k.ctx, k.server, core.NewObject("trigger", "schedule")); err != nil {
		t.Fatal(err)
	}
	issues := automationFind(t, k, "packageRuleIssues", core.NewObject("tenantId", "org"))
	if len(issues) != 1 || issues[0].Get("id") != "iss_kept" {
		t.Fatalf("issues after a full run: %v", issues)
	}
}

func TestReconcileSelectsTenants(t *testing.T) {
	k := automationKernel(t)
	k.insert("tenants", core.NewObject("id", "frozen", "tenantId", "frozen", "name", "Frozen", "type", "organization", "parentId", "root", "status", "suspended", "createdAt", 4.0))
	result, err := ReconcilePackageRules(k.ctx, k.server, core.NewObject("tenantId", "frozen", "trigger", "manual"))
	if err != nil {
		t.Fatal(err)
	}
	if got := core.MustStringify(result.Get("skipped")); got != `{"inactiveTenants":1,"failedTenants":[]}` {
		t.Fatalf("skipped: %s", got)
	}
	_, err = ReconcilePackageRules(k.ctx, k.server, core.NewObject("tenantId", "nope", "trigger", "manual"))
	expectError(t, err, "NOT_FOUND", "Tenant not found")
	// An identity change in a tenant without rules reads nothing more.
	k.insert("accessPackages", automationPackage("pkg_plain", "Plain", nil))
	result, err = ReconcilePackageRules(k.ctx, k.server, core.NewObject("tenantId", "org", "trigger", "identity-change", "identityIds", []string{"usr_a"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := core.MustStringify(result); got != `{"trigger":"identity-change","assigned":0,"refreshed":0,"restored":0,"ending":0,"revoked":0,"stale":0,"failed":[],"suspended":[],"braked":[],"skipped":{"inactiveTenants":0,"failedTenants":[]},"truncated":false}` {
		t.Fatalf("identity change: %s", got)
	}
}

func TestAfterIdentityChangeReturnsTheResult(t *testing.T) {
	k := automationKernel(t)
	value := core.NewObject("id", "usr_a")
	result, err := AfterIdentityChange(k.ctx, k.server, "nope", []string{"usr_a"}, value)
	if err != nil || result != value {
		t.Fatalf("result: %v %v", result, err)
	}
	result, err = AfterIdentityChange(k.ctx, k.server, "org", nil, "same")
	if err != nil || result != "same" {
		t.Fatalf("no identities: %v %v", result, err)
	}
}

func TestAutoAssignView(t *testing.T) {
	k := automationKernel(t)
	k.insert("identities", identity("usr_owner", "org", "name", "Olga"), identity("usr_a", "org", "name", "Ann"))
	k.insert("grantAuthorities", core.NewObject("id", "auth_1", "tenantId", "org", "identityId", "usr_owner", "ceiling", obj(t, `{"version":1,"statements":[]}`), "createdAt", 1.0))
	k.insert("bindings", core.NewObject("id", "b_1", "tenantId", "org", "subjectType", "group", "subjectId", "g-bound", "roleId", "r", "createdAt", 1.0))
	rule := obj(t, `{"include":[{"StringEquals":{"principal.kind":"user"},"ArrayContains":{"identity.groups":["g-bound","g-free"]}}],"ownerId":"usr_owner","authorityId":"auth_1","revision":2,"updatedAt":5}`)
	pkg := automationPackage("pkg_1", "Kit", rule)
	k.insert("packageRuleIssues",
		core.NewObject("id", "iss_1", "tenantId", "org", "uniqueKey", "pkg_1:identity:usr_a", "packageId", "pkg_1", "kind", "failed", "identityId", "usr_a", "code", "SOD_CONFLICT", "message", "no", "revision", 2.0, "since", 10.0),
		core.NewObject("id", "iss_2", "tenantId", "org", "uniqueKey", "pkg_1:braked:grants", "packageId", "pkg_1", "kind", "braked", "code", "grants", "message", "200 planned, threshold 100", "revision", 2.0, "since", 20.0),
	)
	env := obj(t, `{"identityAttributes":{},"groups":["g-bound","g-free"]}`)
	view := func(pkg *core.Object, env *core.Object) string {
		t.Helper()
		var out *core.Object
		err := k.tx(func(ctx context.Context, tx core.IamStore) error {
			var err error
			out, err = AutoAssignView(ctx, k.server, tx, pkg, env)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return core.MustStringify(out)
	}
	if got := view(pkg, env); got != `{"include":[{"StringEquals":{"principal.kind":"user"},"ArrayContains":{"identity.groups":["g-bound","g-free"]}}],"ownerId":"usr_owner","authorityId":"auth_1","revision":2,"updatedAt":5,"ownerName":"Olga","status":"active","warnings":["include[0] tests identity.groups for g-free, a group without role bindings whose members anyone holding iam:groups:update can change, so they choose who receives this package under its owner’s authority"],"issueCount":2,"issues":[{"kind":"braked","code":"grants","message":"200 planned, threshold 100","since":20},{"kind":"failed","identityId":"usr_a","identityName":"Ann","code":"SOD_CONFLICT","message":"no","since":10}]}` {
		t.Fatalf("view: %s", got)
	}
	// A rule that no longer validates.
	if got := view(pkg, obj(t, `{"identityAttributes":{},"groups":["g-bound"]}`)); !strings.Contains(got, `"status":"suspended","suspendedReason":"invalid-rule","suspendedDetail":"autoAssign.include[0]: unknown group g-free"`) {
		t.Fatalf("invalid rule: %s", got)
	}
	// A stored lack of rights.
	k.insert("packageRuleIssues", core.NewObject("id", "iss_3", "tenantId", "org", "uniqueKey", "pkg_1:suspended", "packageId", "pkg_1", "kind", "suspended", "code", "owner-lacks-rights", "message", "Olga may not assign this package", "revision", 2.0, "since", 5.0))
	if got := view(pkg, env); !strings.Contains(got, `"status":"suspended","suspendedReason":"owner-lacks-rights","suspendedDetail":"Olga may not assign this package"`) {
		t.Fatalf("lacking rights: %s", got)
	}
	// An authority that is revoked, or another person's.
	err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		authority, err := tx.Get(ctx, "grantAuthorities", "auth_1")
		if err != nil {
			return err
		}
		authority.Set("identityId", "usr_a")
		_, err = tx.Put(ctx, "grantAuthorities", authority)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := view(pkg, env); !strings.Contains(got, `"suspendedReason":"authority-revoked","suspendedDetail":"The rule owner’s grant authority is revoked or no longer theirs"`) {
		t.Fatalf("authority: %s", got)
	}
	// An owner who left.
	err = k.tx(func(ctx context.Context, tx core.IamStore) error {
		owner, err := tx.Get(ctx, "identities", "usr_owner")
		if err != nil {
			return err
		}
		owner.Set("status", "disabled")
		_, err = tx.Put(ctx, "identities", owner)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := view(pkg, env); !strings.Contains(got, `"suspendedReason":"owner-inactive","suspendedDetail":"The rule owner Olga is not active"`) {
		t.Fatalf("owner: %s", got)
	}
}

func TestPreviewRuleKeysAndValidation(t *testing.T) {
	k := automationKernel(t)
	principal := principalOf(identity("usr_owner", "org"), session("ses_1", "usr_owner", "org", "user"))
	var preview *core.Object
	err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		preview, err = PreviewRule(ctx, k.server, tx, principal, core.NewObject("tenantId", "org"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Get("rule") != "none" || preview.Get("matching") != 0.0 {
		t.Fatalf("preview: %s", core.MustStringify(preview))
	}
	keys, _ := preview.Get("keys").([]any)
	last := core.MustStringify(keys[len(keys)-1])
	if len(keys) != 13 || last != `{"key":"principal.department","type":"string","operators":["StringEquals","StringNotEquals","StringEqualsIgnoreCase","StringNotEqualsIgnoreCase","StringLike","StringNotLike","StringLikeIgnoreCase","DateBefore","DateAfter","Exists"]}` {
		t.Fatalf("keys: %d %s", len(keys), last)
	}
	err = k.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := PreviewRule(ctx, k.server, tx, principal, core.NewObject("tenantId", "org", "sample", 0.0))
		return err
	})
	expectError(t, err, "INVALID_INPUT", "Invalid sample")
	err = k.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := PreviewRule(ctx, k.server, tx, principal, core.NewObject("tenantId", "org", "autoAssign", obj(t, `{"include":[{"ArrayContains":{"identity.groups":"g-x"}}]}`)))
		return err
	})
	expectError(t, err, "INVALID_INPUT", "autoAssign.include[0]: unknown group g-x")
	err = k.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := PreviewRule(ctx, k.server, tx, principal, core.NewObject("tenantId", "org", "packageId", "pkg_missing"))
		return err
	})
	expectError(t, err, "NOT_FOUND", "Resource not found")
}
