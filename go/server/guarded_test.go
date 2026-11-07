package server

// guarded.ts and grant-deadline.ts against fake decision, principal and usage services (kernel B ports the real
// ones; tests/kms.test.ts and tests/pki.test.ts exercise the envelope end to end through those modules).

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

type fakeDecisions struct {
	// allow maps "action resourceID" to the decision reason ("" denies with NO_APPLICABLE_GRANT).
	allow    map[string]string
	fixed    *core.Decision
	root     bool
	bindings []EffectiveBinding
	grants   map[string][]any
	prepared int
}

func (f *fakeDecisions) RoleGrants(ctx context.Context, tx core.IamStore, role *core.Object, tenantID string, ceilings []any, authorityID string, seen map[string]bool, lapsed *[]GrantPath) ([]GrantPath, error) {
	return []GrantPath{{Grants: f.grants[jsString(role.Get("id"))], AuthorityID: authorityID}}, nil
}
func (f *fakeDecisions) GrantSources(context.Context, core.IamStore, string, string) (*GrantSources, error) {
	return &GrantSources{}, nil
}
func (f *fakeDecisions) LiveActivations(context.Context, core.IamStore, string, string) (map[string]*core.Object, error) {
	return nil, nil
}
func (f *fakeDecisions) IdentityGrants(context.Context, core.IamStore, string, string, *GrantSources, *[]GrantPath) ([]GrantPath, error) {
	return nil, nil
}
func (f *fakeDecisions) EffectiveBindings(context.Context, core.IamStore, string, string) ([]EffectiveBinding, error) {
	return f.bindings, nil
}
func (f *fakeDecisions) Resolve(context.Context, core.IamStore, core.ResourceRef, bool, string, *SchemeKnown) (*ResolvedResource, error) {
	return nil, notImplemented("fake")
}
func (f *fakeDecisions) PrepareDecision(ctx context.Context, tx core.IamStore, principal *Principal, target *core.Object, action string) (*PreparedDecision, error) {
	f.prepared++
	if f.fixed != nil {
		return &PreparedDecision{Fixed: f.fixed}, nil
	}
	return &PreparedDecision{RootOverride: f.root, Evaluate: func(resource ResolvedResource, override string) (core.Decision, error) {
		if override == "" {
			override = action
		}
		reason, ok := f.allow[override+" "+resource.ID]
		if !ok {
			return core.Decision{Allowed: false, Reason: "NO_APPLICABLE_GRANT", Matched: []string{}}, nil
		}
		return core.Decision{Allowed: reason != "DENIED", Reason: reason, Matched: []string{}}, nil
	}}, nil
}
func (f *fakeDecisions) Decide(context.Context, core.IamStore, *Principal, AuthorizationRequest, bool) (core.Decision, error) {
	return core.Decision{}, notImplemented("fake")
}
func (f *fakeDecisions) SimulatedPrincipal(*core.Object, bool) *Principal { return nil }

type fakePrincipals struct{ byToken map[string]*Principal }

func (f *fakePrincipals) Authenticate(ctx context.Context, input core.CredentialInput) (*Principal, error) {
	if principal, ok := f.byToken[input.Token]; ok {
		return principal, nil
	}
	return nil, core.NewIamError("UNAUTHENTICATED", "Invalid credentials", 401)
}
func (f *fakePrincipals) CurrentPrincipal(ctx context.Context, tx core.IamStore, principal *Principal) (*Principal, error) {
	return principal, nil
}

type fakeUsage struct {
	mu       sync.Mutex
	recorded []string
}

func (f *fakeUsage) Enabled() bool { return true }
func (f *fakeUsage) Record(tenantID, identityID, action string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, tenantID+" "+identityID+" "+action)
}
func (f *fakeUsage) Flush(context.Context) (int, error) { return 0, nil }
func (f *fakeUsage) Stop()                              {}

type keyTarget struct {
	ID   string
	Spec string
}

func (k keyTarget) Target() GuardTarget {
	return GuardTarget{ResourceID: "kms/" + k.ID, Attributes: core.NewObject("spec", k.Spec)}
}

type guardKernel struct {
	*kernel
	decisions *fakeDecisions
	usage     *fakeUsage
	spans     []IamSpan
	hooks     []string
}

func newGuardKernel(t *testing.T) *guardKernel {
	g := &guardKernel{decisions: &fakeDecisions{allow: map[string]string{}, grants: map[string][]any{}}, usage: &fakeUsage{}}
	g.kernel = newKernel(t, func(options *BetterIamOptions) {
		options.Observability = &ObservabilityOptions{OnSpan: func(span IamSpan) { g.spans = append(g.spans, span) }}
		options.Plugins = []*core.IamPlugin{{ID: "hooks", Hooks: &core.PluginHooks{
			BeforeOperation: func(ctx context.Context, input core.OperationHookInput) error {
				g.hooks = append(g.hooks, "before "+input.Action+" "+input.ResourceID+" "+input.Principal.Identity.ID)
				return nil
			},
			AfterOperation: func(ctx context.Context, input core.OperationHookInput) error {
				g.hooks = append(g.hooks, "after "+input.Action+" "+jsString(input.Result))
				return nil
			},
		}}}
	})
	g.tenantTree()
	g.server.Decisions = g.decisions
	g.server.Usage = g.usage
	admin := principalOf(identity("admin", "org"), session("s-admin", "admin", "org", "user", "mfa", true))
	viewer := principalOf(identity("member", "org"), session("s-view", "member", "org", "user", "impersonatorId", "admin"))
	outsider := principalOf(identity("stranger", "project"), session("s-out", "stranger", "project", "user"))
	g.server.Principals = &fakePrincipals{byToken: map[string]*Principal{"admin": admin, "viewer": viewer, "outsider": outsider}}
	return g
}

func (g *guardKernel) audits() []string {
	events := sortBySequence(must(g.store.Find(g.ctx, "audit", core.NewObject("tenantId", "org"), nil)))
	out := make([]string, len(events))
	for index, event := range events {
		line := jsString(event.Get("action")) + " " + jsString(event.Get("resourceId")) + " " + jsString(event.Get("outcome"))
		if event.Get("rootOverride") == true {
			line += " root"
		}
		if metadata := event.Get("metadata"); !isUndefined(metadata) {
			line += " " + core.MustStringify(metadata)
		}
		out[index] = line
	}
	return out
}

func TestGuardRun(t *testing.T) {
	g := newGuardKernel(t)
	guard := CreateGuard(g.server, "kms", GuardOptions[keyTarget]{
		Describe:         func(target keyTarget) *core.Object { return core.NewObject("spec", target.Spec) },
		RecordedFailures: map[string]string{"KEY_DISABLED": "disabled"},
		HookResult:       func(value any) any { return "redacted" },
		Fallback: func(ctx context.Context, tx core.IamStore, principal *Principal, action string, target keyTarget) (*core.Object, error) {
			if target.ID == "granted" {
				return core.NewObject("grantId", "g1"), nil
			}
			return nil, nil
		},
	})
	locate := func(id string) func(context.Context, core.IamStore, *Principal) (keyTarget, error) {
		return func(context.Context, core.IamStore, *Principal) (keyTarget, error) {
			return keyTarget{ID: id, Spec: "AES_256"}, nil
		}
	}
	call := func(token, id string, fn func(ctx context.Context, call GuardCall, target keyTarget) (any, error)) (any, error) {
		return guard.Run(g.ctx, core.CredentialInput{Token: token}, "org", GuardAction[keyTarget]{Name: "iam:kms:encrypt"}, locate(id), fn)
	}
	ok := func(ctx context.Context, call GuardCall, target keyTarget) (any, error) {
		call.Metadata.Set("bytes", 3.0)
		other := must(call.Allowed(ctx, "iam:kms:decrypt", target.Target()))
		return "ciphertext-" + jsString(other), nil
	}
	g.decisions.allow["iam:kms:encrypt kms/k1"] = "ALLOW"
	value := must(call("admin", "k1", ok))
	if value != "ciphertext-false" {
		t.Fatal(value)
	}
	if g.decisions.prepared != 2 {
		t.Fatalf("prepared %d", g.decisions.prepared)
	}
	// Refusals before any lookup, policy denials, fallbacks, refusals inside the call and recorded failures.
	_, err := call("viewer", "k1", ok)
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	_, err = call("outsider", "k1", ok)
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	_, err = call("admin", "k2", ok)
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	if value := must(call("admin", "granted", ok)); value != "ciphertext-false" {
		t.Fatal(value)
	}
	g.decisions.allow["iam:kms:encrypt kms/k3"] = "ALLOW"
	_, err = call("admin", "k3", func(ctx context.Context, call GuardCall, target keyTarget) (any, error) {
		return nil, NewOperationDenied("Key is protected")
	})
	expectError(t, err, "ACCESS_DENIED", "Key is protected")
	_, err = call("admin", "k3", func(ctx context.Context, call GuardCall, target keyTarget) (any, error) {
		return nil, core.NewIamError("KEY_DISABLED", "Key is disabled", 409)
	})
	expectError(t, err, "KEY_DISABLED", "Key is disabled")
	g.decisions.allow["iam:kms:encrypt kms/root"] = "ROOT_OVERRIDE"
	must(call("admin", "root", ok))
	want := []string{
		`iam:kms:encrypt kms/k1 allow {"spec":"AES_256","bytes":3}`,
		`iam:kms:encrypt kms deny {"reason":"impersonation"}`,
		`iam:kms:encrypt kms deny {"reason":"tenant"}`,
		`iam:kms:encrypt kms/k2 deny {"spec":"AES_256"}`,
		`iam:kms:encrypt kms/granted allow {"spec":"AES_256","grantId":"g1","bytes":3}`,
		`iam:kms:encrypt kms/k3 deny {"reason":"refused"}`,
		`iam:kms:encrypt kms/k3 deny {"reason":"disabled"}`,
		`iam:kms:encrypt kms/root allow root {"spec":"AES_256","bytes":3}`,
	}
	if got := g.audits(); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit:\n%s", strings.Join(got, "\n"))
	}
	// The refusals of the viewer and the outsider are recorded on the tenant-wide resource.
	viewerEvents := must(g.store.Find(g.ctx, "audit", core.NewObject("actorId", "member"), nil))
	outsiderEvents := must(g.store.Find(g.ctx, "audit", core.NewObject("actorId", "stranger"), nil))
	if len(viewerEvents) != 1 || core.MustStringify(viewerEvents[0].Get("metadata")) != `{"reason":"impersonation"}` || viewerEvents[0].Get("resourceId") != "kms" ||
		len(outsiderEvents) != 1 || core.MustStringify(outsiderEvents[0].Get("metadata")) != `{"reason":"tenant"}` {
		t.Fatal("refusals before lookup")
	}
	if !reflect.DeepEqual(g.usage.recorded, []string{"org admin iam:kms:encrypt", "org admin iam:kms:encrypt"}) {
		t.Fatalf("usage %v", g.usage.recorded)
	}
	if g.hooks[0] != "before iam:kms:encrypt kms/k1 admin" || g.hooks[1] != "after iam:kms:encrypt redacted" {
		t.Fatalf("hooks %v", g.hooks)
	}
	if len(g.spans) != 8 || g.spans[0].Name != "iam:kms:encrypt" || g.spans[1].Outcome != "denied" || g.spans[6].Code != "KEY_DISABLED" {
		t.Fatalf("spans %+v", g.spans)
	}
	// An action computed from the target: refusals before the lookup are labeled iam:call.
	_, err = guard.Run(g.ctx, core.CredentialInput{Token: "viewer"}, "org", GuardAction[keyTarget]{Of: func(target keyTarget) string { return "iam:kms:sign" }}, locate("k1"), ok)
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	last := sortBySequence(must(g.store.Find(g.ctx, "audit", core.NewObject("actorId", "member"), nil)))
	if last[len(last)-1].Get("action") != "iam:call" {
		t.Fatal(last[len(last)-1].Get("action"))
	}
	_, err = guard.Run(g.ctx, core.CredentialInput{Token: "admin"}, "", GuardAction[keyTarget]{Name: "iam:kms:encrypt"}, locate("k1"), ok)
	expectError(t, err, "INVALID_INPUT", "Invalid tenantId")
	_, err = guard.Run(g.ctx, core.CredentialInput{Token: "nobody"}, "org", GuardAction[keyTarget]{Name: "iam:kms:encrypt"}, locate("k1"), ok)
	expectError(t, err, "UNAUTHENTICATED", "Invalid credentials")
}

func TestGuardVisible(t *testing.T) {
	g := newGuardKernel(t)
	guard := CreateGuard(g.server, "kms", GuardOptions[keyTarget]{})
	load := func(ctx context.Context, tx core.IamStore, tenant *core.Object) ([]VisibleItem[string], error) {
		var items []VisibleItem[string]
		for _, id := range []string{"k1", "k2", "k3"} {
			items = append(items, VisibleItem[string]{Item: id, Target: keyTarget{ID: id}.Target()})
		}
		return items, nil
	}
	g.decisions.allow["iam:kms:read kms/k1"] = "ALLOW"
	g.decisions.allow["iam:kms:read kms/k3"] = "ALLOW"
	items := must(GuardVisible(g.ctx, guard, core.CredentialInput{Token: "admin"}, "org", "iam:kms:read", "kms", load))
	if !reflect.DeepEqual(items, []string{"k1", "k3"}) {
		t.Fatal(items)
	}
	_, err := GuardVisible(g.ctx, guard, core.CredentialInput{Token: "viewer"}, "org", "iam:kms:read", "kms", load)
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	g.decisions.fixed = &core.Decision{Allowed: false, Reason: "TENANT_INACTIVE", Matched: []string{}}
	_, err = GuardVisible(g.ctx, guard, core.CredentialInput{Token: "admin"}, "org", "iam:kms:read", "kms", load)
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	g.decisions.fixed = &core.Decision{Allowed: true, Reason: "ROOT_OVERRIDE", Matched: []string{}}
	if all := must(GuardVisible(g.ctx, guard, core.CredentialInput{Token: "admin"}, "org", "iam:kms:read", "kms", load)); len(all) != 3 {
		t.Fatal(all)
	}
	want := []string{`iam:kms:read kms allow {"listed":2}`, `iam:kms:read kms deny`, `iam:kms:read kms deny`, `iam:kms:read kms allow root {"listed":3}`}
	if got := g.audits(); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit:\n%s", strings.Join(got, "\n"))
	}
}

func TestGrantDeadline(t *testing.T) {
	g := newGuardKernel(t)
	now := float64(g.clock.Load())
	horizon := now + 30*86400000
	user := principalOf(identity("alice", "org"), session("s1", "alice", "org", "user"))
	role := core.NewObject("id", "signer")
	reader := core.NewObject("id", "reader")
	g.decisions.grants["signer"] = []any{parse(t, `{"version":1,"statements":[{"effect":"allow","actions":["ssh:*"],"resources":["*"]}]}`)}
	g.decisions.grants["reader"] = []any{parse(t, `{"version":1,"statements":[{"effect":"allow","actions":["docs:read"],"resources":["*"]},{"effect":"deny","actions":["ssh:login"],"resources":["*"]}]}`)}
	deadline := func(principal *Principal, tenantID string) float64 {
		return must(GrantDeadline(g.ctx, g.server, g.store, principal, tenantID, horizon, "ssh:login"))
	}
	if deadline(user, "org") != horizon {
		t.Fatal("standing access sets no limit")
	}
	g.decisions.bindings = []EffectiveBinding{
		{Binding: core.NewObject("id", "b-reader", "expiresAt", now+1000, "authorityId", "a"), Role: reader},
		{Binding: core.NewObject("id", "b-signer", "expiresAt", now+5*86400000, "authorityId", "a"), Role: role},
		{Binding: core.NewObject("id", "b-eligible", "eligible", true, "authorityId", "a"), Role: role},
		{Binding: core.NewObject("id", "b-future", "startsAt", now+1, "expiresAt", now+2000, "authorityId", "a"), Role: role},
		{Binding: core.NewObject("id", "b-norole", "expiresAt", now+3000, "authorityId", "a")},
	}
	if got := deadline(user, "org"); got != now+5*86400000 {
		t.Fatalf("binding expiry: %v", got-now)
	}
	g.decisions.bindings = append(g.decisions.bindings, EffectiveBinding{
		Binding: core.NewObject("id", "b-active", "eligible", true, "authorityId", "a"), Role: role,
		Activation: core.NewObject("id", "act", "activatedAt", now, "expiresAt", now+3600000),
	})
	if got := deadline(user, "org"); got != now+3600000 {
		t.Fatalf("activation: %v", got-now)
	}
	g.insert("groupMembers", core.NewObject("id", "gm", "tenantId", "org", "groupId", "ops", "identityId", "alice", "expiresAt", now+600000))
	g.decisions.bindings = append(g.decisions.bindings, EffectiveBinding{Binding: core.NewObject("id", "b-group", "authorityId", "a"), Role: role, ViaGroupID: "ops"})
	if got := deadline(user, "org"); got != now+600000 {
		t.Fatalf("membership: %v", got-now)
	}
	// An open access window closes within the next five-minute step after it ends.
	minutes := int(now/60000) % 1440
	clock := func(m int) string {
		m = ((m % 1440) + 1440) % 1440
		return pad2(m/60) + ":" + pad2(m%60)
	}
	g.decisions.bindings = append(g.decisions.bindings, EffectiveBinding{
		Binding: core.NewObject("id", "b-window", "authorityId", "a", "window", core.NewObject("from", clock(minutes-60), "to", clock(minutes+7), "timeZone", "UTC")),
		Role:    role,
	})
	if got := deadline(user, "org") - now; got <= 0 || got > 15*60000 {
		t.Fatalf("window: %v", got)
	}
	// Temporary sessions and other tenants are bounded by their session instead.
	if deadline(principalOf(identity("alice", "org"), session("s2", "alice", "org", "role")), "org") != horizon || deadline(user, "project") != horizon {
		t.Fatal("bounded by the session")
	}
}

func pad2(n int) string {
	if n < 10 {
		return "0" + core.NumberString(float64(n))
	}
	return core.NumberString(float64(n))
}
