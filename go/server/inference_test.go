package server

// Port of tests/inference.test.ts and the inference parts of tests/security-inference.test.ts and
// tests/delegation-spend.test.ts. The `inference` API group (api/inference.ts) is ported separately, so providers,
// models and budgets are seeded in the store the way inference.createProvider / createModel / setBudget write them,
// and checks go through CheckInvocation, RecordInvocation and the gateway runtime directly.

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const inferenceProviderKey = "sk-ant-secret-provider-key-0042"

type inferenceFixture struct {
	*directoryFixture
	tenantID string
	owner    core.CredentialInput
	ownerID  string
	runtime  *GatewayRuntime
}

// newInferenceFixture composes a server with inference on (settings nil: `inference: true`) and an organization.
func newInferenceFixture(t *testing.T, settings *InferenceOptions, mutate ...func(options *BetterIamOptions)) *inferenceFixture {
	t.Helper()
	f := newDirectoryFixture(t, func(options *BetterIamOptions) {
		if settings == nil {
			options.Inference = On[InferenceOptions]()
		} else {
			options.Inference = With(*settings)
		}
		for _, change := range mutate {
			change(options)
		}
	})
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	owners := f.find("identities", core.NewObject("tenantId", tenantID, "owner", true))
	if len(owners) != 1 {
		t.Fatalf("owner: %d", len(owners))
	}
	return &inferenceFixture{directoryFixture: f, tenantID: tenantID, owner: owner, ownerID: anaID(owners[0]),
		runtime: NewGatewayRuntime(f.iam.Context)}
}

// provider seeds a provider as inference.createProvider writes it and returns its ID; baseURL "" is the kind's
// public endpoint.
func (f *inferenceFixture) provider(tenantID, name, kind, apiKey, baseURL string) string {
	f.t.Helper()
	id := ID()
	if baseURL == "" {
		baseURL = jsString(ProviderBaseURLs.Get(kind))
	}
	sealed := must(SealProviderKey(f.iam.Context.Options.Secret, id, apiKey))
	now := f.now()
	f.seed("inferenceProviders", core.NewObject("id", id, "tenantId", tenantID, "uniqueKey", "name:"+strings.ToLower(name),
		"name", name, "kind", kind, "baseUrl", baseURL, "keySealed", sealed, "keyHint", "…"+apiKey[len(apiKey)-4:],
		"createdAt", now, "updatedAt", now, "keyRotatedAt", now))
	return id
}

// model seeds a model as inference.createModel writes it (members are the optional fields).
func (f *inferenceFixture) model(tenantID, name, providerID, upstream string, members ...any) *core.Object {
	f.t.Helper()
	now := f.now()
	model := core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", name, "name", name, "providerId", providerID,
		"upstreamModel", upstream, "enabled", true, "createdAt", now, "updatedAt", now)
	for index := 0; index+1 < len(members); index += 2 {
		model.Set(members[index].(string), members[index+1])
	}
	f.seed("inferenceModels", model)
	return model
}

// updateModel merges fields into a model (undefined members are removed, as inference.updateModel clears them).
func (f *inferenceFixture) updateModel(tenantID, name string, members ...any) {
	f.t.Helper()
	models := f.find("inferenceModels", core.NewObject("tenantId", tenantID, "uniqueKey", name))
	if len(models) != 1 {
		f.t.Fatalf("model %s not found", name)
	}
	next := models[0].Spread()
	for index := 0; index+1 < len(members); index += 2 {
		key := members[index].(string)
		if isUndefined(members[index+1]) {
			next.Delete(key)
		} else {
			next.Set(key, members[index+1])
		}
	}
	f.seed("inferenceModels", next)
}

// budget seeds a budget as inference.setBudget writes it (scope `shared` unless given) and returns it.
func (f *inferenceFixture) budget(tenantID, name string, members ...any) *core.Object {
	f.t.Helper()
	now := f.now()
	budget := core.NewObject("name", name, "uniqueKey", "name:"+strings.ToLower(name), "scope", "shared")
	for index := 0; index+1 < len(members); index += 2 {
		budget.Set(members[index].(string), members[index+1])
	}
	budget.Set("id", ID())
	budget.Set("tenantId", tenantID)
	budget.Set("createdAt", now)
	budget.Set("updatedAt", now)
	f.seed("inferenceBudgets", budget)
	return budget
}

// grant gives an identity a role with the statements.
func (f *inferenceFixture) grant(tenantID, identityID string, statements ...*core.Object) {
	f.t.Helper()
	f.bind(tenantID, f.role(tenantID, "Grant "+ID(), statements...), "identity", identityID)
}

// principal authenticates a credential and re-reads it.
func (f *inferenceFixture) principal(credential core.CredentialInput) *Principal {
	f.t.Helper()
	server := f.iam.Context
	authenticated, err := server.Principals.Authenticate(f.ctx, credential)
	if err != nil {
		f.t.Fatal(err)
	}
	principal, err := core.Transact(f.ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*Principal, error) {
		return server.Principals.CurrentPrincipal(ctx, tx, authenticated)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return principal
}

// check runs CheckInvocation for a credential in the organization.
func (f *inferenceFixture) check(credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	server := f.iam.Context
	principal := f.principal(credential)
	if !input.Has("tenantId") {
		input = core.NewObject("tenantId", f.tenantID).Assign(input)
	}
	return core.Transact(f.ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return CheckInvocation(ctx, server, tx, principal, input)
	})
}

// meter meters a call for a principal in the organization.
func (f *inferenceFixture) meter(principal *Principal, input *core.Object) *core.Object {
	f.t.Helper()
	server := f.iam.Context
	if !input.Has("tenantId") {
		input = core.NewObject("tenantId", f.tenantID).Assign(input)
	}
	record, err := core.Transact(f.ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return RecordInvocation(ctx, server, tx, principal, input)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return record
}

// permit authorizes a credential for a model, failing the test when it is refused.
func (f *inferenceFixture) permit(credential core.CredentialInput, model string) *core.Object {
	f.t.Helper()
	outcome, err := f.runtime.Authorize(f.ctx, credential, core.NewObject("model", model))
	if err != nil {
		f.t.Fatal(err)
	}
	if outcome.Has("denied") {
		f.t.Fatalf("denied: %v", member(outcome.Get("denied"), "reason"))
	}
	return outcome
}

// auditActions lists the organization's audit actions.
func (f *inferenceFixture) auditActions() []string {
	var actions []string
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		actions = append(actions, jsString(event.Get("action")))
	}
	return actions
}

// usageByModel sums the organization's usage records per model, like inference.usage with groupBy: 'model'.
func (f *inferenceFixture) usageByModel() map[string]map[string]float64 {
	rows := map[string]map[string]float64{}
	for _, record := range f.find("inferenceUsage", core.NewObject("tenantId", f.tenantID)) {
		key := jsString(record.Get("model"))
		row := rows[key]
		if row == nil {
			row = map[string]float64{}
			rows[key] = row
		}
		row["requests"]++
		for _, field := range []string{"inputTokens", "outputTokens", "cacheReadTokens", "cacheWriteTokens", "costMicros"} {
			row[field] += numberOr(record.Get(field), 0)
		}
	}
	return rows
}

func countOf(items []string, item string) int {
	count := 0
	for _, candidate := range items {
		if candidate == item {
			count++
		}
	}
	return count
}

func infExpect(t *testing.T, object any, path string, want any) {
	t.Helper()
	value := object
	for _, key := range strings.Split(path, ".") {
		value = member(value, key)
	}
	if !core.DeepEqual(core.Normalize(want), value) {
		t.Fatalf("%s = %s, want %s", path, gatewayJSON(value), gatewayJSON(core.Normalize(want)))
	}
}

// catalogSetup is tests/inference.test.ts setup(): one Anthropic provider, a frontier and a small model, and alice
// limited to small ones.
func catalogSetup(t *testing.T, settings *InferenceOptions) (*inferenceFixture, string, *core.Object, core.CredentialInput) {
	f := newInferenceFixture(t, settings)
	provider := f.provider(f.tenantID, "Anthropic", "anthropic", inferenceProviderKey, "")
	f.model(f.tenantID, "opus", provider, "claude-opus-5-5", "tier", "frontier", "inputPricePerMTok", 5.0, "outputPricePerMTok", 25.0)
	f.model(f.tenantID, "haiku", provider, "claude-haiku-4-5", "tier", "small", "inputPricePerMTok", 1.0, "outputPricePerMTok", 5.0)
	alice, aliceSession := f.person(f.tenantID, "alice")
	f.grant(f.tenantID, anaID(alice), allow(items("inference:invoke"), items("model/*"),
		"conditions", core.NewObject("StringEquals", core.NewObject("resource.tier", "small"))))
	return f, provider, alice, aliceSession
}

func TestInferenceSealsProviderKeysAndDecidesModelAccess(t *testing.T) {
	f, providerID, _, aliceSession := catalogSetup(t, nil)
	stored := f.record("inferenceProviders", providerID)
	if strings.Contains(gatewayJSON(stored), inferenceProviderKey) {
		t.Fatal("the provider key is stored in the clear")
	}
	check := func(model string) *core.Object {
		t.Helper()
		result, err := f.check(aliceSession, core.NewObject("model", model))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	refused := check("opus")
	infExpect(t, refused, "allowed", false)
	infExpect(t, refused, "reason", "ACCESS_DENIED")
	allowed := check("haiku")
	infExpect(t, allowed, "allowed", true)
	infExpect(t, allowed, "model.name", "haiku")
	infExpect(t, allowed, "model.tier", "small")
	infExpect(t, allowed, "model.provider.name", "Anthropic")
	infExpect(t, allowed, "model.provider.kind", "anthropic")
	infExpect(t, allowed, "budgets", []any{})
	_, err := f.check(aliceSession, core.NewObject("model", "nope"))
	expectError(t, err, "NOT_FOUND", "Model not found")
	// The denial is audited like any decision.
	if countOf(f.auditActions(), "inference:invoke") == 0 {
		t.Fatalf("no audited denial: %v", f.auditActions())
	}

	// Models a caller may use, as the gateway lists them.
	names := func(credential core.CredentialInput) []string {
		t.Helper()
		models, err := f.runtime.Models(f.ctx, credential)
		if err != nil {
			t.Fatal(err)
		}
		var result []string
		for _, model := range models {
			result = append(result, jsString(model.Get("name")))
		}
		return result
	}
	if got := strings.Join(names(aliceSession), ","); got != "haiku" {
		t.Fatalf("alice models: %s", got)
	}
	if got := strings.Join(names(f.owner), ","); got != "haiku,opus" {
		t.Fatalf("owner models: %s", got)
	}

	// The same decision through the generic authorize API.
	decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{Credential: aliceSession, TenantID: f.tenantID,
		Action: InferenceAction, Resource: ResourceTarget{Type: InferenceResourceType, ID: "haiku"}})
	if err != nil || !decision.Allowed {
		t.Fatalf("authorize: %v %v", decision, err)
	}

	// Disabling a model stops it for everyone.
	f.updateModel(f.tenantID, "haiku", "enabled", false)
	disabled := check("haiku")
	infExpect(t, disabled, "reason", "MODEL_DISABLED")

	// The gateway runtime opens the key server-side only.
	owner := f.permit(f.owner, "opus")
	infExpect(t, owner, "provider.apiKey", inferenceProviderKey)
	infExpect(t, owner, "provider.kind", "anthropic")
	infExpect(t, owner, "upstreamModel", "claude-opus-5-5")
	if member(owner.Get("provider"), "guard") != core.Undefined {
		t.Fatal("a public endpoint needs no SSRF guard")
	}
}

func TestInferenceInheritsModelsAndGuardsOrganizationBaseURLs(t *testing.T) {
	f, _, _, _ := catalogSetup(t, &InferenceOptions{AllowCustomBaseUrls: flag(true)})
	root := f.rootTenantID()
	shared := f.provider(root, "Platform vLLM", "openai-compatible", "platform-key-123456", "https://llm.platform.example/v1")
	f.model(root, "llama-local", shared, "meta-llama/Llama-4", "tier", "small")
	server := f.iam.Context
	visible, err := core.Transact(f.ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		return VisibleModels(ctx, server, tx, f.tenantID)
	})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, found := range visible {
		model, provider := foundParts(found)
		view := must(PublicModel(model, provider, f.tenantID))
		names = append(names, jsString(view.Get("name")))
		if view.Get("name") == "llama-local" {
			infExpect(t, view, "inherited", true)
			infExpect(t, view, "provider.id", shared)
			infExpect(t, view, "provider.kind", "openai-compatible")
		}
	}
	if got := strings.Join(names, ","); got != "haiku,llama-local,opus" {
		t.Fatalf("visible: %s", got)
	}
	providers, err := core.Transact(f.ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		return VisibleProviders(ctx, server, tx, f.tenantID)
	})
	if err != nil || len(providers) != 2 || providers[0].Get("name") != "Anthropic" || providers[1].Get("name") != "Platform vLLM" {
		t.Fatalf("providers: %v %v", providers, err)
	}
	// An organization may shadow an inherited name with its own model.
	own := f.provider(f.tenantID, "Self hosted", "openai-compatible", "local-key-123456", "https://llm.internal.example/v1")
	f.model(f.tenantID, "llama-local", own, "llama-own")
	found, err := core.Transact(f.ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return ResolveModel(ctx, server, tx, f.tenantID, "llama-local")
	})
	if err != nil {
		t.Fatal(err)
	}
	infExpect(t, found, "model.upstreamModel", "llama-own")
	// A base URL the platform chose is trusted; one an organization chose goes through the SSRF guard.
	platform := f.permitFor(t, "llama-local", root)
	if member(platform.Get("provider"), "guard") != core.Undefined {
		t.Fatal("the platform's provider is guarded")
	}
	organization := f.permit(f.owner, "llama-local")
	infExpect(t, organization, "provider.guard", core.NewObject("anyPort", true, "allowInsecureLocalhost", false, "allowPrivateNetworks", false))
}

// permitFor authorizes the root administrator for a model in a tenant.
func (f *inferenceFixture) permitFor(t *testing.T, model, tenantID string) *core.Object {
	t.Helper()
	outcome, err := f.runtime.Authorize(f.ctx, f.rootCred, core.NewObject("model", model, "tenantId", tenantID))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Has("denied") {
		t.Fatalf("denied: %s", gatewayJSON(outcome.Get("denied")))
	}
	return outcome
}

func TestInferenceReopensKeysSealedWithAPreviousSecret(t *testing.T) {
	f, _, _, _ := catalogSetup(t, nil)
	server := f.iam.Context
	original := server.Options.Secret
	server.Options.Secret = "a-brand-new-deployment-secret-of-32-chars"
	server.Options.PreviousSecrets = []string{original}
	defer func() { server.Options.Secret, server.Options.PreviousSecrets = original, nil }()
	outcome := f.permit(f.owner, "opus")
	infExpect(t, outcome, "provider.apiKey", inferenceProviderKey)
	server.Options.PreviousSecrets = nil
	providers := f.find("inferenceProviders", core.NewObject("tenantId", f.tenantID))
	if _, err := OpenProviderKey(server, providers[0]); err == nil {
		t.Fatal("a key sealed with a retired secret opened")
	}
}

func TestInferenceValidatesItsOptionsAtConstruction(t *testing.T) {
	for _, days := range []float64{0, 1.5, 3651} {
		_, err := InferencePlugins(&BetterIamOptions{Inference: With(InferenceOptions{UsageRetentionDays: float(days)})})
		expectError(t, err, "INVALID_CONFIG", "inference.usageRetentionDays must be 1 to 3650")
		_, err = New(&BetterIamOptions{Database: newStore(t), Secret: testSecret, BaseURL: "http://localhost:3000",
			Inference: With(InferenceOptions{UsageRetentionDays: float(days)})})
		expectError(t, err, "INVALID_CONFIG", "inference.usageRetentionDays must be 1 to 3650")
	}
	plugins := must(InferencePlugins(&BetterIamOptions{Inference: On[InferenceOptions]()}))
	if len(plugins) != 1 || plugins[0].ID != "better-iam:inference" || len(plugins[0].ResourceTypes) != 2 ||
		plugins[0].ResourceTypes[0].Name != "model" || plugins[0].ResourceTypes[1].Name != "model-tool" {
		t.Fatalf("plugins: %+v", plugins)
	}
	if none := must(InferencePlugins(&BetterIamOptions{})); len(none) != 0 {
		t.Fatal("inference off contributes plugins")
	}
	if settings := InferenceSettings(&ServerContext{Options: &BetterIamOptions{Inference: On[InferenceOptions]()}}); settings == nil ||
		settings.UsageRetentionDays != nil {
		t.Fatal("inference: true has empty settings")
	}
}

func TestInferenceIsRefusedWithoutTheOption(t *testing.T) {
	f := newDirectoryFixture(t, nil)
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	runtime := NewGatewayRuntime(f.iam.Context)
	_, err := runtime.Models(f.ctx, owner)
	expectError(t, err, "FEATURE_DISABLED", "Inference is not enabled on this deployment")
	_, err = runtime.Authorize(f.ctx, owner, core.NewObject("model", "haiku", "tenantId", tenantID))
	expectError(t, err, "FEATURE_DISABLED", "Inference is not enabled on this deployment")
	// Without the option, `model/...` is an ordinary (application) resource type again.
	resolved, err := ResolveModelResource(f.ctx, f.iam.Context, f.iam.Store, core.ResourceRef{TenantID: tenantID, Type: "model", ID: "x"})
	if err != nil || resolved != nil {
		t.Fatalf("resolved: %v %v", resolved, err)
	}
}

func TestInferenceMetersCallsAndRefusesExhaustedBudgets(t *testing.T) {
	f, _, alice, aliceSession := catalogSetup(t, nil)
	budget := f.budget(f.tenantID, "Daily per person", "subjectType", "tenant", "subjectId", f.tenantID, "scope", "each",
		"period", "day", "maxTokens", 1000.0, "alertAtPercent", 80.0)
	used := f.permit(aliceSession, "haiku")
	budgets, _ := member(used.Get("check"), "budgets").([]any)
	if len(budgets) != 1 {
		t.Fatalf("budgets: %s", gatewayJSON(budgets))
	}
	infExpect(t, budgets[0], "budgetId", budget.Get("id"))
	infExpect(t, budgets[0], "remainingTokens", 1000.0)
	recorded, err := f.runtime.Record(f.ctx, used, core.NewObject("model", "haiku", "inputTokens", 600.0, "outputTokens", 300.0))
	if err != nil {
		t.Fatal(err)
	}
	// 600 × $1 + 300 × $5 per million tokens = 2100 micro-dollars.
	infExpect(t, recorded, "identityId", alice.Get("id"))
	infExpect(t, recorded, "costMicros", 2100.0)
	infExpect(t, recorded, "status", "ok")
	infExpect(t, recorded, "sessionKind", "user")

	check := func(estimate float64) *core.Object {
		t.Helper()
		result, err := f.check(aliceSession, core.NewObject("model", "haiku", "estimatedTokens", estimate))
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	infExpect(t, check(50), "allowed", true)
	refused := check(200)
	infExpect(t, refused, "allowed", false)
	infExpect(t, refused, "reason", "BUDGET_EXCEEDED")
	infExpect(t, refused, "budget.budgetId", budget.Get("id"))
	infExpect(t, refused, "budget.usedTokens", 900.0)
	infExpect(t, refused, "budget.remainingTokens", 100.0)
	check(200)
	// The owner has their own share of an `each` budget.
	ownerCheck, err := f.check(f.owner, core.NewObject("model", "haiku", "estimatedTokens", 900.0))
	if err != nil {
		t.Fatal(err)
	}
	infExpect(t, ownerCheck, "allowed", true)
	actions := f.auditActions()
	if countOf(actions, "inference:budget-exceeded") != 1 || countOf(actions, "inference:budget-alert") != 1 {
		t.Fatalf("audit: %v", actions)
	}
	counter := f.record("inferenceCounters", counterID(anaID(budget), anaID(alice), jsNumber(refused.Get("budget").(*core.Object).Get("windowStart"))))
	infExpect(t, counter, "tokens", 900.0)
	infExpect(t, counter, "costMicros", 2100.0)
	infExpect(t, counter, "requests", 1.0)
	infExpect(t, counter, "alerted", true)
	infExpect(t, counter, "exceeded", true)
	if got := strings.Join(counter.Keys(), ","); got != "id,tenantId,budgetId,subjectKey,windowStart,windowEnd,tokens,costMicros,requests,expiresAt,alerted,exceeded" {
		t.Fatalf("counter members: %s", got)
	}
	usage := f.find("inferenceUsage", core.NewObject("tenantId", f.tenantID))
	if len(usage) != 1 {
		t.Fatalf("usage: %d", len(usage))
	}
	if got := strings.Join(usage[0].Keys(), ","); got != "id,tenantId,identityId,sessionKind,model,providerId,inputTokens,outputTokens,costMicros,status,createdAt,expiresAt" {
		t.Fatalf("usage members: %s", got)
	}
	infExpect(t, usage[0], "expiresAt", f.now()+90*86_400_000)

	// The next day starts a fresh window.
	f.advance(86_400_000)
	fresh := f.issue(alice, false)
	next, err := f.check(fresh, core.NewObject("model", "haiku", "estimatedTokens", 900.0))
	if err != nil {
		t.Fatal(err)
	}
	infExpect(t, next, "allowed", true)
}

func TestInferenceCapsAnAgentAcrossEverythingItDoes(t *testing.T) {
	f, _, alice, _ := catalogSetup(t, &InferenceOptions{UsageRetentionDays: float(7)})
	agent := f.agent("Summarizer")
	cap := f.budget(f.tenantID, "Summarizer cap", "subjectType", "identity", "subjectId", anaID(agent), "period", "month",
		"maxCostMicros", 1000.0)
	delegationID := ID()
	f.seed("delegations", core.NewObject("id", delegationID, "tenantId", f.tenantID, "agentId", anaID(agent),
		"subjectId", anaID(alice), "status", "active", "createdAt", f.now()))
	// Acting for alice: metered to alice and to the agent.
	onBehalf := &Principal{Identity: alice, Session: core.NewObject("id", ID(), "tenantId", f.tenantID, "identityId", anaID(alice),
		"kind", "delegated", "agentId", anaID(agent), "delegationId", delegationID)}
	record := f.meter(onBehalf, core.NewObject("model", "haiku", "inputTokens", 500.0, "outputTokens", 100.0, "requestId", "req-1",
		"latencyMs", 12.0))
	infExpect(t, record, "identityId", alice.Get("id"))
	infExpect(t, record, "agentId", agent.Get("id"))
	infExpect(t, record, "delegationId", delegationID)
	infExpect(t, record, "sessionKind", "delegated")
	infExpect(t, record, "costMicros", 1000.0)
	infExpect(t, record, "expiresAt", f.now()+7*86_400_000)
	if got := strings.Join(record.Keys(), ","); got != "id,tenantId,identityId,sessionKind,model,providerId,inputTokens,outputTokens,costMicros,status,createdAt,expiresAt,agentId,delegationId,requestId,latencyMs" {
		t.Fatalf("record members: %s", got)
	}
	// The agent's cap is spent, for its own key too; alice herself is not capped.
	server := f.iam.Context
	own := &Principal{Identity: agent, Session: core.NewObject("id", ID(), "tenantId", f.tenantID, "identityId", anaID(agent), "kind", "api-key")}
	standings := func(principal *Principal) []*core.Object {
		t.Helper()
		result, err := core.Transact(f.ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
			subject, err := UsageSubject(ctx, server, tx, principal, f.tenantID)
			if err != nil {
				return nil, err
			}
			return BudgetStandings(ctx, server, tx, subject, "haiku")
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	agentStandings := standings(own)
	if len(agentStandings) != 1 {
		t.Fatalf("agent standings: %d", len(agentStandings))
	}
	infExpect(t, agentStandings[0], "standing.budgetId", cap.Get("id"))
	infExpect(t, agentStandings[0], "standing.usedCostMicros", 1000.0)
	infExpect(t, agentStandings[0], "standing.remainingCostMicros", 0.0)
	alicePrincipal := &Principal{Identity: alice, Session: core.NewObject("id", ID(), "tenantId", f.tenantID, "identityId", anaID(alice), "kind", "user")}
	if got := standings(alicePrincipal); len(got) != 0 {
		t.Fatalf("alice is capped: %s", gatewayJSON(got))
	}
}

func TestInferenceCountsAgentWorkForPeopleAgainstAGroupBudgetOnTheAgents(t *testing.T) {
	f, _, alice, _ := catalogSetup(t, nil)
	agent := f.agent("Looper")
	groupID := ID()
	f.seed("groups", core.NewObject("id", groupID, "tenantId", f.tenantID, "name", "Bots", "createdAt", f.now()))
	f.seed("groupMembers", core.NewObject("id", ID(), "tenantId", f.tenantID, "groupId", groupID, "identityId", anaID(agent),
		"createdAt", f.now()))
	budget := f.budget(f.tenantID, "Bots: 2 calls a day", "subjectType", "group", "subjectId", groupID, "scope", "each",
		"period", "day", "maxRequests", 2.0)
	own := &Principal{Identity: agent, Session: core.NewObject("id", ID(), "tenantId", f.tenantID, "identityId", anaID(agent), "kind", "api-key")}
	f.meter(own, core.NewObject("model", "haiku", "inputTokens", 10.0, "outputTokens", 10.0))
	delegationID := ID()
	f.seed("delegations", core.NewObject("id", delegationID, "tenantId", f.tenantID, "agentId", anaID(agent),
		"subjectId", anaID(alice), "status", "active", "createdAt", f.now()))
	forAlice := &Principal{Identity: alice, Session: core.NewObject("id", ID(), "tenantId", f.tenantID, "identityId", anaID(alice),
		"kind", "delegated", "agentId", anaID(agent), "delegationId", delegationID)}
	f.meter(forAlice, core.NewObject("model", "haiku", "inputTokens", 10.0, "outputTokens", 10.0))
	// Two calls used the group's allowance (counted against the agent), whichever credential made them.
	window := must(BudgetWindow("day", int64(f.now())))
	counter := f.record("inferenceCounters", counterID(anaID(budget), anaID(agent), jsNumber(window.Get("start"))))
	infExpect(t, counter, "requests", 2.0)
}

func TestInferenceRateLimitsCallsWithMaxRequests(t *testing.T) {
	f, _, alice, aliceSession := catalogSetup(t, nil)
	limit := f.budget(f.tenantID, "Three calls an hour", "subjectType", "identity", "subjectId", anaID(alice), "period", "hour",
		"maxRequests", 3.0)
	for call := 0; call < 3; call++ {
		permit := f.permit(aliceSession, "haiku")
		if _, err := f.runtime.Record(f.ctx, permit, core.NewObject("model", "haiku", "inputTokens", 1.0, "outputTokens", 1.0)); err != nil {
			t.Fatal(err)
		}
	}
	outcome, err := f.runtime.Authorize(f.ctx, aliceSession, core.NewObject("model", "haiku"))
	if err != nil {
		t.Fatal(err)
	}
	infExpect(t, outcome, "denied.reason", "BUDGET_EXCEEDED")
	infExpect(t, outcome, "denied.budget.budgetId", limit.Get("id"))
	infExpect(t, outcome, "denied.budget.usedRequests", 3.0)
	infExpect(t, outcome, "denied.budget.remainingRequests", 0.0)
	f.advance(3_600_000)
	fresh := f.issue(alice, false)
	again, err := f.runtime.Authorize(f.ctx, fresh, core.NewObject("model", "haiku"))
	if err != nil || again.Has("denied") {
		t.Fatalf("after the window: %v %v", again, err)
	}
}

func TestInferenceDelegationSpendStanding(t *testing.T) {
	f, _, alice, _ := catalogSetup(t, nil)
	delegation := core.NewObject("id", "d1", "tenantId", f.tenantID, "agentId", "agent-1", "subjectId", anaID(alice),
		"createdAt", 5.0, "spend", core.NewObject("period", "day", "maxTokens", 100.0, "maxCostMicros", 50.0))
	budget := DelegationBudget(delegation)
	if got := gatewayJSON(budget); got != `{"id":"delegation:d1","tenantId":"`+f.tenantID+`","name":"Delegation spending limit","subjectType":"identity","subjectId":"`+anaID(alice)+`","scope":"shared","period":"day","maxTokens":100,"maxCostMicros":50,"createdAt":5,"updatedAt":5}` {
		t.Fatalf("budget: %s", got)
	}
	now := int64(f.now())
	standing := must(DelegationSpendStanding(f.ctx, f.iam.Store, delegation, now))
	window := must(BudgetWindow("day", now))
	if got := gatewayJSON(standing); got != `{"budgetId":"delegation:d1","name":"Delegation spending limit","period":"day","windowStart":`+
		core.NumberString(jsNumber(window.Get("start")))+`,"resetsAt":`+core.NumberString(jsNumber(window.Get("end")))+
		`,"usedTokens":0,"usedCostMicros":0,"usedRequests":0,"remainingTokens":100,"remainingCostMicros":50}` {
		t.Fatalf("standing: %s", got)
	}
	if none := must(DelegationSpendStanding(f.ctx, f.iam.Store, core.NewObject("id", "d2"), now)); none != nil {
		t.Fatal("a delegation without a cap has a standing")
	}
	// A call under the delegation counts against its cap.
	f.seed("delegations", delegation)
	onBehalf := &Principal{Identity: alice, Session: core.NewObject("id", ID(), "tenantId", f.tenantID, "identityId", anaID(alice),
		"kind", "delegated", "agentId", "agent-1", "delegationId", "d1")}
	f.meter(onBehalf, core.NewObject("model", "haiku", "inputTokens", 30.0, "outputTokens", 10.0))
	spent := must(DelegationSpendStanding(f.ctx, f.iam.Store, delegation, now))
	infExpect(t, spent, "usedTokens", 40.0)
	infExpect(t, spent, "usedRequests", 1.0)
	infExpect(t, spent, "remainingTokens", 60.0)
}

func TestInferenceBudgetWindowsAndCosts(t *testing.T) {
	at := int64(1_790_000_123_456) // 2026-09-21T...
	for period, want := range map[string][2]float64{
		"minute": {1_790_000_100_000, 1_790_000_160_000},
		"hour":   {1_789_999_200_000, 1_790_002_800_000},
		"day":    {1_789_948_800_000, 1_790_035_200_000},
		"month":  {1_788_220_800_000, 1_790_812_800_000},
	} {
		window := must(BudgetWindow(period, at))
		if jsNumber(window.Get("start")) != want[0] || jsNumber(window.Get("end")) != want[1] {
			t.Fatalf("%s window: %s", period, gatewayJSON(window))
		}
	}
	december := must(BudgetWindow("month", 1_798_761_600_000+5)) // 2027-01-01
	if isoString(jsNumber(december.Get("start"))) != "2027-01-01T00:00:00.000Z" || isoString(jsNumber(december.Get("end"))) != "2027-02-01T00:00:00.000Z" {
		t.Fatalf("month window: %s", gatewayJSON(december))
	}
	model := core.NewObject("inputPricePerMTok", 3.0, "outputPricePerMTok", 15.0, "cachedInputPricePerMTok", 0.3)
	// 10 × $3 + 5 cached × $0.30 + 20 × $15 per million = 331.5 micro-dollars.
	if cost := UsageCost(model, core.NewObject("inputTokens", 10.0, "outputTokens", 20.0, "cacheReadTokens", 5.0)); cost != 331.5 {
		t.Fatalf("cost: %v", cost)
	}
	if cost := UsageCost(core.NewObject("inputPricePerMTok", 2.0), core.NewObject("inputTokens", 1.0, "outputTokens", 1.0,
		"cacheReadTokens", 1.0, "cacheWriteTokens", 1.0)); cost != 6 {
		t.Fatalf("cached input defaults to the input price: %v", cost)
	}
	if tokens := UsageTokens(core.NewObject("inputTokens", 1.0, "outputTokens", 2.0, "cacheReadTokens", 3.0, "cacheWriteTokens", 4.0)); tokens != 10 {
		t.Fatalf("tokens: %v", tokens)
	}
	standing := must(StandingOf(core.NewObject("id", "b", "name", "B", "period", "hour", "maxRequests", 2.0),
		core.NewObject("start", 1.0, "end", 2.0), core.NewObject("tokens", 5.0, "costMicros", 1.5, "requests", 3.0)))
	if got := gatewayJSON(standing); got != `{"budgetId":"b","name":"B","period":"hour","windowStart":1,"resetsAt":2,"usedTokens":5,"usedCostMicros":1.5,"usedRequests":3,"remainingRequests":0}` {
		t.Fatalf("standing: %s", got)
	}
}

func TestInferenceInputValidators(t *testing.T) {
	for _, name := range []string{"claude-sonnet-5", "a", "vendor/model@v1:latest+x", strings.Repeat("m", 128)} {
		if _, err := ModelName(name); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, name := range []any{"", "-lead", strings.Repeat("m", 129), "has space", 5.0, core.Undefined} {
		_, err := ModelName(name)
		expectError(t, err, "INVALID_INPUT", "Model names use 1-128 letters, digits or ._:/@+- characters and start with a letter or digit")
	}
	if value := must(Price(0.0, "inputPricePerMTok")); value != 0 {
		t.Fatal(value)
	}
	for _, value := range []any{-1.0, 10_001.0, "3"} {
		_, err := Price(value, "inputPricePerMTok")
		expectError(t, err, "INVALID_INPUT", "inputPricePerMTok must be a price from 0 to 10000 dollars per million tokens")
	}
	if _, err := ProviderKey("sk-12345678"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{"short", "has a space here", "tab\there-12345", "nbsp key-12345", strings.Repeat("k", 4097), 12345678.0} {
		_, err := ProviderKey(value)
		expectError(t, err, "INVALID_INPUT", "apiKey must be 8-4096 characters without whitespace")
	}
	settings := &InferenceOptions{}
	if got := must(BaseURL("https://router.example/api/v1/", settings)); got != "https://router.example/api/v1" {
		t.Fatal(got)
	}
	if got := must(BaseURL("https://Router.Example", settings)); got != "https://router.example" {
		t.Fatal(got)
	}
	_, err := BaseURL("not a url", settings)
	expectError(t, err, "INVALID_INPUT", "baseUrl must be an absolute URL")
	for _, value := range []string{"http://router.example", "https://user:pw@router.example", "https://router.example/?q=1",
		"https://router.example/#x", "http://localhost:8080"} {
		_, err := BaseURL(value, settings)
		expectError(t, err, "INVALID_INPUT", "baseUrl must be an https URL without credentials or query")
	}
	if got := must(BaseURL("http://localhost:8080/v1", &InferenceOptions{AllowInsecureLocalhost: flag(true)})); got != "http://localhost:8080/v1" {
		t.Fatal(got)
	}
	_, err = BaseURL(5.0, settings)
	expectError(t, err, "INVALID_INPUT", "Invalid baseUrl")
	tools := must(ProviderToolList([]any{"web_search", "mcp:kb.acme.test", "web_search"}))
	if strings.Join(tools, ",") != "web_search,mcp:kb.acme.test" {
		t.Fatal(tools)
	}
	_, err = ProviderToolList("web_search")
	expectError(t, err, "INVALID_INPUT", "tools must be a list")
	for _, value := range []any{[]any{"Web"}, []any{5.0}, stringsOf(make([]string, 65))} {
		_, err := ProviderToolList(value)
		expectError(t, err, "INVALID_INPUT", "tools must list at most 64 provider tool ids (such as web_search or mcp:tools.example.com)")
	}
}

func TestInferenceResolvesModelAndToolResources(t *testing.T) {
	f, _, _, _ := catalogSetup(t, nil)
	server := f.iam.Context
	resolve := func(kind, id string) (*ResolvedResource, error) {
		return ResolveModelResource(f.ctx, server, f.iam.Store, core.ResourceRef{TenantID: f.tenantID, Type: kind, ID: id})
	}
	model := must(resolve("model", "haiku"))
	if got := gatewayJSON(model.Attributes); got != `{"provider":"Anthropic","providerKind":"anthropic","upstreamModel":"claude-haiku-4-5","enabled":true,"tier":"small","inputPricePerMTok":1,"outputPricePerMTok":5}` {
		t.Fatalf("attributes: %s", got)
	}
	_, err := resolve("model", "missing")
	expectError(t, err, "NOT_FOUND", "Model not found")
	tool := must(resolve("model-tool", "mcp:kb.acme.test"))
	if got := gatewayJSON(tool.Attributes); got != `{"kind":"mcp","host":"kb.acme.test"}` {
		t.Fatalf("tool attributes: %s", got)
	}
	plain := must(resolve("model-tool", "web_search"))
	if got := gatewayJSON(plain.Attributes); got != `{"kind":"web_search"}` {
		t.Fatalf("tool attributes: %s", got)
	}
	_, err = resolve("model-tool", "Bad Tool")
	expectError(t, err, "NOT_FOUND", "Unknown provider tool")
	if other := must(resolve("document", "x")); other != nil {
		t.Fatal("other types are not the inference module's")
	}
	// A model whose provider is gone is disabled for everyone.
	provider := f.find("inferenceProviders", core.NewObject("tenantId", f.tenantID))[0]
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "inferenceProviders", anaID(provider))
	})
	orphan := must(resolve("model", "haiku"))
	if got := gatewayJSON(orphan.Attributes); !strings.HasPrefix(got, `{"provider":"","providerKind":"","upstreamModel":"claude-haiku-4-5","enabled":false`) {
		t.Fatalf("orphan: %s", got)
	}
	found := must(core.Transact(f.ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return ResolveModel(ctx, server, tx, f.tenantID, "haiku")
	}))
	view := must(PublicModel(found.Get("model").(*core.Object), nil, f.tenantID))
	infExpect(t, view, "provider", core.NewObject("id", anaID(provider), "name", "(missing)", "kind", "openai-compatible"))
	infExpect(t, view, "enabled", false)
}

func TestInferenceOwnsOnlyItsOwnResponses(t *testing.T) {
	f, providerID, alice, _ := catalogSetup(t, nil)
	server := f.iam.Context
	owner := &Principal{Identity: alice, Session: core.NewObject("id", ID(), "tenantId", f.tenantID, "identityId", anaID(alice), "kind", "user")}
	f.meter(owner, core.NewObject("model", "haiku", "inputTokens", 1.0, "outputTokens", 1.0, "responseId", "resp_1"))
	f.meter(owner, core.NewObject("model", "haiku", "inputTokens", 1.0, "outputTokens", 1.0, "responseId", "../bad"))
	stored := f.record("inferenceResponses", f.tenantID+":resp_1")
	if got := strings.Join(stored.Keys(), ","); got != "id,tenantId,responseId,identityId,model,providerId,createdAt,expiresAt" {
		t.Fatalf("response members: %s", got)
	}
	if len(f.find("inferenceResponses", core.NewObject("tenantId", f.tenantID))) != 1 {
		t.Fatal("an invalid response id was recorded")
	}
	owns := func(principal *Principal, responseID, provider string) bool {
		t.Helper()
		return must(core.Transact(f.ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
			return OwnsInferenceResponse(ctx, server, tx, principal, f.tenantID, responseID, provider)
		}))
	}
	if !owns(owner, "resp_1", providerID) {
		t.Fatal("the creator does not own the response")
	}
	if owns(owner, "resp_1", "other-provider") || owns(owner, "resp_2", providerID) || owns(owner, "../resp_1", providerID) {
		t.Fatal("ownership leaks across providers or ids")
	}
	viaAgent := &Principal{Identity: alice, Session: core.NewObject("id", ID(), "tenantId", f.tenantID, "identityId", anaID(alice),
		"kind", "delegated", "agentId", "agent-1")}
	if owns(viaAgent, "resp_1", providerID) {
		t.Fatal("an agent acting for the creator owns the creator's own response")
	}
	f.advance(91 * 86_400_000)
	if owns(owner, "resp_1", providerID) {
		t.Fatal("an expired response is still owned")
	}
}

func TestInferenceGovernsProviderToolsInChecks(t *testing.T) {
	f, _, alice, aliceSession := catalogSetup(t, nil)
	f.updateModel(f.tenantID, "haiku", "providerTools", "policy")
	f.grant(f.tenantID, anaID(alice), allow(items("inference:use-tool"), items("model-tool/web_search")))
	allowed, err := f.check(aliceSession, core.NewObject("model", "haiku", "tools", items("web_search")))
	if err != nil {
		t.Fatal(err)
	}
	infExpect(t, allowed, "allowed", true)
	infExpect(t, allowed, "model.providerTools", "policy")
	refused, err := f.check(aliceSession, core.NewObject("model", "haiku", "tools", items("web_search", "code_interpreter")))
	if err != nil {
		t.Fatal(err)
	}
	infExpect(t, refused, "reason", "TOOL_NOT_ALLOWED")
	infExpect(t, refused, "tool", "code_interpreter")
	f.updateModel(f.tenantID, "haiku", "providerTools", "deny")
	denied, err := f.check(aliceSession, core.NewObject("model", "haiku", "tools", items("web_search")))
	if err != nil {
		t.Fatal(err)
	}
	infExpect(t, denied, "reason", "TOOL_NOT_ALLOWED")
	var metadata *core.Object
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "inference:use-tool")) {
		if event.Get("resourceId") == "model-tool/web_search" && event.Get("outcome") == "deny" {
			metadata, _ = event.Get("metadata").(*core.Object)
		}
	}
	if gatewayJSON(metadata) != `{"model":"haiku","providerTools":"deny"}` {
		t.Fatalf("tool refusal audit: %s", gatewayJSON(metadata))
	}
	f.updateModel(f.tenantID, "haiku", "providerTools", "allow")
	passed, err := f.check(aliceSession, core.NewObject("model", "haiku", "tools", items("anything")))
	if err != nil {
		t.Fatal(err)
	}
	infExpect(t, passed, "allowed", true)
	if member(passed.Get("model"), "providerTools") != core.Undefined {
		t.Fatal("allow is the default and not shown")
	}
}

// agent seeds an AI agent identity of the organization (sponsored by the owner).
func (f *inferenceFixture) agent(name string) *core.Object {
	f.t.Helper()
	agent := core.NewObject("id", ID(), "tenantId", f.tenantID, "kind", "agent", "name", name, "status", "active",
		"emailVerified", false, "rootAdmin", false, "owner", false, "sponsorId", f.ownerID, "createdAt", f.now())
	f.seed("identities", agent)
	return agent
}
