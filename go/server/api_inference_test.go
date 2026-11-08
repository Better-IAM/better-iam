package server

// Inference API tests, after tests/inference.test.ts and tests/security-inference.test.ts: sealed provider keys,
// model access by ordinary policies, custom base URLs, inherited models, budgets and metering, agent caps, request
// limits, ticket redemption, the platform's hold on models and budgets it set, and the unit-level helpers (usage
// reports, model fields, budget fields). Steps that reach another unit's NOT_IMPLEMENTED stub (inference.ts) skip the
// rest of their test until that unit is ported.

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const infProviderKey = "sk-ant-secret-provider-key-0042"

type infFixture struct {
	*orgFixture
}

func newInfFixture(t *testing.T, mutate func(options *BetterIamOptions)) *infFixture {
	t.Helper()
	// A deployment with inference on cannot be built until inference.ts contributes its catalog entries.
	if _, err := InferencePlugins(&BetterIamOptions{Inference: On[InferenceOptions]()}); err != nil {
		requirePorted(t, err)
	}
	return &infFixture{orgFixture: newOrgFixture(t, func(options *BetterIamOptions) {
		options.Inference = On[InferenceOptions]()
		if mutate != nil {
			mutate(options)
		}
	})}
}

// infCall calls an inference API method with { tenantId, ...members }.
func infCall[I, O any](f *infFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, members ...any) (any, error) {
	input := core.NewObject("tenantId", f.tenantID).Assign(core.NewObject(members...))
	answer, err := method(f.ctx, credential, Input[I](input))
	if err != nil {
		return nil, err
	}
	return answer.Value, nil
}

// infObject unwraps an object answer (skipping on another unit's stub).
func (f *infFixture) infObject(value any, err error) *core.Object {
	f.t.Helper()
	requirePorted(f.t, err)
	object, ok := value.(*core.Object)
	if !ok {
		f.t.Fatalf("expected an object, got %T", value)
	}
	return object
}

// infList unwraps a list answer (skipping on another unit's stub).
func (f *infFixture) infList(value any, err error) []*core.Object {
	f.t.Helper()
	requirePorted(f.t, err)
	return aiObjects(value)
}

// infSame expects a model value to contain the members of want (toMatchObject).
func infSame(t *testing.T, label string, got any, want string) {
	t.Helper()
	if !infMatches(got, parse(t, want)) {
		t.Fatalf("%s:\n got  %s\n want %s", label, core.MustStringify(got), want)
	}
}

// infMatches is toMatchObject: objects match member by member (extra members allowed), arrays element by element.
func infMatches(got, want any) bool {
	switch expected := want.(type) {
	case *core.Object:
		actual, ok := got.(*core.Object)
		if !ok {
			return false
		}
		for _, key := range expected.Keys() {
			if !infMatches(actual.Get(key), expected.Get(key)) {
				return false
			}
		}
		return true
	case []any:
		actual, ok := got.([]any)
		if !ok || len(actual) != len(expected) {
			return false
		}
		for index := range expected {
			if !infMatches(actual[index], expected[index]) {
				return false
			}
		}
		return true
	}
	return syncSame(got, want)
}

// infSetup is Acme with one Anthropic provider, a frontier and a small model, and alice limited to small ones.
func (f *infFixture) infSetup() (provider, alice, role *core.Object, aliceSession core.CredentialInput) {
	f.t.Helper()
	api := f.iam.API.Inference
	provider = f.infObject(infCall(f, api.CreateProvider, f.owner, "name", "Anthropic", "kind", "anthropic", "apiKey", infProviderKey))
	f.infObject(infCall(f, api.CreateModel, f.owner, "name", "opus", "providerId", provider.Get("id"), "upstreamModel", "claude-opus-5-5",
		"tier", "frontier", "inputPricePerMTok", 5.0, "outputPricePerMTok", 25.0))
	f.infObject(infCall(f, api.CreateModel, f.owner, "name", "haiku", "providerId", provider.Get("id"), "upstreamModel", "claude-haiku-4-5",
		"tier", "small", "inputPricePerMTok", 1.0, "outputPricePerMTok", 5.0))
	alice = f.member("alice")
	role = f.createRole(f.owner, "name", "Small models", "document", obj(f.t, `{"version":1,"statements":[{"effect":"allow",
		"actions":["inference:invoke"],"resources":["model/*"],"conditions":{"StringEquals":{"resource.tier":"small"}}}]}`))
	f.bind(f.owner, role.Get("id"), "identity", alice.Get("id"))
	return provider, alice, role, f.login("alice")
}

// infPermit authorizes a model for a credential and expects a permit.
func (f *infFixture) infPermit(credential core.CredentialInput, model string) *core.Object {
	f.t.Helper()
	outcome, err := f.iam.Inference.Authorize(f.ctx, credential, core.NewObject("model", model))
	requirePorted(f.t, err)
	if outcome.Has("denied") {
		f.t.Fatalf("denied: %s", core.MustStringify(outcome.Get("denied")))
	}
	return outcome
}

func (f *infFixture) infRecord(permit *core.Object, usage string) *core.Object {
	f.t.Helper()
	record, err := f.iam.Inference.Record(f.ctx, permit, obj(f.t, usage))
	requirePorted(f.t, err)
	return record
}

func (f *infFixture) infCheck(credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	return f.infObject(infCall(f, f.iam.API.Inference.Check, credential, members...))
}

func TestInferenceSealsProviderKeysAndDecidesModelAccessWithOrdinaryPolicies(t *testing.T) {
	f := newInfFixture(t, nil)
	api := f.iam.API.Inference
	provider, _, _, aliceSession := f.infSetup()
	infSame(t, "provider", provider, `{"kind":"anthropic","baseUrl":"https://api.anthropic.com","keyHint":"…0042"}`)
	providers := f.infList(infCall(f, api.ListProviders, f.owner))
	if strings.Contains(core.MustStringify(providers), infProviderKey) {
		t.Fatal("listProviders leaked the provider key")
	}
	if strings.Contains(core.MustStringify(f.record("inferenceProviders", jsString(provider.Get("id")))), infProviderKey) {
		t.Fatal("the stored provider holds the key in the clear")
	}
	infSame(t, "opus", f.infCheck(aliceSession, "model", "opus"), `{"allowed":false,"reason":"ACCESS_DENIED"}`)
	allowed := f.infCheck(aliceSession, "model", "haiku")
	infSame(t, "haiku", allowed, `{"allowed":true,"model":{"name":"haiku","tier":"small","provider":{"name":"Anthropic","kind":"anthropic"}}}`)
	if _, ok := allowed.Get("ticket").(string); !ok {
		t.Fatalf("an allowed check carries a ticket: %s", core.MustStringify(allowed))
	}
	_, err := infCall(f, api.Check, aliceSession, "model", "nope")
	expectCodeOrSkip(t, err, "NOT_FOUND")
	names := func(models []*core.Object) string {
		out := []string{}
		for _, model := range models {
			out = append(out, jsString(model.Get("name")))
		}
		return strings.Join(out, ",")
	}
	if got := names(f.infList(infCall(f, api.ListMine, aliceSession))); got != "haiku" {
		t.Fatalf("alice's models: %s", got)
	}
	if got := names(f.infList(infCall(f, api.ListMine, f.owner))); got != "haiku,opus" {
		t.Fatalf("the owner's models: %s", got)
	}
	// The same decision through the generic authorize API.
	if !f.can(aliceSession, "inference:invoke", "model", "haiku") {
		t.Fatal("authorize must allow alice the small model")
	}
	// Disabling a model stops it for everyone.
	f.infObject(infCall(f, api.UpdateModel, f.owner, "name", "haiku", "enabled", false))
	infSame(t, "disabled", f.infCheck(aliceSession, "model", "haiku"), `{"allowed":false,"reason":"MODEL_DISABLED"}`)
	// The gateway runtime opens the key server-side only.
	owner := f.infPermit(f.owner, "opus")
	infSame(t, "permit", owner, `{"provider":{"apiKey":"`+infProviderKey+`","kind":"anthropic"},"upstreamModel":"claude-opus-5-5"}`)
}

func TestInferenceLetsOnlyRootPointProvidersAtCustomURLsAndInheritsModels(t *testing.T) {
	f := newInfFixture(t, nil)
	api := f.iam.API.Inference
	f.infSetup()
	_, err := infCall(f, api.CreateProvider, f.owner, "name", "Self hosted", "kind", "openai-compatible", "apiKey", "local-key-123456",
		"baseUrl", "https://llm.internal.example/v1")
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	// The platform defines a provider and model once, at the root tenant; organizations inherit them.
	shared := f.infObject(infCall(f, api.CreateProvider, f.credential, "tenantId", f.rootID, "name", "Platform vLLM", "kind", "openai-compatible",
		"apiKey", "platform-key-123456", "baseUrl", "https://llm.platform.example/v1"))
	f.infObject(infCall(f, api.CreateModel, f.credential, "tenantId", f.rootID, "name", "llama-local", "providerId", shared.Get("id"),
		"upstreamModel", "meta-llama/Llama-4", "tier", "small"))
	var inherited *core.Object
	for _, model := range f.infList(infCall(f, api.ListModels, f.owner)) {
		if model.Get("name") == "llama-local" {
			inherited = model
		}
	}
	infSame(t, "inherited model", inherited, `{"inherited":true,"provider":{"id":"`+jsString(shared.Get("id"))+`","kind":"openai-compatible"}}`)
	own := f.infList(infCall(f, api.ListProviders, f.owner))
	got := []string{}
	for _, item := range own {
		got = append(got, jsString(item.Get("name"))+":"+jsString(item.Get("inherited")))
	}
	if strings.Join(got, ",") != "Anthropic:false,Platform vLLM:true" {
		t.Fatalf("providers: %v", got)
	}
}

func TestInferenceIsRefusedWithoutTheInferenceOption(t *testing.T) {
	f := &infFixture{orgFixture: newOrgFixture(t, nil)}
	_, err := infCall(f, f.iam.API.Inference.ListModels, f.owner)
	expectCodeOrSkip(t, err, "FEATURE_DISABLED")
}

func TestInferenceMetersCallsRefusesExhaustedBudgetsAndReportsUsage(t *testing.T) {
	f := newInfFixture(t, nil)
	api := f.iam.API.Inference
	_, alice, _, aliceSession := f.infSetup()
	budget := f.infObject(infCall(f, api.SetBudget, f.owner, "name", "Daily per person", "subjectType", "tenant", "scope", "each",
		"period", "day", "maxTokens", 1000.0, "alertAtPercent", 80.0))
	infSame(t, "budget", budget, `{"subjectId":"`+f.tenantID+`","scope":"each","maxTokens":1000}`)
	used := f.infPermit(aliceSession, "haiku")
	budgets := aiObjects(member(used.Get("check"), "budgets"))
	if len(budgets) != 1 || !core.StrictEquals(budgets[0].Get("budgetId"), budget.Get("id")) || budgets[0].Get("remainingTokens") != 1000.0 {
		t.Fatalf("permit budgets: %s", core.MustStringify(budgets))
	}
	record := f.infRecord(used, `{"model":"haiku","inputTokens":600,"outputTokens":300}`)
	// 600 × $1 + 300 × $5 per million tokens = 2100 micro-dollars.
	infSame(t, "record", record, `{"identityId":"`+jsString(alice.Get("id"))+`","costMicros":2100,"status":"ok"}`)
	infSame(t, "fits", f.infCheck(aliceSession, "model", "haiku", "estimatedTokens", 50.0), `{"allowed":true}`)
	infSame(t, "refused", f.infCheck(aliceSession, "model", "haiku", "estimatedTokens", 200.0),
		`{"allowed":false,"reason":"BUDGET_EXCEEDED","budget":{"budgetId":"`+jsString(budget.Get("id"))+`","usedTokens":900,"remainingTokens":100}}`)
	f.infCheck(aliceSession, "model", "haiku", "estimatedTokens", 200.0)
	// The owner has their own share of an `each` budget.
	infSame(t, "owner share", f.infCheck(f.owner, "model", "haiku", "estimatedTokens", 900.0), `{"allowed":true}`)
	if got := len(f.auditTrail(f.tenantID, "inference:budget-exceeded")); got != 1 {
		t.Fatalf("budget-exceeded events: %d", got)
	}
	if len(f.auditTrail(f.tenantID, "inference:budget-alert")) == 0 {
		t.Fatal("expected an inference:budget-alert event")
	}
	report := f.infObject(infCall(f, api.Usage, f.owner, "groupBy", "identity"))
	infSame(t, "report rows", report.Get("rows"), `[{"key":"`+jsString(alice.Get("id"))+`","label":"alice@acme.test","requests":1,
		"inputTokens":600,"outputTokens":300,"costMicros":2100}]`)
	mine := f.infObject(infCall(f, api.MyUsage, aliceSession))
	infSame(t, "my totals", mine.Get("totals"), `{"requests":1,"costUsd":0.0021}`)
	infSame(t, "my budgets", mine.Get("budgets"), `[{"budgetId":"`+jsString(budget.Get("id"))+`","usedTokens":900}]`)
	// The next day starts a fresh window.
	f.clock.Add(86_400_000)
	fresh := f.login("alice")
	infSame(t, "next day", f.infCheck(fresh, "model", "haiku", "estimatedTokens", 900.0), `{"allowed":true}`)
}

func TestInferenceCapsAnAgentAcrossEverythingItDoes(t *testing.T) {
	f := newInfFixture(t, nil)
	api := f.iam.API.Inference
	_, alice, role, aliceSession := f.infSetup()
	agent := f.infObject(infCall(f, f.iam.API.Agents.Create, f.owner, "name", "Summarizer"))
	f.bind(f.owner, role.Get("id"), "identity", agent.Get("id"))
	key := f.infObject(infCall(f, f.iam.API.Credentials.Create, f.owner, "identityId", agent.Get("id")))
	cap := f.infObject(infCall(f, api.SetBudget, f.owner, "name", "Summarizer cap", "subjectType", "identity", "subjectId", agent.Get("id"),
		"period", "month", "maxCostUsd", 0.001))
	infSame(t, "cap", cap, `{"maxCostMicros":1000,"maxCostUsd":0.001}`)
	delegation := f.infObject(infCall(f, f.iam.API.Delegations.Grant, aliceSession, "agentId", agent.Get("id"), "scopes", []any{"inference:invoke"}))
	delegated := f.infObject(infCall(f, f.iam.API.Delegations.Assume, core.CredentialInput{Token: jsString(key.Get("token"))}, "delegationId", delegation.Get("id")))
	delegatedToken := core.CredentialInput{Token: jsString(delegated.Get("token"))}
	// Acting for alice: alice's access (small models only), metered to alice and to the agent.
	denied, err := f.iam.Inference.Authorize(f.ctx, delegatedToken, core.NewObject("model", "opus"))
	requirePorted(t, err)
	infSame(t, "delegated opus", denied, `{"denied":{"reason":"ACCESS_DENIED"}}`)
	record := f.infRecord(f.infPermit(delegatedToken, "haiku"), `{"model":"haiku","inputTokens":500,"outputTokens":100}`)
	infSame(t, "delegated record", record, `{"identityId":"`+jsString(alice.Get("id"))+`","agentId":"`+jsString(agent.Get("id"))+
		`","delegationId":"`+jsString(delegation.Get("id"))+`","sessionKind":"delegated","costMicros":1000}`)
	// The agent's cap is spent, for its own key too; alice herself is not capped.
	own, err := f.iam.Inference.Authorize(f.ctx, core.CredentialInput{Token: jsString(key.Get("token"))}, core.NewObject("model", "haiku"))
	requirePorted(t, err)
	infSame(t, "agent capped", own, `{"denied":{"reason":"BUDGET_EXCEEDED","budget":{"budgetId":"`+jsString(cap.Get("id"))+`"}}}`)
	if mine, err := f.iam.Inference.Authorize(f.ctx, aliceSession, core.NewObject("model", "haiku")); err != nil || mine.Has("denied") {
		t.Fatalf("alice is not capped: %v %s", err, core.MustStringify(mine))
	}
	// A call without an agent groups under '(none)'.
	f.infRecord(f.infPermit(aliceSession, "haiku"), `{"model":"haiku","inputTokens":1,"outputTokens":0}`)
	byAgent := f.infObject(infCall(f, api.Usage, f.owner, "groupBy", "agent"))
	infSame(t, "by agent", byAgent.Get("rows"), `[{"key":"`+jsString(agent.Get("id"))+`","label":"Summarizer","costMicros":1000},{"key":"(none)","requests":1}]`)
}

func TestInferenceRateLimitsCallsPerWindowWithMaxRequests(t *testing.T) {
	f := newInfFixture(t, nil)
	api := f.iam.API.Inference
	_, alice, _, aliceSession := f.infSetup()
	limit := f.infObject(infCall(f, api.SetBudget, f.owner, "name", "Three calls an hour", "subjectType", "identity", "subjectId", alice.Get("id"),
		"period", "hour", "maxRequests", 3.0))
	infSame(t, "limit", limit, `{"maxRequests":3,"standing":{"usedRequests":0,"remainingRequests":3}}`)
	for call := 0; call < 3; call++ {
		f.infRecord(f.infPermit(aliceSession, "haiku"), `{"model":"haiku","inputTokens":1,"outputTokens":1}`)
	}
	outcome, err := f.iam.Inference.Authorize(f.ctx, aliceSession, core.NewObject("model", "haiku"))
	requirePorted(t, err)
	infSame(t, "limited", outcome, `{"denied":{"reason":"BUDGET_EXCEEDED","budget":{"budgetId":"`+jsString(limit.Get("id"))+`","usedRequests":3,"remainingRequests":0}}}`)
	_, err = infCall(f, api.SetBudget, f.owner, "name", "Empty", "subjectType", "tenant", "period", "day")
	expectCodeOrSkip(t, err, "INVALID_INPUT")
	f.clock.Add(3_600_000)
	fresh := f.login("alice")
	if outcome, err := f.iam.Inference.Authorize(f.ctx, fresh, core.NewObject("model", "haiku")); err != nil || outcome.Has("denied") {
		t.Fatalf("a new window allows calls again: %v %s", err, core.MustStringify(outcome))
	}
}

func TestInferenceLetsAnExternalGatewayRedeemACheckTicketOnce(t *testing.T) {
	f := newInfFixture(t, nil)
	api := f.iam.API.Inference
	_, alice, _, aliceSession := f.infSetup()
	gateway := f.infObject(infCall(f, f.iam.API.ServiceAccounts.Create, f.owner, "name", "LLM gateway"))
	recorder := f.createRole(f.owner, "name", "Inference recorder", "document",
		obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["iam:inference:record"],"resources":["iam/*"]}]}`))
	f.bind(f.owner, recorder.Get("id"), "identity", gateway.Get("id"))
	gatewayKey := core.CredentialInput{Token: jsString(f.infObject(infCall(f, f.iam.API.Credentials.Create, f.owner, "identityId", gateway.Get("id"))).Get("token"))}
	check := f.infCheck(aliceSession, "model", "haiku")
	ticket, ok := check.Get("ticket").(string)
	if check.Get("allowed") != true || !ok {
		t.Fatalf("expected an allowed check: %s", core.MustStringify(check))
	}
	// Alice cannot meter her own calls.
	_, err := infCall(f, api.Record, aliceSession, "ticket", ticket, "inputTokens", 0.0, "outputTokens", 0.0)
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	recorded := f.infObject(infCall(f, api.Record, gatewayKey, "ticket", ticket, "inputTokens", 1000.0, "outputTokens", 1000.0))
	configSameJSON(t, "recorded", recorded, `{"recorded":true,"costMicros":6000}`)
	_, err = infCall(f, api.Record, gatewayKey, "ticket", ticket, "inputTokens", 1.0, "outputTokens", 1.0)
	expectCodeOrSkip(t, err, "INVALID_TICKET")
	report := f.infObject(infCall(f, api.Usage, f.owner, "identityId", alice.Get("id")))
	infSame(t, "totals", report.Get("totals"), `{"requests":1,"costMicros":6000}`)
}

// infPlatform is Acme with a provider the platform defines at the root tenant.
func infPlatform(t *testing.T, allowCustomBaseUrls bool) (*infFixture, *core.Object) {
	f := newInfFixture(t, func(options *BetterIamOptions) {
		settings := InferenceOptions{}
		if allowCustomBaseUrls {
			settings.AllowCustomBaseUrls = flag(true)
		}
		options.Inference = With(settings)
	})
	provider := f.infObject(infCall(f, f.iam.API.Inference.CreateProvider, f.credential, "tenantId", f.rootID, "name", "Platform Anthropic",
		"kind", "anthropic", "apiKey", "sk-ant-platform-owned-key-9999"))
	return f, provider
}

func TestInferenceKeepsModelsOnAParentProviderInThePlatformsHands(t *testing.T) {
	f, provider := infPlatform(t, false)
	api := f.iam.API.Inference
	_, err := infCall(f, api.CreateModel, f.owner, "name", "opus", "providerId", provider.Get("id"), "upstreamModel", "claude-opus-5-5",
		"inputPricePerMTok", 0.0, "outputPricePerMTok", 0.0)
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	// The platform may set one up for the organization; the organization may turn it off, not reprice it.
	f.infObject(infCall(f, api.CreateModel, f.credential, "name", "opus", "providerId", provider.Get("id"), "upstreamModel", "claude-opus-5-5",
		"inputPricePerMTok", 5.0, "outputPricePerMTok", 25.0))
	_, err = infCall(f, api.UpdateModel, f.owner, "name", "opus", "inputPricePerMTok", 0.0)
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	off := f.infObject(infCall(f, api.UpdateModel, f.owner, "name", "opus", "enabled", false))
	infSame(t, "disabled", off, `{"enabled":false}`)
}

func TestInferenceLetsOnlyThePlatformChangeABudgetItSet(t *testing.T) {
	f, _ := infPlatform(t, false)
	api := f.iam.API.Inference
	cap := f.infObject(infCall(f, api.SetBudget, f.credential, "name", "Platform cap", "subjectType", "tenant", "period", "month", "maxCostUsd", 1.0))
	_, err := infCall(f, api.DeleteBudget, f.owner, "budgetId", cap.Get("id"))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	_, err = infCall(f, api.SetBudget, f.owner, "budgetId", cap.Get("id"), "name", "Platform cap", "subjectType", "tenant", "period", "month",
		"maxCostUsd", 1_000_000.0)
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	// The organization's own budgets stay its own.
	own := f.infObject(infCall(f, api.SetBudget, f.owner, "name", "Team cap", "subjectType", "tenant", "period", "day", "maxTokens", 1000.0))
	infSame(t, "own delete", f.infObject(infCall(f, api.DeleteBudget, f.owner, "budgetId", own.Get("id"))), `{"deleted":true}`)
	infSame(t, "platform delete", f.infObject(infCall(f, api.DeleteBudget, f.credential, "budgetId", cap.Get("id"))), `{"deleted":true}`)
}

func TestInferenceNeedsTheProviderKeyAgainToMoveAProvider(t *testing.T) {
	f, _ := infPlatform(t, true)
	api := f.iam.API.Inference
	provider := f.infObject(infCall(f, api.CreateProvider, f.owner, "name", "Self-hosted", "kind", "openai-compatible",
		"apiKey", "org-secret-key-1234", "baseUrl", "https://llm.acme.example"))
	_, err := infCall(f, api.UpdateProvider, f.owner, "providerId", provider.Get("id"), "baseUrl", "https://collector.evil.example")
	expectCodeOrSkip(t, err, "INVALID_INPUT")
	moved := f.infObject(infCall(f, api.UpdateProvider, f.owner, "providerId", provider.Get("id"), "baseUrl", "https://llm2.acme.example",
		"apiKey", "org-secret-key-5678"))
	infSame(t, "moved", moved, `{"baseUrl":"https://llm2.acme.example"}`)
	f.infObject(infCall(f, api.CreateModel, f.owner, "name", "local", "providerId", provider.Get("id"), "upstreamModel", "llama"))
	f.object(f.iam.API.Policies.Create(f.ctx, f.owner, Input[apitypes.PoliciesCreateInput](core.NewObject("tenantId", f.tenantID, "name", "Models",
		"document", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["inference:invoke"],"resources":["*"]}]}`)))))
	permit := f.infPermit(f.owner, "local")
	infSame(t, "guard", member(permit.Get("provider"), "guard"), `{"anyPort":true,"allowPrivateNetworks":false}`)
}

func TestInferenceCountsWhatAgentsDoForPeopleAgainstAGroupBudget(t *testing.T) {
	f := newInfFixture(t, nil)
	api := f.iam.API.Inference
	provider := f.infObject(infCall(f, api.CreateProvider, f.owner, "name", "Anthropic", "kind", "anthropic", "apiKey", "sk-ant-org-key-000000"))
	f.infObject(infCall(f, api.CreateModel, f.owner, "name", "haiku", "providerId", provider.Get("id"), "upstreamModel", "claude-haiku-4-5"))
	invoke := f.createRole(f.owner, "name", "Models", "document",
		obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["inference:invoke"],"resources":["model/*"]}]}`))
	alice := f.member("alice")
	agent := f.infObject(infCall(f, f.iam.API.Agents.Create, f.owner, "name", "Looper"))
	for _, subjectID := range []any{alice.Get("id"), agent.Get("id")} {
		f.bind(f.owner, invoke.Get("id"), "identity", subjectID)
	}
	bots := f.createGroup("Bots")
	if _, err := f.addMember("groupId", bots.Get("id"), "identityId", agent.Get("id")); err != nil {
		requirePorted(t, err)
	}
	f.infObject(infCall(f, api.SetBudget, f.owner, "name", "Bots: 2 calls a day", "subjectType", "group", "subjectId", bots.Get("id"),
		"period", "day", "maxRequests", 2.0))
	key := core.CredentialInput{Token: jsString(f.infObject(infCall(f, f.iam.API.Credentials.Create, f.owner, "identityId", agent.Get("id"))).Get("token"))}
	f.infRecord(f.infPermit(key, "haiku"), `{"model":"haiku","inputTokens":10,"outputTokens":10}`)
	aliceSession := f.login("alice")
	delegation := f.infObject(infCall(f, f.iam.API.Delegations.Grant, aliceSession, "agentId", agent.Get("id"), "scopes", []any{"inference:invoke"}))
	delegated := core.CredentialInput{Token: jsString(f.infObject(infCall(f, f.iam.API.Delegations.Assume, key, "delegationId", delegation.Get("id"))).Get("token"))}
	f.infRecord(f.infPermit(delegated, "haiku"), `{"model":"haiku","inputTokens":10,"outputTokens":10}`)
	// Two calls used the group's allowance, whichever credential made them.
	for _, credential := range []core.CredentialInput{delegated, key} {
		outcome, err := f.iam.Inference.Authorize(f.ctx, credential, core.NewObject("model", "haiku"))
		requirePorted(t, err)
		infSame(t, "group budget", outcome, `{"denied":{"reason":"BUDGET_EXCEEDED"}}`)
	}
}

// Unit-level helpers.

func TestInferenceUsageAggregateOrdersRowsAndRoundsCosts(t *testing.T) {
	records := []*core.Object{
		obj(t, `{"identityId":"u1","model":"haiku","inputTokens":10,"outputTokens":5,"costMicros":0.0006,"createdAt":86400000,"status":"ok"}`),
		obj(t, `{"identityId":"u2","agentId":"a1","model":"opus","inputTokens":100,"outputTokens":50,"cacheReadTokens":7,"costMicros":2500.5,"createdAt":172800001,"status":"error"}`),
		obj(t, `{"identityId":"u1","model":"haiku","inputTokens":1,"outputTokens":1,"costMicros":0.0006,"createdAt":90000000}`),
	}
	byModel := aggregate(records, "model", 0, 200_000_000, map[string]string{})
	configSameJSON(t, "by model", byModel, `{"from":0,"to":200000000,"groupBy":"model","rows":[
		{"key":"opus","requests":1,"errors":1,"inputTokens":100,"outputTokens":50,"cacheReadTokens":7,"cacheWriteTokens":0,"costMicros":2500.5,"costUsd":0.002501},
		{"key":"haiku","requests":2,"errors":0,"inputTokens":11,"outputTokens":6,"cacheReadTokens":0,"cacheWriteTokens":0,"costMicros":0.002,"costUsd":0}],
		"totals":{"key":"total","requests":3,"errors":1,"inputTokens":111,"outputTokens":56,"cacheReadTokens":7,"cacheWriteTokens":0,"costMicros":2500.502,"costUsd":0.002501}}`)
	byAgent := aggregate(records, "agent", 0, 1, map[string]string{"a1": "Bot"})
	configSameJSON(t, "by agent", byAgent.Get("rows"), `[
		{"key":"a1","label":"Bot","requests":1,"errors":1,"inputTokens":100,"outputTokens":50,"cacheReadTokens":7,"cacheWriteTokens":0,"costMicros":2500.5,"costUsd":0.002501},
		{"key":"(none)","requests":2,"errors":0,"inputTokens":11,"outputTokens":6,"cacheReadTokens":0,"cacheWriteTokens":0,"costMicros":0.002,"costUsd":0}]`)
	byDay := aggregate(records, "day", 0, 1, nil)
	keys := []string{}
	for _, row := range aiObjects(byDay.Get("rows")) {
		keys = append(keys, jsString(row.Get("key")))
	}
	if strings.Join(keys, ",") != "1970-01-03,1970-01-02" {
		t.Fatalf("day keys: %v", keys)
	}
	// Ties fall back to requests, then the key.
	ties := aggregate([]*core.Object{
		obj(t, `{"identityId":"b","model":"m","inputTokens":0,"outputTokens":0,"costMicros":0}`),
		obj(t, `{"identityId":"a","model":"m","inputTokens":0,"outputTokens":0,"costMicros":0}`),
	}, "identity", 0, 1, map[string]string{})
	if first := aiObjects(ties.Get("rows"))[0].Get("key"); first != "a" {
		t.Fatalf("ties order by key: %v", first)
	}
}

func TestInferenceKeyHintAndPermitPrincipal(t *testing.T) {
	if got := inferenceKeyHint("sk-ant-secret-provider-key-0042"); got != "…0042" {
		t.Fatalf("key hint: %s", got)
	}
	identity := obj(t, `{"id":"u1"}`)
	session := obj(t, `{"id":"s1"}`)
	principal := PermitPrincipal(core.NewObject("principal", core.NewObject("identity", identity, "session", session)))
	if principal == nil || principal.Identity != identity || principal.Session != session {
		t.Fatal("PermitPrincipal reads { identity, session }")
	}
	raw := &Principal{Identity: identity, Session: session}
	if PermitPrincipal(core.NewObject().SetRaw("principal", raw)) != raw {
		t.Fatal("PermitPrincipal keeps a raw principal")
	}
	if PermitPrincipal(core.NewObject()) != nil {
		t.Fatal("no principal")
	}
}

func TestInferenceApplyModelFields(t *testing.T) {
	mutations, _ := InferenceMutations(nil)
	next := obj(t, `{"name":"opus","upstreamModel":"a","displayName":"Old","tier":"x","enabled":true}`)
	if err := mutations.ApplyModelFields(next, obj(t, `{"displayName":null,"family":"claude","tier":"frontier","contextWindow":200000,
		"upstreamModel":"claude-opus","providerTools":"allow","enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	configSameJSON(t, "applied", next, `{"name":"opus","upstreamModel":"claude-opus","tier":"frontier","enabled":false,"family":"claude","contextWindow":200000}`)
	for _, c := range []struct{ input, message string }{
		{`{"tier":"not an identifier"}`, "tier must be a short identifier"},
		{`{"family":""}`, "Invalid family"},
		{`{"contextWindow":0}`, "Invalid contextWindow"},
		{`{"maxOutputTokens":1.5}`, "Invalid maxOutputTokens"},
		{`{"upstreamModel":7}`, "Invalid upstreamModel"},
		{`{"providerTools":"sometimes"}`, "providerTools must be 'allow', 'deny' or 'policy'"},
		{`{"enabled":"yes"}`, "enabled must be a boolean"},
	} {
		expectError(t, mutations.ApplyModelFields(obj(t, `{"name":"m"}`), obj(t, c.input)), "INVALID_INPUT", c.message)
	}
	tools := obj(t, `{"name":"m","providerTools":"deny"}`)
	if err := mutations.ApplyModelFields(tools, obj(t, `{"providerTools":"policy"}`)); err != nil {
		t.Fatal(err)
	}
	if tools.Get("providerTools") != "policy" {
		t.Fatalf("providerTools: %v", tools.Get("providerTools"))
	}
	if err := mutations.ApplyModelFields(tools, obj(t, `{"providerTools":null}`)); err != nil || tools.Has("providerTools") {
		t.Fatalf("null clears providerTools: %v", err)
	}
	// Fallbacks and prices go through inference.ts (modelName, price).
	err := mutations.ApplyModelFields(obj(t, `{"name":"m"}`), obj(t, `{"fallbacks":["m"]}`))
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
	expectError(t, err, "INVALID_INPUT", "A model cannot fall back to itself")
	expectError(t, mutations.ApplyModelFields(obj(t, `{"name":"m"}`), obj(t, `{"fallbacks":["a","b","c","d","e","f"]}`)), "INVALID_INPUT",
		"fallbacks may name at most 5 models")
	cleared := obj(t, `{"name":"m","fallbacks":["a"]}`)
	if err := mutations.ApplyModelFields(cleared, obj(t, `{"fallbacks":[]}`)); err != nil || cleared.Has("fallbacks") {
		t.Fatalf("an empty list clears fallbacks: %v", err)
	}
}

func TestInferenceBudgetFieldsValidateInTheTypeScriptOrder(t *testing.T) {
	// Budget fields need no inference option: only maxCostUsd goes through inference.ts (price).
	f := &infFixture{orgFixture: newOrgFixture(t, nil)}
	mutations, _ := InferenceMutations(f.iam.Context)
	fields := func(input string, previous *core.Object) (*core.Object, error) {
		var result *core.Object
		err := f.store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
			var err error
			result, err = mutations.BudgetFields(ctx, tx, f.tenantID, obj(t, input), previous)
			return err
		})
		return result, err
	}
	for _, c := range []struct{ input, message string }{
		{`{}`, "Invalid name"},
		{`{"name":"B"}`, "subjectType must be 'tenant', 'group' or 'identity'"},
		{`{"name":"B","subjectType":"group"}`, "Invalid subjectId"},
		{`{"name":"B","subjectType":"tenant","scope":"all"}`, "scope must be 'shared' or 'each'"},
		{`{"name":"B","subjectType":"tenant"}`, "period must be 'minute', 'hour', 'day' or 'month'"},
		{`{"name":"B","subjectType":"tenant","period":"day"}`, "A budget needs at least one of maxTokens, maxCostUsd and maxRequests"},
		{`{"name":"B","subjectType":"tenant","period":"day","maxTokens":0}`, "Invalid maxTokens"},
		{`{"name":"B","subjectType":"tenant","period":"day","maxRequests":1e10}`, "Invalid maxRequests"},
		{`{"name":"B","subjectType":"tenant","period":"day","maxTokens":5,"models":["-bad"]}`, "Invalid model pattern -bad"},
		{`{"name":"B","subjectType":"tenant","period":"day","maxTokens":5,"alertAtPercent":101}`, "Invalid alertAtPercent"},
	} {
		_, err := fields(c.input, nil)
		expectError(t, err, "INVALID_INPUT", c.message)
	}
	_, err := fields(`{"name":"B","subjectType":"group","subjectId":"missing","period":"day","maxTokens":5}`, nil)
	expectError(t, err, "NOT_FOUND", "Resource not found")
	got, err := fields(`{"name":"  Daily  ","subjectType":"tenant","period":"day","maxTokens":5,"models":["opus*","opus*","haiku"],"alertAtPercent":null}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	configSameJSON(t, "fields", got, `{"uniqueKey":"name:daily","name":"Daily","subjectType":"tenant","subjectId":"`+f.tenantID+`",
		"scope":"shared","period":"day","maxTokens":5,"models":["opus*","haiku"]}`)
	// A replacement keeps what the input leaves out and clears what it sets to null.
	previous := obj(t, `{"id":"b1","name":"Daily","subjectType":"identity","subjectId":"`+f.ownerID+`","scope":"shared","period":"hour",
		"maxTokens":10,"maxRequests":3,"models":["opus"],"alertAtPercent":50}`)
	got, err = fields(`{"maxTokens":null,"scope":"each","models":null}`, previous)
	if err != nil {
		t.Fatal(err)
	}
	configSameJSON(t, "replacement", got, `{"uniqueKey":"name:daily","name":"Daily","subjectType":"identity","subjectId":"`+f.ownerID+`",
		"scope":"shared","period":"hour","maxRequests":3,"alertAtPercent":50}`)
}
