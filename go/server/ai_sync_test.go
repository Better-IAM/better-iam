package server

// AI configuration sync tests, after tests/config-ai.test.ts: agents, models and budgets applied from a document and
// exported back unchanged, updates in place and pruning, and documents naming things that do not exist; plus the
// document parsers, exportAi and planAi over a fixed state. Steps that reach another unit's NOT_IMPLEMENTED stub skip
// the rest of their test until that unit is ported.

import (
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func aiItems(t *testing.T, text string) []*core.Object {
	t.Helper()
	return aiObjects(parse(t, text))
}

func TestParseAgentsConfigNormalizesAndRefuses(t *testing.T) {
	agents, err := ParseAgentsConfig(aiItems(t, `[
		{"name":"Triage","sponsor":"Alice@Acme.test","provider":"Anthropic","protocols":["MCP","a2a","mcp"],"delegable":true,
		 "maxDelegatedSessionSeconds":1800,"boundary":{"version":1,"statements":[]},"description":null,"tokenAudiences":["https://tickets.example.com"]},
		{"name":"Reporter","sponsor":"bob@acme.test","delegable":false}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	configSameJSON(t, "agents", objectList(agents), `[
		{"name":"Triage","sponsor":"alice@acme.test","provider":"anthropic","protocols":["a2a","mcp"],"maxDelegatedSessionSeconds":1800,
		 "boundary":{"version":1,"statements":[]},"tokenAudiences":["https://tickets.example.com"]},
		{"name":"Reporter","sponsor":"bob@acme.test","delegable":false}]`)
	if strings.Join(agents[0].Keys(), ",") != "name,sponsor,provider,protocols,maxDelegatedSessionSeconds,boundary,tokenAudiences" {
		t.Fatalf("member order: %v", agents[0].Keys())
	}
	for _, c := range []struct{ items, message string }{
		{`[{"sponsor":"a@acme.test"}]`, "Invalid agent name"},
		{`[{"name":"A"}]`, "Invalid Agent A sponsor"},
		{`[{"name":"A","sponsor":"a@acme.test","delegable":"no"}]`, "Agent A: delegable must be a boolean"},
		{`[{"name":"A","sponsor":"a@acme.test","boundary":[]}]`, "Expected an object"},
		{`[{"name":"A","sponsor":"a@acme.test","maxDelegatedSessionSeconds":30}]`, "Invalid Agent A maxDelegatedSessionSeconds"},
		{`[{"name":"A","sponsor":"a@acme.test","purpose":""}]`, "Invalid Agent A purpose"},
		{`[{"name":"Twin","sponsor":"a@acme.test"},{"name":" twin","sponsor":"a@acme.test"}]`, "Duplicate agent  twin"},
	} {
		_, err := ParseAgentsConfig(aiItems(t, c.items))
		expectError(t, err, "INVALID_INPUT", c.message)
	}
}

func TestParseModelsConfigNormalizesAndRefuses(t *testing.T) {
	models, err := ParseModelsConfig(aiItems(t, `[
		{"name":"sonnet","provider":"Anthropic","upstreamModel":"claude-sonnet-5","tier":"frontier","maxOutputTokens":8000,
		 "inputPricePerMTok":3,"providerTools":"allow","enabled":true,"fallbacks":["haiku","haiku"]},
		{"name":"haiku","provider":"Anthropic","upstreamModel":"claude-haiku-4-5","enabled":false,"providerTools":"policy"}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	configSameJSON(t, "models", objectList(models), `[
		{"name":"sonnet","provider":"Anthropic","upstreamModel":"claude-sonnet-5","tier":"frontier","maxOutputTokens":8000,"inputPricePerMTok":3,
		 "fallbacks":["haiku","haiku"]},
		{"name":"haiku","provider":"Anthropic","upstreamModel":"claude-haiku-4-5","providerTools":"policy","enabled":false}]`)
	for _, c := range []struct{ items, message string }{
		{`[{"name":"m","provider":"A","upstreamModel":"x","enabled":1}]`, "Model m: enabled must be a boolean"},
		{`[{"name":"m","upstreamModel":"x"}]`, "Invalid Model m provider"},
		{`[{"name":"m","provider":"A"}]`, "Invalid Model m upstreamModel"},
		{`[{"name":"m","provider":"A","upstreamModel":"x","contextWindow":0}]`, "Invalid Model m contextWindow"},
		{`[{"name":"m","provider":"A","upstreamModel":"x","outputPricePerMTok":-1}]`, "Model m: outputPricePerMTok must be a non-negative number"},
		{`[{"name":"m","provider":"A","upstreamModel":"x","providerTools":"maybe"}]`, "Model m: providerTools must be 'allow', 'deny' or 'policy'"},
		{`[{"name":"m","provider":"A","upstreamModel":"x"},{"name":"M","provider":"A","upstreamModel":"x"}]`, "Duplicate model M"},
	} {
		_, err := ParseModelsConfig(aiItems(t, c.items))
		expectError(t, err, "INVALID_INPUT", c.message)
	}
}

func TestParseBudgetsConfigNormalizesAndRefuses(t *testing.T) {
	budgets, err := ParseBudgetsConfig(aiItems(t, `[
		{"name":" Engineers daily ","subject":{"group":"Engineers"},"scope":"each","period":"day","maxCostUsd":20},
		{"name":"Triage rate","subject":{"agent":"Triage"},"scope":"each","period":"minute","maxRequests":30},
		{"name":"Alice","subject":{"identity":"Alice@Acme.test"},"period":"hour","maxTokens":5},
		{"name":"Tenant monthly","subject":"tenant","scope":"shared","period":"month","maxTokens":10000000,"models":["sonnet","haiku","sonnet"],"alertAtPercent":80}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	configSameJSON(t, "budgets", objectList(budgets), `[
		{"name":"Engineers daily","subject":{"group":"Engineers"},"scope":"each","period":"day","maxCostUsd":20},
		{"name":"Triage rate","subject":{"agent":"Triage"},"period":"minute","maxRequests":30},
		{"name":"Alice","subject":{"identity":"alice@acme.test"},"period":"hour","maxTokens":5},
		{"name":"Tenant monthly","subject":"tenant","period":"month","maxTokens":10000000,"models":["haiku","sonnet"],"alertAtPercent":80}]`)
	for _, c := range []struct{ items, message string }{
		{`[{"name":"B","subject":"tenant","period":"week","maxTokens":1}]`, "Budget B: period must be minute, hour, day or month"},
		{`[{"name":"B","subject":"tenant","period":"day","scope":"all","maxTokens":1}]`, "Budget B: scope must be shared or each"},
		{`[{"name":"B","subject":{"team":"x"},"period":"day","maxTokens":1}]`, "Budget B: subject must be 'tenant', { group }, { identity } or { agent }"},
		{`[{"name":"B","subject":"everyone","period":"day","maxTokens":1}]`, "Expected an object"},
		{`[{"name":"B","subject":"tenant","period":"day"}]`, "Budget B: set maxTokens, maxCostUsd or maxRequests"},
		{`[{"name":"B","subject":"tenant","period":"day","maxTokens":0}]`, "Invalid Budget B maxTokens"},
		{`[{"name":"B","subject":"tenant","period":"day","maxTokens":1},{"name":"b","subject":"tenant","period":"day","maxTokens":1}]`, "Duplicate budget b"},
	} {
		_, err := ParseBudgetsConfig(aiItems(t, c.items))
		expectError(t, err, "INVALID_INPUT", c.message)
	}
}

// aiState is a fixed readAiState result: two agents, a model on a provider, and three budgets.
func aiState(t *testing.T, inference bool) *core.Object {
	t.Helper()
	state := obj(t, `{
		"agents":[
			{"id":"ag1","name":"Reporter","kind":"agent","status":"active","agent":{"sponsorId":"u2","delegable":false}},
			{"id":"ag2","name":"Triage","kind":"agent","status":"active","description":"Sorts","agent":{"sponsorId":"u1","purpose":"Sorts incoming tickets",
			 "provider":"anthropic","protocols":["a2a","mcp"],"maxDelegatedSessionSeconds":1800,"tokenAudiences":[]}}],
		"models":[{"id":"m1","name":"sonnet","providerId":"p1","upstreamModel":"claude-sonnet-5","tier":"frontier","outputPricePerMTok":15,
			"fallbacks":[],"providerTools":"policy","enabled":true}],
		"providers":[{"id":"p1","name":"Anthropic"}],
		"budgets":[
			{"id":"b1","name":"Engineers daily","subjectType":"group","subjectId":"g1","scope":"each","period":"day","maxCostMicros":20000000},
			{"id":"b2","name":"Tenant monthly","subjectType":"tenant","subjectId":"t1","scope":"shared","period":"month","maxTokens":10000000,
			 "models":["sonnet","haiku"],"alertAtPercent":80},
			{"id":"b3","name":"Triage rate","subjectType":"identity","subjectId":"ag2","scope":"shared","period":"minute","maxRequests":30}]
	}`)
	state.Set("inference", inference)
	return state
}

func aiNames() *core.Object {
	return syncAiNames(map[string]string{"u1": "alice@acme.test", "u2": "bob@acme.test"}, map[string]string{"g1": "Engineers"})
}

func aiEnv(prune bool, groups ...string) *core.Object {
	env := aiNames()
	env.SetRaw("identitiesByEmail", map[string]*core.Object{
		"alice@acme.test": core.NewObject("id", "u1", "kind", "user"),
		"bob@acme.test":   core.NewObject("id", "u2", "kind", "user"),
		"svc@acme.test":   core.NewObject("id", "s1", "kind", "service"),
	})
	env.SetRaw("groupNamesAfter", newOrderedSet(groups...))
	env.SetRaw("prune", prune)
	return env
}

func aiChangeLines(plan *core.Object) []string {
	lines := []string{}
	for _, key := range []string{"agents", "models", "budgets"} {
		for _, item := range aiObjects(plan.Get(key)) {
			change := item.Get("change").(*core.Object)
			lines = append(lines, jsString(change.Get("kind"))+":"+jsString(change.Get("name"))+":"+jsString(change.Get("action"))+":"+
				strings.Join(syncStringList(change.Get("fields")), ","))
		}
	}
	return lines
}

func TestExportAiAndPlanAiConverge(t *testing.T) {
	state := aiState(t, true)
	exported, err := ExportAi(state, aiNames())
	if err != nil {
		t.Fatal(err)
	}
	configSameJSON(t, "export", exported, `{
		"agents":[{"name":"Reporter","sponsor":"bob@acme.test","delegable":false},
			{"name":"Triage","sponsor":"alice@acme.test","description":"Sorts","purpose":"Sorts incoming tickets","provider":"anthropic",
			 "protocols":["a2a","mcp"],"maxDelegatedSessionSeconds":1800}],
		"inferenceModels":[{"name":"sonnet","provider":"Anthropic","upstreamModel":"claude-sonnet-5","tier":"frontier","outputPricePerMTok":15,"providerTools":"policy"}],
		"inferenceBudgets":[
			{"name":"Engineers daily","subject":{"group":"Engineers"},"scope":"each","period":"day","maxCostUsd":20},
			{"name":"Tenant monthly","subject":"tenant","period":"month","maxTokens":10000000,"models":["haiku","sonnet"],"alertAtPercent":80},
			{"name":"Triage rate","subject":{"agent":"Triage"},"period":"minute","maxRequests":30}]}`)
	// The export reads back as the same document: planning it changes nothing.
	plan, err := PlanAi(exported, state, aiEnv(true, "Engineers"))
	if err != nil {
		t.Fatal(err)
	}
	configLines(t, "unchanged", aiChangeLines(plan),
		"agent:Reporter:unchanged:", "agent:Triage:unchanged:", "inferenceModel:sonnet:unchanged:",
		"inferenceBudget:Engineers daily:unchanged:", "inferenceBudget:Tenant monthly:unchanged:", "inferenceBudget:Triage rate:unchanged:")
	// Nothing for a tenant without AI.
	empty, _ := ExportAi(obj(t, `{"agents":[],"models":[],"providers":[],"budgets":[],"inference":false}`), aiNames())
	if empty.Len() != 0 {
		t.Fatalf("empty export: %s", core.MustStringify(empty))
	}
}

func TestPlanAiUpdatesCreatesAndPrunes(t *testing.T) {
	state := aiState(t, true)
	desired := obj(t, `{"version":1,
		"agents":[{"name":"triage","sponsor":"bob@acme.test","purpose":"Routes tickets","provider":"anthropic","protocols":["a2a","mcp"],
			"maxDelegatedSessionSeconds":1800,"description":"Sorts"},{"name":"Scout","sponsor":"alice@acme.test"}],
		"inferenceModels":[{"name":"sonnet","provider":"Anthropic","upstreamModel":"claude-sonnet-5","tier":"frontier","outputPricePerMTok":12,"providerTools":"policy"}],
		"inferenceBudgets":[{"name":"Scout rate","subject":{"agent":"Scout"},"period":"minute","maxRequests":10},
			{"name":"triage rate","subject":{"agent":"Triage"},"period":"minute","maxRequests":10}]}`)
	plan, err := PlanAi(desired, state, aiEnv(true, "Engineers"))
	if err != nil {
		t.Fatal(err)
	}
	configLines(t, "changes", aiChangeLines(plan),
		"agent:triage:update:name,purpose,sponsor", "agent:Scout:create:", "agent:Reporter:delete:",
		"inferenceModel:sonnet:update:outputPricePerMTok",
		"inferenceBudget:Scout rate:create:", "inferenceBudget:triage rate:update:maxRequests,name",
		"inferenceBudget:Engineers daily:delete:", "inferenceBudget:Tenant monthly:delete:")
	agents := aiObjects(plan.Get("agents"))
	if !agents[0].Has("record") || !agents[0].Has("desired") || agents[1].Has("record") || agents[2].Has("desired") {
		t.Fatalf("planned items: %s", core.MustStringify(plan.Get("agents")))
	}
	deleted := agents[2].Get("change").(*core.Object)
	configSameJSON(t, "delete change", deleted, `{"kind":"agent","name":"Reporter","action":"delete","before":{"name":"Reporter","sponsor":"bob@acme.test","delegable":false}}`)
	created := agents[1].Get("change").(*core.Object)
	configSameJSON(t, "create change", created, `{"kind":"agent","name":"Scout","action":"create","after":{"name":"Scout","sponsor":"alice@acme.test"}}`)
	// Without prune, kinds keep what the document leaves out; kinds the document omits are left alone.
	plan, err = PlanAi(obj(t, `{"version":1,"agents":[{"name":"Reporter","sponsor":"bob@acme.test","delegable":false}]}`), state, aiEnv(false))
	if err != nil {
		t.Fatal(err)
	}
	configLines(t, "agents only", aiChangeLines(plan), "agent:Reporter:unchanged:")
}

func TestPlanAiRefusesDocumentsNamingThingsThatDoNotExist(t *testing.T) {
	state := aiState(t, true)
	for _, c := range []struct{ desired, message string }{
		{`{"agents":[{"name":"Ghost","sponsor":"nobody@acme.test"}]}`, "Agent Ghost: no person nobody@acme.test"},
		{`{"agents":[{"name":"Bot","sponsor":"svc@acme.test"}]}`, "Agent Bot: no person svc@acme.test"},
		{`{"inferenceModels":[{"name":"x","provider":"Missing","upstreamModel":"x-1"}]}`, "Model x: no provider named Missing (create providers through the API)"},
		{`{"inferenceBudgets":[{"name":"B","subject":{"agent":"Nobody"},"period":"day","maxRequests":1}]}`, "Budget B: no agent Nobody"},
		{`{"inferenceBudgets":[{"name":"B","subject":{"group":"Nobody"},"period":"day","maxRequests":1}]}`, "Budget B: no group Nobody"},
		{`{"inferenceBudgets":[{"name":"B","subject":{"identity":"x@acme.test"},"period":"day","maxRequests":1}]}`, "Budget B: no identity x@acme.test"},
	} {
		_, err := PlanAi(obj(t, c.desired), state, aiEnv(false))
		expectError(t, err, "INVALID_INPUT", c.message)
	}
	// A budget may name an agent the same document creates.
	if _, err := PlanAi(obj(t, `{"agents":[{"name":"Scout","sponsor":"alice@acme.test"}],
		"inferenceBudgets":[{"name":"B","subject":{"agent":"scout"},"period":"day","maxRequests":1}]}`), state, aiEnv(false)); err != nil {
		t.Fatal(err)
	}
	twins := aiState(t, true)
	twins.Set("agents", []any{obj(t, `{"id":"a","name":"Twin"}`), obj(t, `{"id":"b","name":"twin "}`)})
	_, err := PlanAi(obj(t, `{"agents":[]}`), twins, aiEnv(false))
	expectError(t, err, "INVALID_INPUT", "More than one agent is named twin ; rename one before syncing agents")
	_, err = PlanAi(obj(t, `{"inferenceBudgets":[]}`), aiState(t, false), aiEnv(false))
	expectError(t, err, "INVALID_INPUT", "inferenceModels and inferenceBudgets need the inference option on this deployment")
}

// Through the config API (tests/config-ai.test.ts).

const aiBaseConfig = `{
  "version": 1,
  "groups": [{ "name": "Engineers", "members": ["alice@acme.test"] }],
  "agents": [
    { "name": "Triage", "sponsor": "alice@acme.test", "purpose": "Sorts incoming tickets", "model": "claude-sonnet-5", "provider": "anthropic",
      "protocols": ["a2a", "mcp"], "maxDelegatedSessionSeconds": 1800,
      "boundary": { "version": 1, "statements": [{ "effect": "allow", "actions": ["documents:*"], "resources": ["document/*"] }] },
      "tokenAudiences": ["https://tickets.example.com"] },
    { "name": "Reporter", "sponsor": "bob@acme.test", "delegable": false }
  ],
  "inferenceModels": [
    { "name": "sonnet", "provider": "Anthropic", "upstreamModel": "claude-sonnet-5", "tier": "frontier", "maxOutputTokens": 8000,
      "inputPricePerMTok": 3, "outputPricePerMTok": 15, "providerTools": "policy" },
    { "name": "haiku", "provider": "Anthropic", "upstreamModel": "claude-haiku-4-5", "enabled": false }
  ],
  "inferenceBudgets": [
    { "name": "Engineers daily", "subject": { "group": "Engineers" }, "scope": "each", "period": "day", "maxCostUsd": 20 },
    { "name": "Triage rate", "subject": { "agent": "Triage" }, "period": "minute", "maxRequests": 30 },
    { "name": "Tenant monthly", "subject": "tenant", "period": "month", "maxTokens": 10000000, "models": ["sonnet"], "alertAtPercent": 80 }
  ]
}`

// aiScenario is Acme with alice and bob and (with inference) an Anthropic provider.
func aiScenario(t *testing.T, inference bool) *configFixture {
	t.Helper()
	if inference {
		if _, err := InferencePlugins(&BetterIamOptions{Inference: On[InferenceOptions]()}); err != nil {
			requirePorted(t, err)
		}
	}
	f := newConfigFixture(t, func(options *BetterIamOptions) {
		if inference {
			options.Inference = On[InferenceOptions]()
		}
	})
	f.member("alice")
	f.member("bob")
	if inference {
		configCall(f, f.iam.API.Inference.CreateProvider, f.owner, "name", "Anthropic", "kind", "anthropic", "apiKey", "sk-ant-provider-key-0001")
	}
	return f
}

func aiConfigLines(plan *core.Object, withFields bool) []string {
	lines := []string{}
	for _, change := range configObjectsOf(plan.Get("changes")) {
		kind := jsString(change.Get("kind"))
		if kind != "agent" && kind != "inferenceModel" && kind != "inferenceBudget" {
			continue
		}
		line := kind + ":" + jsString(change.Get("name")) + ":" + jsString(change.Get("action"))
		if withFields {
			line += ":" + strings.Join(syncStringList(change.Get("fields")), ",")
		}
		lines = append(lines, line)
	}
	return lines
}

func TestConfigAiAppliesAgentsModelsAndBudgetsAndExportsThemBack(t *testing.T) {
	f := aiScenario(t, true)
	base := parse(t, aiBaseConfig)
	plan := f.plan(f.owner, base, false)
	configLines(t, "plan", aiConfigLines(plan, false),
		"agent:Reporter:create", "agent:Triage:create", "inferenceModel:haiku:create", "inferenceModel:sonnet:create",
		"inferenceBudget:Engineers daily:create", "inferenceBudget:Tenant monthly:create", "inferenceBudget:Triage rate:create")
	f.apply(f.owner, base, false)

	agents := configObjects(t, configCall(f, f.iam.API.Agents.List, f.owner))
	var triage, reporter *core.Object
	for _, agent := range agents {
		switch agent.Get("name") {
		case "Triage":
			triage = agent
		case "Reporter":
			reporter = agent
		}
	}
	infSame(t, "triage", triage, `{"standing":"ok","sponsor":{"email":"alice@acme.test"},"agent":{"purpose":"Sorts incoming tickets","provider":"anthropic",
		"protocols":["a2a","mcp"],"maxDelegatedSessionSeconds":1800,
		"boundary":{"version":1,"statements":[{"effect":"allow","actions":["documents:*"],"resources":["document/*"]}]},
		"tokenAudiences":["https://tickets.example.com"]}}`)
	if member(reporter.Get("agent"), "delegable") != false {
		t.Fatalf("Reporter is not delegable: %s", core.MustStringify(reporter))
	}
	models := configObjects(t, configCall(f, f.iam.API.Inference.ListModels, f.owner))
	got := []string{}
	for _, model := range models {
		got = append(got, jsString(model.Get("name"))+":"+jsString(model.Get("enabled"))+":"+jsString(model.Get("maxOutputTokens")))
	}
	configLines(t, "models", got, "haiku:false:undefined", "sonnet:true:8000")
	budgets := configObjects(t, configCall(f, f.iam.API.Inference.ListBudgets, f.owner))
	got = []string{}
	for _, budget := range budgets {
		got = append(got, jsString(budget.Get("name"))+":"+jsString(budget.Get("subjectType"))+":"+jsString(budget.Get("subjectName"))+":"+jsString(budget.Get("period")))
	}
	configLines(t, "budgets", got, "Engineers daily:group:Engineers:day", "Tenant monthly:tenant:undefined:month", "Triage rate:identity:Triage:minute")

	// The export reads back as the same document: planning it again changes nothing.
	exported := f.export(f.owner)
	found := false
	for _, agent := range configObjectsOf(exported.Get("agents")) {
		found = found || (agent.Get("name") == "Triage" && agent.Get("sponsor") == "alice@acme.test")
	}
	if !found {
		t.Fatalf("export agents: %s", core.MustStringify(exported.Get("agents")))
	}
	found = false
	for _, budget := range configObjectsOf(exported.Get("inferenceBudgets")) {
		found = found || syncSame(budget, parse(t, `{"name":"Triage rate","subject":{"agent":"Triage"},"period":"minute","maxRequests":30}`))
	}
	if !found {
		t.Fatalf("export budgets: %s", core.MustStringify(exported.Get("inferenceBudgets")))
	}
	if pending := configPending(f.plan(f.owner, exported, false)); len(pending) > 0 {
		t.Fatalf("the export does not converge: %s", core.MustStringify(objectList(pending)))
	}
}

func TestConfigAiUpdatesInPlaceAndPrunes(t *testing.T) {
	f := aiScenario(t, true)
	base := parse(t, aiBaseConfig).(*core.Object)
	f.apply(f.owner, base, false)
	next := base.Spread()
	agents := aiObjects(base.Get("agents"))
	models := aiObjects(base.Get("inferenceModels"))
	budgets := aiObjects(base.Get("inferenceBudgets"))
	next.Set("agents", []any{agents[0].Spread(core.NewObject("sponsor", "bob@acme.test", "purpose", "Routes tickets"))})
	next.Set("inferenceModels", []any{models[0].Spread(core.NewObject("outputPricePerMTok", 12.0))})
	next.Set("inferenceBudgets", []any{budgets[1].Spread(core.NewObject("maxRequests", 10.0))})
	plan := f.plan(f.owner, next, true)
	configLines(t, "plan", aiConfigLines(plan, true),
		"agent:Reporter:delete:", "agent:Triage:update:purpose,sponsor", "inferenceModel:haiku:delete:",
		"inferenceModel:sonnet:update:outputPricePerMTok", "inferenceBudget:Engineers daily:delete:",
		"inferenceBudget:Tenant monthly:delete:", "inferenceBudget:Triage rate:update:maxRequests")
	f.apply(f.owner, next, true)
	got := []string{}
	for _, agent := range configObjects(t, configCall(f, f.iam.API.Agents.List, f.owner)) {
		got = append(got, jsString(agent.Get("name"))+":"+jsString(member(agent.Get("sponsor"), "email"))+":"+jsString(member(agent.Get("agent"), "purpose")))
	}
	configLines(t, "agents", got, "Triage:bob@acme.test:Routes tickets")
	got = []string{}
	for _, model := range configObjects(t, configCall(f, f.iam.API.Inference.ListModels, f.owner)) {
		got = append(got, jsString(model.Get("name"))+":"+jsString(model.Get("outputPricePerMTok")))
	}
	configLines(t, "models", got, "sonnet:12")
	got = []string{}
	for _, budget := range configObjects(t, configCall(f, f.iam.API.Inference.ListBudgets, f.owner)) {
		got = append(got, jsString(budget.Get("name"))+":"+jsString(budget.Get("maxRequests")))
	}
	configLines(t, "budgets", got, "Triage rate:10")
	if events := f.auditTrail(f.tenantID, "agent:sponsor-change"); len(events) != 1 {
		t.Fatalf("sponsor-change events: %d", len(events))
	}
}

func TestConfigAiRefusesDocumentsNamingThingsThatDoNotExist(t *testing.T) {
	f := aiScenario(t, true)
	refused := func(config string) *core.IamError {
		return f.planFails(f.owner, parse(t, `{"version":1,`+config+`}`), false)
	}
	if known := refused(`"agents":[{"name":"Ghost","sponsor":"nobody@acme.test"}]`); known.Code != "INVALID_INPUT" || !strings.Contains(known.Message, "no person") {
		t.Fatalf("ghost sponsor: %v", known)
	}
	if known := refused(`"inferenceModels":[{"name":"x","provider":"Missing","upstreamModel":"x-1"}]`); !strings.Contains(known.Message, "no provider named Missing") {
		t.Fatalf("missing provider: %v", known)
	}
	if known := refused(`"inferenceBudgets":[{"name":"B","subject":{"agent":"Nobody"},"period":"day","maxRequests":1}]`); !strings.Contains(known.Message, "no agent Nobody") {
		t.Fatalf("missing agent: %v", known)
	}
	if known := refused(`"inferenceBudgets":[{"name":"B","subject":"tenant","period":"day"}]`); known.Code != "INVALID_INPUT" {
		t.Fatalf("limitless budget: %v", known)
	}
	if known := refused(`"agents":[{"name":"Twin","sponsor":"alice@acme.test"},{"name":"twin","sponsor":"alice@acme.test"}]`); !strings.Contains(known.Message, "Duplicate agent") {
		t.Fatalf("twins: %v", known)
	}
}

func TestConfigAiNeedsTheInferenceOptionForModelsAndBudgets(t *testing.T) {
	plain := aiScenario(t, false)
	known := plain.planFails(plain.owner, parse(t, `{"version":1,"inferenceModels":[{"name":"x","provider":"A","upstreamModel":"x"}]}`), false)
	if !strings.Contains(known.Message, "inference option") {
		t.Fatalf("plain deployment: %v", known)
	}
}
