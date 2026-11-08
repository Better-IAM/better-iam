package server

// Port of packages/server/src/ai-sync.ts: configuration as code for AI (the `agents`, `inferenceModels` and
// `inferenceBudgets` kinds of sync.go). Agents by name with their sponsor by email, the tenant's own models by name
// with their provider by name, and inference budgets by name with their subject by group name, person email or agent
// name. API keys, provider keys and delegations are runtime state and never synced. Providers hold secret keys, so
// they are managed through the API and only named here.
//
// Shapes (model objects, undefined members left out as compact() drops them):
//
//	document items: TenantConfigAgent, TenantConfigInferenceModel, TenantConfigInferenceBudget (subject: 'tenant',
//	                { group }, { identity } or { agent })
//	readAiState:    { agents, inference, models, providers, budgets } (lists of records)
//	exportAi names: identityEmails, groupNames (map[string]string, stored raw)
//	planAi env:     names plus identitiesByEmail (map[string]*core.Object), groupNamesAfter (*orderedSet), prune (bool)
//	planAi result:  { agents, models, budgets }, each a list of { change, desired?, record? }
//	applyAi env:    *SyncApplyEnv

import (
	"context"
	"math"
	"sort"

	"github.com/Better-IAM/better-iam/go/core"
)

// aiLower is ai-sync.ts lower: value.trim().toLowerCase().
func aiLower(value string) string { return core.JSLower(core.JSTrim(value)) }

// aiPeriods are the budget periods a document may name.
var aiPeriods = map[string]bool{"minute": true, "hour": true, "day": true, "month": true}

// aiProviderToolsSetting is providerToolsSetting: a model's `providerTools` in a document, `deny` or `policy`, or
// undefined for `allow` (the default).
func aiProviderToolsSetting(value any, label string) (any, error) {
	if nullish(value) || value == "allow" {
		return core.Undefined, nil
	}
	if value == "deny" || value == "policy" {
		return value, nil
	}
	return nil, invalidInput(label + ": providerTools must be 'allow', 'deny' or 'policy'")
}

// aiOptionalText is optionalText: undefined for undefined or null, the validated text otherwise.
func aiOptionalText(item *core.Object, key, label string, max int) (any, error) {
	value := item.Get(key)
	if nullish(value) {
		return core.Undefined, nil
	}
	return Text(value, label+" "+key, max)
}

// aiOptionalNumber is optionalNumber: undefined for undefined or null, a non-negative finite number otherwise.
func aiOptionalNumber(item *core.Object, key, label string) (any, error) {
	value := item.Get(key)
	if nullish(value) {
		return core.Undefined, nil
	}
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number < 0 {
		return nil, invalidInput(label + ": " + key + " must be a non-negative number")
	}
	return number, nil
}

// aiUnique is unique: refuses two items whose names differ only by case or surrounding space.
func aiUnique(items []*core.Object, kind string) ([]*core.Object, error) {
	seen := newOrderedSet()
	for _, item := range items {
		name := jsString(item.Get("name"))
		if seen.Has(aiLower(name)) {
			return nil, invalidInput("Duplicate " + kind + " " + name)
		}
		seen.Add(aiLower(name))
	}
	return items, nil
}

// aiCompact is compact: drops undefined members, so documents and exports compare alike.
func aiCompact(value *core.Object) *core.Object {
	for _, key := range value.Keys() {
		if isUndefined(value.Get(key)) {
			value.Delete(key)
		}
	}
	return value
}

// aiSortedUnique is `[...new Set(items)].sort()` as a model array.
func aiSortedUnique(items []string) []any { return stringsOf(syncSortedUnique(items)) }

// ParseAgentsConfig (ai-sync.ts parseAgentsConfig): validates the `agents` list of a configuration document.
func ParseAgentsConfig(items []*core.Object) (result []*core.Object, err error) {
	agents := make([]*core.Object, 0, len(items))
	for _, raw := range items {
		agent, err := parseAgentConfig(raw)
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	return aiUnique(agents, "agent")
}

func parseAgentConfig(raw *core.Object) (*core.Object, error) {
	item, err := Object(raw)
	if err != nil {
		return nil, err
	}
	name, err := Text(item.Get("name"), "agent name", 200)
	if err != nil {
		return nil, err
	}
	label := "Agent " + name
	sponsor, err := Text(item.Get("sponsor"), label+" sponsor", 320)
	if err != nil {
		return nil, err
	}
	if delegable := item.Get("delegable"); !isUndefined(delegable) {
		if _, ok := delegable.(bool); !ok {
			return nil, invalidInput(label + ": delegable must be a boolean")
		}
	}
	if boundary := item.Get("boundary"); !nullish(boundary) {
		if _, err := Object(boundary); err != nil {
			return nil, err
		}
	}
	description, err := aiOptionalText(item, "description", label, 512)
	if err != nil {
		return nil, err
	}
	purpose, err := aiOptionalText(item, "purpose", label, 1024)
	if err != nil {
		return nil, err
	}
	model, err := aiOptionalText(item, "model", label, 128)
	if err != nil {
		return nil, err
	}
	provider, err := aiOptionalText(item, "provider", label, 64)
	if err != nil {
		return nil, err
	}
	if text, ok := provider.(string); ok {
		provider = core.JSLower(text)
	}
	url, err := aiOptionalText(item, "url", label, 2048)
	if err != nil {
		return nil, err
	}
	var protocols any = core.Undefined
	if value := item.Get("protocols"); !nullish(value) {
		list, err := Strings(value, label+" protocols")
		if err != nil {
			return nil, err
		}
		lowered := make([]string, len(list))
		for index, protocol := range list {
			lowered[index] = core.JSLower(protocol)
		}
		protocols = aiSortedUnique(lowered)
	}
	var delegable any = core.Undefined
	if item.Get("delegable") == false {
		delegable = false
	}
	var maxSeconds any = core.Undefined
	if value := item.Get("maxDelegatedSessionSeconds"); !nullish(value) {
		if maxSeconds, err = Integer(value, label+" maxDelegatedSessionSeconds", 60, 43_200); err != nil {
			return nil, err
		}
	}
	var boundary any = core.Undefined
	if value := item.Get("boundary"); !nullish(value) {
		boundary = value
	}
	var audiences any = core.Undefined
	if value := item.Get("tokenAudiences"); !nullish(value) {
		list, err := TokenAudienceList(value, label+" tokenAudiences")
		if err != nil {
			return nil, err
		}
		audiences = stringsOf(list)
	}
	return aiCompact(core.NewObject(
		"name", name,
		"sponsor", core.JSLower(sponsor),
		"description", description,
		"purpose", purpose,
		"model", model,
		"provider", provider,
		"url", url,
		"protocols", protocols,
		"delegable", delegable,
		"maxDelegatedSessionSeconds", maxSeconds,
		"boundary", boundary,
		"tokenAudiences", audiences,
	)), nil
}

// ParseModelsConfig (ai-sync.ts parseModelsConfig): validates the `inferenceModels` list of a configuration document.
func ParseModelsConfig(items []*core.Object) (result []*core.Object, err error) {
	models := make([]*core.Object, 0, len(items))
	for _, raw := range items {
		model, err := parseModelConfig(raw)
		if err != nil {
			return nil, err
		}
		models = append(models, model)
	}
	return aiUnique(models, "model")
}

func parseModelConfig(raw *core.Object) (*core.Object, error) {
	item, err := Object(raw)
	if err != nil {
		return nil, err
	}
	name, err := Text(item.Get("name"), "model name", 128)
	if err != nil {
		return nil, err
	}
	label := "Model " + name
	if enabled := item.Get("enabled"); !isUndefined(enabled) {
		if _, ok := enabled.(bool); !ok {
			return nil, invalidInput(label + ": enabled must be a boolean")
		}
	}
	count := func(key string) (any, error) {
		value := item.Get(key)
		if nullish(value) {
			return core.Undefined, nil
		}
		return Integer(value, label+" "+key, 1, 100_000_000)
	}
	provider, err := Text(item.Get("provider"), label+" provider", 200)
	if err != nil {
		return nil, err
	}
	upstream, err := Text(item.Get("upstreamModel"), label+" upstreamModel", 256)
	if err != nil {
		return nil, err
	}
	displayName, err := aiOptionalText(item, "displayName", label, 128)
	if err != nil {
		return nil, err
	}
	family, err := aiOptionalText(item, "family", label, 64)
	if err != nil {
		return nil, err
	}
	tier, err := aiOptionalText(item, "tier", label, 64)
	if err != nil {
		return nil, err
	}
	contextWindow, err := count("contextWindow")
	if err != nil {
		return nil, err
	}
	maxOutput, err := count("maxOutputTokens")
	if err != nil {
		return nil, err
	}
	inputPrice, err := aiOptionalNumber(item, "inputPricePerMTok", label)
	if err != nil {
		return nil, err
	}
	outputPrice, err := aiOptionalNumber(item, "outputPricePerMTok", label)
	if err != nil {
		return nil, err
	}
	cachedPrice, err := aiOptionalNumber(item, "cachedInputPricePerMTok", label)
	if err != nil {
		return nil, err
	}
	var fallbacks any = core.Undefined
	if value := item.Get("fallbacks"); !nullish(value) {
		list, err := Strings(value, label+" fallbacks")
		if err != nil {
			return nil, err
		}
		fallbacks = stringsOf(list)
	}
	tools, err := aiProviderToolsSetting(item.Get("providerTools"), label)
	if err != nil {
		return nil, err
	}
	var enabled any = core.Undefined
	if item.Get("enabled") == false {
		enabled = false
	}
	return aiCompact(core.NewObject(
		"name", name,
		"provider", provider,
		"upstreamModel", upstream,
		"displayName", displayName,
		"family", family,
		"tier", tier,
		"contextWindow", contextWindow,
		"maxOutputTokens", maxOutput,
		"inputPricePerMTok", inputPrice,
		"outputPricePerMTok", outputPrice,
		"cachedInputPricePerMTok", cachedPrice,
		"fallbacks", fallbacks,
		"providerTools", tools,
		"enabled", enabled,
	)), nil
}

// aiBudgetSubject is budgetSubject: whom a budget covers, the whole tenant ('tenant'), a group by name, a person by
// email, or an agent by name.
func aiBudgetSubject(value any, label string) (any, error) {
	if value == "tenant" {
		return "tenant", nil
	}
	subject, err := Object(value)
	if err != nil {
		return nil, err
	}
	keys := subject.Keys()
	if len(keys) == 1 && (keys[0] == "group" || keys[0] == "agent") {
		name, err := Text(subject.Get(keys[0]), label+" subject", 200)
		if err != nil {
			return nil, err
		}
		return core.NewObject(keys[0], name), nil
	}
	if len(keys) == 1 && keys[0] == "identity" {
		email, err := Text(subject.Get("identity"), label+" subject", 320)
		if err != nil {
			return nil, err
		}
		return core.NewObject("identity", core.JSLower(email)), nil
	}
	return nil, invalidInput(label + ": subject must be 'tenant', { group }, { identity } or { agent }")
}

// ParseBudgetsConfig (ai-sync.ts parseBudgetsConfig): validates the `inferenceBudgets` list of a configuration
// document.
func ParseBudgetsConfig(items []*core.Object) (result []*core.Object, err error) {
	budgets := make([]*core.Object, 0, len(items))
	for _, raw := range items {
		budget, err := parseBudgetConfig(raw)
		if err != nil {
			return nil, err
		}
		budgets = append(budgets, budget)
	}
	return aiUnique(budgets, "budget")
}

func parseBudgetConfig(raw *core.Object) (*core.Object, error) {
	item, err := Object(raw)
	if err != nil {
		return nil, err
	}
	nameText, err := Text(item.Get("name"), "budget name", 100)
	if err != nil {
		return nil, err
	}
	name := core.JSTrim(nameText)
	label := "Budget " + name
	period, ok := item.Get("period").(string)
	if !ok || !aiPeriods[period] {
		return nil, invalidInput(label + ": period must be minute, hour, day or month")
	}
	scope := item.Get("scope")
	if !isUndefined(scope) && scope != "shared" && scope != "each" {
		return nil, invalidInput(label + ": scope must be shared or each")
	}
	subject, err := aiBudgetSubject(item.Get("subject"), label)
	if err != nil {
		return nil, err
	}
	var budgetScope any = core.Undefined
	if object, ok := subject.(*core.Object); scope == "each" && (subject == "tenant" || ok && object.Has("group")) {
		budgetScope = "each"
	}
	var maxTokens any = core.Undefined
	if value := item.Get("maxTokens"); !nullish(value) {
		if maxTokens, err = Integer(value, label+" maxTokens", 1, 1e15); err != nil {
			return nil, err
		}
	}
	maxCost, err := aiOptionalNumber(item, "maxCostUsd", label)
	if err != nil {
		return nil, err
	}
	var maxRequests any = core.Undefined
	if value := item.Get("maxRequests"); !nullish(value) {
		if maxRequests, err = Integer(value, label+" maxRequests", 1, 1_000_000_000); err != nil {
			return nil, err
		}
	}
	var models any = core.Undefined
	if value := item.Get("models"); !nullish(value) {
		list, err := Strings(value, label+" models")
		if err != nil {
			return nil, err
		}
		models = aiSortedUnique(list)
	}
	var alert any = core.Undefined
	if value := item.Get("alertAtPercent"); !nullish(value) {
		if alert, err = Integer(value, label+" alertAtPercent", 1, 100); err != nil {
			return nil, err
		}
	}
	budget := aiCompact(core.NewObject(
		"name", name,
		"subject", subject,
		"scope", budgetScope,
		"period", period,
		"maxTokens", maxTokens,
		"maxCostUsd", maxCost,
		"maxRequests", maxRequests,
		"models", models,
		"alertAtPercent", alert,
	))
	if isUndefined(budget.Get("maxTokens")) && isUndefined(budget.Get("maxCostUsd")) && isUndefined(budget.Get("maxRequests")) {
		return nil, invalidInput(label + ": set maxTokens, maxCostUsd or maxRequests")
	}
	return budget, nil
}

// aiSortByName sorts records by name (`a.name < b.name`), stably.
func aiSortByName(records []*core.Object) []*core.Object {
	sort.SliceStable(records, func(i, j int) bool {
		return compareUTF16(jsString(records[i].Get("name")), jsString(records[j].Get("name"))) < 0
	})
	return records
}

// ReadAiState (ai-sync.ts readAiState): the tenant's agents that are not deleted, and (with the inference option)
// its own models, the providers it may use (nearest first) and its budgets, each by name.
func ReadAiState(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	found, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "kind", "agent"), nil)
	if err != nil {
		return nil, err
	}
	agents := []*core.Object{}
	for _, agent := range found {
		if agent.Get("status") != "deleted" {
			agents = append(agents, agent)
		}
	}
	aiSortByName(agents)
	inference, err := InferenceEnabled(inferenceServerValue(server))
	if err != nil {
		return nil, err
	}
	models, providers, budgets := []*core.Object{}, []*core.Object{}, []*core.Object{}
	if inference {
		if models, err = tx.Find(ctx, "inferenceModels", core.NewObject("tenantId", tenantID), nil); err != nil {
			return nil, err
		}
		aiSortByName(models)
		if providers, err = VisibleProviders(ctx, server, tx, tenantID); err != nil {
			return nil, err
		}
		if budgets, err = tx.Find(ctx, "inferenceBudgets", core.NewObject("tenantId", tenantID), nil); err != nil {
			return nil, err
		}
		aiSortByName(budgets)
	}
	return core.NewObject(
		"agents", objectList(agents),
		"inference", inference,
		"models", objectList(models),
		"providers", objectList(providers),
		"budgets", objectList(budgets),
	), nil
}

// aiObjects is the objects of a model array (other members skipped).
func aiObjects(value any) []*core.Object {
	list, _ := value.([]any)
	objects := []*core.Object{}
	for _, item := range list {
		if object, ok := item.(*core.Object); ok {
			objects = append(objects, object)
		}
	}
	return objects
}

// aiStringMap is a raw map[string]string member of an environment object.
func aiStringMap(env *core.Object, key string) map[string]string {
	values, _ := member(env, key).(map[string]string)
	return values
}

// aiLookup is `map.get(key)` over a map with string keys: undefined for a missing key or a key that is not a string.
func aiLookup(values map[string]string, key any) any {
	text, ok := key.(string)
	if !ok {
		return core.Undefined
	}
	if value, found := values[text]; found {
		return value
	}
	return core.Undefined
}

// aiListCopy is `list?.length ? [...list] : undefined`.
func aiListCopy(value any) any {
	if list, ok := value.([]any); ok && len(list) > 0 {
		return append([]any{}, list...)
	}
	return core.Undefined
}

// exportedAgent is exportedAgent: an agent in document form.
func exportedAgent(agent *core.Object, names *core.Object) *core.Object {
	profile := agent.Get("agent")
	identityEmails := aiStringMap(names, "identityEmails")
	sponsorID := member(profile, "sponsorId")
	sponsor := coalesce(coalesce(aiLookup(identityEmails, coalesce(sponsorID, "")), sponsorID), "")
	var delegable any = core.Undefined
	if member(profile, "delegable") == false {
		delegable = false
	}
	return aiCompact(core.NewObject(
		"name", agent.Get("name"),
		"sponsor", sponsor,
		"description", agent.Get("description"),
		"purpose", member(profile, "purpose"),
		"model", member(profile, "model"),
		"provider", member(profile, "provider"),
		"url", member(profile, "url"),
		"protocols", aiListCopy(member(profile, "protocols")),
		"delegable", delegable,
		"maxDelegatedSessionSeconds", member(profile, "maxDelegatedSessionSeconds"),
		"boundary", member(profile, "boundary"),
		"tokenAudiences", aiListCopy(member(profile, "tokenAudiences")),
	))
}

// exportedModel is exportedModel: a model in document form, its provider by name.
func exportedModel(model *core.Object, providers []*core.Object) *core.Object {
	var provider any = model.Get("providerId")
	for _, item := range providers {
		if core.StrictEquals(item.Get("id"), model.Get("providerId")) {
			provider = coalesce(item.Get("name"), model.Get("providerId"))
			break
		}
	}
	var tools any = core.Undefined
	if mode := model.Get("providerTools"); mode == "deny" || mode == "policy" {
		tools = mode
	}
	var enabled any = core.Undefined
	if model.Get("enabled") == false {
		enabled = false
	}
	return aiCompact(core.NewObject(
		"name", model.Get("name"),
		"provider", provider,
		"upstreamModel", model.Get("upstreamModel"),
		"displayName", model.Get("displayName"),
		"family", model.Get("family"),
		"tier", model.Get("tier"),
		"contextWindow", model.Get("contextWindow"),
		"maxOutputTokens", model.Get("maxOutputTokens"),
		"inputPricePerMTok", model.Get("inputPricePerMTok"),
		"outputPricePerMTok", model.Get("outputPricePerMTok"),
		"cachedInputPricePerMTok", model.Get("cachedInputPricePerMTok"),
		"fallbacks", aiListCopy(model.Get("fallbacks")),
		"providerTools", tools,
		"enabled", enabled,
	))
}

// exportedBudget is exportedBudget: a budget in document form, its subject by group name, agent name or email.
func exportedBudget(budget *core.Object, state *core.Object, names *core.Object) *core.Object {
	var subject any = "tenant"
	subjectID := budget.Get("subjectId")
	switch budget.Get("subjectType") {
	case "group":
		subject = core.NewObject("group", coalesce(aiLookup(aiStringMap(names, "groupNames"), subjectID), subjectID))
	case "identity":
		var agent *core.Object
		for _, item := range aiObjects(member(state, "agents")) {
			if core.StrictEquals(item.Get("id"), subjectID) {
				agent = item
				break
			}
		}
		if agent != nil {
			subject = core.NewObject("agent", agent.Get("name"))
		} else {
			subject = core.NewObject("identity", coalesce(aiLookup(aiStringMap(names, "identityEmails"), subjectID), subjectID))
		}
	}
	var scope any = core.Undefined
	if budget.Get("scope") == "each" && budget.Get("subjectType") != "identity" {
		scope = "each"
	}
	var maxCost any = core.Undefined
	if micros := budget.Get("maxCostMicros"); !isUndefined(micros) {
		maxCost = jsNumber(micros) / 1_000_000
	}
	var models any = core.Undefined
	if list, ok := budget.Get("models").([]any); ok && len(list) > 0 {
		sorted := append([]any{}, list...)
		sort.SliceStable(sorted, func(i, j int) bool { return compareUTF16(jsString(sorted[i]), jsString(sorted[j])) < 0 })
		models = sorted
	}
	return aiCompact(core.NewObject(
		"name", budget.Get("name"),
		"subject", subject,
		"scope", scope,
		"period", budget.Get("period"),
		"maxTokens", budget.Get("maxTokens"),
		"maxCostUsd", maxCost,
		"maxRequests", budget.Get("maxRequests"),
		"models", models,
		"alertAtPercent", budget.Get("alertAtPercent"),
	))
}

// ExportAi (ai-sync.ts exportAi): The AI part of an export, each kind only when the tenant has some (so other
// exports stay unchanged).
func ExportAi(state *core.Object, names *core.Object) (result *core.Object, err error) {
	config := core.NewObject()
	if agents := aiObjects(member(state, "agents")); len(agents) > 0 {
		list := make([]any, len(agents))
		for index, agent := range agents {
			list[index] = exportedAgent(agent, names)
		}
		config.Set("agents", list)
	}
	providers := aiObjects(member(state, "providers"))
	if models := aiObjects(member(state, "models")); len(models) > 0 {
		list := make([]any, len(models))
		for index, model := range models {
			list[index] = exportedModel(model, providers)
		}
		config.Set("inferenceModels", list)
	}
	if budgets := aiObjects(member(state, "budgets")); len(budgets) > 0 {
		list := make([]any, len(budgets))
		for index, budget := range budgets {
			list[index] = exportedBudget(budget, state, names)
		}
		config.Set("inferenceBudgets", list)
	}
	return config, nil
}

// aiPlanned is the change helper of planAi: a create (no before), a delete (no after), or an update or unchanged
// item with the fields that differ.
func aiPlanned(kind, name string, before, after *core.Object, desired, record *core.Object) *core.Object {
	optional := func(value *core.Object) any {
		if value == nil {
			return core.Undefined
		}
		return value
	}
	if before == nil {
		return core.NewObject(
			"change", core.NewObject("kind", kind, "name", name, "action", "create", "after", after),
			"desired", optional(desired),
		)
	}
	if after == nil {
		return core.NewObject(
			"change", core.NewObject("kind", kind, "name", name, "action", "delete", "before", before),
			"record", optional(record),
		)
	}
	fields := syncDiffFields(before, after)
	change := core.NewObject("kind", kind, "name", name, "action", "unchanged")
	if len(fields) > 0 {
		change = core.NewObject("kind", kind, "name", name, "action", "update", "fields", stringsOf(fields), "before", before, "after", after)
	}
	return core.NewObject("change", change, "desired", optional(desired), "record", optional(record))
}

// PlanAi (ai-sync.ts planAi): Plans the AI kinds a document names (a kind the document leaves out is left alone).
// Sponsors must be people of the tenant now; budget groups must exist after the apply (`groupNamesAfter`); a
// budget's agent must be an agent now or one this document creates; a model's provider must be visible to the
// tenant.
func PlanAi(desired *core.Object, state *core.Object, env *core.Object) (result *core.Object, err error) {
	agentsPlan, modelsPlan, budgetsPlan := []any{}, []any{}, []any{}
	identitiesByEmail, _ := member(env, "identitiesByEmail").(map[string]*core.Object)
	groupNamesAfter, _ := member(env, "groupNamesAfter").(*orderedSet)
	prune, _ := member(env, "prune").(bool)
	stateAgents := aiObjects(member(state, "agents"))
	stateModels := aiObjects(member(state, "models"))
	stateProviders := aiObjects(member(state, "providers"))
	stateBudgets := aiObjects(member(state, "budgets"))
	if !truthy(member(state, "inference")) && (truthy(member(desired, "inferenceModels")) || truthy(member(desired, "inferenceBudgets"))) {
		return nil, invalidInput("inferenceModels and inferenceBudgets need the inference option on this deployment")
	}

	desiredAgents, hasAgents := syncConfigItems(desired, "agents")
	if hasAgents {
		existing := map[string]*core.Object{}
		for _, agent := range stateAgents {
			key := aiLower(jsString(agent.Get("name")))
			if existing[key] != nil {
				return nil, invalidInput("More than one agent is named " + jsString(agent.Get("name")) + "; rename one before syncing agents")
			}
			existing[key] = agent
		}
		for _, agent := range desiredAgents {
			name := jsString(agent.Get("name"))
			sponsorEmail := jsString(agent.Get("sponsor"))
			sponsor := identitiesByEmail[sponsorEmail]
			if sponsor == nil || sponsor.Get("kind") != "user" {
				return nil, invalidInput("Agent " + name + ": no person " + sponsorEmail)
			}
			record := existing[aiLower(name)]
			var before *core.Object
			if record != nil {
				before = exportedAgent(record, env).Spread()
			}
			agentsPlan = append(agentsPlan, aiPlanned("agent", name, before, agent.Spread(), agent, record))
		}
		if prune {
			for _, record := range stateAgents {
				name := jsString(record.Get("name"))
				if !syncSome(desiredAgents, func(agent *core.Object) bool { return aiLower(jsString(agent.Get("name"))) == aiLower(name) }) {
					agentsPlan = append(agentsPlan, aiPlanned("agent", name, exportedAgent(record, env).Spread(), nil, nil, record))
				}
			}
		}
	}

	desiredModels, hasModels := syncConfigItems(desired, "inferenceModels")
	if hasModels {
		existing := map[string]*core.Object{}
		for _, model := range stateModels {
			existing[jsString(model.Get("name"))] = model
		}
		for _, model := range desiredModels {
			name := jsString(model.Get("name"))
			if !syncSome(stateProviders, func(provider *core.Object) bool {
				return core.StrictEquals(provider.Get("name"), model.Get("provider"))
			}) {
				return nil, invalidInput("Model " + name + ": no provider named " + jsString(model.Get("provider")) + " (create providers through the API)")
			}
			record := existing[name]
			var before *core.Object
			if record != nil {
				before = exportedModel(record, stateProviders).Spread()
			}
			modelsPlan = append(modelsPlan, aiPlanned("inferenceModel", name, before, model.Spread(), model, record))
		}
		if prune {
			for _, record := range stateModels {
				name := jsString(record.Get("name"))
				if !syncSome(desiredModels, func(model *core.Object) bool { return jsString(model.Get("name")) == name }) {
					modelsPlan = append(modelsPlan, aiPlanned("inferenceModel", name, exportedModel(record, stateProviders).Spread(), nil, nil, record))
				}
			}
		}
	}

	desiredBudgets, hasBudgets := syncConfigItems(desired, "inferenceBudgets")
	if hasBudgets {
		agentsAfter := newOrderedSet()
		for _, agent := range stateAgents {
			agentsAfter.Add(aiLower(jsString(agent.Get("name"))))
		}
		for _, agent := range desiredAgents {
			agentsAfter.Add(aiLower(jsString(agent.Get("name"))))
		}
		existing := map[string]*core.Object{}
		for _, budget := range stateBudgets {
			existing[aiLower(jsString(budget.Get("name")))] = budget
		}
		for _, budget := range desiredBudgets {
			name := jsString(budget.Get("name"))
			if subject, ok := budget.Get("subject").(*core.Object); ok {
				if subject.Has("group") && !groupNamesAfter.Has(jsString(subject.Get("group"))) {
					return nil, invalidInput("Budget " + name + ": no group " + jsString(subject.Get("group")))
				}
				if _, found := identitiesByEmail[jsString(subject.Get("identity"))]; subject.Has("identity") && !found {
					return nil, invalidInput("Budget " + name + ": no identity " + jsString(subject.Get("identity")))
				}
				if subject.Has("agent") && !agentsAfter.Has(aiLower(jsString(subject.Get("agent")))) {
					return nil, invalidInput("Budget " + name + ": no agent " + jsString(subject.Get("agent")))
				}
			}
			record := existing[aiLower(name)]
			var before *core.Object
			if record != nil {
				before = exportedBudget(record, state, env).Spread()
			}
			budgetsPlan = append(budgetsPlan, aiPlanned("inferenceBudget", name, before, budget.Spread(), budget, record))
		}
		if prune {
			for _, record := range stateBudgets {
				name := jsString(record.Get("name"))
				if !syncSome(desiredBudgets, func(budget *core.Object) bool { return aiLower(jsString(budget.Get("name"))) == aiLower(name) }) {
					budgetsPlan = append(budgetsPlan, aiPlanned("inferenceBudget", name, exportedBudget(record, state, env).Spread(), nil, nil, record))
				}
			}
		}
	}
	return core.NewObject("agents", agentsPlan, "models", modelsPlan, "budgets", budgetsPlan), nil
}

// aiNullable is `value ?? null`.
func aiNullable(value any) any { return coalesce(value, nil) }

// ApplyAi (ai-sync.ts applyAi): Applies a planned AI change set inside the configuration apply transaction. `upsert`
// creates and updates (agents first, so budgets can name them), `delete` removes (budgets first, then models and
// agents); both by default. Every change is authorized like the equivalent API call (`allow`).
func ApplyAi(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, plan *core.Object, env any, phase string) (err error) {
	apply, ok := env.(*SyncApplyEnv)
	if !ok || apply == nil {
		return &core.TypeError{Message: "applyAi needs the apply environment"}
	}
	if phase == "" {
		phase = "all"
	}
	tenantID := jsString(tenant.Get("id"))
	agents, err := AgentMutations(server)
	if err != nil {
		return err
	}
	inference, err := InferenceMutations(server)
	if err != nil {
		return err
	}
	personID := func(email string) (any, error) {
		person := apply.IdentitiesByEmail[email]
		if person == nil {
			return nil, invalidInput("No person " + email)
		}
		return person.Get("id"), nil
	}
	profileOf := func(agent *core.Object) *core.Object {
		return core.NewObject(
			"description", aiNullable(agent.Get("description")),
			"purpose", aiNullable(agent.Get("purpose")),
			"model", aiNullable(agent.Get("model")),
			"provider", aiNullable(agent.Get("provider")),
			"url", aiNullable(agent.Get("url")),
			"protocols", aiNullable(agent.Get("protocols")),
			"delegable", agent.Get("delegable") != false,
			"maxDelegatedSessionSeconds", aiNullable(agent.Get("maxDelegatedSessionSeconds")),
			"boundary", aiNullable(agent.Get("boundary")),
			"tokenAudiences", aiNullable(agent.Get("tokenAudiences")),
		)
	}
	modelInput := func(model *core.Object, providers []*core.Object) (*core.Object, error) {
		var provider *core.Object
		for _, item := range providers {
			if core.StrictEquals(item.Get("name"), model.Get("provider")) {
				provider = item
				break
			}
		}
		if provider == nil {
			return nil, &core.TypeError{Message: "Cannot read properties of undefined (reading 'id')"}
		}
		return core.NewObject(
			"providerId", provider.Get("id"),
			"upstreamModel", model.Get("upstreamModel"),
			"displayName", aiNullable(model.Get("displayName")),
			"family", aiNullable(model.Get("family")),
			"tier", aiNullable(model.Get("tier")),
			"contextWindow", aiNullable(model.Get("contextWindow")),
			"maxOutputTokens", aiNullable(model.Get("maxOutputTokens")),
			"inputPricePerMTok", aiNullable(model.Get("inputPricePerMTok")),
			"outputPricePerMTok", aiNullable(model.Get("outputPricePerMTok")),
			"cachedInputPricePerMTok", aiNullable(model.Get("cachedInputPricePerMTok")),
			"fallbacks", aiNullable(model.Get("fallbacks")),
			"providerTools", aiNullable(model.Get("providerTools")),
			"enabled", model.Get("enabled") != false,
		), nil
	}
	// withoutNulls is `Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== null))`.
	withoutNulls := func(value *core.Object) *core.Object {
		out := core.NewObject()
		value.Entries(func(key string, entry any) bool {
			if entry != nil {
				out.SetRaw(key, entry)
			}
			return true
		})
		return out
	}
	items := func(key string) []*core.Object { return aiObjects(member(plan, key)) }
	changeOf := func(item *core.Object) *core.Object {
		change, _ := item.Get("change").(*core.Object)
		if change == nil {
			change = core.NewObject()
		}
		return change
	}
	objectOf := func(item *core.Object, key string) *core.Object {
		value, _ := item.Get(key).(*core.Object)
		return value
	}

	if phase != "delete" {
		for _, item := range items("agents") {
			change, desired, record := changeOf(item), objectOf(item, "desired"), objectOf(item, "record")
			switch syncChangeAction(change) {
			case "create":
				name := jsString(desired.Get("name"))
				if err := apply.Allow(ctx, "iam:agents:create", tenantID, "create agent "+name); err != nil {
					return err
				}
				profile := profileOf(desired)
				description := profile.Get("description")
				profile.Delete("description")
				sponsorID, err := personID(jsString(desired.Get("sponsor")))
				if err != nil {
					return err
				}
				input := core.NewObject("name", desired.Get("name"), "sponsorId", sponsorID)
				if description != nil {
					input.Set("description", description)
				}
				input.Assign(withoutNulls(profile))
				if _, err := agents.CreateAgent(ctx, tx, principal, tenant, input); err != nil {
					return err
				}
			case "update":
				if err := apply.Allow(ctx, "iam:agents:update", jsString(record.Get("id")), "update agent "+syncChangeName(change)); err != nil {
					return err
				}
				sponsorID, err := personID(jsString(desired.Get("sponsor")))
				if err != nil {
					return err
				}
				input := core.NewObject("name", desired.Get("name"), "sponsorId", sponsorID).Assign(profileOf(desired))
				if _, err := agents.UpdateAgent(ctx, tx, principal, record, input); err != nil {
					return err
				}
			}
		}
		providers, err := VisibleProviders(ctx, server, tx, tenantID)
		if err != nil {
			return err
		}
		for _, item := range items("models") {
			change, desired := changeOf(item), objectOf(item, "desired")
			switch syncChangeAction(change) {
			case "create":
				if err := apply.Allow(ctx, "iam:inference:manage", tenantID, "create model "+jsString(desired.Get("name"))); err != nil {
					return err
				}
				input, err := modelInput(desired, providers)
				if err != nil {
					return err
				}
				if _, err := inference.CreateModel(ctx, tx, principal, tenantID, core.NewObject("name", desired.Get("name")).Assign(withoutNulls(input))); err != nil {
					return err
				}
			case "update":
				if err := apply.Allow(ctx, "iam:inference:manage", tenantID, "update model "+syncChangeName(change)); err != nil {
					return err
				}
				input, err := modelInput(desired, providers)
				if err != nil {
					return err
				}
				if _, err := inference.UpdateModel(ctx, tx, principal, tenantID, core.NewObject("name", desired.Get("name")).Assign(input)); err != nil {
					return err
				}
			}
		}
		found, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "kind", "agent"), nil)
		if err != nil {
			return err
		}
		agentIDs := map[string]any{}
		for _, agent := range found {
			if agent.Get("status") != "deleted" {
				agentIDs[aiLower(jsString(agent.Get("name")))] = agent.Get("id")
			}
		}
		for _, item := range items("budgets") {
			change, budget, record := changeOf(item), objectOf(item, "desired"), objectOf(item, "record")
			action := syncChangeAction(change)
			if action != "create" && action != "update" {
				continue
			}
			if err := apply.Allow(ctx, "iam:inference:manage", tenantID, action+" budget "+syncChangeName(change)); err != nil {
				return err
			}
			subject := budget.Get("subject")
			subjectObject, _ := subject.(*core.Object)
			if subjectObject == nil {
				subjectObject = core.NewObject()
			}
			subjectType := "identity"
			if subject == "tenant" {
				subjectType = "tenant"
			} else if subjectObject.Has("group") {
				subjectType = "group"
			}
			input := core.NewObject("name", budget.Get("name"), "subjectType", subjectType)
			if subject != "tenant" {
				var subjectID any
				switch {
				case subjectObject.Has("group"):
					group := jsString(subjectObject.Get("group"))
					if id, found := apply.GroupIDs[group]; found {
						subjectID = id
					} else {
						groups, err := tx.Find(ctx, "groups", core.NewObject("tenantId", tenantID), nil)
						if err != nil {
							return err
						}
						subjectID = ""
						for _, candidate := range groups {
							if candidate.Get("name") == group {
								subjectID = coalesce(candidate.Get("id"), "")
								break
							}
						}
					}
				case subjectObject.Has("agent"):
					subjectID = ""
					if id, found := agentIDs[aiLower(jsString(subjectObject.Get("agent")))]; found {
						subjectID = coalesce(id, "")
					}
				default:
					if subjectID, err = personID(jsString(subjectObject.Get("identity"))); err != nil {
						return err
					}
				}
				input.Set("subjectId", subjectID)
			}
			input.Assign(core.NewObject(
				"scope", coalesce(budget.Get("scope"), "shared"),
				"period", budget.Get("period"),
				"maxTokens", aiNullable(budget.Get("maxTokens")),
				"maxCostUsd", aiNullable(budget.Get("maxCostUsd")),
				"maxRequests", aiNullable(budget.Get("maxRequests")),
				"models", aiNullable(budget.Get("models")),
				"alertAtPercent", aiNullable(budget.Get("alertAtPercent")),
			))
			if _, err := inference.SaveBudget(ctx, tx, principal, tenantID, input, record); err != nil {
				return err
			}
		}
	}
	if phase != "upsert" {
		for _, item := range items("budgets") {
			change := changeOf(item)
			if syncChangeAction(change) != "delete" {
				continue
			}
			if err := apply.Allow(ctx, "iam:inference:manage", tenantID, "delete budget "+syncChangeName(change)); err != nil {
				return err
			}
			if err := inference.DeleteBudget(ctx, tx, principal, objectOf(item, "record")); err != nil {
				return err
			}
		}
		for _, item := range items("models") {
			change := changeOf(item)
			if syncChangeAction(change) != "delete" {
				continue
			}
			if err := apply.Allow(ctx, "iam:inference:manage", tenantID, "delete model "+syncChangeName(change)); err != nil {
				return err
			}
			if err := inference.DeleteModel(ctx, tx, tenantID, syncChangeName(change)); err != nil {
				return err
			}
		}
		for _, item := range items("agents") {
			change, record := changeOf(item), objectOf(item, "record")
			if syncChangeAction(change) != "delete" {
				continue
			}
			if err := apply.Allow(ctx, "iam:agents:delete", jsString(record.Get("id")), "delete agent "+syncChangeName(change)); err != nil {
				return err
			}
			// As `agents.delete`: removing an agent needs a fresh sign-in in person.
			if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
				return err
			}
			if _, err := agents.DeleteAgent(ctx, tx, principal, record); err != nil {
				return err
			}
		}
	}
	return nil
}
