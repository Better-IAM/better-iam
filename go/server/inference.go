package server

// Port of packages/server/src/inference.ts: inference access control. Which people, service accounts and AI agents
// may call which AI models, how much they may spend, and what they did. Models are defined per tenant and inherited
// by sub-tenants; each one is a resource of type `model` that policies grant `inference:invoke` on (`model/claude-*`,
// conditions on `resource.tier`, ...). Upstream provider keys are sealed with the deployment secret and only ever
// leave storage inside the server (the gateway). Budgets cap tokens and cost per hour, day or month for a tenant, a
// group or one identity (an agent's budget also covers the sessions in which it acts for people). Every call is
// metered.
//
// Records are *core.Object in the TypeScript shapes (InferenceProvider, InferenceModel, InferenceBudget,
// InferenceCounter, InferenceUsageRecord, InferenceResponseRecord); results (PublicModel, BudgetStanding,
// InvocationCheck, UsageSubject, ProviderCredential) are *core.Object with the TypeScript member order.

import (
	"context"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// InferenceResourceType is inference.ts inferenceResourceType.
const InferenceResourceType = "model"

// InferenceAction is inference.ts inferenceAction.
const InferenceAction = "inference:invoke"

// InferenceToolResourceType is inference.ts inferenceToolResourceType: tools the provider runs itself (web search,
// code execution, remote MCP servers, ...), as resources of this type named by kind (`model-tool/web_search`,
// `model-tool/mcp:{host}`), checked with `inference:use-tool` for models whose `providerTools` is `policy`.
const InferenceToolResourceType = "model-tool"

// InferenceToolAction is inference.ts inferenceToolAction: the action decided on each `model-tool/{kind}` a request
// asks for, for models whose `providerTools` is `policy`.
const InferenceToolAction = "inference:use-tool"

// ProviderToolsModes is inference.ts providerToolsModes.
var ProviderToolsModes = []string{"allow", "deny", "policy"}

// ProviderToolPattern is inference.ts providerToolPattern: a provider tool id, its kind or `mcp:{host}` /
// `mcp:{connector}` for remote MCP servers.
var ProviderToolPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,254}$`)

// ProviderKinds is inference.ts providerKinds.
var ProviderKinds = []string{"anthropic", "openai", "openai-compatible"}

// ProviderBaseURLs is inference.ts providerBaseUrls: the public endpoint of each kind; `openai-compatible` always
// needs a base URL.
var ProviderBaseURLs = mustObject(`{"anthropic":"https://api.anthropic.com","openai":"https://api.openai.com"}`)

var modelNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`)

// inferenceResponseIDPattern is the shape of a provider's Responses API response id.
var inferenceResponseIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,200}$`)

var providerKeyWhitespace = regexp.MustCompile(`[` + jsWhitespace + `]`)

const inferenceHour = 3_600_000
const inferenceDay = 86_400_000

// ProviderToolList (inference.ts providerToolList): Reads a list of provider tool ids (at most 64), deduplicated.
func ProviderToolList(value any) ([]string, error) {
	list, ok := value.([]any)
	if !ok {
		if typed, isStrings := value.([]string); isStrings {
			list, ok = stringsOf(typed), true
		}
	}
	if !ok {
		return nil, invalidInput("tools must be a list")
	}
	// [...new Set(value)]: SameValueZero over model values.
	var tools []any
	for _, item := range list {
		duplicate := false
		for _, seen := range tools {
			if sameValueZero(seen, item) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			tools = append(tools, item)
		}
	}
	invalid := len(tools) > 64
	for _, tool := range tools {
		text, isString := tool.(string)
		if !isString || !ProviderToolPattern.MatchString(text) {
			invalid = true
		}
	}
	if invalid {
		return nil, invalidInput("tools must list at most 64 provider tool ids (such as web_search or mcp:tools.example.com)")
	}
	result := make([]string, len(tools))
	for index, tool := range tools {
		result[index] = tool.(string)
	}
	return result, nil
}

// sameValueZero is the SameValueZero comparison of a Set over model values (objects and arrays by identity).
func sameValueZero(a, b any) bool {
	switch x := a.(type) {
	case float64:
		y, ok := b.(float64)
		return ok && (x == y || (math.IsNaN(x) && math.IsNaN(y)))
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case nil:
		return b == nil
	case core.UndefinedType:
		return isUndefined(b)
	case *core.Object:
		y, ok := b.(*core.Object)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		return ok && len(x) > 0 && len(y) > 0 && &x[0] == &y[0]
	}
	return false
}

// InferenceEnabled (inference.ts inferenceEnabled): Whether the deployment enabled inference (`inference` option).
func InferenceEnabled(server *ServerContext) bool {
	return server.Options.Inference.IsOn()
}

// InferenceSettings (inference.ts inferenceSettings): the `inference` options object, or empty settings when the
// option is `true` or off.
func InferenceSettings(server *ServerContext) *InferenceOptions {
	if server.Options.Inference != nil && server.Options.Inference.Options != nil {
		return server.Options.Inference.Options
	}
	return &InferenceOptions{}
}

// AssertInference (inference.ts assertInference): Refuses inference calls on deployments that did not enable it.
func AssertInference(server *ServerContext) error {
	if !InferenceEnabled(server) {
		return core.NewIamError("FEATURE_DISABLED", "Inference is not enabled on this deployment", 403)
	}
	return nil
}

// InferencePlugins (inference.ts inferencePlugins): the catalog entries the inference module contributes when
// enabled (the `model` type and `inference:invoke`); none when it is off. The options are validated once, at
// construction (the boolean members are typed, so only `usageRetentionDays` can be out of range here).
func InferencePlugins(options *BetterIamOptions) ([]*core.IamPlugin, error) {
	if !options.Inference.IsOn() {
		return nil, nil
	}
	if settings := options.Inference.Options; settings != nil {
		if days := settings.UsageRetentionDays; days != nil && (!core.IsSafeInteger(*days) || *days < 1 || *days > 3650) {
			return nil, invalidConfig("inference.usageRetentionDays must be 1 to 3650")
		}
	}
	return []*core.IamPlugin{{
		ID: "better-iam:inference",
		ResourceTypes: []core.NamedResourceType{
			{Name: InferenceResourceType, Definition: core.ResourceTypeDefinition{
				Description: "An AI model callers may invoke through the inference gateway",
				Actions:     []string{InferenceAction},
				Attributes: []core.NamedAttribute{
					{Name: "provider", Type: "string"},
					{Name: "providerKind", Type: "string"},
					{Name: "upstreamModel", Type: "string"},
					{Name: "family", Type: "string"},
					{Name: "tier", Type: "string"},
					{Name: "contextWindow", Type: "number"},
					{Name: "inputPricePerMTok", Type: "number"},
					{Name: "outputPricePerMTok", Type: "number"},
					{Name: "enabled", Type: "boolean"},
				},
			}},
			{Name: InferenceToolResourceType, Definition: core.ResourceTypeDefinition{
				Description: "A tool the model provider runs itself (web search, code execution, a remote MCP server, ...)",
				Actions:     []string{InferenceToolAction},
				Attributes:  []core.NamedAttribute{{Name: "kind", Type: "string"}, {Name: "host", Type: "string"}},
			}},
		},
	}}, nil
}

// ModelName (inference.ts modelName): A public model name.
func ModelName(value any) (string, error) {
	name, ok := value.(string)
	if !ok || !modelNamePattern.MatchString(name) {
		return "", invalidInput("Model names use 1-128 letters, digits or ._:/@+- characters and start with a letter or digit")
	}
	return name, nil
}

// Price (inference.ts price): A non-negative price in dollars per million tokens (at most 10 000).
func Price(value any, name string) (float64, error) {
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number < 0 || number > 10_000 {
		return 0, invalidInput(name + " must be a price from 0 to 10000 dollars per million tokens")
	}
	return number, nil
}

// ProviderKeyContext (inference.ts providerKeyContext): The encryption context of a provider's key: binds the
// ciphertext to its record.
func ProviderKeyContext(providerID string) string { return "inference-provider:" + providerID }

// SealProviderKey (inference.ts sealProviderKey): Seals a provider key for storage with the current deployment
// secret.
func SealProviderKey(secret string, providerID string, key string) (string, error) {
	return auth.EncryptSecret(key, secret, ProviderKeyContext(providerID)), nil
}

// OpenProviderKey (inference.ts openProviderKey): Opens a provider's sealed key with the current secret or any
// previous one (`rotateSecrets` re-seals).
func OpenProviderKey(server *ServerContext, provider *core.Object) (string, error) {
	secrets := append([]string{server.Options.Secret}, server.Options.PreviousSecrets...)
	return auth.DecryptSecret(jsString(provider.Get("keySealed")), secrets, ProviderKeyContext(jsString(provider.Get("id"))))
}

// ProviderKey (inference.ts providerKey): A provider key: 8 to 4096 printable characters without whitespace.
func ProviderKey(value any) (string, error) {
	key, ok := value.(string)
	if !ok || utf16Len(key) < 8 || utf16Len(key) > 4096 || providerKeyWhitespace.MatchString(key) {
		return "", invalidInput("apiKey must be 8-4096 characters without whitespace")
	}
	return key, nil
}

// BaseURL (inference.ts baseUrl): A provider base URL: https without credentials, query or fragment (http on
// loopback only with `allowInsecureLocalhost`); the trailing slash is removed.
func BaseURL(value any, settings *InferenceOptions) (string, error) {
	raw, err := Text(value, "baseUrl", 2048)
	if err != nil {
		return "", err
	}
	u, parseErr := auth.ParseFetchURL(raw)
	if parseErr != nil {
		return "", invalidInput("baseUrl must be an absolute URL")
	}
	loopback := u.Hostname == "localhost" || u.Hostname == "127.0.0.1" || u.Hostname == "[::1]"
	insecureLocal := settings != nil && settings.AllowInsecureLocalhost != nil && *settings.AllowInsecureLocalhost
	if urlUsername(u) != "" || urlPassword(u) != "" || signingURLSearch(u) != "" || signingURLHash(u) != "" ||
		!(u.Protocol == "https:" || (u.Protocol == "http:" && loopback && insecureLocal)) {
		return "", invalidInput("baseUrl must be an https URL without credentials or query")
	}
	return strings.TrimRight(u.Href, "/"), nil
}

// realmChain is the tenant and its ancestors, nearest first, for inherited models and providers.
func realmChain(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) ([]*core.Object, error) {
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	return server.Ancestry(ctx, tx, tenant)
}

// VisibleProvider (inference.ts visibleProvider): A provider visible from a tenant: its own or an ancestor's.
func VisibleProvider(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, providerID string) (*core.Object, error) {
	provider, err := tx.Get(ctx, "inferenceProviders", providerID)
	if err != nil || provider == nil {
		return nil, err
	}
	chain, err := realmChain(ctx, server, tx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, realm := range chain {
		if realm.Get("id") == provider.Get("tenantId") {
			return provider, nil
		}
	}
	return nil, nil
}

// VisibleProviders (inference.ts visibleProviders): Every provider a tenant may use (its own and its ancestors'),
// nearest first.
func VisibleProviders(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) ([]*core.Object, error) {
	chain, err := realmChain(ctx, server, tx, tenantID)
	if err != nil {
		return nil, err
	}
	providers := []*core.Object{}
	for _, realm := range chain {
		found, err := tx.Find(ctx, "inferenceProviders", core.NewObject("tenantId", realm.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		providers = append(providers, found...)
	}
	return providers, nil
}

// foundModel is `{ model, provider }` (provider absent when it is not visible).
func foundModel(model, provider *core.Object) *core.Object {
	found := core.NewObject("model", model)
	if provider != nil {
		found.Set("provider", provider)
	} else {
		found.SetRaw("provider", core.Undefined)
	}
	return found
}

// foundParts reads `{ model, provider }`.
func foundParts(found *core.Object) (model, provider *core.Object) {
	model, _ = found.Get("model").(*core.Object)
	provider, _ = found.Get("provider").(*core.Object)
	return model, provider
}

// ResolveModel (inference.ts resolveModel): The nearest definition of a model name for a tenant (its own, else the
// closest ancestor's), with its provider: `{ model, provider }`, nil when no tenant on the way defines it.
func ResolveModel(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, name string) (*core.Object, error) {
	chain, err := realmChain(ctx, server, tx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, realm := range chain {
		realmID := jsString(realm.Get("id"))
		models, err := tx.Find(ctx, "inferenceModels", core.NewObject("tenantId", realmID, "uniqueKey", name), nil)
		if err != nil {
			return nil, err
		}
		if len(models) > 0 {
			model := models[0]
			provider, err := VisibleProvider(ctx, server, tx, realmID, jsString(model.Get("providerId")))
			if err != nil {
				return nil, err
			}
			return foundModel(model, provider), nil
		}
	}
	return nil, nil
}

// VisibleModels (inference.ts visibleModels): Every model visible from a tenant: its own and inherited ones, the
// nearest definition of each name winning, as `{ model, provider }` sorted by name.
func VisibleModels(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) ([]*core.Object, error) {
	chain, err := realmChain(ctx, server, tx, tenantID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	result := []*core.Object{}
	for _, realm := range chain {
		realmID := jsString(realm.Get("id"))
		models, err := tx.Find(ctx, "inferenceModels", core.NewObject("tenantId", realmID), nil)
		if err != nil {
			return nil, err
		}
		for _, model := range models {
			name := jsString(model.Get("name"))
			if seen[name] {
				continue
			}
			provider, err := VisibleProvider(ctx, server, tx, realmID, jsString(model.Get("providerId")))
			if err != nil {
				return nil, err
			}
			seen[name] = true
			result = append(result, foundModel(model, provider))
		}
	}
	sortStable(result, func(a, b *core.Object) int {
		left, _ := foundParts(a)
		right, _ := foundParts(b)
		return localeCompare(jsString(left.Get("name")), jsString(right.Get("name")))
	})
	return result, nil
}

// jsAnd is `a && b`: a when it is falsy, else b.
func jsAnd(a, b any) any {
	if !truthy(a) {
		return a
	}
	return b
}

// PublicModel (inference.ts publicModel): A model as callers see it: never the provider key, only which provider
// serves it.
func PublicModel(model *core.Object, provider *core.Object, tenantID string) (*core.Object, error) {
	providerView := core.NewObject("id", model.Get("providerId"), "name", "(missing)", "kind", "openai-compatible")
	if provider != nil {
		providerView = core.NewObject("id", provider.Get("id"), "name", provider.Get("name"), "kind", provider.Get("kind"))
	}
	result := core.NewObject(
		"name", model.Get("name"),
		"tenantId", model.Get("tenantId"),
		"inherited", model.Get("tenantId") != tenantID,
		"provider", providerView,
		"upstreamModel", model.Get("upstreamModel"),
		"enabled", jsAnd(model.Get("enabled"), provider != nil),
	)
	for _, key := range []string{"displayName", "family", "tier", "contextWindow", "maxOutputTokens", "inputPricePerMTok",
		"outputPricePerMTok", "cachedInputPricePerMTok"} {
		if value := model.Get(key); !isUndefined(value) {
			result.Set(key, value)
		}
	}
	if fallbacks, ok := model.Get("fallbacks").([]any); ok && len(fallbacks) > 0 {
		result.Set("fallbacks", append([]any(nil), fallbacks...))
	}
	if tools := model.Get("providerTools"); truthy(tools) && tools != "allow" {
		result.Set("providerTools", tools)
	}
	return result, nil
}

// modelAttributes is a model as the policy engine sees it: `resource.provider`, `resource.tier`,
// `resource.inputPricePerMTok`, ...
func modelAttributes(model *core.Object, provider *core.Object) *core.Object {
	var providerName, providerKind any = "", ""
	if provider != nil {
		providerName = coalesce(provider.Get("name"), "")
		providerKind = coalesce(provider.Get("kind"), "")
	}
	attributes := core.NewObject(
		"provider", providerName,
		"providerKind", providerKind,
		"upstreamModel", model.Get("upstreamModel"),
		"enabled", jsAnd(model.Get("enabled"), provider != nil),
	)
	for _, key := range []string{"family", "tier", "contextWindow", "inputPricePerMTok", "outputPricePerMTok"} {
		if value := model.Get(key); !isUndefined(value) {
			attributes.Set(key, value)
		}
	}
	return attributes
}

// ResolveModelResource (inference.ts resolveModelResource): the decision engine's resolver for `model/{name}` (and
// `model-tool/{kind}`) when inference is enabled: the nearest definition's attributes. nil for other types (the
// caller resolves those) or when inference is off; NOT_FOUND for a model the tenant cannot see.
func ResolveModelResource(ctx context.Context, server *ServerContext, tx core.IamStore, reference core.ResourceRef) (*ResolvedResource, error) {
	// Provider tools are named, not registered: `model-tool/{kind}` or `model-tool/mcp:{host}`.
	if reference.Type == InferenceToolResourceType && InferenceEnabled(server) {
		if !ProviderToolPattern.MatchString(reference.ID) {
			return nil, core.NewIamError("NOT_FOUND", "Unknown provider tool", 404)
		}
		attributes := core.NewObject("kind", reference.ID)
		if colon := strings.Index(reference.ID, ":"); colon > 0 {
			attributes = core.NewObject("kind", reference.ID[:colon], "host", reference.ID[colon+1:])
		}
		return &ResolvedResource{TenantID: reference.TenantID, Type: InferenceToolResourceType, ID: reference.ID,
			Attributes: attributes}, nil
	}
	if reference.Type != InferenceResourceType || !InferenceEnabled(server) {
		return nil, nil
	}
	found, err := ResolveModel(ctx, server, tx, reference.TenantID, reference.ID)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, core.NewIamError("NOT_FOUND", "Model not found", 404)
	}
	model, provider := foundParts(found)
	return &ResolvedResource{TenantID: reference.TenantID, Type: InferenceResourceType, ID: reference.ID,
		Attributes: modelAttributes(model, provider)}, nil
}

// BudgetWindow (inference.ts budgetWindow): The current window of a period (UTC), as [start, end): `{ start, end }`.
func BudgetWindow(period string, now int64) (*core.Object, error) {
	window := func(start, end int64) *core.Object {
		return core.NewObject("start", float64(start), "end", float64(end))
	}
	floorTo := func(unit int64) int64 {
		return int64(math.Floor(float64(now)/float64(unit))) * unit
	}
	switch period {
	case "minute":
		start := floorTo(60_000)
		return window(start, start+60_000), nil
	case "hour":
		start := floorTo(inferenceHour)
		return window(start, start+inferenceHour), nil
	case "day":
		start := floorTo(inferenceDay)
		return window(start, start+inferenceDay), nil
	}
	date := time.UnixMilli(now).UTC()
	return window(utcMonthStart(date.Year(), int(date.Month())), utcMonthStart(date.Year(), int(date.Month())+1)), nil
}

// utcMonthStart is Date.UTC(year, month - 1, 1) (month 13 is January of the next year).
func utcMonthStart(year, month int) int64 {
	return time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC).UnixMilli()
}

// UsageCost (inference.ts usageCost): Cost of a call in micro-dollars: tokens × dollars per million tokens (cached
// input at its own price when set).
func UsageCost(model *core.Object, usage *core.Object) float64 {
	cached := numberOr(usage.Get("cacheReadTokens"), 0)
	input := numberOr(model.Get("inputPricePerMTok"), 0)
	cost := jsNumber(usage.Get("inputTokens"))*input +
		numberOr(usage.Get("cacheWriteTokens"), 0)*input +
		cached*numberOr(model.Get("cachedInputPricePerMTok"), input) +
		jsNumber(usage.Get("outputTokens"))*numberOr(model.Get("outputPricePerMTok"), 0)
	return jsMathRound(cost*1000) / 1000
}

// UsageTokens (inference.ts usageTokens): Tokens a budget counts for a call: input (including cache reads and
// writes) plus output.
func UsageTokens(usage *core.Object) float64 {
	return jsNumber(usage.Get("inputTokens")) + jsNumber(usage.Get("outputTokens")) +
		numberOr(usage.Get("cacheReadTokens"), 0) + numberOr(usage.Get("cacheWriteTokens"), 0)
}

// sessionAgentID is the agent behind a principal's calls: the acting agent of a delegated session, else the identity
// when it is an agent (Undefined otherwise).
func sessionAgentID(principal *Principal) any {
	if principal.Session.Get("kind") == "delegated" {
		return principal.Session.Get("agentId")
	}
	if principal.Identity.Get("kind") == "agent" {
		return principal.Identity.Get("id")
	}
	return core.Undefined
}

// UsageSubject (inference.ts usageSubject): The subject of a principal's calls in `tenantId`: who a call is
// attributed to (the identity, the agent behind the credential, the delegation it acts under, and the identity's
// groups). `groupIds` and `agentGroupIds` are arrays (TypeScript sets).
func UsageSubject(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string) (*core.Object, error) {
	identityID := principal.Identity.Get("id")
	members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	groupIDs := newOrderedSet()
	for _, member := range members {
		if server.LiveMembership(member) {
			groupIDs.Add(jsString(member.Get("groupId")))
		}
	}
	delegated := principal.Session.Get("kind") == "delegated"
	agentID := sessionAgentID(principal)
	var delegationID any = core.Undefined
	if delegated {
		delegationID = principal.Session.Get("delegationId")
	}
	var chain []any
	hasChain := false
	if id, ok := delegationID.(string); ok {
		delegation, err := tx.Get(ctx, "delegations", id)
		if err != nil {
			return nil, err
		}
		if delegation != nil {
			chain, hasChain = delegation.Get("chain").([]any)
		}
	}
	agentGroupIDs := newOrderedSet()
	if delegated {
		for _, actingID := range append([]any{agentID}, chain...) {
			acting, ok := actingID.(string)
			if !ok {
				continue
			}
			found, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", acting), nil)
			if err != nil {
				return nil, err
			}
			for _, member := range found {
				if server.LiveMembership(member) {
					agentGroupIDs.Add(jsString(member.Get("groupId")))
				}
			}
		}
	}
	subject := core.NewObject("tenantId", tenantID, "identityId", identityID)
	if id, ok := agentID.(string); ok {
		subject.Set("agentId", id)
	}
	if id, ok := delegationID.(string); ok {
		subject.Set("delegationId", id)
	}
	if hasChain && len(chain) > 0 {
		subject.Set("chainAgentIds", append([]any(nil), chain...))
	}
	subject.Set("groupIds", stringsOf(groupIDs.Values()))
	if agentGroupIDs.Len() > 0 {
		subject.Set("agentGroupIds", stringsOf(agentGroupIDs.Values()))
	}
	return subject, nil
}

// subjectHas is `subject[key]?.has(value)` / `.includes(value)` over a subject's id list.
func subjectHas(subject *core.Object, key string, value any) bool {
	list, _ := subject.Get(key).([]any)
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// DelegationBudget (inference.ts delegationBudget): A delegation's spending cap (`Delegation.spend`) as a budget: one
// shared pool per window, over every model, whose counters are kept under the id `delegation:{delegationId}`.
func DelegationBudget(delegation *core.Object) *core.Object {
	spend, _ := delegation.Get("spend").(*core.Object)
	budget := core.NewObject(
		"id", "delegation:"+jsString(delegation.Get("id")),
		"tenantId", delegation.Get("tenantId"),
		"name", "Delegation spending limit",
		"subjectType", "identity",
		"subjectId", delegation.Get("subjectId"),
		"scope", "shared",
		"period", spend.Get("period"),
	)
	for _, key := range []string{"maxTokens", "maxCostMicros", "maxRequests"} {
		if value := spend.Get(key); !isUndefined(value) {
			budget.Set(key, value)
		}
	}
	budget.Set("createdAt", delegation.Get("createdAt"))
	budget.Set("updatedAt", coalesce(delegation.Get("decidedAt"), delegation.Get("createdAt")))
	return budget
}

// DelegationSpendStanding (inference.ts delegationSpendStanding): How much of a delegation's spending cap is used in
// the current window (nil without a cap).
func DelegationSpendStanding(ctx context.Context, tx core.IamStore, delegation *core.Object, now int64) (*core.Object, error) {
	if !truthy(delegation.Get("spend")) {
		return nil, nil
	}
	budget := DelegationBudget(delegation)
	window, err := BudgetWindow(jsString(budget.Get("period")), now)
	if err != nil {
		return nil, err
	}
	counter, err := tx.Get(ctx, "inferenceCounters", counterID(jsString(budget.Get("id")), "shared", jsNumber(window.Get("start"))))
	if err != nil {
		return nil, err
	}
	return StandingOf(budget, window, counter)
}

// coveringBudget is one budget covering a call, with the counter key it uses.
type coveringBudget struct {
	budget     *core.Object
	subjectKey string
}

// coveringBudgets are the budgets that cover a subject's use of a model, with the counter key each one uses.
func coveringBudgets(ctx context.Context, tx core.IamStore, subject *core.Object, model string) ([]coveringBudget, error) {
	covering := []coveringBudget{}
	budgets, err := tx.Find(ctx, "inferenceBudgets", core.NewObject("tenantId", subject.Get("tenantId")), nil)
	if err != nil {
		return nil, err
	}
	for _, budget := range budgets {
		if patterns, ok := budget.Get("models").([]any); ok && len(patterns) > 0 {
			matched := false
			for _, pattern := range patterns {
				if core.MatchPattern(jsString(pattern), model, nil) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		subjectType := budget.Get("subjectType")
		subjectID := budget.Get("subjectId")
		viaAgentGroup := subjectType == "group" && !subjectHas(subject, "groupIds", subjectID) &&
			subjectHas(subject, "agentGroupIds", subjectID)
		var covers bool
		switch subjectType {
		case "tenant":
			covers = subjectID == subject.Get("tenantId")
		case "group":
			covers = subjectHas(subject, "groupIds", subjectID) || viaAgentGroup
		default:
			// An agent's budget also counts the work it handed on to other agents.
			covers = subjectID == subject.Get("identityId") || subjectID == subject.Get("agentId") ||
				subjectHas(subject, "chainAgentIds", subjectID)
		}
		if !covers {
			continue
		}
		// An identity budget on an agent counts everything the agent does, for anyone; a per-identity group budget that
		// covers the call through the agent's group counts it against the agent.
		subjectKey := jsString(subject.Get("identityId"))
		if subjectType == "identity" || budget.Get("scope") == "shared" {
			subjectKey = "shared"
		} else if agentID := subject.Get("agentId"); viaAgentGroup && truthy(agentID) {
			subjectKey = jsString(agentID)
		}
		covering = append(covering, coveringBudget{budget: budget, subjectKey: subjectKey})
	}
	// The person's spending caps on the delegation the call is made under and on every delegation above it (hand-offs).
	delegationID := subject.Get("delegationId")
	for depth := 0; !isUndefined(delegationID) && depth <= 3; depth++ {
		delegation, err := tx.Get(ctx, "delegations", jsString(delegationID))
		if err != nil {
			return nil, err
		}
		if delegation == nil {
			break
		}
		if truthy(delegation.Get("spend")) {
			covering = append(covering, coveringBudget{budget: DelegationBudget(delegation), subjectKey: "shared"})
		}
		delegationID = delegation.Get("parentId")
	}
	sortStable(covering, func(a, b coveringBudget) int {
		if compareUTF16(jsString(a.budget.Get("id")), jsString(b.budget.Get("id"))) < 0 {
			return -1
		}
		return 1
	})
	return covering, nil
}

// counterID is the id of a budget pool's counter in a window.
func counterID(budgetID, subjectKey string, windowStart float64) string {
	return budgetID + ":" + subjectKey + ":" + core.NumberString(windowStart)
}

// StandingOf (inference.ts standingOf): A budget's standing in a window, from its counter (nil: nothing used yet).
func StandingOf(budget *core.Object, window *core.Object, counter *core.Object) (*core.Object, error) {
	usedTokens, usedCostMicros, usedRequests := any(0.0), any(0.0), any(0.0)
	if counter != nil {
		usedTokens = coalesce(counter.Get("tokens"), 0.0)
		usedCostMicros = coalesce(counter.Get("costMicros"), 0.0)
		usedRequests = coalesce(counter.Get("requests"), 0.0)
	}
	result := core.NewObject(
		"budgetId", budget.Get("id"),
		"name", budget.Get("name"),
		"period", budget.Get("period"),
		"windowStart", window.Get("start"),
		"resetsAt", window.Get("end"),
		"usedTokens", usedTokens,
		"usedCostMicros", usedCostMicros,
		"usedRequests", usedRequests,
	)
	if value := budget.Get("maxTokens"); !isUndefined(value) {
		result.Set("remainingTokens", math.Max(0, jsNumber(value)-jsNumber(usedTokens)))
	}
	if value := budget.Get("maxCostMicros"); !isUndefined(value) {
		result.Set("remainingCostMicros", math.Max(0, jsNumber(value)-jsNumber(usedCostMicros)))
	}
	if value := budget.Get("maxRequests"); !isUndefined(value) {
		result.Set("remainingRequests", math.Max(0, jsNumber(value)-jsNumber(usedRequests)))
	}
	return result, nil
}

// BudgetStandings (inference.ts budgetStandings): The standing of every budget covering a subject's use of a model,
// in the current windows: `{ budget, subjectKey, standing }` each.
func BudgetStandings(ctx context.Context, server *ServerContext, tx core.IamStore, subject *core.Object, model string) ([]*core.Object, error) {
	now := server.Now()
	covering, err := coveringBudgets(ctx, tx, subject, model)
	if err != nil {
		return nil, err
	}
	result := []*core.Object{}
	for _, entry := range covering {
		window, err := BudgetWindow(jsString(entry.budget.Get("period")), now)
		if err != nil {
			return nil, err
		}
		counter, err := tx.Get(ctx, "inferenceCounters", counterID(jsString(entry.budget.Get("id")), entry.subjectKey, jsNumber(window.Get("start"))))
		if err != nil {
			return nil, err
		}
		standing, err := StandingOf(entry.budget, window, counter)
		if err != nil {
			return nil, err
		}
		result = append(result, core.NewObject("budget", entry.budget, "subjectKey", entry.subjectKey, "standing", standing))
	}
	return result, nil
}

// CheckInvocation (inference.ts checkInvocation): Whether a principal may call a model now: the model must be
// visible and enabled, `inference:invoke` on `model/{name}` must be allowed (denials are audited like any decision),
// and no covering budget may be exhausted (`estimatedTokens`, when given, must fit in what remains, priced at the
// model's input price). The first refusal of a budget in a window is audited as `inference:budget-exceeded`.
// input is `{ tenantId, model, estimatedTokens?, tools? }`; the result is `{ allowed: true, model, budgets }` or
// `{ allowed: false, reason, model?, budget?, tool? }`.
func CheckInvocation(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (*core.Object, error) {
	if err := AssertInference(server); err != nil {
		return nil, err
	}
	name, err := ModelName(input.Get("model"))
	if err != nil {
		return nil, err
	}
	estimate := 0.0
	if value := input.Get("estimatedTokens"); !isUndefined(value) {
		if estimate, err = Integer(value, "estimatedTokens", 0, 100_000_000); err != nil {
			return nil, err
		}
	}
	tools := []string{}
	if value := input.Get("tools"); !isUndefined(value) {
		if tools, err = ProviderToolList(value); err != nil {
			return nil, err
		}
	}
	tenantID := jsString(input.Get("tenantId"))
	found, err := ResolveModel(ctx, server, tx, tenantID, name)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, core.NewIamError("NOT_FOUND", "Model not found", 404)
	}
	foundRecord, foundProvider := foundParts(found)
	model, err := PublicModel(foundRecord, foundProvider, tenantID)
	if err != nil {
		return nil, err
	}
	decision, err := server.Operations.RecordedDecision(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: InferenceAction, Resource: ResourceTarget{Type: InferenceResourceType, ID: name},
	})
	if err != nil {
		return nil, err
	}
	if !decision.Allowed {
		return core.NewObject("allowed", false, "reason", "ACCESS_DENIED", "model", model), nil
	}
	if !truthy(model.Get("enabled")) {
		return core.NewObject("allowed", false, "reason", "MODEL_DISABLED", "model", model), nil
	}
	// Provider-run tools the request asks for, by the model's setting.
	mode := coalesce(foundRecord.Get("providerTools"), "allow")
	if mode != "allow" {
		for _, tool := range tools {
			allowed := false
			if mode == "policy" {
				decision, err := server.Operations.RecordedDecision(ctx, tx, principal, AuthorizationRequest{
					TenantID: tenantID, Action: InferenceToolAction, Resource: ResourceTarget{Type: InferenceToolResourceType, ID: tool},
				})
				if err != nil {
					return nil, err
				}
				allowed = decision.Allowed
			} else {
				// Refused by the model itself: audited like a denied decision.
				if err := server.Events.Audit(ctx, tx, principal, InferenceToolAction, tenantID, InferenceToolResourceType+"/"+tool,
					"deny", false, core.NewObject("model", name, "providerTools", "deny")); err != nil {
					return nil, err
				}
			}
			if !allowed {
				return core.NewObject("allowed", false, "reason", "TOOL_NOT_ALLOWED", "model", model, "tool", tool), nil
			}
		}
	}
	subject, err := UsageSubject(ctx, server, tx, principal, tenantID)
	if err != nil {
		return nil, err
	}
	estimateCost := UsageCost(foundRecord, core.NewObject("inputTokens", estimate, "outputTokens", 0.0))
	standings, err := BudgetStandings(ctx, server, tx, subject, name)
	if err != nil {
		return nil, err
	}
	budgets := []any{}
	for _, entry := range standings {
		budget := entry.Get("budget").(*core.Object)
		current := entry.Get("standing").(*core.Object)
		usedTokens := jsNumber(current.Get("usedTokens"))
		usedCost := jsNumber(current.Get("usedCostMicros"))
		usedRequests := jsNumber(current.Get("usedRequests"))
		maxTokens, maxCost, maxRequests := budget.Get("maxTokens"), budget.Get("maxCostMicros"), budget.Get("maxRequests")
		overTokens := !isUndefined(maxTokens) && usedTokens+estimate > jsNumber(maxTokens)
		overCost := !isUndefined(maxCost) && usedCost+estimateCost > jsNumber(maxCost)
		exhausted := (!isUndefined(maxTokens) && usedTokens >= jsNumber(maxTokens)) ||
			(!isUndefined(maxCost) && usedCost >= jsNumber(maxCost)) ||
			(!isUndefined(maxRequests) && usedRequests >= jsNumber(maxRequests))
		if overTokens || overCost || exhausted {
			if err := noteExceeded(ctx, server, tx, principal, budget, jsString(entry.Get("subjectKey")), current); err != nil {
				return nil, err
			}
			return core.NewObject("allowed", false, "reason", "BUDGET_EXCEEDED", "model", model, "budget", current), nil
		}
		budgets = append(budgets, current)
	}
	return core.NewObject("allowed", true, "model", model, "budgets", budgets), nil
}

// noteExceeded audits the first refusal of a budget in a window (`inference:budget-exceeded`) and marks the counter.
func noteExceeded(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, budget *core.Object, subjectKey string, current *core.Object) error {
	windowStart := jsNumber(current.Get("windowStart"))
	key := counterID(jsString(budget.Get("id")), subjectKey, windowStart)
	counter, err := tx.Get(ctx, "inferenceCounters", key)
	if err != nil {
		return err
	}
	if counter != nil && truthy(counter.Get("exceeded")) {
		return nil
	}
	if counter != nil {
		if _, err := tx.Put(ctx, "inferenceCounters", counter.Spread(core.NewObject("exceeded", true))); err != nil {
			return err
		}
	} else {
		resetsAt := jsNumber(current.Get("resetsAt"))
		next := core.NewObject(
			"id", key,
			"tenantId", budget.Get("tenantId"),
			"budgetId", budget.Get("id"),
			"subjectKey", subjectKey,
			"windowStart", windowStart,
			"windowEnd", resetsAt,
			"tokens", 0.0,
			"costMicros", 0.0,
			"requests", 0.0,
			"exceeded", true,
			"expiresAt", resetsAt+35*inferenceDay,
		)
		if _, err := tx.Insert(ctx, "inferenceCounters", next); err != nil {
			return err
		}
	}
	return server.Events.Audit(ctx, tx, principal, "inference:budget-exceeded", jsString(budget.Get("tenantId")), jsString(budget.Get("id")),
		"deny", false, core.NewObject("budget", budget.Get("name"), "period", budget.Get("period"), "windowStart", windowStart))
}

// responseOwner is the caller a Responses API conversation belongs to: the person or account, and the agent acting,
// if any: `{ identityId, agentId? }`.
func responseOwner(principal *Principal) *core.Object {
	owner := core.NewObject("identityId", principal.Identity.Get("id"))
	if agentID, ok := sessionAgentID(principal).(string); ok {
		owner.Set("agentId", agentID)
	}
	return owner
}

func responseRecordID(tenantID, responseID string) string { return tenantID + ":" + responseID }

// OwnsInferenceResponse (inference.ts ownsInferenceResponse): Whether `responseId` was created through the gateway
// in `tenantId` by the same caller as `principal`, at the provider `providerId` (so a provider that echoes someone
// else's response id cannot claim it for another provider's key).
func OwnsInferenceResponse(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, responseID string, providerID string) (bool, error) {
	if !inferenceResponseIDPattern.MatchString(responseID) {
		return false, nil
	}
	record, err := tx.Get(ctx, "inferenceResponses", responseRecordID(tenantID, responseID))
	if err != nil {
		return false, err
	}
	if record == nil || record.Get("tenantId") != tenantID || record.Get("providerId") != providerID ||
		jsNumber(record.Get("expiresAt")) <= float64(server.Now()) {
		return false, nil
	}
	owner := responseOwner(principal)
	return record.Get("identityId") == owner.Get("identityId") && record.Get("agentId") == owner.Get("agentId"), nil
}

// RecordInvocation (inference.ts recordInvocation): Meters one call: stores a usage record (cost from the model's
// prices) and adds it to every covering budget's counter. A counter crossing a budget's `alertAtPercent` is audited
// once per window as `inference:budget-alert`. input is the InvocationRecord `{ tenantId, model, inputTokens,
// outputTokens, cacheReadTokens?, cacheWriteTokens?, status?, requestId?, latencyMs?, responseId? }`.
func RecordInvocation(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (*core.Object, error) {
	if err := AssertInference(server); err != nil {
		return nil, err
	}
	name, err := ModelName(input.Get("model"))
	if err != nil {
		return nil, err
	}
	inputTokens, err := Integer(input.Get("inputTokens"), "inputTokens", 0, 100_000_000)
	if err != nil {
		return nil, err
	}
	outputTokens, err := Integer(input.Get("outputTokens"), "outputTokens", 0, 100_000_000)
	if err != nil {
		return nil, err
	}
	usage := core.NewObject("inputTokens", inputTokens, "outputTokens", outputTokens)
	if value := input.Get("cacheReadTokens"); !isUndefined(value) {
		tokens, err := Integer(value, "cacheReadTokens", 0, 100_000_000)
		if err != nil {
			return nil, err
		}
		usage.Set("cacheReadTokens", tokens)
	}
	if value := input.Get("cacheWriteTokens"); !isUndefined(value) {
		tokens, err := Integer(value, "cacheWriteTokens", 0, 100_000_000)
		if err != nil {
			return nil, err
		}
		usage.Set("cacheWriteTokens", tokens)
	}
	tenantID := jsString(input.Get("tenantId"))
	found, err := ResolveModel(ctx, server, tx, tenantID, name)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, core.NewIamError("NOT_FOUND", "Model not found", 404)
	}
	foundRecord, _ := foundParts(found)
	now := float64(server.Now())
	subject, err := UsageSubject(ctx, server, tx, principal, tenantID)
	if err != nil {
		return nil, err
	}
	retentionDays := 90.0
	if days := InferenceSettings(server).UsageRetentionDays; days != nil {
		retentionDays = *days
	}
	status := "ok"
	if input.Get("status") == "error" {
		status = "error"
	}
	record := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"identityId", principal.Identity.Get("id"),
		"sessionKind", principal.Session.Get("kind"),
		"model", name,
		"providerId", foundRecord.Get("providerId"),
	)
	record.Assign(usage)
	record.Set("costMicros", UsageCost(foundRecord, usage))
	record.Set("status", status)
	record.Set("createdAt", now)
	record.Set("expiresAt", now+retentionDays*inferenceDay)
	if agentID := subject.Get("agentId"); truthy(agentID) {
		record.Set("agentId", agentID)
	}
	if delegationID, ok := principal.Session.Get("delegationId").(string); ok {
		record.Set("delegationId", delegationID)
	}
	if value := input.Get("requestId"); !isUndefined(value) {
		requestID, err := Text(value, "requestId", 128)
		if err != nil {
			return nil, err
		}
		record.Set("requestId", requestID)
	}
	if value := input.Get("latencyMs"); !isUndefined(value) {
		latency, err := Integer(value, "latencyMs", 0, 86_400_000)
		if err != nil {
			return nil, err
		}
		record.Set("latencyMs", latency)
	}
	if _, err := tx.Insert(ctx, "inferenceUsage", record); err != nil {
		return nil, err
	}
	// A Responses API response belongs to whoever created it first; ids are the provider's and never reused.
	if responseID, ok := input.Get("responseId").(string); ok && inferenceResponseIDPattern.MatchString(responseID) {
		id := responseRecordID(tenantID, responseID)
		existing, err := tx.Get(ctx, "inferenceResponses", id)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			response := core.NewObject("id", id, "tenantId", tenantID, "responseId", responseID)
			response.Assign(responseOwner(principal))
			response.Set("model", name)
			response.Set("providerId", foundRecord.Get("providerId"))
			response.Set("createdAt", now)
			response.Set("expiresAt", record.Get("expiresAt"))
			if _, err := tx.Insert(ctx, "inferenceResponses", response); err != nil {
				return nil, err
			}
		}
	}
	// The spend ledger (billing-service.ts), in the same transaction; it never throws and is idempotent on sourceId.
	if server.Billing != nil {
		priced := core.NewObject(
			"tenantId", record.Get("tenantId"),
			"meter", "inference",
			"costMicros", record.Get("costMicros"),
			"quantity", jsNumber(record.Get("inputTokens"))+jsNumber(record.Get("outputTokens")),
			"identityId", record.Get("identityId"),
		)
		if agentID := record.Get("agentId"); truthy(agentID) {
			priced.Set("agentId", agentID)
		}
		priced.Set("tags", core.NewObject("model", record.Get("model"), "provider", record.Get("providerId")))
		priced.Set("sourceId", record.Get("id"))
		if err := server.Billing.RecordPriced(ctx, tx, priced); err != nil {
			return nil, err
		}
	}
	tokens := UsageTokens(usage)
	standings, err := BudgetStandings(ctx, server, tx, subject, name)
	if err != nil {
		return nil, err
	}
	for _, entry := range standings {
		budget := entry.Get("budget").(*core.Object)
		subjectKey := jsString(entry.Get("subjectKey"))
		current := entry.Get("standing").(*core.Object)
		key := counterID(jsString(budget.Get("id")), subjectKey, jsNumber(current.Get("windowStart")))
		counter, err := tx.Get(ctx, "inferenceCounters", key)
		if err != nil {
			return nil, err
		}
		var previousTokens, previousCost, previousRequests float64
		if counter != nil {
			previousTokens = numberOr(counter.Get("tokens"), 0)
			previousCost = numberOr(counter.Get("costMicros"), 0)
			previousRequests = numberOr(counter.Get("requests"), 0)
		}
		resetsAt := jsNumber(current.Get("resetsAt"))
		next := core.NewObject(
			"id", key,
			"tenantId", budget.Get("tenantId"),
			"budgetId", budget.Get("id"),
			"subjectKey", subjectKey,
			"windowStart", current.Get("windowStart"),
			"windowEnd", resetsAt,
			"tokens", previousTokens+tokens,
			"costMicros", jsMathRound((previousCost+jsNumber(record.Get("costMicros")))*1000)/1000,
			"requests", previousRequests+1,
			"expiresAt", resetsAt+35*inferenceDay,
		)
		if counter != nil && truthy(counter.Get("alerted")) {
			next.Set("alerted", true)
		}
		if counter != nil && truthy(counter.Get("exceeded")) {
			next.Set("exceeded", true)
		}
		threshold := budget.Get("alertAtPercent")
		percent := jsNumber(threshold)
		maxTokens, maxCost, maxRequests := budget.Get("maxTokens"), budget.Get("maxCostMicros"), budget.Get("maxRequests")
		crossed := !isUndefined(threshold) && !truthy(next.Get("alerted")) &&
			((!isUndefined(maxTokens) && jsNumber(next.Get("tokens"))*100 >= jsNumber(maxTokens)*percent) ||
				(!isUndefined(maxCost) && jsNumber(next.Get("costMicros"))*100 >= jsNumber(maxCost)*percent) ||
				(!isUndefined(maxRequests) && jsNumber(next.Get("requests"))*100 >= jsNumber(maxRequests)*percent))
		if crossed {
			next.Set("alerted", true)
		}
		if counter != nil {
			_, err = tx.Put(ctx, "inferenceCounters", next)
		} else {
			_, err = tx.Insert(ctx, "inferenceCounters", next)
		}
		if err != nil {
			return nil, err
		}
		if crossed {
			if err := server.Events.Audit(ctx, tx, principal, "inference:budget-alert", jsString(budget.Get("tenantId")), jsString(budget.Get("id")),
				"allow", false, core.NewObject(
					"budget", budget.Get("name"),
					"percent", threshold,
					"period", budget.Get("period"),
					"usedTokens", next.Get("tokens"),
					"usedCostMicros", next.Get("costMicros"),
				)); err != nil {
				return nil, err
			}
		}
	}
	return record, nil
}

// ProviderCredential (inference.ts providerCredential): A provider's secret material for the gateway: `{ id, kind,
// baseUrl, apiKey, guard? }` with the opened key. Server-side only. `guard` (`{ anyPort, allowInsecureLocalhost,
// allowPrivateNetworks }`) is set when an organization (not the platform) owns a provider with a custom base URL:
// upstream calls must go through the SSRF guard with these address rules, since the organization chose where they go.
func ProviderCredential(ctx context.Context, server *ServerContext, tx core.IamStore, provider *core.Object) (*core.Object, error) {
	apiKey, err := OpenProviderKey(server, provider)
	if err != nil {
		return nil, err
	}
	credential := core.NewObject(
		"id", provider.Get("id"),
		"kind", provider.Get("kind"),
		"baseUrl", provider.Get("baseUrl"),
		"apiKey", apiKey,
	)
	if provider.Get("baseUrl") != ProviderBaseURLs.Get(jsString(provider.Get("kind"))) {
		realm, err := server.Tenant(ctx, tx, provider.Get("tenantId"))
		if err != nil {
			return nil, err
		}
		if realm.Get("type") != "root" || realm.Get("parentId") != nil {
			settings := InferenceSettings(server)
			credential.Set("guard", core.NewObject(
				"anyPort", true,
				"allowInsecureLocalhost", settings.AllowInsecureLocalhost != nil && *settings.AllowInsecureLocalhost,
				"allowPrivateNetworks", settings.AllowPrivateNetworks != nil && *settings.AllowPrivateNetworks,
			))
		}
	}
	return credential, nil
}
