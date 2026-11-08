package server

// Port of packages/server/src/api/inference.ts: the `inference` group (AI model access for people, service accounts
// and agents), the model and budget mutations configuration sync shares, and `iam.inference`, the server-side half
// of inference for the gateway and for applications that call models themselves.
//
// Records follow inference.ts: providers (`inferenceProviders`, the key sealed), models (`inferenceModels`), budgets
// (`inferenceBudgets`), their counters (`inferenceCounters`), usage records (`inferenceUsage`) and single-use check
// tickets (`inferenceTickets`). A gateway permit is a model object { principal, tenantId, check, upstreamModel,
// provider } whose principal is { identity, session } (see PermitPrincipal).

import (
	"context"
	"math"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// inferenceTicketLifetimeMs is ticketLifetimeMs: a check's ticket is valid one hour.
const inferenceTicketLifetimeMs = 3_600_000

// inferenceTierPattern is tierPattern: the short identifiers `family` and `tier` take.
var inferenceTierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// inferenceModelPattern is the model name pattern a budget's `models` take.
var inferenceModelPattern = regexp.MustCompile(`^[A-Za-z0-9*?][A-Za-z0-9._:/@+*?-]{0,127}$`)

// inferenceBody is a request body, empty when there is none.
func inferenceBody(body *core.Object) *core.Object {
	if body == nil {
		return core.NewObject()
	}
	return body
}

// publicProvider is a provider as administrators see it: never the key, only its last four characters.
func publicProvider(provider *core.Object, tenantID string) *core.Object {
	return core.NewObject(
		"id", provider.Get("id"),
		"tenantId", provider.Get("tenantId"),
		"name", provider.Get("name"),
		"kind", provider.Get("kind"),
		"baseUrl", provider.Get("baseUrl"),
		"keyHint", provider.Get("keyHint"),
		"createdAt", provider.Get("createdAt"),
		"updatedAt", provider.Get("updatedAt"),
		"keyRotatedAt", provider.Get("keyRotatedAt"),
		"inherited", !core.StrictEquals(provider.Get("tenantId"), tenantID),
	)
}

// inferenceKeyHint is keyHint: `…` and the key's last four characters.
func inferenceKeyHint(key string) string {
	units := core.ToUTF16(key)
	if len(units) > 4 {
		units = units[len(units)-4:]
	}
	return "…" + core.FromUTF16(units)
}

// usageRow is UsageRow.
type usageRow struct {
	key              string
	label            any
	requests         float64
	errors           float64
	inputTokens      float64
	outputTokens     float64
	cacheReadTokens  float64
	cacheWriteTokens float64
	costMicros       float64
	costUsd          float64
}

// emptyRow is emptyRow: a row with nothing counted (label undefined: left out).
func emptyRow(key string, label any) *usageRow {
	return &usageRow{key: key, label: label}
}

// model is the row as the TypeScript answer.
func (row *usageRow) model() *core.Object {
	out := core.NewObject("key", row.key)
	if !isUndefined(row.label) {
		out.Set("label", row.label)
	}
	return out.Assign(core.NewObject(
		"requests", row.requests,
		"errors", row.errors,
		"inputTokens", row.inputTokens,
		"outputTokens", row.outputTokens,
		"cacheReadTokens", row.cacheReadTokens,
		"cacheWriteTokens", row.cacheWriteTokens,
		"costMicros", row.costMicros,
		"costUsd", row.costUsd,
	))
}

// addUsage is addUsage: counts one usage record into a row.
func addUsage(row *usageRow, record *core.Object) {
	row.requests++
	if record.Get("status") == "error" {
		row.errors++
	}
	row.inputTokens += jsNumber(record.Get("inputTokens"))
	row.outputTokens += jsNumber(record.Get("outputTokens"))
	row.cacheReadTokens += jsNumber(coalesce(record.Get("cacheReadTokens"), 0.0))
	row.cacheWriteTokens += jsNumber(coalesce(record.Get("cacheWriteTokens"), 0.0))
	row.costMicros = jsMathRound((row.costMicros+jsNumber(record.Get("costMicros")))*1000) / 1000
	row.costUsd = jsMathRound(row.costMicros) / 1_000_000
}

// inferenceDayKey is `new Date(Math.floor(createdAt / 86_400_000) * 86_400_000).toISOString().slice(0, 10)`.
func inferenceDayKey(createdAt float64) string {
	day := math.Floor(createdAt/86_400_000) * 86_400_000
	return time.UnixMilli(int64(day)).UTC().Format("2006-01-02")
}

// aggregate is aggregate: usage records between `from` and `to` by one dimension, largest cost first.
func aggregate(records []*core.Object, groupBy string, from, to float64, labels map[string]string) *core.Object {
	rows := map[string]*usageRow{}
	order := []string{}
	totals := emptyRow("total", core.Undefined)
	for _, record := range records {
		var key string
		switch groupBy {
		case "identity":
			key = jsString(record.Get("identityId"))
		case "agent":
			key = jsString(coalesce(record.Get("agentId"), "(none)"))
		case "model":
			key = jsString(record.Get("model"))
		default:
			key = inferenceDayKey(jsNumber(record.Get("createdAt")))
		}
		row := rows[key]
		if row == nil {
			var label any = core.Undefined
			if value, ok := labels[key]; ok {
				label = value
			}
			row = emptyRow(key, label)
			rows[key] = row
			order = append(order, key)
		}
		addUsage(row, record)
		addUsage(totals, record)
	}
	sorted := make([]*usageRow, len(order))
	for index, key := range order {
		sorted[index] = rows[key]
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.costMicros != b.costMicros {
			return a.costMicros > b.costMicros
		}
		if a.requests != b.requests {
			return a.requests > b.requests
		}
		return compareUTF16(a.key, b.key) < 0
	})
	list := make([]any, len(sorted))
	for index, row := range sorted {
		list[index] = row.model()
	}
	return core.NewObject("from", from, "to", to, "groupBy", groupBy, "rows", list, "totals", totals.model())
}

// invocableModels is invocableModels: the enabled models a principal may invoke in a tenant, decided like
// `inference:invoke` without recording.
func invocableModels(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string) ([]any, error) {
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, tenant, InferenceAction)
	if err != nil {
		return nil, err
	}
	// Security clearances: label every model under the scheme the prepared decision already read.
	labeling := PreparedLabeling(prepared)
	result := []any{}
	visible, err := VisibleModels(ctx, server, tx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, item := range visible {
		model, _ := item.Get("model").(*core.Object)
		provider, _ := item.Get("provider").(*core.Object)
		view, err := PublicModel(model, provider, tenantID)
		if err != nil {
			return nil, err
		}
		if !truthy(view.Get("enabled")) {
			continue
		}
		resource, err := server.Decisions.Resolve(ctx, tx, core.ResourceRef{TenantID: tenantID, Type: InferenceResourceType, ID: jsString(model.Get("name"))}, false, "", labeling)
		if err != nil {
			return nil, err
		}
		decision, err := DecideOn(prepared, *resource, "")
		if err != nil {
			return nil, err
		}
		if decision.Allowed {
			result = append(result, view)
		}
	}
	return result, nil
}

// InferenceMutationsResult is api/inference.ts inferenceMutations().
type InferenceMutationsResult struct {
	server *ServerContext
}

// inferencePlatformOnly is platformOnly.
func inferencePlatformOnly(what string) *core.IamError {
	return core.NewIamError("ACCESS_DENIED", "Only a platform administrator can "+what, 403)
}

// assertProviderControl: a model on a parent organization's provider runs on that organization's upstream key, at
// the prices and limits the model sets. Only a platform administrator may publish or change one, so an organization
// cannot price calls on the platform's account at nothing or lift the platform's caps. Turning such a model off stays
// open to it. Undefined provider IDs are skipped.
func (s *InferenceMutationsResult) assertProviderControl(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, providerIDs []any) error {
	for _, providerID := range providerIDs {
		if isUndefined(providerID) {
			continue
		}
		provider, err := tx.Get(ctx, "inferenceProviders", jsString(providerID))
		if err != nil {
			return err
		}
		if provider == nil || core.StrictEquals(provider.Get("tenantId"), tenantID) {
			continue
		}
		root, err := s.server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return err
		}
		if !root {
			return inferencePlatformOnly("publish or change a model on a parent organization’s provider")
		}
	}
	return nil
}

// OwnModel (api/inference.ts inferenceMutations().ownModel): one of the tenant's own models by name (NOT_FOUND
// otherwise).
func (s *InferenceMutationsResult) OwnModel(ctx context.Context, tx core.IamStore, tenantID string, name string) (result *core.Object, err error) {
	unique, err := ModelName(name)
	if err != nil {
		return nil, err
	}
	found, err := tx.Find(ctx, "inferenceModels", core.NewObject("tenantId", tenantID, "uniqueKey", unique), nil)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, core.NewIamError("NOT_FOUND", "Model not found in this tenant", 404)
	}
	return found[0], nil
}

// ownModelOf is OwnModel for a raw name (modelName validates it).
func (s *InferenceMutationsResult) ownModelOf(ctx context.Context, tx core.IamStore, tenantID string, name any) (*core.Object, error) {
	unique, err := ModelName(name)
	if err != nil {
		return nil, err
	}
	return s.OwnModel(ctx, tx, tenantID, unique)
}

// ApplyModelFields (api/inference.ts inferenceMutations().applyModelFields): applies the optional fields of a model
// input to `next` (null clears a field, undefined leaves it alone).
func (s *InferenceMutationsResult) ApplyModelFields(next *core.Object, input *core.Object) (err error) {
	input = inferenceBody(input)
	optionalText := func(key string, value any, max int) error {
		if isUndefined(value) {
			return nil
		}
		if value == nil {
			next.Delete(key)
			return nil
		}
		valueText, err := Text(value, key, max)
		if err != nil {
			return err
		}
		if key != "displayName" && !inferenceTierPattern.MatchString(valueText) {
			return invalidInput(key + " must be a short identifier")
		}
		next.Set(key, valueText)
		return nil
	}
	if err := optionalText("displayName", input.Get("displayName"), 128); err != nil {
		return err
	}
	if err := optionalText("family", input.Get("family"), 64); err != nil {
		return err
	}
	if err := optionalText("tier", input.Get("tier"), 64); err != nil {
		return err
	}
	optionalNumber := func(key string, value any) error {
		if isUndefined(value) {
			return nil
		}
		if value == nil {
			next.Delete(key)
			return nil
		}
		var number float64
		var err error
		if key == "contextWindow" || key == "maxOutputTokens" {
			number, err = Integer(value, key, 1, 100_000_000)
		} else {
			number, err = Price(value, key)
		}
		if err != nil {
			return err
		}
		next.Set(key, number)
		return nil
	}
	for _, key := range []string{"contextWindow", "maxOutputTokens", "inputPricePerMTok", "outputPricePerMTok", "cachedInputPricePerMTok"} {
		if err := optionalNumber(key, input.Get(key)); err != nil {
			return err
		}
	}
	if upstream := input.Get("upstreamModel"); !isUndefined(upstream) {
		value, err := Text(upstream, "upstreamModel", 256)
		if err != nil {
			return err
		}
		next.Set("upstreamModel", value)
	}
	if fallbacks := input.Get("fallbacks"); fallbacks == nil {
		next.Delete("fallbacks")
	} else if !isUndefined(fallbacks) {
		list, err := Strings(fallbacks, "fallbacks")
		if err != nil {
			return err
		}
		names := make([]string, len(list))
		for index, item := range list {
			if names[index], err = ModelName(item); err != nil {
				return err
			}
		}
		names = unique(names)
		if len(names) > 5 {
			return invalidInput("fallbacks may name at most 5 models")
		}
		if name, ok := next.Get("name").(string); ok && containsString(names, name) {
			return invalidInput("A model cannot fall back to itself")
		}
		if len(names) > 0 {
			next.Set("fallbacks", stringsOf(names))
		} else {
			next.Delete("fallbacks")
		}
	}
	if tools := input.Get("providerTools"); tools == nil || tools == "allow" {
		next.Delete("providerTools")
	} else if !isUndefined(tools) {
		mode, ok := tools.(string)
		if !ok || !containsString(ProviderToolsModes, mode) {
			return invalidInput("providerTools must be 'allow', 'deny' or 'policy'")
		}
		next.Set("providerTools", mode)
	}
	if enabled := input.Get("enabled"); !isUndefined(enabled) {
		if _, ok := enabled.(bool); !ok {
			return invalidInput("enabled must be a boolean")
		}
		next.Set("enabled", enabled)
	}
	return nil
}

// BudgetView (api/inference.ts inferenceMutations().budgetView): a budget without its uniqueKey, with maxCostUsd,
// the subject's name, and (for shared pools) its standing in the current window.
func (s *InferenceMutationsResult) BudgetView(ctx context.Context, tx core.IamStore, budget *core.Object) (result *core.Object, err error) {
	view := budget.Spread()
	view.Delete("uniqueKey")
	if micros := budget.Get("maxCostMicros"); !isUndefined(micros) {
		view.Set("maxCostUsd", jsNumber(micros)/1_000_000)
	}
	switch budget.Get("subjectType") {
	case "group":
		group, err := tx.Get(ctx, "groups", jsString(budget.Get("subjectId")))
		if err != nil {
			return nil, err
		}
		if group != nil {
			view.Set("subjectName", group.Get("name"))
		}
	case "identity":
		identity, err := tx.Get(ctx, "identities", jsString(budget.Get("subjectId")))
		if err != nil {
			return nil, err
		}
		if identity != nil {
			view.Set("subjectName", coalesce(identity.Get("email"), identity.Get("name")))
		}
	}
	if budget.Get("subjectType") == "identity" || budget.Get("scope") == "shared" {
		window, err := BudgetWindow(jsString(budget.Get("period")), s.server.Now())
		if err != nil {
			return nil, err
		}
		counter, err := tx.Get(ctx, "inferenceCounters", jsString(budget.Get("id"))+":shared:"+jsString(window.Get("start")))
		if err != nil {
			return nil, err
		}
		standing, err := StandingOf(budget, window, counter)
		if err != nil {
			return nil, err
		}
		view.Set("standing", standing)
	}
	return view, nil
}

// BudgetFields (api/inference.ts inferenceMutations().budgetFields): the validated, user-controlled fields of a
// budget, from an input over the budget it replaces (`previous`, nil for a new one).
func (s *InferenceMutationsResult) BudgetFields(ctx context.Context, tx core.IamStore, tenantID string, input *core.Object, previous *core.Object) (result *core.Object, err error) {
	server := s.server
	input = inferenceBody(input)
	nameText, err := Text(coalesce(input.Get("name"), previousMember(previous, "name")), "name", 100)
	if err != nil {
		return nil, err
	}
	name := core.JSTrim(nameText)
	subjectType := coalesce(input.Get("subjectType"), previousMember(previous, "subjectType"))
	if subjectType != "tenant" && subjectType != "group" && subjectType != "identity" {
		return nil, invalidInput("subjectType must be 'tenant', 'group' or 'identity'")
	}
	var subjectID string
	if subjectType == "tenant" {
		subjectID = tenantID
	} else {
		if subjectID, err = Text(coalesce(input.Get("subjectId"), previousMember(previous, "subjectId")), "subjectId"); err != nil {
			return nil, err
		}
		if subjectType == "group" {
			if _, err := server.Scoped(ctx, tx, "groups", subjectID, tenantID); err != nil {
				return nil, err
			}
		} else if _, err := server.ActiveIdentity(ctx, tx, subjectID, tenantID); err != nil {
			return nil, err
		}
	}
	scope := coalesce(coalesce(input.Get("scope"), previousMember(previous, "scope")), "shared")
	if scope != "shared" && scope != "each" {
		return nil, invalidInput("scope must be 'shared' or 'each'")
	}
	period := coalesce(input.Get("period"), previousMember(previous, "period"))
	if period != "minute" && period != "hour" && period != "day" && period != "month" {
		return nil, invalidInput("period must be 'minute', 'hour', 'day' or 'month'")
	}
	if subjectType == "identity" {
		scope = "shared"
	}
	fields := core.NewObject(
		"uniqueKey", "name:"+core.JSLower(name),
		"name", name,
		"subjectType", subjectType,
		"subjectId", subjectID,
		"scope", scope,
		"period", period,
	)
	// `input[key] === undefined ? previous?.[key] : (input[key] ?? undefined)`.
	replaced := func(key, previousKey string) any {
		value := input.Get(key)
		if isUndefined(value) {
			return previousMember(previous, previousKey)
		}
		if value == nil {
			return core.Undefined
		}
		return value
	}
	if maxTokens := replaced("maxTokens", "maxTokens"); !isUndefined(maxTokens) {
		value, err := Integer(maxTokens, "maxTokens", 1, 1e15)
		if err != nil {
			return nil, err
		}
		fields.Set("maxTokens", value)
	}
	var maxCost any
	switch cost := input.Get("maxCostUsd"); {
	case isUndefined(cost):
		maxCost = previousMember(previous, "maxCostMicros")
	case cost == nil:
		maxCost = core.Undefined
	default:
		dollars, err := Price(cost, "maxCostUsd")
		if err != nil {
			return nil, err
		}
		maxCost = jsMathRound(dollars * 1_000_000)
	}
	if cost := input.Get("maxCostUsd"); !nullish(cost) && jsNumber(cost) <= 0 {
		return nil, invalidInput("maxCostUsd must be positive")
	}
	if !isUndefined(maxCost) {
		fields.Set("maxCostMicros", maxCost)
	}
	if maxRequests := replaced("maxRequests", "maxRequests"); !isUndefined(maxRequests) {
		value, err := Integer(maxRequests, "maxRequests", 1, 1_000_000_000)
		if err != nil {
			return nil, err
		}
		fields.Set("maxRequests", value)
	}
	if isUndefined(fields.Get("maxTokens")) && isUndefined(fields.Get("maxCostMicros")) && isUndefined(fields.Get("maxRequests")) {
		return nil, invalidInput("A budget needs at least one of maxTokens, maxCostUsd and maxRequests")
	}
	if models := replaced("models", "models"); !isUndefined(models) {
		list, err := Strings(models, "models")
		if err != nil {
			return nil, err
		}
		list = unique(list)
		for _, pattern := range list {
			if !inferenceModelPattern.MatchString(pattern) {
				return nil, invalidInput("Invalid model pattern " + pattern)
			}
		}
		if len(list) > 0 {
			fields.Set("models", stringsOf(list))
		}
	}
	if alert := replaced("alertAtPercent", "alertAtPercent"); !isUndefined(alert) {
		value, err := Integer(alert, "alertAtPercent", 1, 100)
		if err != nil {
			return nil, err
		}
		fields.Set("alertAtPercent", value)
	}
	return fields, nil
}

// CreateModel (api/inference.ts inferenceMutations().createModel): publishes a model of the tenant on a provider it
// may use (`input` holds name, providerId, upstreamModel and the optional model fields).
func (s *InferenceMutationsResult) CreateModel(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, input *core.Object) (result *core.Object, err error) {
	server := s.server
	input = inferenceBody(input)
	name, err := ModelName(input.Get("name"))
	if err != nil {
		return nil, err
	}
	existing, err := tx.Find(ctx, "inferenceModels", core.NewObject("tenantId", tenantID, "uniqueKey", name), nil)
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		return nil, core.NewIamError("CONFLICT", "A model with this name exists in this tenant", 409)
	}
	providerID, err := Text(input.Get("providerId"), "providerId")
	if err != nil {
		return nil, err
	}
	provider, err := VisibleProvider(ctx, server, tx, tenantID, providerID)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, core.NewIamError("NOT_FOUND", "Provider not found", 404)
	}
	if err := s.assertProviderControl(ctx, tx, principal, tenantID, []any{provider.Get("id")}); err != nil {
		return nil, err
	}
	now := float64(server.Now())
	upstream, err := Text(input.Get("upstreamModel"), "upstreamModel", 256)
	if err != nil {
		return nil, err
	}
	model := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", name,
		"name", name,
		"providerId", provider.Get("id"),
		"upstreamModel", upstream,
		"enabled", true,
		"createdAt", now,
		"updatedAt", now,
	)
	if err := s.ApplyModelFields(model, input); err != nil {
		return nil, err
	}
	if _, err := tx.Insert(ctx, "inferenceModels", model); err != nil {
		return nil, err
	}
	return PublicModel(model, provider, tenantID)
}

// UpdateModel (api/inference.ts inferenceMutations().updateModel): changes one of the tenant's own models, found by
// its name.
func (s *InferenceMutationsResult) UpdateModel(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, input *core.Object) (result *core.Object, err error) {
	server := s.server
	input = inferenceBody(input)
	model, err := s.ownModelOf(ctx, tx, tenantID, input.Get("name"))
	if err != nil {
		return nil, err
	}
	next := model.Spread(core.NewObject("updatedAt", float64(server.Now())))
	if providerID := input.Get("providerId"); !isUndefined(providerID) {
		id, err := Text(providerID, "providerId")
		if err != nil {
			return nil, err
		}
		provider, err := VisibleProvider(ctx, server, tx, tenantID, id)
		if err != nil {
			return nil, err
		}
		if provider == nil {
			return nil, core.NewIamError("NOT_FOUND", "Provider not found", 404)
		}
		next.Set("providerId", provider.Get("id"))
	}
	if err := s.ApplyModelFields(next, input); err != nil {
		return nil, err
	}
	// Turning a model off never needs more than managing the tenant's models.
	onlyDisables := false
	if next.Get("enabled") == false {
		a, _, err := core.Stringify(next.Spread(core.NewObject("enabled", model.Get("enabled"), "updatedAt", 0.0)))
		if err != nil {
			return nil, err
		}
		b, _, err := core.Stringify(model.Spread(core.NewObject("updatedAt", 0.0)))
		if err != nil {
			return nil, err
		}
		onlyDisables = a == b
	}
	if !onlyDisables {
		if err := s.assertProviderControl(ctx, tx, principal, tenantID, []any{model.Get("providerId"), next.Get("providerId")}); err != nil {
			return nil, err
		}
	}
	saved, err := tx.Put(ctx, "inferenceModels", next)
	if err != nil {
		return nil, err
	}
	provider, err := VisibleProvider(ctx, server, tx, tenantID, jsString(saved.Get("providerId")))
	if err != nil {
		return nil, err
	}
	return PublicModel(saved, provider, tenantID)
}

// DeleteModel (api/inference.ts inferenceMutations().deleteModel): removes one of the tenant's own models.
func (s *InferenceMutationsResult) DeleteModel(ctx context.Context, tx core.IamStore, tenantID string, name string) (err error) {
	model, err := s.OwnModel(ctx, tx, tenantID, name)
	if err != nil {
		return err
	}
	return tx.Delete(ctx, "inferenceModels", jsString(model.Get("id")))
}

// deleteModelOf is DeleteModel for a raw name (modelName validates it).
func (s *InferenceMutationsResult) deleteModelOf(ctx context.Context, tx core.IamStore, tenantID string, name any) error {
	model, err := s.ownModelOf(ctx, tx, tenantID, name)
	if err != nil {
		return err
	}
	return tx.Delete(ctx, "inferenceModels", jsString(model.Get("id")))
}

// SaveBudget (api/inference.ts inferenceMutations().saveBudget): creates a budget, or replaces `previous`; names are
// unique regardless of case.
func (s *InferenceMutationsResult) SaveBudget(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, input *core.Object, previous *core.Object) (result *core.Object, err error) {
	server := s.server
	// A cap the platform put on an organization binds the organization's own administrators.
	platform, err := server.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return nil, err
	}
	if previous != nil && truthy(previous.Get("platform")) && !platform {
		return nil, inferencePlatformOnly("change a budget the platform set")
	}
	fields, err := s.BudgetFields(ctx, tx, tenantID, input, previous)
	if err != nil {
		return nil, err
	}
	others, err := tx.Find(ctx, "inferenceBudgets", core.NewObject("tenantId", tenantID, "uniqueKey", fields.Get("uniqueKey")), nil)
	if err != nil {
		return nil, err
	}
	for _, other := range others {
		if !core.StrictEquals(other.Get("id"), previousMember(previous, "id")) {
			return nil, core.NewIamError("CONFLICT", "A budget with this name exists", 409)
		}
	}
	now := float64(server.Now())
	var budget *core.Object
	if previous != nil {
		budget = fields.Spread(core.NewObject("id", previous.Get("id"), "tenantId", tenantID, "createdAt", previous.Get("createdAt"), "updatedAt", now))
	} else {
		budget = fields.Spread(core.NewObject("id", ID(), "tenantId", tenantID, "createdAt", now, "updatedAt", now))
	}
	if platform {
		budget.Set("platform", true)
	} else {
		budget.Delete("platform")
	}
	if previous != nil {
		_, err = tx.Put(ctx, "inferenceBudgets", budget)
	} else {
		_, err = tx.Insert(ctx, "inferenceBudgets", budget)
	}
	if err != nil {
		return nil, err
	}
	return budget, nil
}

// DeleteBudget (api/inference.ts inferenceMutations().deleteBudget): deletes a budget and its counters.
func (s *InferenceMutationsResult) DeleteBudget(ctx context.Context, tx core.IamStore, principal *Principal, budget *core.Object) (err error) {
	if truthy(budget.Get("platform")) {
		root, err := s.server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return err
		}
		if !root {
			return inferencePlatformOnly("remove a budget the platform set")
		}
	}
	if err := tx.Delete(ctx, "inferenceBudgets", jsString(budget.Get("id"))); err != nil {
		return err
	}
	counters, err := tx.Find(ctx, "inferenceCounters", core.NewObject("budgetId", budget.Get("id")), nil)
	if err != nil {
		return err
	}
	for _, counter := range counters {
		if err := tx.Delete(ctx, "inferenceCounters", jsString(counter.Get("id"))); err != nil {
			return err
		}
	}
	return nil
}

// InferenceMutations (api/inference.ts inferenceMutations): Model and budget changes without a credential, for the
// `inference` API (which authorizes first) and for configuration sync (sync.ts, ai-sync.ts). Every function runs
// inside the caller's transaction.
func InferenceMutations(server *ServerContext) (result *InferenceMutationsResult, err error) {
	return &InferenceMutationsResult{server: server}, nil
}

// InferenceAPI is the `inference` API group (packages/server/src/api/inference.ts createInferenceApi): AI model
// access for people, service accounts and agents. Administrators with `iam:inference:manage` register upstream
// providers (keys are sealed and never returned), the models callers use, and budgets; `iam:inference:read` reads
// them and the usage reports. Access to a model is an ordinary policy decision: `inference:invoke` on `model/{name}`.
// Callers check their own access (`check`, `listMine`) and see their own usage (`myUsage`); an external gateway
// redeems the ticket a check returns with `record` (`iam:inference:record`). Requires the `inference` option.
type InferenceAPI struct {
	server    *ServerContext
	mutations *InferenceMutationsResult
}

// CreateInferenceAPI builds the `inference` API group.
func CreateInferenceAPI(server *ServerContext) *InferenceAPI {
	mutations, _ := InferenceMutations(server)
	return &InferenceAPI{server: server, mutations: mutations}
}

// enabled refuses with FEATURE_DISABLED when inference is off (`enabled` wraps every operation).
func (api *InferenceAPI) enabled() error {
	return AssertInference(api.server)
}

// settings is inferenceSettings(ctx).
func (api *InferenceAPI) settings() *InferenceOptions {
	return InferenceSettings(api.server)
}

// ownProvider is one of the tenant's own providers (NOT_FOUND otherwise).
func (api *InferenceAPI) ownProvider(ctx context.Context, tx core.IamStore, providerID any, tenantID string) (*core.Object, error) {
	return api.server.Scoped(ctx, tx, "inferenceProviders", providerID, tenantID)
}

// allowedBaseURL: custom base URLs point the gateway (and the provider key) somewhere else, so they need root unless
// the deployment opted in (`inference.allowCustomBaseUrls`).
func (api *InferenceAPI) allowedBaseURL(ctx context.Context, tx core.IamStore, principal *Principal, kind string, value any) (string, error) {
	fallback := ProviderBaseURLs.Get(kind)
	if isUndefined(value) {
		if !truthy(fallback) {
			return "", invalidInput("An openai-compatible provider needs a baseUrl")
		}
		return jsString(fallback), nil
	}
	settings := api.settings()
	url, err := BaseURL(value, settings)
	if err != nil {
		return "", err
	}
	if !core.StrictEquals(url, fallback) && !(settings.AllowCustomBaseUrls != nil && *settings.AllowCustomBaseUrls) {
		root, err := api.server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return "", err
		}
		if !root {
			return "", core.NewIamError("ACCESS_DENIED", "Only a root administrator can point a provider at a custom base URL on this deployment", 403)
		}
	}
	return url, nil
}

// usageRange is usageRange: `from` (default: the start of this month, UTC) and `to` (default: now).
func (api *InferenceAPI) usageRange(input *core.Object) (float64, float64, error) {
	now := api.server.Now()
	to := float64(now)
	if value := input.Get("to"); !isUndefined(value) {
		number, err := Integer(value, "to", 0, maxSafeInteger)
		if err != nil {
			return 0, 0, err
		}
		to = number
	}
	var from float64
	if value := input.Get("from"); !isUndefined(value) {
		number, err := Integer(value, "from", 0, maxSafeInteger)
		if err != nil {
			return 0, 0, err
		}
		from = number
	} else {
		window, err := BudgetWindow("month", now)
		if err != nil {
			return 0, 0, err
		}
		from = jsNumber(window.Get("start"))
	}
	if from > to {
		return 0, 0, invalidInput("from must not be after to")
	}
	return from, to, nil
}

// usageRecords is records: the usage records matching filter created between from and to.
func usageRecords(ctx context.Context, tx core.IamStore, filter *core.Object, from, to float64) ([]*core.Object, error) {
	found, err := tx.Find(ctx, "inferenceUsage", filter, nil)
	if err != nil {
		return nil, err
	}
	out := []*core.Object{}
	for _, record := range found {
		createdAt := jsNumber(record.Get("createdAt"))
		if createdAt >= from && createdAt <= to {
			out = append(out, record)
		}
	}
	return out, nil
}

// usageLabels is labelsFor: each identity's email, else its name.
func usageLabels(ctx context.Context, tx core.IamStore, ids []string) (map[string]string, error) {
	labels := map[string]string{}
	for _, key := range ids {
		identity, err := tx.Get(ctx, "identities", key)
		if err != nil {
			return nil, err
		}
		if identity != nil {
			labels[key] = jsString(coalesce(identity.Get("email"), identity.Get("name")))
		}
	}
	return labels, nil
}

// operate runs fn in the operation envelope once inference is known to be on.
func (api *InferenceAPI) operate(ctx context.Context, credential core.CredentialInput, tenantID any, action, resourceID string, fn func(ctx context.Context, call MutationContext) (any, error)) (any, error) {
	return Operate(ctx, api.server.Operations, credential, tenantID, action, resourceID, fn, false)
}

// Check is POST {basePath}/inference/check. Tells the caller whether they may invoke a model now and, when they may, returns a single-use ticket for an external gateway.
func (api *InferenceAPI) Check(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceCheckInput]) (Out[apitypes.InferenceCheckOutput], error) {
	server := api.server
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceCheckOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.InferenceCheckOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.InferenceCheckOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		request := core.NewObject("tenantId", tenantID, "model", input.Get("model"))
		if value := input.Get("estimatedTokens"); !isUndefined(value) {
			request.Set("estimatedTokens", value)
		}
		if value := input.Get("tools"); !isUndefined(value) {
			request.Set("tools", value)
		}
		result, err := CheckInvocation(ctx, server, tx, principal, request)
		if err != nil {
			return nil, err
		}
		if !truthy(result.Get("allowed")) {
			return result, nil
		}
		ticket := Token()
		now := float64(server.Now())
		var agentID any = core.Undefined
		if principal.Session.Get("kind") == "delegated" {
			agentID = principal.Session.Get("agentId")
		} else if principal.Identity.Get("kind") == "agent" {
			agentID = principal.Identity.Get("id")
		}
		record := core.NewObject(
			"id", ticket,
			"tenantId", tenantID,
			"identityId", principal.Identity.Get("id"),
			"sessionId", principal.Session.Get("id"),
			"sessionKind", principal.Session.Get("kind"),
		)
		if _, ok := agentID.(string); ok {
			record.Set("agentId", agentID)
		}
		if delegationID, ok := principal.Session.Get("delegationId").(string); ok {
			record.Set("delegationId", delegationID)
		}
		record.Set("model", member(result.Get("model"), "name"))
		record.Set("createdAt", now)
		record.Set("expiresAt", now+inferenceTicketLifetimeMs)
		if _, err := tx.Insert(ctx, "inferenceTickets", record); err != nil {
			return nil, err
		}
		return result.Spread(core.NewObject("ticket", ticket)), nil
	})
	if err != nil {
		return Out[apitypes.InferenceCheckOutput]{}, err
	}
	return Answer[apitypes.InferenceCheckOutput](result), nil
}

// CreateModel is POST {basePath}/inference/createModel. Publishes a model under a public name, served by a provider of this tenant or an ancestor.
func (api *InferenceAPI) CreateModel(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceCreateModelInput]) (Out[apitypes.InferenceCreateModelOutput], error) {
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceCreateModelOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:manage", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		return api.mutations.CreateModel(ctx, call.Tx, call.Principal, jsString(call.Tenant.Get("id")), inferenceBody(input.Body))
	})
	if err != nil {
		return Out[apitypes.InferenceCreateModelOutput]{}, err
	}
	return Answer[apitypes.InferenceCreateModelOutput](result), nil
}

// CreateProvider is POST {basePath}/inference/createProvider. Registers an upstream model provider account, whose API key is sealed and never returned.
func (api *InferenceAPI) CreateProvider(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceCreateProviderInput]) (Out[apitypes.InferenceCreateProviderOutput], error) {
	server := api.server
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceCreateProviderOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:manage", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenantID := call.Tx, call.Principal, jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		nameText, err := Text(input.Get("name"), "name", 100)
		if err != nil {
			return nil, err
		}
		name := core.JSTrim(nameText)
		kind, ok := input.Get("kind").(string)
		if !ok || !containsString(ProviderKinds, kind) {
			return nil, invalidInput("kind must be one of " + joinStrings(ProviderKinds, ", "))
		}
		apiKey, err := ProviderKey(input.Get("apiKey"))
		if err != nil {
			return nil, err
		}
		uniqueKey := "name:" + core.JSLower(name)
		existing, err := tx.Find(ctx, "inferenceProviders", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
		if err != nil {
			return nil, err
		}
		if len(existing) > 0 {
			return nil, core.NewIamError("CONFLICT", "A provider with this name exists", 409)
		}
		now := float64(server.Now())
		providerID := ID()
		baseURL, err := api.allowedBaseURL(ctx, tx, principal, kind, input.Get("baseUrl"))
		if err != nil {
			return nil, err
		}
		sealed, err := SealProviderKey(server.Options.Secret, providerID, apiKey)
		if err != nil {
			return nil, err
		}
		provider := core.NewObject(
			"id", providerID,
			"tenantId", tenantID,
			"uniqueKey", uniqueKey,
			"name", name,
			"kind", kind,
			"baseUrl", baseURL,
			"keySealed", sealed,
			"keyHint", inferenceKeyHint(apiKey),
			"createdAt", now,
			"updatedAt", now,
			"keyRotatedAt", now,
		)
		if _, err := tx.Insert(ctx, "inferenceProviders", provider); err != nil {
			return nil, err
		}
		return publicProvider(provider, tenantID), nil
	})
	if err != nil {
		return Out[apitypes.InferenceCreateProviderOutput]{}, err
	}
	return Answer[apitypes.InferenceCreateProviderOutput](result), nil
}

// DeleteBudget is POST {basePath}/inference/deleteBudget. Deletes a budget together with its usage counters.
func (api *InferenceAPI) DeleteBudget(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceDeleteBudgetInput]) (Out[apitypes.InferenceDeleteBudgetOutput], error) {
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceDeleteBudgetOutput]{}, err
	}
	budgetID, err := Text(input.Get("budgetId"), "budgetId")
	if err != nil {
		return Out[apitypes.InferenceDeleteBudgetOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:manage", budgetID, func(ctx context.Context, call MutationContext) (any, error) {
		budget, err := api.server.Scoped(ctx, call.Tx, "inferenceBudgets", input.Get("budgetId"), jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		if err := api.mutations.DeleteBudget(ctx, call.Tx, call.Principal, budget); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	})
	if err != nil {
		return Out[apitypes.InferenceDeleteBudgetOutput]{}, err
	}
	return Answer[apitypes.InferenceDeleteBudgetOutput](result), nil
}

// DeleteModel is POST {basePath}/inference/deleteModel. Removes one of this tenant's models; an inherited model of the same name becomes visible again.
func (api *InferenceAPI) DeleteModel(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceDeleteModelInput]) (Out[apitypes.InferenceDeleteModelOutput], error) {
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceDeleteModelOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:manage", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		if err := api.mutations.deleteModelOf(ctx, call.Tx, jsString(call.Tenant.Get("id")), input.Get("name")); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	})
	if err != nil {
		return Out[apitypes.InferenceDeleteModelOutput]{}, err
	}
	return Answer[apitypes.InferenceDeleteModelOutput](result), nil
}

// DeleteProvider is POST {basePath}/inference/deleteProvider. Deletes a provider that no model uses, together with its sealed key.
func (api *InferenceAPI) DeleteProvider(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceDeleteProviderInput]) (Out[apitypes.InferenceDeleteProviderOutput], error) {
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceDeleteProviderOutput]{}, err
	}
	providerID, err := Text(input.Get("providerId"), "providerId")
	if err != nil {
		return Out[apitypes.InferenceDeleteProviderOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:manage", providerID, func(ctx context.Context, call MutationContext) (any, error) {
		provider, err := api.ownProvider(ctx, call.Tx, input.Get("providerId"), jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		models, err := call.Tx.Find(ctx, "inferenceModels", core.NewObject("providerId", provider.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		if len(models) > 0 {
			return nil, core.NewIamError("RESOURCE_IN_USE", "Models still use this provider", 409)
		}
		if err := call.Tx.Delete(ctx, "inferenceProviders", jsString(provider.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	})
	if err != nil {
		return Out[apitypes.InferenceDeleteProviderOutput]{}, err
	}
	return Answer[apitypes.InferenceDeleteProviderOutput](result), nil
}

// ListBudgets is POST {basePath}/inference/listBudgets. Lists the tenant's budgets by name, with the current window's standing of each shared pool.
func (api *InferenceAPI) ListBudgets(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceListBudgetsInput]) (Out[apitypes.InferenceListBudgetsOutput], error) {
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceListBudgetsOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:read", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		budgets, err := call.Tx.Find(ctx, "inferenceBudgets", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(budgets, func(i, j int) bool {
			return localeCompare(jsString(budgets[i].Get("name")), jsString(budgets[j].Get("name"))) < 0
		})
		views := make([]any, len(budgets))
		for index, budget := range budgets {
			view, err := api.mutations.BudgetView(ctx, call.Tx, budget)
			if err != nil {
				return nil, err
			}
			views[index] = view
		}
		return views, nil
	})
	if err != nil {
		return Out[apitypes.InferenceListBudgetsOutput]{}, err
	}
	return Answer[apitypes.InferenceListBudgetsOutput](result), nil
}

// ListMine is POST {basePath}/inference/listMine. Lists the enabled models the caller may invoke, for a model picker.
func (api *InferenceAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceListMineInput]) (Out[apitypes.InferenceListMineOutput], error) {
	server := api.server
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceListMineOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.InferenceListMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.InferenceListMineOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		return invocableModels(ctx, server, tx, principal, tenantID)
	})
	if err != nil {
		return Out[apitypes.InferenceListMineOutput]{}, err
	}
	return Answer[apitypes.InferenceListMineOutput](result), nil
}

// ListModels is POST {basePath}/inference/listModels. Lists every model the tenant can see, its own and inherited ones, by name.
func (api *InferenceAPI) ListModels(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceListModelsInput]) (Out[apitypes.InferenceListModelsOutput], error) {
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceListModelsOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:read", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		visible, err := VisibleModels(ctx, api.server, call.Tx, tenantID)
		if err != nil {
			return nil, err
		}
		models := make([]any, len(visible))
		for index, item := range visible {
			model, _ := item.Get("model").(*core.Object)
			provider, _ := item.Get("provider").(*core.Object)
			view, err := PublicModel(model, provider, tenantID)
			if err != nil {
				return nil, err
			}
			models[index] = view
		}
		return models, nil
	})
	if err != nil {
		return Out[apitypes.InferenceListModelsOutput]{}, err
	}
	return Answer[apitypes.InferenceListModelsOutput](result), nil
}

// ListProviders is POST {basePath}/inference/listProviders. Lists the providers this tenant's models may use: its own, then its ancestors'.
func (api *InferenceAPI) ListProviders(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceListProvidersInput]) (Out[apitypes.InferenceListProvidersOutput], error) {
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceListProvidersOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:read", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		realms, err := api.server.Ancestry(ctx, call.Tx, call.Tenant)
		if err != nil {
			return nil, err
		}
		providers := []*core.Object{}
		for _, realm := range realms {
			found, err := call.Tx.Find(ctx, "inferenceProviders", core.NewObject("tenantId", realm.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			for _, provider := range found {
				providers = append(providers, publicProvider(provider, tenantID))
			}
		}
		sort.SliceStable(providers, func(i, j int) bool {
			a, b := providers[i].Get("inherited") == true, providers[j].Get("inherited") == true
			if a != b {
				return !a
			}
			return localeCompare(jsString(providers[i].Get("name")), jsString(providers[j].Get("name"))) < 0
		})
		return objectList(providers), nil
	})
	if err != nil {
		return Out[apitypes.InferenceListProvidersOutput]{}, err
	}
	return Answer[apitypes.InferenceListProvidersOutput](result), nil
}

// MyUsage is POST {basePath}/inference/myUsage. Returns the caller's own usage by model and the standing of every budget that covers them.
func (api *InferenceAPI) MyUsage(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceMyUsageInput]) (Out[apitypes.InferenceMyUsageOutput], error) {
	server := api.server
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceMyUsageOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.InferenceMyUsageOutput]{}, err
	}
	from, to, err := api.usageRange(inferenceBody(input.Body))
	if err != nil {
		return Out[apitypes.InferenceMyUsageOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.InferenceMyUsageOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if !core.StrictEquals(principal.Session.Get("tenantId"), tenantID) {
			return nil, core.NewIamError("ACCESS_DENIED", "Usage is read in the credential’s own tenant", 403)
		}
		found, err := usageRecords(ctx, tx, core.NewObject("tenantId", tenantID, "identityId", principal.Identity.Get("id")), from, to)
		if err != nil {
			return nil, err
		}
		report := aggregate(found, "model", from, to, map[string]string{})
		subject, err := UsageSubject(ctx, server, tx, principal, tenantID)
		if err != nil {
			return nil, err
		}
		names := newOrderedSet()
		for _, record := range found {
			names.Add(jsString(record.Get("model")))
		}
		visible, err := VisibleModels(ctx, server, tx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, item := range visible {
			names.Add(jsString(member(item.Get("model"), "name")))
		}
		seen := map[string]any{}
		order := []string{}
		for _, name := range names.Values() {
			standings, err := BudgetStandings(ctx, server, tx, subject, name)
			if err != nil {
				return nil, err
			}
			for _, item := range standings {
				standing := item.Get("standing")
				budgetID := jsString(member(standing, "budgetId"))
				if _, ok := seen[budgetID]; !ok {
					order = append(order, budgetID)
				}
				seen[budgetID] = standing
			}
		}
		budgets := make([]any, len(order))
		for index, budgetID := range order {
			budgets[index] = seen[budgetID]
		}
		return report.Spread(core.NewObject("budgets", budgets)), nil
	})
	if err != nil {
		return Out[apitypes.InferenceMyUsageOutput]{}, err
	}
	return Answer[apitypes.InferenceMyUsageOutput](result), nil
}

// Record is POST {basePath}/inference/record. Meters a call an external gateway made after check, by redeeming the check's ticket.
func (api *InferenceAPI) Record(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceRecordInput]) (Out[apitypes.InferenceRecordOutput], error) {
	server := api.server
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceRecordOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:record", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		tx, tenantID := call.Tx, jsString(call.Tenant.Get("id"))
		ticketID, err := Text(input.Get("ticket"), "ticket")
		if err != nil {
			return nil, err
		}
		ticket, err := tx.Get(ctx, "inferenceTickets", ticketID)
		if err != nil {
			return nil, err
		}
		if ticket == nil || !core.StrictEquals(ticket.Get("tenantId"), tenantID) || jsNumber(ticket.Get("expiresAt")) <= float64(server.Now()) {
			return nil, core.NewIamError("INVALID_TICKET", "Unknown, used or expired inference ticket", 400)
		}
		if err := tx.Delete(ctx, "inferenceTickets", jsString(ticket.Get("id"))); err != nil {
			return nil, err
		}
		// Metered as the caller the check saw, not re-authenticated: an ended session (or a deleted caller) must not
		// let a call it was allowed escape the budgets it counts against.
		identity, err := tx.Get(ctx, "identities", jsString(ticket.Get("identityId")))
		if err != nil {
			return nil, err
		}
		if identity == nil {
			identity = core.NewObject(
				"id", ticket.Get("identityId"),
				"tenantId", tenantID,
				"kind", "user",
				"name", ticket.Get("identityId"),
				"status", "deleted",
				"emailVerified", false,
				"owner", false,
				"rootAdmin", false,
				"createdAt", ticket.Get("createdAt"),
			)
		}
		stored, err := tx.Get(ctx, "sessions", jsString(ticket.Get("sessionId")))
		if err != nil {
			return nil, err
		}
		base := stored
		if base == nil {
			base = core.NewObject(
				"id", ticket.Get("sessionId"),
				"tenantId", tenantID,
				"identityId", ticket.Get("identityId"),
				"createdAt", ticket.Get("createdAt"),
				"lastSeenAt", ticket.Get("createdAt"),
				"expiresAt", ticket.Get("expiresAt"),
				"mfa", false,
			)
		}
		kind := coalesce(coalesce(ticket.Get("sessionKind"), previousMember(stored, "kind")), "user")
		session := base.Spread(core.NewObject("kind", kind))
		if agentID := ticket.Get("agentId"); !isUndefined(agentID) && session.Get("kind") == "delegated" {
			session.Set("agentId", agentID)
		}
		if delegationID := ticket.Get("delegationId"); !isUndefined(delegationID) {
			session.Set("delegationId", delegationID)
		}
		caller := &Principal{Identity: identity, Session: session}
		usage := core.NewObject(
			"tenantId", tenantID,
			"model", ticket.Get("model"),
			"inputTokens", input.Get("inputTokens"),
			"outputTokens", input.Get("outputTokens"),
		)
		for _, key := range []string{"cacheReadTokens", "cacheWriteTokens", "status", "requestId", "latencyMs"} {
			if value := input.Get(key); !isUndefined(value) {
				usage.Set(key, value)
			}
		}
		record, err := RecordInvocation(ctx, server, tx, caller, usage)
		if err != nil {
			return nil, err
		}
		return core.NewObject("recorded", true, "costMicros", record.Get("costMicros")), nil
	})
	if err != nil {
		return Out[apitypes.InferenceRecordOutput]{}, err
	}
	return Answer[apitypes.InferenceRecordOutput](result), nil
}

// SetBudget is POST {basePath}/inference/setBudget. Creates a budget, or replaces one when budgetId is given.
func (api *InferenceAPI) SetBudget(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceSetBudgetInput]) (Out[apitypes.InferenceSetBudgetOutput], error) {
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceSetBudgetOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:manage", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		var previous *core.Object
		if budgetID := input.Get("budgetId"); !isUndefined(budgetID) {
			found, err := api.server.Scoped(ctx, call.Tx, "inferenceBudgets", budgetID, tenantID)
			if err != nil {
				return nil, err
			}
			previous = found
		}
		budget, err := api.mutations.SaveBudget(ctx, call.Tx, call.Principal, tenantID, inferenceBody(input.Body), previous)
		if err != nil {
			return nil, err
		}
		return api.mutations.BudgetView(ctx, call.Tx, budget)
	})
	if err != nil {
		return Out[apitypes.InferenceSetBudgetOutput]{}, err
	}
	return Answer[apitypes.InferenceSetBudgetOutput](result), nil
}

// UpdateModel is POST {basePath}/inference/updateModel. Changes one of this tenant's models, found by its name.
func (api *InferenceAPI) UpdateModel(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceUpdateModelInput]) (Out[apitypes.InferenceUpdateModelOutput], error) {
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceUpdateModelOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:manage", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		return api.mutations.UpdateModel(ctx, call.Tx, call.Principal, jsString(call.Tenant.Get("id")), inferenceBody(input.Body))
	})
	if err != nil {
		return Out[apitypes.InferenceUpdateModelOutput]{}, err
	}
	return Answer[apitypes.InferenceUpdateModelOutput](result), nil
}

// UpdateProvider is POST {basePath}/inference/updateProvider. Renames a provider, moves its base URL, or replaces its API key.
func (api *InferenceAPI) UpdateProvider(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceUpdateProviderInput]) (Out[apitypes.InferenceUpdateProviderOutput], error) {
	server := api.server
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceUpdateProviderOutput]{}, err
	}
	providerID, err := Text(input.Get("providerId"), "providerId")
	if err != nil {
		return Out[apitypes.InferenceUpdateProviderOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:manage", providerID, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenantID := call.Tx, call.Principal, jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		provider, err := api.ownProvider(ctx, tx, input.Get("providerId"), tenantID)
		if err != nil {
			return nil, err
		}
		next := provider.Spread(core.NewObject("updatedAt", float64(server.Now())))
		if name := input.Get("name"); !isUndefined(name) {
			nameText, err := Text(name, "name", 100)
			if err != nil {
				return nil, err
			}
			next.Set("name", core.JSTrim(nameText))
			next.Set("uniqueKey", "name:"+core.JSLower(core.JSTrim(nameText)))
			others, err := tx.Find(ctx, "inferenceProviders", core.NewObject("tenantId", tenantID, "uniqueKey", next.Get("uniqueKey")), nil)
			if err != nil {
				return nil, err
			}
			for _, other := range others {
				if !core.StrictEquals(other.Get("id"), provider.Get("id")) {
					return nil, core.NewIamError("CONFLICT", "A provider with this name exists", 409)
				}
			}
		}
		if baseURL := input.Get("baseUrl"); !isUndefined(baseURL) {
			url, err := api.allowedBaseURL(ctx, tx, principal, jsString(provider.Get("kind")), baseURL)
			if err != nil {
				return nil, err
			}
			next.Set("baseUrl", url)
		}
		// The sealed key is write-only: pointing the provider somewhere else must not send it along, so a new base URL
		// needs the key again.
		if !core.StrictEquals(next.Get("baseUrl"), provider.Get("baseUrl")) && isUndefined(input.Get("apiKey")) {
			return nil, invalidInput("Changing the base URL needs the provider key (apiKey) again")
		}
		if value := input.Get("apiKey"); !isUndefined(value) {
			apiKey, err := ProviderKey(value)
			if err != nil {
				return nil, err
			}
			sealed, err := SealProviderKey(server.Options.Secret, jsString(provider.Get("id")), apiKey)
			if err != nil {
				return nil, err
			}
			next.Set("keySealed", sealed)
			next.Set("keyHint", inferenceKeyHint(apiKey))
			next.Set("keyRotatedAt", next.Get("updatedAt"))
		}
		saved, err := tx.Put(ctx, "inferenceProviders", next)
		if err != nil {
			return nil, err
		}
		return publicProvider(saved, tenantID), nil
	})
	if err != nil {
		return Out[apitypes.InferenceUpdateProviderOutput]{}, err
	}
	return Answer[apitypes.InferenceUpdateProviderOutput](result), nil
}

// Usage is POST {basePath}/inference/usage. Reports model calls between two times, grouped by identity, agent, model, or day.
func (api *InferenceAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.InferenceUsageInput]) (Out[apitypes.InferenceUsageOutput], error) {
	if err := api.enabled(); err != nil {
		return Out[apitypes.InferenceUsageOutput]{}, err
	}
	result, err := api.operate(ctx, credential, input.Get("tenantId"), "iam:inference:read", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (any, error) {
		tx := call.Tx
		from, to, err := api.usageRange(inferenceBody(input.Body))
		if err != nil {
			return nil, err
		}
		groupBy := coalesce(input.Get("groupBy"), "model")
		group, ok := groupBy.(string)
		if !ok || !containsString([]string{"identity", "agent", "model", "day"}, group) {
			return nil, invalidInput("groupBy must be 'identity', 'agent', 'model' or 'day'")
		}
		filter := core.NewObject("tenantId", call.Tenant.Get("id"))
		if value := input.Get("identityId"); !isUndefined(value) {
			identityID, err := Text(value, "identityId")
			if err != nil {
				return nil, err
			}
			filter.Set("identityId", identityID)
		}
		if value := input.Get("agentId"); !isUndefined(value) {
			agentID, err := Text(value, "agentId")
			if err != nil {
				return nil, err
			}
			filter.Set("agentId", agentID)
		}
		if value := input.Get("model"); !isUndefined(value) {
			model, err := ModelName(value)
			if err != nil {
				return nil, err
			}
			filter.Set("model", model)
		}
		found, err := usageRecords(ctx, tx, filter, from, to)
		if err != nil {
			return nil, err
		}
		labels := map[string]string{}
		if group == "identity" || group == "agent" {
			keys := newOrderedSet()
			for _, record := range found {
				var key any
				if group == "identity" {
					key = record.Get("identityId")
				} else {
					key = record.Get("agentId")
				}
				if truthy(key) {
					keys.Add(jsString(key))
				}
			}
			if labels, err = usageLabels(ctx, tx, keys.Values()); err != nil {
				return nil, err
			}
		}
		return aggregate(found, group, from, to, labels), nil
	})
	if err != nil {
		return Out[apitypes.InferenceUsageOutput]{}, err
	}
	return Answer[apitypes.InferenceUsageOutput](result), nil
}

// InferenceRuntime is `iam.inference` (api/inference.ts createInferenceRuntime): the server-side half of inference,
// for the gateway and for applications that call models themselves. `Authorize` checks a credential for a model and
// returns the opened provider credential (never expose it); `Record` meters a call; `Gateway` builds the HTTP gateway.
type InferenceRuntime struct {
	server *ServerContext
}

// CreateInferenceRuntime builds the runtime.
func CreateInferenceRuntime(server *ServerContext) *InferenceRuntime {
	return &InferenceRuntime{server: server}
}

// PermitPrincipal is the caller of a gateway permit: its `principal` member, either { identity, session } (what
// Authorize answers, and what a permit read from JSON holds) or a *Principal stored raw.
func PermitPrincipal(permit *core.Object) *Principal {
	switch principal := member(permit, "principal").(type) {
	case *Principal:
		return principal
	case *core.Object:
		identity, _ := principal.Get("identity").(*core.Object)
		session, _ := principal.Get("session").(*core.Object)
		return &Principal{Identity: identity, Session: session}
	}
	return nil
}

// Models lists the enabled models a credential may invoke in its session's tenant (or tenantID).
func (r *InferenceRuntime) Models(ctx context.Context, credential core.CredentialInput, tenantID ...string) ([]any, error) {
	server := r.server
	if err := AssertInference(server); err != nil {
		return nil, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		tenant := jsString(principal.Session.Get("tenantId"))
		if len(tenantID) > 0 && tenantID[0] != "" {
			tenant = tenantID[0]
		}
		return invocableModels(ctx, server, tx, principal, tenant)
	})
}

// Gateway is the HTTP inference gateway (inference-gateway.ts createInferenceGateway): Anthropic `POST /v1/messages`
// (and `/v1/messages/count_tokens`), OpenAI `POST /v1/chat/completions`, `/v1/responses` and `/v1/embeddings`, and
// `GET /v1/models`, authorized and metered per caller. Mount it on any route.
func (r *InferenceRuntime) Gateway(options *core.Object) (http.Handler, error) {
	handle, err := CreateInferenceGateway(&GatewayRuntime{server: r.server}, options)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		response, err := handle(request.Context(), request)
		if err != nil {
			writeResponse(w, errorResponse(err))
			return
		}
		writeGatewayResponse(w, response)
	}), nil
}

// writeGatewayResponse streams a gateway answer to the client, flushing as the body arrives (server-sent events).
func writeGatewayResponse(w http.ResponseWriter, response *http.Response) {
	header := w.Header()
	for key, values := range response.Header {
		header[key] = append([]string(nil), values...)
	}
	w.WriteHeader(response.StatusCode)
	if response.Body == nil {
		return
	}
	defer response.Body.Close()
	flusher, _ := w.(http.Flusher)
	buffer := make([]byte, 32*1024)
	for {
		n, err := response.Body.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// Authorize authenticates `credential`, checks `model` for it in the credential's tenant (or `tenantId`), with the
// provider-run `tools` the request asks for, and on success returns the permit with the provider's opened key
// ({ principal, tenantId, check, upstreamModel, provider }); a refusal answers { denied: check }. Throws
// FEATURE_DISABLED when inference is off.
func (r *InferenceRuntime) Authorize(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	server := r.server
	input = inferenceBody(input)
	if err := AssertInference(server); err != nil {
		return nil, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		tenantID := coalesce(input.Get("tenantId"), principal.Session.Get("tenantId"))
		request := core.NewObject("tenantId", tenantID, "model", input.Get("model"))
		if value := input.Get("estimatedTokens"); !isUndefined(value) {
			request.Set("estimatedTokens", value)
		}
		if value := input.Get("tools"); !isUndefined(value) {
			request.Set("tools", value)
		}
		check, err := CheckInvocation(ctx, server, tx, principal, request)
		if err != nil {
			return nil, err
		}
		if !truthy(check.Get("allowed")) {
			return core.NewObject("denied", check), nil
		}
		found, err := ResolveModel(ctx, server, tx, jsString(tenantID), jsString(member(check.Get("model"), "name")))
		if err != nil {
			return nil, err
		}
		provider, _ := member(found, "provider").(*core.Object)
		if provider == nil {
			return nil, core.NewIamError("NOT_FOUND", "Model provider not found", 404)
		}
		credential, err := ProviderCredential(ctx, server, tx, provider)
		if err != nil {
			return nil, err
		}
		return core.NewObject(
			"principal", core.NewObject("identity", principal.Identity, "session", principal.Session),
			"tenantId", tenantID,
			"check", check,
			"upstreamModel", member(found.Get("model"), "upstreamModel"),
			"provider", credential,
		), nil
	})
}

// OwnsResponse reports whether a Responses API response was created through the gateway by the permit's caller, at
// its provider.
func (r *InferenceRuntime) OwnsResponse(ctx context.Context, permit *core.Object, responseID string) (bool, error) {
	server := r.server
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
		return OwnsInferenceResponse(ctx, server, tx, PermitPrincipal(permit), jsString(member(permit, "tenantId")), responseID, jsString(member(member(permit, "provider"), "id")))
	})
}

// Record meters a call made under a permit (`usage` without its tenantId: the permit's).
func (r *InferenceRuntime) Record(ctx context.Context, permit *core.Object, usage *core.Object) (*core.Object, error) {
	server := r.server
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return RecordInvocation(ctx, server, tx, PermitPrincipal(permit), inferenceBody(usage).Spread(core.NewObject("tenantId", member(permit, "tenantId"))))
	})
}
