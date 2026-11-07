package server

// Port of packages/server/src/api/clearances.ts: security clearances and classification labels (the `clearances`
// option; FEATURE_DISABLED otherwise). Schemes: `templates` (no permission), `getScheme` (iam:clearances:read),
// `defineScheme` / `updateScheme` (iam:classifications:manage, recent sign-in) on `iam/classifications/scheme`.
// Clearances on `iam/clearances/{identityId}`: `grant`, `update`, `readIn`, `reinstate`, `revoke`
// (iam:clearances:adjudicate, recent sign-in), `debrief` (adjudicate), `suspend` (iam:clearances:suspend, usable in an
// incident), `get` / `list` (iam:clearances:read), `explain` (adjudicate), and `mine` (no permission). Nobody
// adjudicates their own clearance, not even an owner or root; under `within-own` adjudication an officer grants only
// levels and compartments their own clearance holds (an owner or root may bootstrap a level or compartment nobody in
// the scheme's subtree holds yet). Labels on `iam/classifications/labels/{type}/{id}`: `label` raises
// (iam:classifications:label), `declassify` lowers or removes (iam:classifications:declassify, recent sign-in, and the
// caller's own clearance must dominate the current label), `getLabel` / `listLabels` (iam:clearances:read).

import (
	"context"
	"math"
	"regexp"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// ClearancesAPI is the `clearances` API group (packages/server/src/api/clearances.ts createClearancesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/clearances/{method} onto it.
type ClearancesAPI struct {
	server *ServerContext
}

// CreateClearancesAPI builds the `clearances` API group.
func CreateClearancesAPI(server *ServerContext) *ClearancesAPI {
	return &ClearancesAPI{server: server}
}

// --- validation ------------------------------------------------------------------------------------

// clearanceTemplateNames are templateNames, in TypeScript order.
var clearanceTemplateNames = []struct{ id, name string }{
	{"us", "United States"},
	{"uk", "United Kingdom"},
	{"nato", "NATO"},
	{"corporate", "Corporate"},
}

// clearanceTemplate is `Object.hasOwn(templateNames, value)`: the template name when value names one.
func clearanceTemplate(value any) (string, bool) {
	name, ok := value.(string)
	if !ok {
		return "", false
	}
	for _, template := range clearanceTemplateNames {
		if template.id == name {
			return name, true
		}
	}
	return "", false
}

var clearanceAdjudicationModes = map[string]bool{"within-own": true, "unrestricted": true}

var clearanceStatusNames = map[string]bool{"interim": true, "active": true, "suspended": true, "revoked": true, "terminated": true}

// clearanceLiveStatuses are the statuses of a clearance that is in force or can be again (by reinstatement).
var clearanceLiveStatuses = map[string]bool{"interim": true, "active": true, "suspended": true}

var clearanceCountryPattern = regexp.MustCompile(`^[A-Z]{3}$`)

const (
	clearanceDayMs  = 86_400_000
	clearanceYearMs = 365 * clearanceDayMs
)

const clearanceSchemeResource = "classifications/scheme"

// clearanceIn is `set.has(value)` for a set of status or mode names.
func clearanceIn(set map[string]bool, value any) bool {
	name, ok := value.(string)
	return ok && set[name]
}

// clearanceResource is `clearances/{identityId}`.
func clearanceResource(identityID any) (string, error) {
	text, err := Text(identityID, "identityId")
	if err != nil {
		return "", err
	}
	return "clearances/" + text, nil
}

// clearanceLabelResource is `classifications/labels/{type}/{id}`. Too long to authorize as one resource id, the id
// becomes `sha256:{hex}` (so per-type policy patterns keep working), and with a very long type the whole name does.
func clearanceLabelResource(resourceType, resourceID string) string {
	plain := "classifications/labels/" + resourceType + "/" + resourceID
	if utf16Len(plain) <= 256 {
		return plain
	}
	typed := "classifications/labels/" + resourceType + "/sha256:" + Hash(resourceID)
	if utf16Len(typed) <= 256 {
		return typed
	}
	return "classifications/labels/sha256:" + Hash(resourceType+"/"+resourceID)
}

// clearanceFlag is flag(): set is false for undefined; anything but a boolean is refused.
func clearanceFlag(value any, name string) (flag bool, set bool, err error) {
	if isUndefined(value) {
		return false, false, nil
	}
	flag, ok := value.(bool)
	if !ok {
		return false, false, invalidInput(name + " must be a boolean")
	}
	return flag, true, nil
}

// clearanceSorted is `[...values].sort()` (UTF-16 code unit order) as a model list.
func clearanceSorted(values []string) []any {
	sorted := append([]string(nil), values...)
	sort.SliceStable(sorted, func(i, j int) bool { return compareUTF16(sorted[i], sorted[j]) < 0 })
	return stringsOf(sorted)
}

// clearanceCitizenship is citizenshipList().
func clearanceCitizenship(value any) ([]any, error) {
	list, ok := value.([]any)
	if !ok || float64(len(list)) > ClearanceLimits.MaxCitizenship {
		return nil, invalidInput("citizenship must list at most " + core.NumberString(ClearanceLimits.MaxCitizenship) + " countries")
	}
	countries := newOrderedSet()
	for _, item := range list {
		country, ok := item.(string)
		if !ok || !clearanceCountryPattern.MatchString(country) {
			return nil, invalidInput("citizenship must hold ISO 3166-1 alpha-3 codes in upper case")
		}
		countries.Add(country)
	}
	return clearanceSorted(countries.Values()), nil
}

// clearanceLabelType is labelType(): a resource type that can carry a label, a resource type name other than the
// platform's own. Never a `/`, so the `{type}/{id}` key of a label and its `classifications/labels/{type}/{id}`
// resource name each belong to exactly one resource.
func clearanceLabelType(value any) (string, error) {
	resourceType, err := Text(value, "type")
	if err != nil {
		return "", err
	}
	if !ResourceTypeName.MatchString(resourceType) {
		return "", invalidInput(`type must be a resource type name: a lowercase letter, then up to 63 lowercase letters, digits or "-"`)
	}
	if ReservedResourceTypes.Has(resourceType) {
		return "", invalidInput("Platform resource types cannot be labeled")
	}
	return resourceType, nil
}

// clearanceRequiredTypes is requiredTypes().
func clearanceRequiredTypes(value any) ([]any, error) {
	list, ok := value.([]any)
	if !ok || float64(len(list)) > ClearanceLimits.MaxRequiredTypes {
		return nil, invalidInput("requireLabels must list at most " + core.NumberString(ClearanceLimits.MaxRequiredTypes) + " resource types")
	}
	types := newOrderedSet()
	for _, item := range list {
		if item == "*" {
			types.Add("*")
			continue
		}
		resourceType, err := clearanceLabelType(item)
		if err != nil {
			return nil, err
		}
		types.Add(resourceType)
	}
	return clearanceSorted(types.Values()), nil
}

// clearanceNotifyEmails is notifyEmails(): nil (undefined) for null or an empty list.
func clearanceNotifyEmails(value any) (*core.Object, error) {
	if value == nil {
		return nil, nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	list, ok := input.Get("emails").([]any)
	if !ok || float64(len(list)) > ClearanceLimits.MaxNotifyEmails {
		return nil, invalidInput("notify.emails must list at most " + core.NumberString(ClearanceLimits.MaxNotifyEmails) + " addresses")
	}
	addresses := make([]string, 0, len(list))
	for _, item := range list {
		address, err := Email(item)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	emails := clearanceSorted(newOrderedSet(addresses...).Values())
	if len(emails) == 0 {
		return nil, nil
	}
	return core.NewObject("emails", emails), nil
}

// clearanceDefinition reads a stored scheme definition as the core type.
func clearanceDefinition(value any) *core.ClassificationSchemeDefinition {
	definition := &core.ClassificationSchemeDefinition{}
	if err := core.FromRecord(value, definition); err != nil {
		return &core.ClassificationSchemeDefinition{}
	}
	return definition
}

// clearanceSchemeDefinition is `scheme.definition` as the core type.
func clearanceSchemeDefinition(scheme *core.Object) *core.ClassificationSchemeDefinition {
	return clearanceDefinition(scheme.Get("definition"))
}

// clearanceDefinitionModel is a validated definition as the model value TypeScript stores.
func clearanceDefinitionModel(definition *core.ClassificationSchemeDefinition) *core.Object {
	model, _ := core.Normalize(definition).(*core.Object)
	return model
}

// clearanceLabelModel is a label (a model value or a core label) as a model value; nil when there is none.
func clearanceLabelModel(label any) any {
	switch value := label.(type) {
	case *core.ClassificationLabel:
		if value == nil {
			return nil
		}
		return value.ToValue()
	case core.ClassificationLabel:
		return value.ToValue()
	}
	return core.Normalize(label)
}

// clearanceSchemeLevel is schemeLevel() for a level id of any type: undefined (nil) unless it is a string.
func clearanceSchemeLevel(scheme *core.Object, levelID any) (*core.Object, error) {
	id, ok := levelID.(string)
	if !ok {
		return nil, nil
	}
	return SchemeLevel(scheme, id)
}

// clearanceSchemeSettings is schemeSettings(): the settings of a scheme over `previous` (nil when defining), checked
// against `definition`.
func clearanceSchemeSettings(input *core.Object, definition *core.Object, typed *core.ClassificationSchemeDefinition, previous *core.Object) (*core.Object, error) {
	var name any = core.Undefined
	if raw := input.Get("name"); !isUndefined(raw) {
		text, err := Text(raw, "name", 100)
		if err != nil {
			return nil, err
		}
		name = core.JSTrim(text)
	} else {
		name = previousMember(previous, "name")
	}
	if !truthy(name) {
		return nil, invalidInput("name is required")
	}
	var requireLabels any
	if raw := input.Get("requireLabels"); !isUndefined(raw) {
		types, err := clearanceRequiredTypes(raw)
		if err != nil {
			return nil, err
		}
		requireLabels = types
	} else {
		requireLabels = coalesce(previousMember(previous, "requireLabels"), []any{})
	}
	var defaultLabel any = core.Undefined
	if raw := input.Get("defaultLabel"); isUndefined(raw) {
		defaultLabel = previousMember(previous, "defaultLabel")
		if truthy(defaultLabel) && !core.IsValidClassificationLabel(defaultLabel, typed) {
			return nil, invalidInput("The default label is not valid under the new definition; set a new defaultLabel or null")
		}
		if truthy(defaultLabel) {
			checked, err := core.ValidateLabel(defaultLabel, typed)
			if err != nil {
				return nil, err
			}
			defaultLabel = checked.ToValue()
		}
	} else if raw != nil {
		checked, err := core.ValidateLabel(raw, typed)
		if err != nil {
			return nil, err
		}
		defaultLabel = checked.ToValue()
	}
	var guestCeiling any
	if raw := input.Get("guestCeiling"); isUndefined(raw) {
		guestCeiling = coalesce(previousMember(previous, "guestCeiling"), nil)
	} else {
		guestCeiling = raw
	}
	if guestCeiling != nil {
		level, err := clearanceSchemeLevel(core.NewObject("definition", definition), guestCeiling)
		if err != nil {
			return nil, err
		}
		if level == nil {
			return nil, invalidInput("guestCeiling must be a level id of the scheme, or null")
		}
	}
	interim, set, err := clearanceFlag(input.Get("interimAllowed"), "interimAllowed")
	if err != nil {
		return nil, err
	}
	var interimAllowed any = interim
	if !set {
		interimAllowed = coalesce(previousMember(previous, "interimAllowed"), false)
	}
	adjudication := coalesce(coalesce(input.Get("adjudication"), previousMember(previous, "adjudication")), "within-own")
	if !clearanceIn(clearanceAdjudicationModes, adjudication) {
		return nil, invalidInput("adjudication must be within-own or unrestricted")
	}
	var notify any = core.Undefined
	if raw := input.Get("notify"); isUndefined(raw) {
		notify = previousMember(previous, "notify")
	} else {
		emails, err := clearanceNotifyEmails(raw)
		if err != nil {
			return nil, err
		}
		if emails != nil {
			notify = emails
		}
	}
	settings := core.NewObject("name", name, "requireLabels", requireLabels)
	if truthy(defaultLabel) {
		settings.Set("defaultLabel", defaultLabel)
	}
	settings.Set("guestCeiling", guestCeiling)
	settings.Set("interimAllowed", interimAllowed)
	settings.Set("adjudication", adjudication)
	if truthy(notify) {
		settings.Set("notify", notify)
	}
	return settings, nil
}

// clearanceList is `[...value]` of a stored list (empty when it is none).
func clearanceList(value any) []any {
	list, _ := value.([]any)
	return append([]any{}, list...)
}

// clearanceSchemeView is schemeView().
func clearanceSchemeView(scheme *core.Object, askingTenantID any) *core.Object {
	view := core.NewObject(
		"tenantId", scheme.Get("tenantId"),
		"inherited", !core.StrictEquals(scheme.Get("tenantId"), askingTenantID),
		"name", scheme.Get("name"),
		"definition", scheme.Get("definition"),
		"requireLabels", clearanceList(scheme.Get("requireLabels")),
	)
	if defaultLabel := scheme.Get("defaultLabel"); truthy(defaultLabel) {
		view.Set("defaultLabel", defaultLabel)
	}
	view.Set("guestCeiling", scheme.Get("guestCeiling"))
	view.Set("interimAllowed", scheme.Get("interimAllowed"))
	view.Set("adjudication", scheme.Get("adjudication"))
	if notify := scheme.Get("notify"); truthy(notify) {
		view.Set("notify", core.NewObject("emails", clearanceList(member(notify, "emails"))))
	}
	view.Set("createdAt", scheme.Get("createdAt"))
	view.Set("createdBy", scheme.Get("createdBy"))
	view.Set("updatedAt", scheme.Get("updatedAt"))
	view.Set("updatedBy", scheme.Get("updatedBy"))
	view.Set("version", scheme.Get("version"))
	return view
}

// clearanceLabelView is labelView(); scheme nil is undefined.
func clearanceLabelView(stored *core.Object, scheme *core.Object) (*core.Object, error) {
	var level *core.Object
	if scheme != nil {
		var err error
		if level, err = clearanceSchemeLevel(scheme, member(stored.Get("label"), "level")); err != nil {
			return nil, err
		}
	}
	view := core.NewObject("type", stored.Get("type"), "id", stored.Get("resourceId"), "label", stored.Get("label"))
	if level != nil {
		view.Set("levelName", level.Get("name"))
	}
	view.Set("inheritToChildren", stored.Get("inheritToChildren"))
	view.Set("labeledBy", stored.Get("labeledBy"))
	view.Set("labeledAt", stored.Get("labeledAt"))
	view.Set("version", stored.Get("version"))
	return view, nil
}

// clearanceLabelMetadata is labelMetadata(): audit metadata for a label, level and compartment ids, never names.
func clearanceLabelMetadata(label any) *core.Object {
	metadata := core.NewObject("level", member(label, "level"))
	if compartments, ok := member(label, "compartments").([]any); ok && len(compartments) > 0 {
		metadata.Set("compartments", clearanceList(compartments))
	}
	if truthy(member(label, "noforn")) {
		metadata.Set("noforn", true)
	}
	if releasable := member(label, "releasableTo"); truthy(releasable) {
		metadata.Set("releasableTo", clearanceList(releasable))
	}
	return metadata
}

// clearanceStrings reads a party's set (a list, a Go set or a model object of members) as its members.
func clearanceStrings(value any) []string {
	var out []string
	switch set := value.(type) {
	case []any:
		for _, item := range set {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
	case []string:
		out = append(out, set...)
	case map[string]bool:
		for key, held := range set {
			if held {
				out = append(out, key)
			}
		}
	case *orderedSet:
		if set != nil {
			out = set.Values()
		}
	case *core.Object:
		if set != nil {
			out = set.Keys()
		}
	}
	return out
}

// clearancePartyModel is a party (a model object or a core party) as a model object: identityId, rank, compartments
// and citizenship.
func clearancePartyModel(value any) *core.Object {
	switch party := value.(type) {
	case *core.Object:
		if party != nil {
			return party
		}
	case *core.ClearanceParty:
		if party != nil {
			return clearanceCoreParty(*party)
		}
	case core.ClearanceParty:
		return clearanceCoreParty(party)
	}
	return core.NewObject("identityId", core.Undefined, "rank", -1.0, "compartments", []any{}, "citizenship", []any{})
}

func clearanceCoreParty(party core.ClearanceParty) *core.Object {
	set := func(values map[string]bool) []any {
		var out []string
		for key, held := range values {
			if held {
				out = append(out, key)
			}
		}
		return clearanceSorted(out)
	}
	return core.NewObject("identityId", party.IdentityID, "rank", party.Rank, "compartments", set(party.Compartments), "citizenship", set(party.Citizenship))
}

// clearanceParty is `state.party`.
func clearanceParty(state *core.Object) *core.Object { return clearancePartyModel(state.Get("party")) }

// clearancePartyRank is `party.rank`.
func clearancePartyRank(party *core.Object) float64 {
	if rank, ok := party.Get("rank").(float64); ok {
		return rank
	}
	return math.NaN()
}

// clearancePartyHas is `party.compartments.has(id)`.
func clearancePartyHas(party *core.Object, compartmentID string) bool {
	return containsString(clearanceStrings(party.Get("compartments")), compartmentID)
}

// clearanceLevelModel is a level (a model object or a core level) as a model object; nil when there is none.
func clearanceLevelModel(value any) *core.Object {
	switch level := value.(type) {
	case *core.Object:
		return level
	case *core.ClassificationLevel:
		if level == nil {
			return nil
		}
		model, _ := core.Normalize(level).(*core.Object)
		return model
	case core.ClassificationLevel:
		model, _ := core.Normalize(level).(*core.Object)
		return model
	}
	return nil
}

// clearancePartyView is partyView().
func clearancePartyView(state *core.Object) *core.Object {
	party := clearanceParty(state)
	rank := clearancePartyRank(party)
	view := core.NewObject("identityId", party.Get("identityId"), "status", state.Get("status"))
	if level := clearanceLevelModel(state.Get("level")); level != nil && rank >= 0 {
		view.Set("level", level.Get("id"))
	}
	view.Set("rank", party.Get("rank"))
	view.Set("compartments", clearanceSorted(clearanceStrings(party.Get("compartments"))))
	view.Set("citizenship", clearanceSorted(clearanceStrings(party.Get("citizenship"))))
	return view
}

// clearanceParties is `states.map((state) => state.party)`.
func clearanceParties(states []*core.Object) []*core.Object {
	parties := make([]*core.Object, len(states))
	for index, state := range states {
		parties[index] = clearanceParty(state)
	}
	return parties
}

// clearanceNumber is `typeof value === 'number'`.
func clearanceNumber(value any) (float64, bool) {
	number, ok := value.(float64)
	return number, ok
}

// --- the API helpers -------------------------------------------------------------------------------

// schemeIn is schemeIn(): the scheme in force for a tenant; NOT_FOUND when none applies.
func (api *ClearancesAPI) schemeIn(ctx context.Context, tx core.IamStore, tenant *core.Object) (*core.Object, error) {
	scheme, err := api.effectiveScheme(ctx, tx, tenant)
	if err != nil {
		return nil, err
	}
	if scheme == nil {
		return nil, core.NewIamError("NOT_FOUND", "No classification scheme applies to this organization", 404)
	}
	return scheme, nil
}

// effectiveScheme is `effectiveScheme(tx, await ctx.ancestry(tx, tenant))`.
func (api *ClearancesAPI) effectiveScheme(ctx context.Context, tx core.IamStore, tenant *core.Object) (*core.Object, error) {
	chain, err := api.server.Ancestry(ctx, tx, tenant)
	if err != nil {
		return nil, err
	}
	return EffectiveScheme(ctx, tx, chain)
}

// clearanceNoImpersonation is noImpersonation().
func clearanceNoImpersonation(principal *Principal) error {
	if truthy(principal.Session.Get("impersonatorId")) {
		return core.NewIamError("IMPERSONATION_RESTRICTED", "Clearances and labels cannot be changed while impersonating", 403)
	}
	return nil
}

// clearanceActing is what officer() returns: the officer's parties' clearances in the tenant, and whether they are a
// root administrator.
type clearanceActing struct {
	states []*core.Object
	root   bool
}

// officer is the officer acting: never while impersonating, never a guest, never on their own clearance (`subject`,
// nil for none), whatever their role (owners and root included). Returns their parties' clearances in the tenant,
// for `within-own`.
func (api *ClearancesAPI) officer(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, scheme *core.Object, subject *core.Object) (*clearanceActing, error) {
	server := api.server
	if err := clearanceNoImpersonation(principal); err != nil {
		return nil, err
	}
	if !isUndefined(principal.Identity.Get("guest")) && core.StrictEquals(principal.Identity.Get("tenantId"), tenant.Get("id")) {
		return nil, NewOperationDenied("Guests cannot adjudicate clearances")
	}
	root, err := server.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return nil, err
	}
	scope, err := AgentDecisionScopeOf(ctx, tx, principal, server.Now())
	if err != nil {
		return nil, err
	}
	states, err := SessionParties(ctx, tx, principal, tenant, scope, scheme, server.Now(), root)
	if err != nil {
		return nil, err
	}
	if subject != nil {
		self := newOrderedSet(jsString(principal.Identity.Get("id")))
		for _, state := range states {
			if id, ok := clearanceParty(state).Get("identityId").(string); ok {
				self.Add(id)
			}
		}
		if agentID, ok := principal.Session.Get("agentId").(string); ok {
			self.Add(agentID)
		}
		if originalID, ok := principal.Session.Get("originalIdentityId").(string); ok {
			self.Add(originalID)
		}
		if subjectID, ok := subject.Get("id").(string); ok && self.Has(subjectID) {
			return nil, NewOperationDenied("Your own clearance is adjudicated by another officer")
		}
	}
	return &clearanceActing{states: states, root: root}, nil
}

// clearanceNeed is what `within-own` adjudication asks of an officer: a level rank, or a compartment.
type clearanceNeed struct {
	byRank        bool
	rank          float64
	compartmentID string
}

// heldInSubtree is whether an active clearance of the scheme's subtree (people of active, unexpired accounts; guests
// do not count) holds at least `need.rank`, or is read into `need.compartmentId`.
func (api *ClearancesAPI) heldInSubtree(ctx context.Context, tx core.IamStore, scheme *core.Object, need clearanceNeed) (bool, error) {
	now := float64(api.server.Now())
	records, err := tx.Find(ctx, ClearanceCollections.Clearances, core.NewObject("schemeTenantId", scheme.Get("tenantId"), "status", "active"), nil)
	if err != nil {
		return false, err
	}
	for _, record := range records {
		if !core.StrictEquals(record.Get("schemeTenantId"), scheme.Get("tenantId")) || record.Get("status") != "active" {
			continue
		}
		if expiresAt, ok := clearanceNumber(record.Get("expiresAt")); ok && expiresAt <= now {
			continue
		}
		if need.byRank {
			level, err := clearanceSchemeLevel(scheme, record.Get("level"))
			if err != nil {
				return false, err
			}
			if level == nil || jsNumber(level.Get("rank")) < need.rank {
				continue
			}
		} else {
			held := false
			readIns, _ := record.Get("readIns").([]any)
			for _, item := range readIns {
				if core.StrictEquals(member(item, "compartmentId"), need.compartmentID) {
					held = true
					break
				}
			}
			if !held {
				continue
			}
		}
		holder, err := tx.Get(ctx, "identities", jsString(record.Get("identityId")))
		if err != nil {
			return false, err
		}
		if holder == nil || !core.StrictEquals(holder.Get("tenantId"), record.Get("tenantId")) || holder.Get("status") != "active" ||
			!isUndefined(holder.Get("guest")) {
			continue
		}
		if expiresAt, ok := clearanceNumber(holder.Get("expiresAt")); ok && expiresAt <= now {
			continue
		}
		return true, nil
	}
	return false, nil
}

// withinOwn is `within-own` adjudication: every party of the officer must hold `need.rank` (or be read into
// `need.compartmentId`). The bootstrap exception lets an owner of the tenant or root grant it when nobody in the
// scheme's subtree holds it yet. Returns true for a bootstrap grant (audited as such); refuses (audited denial)
// otherwise.
func (api *ClearancesAPI) withinOwn(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, scheme *core.Object, acting *clearanceActing, need clearanceNeed) (bool, error) {
	if scheme.Get("adjudication") == "unrestricted" {
		return false, nil
	}
	covered := len(acting.states) > 0
	for _, state := range acting.states {
		party := clearanceParty(state)
		rank := clearancePartyRank(party)
		if need.byRank {
			covered = covered && rank >= need.rank
		} else {
			covered = covered && rank >= 0 && clearancePartyHas(party, need.compartmentID)
		}
	}
	if covered {
		return false, nil
	}
	tenantID := tenant.Get("id")
	owner := principal.Session.Get("kind") == "user" && truthy(principal.Identity.Get("owner")) &&
		core.StrictEquals(principal.Identity.Get("tenantId"), tenantID) && core.StrictEquals(principal.Session.Get("tenantId"), tenantID)
	if owner || acting.root {
		held, err := api.heldInSubtree(ctx, tx, scheme, need)
		if err != nil {
			return false, err
		}
		if !held {
			return true, nil
		}
	}
	return false, NewOperationDenied("Under within-own adjudication an officer grants only what their own clearance holds")
}

// levelOf is a level of the scheme by id (INVALID_INPUT otherwise).
func (api *ClearancesAPI) levelOf(scheme *core.Object, value any) (*core.Object, error) {
	id, err := Text(value, "level", 64)
	if err != nil {
		return nil, err
	}
	level, err := SchemeLevel(scheme, id)
	if err != nil {
		return nil, err
	}
	if level == nil {
		return nil, invalidInput("level must be a level id of the scheme")
	}
	return level, nil
}

// clearanceAssertGuestLevel is assertGuestLevel(): guests hold at most the scheme's guest ceiling, and nothing when
// it sets none.
func clearanceAssertGuestLevel(scheme *core.Object, identity *core.Object, level *core.Object) error {
	if isUndefined(identity.Get("guest")) {
		return nil
	}
	ceiling, err := clearanceSchemeLevel(scheme, scheme.Get("guestCeiling"))
	if err != nil {
		return err
	}
	if ceiling == nil {
		return invalidInput("Guests hold no clearance under this scheme")
	}
	if jsNumber(level.Get("rank")) > jsNumber(ceiling.Get("rank")) {
		return invalidInput("Guests hold at most the scheme’s guest ceiling")
	}
	return nil
}

// investigationOf is the investigation of a clearance: its kind and when it completed.
func (api *ClearancesAPI) investigationOf(value any) (*core.Object, error) {
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	completedAt, err := Integer(input.Get("completedAt"), "investigation.completedAt", 0, float64(api.server.Now())+clearanceDayMs)
	if err != nil {
		return nil, err
	}
	kind, err := Text(input.Get("kind"), "investigation.kind", 64)
	if err != nil {
		return nil, err
	}
	return core.NewObject("kind", core.JSTrim(kind), "completedAt", completedAt), nil
}

// dueOf is a reinvestigation date, within twenty years.
func (api *ClearancesAPI) dueOf(value any) (float64, error) {
	at, err := Integer(value, "reinvestigationDue", 0, maxSafeInteger)
	if err != nil {
		return 0, err
	}
	if at > float64(api.server.Now())+20*clearanceYearMs {
		return 0, invalidInput("reinvestigationDue must be within twenty years")
	}
	return at, nil
}

// endOf is a clearance's end: in the future, within twenty years.
func (api *ClearancesAPI) endOf(value any) (float64, error) {
	at, err := Integer(value, "expiresAt", 0, maxSafeInteger)
	if err != nil {
		return 0, err
	}
	if at <= float64(api.server.Now()) {
		return 0, invalidInput("expiresAt must be in the future")
	}
	if at > float64(api.server.Now())+20*clearanceYearMs {
		return 0, invalidInput("expiresAt must be within twenty years")
	}
	return at, nil
}

// liveRecord is the record of a live (interim, active or suspended) clearance issued under the scheme in force.
func (api *ClearancesAPI) liveRecord(ctx context.Context, tx core.IamStore, identity *core.Object, scheme *core.Object) (*core.Object, error) {
	record, err := ReadClearance(ctx, tx, identity)
	if err != nil {
		return nil, err
	}
	if record == nil || !clearanceIn(clearanceLiveStatuses, record.Get("status")) {
		return nil, core.NewIamError("NOT_FOUND", "This identity holds no clearance", 404)
	}
	if !core.StrictEquals(record.Get("schemeTenantId"), scheme.Get("tenantId")) {
		return nil, core.NewIamError("CONFLICT", "This clearance was issued under another scheme; revoke it and grant a new one", 409)
	}
	return record, nil
}

// clearanceView is a clearance as officers see it; scheme nil is none in force, identity nil reads the holder.
func (api *ClearancesAPI) clearanceView(ctx context.Context, tx core.IamStore, record *core.Object, scheme *core.Object, identity *core.Object) (*core.Object, error) {
	person := identity
	if person == nil {
		var err error
		if person, err = tx.Get(ctx, "identities", jsString(record.Get("identityId"))); err != nil {
			return nil, err
		}
	}
	now := api.server.Now()
	var state, level *core.Object
	if scheme != nil {
		var err error
		if state, err = PartyState(ctx, tx, scheme, person, jsString(record.Get("identityId")), jsString(record.Get("tenantId")), now); err != nil {
			return nil, err
		}
		if level, err = clearanceSchemeLevel(scheme, record.Get("level")); err != nil {
			return nil, err
		}
	}
	compartments := map[string]any{}
	if scheme != nil {
		list, _ := member(scheme.Get("definition"), "compartments").([]any)
		for _, compartment := range list {
			compartments[jsString(member(compartment, "id"))] = member(compartment, "name")
		}
	}
	readInCurrent := func(compartmentID any, agreementID any) (bool, error) {
		id, isText := compartmentID.(string)
		if _, known := compartments[id]; !isText || !known {
			return false, nil
		}
		if isUndefined(agreementID) {
			return true, nil
		}
		agreement, err := tx.Get(ctx, "agreements", jsString(agreementID))
		if err != nil {
			return false, err
		}
		acceptance, err := tx.Get(ctx, "agreementAcceptances", jsString(agreementID)+":"+jsString(record.Get("identityId")))
		if err != nil {
			return false, err
		}
		return agreement != nil && core.StrictEquals(agreement.Get("tenantId"), record.Get("tenantId")) &&
			acceptance != nil && core.StrictEquals(acceptance.Get("tenantId"), record.Get("tenantId")) &&
			AcceptanceCurrent(agreement, acceptance, now), nil
	}
	readIns := []any{}
	stored, _ := record.Get("readIns").([]any)
	for _, readIn := range stored {
		compartmentID := member(readIn, "compartmentId")
		entry := core.NewObject("compartmentId", compartmentID)
		if id, ok := compartmentID.(string); ok {
			if name, known := compartments[id]; known {
				entry.Set("compartmentName", name)
			}
		}
		entry.Set("readInAt", member(readIn, "readInAt"))
		entry.Set("readInBy", member(readIn, "readInBy"))
		agreementID := member(readIn, "agreementId")
		if !isUndefined(agreementID) {
			entry.Set("agreementId", agreementID)
		}
		if acceptedAt := member(readIn, "acceptedAt"); !isUndefined(acceptedAt) {
			entry.Set("acceptedAt", acceptedAt)
		}
		current, err := readInCurrent(compartmentID, agreementID)
		if err != nil {
			return nil, err
		}
		entry.Set("current", current)
		readIns = append(readIns, entry)
	}
	holder := core.NewObject("id", record.Get("identityId"))
	if person != nil {
		holder.Set("name", coalesce(person.Get("name"), record.Get("identityId")))
		if email := person.Get("email"); truthy(email) {
			holder.Set("email", email)
		}
		holder.Set("kind", coalesce(person.Get("kind"), "user"))
		holder.Set("status", coalesce(person.Get("status"), "deleted"))
		holder.Set("guest", !isUndefined(person.Get("guest")))
	} else {
		holder.Set("name", record.Get("identityId"))
		holder.Set("kind", "user")
		holder.Set("status", "deleted")
		holder.Set("guest", false)
	}
	levelView := core.NewObject("id", record.Get("level"))
	if level != nil {
		levelView.Set("name", level.Get("name"))
		levelView.Set("rank", level.Get("rank"))
	}
	view := core.NewObject(
		"identityId", record.Get("identityId"),
		"identity", holder,
		"schemeTenantId", record.Get("schemeTenantId"),
		"level", levelView,
		"status", record.Get("status"),
	)
	var effectiveStatus any = "none"
	if state != nil {
		effectiveStatus = coalesce(state.Get("status"), "none")
	}
	view.Set("effectiveStatus", effectiveStatus)
	if state != nil {
		if stateLevel := clearanceLevelModel(state.Get("level")); stateLevel != nil && clearancePartyRank(clearanceParty(state)) >= 0 {
			view.Set("effectiveLevel", stateLevel.Get("id"))
		}
	}
	view.Set("citizenship", clearanceList(record.Get("citizenship")))
	if investigation := record.Get("investigation"); truthy(investigation) {
		if object, ok := investigation.(*core.Object); ok {
			view.Set("investigation", object.Spread())
		} else {
			view.Set("investigation", investigation)
		}
	}
	if due := record.Get("reinvestigationDue"); !isUndefined(due) {
		view.Set("reinvestigationDue", due)
	}
	if expiresAt := record.Get("expiresAt"); !isUndefined(expiresAt) {
		view.Set("expiresAt", expiresAt)
	}
	view.Set("readIns", readIns)
	view.Set("grantedAt", record.Get("grantedAt"))
	view.Set("grantedBy", record.Get("grantedBy"))
	view.Set("updatedAt", record.Get("updatedAt"))
	view.Set("updatedBy", record.Get("updatedBy"))
	if suspended := record.Get("suspended"); truthy(suspended) {
		entry := core.NewObject("by", member(suspended, "by"), "at", member(suspended, "at"), "reason", member(suspended, "reason"))
		if incidentID := member(suspended, "incidentId"); !isUndefined(incidentID) {
			entry.Set("incidentId", incidentID)
		}
		view.Set("suspended", entry)
	}
	for _, key := range []string{"revoked", "terminated"} {
		if ended := record.Get(key); truthy(ended) {
			if object, ok := ended.(*core.Object); ok {
				view.Set(key, object.Spread())
			} else {
				view.Set(key, ended)
			}
		}
	}
	return view, nil
}

// labelTarget is labelTarget(): the labels' scheme (the one in force for the tenant; NOT_FOUND when none),
// the type and the resource id.
func (api *ClearancesAPI) labelTarget(ctx context.Context, tx core.IamStore, tenant *core.Object, input *core.Object) (*core.Object, string, string, error) {
	resourceType, err := clearanceLabelType(input.Get("type"))
	if err != nil {
		return nil, "", "", err
	}
	resourceID, err := Text(input.Get("id"), "id")
	if err != nil {
		return nil, "", "", err
	}
	scheme, err := api.schemeIn(ctx, tx, tenant)
	if err != nil {
		return nil, "", "", err
	}
	return scheme, resourceType, resourceID, nil
}

// clearanceLabelResourceOf is `labelResource(labelType(input.type), text(input.id, 'id'))`.
func clearanceLabelResourceOf(body *core.Object) (string, error) {
	resourceType, err := clearanceLabelType(body.Get("type"))
	if err != nil {
		return "", err
	}
	resourceID, err := Text(body.Get("id"), "id")
	if err != nil {
		return "", err
	}
	return clearanceLabelResource(resourceType, resourceID), nil
}

// writeLabel writes a label record (insert or new version).
func (api *ClearancesAPI) writeLabel(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, scheme *core.Object, resourceType, resourceID string, label any, inheritToChildren any, existing *core.Object) (*core.Object, error) {
	now := float64(api.server.Now())
	key, err := LabelKey(resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	var id any = ID()
	version := 1.0
	if existing != nil {
		id = coalesce(existing.Get("id"), id)
		version = jsNumber(coalesce(existing.Get("version"), 0.0)) + 1
	}
	record := core.NewObject(
		"id", id,
		"tenantId", tenant.Get("id"),
		"uniqueKey", key,
		"type", resourceType,
		"resourceId", resourceID,
		"label", label,
		"inheritToChildren", inheritToChildren,
		"schemeTenantId", scheme.Get("tenantId"),
		"labeledBy", principal.Identity.Get("id"),
		"labeledAt", now,
		"version", version,
	)
	if existing != nil {
		return tx.Put(ctx, ClearanceCollections.Labels, record)
	}
	return tx.Insert(ctx, ClearanceCollections.Labels, record)
}

// clearanceRetiredLevelsAfter is retiredLevelsAfter(): the levels a scheme has ever removed, with their last rank,
// once `next` replaces its definition (`retiredLevels`): those removed now join the ones removed before, and any that
// `next` brings back (at that rank) leave. Sorted by id.
func clearanceRetiredLevelsAfter(scheme *core.Object, next *core.ClassificationSchemeDefinition) ([]any, error) {
	retired := map[string]any{}
	stored, _ := scheme.Get("retiredLevels").([]any)
	for _, level := range stored {
		retired[jsString(member(level, "id"))] = member(level, "rank")
	}
	for _, level := range clearanceSchemeDefinition(scheme).Levels {
		retired[level.ID] = level.Rank
	}
	for _, level := range next.Levels {
		delete(retired, level.ID)
	}
	if float64(len(retired)) > ClearanceLimits.MaxRetiredLevels {
		return nil, invalidInput("A scheme removes at most " + core.NumberString(ClearanceLimits.MaxRetiredLevels) + " distinct levels over its life")
	}
	ids := make([]string, 0, len(retired))
	for id := range retired {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return compareUTF16(ids[i], ids[j]) < 0 })
	out := make([]any, len(ids))
	for index, id := range ids {
		out[index] = core.NewObject("id", id, "rank", retired[id])
	}
	return out, nil
}

// clearanceAssertDefinitionChange is assertDefinitionChange(): refuses a definition change that would reinterpret
// what may be in use: new levels must rank above every level kept; every level keeps its rank, and one removed
// earlier comes back only at its former rank (IAM cannot see every use: an application's resolver asserts labels by
// level id, and a default label may name any level); a level a live clearance or a label uses cannot be removed; a
// compartment in use must stay; every label must remain valid.
func clearanceAssertDefinitionChange(ctx context.Context, tx core.IamStore, scheme *core.Object, next *core.ClassificationSchemeDefinition) error {
	current := clearanceSchemeDefinition(scheme)
	before := map[string]core.ClassificationLevel{}
	for _, level := range current.Levels {
		before[level.ID] = level
	}
	after := map[string]bool{}
	for _, level := range next.Levels {
		after[level.ID] = true
	}
	keptTop := -1.0
	kept := false
	for _, level := range next.Levels {
		if previous, ok := before[level.ID]; ok {
			if !kept || previous.Rank > keptTop {
				keptTop = previous.Rank
			}
			kept = true
		}
	}
	for _, level := range next.Levels {
		if _, ok := before[level.ID]; !ok && level.Rank <= keptTop {
			return invalidInput("New levels go above every existing level")
		}
	}
	retired := map[string]any{}
	stored, _ := scheme.Get("retiredLevels").([]any)
	for _, level := range stored {
		retired[jsString(member(level, "id"))] = member(level, "rank")
	}
	for _, level := range next.Levels {
		var former any = core.Undefined
		if previous, ok := before[level.ID]; ok {
			former = previous.Rank
		} else if rank, ok := retired[level.ID]; ok {
			former = rank
		}
		if !isUndefined(former) && !core.StrictEquals(former, level.Rank) {
			return core.NewIamError("RESOURCE_IN_USE", "Levels keep their rank: labels, including those your application asserts, may use any level", 409)
		}
	}
	found, err := tx.Find(ctx, ClearanceCollections.Clearances, core.NewObject("schemeTenantId", scheme.Get("tenantId")), nil)
	if err != nil {
		return err
	}
	var records []*core.Object
	for _, record := range found {
		if core.StrictEquals(record.Get("schemeTenantId"), scheme.Get("tenantId")) && clearanceIn(clearanceLiveStatuses, record.Get("status")) {
			records = append(records, record)
		}
	}
	foundLabels, err := tx.Find(ctx, ClearanceCollections.Labels, core.NewObject("schemeTenantId", scheme.Get("tenantId")), nil)
	if err != nil {
		return err
	}
	var labels []*core.Object
	for _, item := range foundLabels {
		if core.StrictEquals(item.Get("schemeTenantId"), scheme.Get("tenantId")) {
			labels = append(labels, item)
		}
	}
	var levels []any
	for _, record := range records {
		levels = append(levels, record.Get("level"))
	}
	for _, item := range labels {
		levels = append(levels, member(item.Get("label"), "level"))
	}
	for _, value := range levels {
		levelID, ok := value.(string)
		if !ok {
			continue
		}
		if _, existed := before[levelID]; existed && !after[levelID] {
			return core.NewIamError("RESOURCE_IN_USE", "A level that clearances or labels use cannot be removed", 409)
		}
	}
	compartments := map[string]bool{}
	for _, compartment := range next.Compartments {
		compartments[compartment.ID] = true
	}
	var used []any
	for _, record := range records {
		readIns, _ := record.Get("readIns").([]any)
		for _, item := range readIns {
			used = append(used, member(item, "compartmentId"))
		}
	}
	for _, item := range labels {
		list, _ := member(item.Get("label"), "compartments").([]any)
		used = append(used, list...)
	}
	for _, value := range used {
		if compartmentID, ok := value.(string); !ok || !compartments[compartmentID] {
			return core.NewIamError("RESOURCE_IN_USE", "A compartment that clearances or labels use cannot be removed", 409)
		}
	}
	for _, item := range labels {
		if core.IsValidClassificationLabel(item.Get("label"), current) && !core.IsValidClassificationLabel(item.Get("label"), next) {
			return core.NewIamError("RESOURCE_IN_USE", "The change would invalidate existing labels", 409)
		}
	}
	return nil
}

// --- the API ---------------------------------------------------------------------------------------

// Templates is POST {basePath}/clearances/templates. Lists the built-in schemes a tenant can start from: us, uk,
// nato, and corporate; any signed-in caller.
func (api *ClearancesAPI) Templates(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesTemplatesInput]) (Out[apitypes.ClearancesTemplatesOutput], error) {
	if err := AssertClearances(api.server); err != nil {
		return Out[apitypes.ClearancesTemplatesOutput]{}, err
	}
	if _, err := api.server.Principals.Authenticate(ctx, credential); err != nil {
		return Out[apitypes.ClearancesTemplatesOutput]{}, err
	}
	templates := make([]any, 0, len(clearanceTemplateNames))
	for _, template := range clearanceTemplateNames {
		definition, err := core.ValidateScheme(core.ClassificationTemplates[template.id])
		if err != nil {
			return Out[apitypes.ClearancesTemplatesOutput]{}, err
		}
		templates = append(templates, core.NewObject("id", template.id, "name", template.name, "definition", clearanceDefinitionModel(definition)))
	}
	return Out[apitypes.ClearancesTemplatesOutput]{Value: templates}, nil
}

// GetScheme is POST {basePath}/clearances/getScheme. Returns the classification scheme in force for a tenant and
// where it is defined (`inherited` when an ancestor defines it), or null. Requires iam:clearances:read.
func (api *ClearancesAPI) GetScheme(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesGetSchemeInput]) (Out[apitypes.ClearancesGetSchemeOutput], error) {
	if err := AssertClearances(api.server); err != nil {
		return Out[apitypes.ClearancesGetSchemeOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:clearances:read", clearanceSchemeResource, func(ctx context.Context, call MutationContext) (any, error) {
		scheme, err := api.effectiveScheme(ctx, call.Tx, call.Tenant)
		if err != nil {
			return nil, err
		}
		if scheme == nil {
			return nil, nil
		}
		return clearanceSchemeView(scheme, call.Tenant.Get("id")), nil
	}, false)
	return Out[apitypes.ClearancesGetSchemeOutput]{Value: result}, err
}

// DefineScheme is POST {basePath}/clearances/defineScheme. Defines the tenant's classification scheme from a
// `template` or a `definition`. CONFLICT when the tenant, an ancestor or a tenant below it already defines one (the
// scheme closest to the root is in force for its whole subtree). Requires iam:classifications:manage and a recent
// sign-in; audited as `classification:scheme-define`.
func (api *ClearancesAPI) DefineScheme(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesDefineSchemeInput]) (Out[apitypes.ClearancesDefineSchemeOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesDefineSchemeOutput]{}, err
	}
	body := input.Body
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:classifications:manage", clearanceSchemeResource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		template := body.Get("template")
		if isUndefined(template) == isUndefined(body.Get("definition")) {
			return nil, invalidInput("Give either a template or a definition")
		}
		var typed *core.ClassificationSchemeDefinition
		var err error
		if !isUndefined(template) {
			name, ok := clearanceTemplate(template)
			if !ok {
				return nil, invalidInput("template must be us, uk, nato or corporate")
			}
			typed, err = core.ValidateScheme(core.ClassificationTemplates[name])
		} else {
			typed, err = core.ValidateScheme(body.Get("definition"))
		}
		if err != nil {
			return nil, err
		}
		definition := clearanceDefinitionModel(typed)
		settings, err := clearanceSchemeSettings(body, definition, typed, nil)
		if err != nil {
			return nil, err
		}
		chain, err := server.Ancestry(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		for _, realm := range chain {
			defined, err := DefinedScheme(ctx, tx, jsString(realm.Get("id")))
			if err != nil {
				return nil, err
			}
			if defined != nil {
				message := "An ancestor tenant defines the classification scheme in force here"
				if core.StrictEquals(realm.Get("id"), tenant.Get("id")) {
					message = "This tenant already defines a classification scheme"
				}
				return nil, core.NewIamError("CONFLICT", message, 409)
			}
		}
		others, err := tx.Find(ctx, ClearanceCollections.Schemes, nil, nil)
		if err != nil {
			return nil, err
		}
		for _, other := range others {
			ancestors, err := server.AncestorIDs(ctx, tx, jsString(other.Get("tenantId")))
			if err != nil {
				return nil, err
			}
			if containsString(ancestors, jsString(tenant.Get("id"))) {
				return nil, core.NewIamError("CONFLICT", "A tenant below this one defines its own classification scheme", 409)
			}
		}
		now := float64(server.Now())
		record := core.NewObject("id", ID(), "tenantId", tenant.Get("id"), "uniqueKey", "scheme", "definition", definition)
		record.Assign(settings)
		record.Set("createdAt", now)
		record.Set("createdBy", principal.Identity.Get("id"))
		record.Set("updatedAt", now)
		record.Set("updatedBy", principal.Identity.Get("id"))
		record.Set("version", 1.0)
		scheme, err := tx.Insert(ctx, ClearanceCollections.Schemes, record)
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject()
		if !isUndefined(template) {
			metadata.Set("template", template)
		}
		metadata.Set("levels", clearanceLevelIDs(typed))
		metadata.Set("compartments", clearanceCompartmentIDs(typed))
		metadata.Set("requireLabels", settings.Get("requireLabels"))
		metadata.Set("guestCeiling", settings.Get("guestCeiling"))
		metadata.Set("interimAllowed", settings.Get("interimAllowed"))
		metadata.Set("adjudication", settings.Get("adjudication"))
		if err := server.Events.Audit(ctx, tx, principal, "classification:scheme-define", jsString(tenant.Get("id")), jsString(scheme.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return clearanceSchemeView(scheme, tenant.Get("id")), nil
	}, false)
	return Out[apitypes.ClearancesDefineSchemeOutput]{Value: result}, err
}

// clearanceLevelIDs is `definition.levels.map((level) => level.id)`.
func clearanceLevelIDs(definition *core.ClassificationSchemeDefinition) []any {
	ids := make([]any, len(definition.Levels))
	for index, level := range definition.Levels {
		ids[index] = level.ID
	}
	return ids
}

// clearanceCompartmentIDs is `definition.compartments.map((compartment) => compartment.id)`.
func clearanceCompartmentIDs(definition *core.ClassificationSchemeDefinition) []any {
	ids := make([]any, len(definition.Compartments))
	for index, compartment := range definition.Compartments {
		ids[index] = compartment.ID
	}
	return ids
}

// UpdateScheme is POST {basePath}/clearances/updateScheme. Changes the scheme this tenant defines (an inherited one
// is changed where it is defined: CONFLICT). New levels go above every remaining level; no level is ever re-ranked
// (one removed earlier comes back only at its former rank), a level or compartment that a live clearance or a label
// uses cannot be removed, and every label must stay valid (RESOURCE_IN_USE). Settings change freely. `version`
// (optional) must match the stored one. Requires iam:classifications:manage and a recent sign-in; audited as
// `classification:scheme-update`.
func (api *ClearancesAPI) UpdateScheme(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesUpdateSchemeInput]) (Out[apitypes.ClearancesUpdateSchemeOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesUpdateSchemeOutput]{}, err
	}
	body := input.Body
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:classifications:manage", clearanceSchemeResource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if !isUndefined(body.Get("template")) {
			return nil, invalidInput("Templates start a scheme; change it with definition")
		}
		scheme, err := DefinedScheme(ctx, tx, jsString(tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		if scheme == nil {
			inForce, err := api.effectiveScheme(ctx, tx, tenant)
			if err != nil {
				return nil, err
			}
			if inForce != nil {
				return nil, core.NewIamError("CONFLICT", "The scheme in force here is defined by an ancestor tenant; change it there", 409)
			}
			return nil, core.NewIamError("NOT_FOUND", "This tenant defines no classification scheme", 404)
		}
		if version := body.Get("version"); !isUndefined(version) && !core.StrictEquals(version, scheme.Get("version")) {
			return nil, core.NewIamError("VERSION_CONFLICT", "The scheme changed; reload it first", 409)
		}
		redefined := !isUndefined(body.Get("definition"))
		var typed *core.ClassificationSchemeDefinition
		var definition any
		if redefined {
			if typed, err = core.ValidateScheme(body.Get("definition")); err != nil {
				return nil, err
			}
			definition = clearanceDefinitionModel(typed)
		} else {
			definition = scheme.Get("definition")
			typed = clearanceDefinition(definition)
		}
		definitionModel, _ := definition.(*core.Object)
		settings, err := clearanceSchemeSettings(body, definitionModel, typed, scheme)
		if err != nil {
			return nil, err
		}
		if redefined {
			if err := clearanceAssertDefinitionChange(ctx, tx, scheme, typed); err != nil {
				return nil, err
			}
		}
		changed := []any{}
		if redefined {
			changed = append(changed, "definition")
		}
		for _, field := range []string{"name", "requireLabels", "defaultLabel", "guestCeiling", "interimAllowed", "adjudication", "notify"} {
			if !isUndefined(body.Get(field)) {
				changed = append(changed, field)
			}
		}
		now := float64(server.Now())
		retiredLevels, err := clearanceRetiredLevelsAfter(scheme, typed)
		if err != nil {
			return nil, err
		}
		record := scheme.Spread()
		record.Delete("defaultLabel")
		record.Delete("notify")
		record.Delete("retiredLevels")
		record.Set("definition", definition)
		record.Assign(settings)
		if len(retiredLevels) > 0 {
			record.Set("retiredLevels", retiredLevels)
		}
		record.Set("updatedAt", now)
		record.Set("updatedBy", principal.Identity.Get("id"))
		record.Set("version", jsNumber(scheme.Get("version"))+1)
		next, err := tx.Put(ctx, ClearanceCollections.Schemes, record)
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("changed", changed, "version", next.Get("version"))
		if redefined {
			metadata.Set("levels", clearanceLevelIDs(typed))
			metadata.Set("compartments", clearanceCompartmentIDs(typed))
			metadata.Set("ownerCountries", stringsOf(typed.OwnerCountries))
		}
		if !isUndefined(body.Get("guestCeiling")) {
			metadata.Set("guestCeiling", settings.Get("guestCeiling"))
		}
		if !isUndefined(body.Get("adjudication")) {
			metadata.Set("adjudication", settings.Get("adjudication"))
		}
		if !isUndefined(body.Get("interimAllowed")) {
			metadata.Set("interimAllowed", settings.Get("interimAllowed"))
		}
		if err := server.Events.Audit(ctx, tx, principal, "classification:scheme-update", jsString(tenant.Get("id")), jsString(scheme.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return clearanceSchemeView(next, tenant.Get("id")), nil
	}, false)
	return Out[apitypes.ClearancesUpdateSchemeOutput]{Value: result}, err
}

// Grant is POST {basePath}/clearances/grant. Grants a clearance under the scheme in force: a level, adjudicated
// citizenship, optionally interim, the investigation and its dates. CONFLICT when the identity already holds a live
// one (use `update`). Guests are held to the guest ceiling. Never your own; under `within-own` only within the
// officer's own clearance (bootstrap aside). Requires iam:clearances:adjudicate and a recent sign-in; audited as
// `clearance:grant`.
func (api *ClearancesAPI) Grant(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesGrantInput]) (Out[apitypes.ClearancesGrantOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesGrantOutput]{}, err
	}
	resource, err := clearanceResource(input.Get("identityId"))
	if err != nil {
		return Out[apitypes.ClearancesGrantOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:adjudicate", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		scheme, err := api.schemeIn(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		identity, err := server.ActiveIdentity(ctx, tx, input.Get("identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		if identity.Get("status") != "active" {
			return nil, invalidInput("Only active identities are granted clearances")
		}
		acting, err := api.officer(ctx, tx, principal, tenant, scheme, identity)
		if err != nil {
			return nil, err
		}
		level, err := api.levelOf(scheme, input.Get("level"))
		if err != nil {
			return nil, err
		}
		if err := clearanceAssertGuestLevel(scheme, identity, level); err != nil {
			return nil, err
		}
		interim, _, err := clearanceFlag(input.Get("interim"), "interim")
		if err != nil {
			return nil, err
		}
		if interim && !truthy(scheme.Get("interimAllowed")) {
			return nil, invalidInput("This scheme does not allow interim clearances")
		}
		citizenship, err := clearanceCitizenship(input.Get("citizenship"))
		if err != nil {
			return nil, err
		}
		var investigation *core.Object
		if raw := input.Get("investigation"); !isUndefined(raw) {
			if investigation, err = api.investigationOf(raw); err != nil {
				return nil, err
			}
		}
		var reinvestigationDue any = core.Undefined
		if raw := input.Get("reinvestigationDue"); !isUndefined(raw) {
			due, err := api.dueOf(raw)
			if err != nil {
				return nil, err
			}
			reinvestigationDue = due
		}
		var expiresAt any = core.Undefined
		if raw := input.Get("expiresAt"); !isUndefined(raw) {
			end, err := api.endOf(raw)
			if err != nil {
				return nil, err
			}
			expiresAt = end
		}
		existing, err := ReadClearance(ctx, tx, identity)
		if err != nil {
			return nil, err
		}
		if existing != nil && clearanceIn(clearanceLiveStatuses, existing.Get("status")) {
			return nil, core.NewIamError("CONFLICT", "This identity already holds a clearance; change it with update", 409)
		}
		bootstrap, err := api.withinOwn(ctx, tx, principal, tenant, scheme, acting, clearanceNeed{byRank: true, rank: jsNumber(level.Get("rank"))})
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		status := "active"
		if interim {
			status = "interim"
		}
		identityID := identity.Get("id")
		record := core.NewObject(
			"id", identityID,
			"tenantId", tenant.Get("id"),
			"uniqueKey", "identity:"+jsString(identityID),
			"identityId", identityID,
			"schemeTenantId", scheme.Get("tenantId"),
			"level", level.Get("id"),
			"citizenship", citizenship,
			"status", status,
		)
		if investigation != nil {
			record.Set("investigation", investigation)
		}
		if !isUndefined(reinvestigationDue) {
			record.Set("reinvestigationDue", reinvestigationDue)
		}
		if !isUndefined(expiresAt) {
			record.Set("expiresAt", expiresAt)
		}
		record.Set("readIns", []any{})
		record.Set("grantedAt", now)
		record.Set("grantedBy", principal.Identity.Get("id"))
		record.Set("updatedAt", now)
		record.Set("updatedBy", principal.Identity.Get("id"))
		var saved *core.Object
		if existing != nil {
			saved, err = tx.Put(ctx, ClearanceCollections.Clearances, record)
		} else {
			saved, err = tx.Insert(ctx, ClearanceCollections.Clearances, record)
		}
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("level", level.Get("id"), "status", saved.Get("status"))
		if !isUndefined(expiresAt) {
			metadata.Set("expiresAt", expiresAt)
		}
		if bootstrap {
			metadata.Set("bootstrap", true)
		}
		if err := server.Events.Audit(ctx, tx, principal, "clearance:grant", tenantID, jsString(identityID), "allow", false, metadata); err != nil {
			return nil, err
		}
		return api.clearanceView(ctx, tx, saved, scheme, identity)
	}, false)
	return Out[apitypes.ClearancesGrantOutput]{Value: result}, err
}

// Update is POST {basePath}/clearances/update. Changes a live clearance: level, citizenship, interim or final,
// investigation and dates (null clears one). The same rules as `grant` apply to the higher of the old and the new
// level. Requires iam:clearances:adjudicate and a recent sign-in; audited as `clearance:update`.
func (api *ClearancesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesUpdateInput]) (Out[apitypes.ClearancesUpdateOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesUpdateOutput]{}, err
	}
	resource, err := clearanceResource(input.Get("identityId"))
	if err != nil {
		return Out[apitypes.ClearancesUpdateOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:adjudicate", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		scheme, err := api.schemeIn(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		identity, err := server.ActiveIdentity(ctx, tx, input.Get("identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		acting, err := api.officer(ctx, tx, principal, tenant, scheme, identity)
		if err != nil {
			return nil, err
		}
		record, err := api.liveRecord(ctx, tx, identity, scheme)
		if err != nil {
			return nil, err
		}
		previous, err := clearanceSchemeLevel(scheme, record.Get("level"))
		if err != nil {
			return nil, err
		}
		var level *core.Object
		if raw := input.Get("level"); !isUndefined(raw) {
			if level, err = api.levelOf(scheme, raw); err != nil {
				return nil, err
			}
		} else if previous != nil {
			level = previous
		} else {
			return nil, invalidInput("The clearance’s level left the scheme; set a level")
		}
		if err := clearanceAssertGuestLevel(scheme, identity, level); err != nil {
			return nil, err
		}
		next := record.Spread()
		next.Set("level", level.Get("id"))
		changed := []any{}
		if !core.StrictEquals(level.Get("id"), record.Get("level")) {
			changed = append(changed, "level")
		}
		if raw := input.Get("citizenship"); !isUndefined(raw) {
			citizenship, err := clearanceCitizenship(raw)
			if err != nil {
				return nil, err
			}
			next.Set("citizenship", citizenship)
			changed = append(changed, "citizenship")
		}
		interim, set, err := clearanceFlag(input.Get("interim"), "interim")
		if err != nil {
			return nil, err
		}
		if set {
			if interim && !truthy(scheme.Get("interimAllowed")) {
				return nil, invalidInput("This scheme does not allow interim clearances")
			}
			status := "active"
			if interim {
				status = "interim"
			}
			if suspended, ok := record.Get("suspended").(*core.Object); record.Get("status") == "suspended" && truthy(record.Get("suspended")) {
				if ok {
					next.Set("suspended", suspended.Spread(core.NewObject("previousStatus", status)))
				} else {
					next.Set("suspended", core.NewObject("previousStatus", status))
				}
			} else {
				next.Set("status", status)
			}
			changed = append(changed, "interim")
		}
		if raw := input.Get("investigation"); !isUndefined(raw) {
			if raw == nil {
				next.Delete("investigation")
			} else {
				investigation, err := api.investigationOf(raw)
				if err != nil {
					return nil, err
				}
				next.Set("investigation", investigation)
			}
			changed = append(changed, "investigation")
		}
		if raw := input.Get("reinvestigationDue"); !isUndefined(raw) {
			if raw == nil {
				next.Delete("reinvestigationDue")
			} else {
				due, err := api.dueOf(raw)
				if err != nil {
					return nil, err
				}
				next.Set("reinvestigationDue", due)
			}
			changed = append(changed, "reinvestigationDue")
		}
		if raw := input.Get("expiresAt"); !isUndefined(raw) {
			if raw == nil {
				next.Delete("expiresAt")
			} else {
				end, err := api.endOf(raw)
				if err != nil {
					return nil, err
				}
				next.Set("expiresAt", end)
			}
			changed = append(changed, "expiresAt")
		}
		if len(changed) == 0 {
			return api.clearanceView(ctx, tx, record, scheme, identity)
		}
		rank := jsNumber(level.Get("rank"))
		if previous != nil {
			rank = math.Max(rank, jsNumber(previous.Get("rank")))
		}
		bootstrap, err := api.withinOwn(ctx, tx, principal, tenant, scheme, acting, clearanceNeed{byRank: true, rank: rank})
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		next.Set("updatedAt", now)
		next.Set("updatedBy", principal.Identity.Get("id"))
		saved, err := tx.Put(ctx, ClearanceCollections.Clearances, next)
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("level", saved.Get("level"))
		if !core.StrictEquals(saved.Get("level"), record.Get("level")) {
			metadata.Set("previousLevel", record.Get("level"))
		}
		metadata.Set("status", saved.Get("status"))
		metadata.Set("changed", changed)
		if bootstrap {
			metadata.Set("bootstrap", true)
		}
		if err := server.Events.Audit(ctx, tx, principal, "clearance:update", tenantID, jsString(identity.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return api.clearanceView(ctx, tx, saved, scheme, identity)
	}, false)
	return Out[apitypes.ClearancesUpdateOutput]{Value: result}, err
}

// clearanceReadInHas is `(record.readIns ?? []).some((item) => item.compartmentId === compartmentId)`.
func clearanceReadInHas(record *core.Object, compartmentID string) bool {
	readIns, _ := record.Get("readIns").([]any)
	for _, item := range readIns {
		if core.StrictEquals(member(item, "compartmentId"), compartmentID) {
			return true
		}
	}
	return false
}

// clearanceSchemeCompartment is `scheme.definition.compartments.some((item) => item.id === compartmentId)`.
func clearanceSchemeCompartment(scheme *core.Object, compartmentID any) bool {
	compartments, _ := member(scheme.Get("definition"), "compartments").([]any)
	for _, item := range compartments {
		if core.StrictEquals(member(item, "id"), compartmentID) {
			return true
		}
	}
	return false
}

// ReadIn is POST {basePath}/clearances/readIn. Reads a person into a compartment of the scheme, optionally backed by
// an NDA (`agreementId`, an agreement of the person's tenant; the read-in counts only while their acceptance of its
// current version is current). The clearance must be active or interim; guests are never read in. Under
// `within-own` the officer must be read into the compartment (an owner or root may bootstrap one nobody holds).
// Requires iam:clearances:adjudicate and a recent sign-in; audited as `clearance:read-in` with the compartment id.
func (api *ClearancesAPI) ReadIn(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesReadInInput]) (Out[apitypes.ClearancesReadInOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesReadInOutput]{}, err
	}
	resource, err := clearanceResource(input.Get("identityId"))
	if err != nil {
		return Out[apitypes.ClearancesReadInOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:adjudicate", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		scheme, err := api.schemeIn(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		identity, err := server.ActiveIdentity(ctx, tx, input.Get("identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		acting, err := api.officer(ctx, tx, principal, tenant, scheme, identity)
		if err != nil {
			return nil, err
		}
		if !isUndefined(identity.Get("guest")) {
			return nil, invalidInput("Guests are not read into compartments")
		}
		record, err := api.liveRecord(ctx, tx, identity, scheme)
		if err != nil {
			return nil, err
		}
		if record.Get("status") == "suspended" {
			return nil, core.NewIamError("INVALID_TRANSITION", "A suspended clearance cannot be read into compartments", 409)
		}
		compartmentID, err := Text(input.Get("compartmentId"), "compartmentId", 64)
		if err != nil {
			return nil, err
		}
		if !clearanceSchemeCompartment(scheme, compartmentID) {
			return nil, invalidInput("compartmentId must be a compartment of the scheme")
		}
		if clearanceReadInHas(record, compartmentID) {
			return nil, core.NewIamError("CONFLICT", "Already read into this compartment", 409)
		}
		var acceptedAt any = core.Undefined
		var agreementID any = core.Undefined
		if raw := input.Get("agreementId"); !isUndefined(raw) {
			id, err := Text(raw, "agreementId")
			if err != nil {
				return nil, err
			}
			agreement, err := server.Scoped(ctx, tx, "agreements", id, jsString(identity.Get("tenantId")))
			if err != nil {
				return nil, err
			}
			agreementID = agreement.Get("id")
			acceptance, err := tx.Get(ctx, "agreementAcceptances", jsString(agreement.Get("id"))+":"+jsString(identity.Get("id")))
			if err != nil {
				return nil, err
			}
			if acceptance != nil && core.StrictEquals(acceptance.Get("tenantId"), identity.Get("tenantId")) && AcceptanceCurrent(agreement, acceptance, server.Now()) {
				acceptedAt = acceptance.Get("acceptedAt")
			}
		}
		bootstrap, err := api.withinOwn(ctx, tx, principal, tenant, scheme, acting, clearanceNeed{compartmentID: compartmentID})
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		entry := core.NewObject("compartmentId", compartmentID, "readInAt", now, "readInBy", principal.Identity.Get("id"))
		if !isUndefined(agreementID) {
			entry.Set("agreementId", agreementID)
		}
		if !isUndefined(acceptedAt) {
			entry.Set("acceptedAt", acceptedAt)
		}
		next := record.Spread()
		next.Set("readIns", append(clearanceList(record.Get("readIns")), entry))
		next.Set("updatedAt", now)
		next.Set("updatedBy", principal.Identity.Get("id"))
		saved, err := tx.Put(ctx, ClearanceCollections.Clearances, next)
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("compartmentId", compartmentID, "level", record.Get("level"))
		if !isUndefined(agreementID) {
			metadata.Set("agreementId", agreementID)
		}
		if bootstrap {
			metadata.Set("bootstrap", true)
		}
		if err := server.Events.Audit(ctx, tx, principal, "clearance:read-in", tenantID, jsString(identity.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return api.clearanceView(ctx, tx, saved, scheme, identity)
	}, false)
	return Out[apitypes.ClearancesReadInOutput]{Value: result}, err
}

// Debrief is POST {basePath}/clearances/debrief. Ends a read-in. Tightening, so it needs no recent sign-in and may
// be your own. Requires iam:clearances:adjudicate; audited as `clearance:debrief` with the compartment id.
func (api *ClearancesAPI) Debrief(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesDebriefInput]) (Out[apitypes.ClearancesDebriefOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesDebriefOutput]{}, err
	}
	resource, err := clearanceResource(input.Get("identityId"))
	if err != nil {
		return Out[apitypes.ClearancesDebriefOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:adjudicate", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		scheme, err := api.schemeIn(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		if _, err := api.officer(ctx, tx, principal, tenant, scheme, nil); err != nil {
			return nil, err
		}
		identity, err := server.Scoped(ctx, tx, "identities", input.Get("identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		compartmentID, err := Text(input.Get("compartmentId"), "compartmentId", 64)
		if err != nil {
			return nil, err
		}
		reason := ""
		if raw := input.Get("reason"); !isUndefined(raw) {
			text, err := Text(raw, "reason", 512)
			if err != nil {
				return nil, err
			}
			reason = core.JSTrim(text)
		}
		record, err := ReadClearance(ctx, tx, identity)
		if err != nil {
			return nil, err
		}
		if record == nil || !clearanceReadInHas(record, compartmentID) {
			return nil, core.NewIamError("NOT_FOUND", "Not read into this compartment", 404)
		}
		now := float64(server.Now())
		remaining := []any{}
		for _, item := range clearanceList(record.Get("readIns")) {
			if !core.StrictEquals(member(item, "compartmentId"), compartmentID) {
				remaining = append(remaining, item)
			}
		}
		next := record.Spread()
		next.Set("readIns", remaining)
		next.Set("updatedAt", now)
		next.Set("updatedBy", principal.Identity.Get("id"))
		saved, err := tx.Put(ctx, ClearanceCollections.Clearances, next)
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("compartmentId", compartmentID)
		if reason != "" {
			metadata.Set("reason", reason)
		}
		if err := server.Events.Audit(ctx, tx, principal, "clearance:debrief", tenantID, jsString(identity.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		view, err := api.clearanceView(ctx, tx, saved, scheme, identity)
		if err != nil {
			return nil, err
		}
		// Only narrows: an "expect allow" invariant never blocks a debrief (invariants.ts).
		NarrowsAccessOnly(tx)
		return view, nil
	}, false)
	return Out[apitypes.ClearancesDebriefOutput]{Value: result}, err
}

// Suspend is POST {basePath}/clearances/suspend. Suspends an active or interim clearance at once (an incident, an
// investigation). Needs no recent sign-in so it works during an incident; lifted only by `reinstate`. The person is
// emailed (`clearance-status`) unless `notifyPerson` is false (an investigation that must not tip them off).
// Requires iam:clearances:suspend; audited as `clearance:suspend`.
func (api *ClearancesAPI) Suspend(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesSuspendInput]) (Out[apitypes.ClearancesSuspendOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesSuspendOutput]{}, err
	}
	resource, err := clearanceResource(input.Get("identityId"))
	if err != nil {
		return Out[apitypes.ClearancesSuspendOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:suspend", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		scheme, err := api.schemeIn(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		if _, err := api.officer(ctx, tx, principal, tenant, scheme, nil); err != nil {
			return nil, err
		}
		identity, err := server.Scoped(ctx, tx, "identities", input.Get("identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		text, err := Text(input.Get("reason"), "reason", 512)
		if err != nil {
			return nil, err
		}
		reason := core.JSTrim(text)
		var incidentID any = core.Undefined
		if raw := input.Get("incidentId"); !isUndefined(raw) {
			id, err := Text(raw, "incidentId")
			if err != nil {
				return nil, err
			}
			incidentID = id
		}
		notify, set, err := clearanceFlag(input.Get("notifyPerson"), "notifyPerson")
		if err != nil {
			return nil, err
		}
		notifyPerson := notify || !set
		suspension := core.NewObject("by", principal.Identity.Get("id"), "at", float64(server.Now()), "reason", reason)
		if !isUndefined(incidentID) {
			suspension.Set("incidentId", incidentID)
		}
		outcome, err := SuspendClearance(ctx, tx, identity, suspension)
		if err != nil {
			return nil, err
		}
		switch outcome.Get("outcome") {
		case "no-clearance":
			return nil, core.NewIamError("NOT_FOUND", "This identity holds no clearance to suspend", 404)
		case "already-applied":
			return nil, core.NewIamError("INVALID_TRANSITION", "The clearance is already suspended", 409)
		}
		record, _ := outcome.Get("record").(*core.Object)
		if record == nil {
			record = core.NewObject()
		}
		metadata := core.NewObject("level", record.Get("level"), "reason", reason)
		if !isUndefined(incidentID) {
			metadata.Set("incidentId", incidentID)
		}
		if err := server.Events.Audit(ctx, tx, principal, "clearance:suspend", tenantID, jsString(identity.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		if notifyPerson {
			if err := NotifyClearanceStatus(ctx, server, tx, identity, scheme, record, "suspended"); err != nil {
				return nil, err
			}
		}
		return api.clearanceView(ctx, tx, record, scheme, identity)
	}, false)
	return Out[apitypes.ClearancesSuspendOutput]{Value: result}, err
}

// Reinstate is POST {basePath}/clearances/reinstate. Lifts a suspension (back to active or interim). Any officer but
// the person themselves, within their own clearance under `within-own`: its level and every compartment it is read
// into, since reinstating gives them back. Requires iam:clearances:adjudicate and a recent sign-in; audited as
// `clearance:reinstate`.
func (api *ClearancesAPI) Reinstate(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesReinstateInput]) (Out[apitypes.ClearancesReinstateOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesReinstateOutput]{}, err
	}
	resource, err := clearanceResource(input.Get("identityId"))
	if err != nil {
		return Out[apitypes.ClearancesReinstateOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:adjudicate", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		scheme, err := api.schemeIn(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		identity, err := server.ActiveIdentity(ctx, tx, input.Get("identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		acting, err := api.officer(ctx, tx, principal, tenant, scheme, identity)
		if err != nil {
			return nil, err
		}
		reason := ""
		if raw := input.Get("reason"); !isUndefined(raw) {
			text, err := Text(raw, "reason", 512)
			if err != nil {
				return nil, err
			}
			reason = core.JSTrim(text)
		}
		record, err := api.liveRecord(ctx, tx, identity, scheme)
		if err != nil {
			return nil, err
		}
		if record.Get("status") != "suspended" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only a suspended clearance is reinstated", 409)
		}
		level, err := clearanceSchemeLevel(scheme, record.Get("level"))
		if err != nil {
			return nil, err
		}
		if level == nil {
			return nil, invalidInput("The clearance’s level left the scheme; grant anew")
		}
		bootstrap, err := api.withinOwn(ctx, tx, principal, tenant, scheme, acting, clearanceNeed{byRank: true, rank: jsNumber(level.Get("rank"))})
		if err != nil {
			return nil, err
		}
		// The read-ins come back with the clearance: under within-own the officer must hold each compartment the
		// scheme still defines, as for a read-in (the others never count).
		for _, readIn := range clearanceList(record.Get("readIns")) {
			compartmentID := member(readIn, "compartmentId")
			if !clearanceSchemeCompartment(scheme, compartmentID) {
				continue
			}
			again, err := api.withinOwn(ctx, tx, principal, tenant, scheme, acting, clearanceNeed{compartmentID: jsString(compartmentID)})
			if err != nil {
				return nil, err
			}
			bootstrap = again || bootstrap
		}
		now := float64(server.Now())
		suspended := record.Get("suspended")
		next := record.Spread()
		next.Delete("suspended")
		next.Set("status", coalesce(member(suspended, "previousStatus"), "active"))
		next.Set("updatedAt", now)
		next.Set("updatedBy", principal.Identity.Get("id"))
		saved, err := tx.Put(ctx, ClearanceCollections.Clearances, next)
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("level", saved.Get("level"), "status", saved.Get("status"))
		if reason != "" {
			metadata.Set("reason", reason)
		}
		if bootstrap {
			metadata.Set("bootstrap", true)
		}
		if err := server.Events.Audit(ctx, tx, principal, "clearance:reinstate", tenantID, jsString(identity.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		if err := NotifyClearanceStatus(ctx, server, tx, identity, scheme, saved, "reinstated"); err != nil {
			return nil, err
		}
		return api.clearanceView(ctx, tx, saved, scheme, identity)
	}, false)
	return Out[apitypes.ClearancesReinstateOutput]{Value: result}, err
}

// Revoke is POST {basePath}/clearances/revoke. Revokes a clearance for cause and debriefs every compartment; the
// record stays as history and a new clearance needs a new grant. The person is emailed (`clearance-status`) unless
// `notifyPerson` is false. Requires iam:clearances:adjudicate and a recent sign-in; audited as `clearance:revoke`
// with the debriefed compartment ids.
func (api *ClearancesAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesRevokeInput]) (Out[apitypes.ClearancesRevokeOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesRevokeOutput]{}, err
	}
	resource, err := clearanceResource(input.Get("identityId"))
	if err != nil {
		return Out[apitypes.ClearancesRevokeOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:adjudicate", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		scheme, err := api.schemeIn(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		if _, err := api.officer(ctx, tx, principal, tenant, scheme, nil); err != nil {
			return nil, err
		}
		identity, err := server.Scoped(ctx, tx, "identities", input.Get("identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		text, err := Text(input.Get("reason"), "reason", 512)
		if err != nil {
			return nil, err
		}
		reason := core.JSTrim(text)
		notify, set, err := clearanceFlag(input.Get("notifyPerson"), "notifyPerson")
		if err != nil {
			return nil, err
		}
		notifyPerson := notify || !set
		record, err := ReadClearance(ctx, tx, identity)
		if err != nil {
			return nil, err
		}
		if record == nil || !clearanceIn(clearanceLiveStatuses, record.Get("status")) {
			return nil, core.NewIamError("NOT_FOUND", "This identity holds no clearance to revoke", 404)
		}
		now := float64(server.Now())
		next := record.Spread()
		next.Delete("suspended")
		next.Set("status", "revoked")
		next.Set("readIns", []any{})
		next.Set("revoked", core.NewObject("by", principal.Identity.Get("id"), "at", now, "reason", reason))
		next.Set("updatedAt", now)
		next.Set("updatedBy", principal.Identity.Get("id"))
		saved, err := tx.Put(ctx, ClearanceCollections.Clearances, next)
		if err != nil {
			return nil, err
		}
		debriefed := []any{}
		for _, item := range clearanceList(record.Get("readIns")) {
			debriefed = append(debriefed, member(item, "compartmentId"))
		}
		if err := server.Events.Audit(ctx, tx, principal, "clearance:revoke", tenantID, jsString(identity.Get("id")), "allow", false,
			core.NewObject("level", record.Get("level"), "reason", reason, "debriefed", debriefed)); err != nil {
			return nil, err
		}
		if notifyPerson {
			if err := NotifyClearanceStatus(ctx, server, tx, identity, scheme, saved, "revoked"); err != nil {
				return nil, err
			}
		}
		view, err := api.clearanceView(ctx, tx, saved, scheme, identity)
		if err != nil {
			return nil, err
		}
		// Only narrows: an "expect allow" invariant never blocks revoking for cause (invariants.ts).
		NarrowsAccessOnly(tx)
		return view, nil
	}, false)
	return Out[apitypes.ClearancesRevokeOutput]{Value: result}, err
}

// Get is POST {basePath}/clearances/get. Returns one identity's clearance as officers see it, or null. Requires
// iam:clearances:read.
func (api *ClearancesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesGetInput]) (Out[apitypes.ClearancesGetOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesGetOutput]{}, err
	}
	resource, err := clearanceResource(input.Get("identityId"))
	if err != nil {
		return Out[apitypes.ClearancesGetOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:read", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, tenant := call.Tx, call.Tenant
		identity, err := server.Scoped(ctx, tx, "identities", input.Get("identityId"), jsString(tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		record, err := ReadClearance(ctx, tx, identity)
		if err != nil {
			return nil, err
		}
		if record == nil {
			return nil, nil
		}
		scheme, err := api.effectiveScheme(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		return api.clearanceView(ctx, tx, record, scheme, identity)
	}, false)
	return Out[apitypes.ClearancesGetOutput]{Value: result}, err
}

// List is POST {basePath}/clearances/list. Lists the tenant's clearances by person name: optionally one stored
// `status`, one `level`, or those ending within `expiringWithinDays` (ended ones included). Requires
// iam:clearances:read.
func (api *ClearancesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesListInput]) (Out[apitypes.ClearancesListOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesListOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:read", "clearances", func(ctx context.Context, call MutationContext) (any, error) {
		tx, tenant := call.Tx, call.Tenant
		status := input.Get("status")
		if !isUndefined(status) && !clearanceIn(clearanceStatusNames, status) {
			return nil, invalidInput("Invalid status")
		}
		var level any = core.Undefined
		if raw := input.Get("level"); !isUndefined(raw) {
			text, err := Text(raw, "level", 64)
			if err != nil {
				return nil, err
			}
			level = text
		}
		hasWithin := false
		var within float64
		if raw := input.Get("expiringWithinDays"); !isUndefined(raw) {
			var err error
			if within, err = Integer(raw, "expiringWithinDays", 1, 3650); err != nil {
				return nil, err
			}
			hasWithin = true
		}
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 500)
		if err != nil {
			return nil, err
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000)
		if err != nil {
			return nil, err
		}
		scheme, err := api.effectiveScheme(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		horizon := float64(server.Now()) + within*clearanceDayMs
		filter := core.NewObject("tenantId", tenant.Get("id"))
		if !isUndefined(status) {
			filter.Set("status", status)
		}
		found, err := tx.Find(ctx, ClearanceCollections.Clearances, filter, nil)
		if err != nil {
			return nil, err
		}
		type person struct {
			record   *core.Object
			identity *core.Object
			name     string
		}
		var people []person
		for _, record := range found {
			if !core.StrictEquals(record.Get("tenantId"), tenant.Get("id")) {
				continue
			}
			if !isUndefined(level) && !core.StrictEquals(record.Get("level"), level) {
				continue
			}
			if hasWithin {
				expiresAt, ok := clearanceNumber(record.Get("expiresAt"))
				if !ok || expiresAt > horizon {
					continue
				}
			}
			// Ordered by name first, so only the page's clearances are evaluated in full.
			identity, err := tx.Get(ctx, "identities", jsString(record.Get("identityId")))
			if err != nil {
				return nil, err
			}
			name := jsString(record.Get("identityId"))
			if identity != nil {
				name = jsString(coalesce(identity.Get("name"), record.Get("identityId")))
			}
			people = append(people, person{record: record, identity: identity, name: name})
		}
		sort.SliceStable(people, func(i, j int) bool {
			if order := localeCompare(people[i].name, people[j].name); order != 0 {
				return order < 0
			}
			return compareUTF16(jsString(people[i].record.Get("identityId")), jsString(people[j].record.Get("identityId"))) < 0
		})
		views := []any{}
		start := int(math.Min(offset, float64(len(people))))
		end := int(math.Min(offset+limit, float64(len(people))))
		for _, item := range people[start:end] {
			view, err := api.clearanceView(ctx, tx, item.record, scheme, item.identity)
			if err != nil {
				return nil, err
			}
			views = append(views, view)
		}
		return core.NewObject("clearances", views, "total", float64(len(people))), nil
	}, false)
	return Out[apitypes.ClearancesListOutput]{Value: result}, err
}

// Mine is POST {basePath}/clearances/mine. Returns the caller's own clearance under the scheme in force (levels of
// the scheme, their level, status, citizenship, dates and the compartments they are read into with whether each NDA
// is current). Needs only an ordinary session of the tenant (not while impersonating); no permission.
func (api *ClearancesAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesMineInput]) (Out[apitypes.ClearancesMineOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesMineOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.ClearancesMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.ClearancesMineOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if !ActsInOwnRight(principal.Session) || principal.Session.Get("tenantId") != tenantID || principal.Identity.Get("tenantId") != tenantID {
			return nil, core.NewIamError("ACCESS_DENIED", "Your clearance is read from an ordinary session of its tenant", 403)
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "A clearance is not shown while impersonating", 403)
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		scheme, err := api.effectiveScheme(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		if scheme == nil {
			return core.NewObject("scheme", nil, "clearance", nil), nil
		}
		record, err := ReadClearance(ctx, tx, principal.Identity)
		if err != nil {
			return nil, err
		}
		var view *core.Object
		if record != nil {
			if view, err = api.clearanceView(ctx, tx, record, scheme, principal.Identity); err != nil {
				return nil, err
			}
		}
		levels := []any{}
		storedLevels, _ := member(scheme.Get("definition"), "levels").([]any)
		for _, level := range storedLevels {
			if object, ok := level.(*core.Object); ok {
				levels = append(levels, object.Spread())
			} else {
				levels = append(levels, level)
			}
		}
		mine := core.NewObject("scheme", core.NewObject("tenantId", scheme.Get("tenantId"), "name", scheme.Get("name"), "levels", levels))
		if view == nil {
			mine.Set("clearance", nil)
			return mine, nil
		}
		viewLevel := view.Get("level")
		level := core.NewObject("id", member(viewLevel, "id"))
		if name := member(viewLevel, "name"); truthy(name) {
			level.Set("name", name)
		}
		clearance := core.NewObject("level", level, "status", view.Get("status"), "effectiveStatus", view.Get("effectiveStatus"))
		if effectiveLevel := view.Get("effectiveLevel"); truthy(effectiveLevel) {
			clearance.Set("effectiveLevel", effectiveLevel)
		}
		clearance.Set("citizenship", view.Get("citizenship"))
		if due := view.Get("reinvestigationDue"); !isUndefined(due) {
			clearance.Set("reinvestigationDue", due)
		}
		if expiresAt := view.Get("expiresAt"); !isUndefined(expiresAt) {
			clearance.Set("expiresAt", expiresAt)
		}
		readIns := []any{}
		viewReadIns, _ := view.Get("readIns").([]any)
		for _, item := range viewReadIns {
			entry := core.NewObject("compartmentId", member(item, "compartmentId"))
			if name := member(item, "compartmentName"); truthy(name) {
				entry.Set("compartmentName", name)
			}
			if agreementID := member(item, "agreementId"); !isUndefined(agreementID) {
				entry.Set("agreementId", agreementID)
			}
			entry.Set("current", member(item, "current"))
			readIns = append(readIns, entry)
		}
		clearance.Set("readIns", readIns)
		mine.Set("clearance", clearance)
		return mine, nil
	})
	return Out[apitypes.ClearancesMineOutput]{Value: result}, err
}

// Explain is POST {basePath}/clearances/explain. For investigations: whether a person (their own sessions: an agent
// with its sponsor) may read a resource, which dimension the first refused party fails, the label decisions apply
// and each party's clearance. Officers only: requires iam:clearances:adjudicate.
func (api *ClearancesAPI) Explain(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesExplainInput]) (Out[apitypes.ClearancesExplainOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesExplainOutput]{}, err
	}
	resource, err := clearanceResource(input.Get("identityId"))
	if err != nil {
		return Out[apitypes.ClearancesExplainOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:adjudicate", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, tenant := call.Tx, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		resourceType, err := Text(input.Get("type"), "type")
		if err != nil {
			return nil, err
		}
		resourceID, err := Text(input.Get("id"), "id")
		if err != nil {
			return nil, err
		}
		scheme, err := api.schemeIn(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		identity, err := server.ActiveIdentity(ctx, tx, input.Get("identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		subject := server.Decisions.SimulatedPrincipal(identity, false)
		states, err := SessionParties(ctx, tx, subject, tenant, nil, scheme, server.Now(), false)
		if err != nil {
			return nil, err
		}
		reference := core.ResourceRef{TenantID: tenantID, Type: resourceType, ID: resourceID}
		var labeled ResolvedResource
		resolved, err := server.Decisions.Resolve(ctx, tx, reference, false, "", &SchemeKnown{Scheme: scheme})
		if err != nil {
			// An unregistered or unresolvable resource still has its IAM-held label (labels outlive resources).
			if _, known := asIamError(err); !known {
				return nil, err
			}
			if labeled, err = AttachLabel(ctx, server, tx, tenantID, ResolvedResource{TenantID: tenantID, Type: resourceType, ID: resourceID}, AttachLabelOptions{Scheme: scheme}); err != nil {
				return nil, err
			}
		} else {
			labeled = *resolved
		}
		applicable, err := ApplicableLabel(scheme, labeled)
		if err != nil {
			return nil, err
		}
		views := make([]any, len(states))
		for index, state := range states {
			views[index] = clearancePartyView(state)
		}
		var first any = core.Undefined
		if len(views) > 0 {
			first = views[0]
		}
		label := clearanceLabelModel(applicable)
		if label == nil || isUndefined(label) {
			return core.NewObject("allowed", true, "label", nil, "party", first, "parties", views), nil
		}
		if label == false {
			return core.NewObject("allowed", false, "failure", "invalid-label", "label", nil, "party", first, "parties", views), nil
		}
		labelObject, _ := label.(*core.Object)
		definition, _ := scheme.Get("definition").(*core.Object)
		for index, state := range states {
			failure, err := PartiesFail([]*core.Object{clearanceParty(state)}, labelObject, definition)
			if err != nil {
				return nil, err
			}
			if failure != "" {
				return core.NewObject("allowed", false, "failure", failure, "label", label, "party", views[index], "parties", views), nil
			}
		}
		return core.NewObject("allowed", true, "label", label, "party", first, "parties", views), nil
	}, false)
	return Out[apitypes.ClearancesExplainOutput]{Value: result}, err
}

// Label is POST {basePath}/clearances/label. Labels a resource (any application or tenant type; it need not exist
// yet, and the label outlives it). Only raises: the new label must cover the current one in every dimension, and
// inheritance once on stays on; anything else is a declassification. Requires iam:classifications:label; audited as
// `classification:label` with level and compartment ids.
func (api *ClearancesAPI) Label(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesLabelInput]) (Out[apitypes.ClearancesLabelOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesLabelOutput]{}, err
	}
	resource, err := clearanceLabelResourceOf(input.Body)
	if err != nil {
		return Out[apitypes.ClearancesLabelOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:classifications:label", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		if err := clearanceNoImpersonation(principal); err != nil {
			return nil, err
		}
		scheme, resourceType, resourceID, err := api.labelTarget(ctx, tx, tenant, input.Body)
		if err != nil {
			return nil, err
		}
		typed := clearanceSchemeDefinition(scheme)
		checked, err := core.ValidateLabel(input.Get("label"), typed)
		if err != nil {
			return nil, err
		}
		label := checked.ToValue()
		inherit, set, err := clearanceFlag(input.Get("inheritToChildren"), "inheritToChildren")
		if err != nil {
			return nil, err
		}
		existing, err := StoredLabel(ctx, tx, tenantID, resourceType, resourceID)
		if err != nil {
			return nil, err
		}
		var inheritToChildren any = inherit
		if !set {
			inheritToChildren = false
			if existing != nil {
				inheritToChildren = coalesce(existing.Get("inheritToChildren"), false)
			}
		}
		// A label written under another scheme refuses everyone, so replacing it is a declassification too.
		if existing != nil && (!core.StrictEquals(existing.Get("schemeTenantId"), scheme.Get("tenantId")) ||
			!core.LabelCovers(label, existing.Get("label"), typed) ||
			(truthy(existing.Get("inheritToChildren")) && !truthy(inheritToChildren))) {
			return nil, NewOperationDenied("Lowering or removing any part of a label is a declassification: use declassify")
		}
		if existing != nil && core.StrictEquals(existing.Get("inheritToChildren"), inheritToChildren) && clearanceSameJSON(existing.Get("label"), label) {
			return clearanceLabelView(existing, scheme)
		}
		saved, err := api.writeLabel(ctx, tx, principal, tenant, scheme, resourceType, resourceID, label, inheritToChildren, existing)
		if err != nil {
			return nil, err
		}
		key, err := LabelKey(resourceType, resourceID)
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("type", resourceType).Assign(clearanceLabelMetadata(label))
		metadata.Set("inheritToChildren", inheritToChildren)
		if existing != nil {
			metadata.Set("previousLevel", member(existing.Get("label"), "level"))
		}
		if err := server.Events.Audit(ctx, tx, principal, "classification:label", tenantID, key, "allow", false, metadata); err != nil {
			return nil, err
		}
		return clearanceLabelView(saved, scheme)
	}, false)
	return Out[apitypes.ClearancesLabelOutput]{Value: result}, err
}

// clearanceSameJSON is `JSON.stringify(a) === JSON.stringify(b)`.
func clearanceSameJSON(a, b any) bool {
	left, leftOK, leftErr := core.Stringify(a)
	right, rightOK, rightErr := core.Stringify(b)
	return leftErr == nil && rightErr == nil && leftOK == rightOK && left == right
}

// Declassify is POST {basePath}/clearances/declassify. Lowers, changes or (with `label: null`) removes a resource's
// label. The caller's own clearance must dominate the current label as the scheme in force reads it (nobody
// declassifies what they could not read), also for a label written under another scheme; only a label naming a
// level, compartment or caveat the scheme does not define may be repaired without. Requires
// iam:classifications:declassify and a recent sign-in; audited as `classification:declassify` with the reason.
func (api *ClearancesAPI) Declassify(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesDeclassifyInput]) (Out[apitypes.ClearancesDeclassifyOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesDeclassifyOutput]{}, err
	}
	resource, err := clearanceLabelResourceOf(input.Body)
	if err != nil {
		return Out[apitypes.ClearancesDeclassifyOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:classifications:declassify", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		scheme, resourceType, resourceID, err := api.labelTarget(ctx, tx, tenant, input.Body)
		if err != nil {
			return nil, err
		}
		text, err := Text(input.Get("reason"), "reason", 512)
		if err != nil {
			return nil, err
		}
		reason := core.JSTrim(text)
		raw := input.Get("label")
		if isUndefined(raw) {
			return nil, invalidInput("label is required (null removes it)")
		}
		typed := clearanceSchemeDefinition(scheme)
		var label *core.Object
		if raw != nil {
			checked, err := core.ValidateLabel(raw, typed)
			if err != nil {
				return nil, err
			}
			label = checked.ToValue()
		}
		inherit, set, err := clearanceFlag(input.Get("inheritToChildren"), "inheritToChildren")
		if err != nil {
			return nil, err
		}
		existing, err := StoredLabel(ctx, tx, tenantID, resourceType, resourceID)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			return nil, core.NewIamError("NOT_FOUND", "This resource has no label", 404)
		}
		acting, err := api.officer(ctx, tx, principal, tenant, scheme, nil)
		if err != nil {
			return nil, err
		}
		// Nobody declassifies what they could not read, as the scheme in force reads the label, even one written under
		// another scheme (it refuses everyone until replaced, but its level still means what it says here). Only a
		// label naming what this scheme does not define, which no clearance can dominate, may be repaired by anyone
		// holding the permission.
		if core.IsValidClassificationLabel(existing.Get("label"), typed) {
			existingLabel, _ := existing.Get("label").(*core.Object)
			definition, _ := scheme.Get("definition").(*core.Object)
			failure, err := PartiesFail(clearanceParties(acting.states), existingLabel, definition)
			if err != nil {
				return nil, err
			}
			if failure != "" {
				return nil, NewOperationDenied("Only someone cleared to read a label may declassify it")
			}
		}
		var saved *core.Object
		if label == nil {
			if err := tx.Delete(ctx, ClearanceCollections.Labels, jsString(existing.Get("id"))); err != nil {
				return nil, err
			}
		} else {
			var inheritToChildren any = inherit
			if !set {
				inheritToChildren = existing.Get("inheritToChildren")
			}
			if saved, err = api.writeLabel(ctx, tx, principal, tenant, scheme, resourceType, resourceID, label, inheritToChildren, existing); err != nil {
				return nil, err
			}
		}
		key, err := LabelKey(resourceType, resourceID)
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject("type", resourceType, "previous", clearanceLabelMetadata(existing.Get("label")))
		if label != nil {
			metadata.Set("label", clearanceLabelMetadata(label))
		} else {
			metadata.Set("removed", true)
		}
		metadata.Set("reason", reason)
		if err := server.Events.Audit(ctx, tx, principal, "classification:declassify", tenantID, key, "allow", false, metadata); err != nil {
			return nil, err
		}
		if saved == nil {
			return nil, nil
		}
		return clearanceLabelView(saved, scheme)
	}, false)
	return Out[apitypes.ClearancesDeclassifyOutput]{Value: result}, err
}

// GetLabel is POST {basePath}/clearances/getLabel. Returns a resource's own IAM label and what it inherits from its
// managed parents. Requires iam:clearances:read.
func (api *ClearancesAPI) GetLabel(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesGetLabelInput]) (Out[apitypes.ClearancesGetLabelOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesGetLabelOutput]{}, err
	}
	resource, err := clearanceLabelResourceOf(input.Body)
	if err != nil {
		return Out[apitypes.ClearancesGetLabelOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:read", resource, func(ctx context.Context, call MutationContext) (any, error) {
		tx, tenant := call.Tx, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		scheme, resourceType, resourceID, err := api.labelTarget(ctx, tx, tenant, input.Body)
		if err != nil {
			return nil, err
		}
		existing, err := StoredLabel(ctx, tx, tenantID, resourceType, resourceID)
		if err != nil {
			return nil, err
		}
		inherited, err := InheritedLabel(ctx, tx, tenantID, scheme, resourceType, resourceID)
		if err != nil {
			return nil, err
		}
		state := core.NewObject("type", resourceType, "id", resourceID)
		if existing != nil {
			view, err := clearanceLabelView(existing, scheme)
			if err != nil {
				return nil, err
			}
			state.Set("label", view)
		} else {
			state.Set("label", nil)
		}
		if inherited != nil {
			state.Set("inherited", inherited)
		} else {
			state.Set("inherited", nil)
		}
		return state, nil
	}, false)
	return Out[apitypes.ClearancesGetLabelOutput]{Value: result}, err
}

// ListLabels is POST {basePath}/clearances/listLabels. Lists the tenant's IAM labels, optionally of one resource type
// or level. Requires iam:clearances:read.
func (api *ClearancesAPI) ListLabels(ctx context.Context, credential core.CredentialInput, input In[apitypes.ClearancesListLabelsInput]) (Out[apitypes.ClearancesListLabelsOutput], error) {
	server := api.server
	if err := AssertClearances(server); err != nil {
		return Out[apitypes.ClearancesListLabelsOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:clearances:read", "classifications/labels", func(ctx context.Context, call MutationContext) (any, error) {
		tx, tenant := call.Tx, call.Tenant
		var resourceType any = core.Undefined
		if raw := input.Get("type"); !isUndefined(raw) {
			text, err := clearanceLabelType(raw)
			if err != nil {
				return nil, err
			}
			resourceType = text
		}
		var level any = core.Undefined
		if raw := input.Get("level"); !isUndefined(raw) {
			text, err := Text(raw, "level", 64)
			if err != nil {
				return nil, err
			}
			level = text
		}
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 500)
		if err != nil {
			return nil, err
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000)
		if err != nil {
			return nil, err
		}
		scheme, err := api.effectiveScheme(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", tenant.Get("id"))
		if !isUndefined(resourceType) {
			filter.Set("type", resourceType)
		}
		found, err := tx.Find(ctx, ClearanceCollections.Labels, filter, nil)
		if err != nil {
			return nil, err
		}
		var labels []*core.Object
		for _, item := range found {
			if isUndefined(level) || core.StrictEquals(member(item.Get("label"), "level"), level) {
				labels = append(labels, item)
			}
		}
		sort.SliceStable(labels, func(i, j int) bool {
			if order := compareUTF16(jsString(labels[i].Get("type")), jsString(labels[j].Get("type"))); order != 0 {
				return order < 0
			}
			return compareUTF16(jsString(labels[i].Get("resourceId")), jsString(labels[j].Get("resourceId"))) < 0
		})
		views := []any{}
		start := int(math.Min(offset, float64(len(labels))))
		end := int(math.Min(offset+limit, float64(len(labels))))
		for _, item := range labels[start:end] {
			view, err := clearanceLabelView(item, scheme)
			if err != nil {
				return nil, err
			}
			views = append(views, view)
		}
		return core.NewObject("labels", views, "total", float64(len(labels))), nil
	}, false)
	return Out[apitypes.ClearancesListLabelsOutput]{Value: result}, err
}

// --- reminders -------------------------------------------------------------------------------------

// IamClearances is api/clearances.ts IamClearances: clearances, server side.
type IamClearances struct {
	server *ServerContext
}

// clearanceDue is one date of a clearance that is due.
type clearanceDue struct {
	kind string
	at   float64
}

// SendReminders (api/clearances.ts IamClearances.sendReminders): Emails the owners of each scheme's defining tenant
// and the scheme's `notify.emails` (template `clearance-reminder`, naming the level only, never compartments) about
// clearances whose periodic reinvestigation is due or whose end (interim or final) falls within `withinDays`
// (default 60): each date once. `tenantId` limits the run to the clearances held in that tenant. Requires an email
// delivery callback and the `clearances` option.
func (s *IamClearances) SendReminders(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	server := s.server
	if input == nil {
		input = core.NewObject()
	}
	if err := AssertClearances(server); err != nil {
		return nil, err
	}
	withinDays, err := Integer(coalesce(input.Get("withinDays"), ClearanceLimits.ReminderDays), "withinDays", 1, 365)
	if err != nil {
		return nil, err
	}
	if server.Options == nil || server.Options.Authentication == nil || server.Options.Authentication.SendEmail == nil {
		return nil, core.NewIamError("DELIVERY_REQUIRED", "Clearance reminders require an email delivery callback")
	}
	live := func(record *core.Object) bool {
		return record.Get("status") == "active" || record.Get("status") == "interim"
	}
	var tenantIDs []string
	if raw := input.Get("tenantId"); !isUndefined(raw) {
		tenantID, err := Text(raw, "tenantId")
		if err != nil {
			return nil, err
		}
		tenantIDs = []string{tenantID}
	} else {
		all, err := server.Store.Find(ctx, ClearanceCollections.Clearances, nil, nil)
		if err != nil {
			return nil, err
		}
		ids := newOrderedSet()
		for _, record := range all {
			if live(record) {
				ids.Add(jsString(record.Get("tenantId")))
			}
		}
		tenantIDs = ids.Values()
		sort.SliceStable(tenantIDs, func(i, j int) bool { return compareUTF16(tenantIDs[i], tenantIDs[j]) < 0 })
	}
	sent := []any{}
	inactive, noRecipients := 0.0, 0.0
	for _, tenantID := range tenantIDs {
		type outcome struct {
			inactive     bool
			sent         []any
			noRecipients float64
		}
		result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*outcome, error) {
			tenant, err := tx.Get(ctx, "tenants", tenantID)
			if err != nil {
				return nil, err
			}
			if tenant == nil || tenant.Get("status") != "active" {
				return &outcome{inactive: true}, nil
			}
			chain, err := server.Ancestry(ctx, tx, tenant)
			if err != nil {
				return nil, err
			}
			scheme, err := EffectiveScheme(ctx, tx, chain)
			if err != nil {
				return nil, err
			}
			done := &outcome{sent: []any{}}
			if scheme == nil {
				return done, nil
			}
			now := float64(server.Now())
			horizon := now + withinDays*86_400_000
			marks, err := tx.Find(ctx, "expiryReminderMarks", core.NewObject("tenantId", tenantID), nil)
			if err != nil {
				return nil, err
			}
			reminded := map[string]bool{}
			for _, mark := range marks {
				reminded[jsString(mark.Get("uniqueKey"))] = true
			}
			var recipients []string
			recipientsRead := false
			recipientsOf := func() ([]string, error) {
				if recipientsRead {
					return recipients, nil
				}
				found, err := tx.Find(ctx, "identities", core.NewObject("tenantId", scheme.Get("tenantId"), "owner", true, "status", "active"), nil)
				if err != nil {
					return nil, err
				}
				addresses := newOrderedSet()
				for _, owner := range found {
					email, isText := owner.Get("email").(string)
					if owner.Get("kind") != "user" || !isUndefined(owner.Get("guest")) || !isText {
						continue
					}
					if expiresAt, ok := clearanceNumber(owner.Get("expiresAt")); ok && expiresAt <= now {
						continue
					}
					addresses.Add(core.JSLower(email))
				}
				notify, _ := member(scheme.Get("notify"), "emails").([]any)
				for _, address := range notify {
					addresses.Add(jsString(address))
				}
				recipients = addresses.Values()
				sort.SliceStable(recipients, func(i, j int) bool { return compareUTF16(recipients[i], recipients[j]) < 0 })
				recipientsRead = true
				return recipients, nil
			}
			found, err := tx.Find(ctx, ClearanceCollections.Clearances, core.NewObject("tenantId", tenantID), nil)
			if err != nil {
				return nil, err
			}
			var records []*core.Object
			for _, record := range found {
				if record.Get("tenantId") == tenantID && live(record) {
					records = append(records, record)
				}
			}
			sort.SliceStable(records, func(i, j int) bool {
				return compareUTF16(jsString(records[i].Get("id")), jsString(records[j].Get("id"))) < 0
			})
			for _, record := range records {
				if !core.StrictEquals(record.Get("schemeTenantId"), scheme.Get("tenantId")) {
					continue
				}
				person, err := tx.Get(ctx, "identities", jsString(record.Get("identityId")))
				if err != nil {
					return nil, err
				}
				if person == nil || person.Get("tenantId") != tenantID || person.Get("status") != "active" {
					continue
				}
				if expiresAt, ok := clearanceNumber(person.Get("expiresAt")); ok && expiresAt <= now {
					continue
				}
				recordID := jsString(record.Get("id"))
				var due []clearanceDue
				reinvestigationDue, hasDue := clearanceNumber(record.Get("reinvestigationDue"))
				if hasDue && reinvestigationDue <= horizon {
					due = append(due, clearanceDue{kind: "reinvestigation", at: reinvestigationDue})
				}
				expiresAt, hasEnd := clearanceNumber(record.Get("expiresAt"))
				if hasEnd && expiresAt > now && expiresAt <= horizon {
					kind := "expiry"
					if record.Get("status") == "interim" {
						kind = "interim-end"
					}
					due = append(due, clearanceDue{kind: kind, at: expiresAt})
				}
				pending := due[:0]
				for _, item := range due {
					if !reminded["clearance-reminder:"+recordID+":"+core.NumberString(item.at)] {
						pending = append(pending, item)
					}
				}
				due = pending
				if len(due) == 0 {
					continue
				}
				to, err := recipientsOf()
				if err != nil {
					return nil, err
				}
				if len(to) == 0 {
					done.noRecipients++
					continue
				}
				dueAt := math.Inf(1)
				for _, item := range due {
					dueAt = math.Min(dueAt, item.at)
				}
				level, err := clearanceSchemeLevel(scheme, record.Get("level"))
				if err != nil {
					return nil, err
				}
				for _, address := range to {
					payload := core.NewObject(
						"tenantId", tenantID,
						"tenantName", tenant.Get("name"),
						"identityId", person.Get("id"),
						"personName", person.Get("name"),
					)
					if level != nil {
						payload.Set("levelName", level.Get("name"))
					}
					payload.Set("status", record.Get("status"))
					payload.Set("dueAt", isoString(dueAt))
					if hasDue {
						payload.Set("reinvestigationDue", isoString(reinvestigationDue))
					}
					if hasEnd {
						payload.Set("expiresAt", isoString(expiresAt))
					}
					if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{TenantID: tenantID, Kind: "email", To: address, Template: "clearance-reminder", Payload: payload}); err != nil {
						return nil, err
					}
				}
				kinds := make([]any, len(due))
				for index, item := range due {
					key := "clearance-reminder:" + recordID + ":" + core.NumberString(item.at)
					reminded[key] = true
					kinds[index] = item.kind
					// Outlives the date, so the purge cannot let the reminder go out again while it is due.
					if _, err := tx.Insert(ctx, "expiryReminderMarks", core.NewObject(
						"id", ID(),
						"tenantId", tenantID,
						"uniqueKey", key,
						"identityId", person.Get("id"),
						"expiresAt", math.Max(item.at, now)+withinDays*86_400_000,
					)); err != nil {
						return nil, err
					}
				}
				if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(),
					"tenantId", tenantID,
					"actorId", "deployment-operator",
					"action", "clearance:reminder",
					"resourceId", person.Get("id"),
					"timestamp", now,
					"outcome", "allow",
					"metadata", core.NewObject("level", record.Get("level"), "dueAt", dueAt, "kinds", kinds, "recipients", float64(len(to))),
				)); err != nil {
					return nil, err
				}
				done.sent = append(done.sent, core.NewObject("tenantId", tenantID, "identityId", person.Get("id"), "dueAt", dueAt, "recipients", float64(len(to))))
			}
			return done, nil
		})
		if err != nil {
			return nil, err
		}
		if result.inactive {
			inactive++
		} else {
			sent = append(sent, result.sent...)
			noRecipients += result.noRecipients
		}
	}
	return core.NewObject("sent", sent, "skipped", core.NewObject("inactive", inactive, "noRecipients", noRecipients)), nil
}

// CreateClearancesRuntime builds the IamClearances (api/clearances.ts createClearancesRuntime).
func CreateClearancesRuntime(server *ServerContext) *IamClearances {
	return &IamClearances{server: server}
}
