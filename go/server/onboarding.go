package server

// Port of packages/server/src/onboarding.ts: customizable onboarding. A flow is an ordered checklist a newcomer
// completes: people joining a tenant (`member` flows) or a new tenant's administrators setting it up (`tenant`
// flows). Flows are defined at any level of the tenant hierarchy (the platform root, an organization, a project) and
// inherited downward, so the platform sets defaults for every organization, an organization adds its own steps and
// switches off the platform's optional flows, and a project does the same again. This module holds the records, the
// validators, the resolution of which flows apply to whom, and the evaluation of step state; the `onboarding` API
// group (api_onboarding.go) builds on it.
//
// Records are model values (*core.Object). A candidate flow (CandidateFlow in TypeScript) is an object with the
// members `flow`, `source`, `inherited`, `depth` and, when switched off, `disabledBy`.

import (
	"context"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// SettingsReader is onboarding.ts SettingsReader.
// TypeScript: (no super call)
type SettingsReader struct {
	Cache map[string]any
	Tx    core.IamStore
}

const (
	onboardingMaxSteps  = 25
	onboardingMaxFields = 20
)

var (
	onboardingStepIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	onboardingFieldNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,39}$`)
	onboardingDatePattern      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	onboardingStepKinds        = map[string][]string{
		"member": {"form", "acknowledge", "task", "agreement", "verify-email", "mfa", "passkey"},
		"tenant": {"form", "acknowledge", "task", "check"},
	}
	onboardingChecks = []string{
		"verified-domain", "members", "owners", "mfa-policy", "agreement", "slug", "sso", "directory-sync",
		"member-onboarding",
	}
	onboardingFieldTypes = []string{"text", "textarea", "email", "url", "number", "boolean", "select", "date"}
	// onboardingAllowedKeys is the kind-specific members each step kind takes.
	onboardingAllowedKeys = map[string][]string{
		"form":         {"fields"},
		"acknowledge":  {"content"},
		"task":         {"url", "verification"},
		"agreement":    {"agreement"},
		"verify-email": {},
		"mfa":          {},
		"passkey":      {},
		"check":        {"check", "minimum"},
	}
	onboardingCheckLabels = map[string]string{
		"verified-domain":   "verified domain",
		"members":           "member",
		"owners":            "owner",
		"mfa-policy":        "",
		"agreement":         "agreement",
		"slug":              "",
		"sso":               "SSO connection",
		"directory-sync":    "directory connection",
		"member-onboarding": "member onboarding flow",
	}
)

// onboardingIncludes is `list.includes(value)` for a value of any type.
func onboardingIncludes(list []string, value any) bool {
	text, ok := value.(string)
	return ok && containsString(list, text)
}

// onboardingPlain is plainObject: a JSON object (not null, not an array).
func onboardingPlain(value any) (*core.Object, bool) {
	object, ok := value.(*core.Object)
	return object, ok && object != nil
}

// onboardingLongControl is /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.
func onboardingLongControl(text string) bool {
	for _, r := range text {
		if r <= 0x08 || r == 0x0b || r == 0x0c || (r >= 0x0e && r <= 0x1f) || r == 0x7f {
			return true
		}
	}
	return false
}

// onboardingLongText is longText with an int bound.
func onboardingLongText(value any, name string, max int) (string, error) {
	text, ok := value.(string)
	if !ok || core.JSTrim(text) == "" || utf16Len(text) > max || onboardingLongControl(text) {
		return "", invalidInput("Invalid " + name)
	}
	return text, nil
}

// LongText (onboarding.ts longText): Multi-line text: tabs and line breaks allowed, other control characters not.
func LongText(value any, name string, maxValue float64) (result string, err error) {
	return onboardingLongText(value, name, int(maxValue))
}

// onboardingHTTPURL is onboarding.ts httpUrl: an http(s) URL of at most 2048 characters, trimmed.
func onboardingHTTPURL(value any, name string) (string, error) {
	text, err := Text(value, name, 2048)
	if err != nil {
		return "", err
	}
	url := core.JSTrim(text)
	parsed, parseErr := auth.ParseFetchURL(url)
	if parseErr != nil {
		return "", invalidInput(name + " must be an http(s) URL")
	}
	if parsed.Protocol != "https:" && parsed.Protocol != "http:" {
		return "", invalidInput(name + " must be an http(s) URL")
	}
	return url, nil
}

// onboardingFlag is flag(): undefined falls back, anything else must be a boolean.
func onboardingFlag(value any, name string, fallback bool) (bool, error) {
	if isUndefined(value) {
		return fallback, nil
	}
	b, ok := value.(bool)
	if !ok {
		return false, invalidInput(name + " must be a boolean")
	}
	return b, nil
}

// onboardingOnly refuses members outside keys.
func onboardingOnly(value *core.Object, keys []string, path string) error {
	for _, key := range value.Keys() {
		if !containsString(keys, key) {
			return invalidInput(path + ": unknown field " + key)
		}
	}
	return nil
}

// onboardingAttributeTypeOf is attributeTypeOf: the identity attribute type an answer of this field type fills.
func onboardingAttributeTypeOf(fieldType string) string {
	switch fieldType {
	case "number":
		return "number"
	case "boolean":
		return "boolean"
	}
	return "string"
}

func onboardingParseField(value any, path, audience string, identityAttributes *core.Object) (*core.Object, error) {
	input, ok := onboardingPlain(value)
	if !ok {
		return nil, invalidInput(path + " must be an object")
	}
	if err := onboardingOnly(input, []string{"name", "label", "type", "required", "help", "placeholder", "options", "maxLength", "min", "max", "attribute"}, path); err != nil {
		return nil, err
	}
	name, ok := input.Get("name").(string)
	if !ok || !onboardingFieldNamePattern.MatchString(name) {
		return nil, invalidInput(path + ".name must start with a letter and use letters, digits or underscores (at most 40)")
	}
	rawType := coalesce(input.Get("type"), "text")
	if !onboardingIncludes(onboardingFieldTypes, rawType) {
		return nil, invalidInput(path + ".type must be one of " + strings.Join(onboardingFieldTypes, ", "))
	}
	fieldType := rawType.(string)
	label, err := Text(input.Get("label"), path+".label", 100)
	if err != nil {
		return nil, err
	}
	field := core.NewObject("name", name, "label", core.JSTrim(label), "type", fieldType)
	required, err := onboardingFlag(input.Get("required"), path+".required", false)
	if err != nil {
		return nil, err
	}
	if required {
		field.Set("required", true)
	}
	if help := input.Get("help"); !isUndefined(help) {
		text, err := Text(help, path+".help", 300)
		if err != nil {
			return nil, err
		}
		field.Set("help", core.JSTrim(text))
	}
	if placeholder := input.Get("placeholder"); !isUndefined(placeholder) {
		text, err := Text(placeholder, path+".placeholder", 100)
		if err != nil {
			return nil, err
		}
		field.Set("placeholder", text)
	}
	if fieldType == "select" {
		options, ok := input.Get("options").([]any)
		if !ok || len(options) < 1 || len(options) > 50 {
			return nil, invalidInput(path + ".options must list 1-50 choices")
		}
		parsed := make([]string, len(options))
		for index, option := range options {
			text, err := Text(option, path+".options["+jsString(float64(index))+"]", 100)
			if err != nil {
				return nil, err
			}
			parsed[index] = core.JSTrim(text)
		}
		if len(unique(parsed)) != len(parsed) {
			return nil, invalidInput(path + ".options must be distinct")
		}
		field.Set("options", stringsOf(parsed))
	} else if !isUndefined(input.Get("options")) {
		return nil, invalidInput(path + ".options apply to select fields only")
	}
	if maxLength := input.Get("maxLength"); !isUndefined(maxLength) {
		if fieldType != "text" && fieldType != "textarea" {
			return nil, invalidInput(path + ".maxLength applies to text fields only")
		}
		limit := 2_000.0
		if fieldType == "textarea" {
			limit = 10_000
		}
		number, err := Integer(maxLength, path+".maxLength", 1, limit)
		if err != nil {
			return nil, err
		}
		field.Set("maxLength", number)
	}
	for _, bound := range []string{"min", "max"} {
		raw := input.Get(bound)
		if isUndefined(raw) {
			continue
		}
		if fieldType != "number" {
			return nil, invalidInput(path + "." + bound + " applies to number fields only")
		}
		number, ok := raw.(float64)
		if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, invalidInput(path + "." + bound + " must be a number")
		}
		field.Set(bound, number)
	}
	if minimum, ok := field.Get("min").(float64); ok {
		if maximum, ok := field.Get("max").(float64); ok && minimum > maximum {
			return nil, invalidInput(path + ".min must not exceed max")
		}
	}
	if rawAttribute := input.Get("attribute"); !isUndefined(rawAttribute) {
		if audience != "member" {
			return nil, invalidInput(path + ".attribute applies to member flows only")
		}
		// Attribute values are single lines without control characters; a textarea answer is neither.
		if fieldType == "textarea" {
			return nil, invalidInput(path + ".attribute: a textarea answer cannot fill an attribute")
		}
		attribute, err := Text(rawAttribute, path+".attribute", 64)
		if err != nil {
			return nil, err
		}
		var declared any = core.Undefined
		if identityAttributes != nil {
			if found, ok := identityAttributes.Lookup(attribute); ok {
				declared = found
			}
		}
		if !truthy(declared) {
			return nil, invalidInput(path + ".attribute " + attribute + " is not a declared identity attribute")
		}
		if declared != onboardingAttributeTypeOf(fieldType) {
			return nil, invalidInput(path + ".attribute " + attribute + " holds a " + jsString(declared) + "; a " + fieldType + " field cannot fill it")
		}
		field.Set("attribute", attribute)
	}
	return field, nil
}

func onboardingParseStep(value any, path, audience string, identityAttributes *core.Object) (*core.Object, error) {
	input, ok := onboardingPlain(value)
	if !ok {
		return nil, invalidInput(path + " must be an object")
	}
	if err := onboardingOnly(input, []string{"id", "kind", "title", "description", "optional", "fields", "content", "url", "verification", "agreement", "check", "minimum"}, path); err != nil {
		return nil, err
	}
	id, ok := input.Get("id").(string)
	if !ok || !onboardingStepIDPattern.MatchString(id) {
		return nil, invalidInput(path + ".id must use lowercase letters, digits and dashes (at most 40)")
	}
	kinds := onboardingStepKinds[audience]
	if !onboardingIncludes(kinds, input.Get("kind")) {
		return nil, invalidInput(path + ".kind must be one of " + strings.Join(kinds, ", ") + " in a " + audience + " flow")
	}
	kind := input.Get("kind").(string)
	title, err := Text(input.Get("title"), path+".title", 120)
	if err != nil {
		return nil, err
	}
	step := core.NewObject("id", id, "kind", kind, "title", core.JSTrim(title))
	if description := input.Get("description"); !isUndefined(description) {
		text, err := onboardingLongText(description, path+".description", 2_000)
		if err != nil {
			return nil, err
		}
		step.Set("description", text)
	}
	optional, err := onboardingFlag(input.Get("optional"), path+".optional", false)
	if err != nil {
		return nil, err
	}
	if optional {
		step.Set("optional", true)
	}
	for _, key := range []string{"fields", "content", "url", "verification", "agreement", "check", "minimum"} {
		if !isUndefined(input.Get(key)) && !containsString(onboardingAllowedKeys[kind], key) {
			return nil, invalidInput(path + "." + key + " does not apply to " + kind + " steps")
		}
	}
	if kind == "form" {
		fields, ok := input.Get("fields").([]any)
		if !ok || len(fields) < 1 || len(fields) > onboardingMaxFields {
			return nil, invalidInput(path + ".fields must list 1-" + jsString(float64(onboardingMaxFields)) + " fields")
		}
		parsed := make([]any, len(fields))
		names := make([]string, len(fields))
		var attributes []string
		for index, item := range fields {
			field, err := onboardingParseField(item, path+".fields["+jsString(float64(index))+"]", audience, identityAttributes)
			if err != nil {
				return nil, err
			}
			parsed[index] = field
			names[index] = core.JSLower(jsString(field.Get("name")))
			if attribute, ok := field.Get("attribute").(string); ok && attribute != "" {
				attributes = append(attributes, attribute)
			}
		}
		step.Set("fields", parsed)
		if len(unique(names)) != len(names) {
			return nil, invalidInput(path + ".fields must have distinct names")
		}
		if len(unique(attributes)) != len(attributes) {
			return nil, invalidInput(path + ": two fields fill the same attribute")
		}
	}
	if kind == "acknowledge" {
		content, err := onboardingLongText(input.Get("content"), path+".content", 20_000)
		if err != nil {
			return nil, err
		}
		step.Set("content", content)
	}
	if kind == "task" {
		if url := input.Get("url"); !isUndefined(url) {
			parsed, err := onboardingHTTPURL(url, path+".url")
			if err != nil {
				return nil, err
			}
			step.Set("url", parsed)
		}
		verification := coalesce(input.Get("verification"), "self")
		if verification != "self" && verification != "admin" {
			return nil, invalidInput(path + ".verification must be self or admin")
		}
		step.Set("verification", verification)
	}
	if kind == "agreement" {
		agreement, err := Text(input.Get("agreement"), path+".agreement", 100)
		if err != nil {
			return nil, err
		}
		step.Set("agreement", core.JSTrim(agreement))
	}
	if kind == "check" {
		if !onboardingIncludes(onboardingChecks, input.Get("check")) {
			return nil, invalidInput(path + ".check must be one of " + strings.Join(onboardingChecks, ", "))
		}
		check := input.Get("check").(string)
		step.Set("check", check)
		if minimum := input.Get("minimum"); !isUndefined(minimum) {
			if check != "members" && check != "owners" {
				return nil, invalidInput(path + ".minimum applies to members and owners checks")
			}
			number, err := Integer(minimum, path+".minimum", 1, 10_000)
			if err != nil {
				return nil, err
			}
			step.Set("minimum", number)
		}
	}
	return step, nil
}

// ParseSteps (onboarding.ts parseSteps): Validates a flow's steps (1-25, distinct IDs, kinds allowed for the
// audience).
func ParseSteps(value any, audience string, identityAttributes *core.Object) (result []*core.Object, err error) {
	list, ok := value.([]any)
	if !ok || len(list) < 1 || len(list) > onboardingMaxSteps {
		return nil, invalidInput("steps must list 1-" + jsString(float64(onboardingMaxSteps)) + " steps")
	}
	steps := make([]*core.Object, len(list))
	ids := make([]string, len(list))
	for index, item := range list {
		step, err := onboardingParseStep(item, "steps["+jsString(float64(index))+"]", audience, identityAttributes)
		if err != nil {
			return nil, err
		}
		steps[index] = step
		ids[index] = jsString(step.Get("id"))
	}
	if len(unique(ids)) != len(steps) {
		return nil, invalidInput("steps must have distinct IDs")
	}
	if utf16Len(core.MustStringify(onboardingList(steps))) > 200_000 {
		return nil, invalidInput("steps are larger than 200 000 characters")
	}
	return steps, nil
}

// onboardingList is a []*core.Object as a model array.
func onboardingList(items []*core.Object) []any {
	out := make([]any, len(items))
	for index, item := range items {
		out[index] = item
	}
	return out
}

// onboardingObjects is the objects of a model array (other entries left out).
func onboardingObjects(value any) []*core.Object {
	list, _ := value.([]any)
	out := make([]*core.Object, 0, len(list))
	for _, item := range list {
		if object, ok := item.(*core.Object); ok && object != nil {
			out = append(out, object)
		}
	}
	return out
}

// onboardingStrings is the strings of a model array.
func onboardingStrings(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

// onboardingArrayIncludes is `array.includes(value)` for a model array (false when it is not an array).
func onboardingArrayIncludes(array any, value string) bool {
	list, _ := array.([]any)
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// ParseRule (onboarding.ts parseRule): Validates a member flow's targeting rule. Group tests (`identity.groups`)
// name groups of the defining tenant, so they are refused on flows that reach only descendant tenants, whose people
// are never members of those groups. The rule environment carries the groups as a model array.
func ParseRule(value any, identityAttributes *core.Object, groups []string) (result *core.Object, err error) {
	input, ok := onboardingPlain(value)
	if !ok {
		return nil, invalidInput("rule must be an object")
	}
	if err := onboardingOnly(input, []string{"include", "exclude"}, "rule"); err != nil {
		return nil, err
	}
	if identityAttributes == nil {
		identityAttributes = core.NewObject()
	}
	parsed, err := ParseAutoAssign(input, core.NewObject("identityAttributes", identityAttributes, "groups", stringsOf(groups)), "rule")
	if err != nil {
		return nil, err
	}
	rule := core.NewObject("include", parsed.Get("include"))
	if exclude := parsed.Get("exclude"); truthy(exclude) {
		rule.Set("exclude", exclude)
	}
	return rule, nil
}

// onboardingReachesTenant is reachesTenant: whether a flow defined at `source` reaches `target` under its scope and
// tenant types.
func onboardingReachesTenant(flow, source, target *core.Object) bool {
	if source.Get("id") == target.Get("id") {
		return flow.Get("appliesTo") != "descendants"
	}
	if flow.Get("appliesTo") == "tenant" {
		return false
	}
	types := flow.Get("tenantTypes")
	return !truthy(types) || onboardingArrayIncludes(types, jsString(target.Get("type")))
}

// onboardingCandidate builds a CandidateFlow.
func onboardingCandidate(flow, source *core.Object, inherited bool, depth int) *core.Object {
	return core.NewObject("flow", flow, "source", source, "inherited", inherited, "depth", float64(depth))
}

func onboardingCandidateFlow(candidate *core.Object) *core.Object {
	flow, _ := candidate.Get("flow").(*core.Object)
	return flow
}

func onboardingCandidateSource(candidate *core.Object) *core.Object {
	source, _ := candidate.Get("source").(*core.Object)
	return source
}

func onboardingCandidateDisabledBy(candidate *core.Object) *core.Object {
	tenant, _ := candidate.Get("disabledBy").(*core.Object)
	return tenant
}

// onboardingSortCandidates is `.sort(bySourceThenCreated)`: platform first, then oldest first, then by ID.
func onboardingSortCandidates(found []*core.Object) {
	sort.SliceStable(found, func(i, j int) bool {
		a, b := found[i], found[j]
		if difference := jsNumber(b.Get("depth")) - jsNumber(a.Get("depth")); difference != 0 {
			return difference < 0
		}
		flowA, flowB := onboardingCandidateFlow(a), onboardingCandidateFlow(b)
		if difference := jsNumber(flowA.Get("createdAt")) - jsNumber(flowB.Get("createdAt")); difference != 0 {
			return difference < 0
		}
		return compareUTF16(jsString(flowA.Get("id")), jsString(flowB.Get("id"))) < 0
	})
}

// newSettingsReader is `new SettingsReader(tx)`.
func newSettingsReader(tx core.IamStore) *SettingsReaderType {
	return &SettingsReaderType{Cache: map[string]any{}, Tx: tx}
}

// SettingsID (onboarding.ts settingsId): the ID of a tenant's settings record.
func SettingsID(tenantID string) (result string, err error) {
	return onboardingSettingsID(tenantID), nil
}

func onboardingSettingsID(tenantID string) string { return "settings:" + tenantID }

// ProgressID (onboarding.ts progressId): the ID of one subject's progress through one flow.
func ProgressID(flowID string, subjectID string) (result string, err error) {
	return onboardingProgressID(flowID, subjectID), nil
}

func onboardingProgressID(flowID, subjectID string) string { return flowID + ":" + subjectID }

// CandidateFlows (onboarding.ts candidateFlows): The flows of one audience that reach a tenant, before anything
// about a particular person is known: the tenant's own flows for its members, and its ancestors' flows that reach
// down to it. `chain` is the tenant's ancestry (`ctx.ancestry`: the tenant first, the root last). Disabled flows are
// included with `disabledBy` so administrators can see them; locked flows ignore the switch.
func CandidateFlows(ctx context.Context, tx core.IamStore, chain []*core.Object, audience string, settings *SettingsReaderType) (result []*core.Object, err error) {
	if settings == nil {
		settings = newSettingsReader(tx)
	}
	target := chain[0]
	found := []*core.Object{}
	for depth, source := range chain {
		// A tenant is never onboarded by its own tenant flows; they describe how its descendants set up.
		if audience == "tenant" && depth == 0 {
			continue
		}
		flows, err := tx.Find(ctx, "onboardingFlows", core.NewObject("tenantId", source.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		for _, flow := range flows {
			if flow.Get("audience") != audience || !truthy(flow.Get("enabled")) || !onboardingReachesTenant(flow, source, target) {
				continue
			}
			candidate := onboardingCandidate(flow, source, depth > 0, depth)
			if audience == "member" && depth > 0 && !truthy(flow.Get("locked")) {
				for _, between := range chain[:depth] {
					record, err := settings.Get(ctx, jsString(between.Get("id")))
					if err != nil {
						return nil, err
					}
					if record != nil && onboardingArrayIncludes(record.Get("disabledFlowIds"), jsString(flow.Get("id"))) {
						candidate.Set("disabledBy", between)
						break
					}
				}
			}
			found = append(found, candidate)
		}
	}
	onboardingSortCandidates(found)
	return found, nil
}

// LiveGroupIDs (onboarding.ts liveGroupIds): The group IDs an identity is a live member of in its tenant (targeting
// rules test these).
func LiveGroupIDs(ctx context.Context, tx core.IamStore, identity *core.Object, now int64) (result []string, err error) {
	members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", identity.Get("tenantId"), "identityId", identity.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	result = []string{}
	for _, member := range members {
		if expires := member.Get("expiresAt"); isUndefined(expires) || jsNumber(expires) > float64(now) {
			result = append(result, jsString(member.Get("groupId")))
		}
	}
	return result, nil
}

// FlowAppliesTo (onboarding.ts flowAppliesTo): Whether a member flow applies to this person: people only, newcomers
// unless `includeExisting`, and the rule.
func FlowAppliesTo(flow *core.Object, identity *core.Object, groupIDs []string) (result bool, err error) {
	if identity.Get("kind") != "user" || identity.Get("status") == "deleted" {
		return false, nil
	}
	if !truthy(flow.Get("includeExisting")) && jsNumber(identity.Get("createdAt")) < jsNumber(coalesce(flow.Get("effectiveFrom"), flow.Get("createdAt"))) {
		return false, nil
	}
	rule, ok := flow.Get("rule").(*core.Object)
	if !ok || rule == nil {
		return true, nil
	}
	document, err := RuleDocument(rule)
	if err != nil {
		return false, err
	}
	if groupIDs == nil {
		groupIDs = []string{}
	}
	context, err := RuleContext(identity, groupIDs, nil)
	if err != nil {
		return false, err
	}
	match, err := RuleMatch(document, identity, context)
	if err != nil {
		return false, err
	}
	return truthy(match.Get("matched")), nil
}

// TenantFlowApplies (onboarding.ts tenantFlowApplies): Whether a tenant flow applies to this tenant: newcomers
// unless `includeExisting`.
func TenantFlowApplies(flow *core.Object, tenant *core.Object) (result bool, err error) {
	return onboardingTenantFlowApplies(flow, tenant), nil
}

func onboardingTenantFlowApplies(flow, tenant *core.Object) bool {
	return tenant.Get("status") != "deleted" &&
		(truthy(flow.Get("includeExisting")) || jsNumber(tenant.Get("createdAt")) >= jsNumber(coalesce(flow.Get("effectiveFrom"), flow.Get("createdAt"))))
}

// FlowsForIdentity (onboarding.ts flowsForIdentity): The member flows a person is asked to complete (switched-off
// flows removed), in platform-first order. `candidates` nil reads them.
func FlowsForIdentity(ctx context.Context, tx core.IamStore, chain []*core.Object, identity *core.Object, now int64, candidates []*core.Object) (result []*core.Object, err error) {
	if identity.Get("kind") != "user" {
		return []*core.Object{}, nil
	}
	if candidates == nil {
		if candidates, err = CandidateFlows(ctx, tx, chain, "member", nil); err != nil {
			return nil, err
		}
	}
	flows := []*core.Object{}
	ruled := false
	for _, candidate := range candidates {
		if onboardingCandidateDisabledBy(candidate) == nil {
			flows = append(flows, candidate)
			if truthy(onboardingCandidateFlow(candidate).Get("rule")) {
				ruled = true
			}
		}
	}
	if len(flows) == 0 {
		return []*core.Object{}, nil
	}
	var groupIDs []string
	if ruled {
		if groupIDs, err = LiveGroupIDs(ctx, tx, identity, now); err != nil {
			return nil, err
		}
	}
	result = []*core.Object{}
	for _, candidate := range flows {
		applies, err := FlowAppliesTo(onboardingCandidateFlow(candidate), identity, groupIDs)
		if err != nil {
			return nil, err
		}
		if applies {
			result = append(result, candidate)
		}
	}
	return result, nil
}

// onboardingStepKindsOf is the set of step kinds (or checks) the flows use.
func onboardingStepMembers(flows []*core.Object, key string) *orderedSet {
	set := newOrderedSet()
	for _, flow := range flows {
		for _, step := range onboardingObjects(flow.Get("steps")) {
			if value, ok := step.Get(key).(string); ok && value != "" {
				set.Add(value)
			}
		}
	}
	return set
}

// MemberFacts (onboarding.ts memberFacts): Facts a member flow's self-completing steps read, loaded only when a step
// needs them: `passkeys` and `mfa`, and `agreements` (lowercase name to `{ agreement, accepted }`).
func MemberFacts(ctx context.Context, tx core.IamStore, identity *core.Object, flows []*core.Object, now int64) (result *core.Object, err error) {
	kinds := onboardingStepMembers(flows, "kind")
	facts := core.NewObject()
	if kinds.Has("mfa") || kinds.Has("passkey") {
		passkeys, err := tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", identity.Get("tenantId"), "identityId", identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		facts.Set("passkeys", float64(len(passkeys)))
		mfa := len(passkeys) > 0
		if !mfa {
			record, err := tx.Get(ctx, "authMfa", jsString(identity.Get("id")))
			if err != nil {
				return nil, err
			}
			mfa = record != nil && truthy(record.Get("enabled"))
		}
		facts.Set("mfa", mfa)
	}
	if kinds.Has("agreement") {
		found, err := tx.Find(ctx, "agreementAcceptances", core.NewObject("tenantId", identity.Get("tenantId"), "identityId", identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		acceptances := map[string]*core.Object{}
		for _, acceptance := range found {
			acceptances[jsString(acceptance.Get("agreementId"))] = acceptance
		}
		agreements, err := tx.Find(ctx, "agreements", core.NewObject("tenantId", identity.Get("tenantId")), nil)
		if err != nil {
			return nil, err
		}
		byName := core.NewObject()
		for _, agreement := range agreements {
			byName.Set(core.JSLower(jsString(agreement.Get("name"))), core.NewObject(
				"agreement", agreement,
				"accepted", AcceptanceCurrent(agreement, acceptances[jsString(agreement.Get("id"))], now),
			))
		}
		facts.Set("agreements", byName)
	}
	return facts, nil
}

// TenantFacts (onboarding.ts tenantFacts): Facts a tenant flow's check steps read (a count or a boolean per check),
// loaded only when a step needs them.
func TenantFacts(ctx context.Context, tx core.IamStore, tenant *core.Object, flows []*core.Object) (result *core.Object, err error) {
	checks := onboardingStepMembers(flows, "check")
	facts := core.NewObject()
	tenantID := tenant.Get("id")
	people := func() ([]*core.Object, error) {
		identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		out := []*core.Object{}
		for _, identity := range identities {
			if identity.Get("kind") == "user" && identity.Get("status") == "active" {
				out = append(out, identity)
			}
		}
		return out, nil
	}
	count := func(collection string, keep func(record *core.Object) bool) (float64, error) {
		records, err := tx.Find(ctx, collection, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return 0, err
		}
		total := 0
		for _, record := range records {
			if keep == nil || keep(record) {
				total++
			}
		}
		return float64(total), nil
	}
	for _, check := range checks.Values() {
		switch check {
		case "verified-domain":
			value, err := count("tenantDomains", func(domain *core.Object) bool { return domain.Get("status") == "verified" })
			if err != nil {
				return nil, err
			}
			facts.Set(check, value)
		case "members":
			found, err := people()
			if err != nil {
				return nil, err
			}
			facts.Set(check, float64(len(found)))
		case "owners":
			found, err := people()
			if err != nil {
				return nil, err
			}
			owners := 0
			for _, identity := range found {
				if truthy(identity.Get("owner")) {
					owners++
				}
			}
			facts.Set(check, float64(owners))
		case "mfa-policy":
			facts.Set(check, member(tenant.Get("authPolicy"), "requireMfa") == true)
		case "agreement":
			value, err := count("agreements", nil)
			if err != nil {
				return nil, err
			}
			facts.Set(check, value)
		case "slug":
			facts.Set(check, !isUndefined(tenant.Get("slug")))
		case "sso":
			value, err := count("samlConnections", func(connection *core.Object) bool { return connection.Get("enabled") != false })
			if err != nil {
				return nil, err
			}
			facts.Set(check, value)
		case "directory-sync":
			value, err := count("scimConnections", func(connection *core.Object) bool { return !truthy(connection.Get("revoked")) })
			if err != nil {
				return nil, err
			}
			facts.Set(check, value)
		case "member-onboarding":
			value, err := count("onboardingFlows", func(flow *core.Object) bool {
				return flow.Get("audience") == "member" && truthy(flow.Get("enabled")) && flow.Get("appliesTo") != "descendants"
			})
			if err != nil {
				return nil, err
			}
			facts.Set(check, value)
		}
	}
	return facts, nil
}

// onboardingCheckState is checkState: whether a check step is met, and the fact behind it.
func onboardingCheckState(step *core.Object, facts *core.Object) (bool, string) {
	check := jsString(step.Get("check"))
	var value any = core.Undefined
	if facts != nil {
		value = facts.Get(check)
	}
	if done, ok := value.(bool); ok {
		var detail string
		switch {
		case check == "mfa-policy" && done:
			detail = "MFA is required"
		case check == "mfa-policy":
			detail = "MFA is not required yet"
		case done:
			detail = "Sign-in alias set"
		default:
			detail = "No sign-in alias yet"
		}
		return done, detail
	}
	count := jsNumber(coalesce(value, 0.0))
	needed := 1.0
	if check == "members" || check == "owners" {
		needed = jsNumber(coalesce(step.Get("minimum"), 2.0))
	}
	plural := "s"
	if needed == 1 {
		plural = ""
	}
	return count >= needed, jsString(math.Min(count, needed)) + " of " + jsString(needed) + " " + onboardingCheckLabels[check] + plural
}

// EvaluateFlow (onboarding.ts evaluateFlow): The state of each step and of the whole flow for one subject. `facts`
// holds `member` (`{ identity, facts }`) or `tenant` (TenantFacts); `options.answers` includes the answers.
func EvaluateFlow(candidate *core.Object, progress *core.Object, facts *core.Object, options *core.Object) (result *core.Object, err error) {
	flow, source := onboardingCandidateFlow(candidate), onboardingCandidateSource(candidate)
	withAnswers := options != nil && truthy(options.Get("answers"))
	records := map[string]*core.Object{}
	if progress != nil {
		for _, record := range onboardingObjects(progress.Get("steps")) {
			records[jsString(record.Get("stepId"))] = record
		}
	}
	var memberIdentity, memberFacts, tenantFacts *core.Object
	if facts != nil {
		if memberEntry, ok := facts.Get("member").(*core.Object); ok && memberEntry != nil {
			memberIdentity, _ = memberEntry.Get("identity").(*core.Object)
			memberFacts, _ = memberEntry.Get("facts").(*core.Object)
		}
		tenantFacts, _ = facts.Get("tenant").(*core.Object)
	}
	memberFact := func(key string) any {
		if memberFacts == nil {
			return core.Undefined
		}
		return memberFacts.Get(key)
	}
	steps := []any{}
	counted, done := 0, 0
	for _, step := range onboardingObjects(flow.Get("steps")) {
		record := records[jsString(step.Get("id"))]
		recorded := func(key string) any {
			if record == nil {
				return core.Undefined
			}
			return record.Get(key)
		}
		status := step.Spread()
		status.Set("optional", step.Get("optional") == true)
		status.Set("state", "pending")
		if completedAt := recorded("completedAt"); !isUndefined(completedAt) {
			status.Set("completedAt", completedAt)
		}
		if answers := recorded("answers"); withAnswers && truthy(answers) {
			status.Set("answers", answers)
		}
		switch step.Get("kind") {
		case "form", "acknowledge":
			if !isUndefined(recorded("completedAt")) {
				status.Set("state", "complete")
			}
		case "task":
			if !isUndefined(recorded("completedAt")) {
				status.Set("state", "complete")
			} else if submittedAt := recorded("submittedAt"); !isUndefined(submittedAt) {
				status.Set("state", "submitted")
				status.Set("submittedAt", submittedAt)
			} else if rejectedAt := recorded("rejectedAt"); !isUndefined(rejectedAt) {
				status.Set("state", "rejected")
				status.Set("rejectedAt", rejectedAt)
				if note := record.Get("note"); truthy(note) {
					status.Set("note", note)
				}
			}
		case "verify-email":
			if memberIdentity != nil && truthy(memberIdentity.Get("emailVerified")) {
				status.Set("state", "complete")
			} else {
				status.Set("state", "pending")
			}
		case "mfa":
			if truthy(memberFact("mfa")) {
				status.Set("state", "complete")
			} else {
				status.Set("state", "pending")
			}
		case "passkey":
			if jsNumber(coalesce(memberFact("passkeys"), 0.0)) > 0 {
				status.Set("state", "complete")
			} else {
				status.Set("state", "pending")
			}
		case "agreement":
			var found *core.Object
			if agreements, ok := memberFact("agreements").(*core.Object); ok && agreements != nil {
				found, _ = agreements.Get(core.JSLower(jsString(step.Get("agreement")))).(*core.Object)
			}
			switch {
			case found == nil:
				status.Set("state", "unavailable")
			case truthy(found.Get("accepted")):
				status.Set("state", "complete")
			default:
				status.Set("state", "pending")
			}
			if found == nil {
				status.Set("detail", "Your organization has not published this agreement")
			}
		case "check":
			met, detail := onboardingCheckState(step, tenantFacts)
			if met {
				status.Set("state", "complete")
			} else {
				status.Set("state", "pending")
			}
			status.Set("detail", detail)
		}
		steps = append(steps, status)
		if status.Get("optional") != true && status.Get("state") != "unavailable" {
			counted++
			if status.Get("state") == "complete" {
				done++
			}
		}
	}
	result = core.NewObject("id", flow.Get("id"), "name", flow.Get("name"))
	if description := flow.Get("description"); truthy(description) {
		result.Set("description", description)
	}
	result.Set("audience", flow.Get("audience"))
	result.Set("required", flow.Get("required"))
	result.Set("locked", flow.Get("locked"))
	result.Set("version", flow.Get("version"))
	result.Set("source", onboardingSource(source))
	result.Set("inherited", candidate.Get("inherited"))
	result.Set("steps", steps)
	result.Set("complete", done == counted)
	result.Set("done", float64(done))
	result.Set("total", float64(counted))
	if progress != nil && !isUndefined(progress.Get("completedAt")) && done == counted {
		result.Set("completedAt", progress.Get("completedAt"))
	}
	return result, nil
}

// SourceOf (onboarding.ts sourceOf): where a flow or a setting comes from.
func SourceOf(tenant *core.Object) (result *core.Object, err error) {
	return onboardingSource(tenant), nil
}

func onboardingSource(tenant *core.Object) *core.Object {
	return core.NewObject("tenantId", tenant.Get("id"), "name", tenant.Get("name"), "type", tenant.Get("type"))
}

// MentionsOnboarding (onboarding.ts mentionsOnboarding): whether any statement of the documents names an onboarding
// context key in a condition.
func MentionsOnboarding(documents []any) bool {
	return anyConditionNames(documents, "principal.onboarding", "principal.pendingOnboarding")
}

// OnboardingContext (onboarding.ts onboardingContext): Policy context for a person in their own tenant:
// `principal.onboarding` names the member flows they have completed, and `principal.pendingOnboarding` counts
// required ones still open. Service accounts are never onboarded.
func OnboardingContext(ctx context.Context, tx core.IamStore, chain []*core.Object, identity *core.Object, now int64) (result *core.Object, err error) {
	none := core.NewObject("principal.onboarding", []any{}, "principal.pendingOnboarding", 0.0)
	if identity.Get("kind") != "user" || len(chain) == 0 || chain[0].Get("id") != identity.Get("tenantId") {
		return none, nil
	}
	flows, err := FlowsForIdentity(ctx, tx, chain, identity, now, nil)
	if err != nil {
		return nil, err
	}
	if len(flows) == 0 {
		return none, nil
	}
	records, err := tx.Find(ctx, "onboardingProgress", core.NewObject("tenantId", identity.Get("tenantId"), "subjectId", identity.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	progress := map[string]*core.Object{}
	for _, record := range records {
		progress[jsString(record.Get("flowId"))] = record
	}
	defined := make([]*core.Object, len(flows))
	for index, candidate := range flows {
		defined[index] = onboardingCandidateFlow(candidate)
	}
	facts, err := MemberFacts(ctx, tx, identity, defined, now)
	if err != nil {
		return nil, err
	}
	completed := []string{}
	pending := 0
	for _, candidate := range flows {
		flow := onboardingCandidateFlow(candidate)
		status, err := EvaluateFlow(candidate, progress[jsString(flow.Get("id"))], core.NewObject("member", core.NewObject("identity", identity, "facts", facts)), nil)
		if err != nil {
			return nil, err
		}
		if status.Get("complete") == true {
			completed = append(completed, jsString(flow.Get("name")))
		} else if truthy(flow.Get("required")) {
			pending++
		}
	}
	names := unique(completed)
	sortStrings(names)
	return core.NewObject("principal.onboarding", stringsOf(names), "principal.pendingOnboarding", float64(pending)), nil
}

// ResolveSettings (onboarding.ts resolveSettings): Welcome copy and support contacts: for each value, the nearest
// tenant in the chain that set it wins.
func ResolveSettings(ctx context.Context, chain []*core.Object, settings *SettingsReaderType) (result *core.Object, err error) {
	sources := core.NewObject()
	resolved := core.NewObject("sources", sources)
	for _, tenant := range chain {
		record, err := settings.Get(ctx, jsString(tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		if record == nil {
			continue
		}
		for _, key := range []string{"welcomeTitle", "welcomeMessage", "supportEmail", "supportUrl"} {
			if isUndefined(resolved.Get(key)) && !isUndefined(record.Get(key)) {
				resolved.Set(key, record.Get(key))
				sources.Set(key, onboardingSource(tenant))
			}
		}
	}
	return resolved, nil
}

// ParseSettings (onboarding.ts parseSettings): Validates settings input (replace semantics); `disabledFlowIds` is
// checked against the inherited flows by the caller.
func ParseSettings(input *core.Object) (result *core.Object, err error) {
	if input == nil {
		input = core.NewObject()
	}
	if err := onboardingOnly(input, []string{"tenantId", "welcomeTitle", "welcomeMessage", "supportEmail", "supportUrl", "disabledFlowIds"}, "settings"); err != nil {
		return nil, err
	}
	optional := func(value any, parse func(value any) (string, error)) (any, error) {
		if nullish(value) || value == "" {
			return core.Undefined, nil
		}
		return parse(value)
	}
	welcomeTitle, err := optional(input.Get("welcomeTitle"), func(value any) (string, error) {
		text, err := Text(value, "welcomeTitle", 120)
		return core.JSTrim(text), err
	})
	if err != nil {
		return nil, err
	}
	welcomeMessage, err := optional(input.Get("welcomeMessage"), func(value any) (string, error) {
		return onboardingLongText(value, "welcomeMessage", 5_000)
	})
	if err != nil {
		return nil, err
	}
	supportEmail, err := optional(input.Get("supportEmail"), Email)
	if err != nil {
		return nil, err
	}
	supportURL, err := optional(input.Get("supportUrl"), func(value any) (string, error) {
		return onboardingHTTPURL(value, "supportUrl")
	})
	if err != nil {
		return nil, err
	}
	disabled, ok := coalesce(input.Get("disabledFlowIds"), []any{}).([]any)
	if !ok || len(disabled) > 100 {
		return nil, invalidInput("disabledFlowIds must list at most 100 flows")
	}
	ids := make([]string, len(disabled))
	for index, flowID := range disabled {
		text, err := Text(flowID, "disabledFlowIds", 128)
		if err != nil {
			return nil, err
		}
		ids[index] = text
	}
	ids = unique(ids)
	sortStrings(ids)
	result = core.NewObject()
	for _, entry := range []struct {
		key   string
		value any
	}{{"welcomeTitle", welcomeTitle}, {"welcomeMessage", welcomeMessage}, {"supportEmail", supportEmail}, {"supportUrl", supportURL}} {
		if !isUndefined(entry.value) {
			result.Set(entry.key, entry.value)
		}
	}
	result.Set("disabledFlowIds", stringsOf(ids))
	return result, nil
}

// onboardingTextControl is /[\u0000-\u001f\u007f]/.
func onboardingTextControl(text string) bool {
	for _, r := range text {
		if r <= 0x1f || r == 0x7f {
			return true
		}
	}
	return false
}

// ParseAnswers (onboarding.ts parseAnswers): Validates a form step's answers: every required field present, values
// of the declared type and within bounds. Unknown answer keys are refused. Returns the answers to record (empty
// optional fields left out).
func ParseAnswers(step *core.Object, value any) (result *core.Object, err error) {
	if isUndefined(value) {
		value = core.NewObject()
	}
	input, ok := onboardingPlain(value)
	if !ok {
		return nil, invalidInput("answers must be an object")
	}
	fields := onboardingObjects(step.Get("fields"))
	names := map[string]bool{}
	for _, field := range fields {
		names[jsString(field.Get("name"))] = true
	}
	for _, key := range input.Keys() {
		if !names[key] {
			return nil, invalidInput("Unknown answer " + key)
		}
	}
	answers := core.NewObject()
	for _, field := range fields {
		name := jsString(field.Get("name"))
		label := jsString(field.Get("label"))
		fieldType := field.Get("type")
		var raw any = core.Undefined
		if found, ok := input.Lookup(name); ok {
			raw = found
		}
		text, isText := raw.(string)
		empty := nullish(raw) || (isText && core.JSTrim(text) == "") || (fieldType == "boolean" && raw == false)
		if empty {
			if truthy(field.Get("required")) {
				if fieldType == "boolean" {
					return nil, invalidInput(label + " must be confirmed")
				}
				return nil, invalidInput(label + " is required")
			}
			if fieldType == "boolean" && raw == false {
				answers.Set(name, false)
			}
			continue
		}
		invalid := invalidInput(label + " is not valid")
		switch fieldType {
		case "text":
			if !isText {
				return nil, invalid
			}
			trimmed := core.JSTrim(text)
			if float64(utf16Len(trimmed)) > jsNumber(coalesce(field.Get("maxLength"), 200.0)) || onboardingTextControl(trimmed) {
				return nil, invalid
			}
			answers.Set(name, trimmed)
		case "textarea":
			if !isText {
				return nil, invalid
			}
			limit := jsNumber(coalesce(field.Get("maxLength"), 2_000.0))
			if float64(utf16Len(text)) > limit {
				return nil, invalid
			}
			parsed, err := onboardingLongText(text, label, int(limit))
			if err != nil {
				return nil, err
			}
			answers.Set(name, parsed)
		case "email":
			parsed, err := Email(raw)
			if err != nil {
				return nil, invalid
			}
			answers.Set(name, parsed)
		case "url":
			parsed, err := onboardingHTTPURL(raw, label)
			if err != nil {
				return nil, invalid
			}
			answers.Set(name, parsed)
		case "number":
			number, ok := raw.(float64)
			if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
				return nil, invalid
			}
			if minimum, ok := field.Get("min").(float64); ok && number < minimum {
				return nil, invalid
			}
			if maximum, ok := field.Get("max").(float64); ok && number > maximum {
				return nil, invalid
			}
			answers.Set(name, number)
		case "boolean":
			b, ok := raw.(bool)
			if !ok {
				return nil, invalid
			}
			answers.Set(name, b)
		case "select":
			if !isText || !containsString(onboardingStrings(field.Get("options")), text) {
				return nil, invalid
			}
			answers.Set(name, text)
		case "date":
			if !isText || !onboardingDatePattern.MatchString(text) {
				return nil, invalid
			}
			date, err := time.Parse("2006-01-02", text)
			if err != nil || date.Format("2006-01-02") != text {
				return nil, invalid
			}
			answers.Set(name, text)
		}
	}
	return answers, nil
}

// PublicFlow (onboarding.ts publicFlow): A flow record without the fields only the defining tenant needs; what
// descendants and members see.
func PublicFlow(flow *core.Object) (result *core.Object, err error) {
	return onboardingPublicFlow(flow), nil
}

func onboardingPublicFlow(flow *core.Object) *core.Object {
	rest := flow.Spread()
	rest.Delete("completionGroupIds")
	rest.Delete("groupsOwnerId")
	rest.Delete("authorId")
	return rest
}

// AutomaticSteps is onboarding.ts automaticSteps.
var AutomaticSteps = newOrderedSet("agreement", "verify-email", "mfa", "passkey", "check")

// MaxCompletionGroups is onboarding.ts maxCompletionGroups.
const MaxCompletionGroups = 10

// MaxFlowsPerTenant is onboarding.ts maxFlowsPerTenant.
const MaxFlowsPerTenant = 50

// SettingsReaderType is onboarding.ts SettingsReader: reads each tenant's settings record at most once.
type SettingsReaderType struct {
	server *ServerContext
	Cache  map[string]any
	Tx     core.IamStore
}

// Get (onboarding.ts SettingsReader.get): the tenant's settings record (nil when it has none), read once.
func (s *SettingsReaderType) Get(ctx context.Context, tenantID string) (result *core.Object, err error) {
	if s.Cache == nil {
		s.Cache = map[string]any{}
	}
	if found, ok := s.Cache[tenantID]; ok {
		record, _ := found.(*core.Object)
		return record, nil
	}
	record, err := s.Tx.Get(ctx, "onboardingSettings", onboardingSettingsID(tenantID))
	if err != nil {
		return nil, err
	}
	s.Cache[tenantID] = record
	return record, nil
}
