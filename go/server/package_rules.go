package server

// Port of packages/server/src/package-rules.ts: the rule language of automatic (birthright) access packages. Pure: no
// store, no server context. A rule is a list of `include` clauses (any may match) and `exclude` clauses (any match
// denies), each exactly a policy statement's `conditions` block, compiled into a policy document and evaluated by the
// core policy engine against a context built from the identity alone.
//
// Rules, environments and results are model values (*core.Object). A RuleEnvironment is
// `{ identityAttributes, groups?, packagedGroups?, org?: { teams?, departments?, licenses? } }`, where each set is a
// model array of strings (a TypeScript Set); an absent member is not checked.

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// OrgRuleKeys is package-rules.ts orgRuleKeys: the rule keys that test the org structure, and what their values name.
var OrgRuleKeys = mustObject(`{"identity.teams":"team","identity.departments":"department","identity.licenses":"license"}`)

// orgRuleKeyOrder is Object.keys(orgRuleKeys).
var orgRuleKeyOrder = []string{"identity.teams", "identity.departments", "identity.licenses"}

// isOrgRuleKey is isOrgRuleKey: Object.hasOwn(orgRuleKeys, key).
func isOrgRuleKey(key string) bool { return OrgRuleKeys.Has(key) }

// MaxRuleClauses is package-rules.ts maxRuleClauses.
const MaxRuleClauses = 10

// MaxRuleBytes is package-rules.ts maxRuleBytes.
const MaxRuleBytes = 16_384

// MaxGraceMs is package-rules.ts maxGraceMs.
const MaxGraceMs = 90 * 86_400_000

// DefaultMaxGrants is package-rules.ts defaultMaxGrants.
const DefaultMaxGrants = 100

// DefaultMaxRemovals is package-rules.ts defaultMaxRemovals.
const DefaultMaxRemovals = 25

// AutomaticJustification is package-rules.ts automaticJustification.
const AutomaticJustification = "Automatic: matches the package rule"

// RuleAction is package-rules.ts ruleAction: the synthetic action used only inside rule documents; never a catalog
// action, grants nothing.
const RuleAction = "auto-assign"

var (
	ruleStringOps  = []string{"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase", "StringLike", "StringNotLike", "StringLikeIgnoreCase"}
	ruleNumericOps = []string{"NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals"}
	ruleBoolOps    = []string{"Bool"}
	ruleArrayOps   = []string{"ArrayContains", "ArrayContainsAll"}
)

// withExists is withExists: the operators followed by Exists.
func withExists(operators []string) []string {
	out := append([]string(nil), operators...)
	return append(out, "Exists")
}

// ruleSessionKeys is sessionKeys: keys that describe a session or a grant rather than the person, with the
// session-derived keys (SessionScopedPrincipalKeys). Every `principal.sessionTags.` key belongs here too.
var ruleSessionKeys = newOrderedSet(append([]string{
	"principal.mfa",
	"principal.sessionKind",
	"principal.authMethod",
	"principal.impersonated",
	"principal.impersonatorId",
	"principal.roles",
	"principal.tenantId",
	"principal.rootAdmin",
}, SessionScopedPrincipalKeys...)...)

// ruleKey is a RuleKey: a key a rule may test, with its type and the operators that apply to it.
type ruleKey struct {
	key       string
	kind      string
	operators []string
}

func (k ruleKey) object() *core.Object {
	return core.NewObject("key", k.key, "type", k.kind, "operators", stringsOf(k.operators))
}

// ruleKeyList is ruleKeys over Go values.
func ruleKeyList(identityAttributes *core.Object, org bool) []ruleKey {
	keys := []ruleKey{
		{"principal.id", "string", withExists(ruleStringOps)},
		{"principal.kind", "string", withExists(ruleStringOps)},
		{"principal.owner", "boolean", withExists(ruleBoolOps)},
		{"identity.email", "string", withExists(ruleStringOps)},
		{"identity.emailDomain", "string", withExists(ruleStringOps)},
		{"identity.emailVerified", "boolean", withExists(ruleBoolOps)},
		{"identity.managerId", "string", withExists(ruleStringOps)},
		{"identity.groups", "array", withExists(ruleArrayOps)},
		// Whether the person is a guest (guests.ts); a rule that never tests it does not match guests (see RuleMatch).
		{"identity.guest", "boolean", withExists(ruleBoolOps)},
	}
	if org {
		for _, key := range orgRuleKeyOrder {
			keys = append(keys, ruleKey{key, "array", withExists(ruleArrayOps)})
		}
	}
	for _, name := range ruleSortedKeys(identityAttributes) {
		kind := jsString(identityAttributes.Get(name))
		var operators []string
		switch kind {
		case "string":
			operators = append(append([]string(nil), ruleStringOps...), "DateBefore", "DateAfter")
		case "number":
			operators = ruleNumericOps
		default:
			operators = ruleBoolOps
		}
		keys = append(keys, ruleKey{"principal." + name, kind, withExists(operators)})
	}
	return keys
}

// sortedKeys is `Object.keys(object).sort()`.
func ruleSortedKeys(object *core.Object) []string {
	if object == nil {
		return []string{}
	}
	keys := object.Keys()
	slices.SortStableFunc(keys, compareUTF16)
	return keys
}

// RuleKeys (package-rules.ts ruleKeys): Every key a rule may test, in a stable order: fixed keys first, then the
// declared identity attributes. `org` adds `identity.teams` and `identity.departments` for callers that evaluate
// them.
func RuleKeys(identityAttributes *core.Object, options *core.Object) (result []*core.Object, err error) {
	keys := ruleKeyList(identityAttributes, truthy(member(options, "org")))
	result = make([]*core.Object, len(keys))
	for index, key := range keys {
		result[index] = key.object()
	}
	return result, nil
}

// ruleSet is a TypeScript Set of strings carried by a rule environment (`Pick<ReadonlySet<string>, 'has'>`).
type ruleSet interface{ Has(string) bool }

// ruleStringSet is a ruleSet over plain strings.
type ruleStringSet map[string]bool

func (s ruleStringSet) Has(item string) bool { return s[item] }

// envSet reads a set member of a rule environment: nil when absent (undefined or null).
func envSet(value any) ruleSet {
	switch v := value.(type) {
	case nil, core.UndefinedType:
		return nil
	case *orderedSet:
		if v == nil {
			return nil
		}
		return v
	case ruleStringSet:
		return v
	case map[string]bool:
		return ruleStringSet(v)
	case []string:
		set := ruleStringSet{}
		for _, item := range v {
			set[item] = true
		}
		return set
	case []any:
		set := ruleStringSet{}
		for _, item := range v {
			if s, ok := item.(string); ok {
				set[s] = true
			}
		}
		return set
	case ruleSet:
		return v
	}
	return ruleStringSet{}
}

// envObject is an object member of a rule environment, nil when absent.
func envObject(value any) *core.Object {
	object, _ := value.(*core.Object)
	return object
}

// plainRuleObject is plainObject.
func plainRuleObject(value any) (*core.Object, bool) {
	object, ok := value.(*core.Object)
	return object, ok && object != nil
}

// ParseAutoAssign (package-rules.ts parseAutoAssign): Validates a rule against the deployment's declared attributes
// and (when known) the tenant's groups. Every error message starts with `path` ("" is the default `autoAssign`), so
// configuration documents point at the offending package. Values keep the scalar or array form they were given, so
// export and plan compare canonically.
func ParseAutoAssign(value any, env *core.Object, path string) (result *core.Object, err error) {
	if path == "" {
		path = "autoAssign"
	}
	input, ok := plainRuleObject(value)
	if !ok {
		return nil, invalidInput(path + " must be an object")
	}
	for _, key := range input.Keys() {
		if !containsString([]string{"include", "exclude", "graceMs", "maxGrants", "maxRemovals"}, key) {
			return nil, invalidInput(path + ": unknown field " + key)
		}
	}
	include, isList := input.Get("include").([]any)
	if !isList || len(include) < 1 || len(include) > MaxRuleClauses {
		return nil, invalidInput(path + ".include must list 1-" + strconv.Itoa(MaxRuleClauses) + " condition sets")
	}
	excludeValue := input.Get("exclude")
	if isUndefined(excludeValue) {
		excludeValue = []any{}
	}
	exclude, isList := excludeValue.([]any)
	if !isList || len(exclude) > MaxRuleClauses {
		return nil, invalidInput(path + ".exclude must list at most " + strconv.Itoa(MaxRuleClauses) + " condition sets")
	}
	identityAttributes := envObject(member(env, "identityAttributes"))
	orgValue := member(env, "org")
	orgObject := envObject(orgValue)
	// `env.org !== undefined` (a typed nil *core.Object is absent in Go).
	orgPresent := !isUndefined(orgValue) && !isPlainObjectPointer(orgValue)
	keys := map[string]ruleKey{}
	for _, key := range ruleKeyList(identityAttributes, orgPresent) {
		keys[key.key] = key
	}
	declared := ruleSortedKeys(identityAttributes)
	groups := envSet(member(env, "groups"))
	packagedGroups := envSet(member(env, "packagedGroups"))
	clause := func(item any, clausePath string) (*core.Object, error) {
		conditions, ok := plainRuleObject(item)
		if !ok || conditions.Len() == 0 {
			return nil, invalidInput(clausePath + " must be a nonempty condition set")
		}
		if err := core.ValidatePolicy(core.NewObject(
			"version", 1.0,
			"statements", []any{core.NewObject(
				"effect", "allow",
				"actions", []any{RuleAction},
				"resources", []any{"identity/*"},
				"conditions", conditions,
			)},
		)); err != nil {
			if known, ok := asIamError(err); ok {
				return nil, core.NewIamError("INVALID_POLICY", clausePath+": "+known.Message)
			}
			return nil, err
		}
		var failure error
		conditions.Entries(func(operator string, entriesValue any) bool {
			entries, _ := entriesValue.(*core.Object)
			entries.Entries(func(key string, expected any) bool {
				known, found := keys[key]
				if !found {
					switch {
					case key == "principal.groups":
						failure = invalidInput(clausePath + ": use identity.groups (memberships not created by access packages) instead of principal.groups")
					case ruleSessionKeys.Has(key) || strings.HasPrefix(key, SessionTagPrefix):
						failure = invalidInput(clausePath + ": " + key + " describes a session or grant and is not available to package rules")
					case isOrgRuleKey(key):
						failure = invalidInput(clausePath + ": " + key + " is available to access package rules only")
					default:
						orgKeys := ""
						if orgPresent && orgValue != nil {
							orgKeys = "identity.teams, identity.departments, identity.licenses, "
						}
						declaredText := "none declared"
						if len(declared) > 0 {
							declaredText = strings.Join(declared, ", ")
						}
						failure = invalidInput(clausePath + ": unknown key " + key + "; use principal.id, principal.kind, principal.owner, identity.email, identity.emailDomain, identity.emailVerified, identity.managerId, identity.groups, identity.guest, " + orgKeys + "or principal.<declared attribute> (" + declaredText + ")")
					}
					return false
				}
				if !containsString(known.operators, operator) {
					failure = invalidInput(clausePath + ": " + operator + " cannot test " + key + " (" + known.kind + "); use " + strings.Join(known.operators, ", "))
					return false
				}
				values, isList := expected.([]any)
				if !isList {
					values = []any{expected}
				}
				for _, entry := range values {
					if s, ok := entry.(string); ok && strings.Contains(s, "${") {
						failure = invalidInput(clausePath + ": policy variables are not available in package rules")
						return false
					}
				}
				if key == "principal.kind" && containsString([]string{"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase"}, operator) {
					for _, entry := range values {
						s, ok := entry.(string)
						if !ok || !containsString([]string{"user", "service"}, core.JSLower(s)) {
							failure = invalidInput(clausePath + ": principal.kind is 'user' or 'service'")
							return false
						}
					}
				}
				if key == "identity.groups" && operator != "Exists" {
					for _, entry := range values {
						s, ok := entry.(string)
						if !ok {
							failure = invalidInput(clausePath + ": identity.groups lists groups")
							return false
						}
						if groups != nil && !groups.Has(s) {
							failure = invalidInput(clausePath + ": unknown group " + s)
							return false
						}
						if packagedGroups != nil && packagedGroups.Has(s) {
							failure = invalidInput(clausePath + ": identity.groups cannot name " + s + ", a group this package grants")
							return false
						}
					}
				}
				if isOrgRuleKey(key) && operator != "Exists" {
					noun := jsString(OrgRuleKeys.Get(key))
					var valid ruleSet
					switch noun {
					case "team":
						valid = envSet(member(orgObject, "teams"))
					case "department":
						valid = envSet(member(orgObject, "departments"))
					default:
						valid = envSet(member(orgObject, "licenses"))
					}
					for _, entry := range values {
						s, ok := entry.(string)
						if !ok {
							failure = invalidInput(clausePath + ": " + key + " lists " + noun + "s")
							return false
						}
						if valid != nil && !valid.Has(s) {
							failure = invalidInput(clausePath + ": unknown " + noun + " " + s)
							return false
						}
					}
				}
				return true
			})
			return failure == nil
		})
		if failure != nil {
			return nil, failure
		}
		return conditions, nil
	}
	parsedInclude := make([]any, 0, len(include))
	for index, item := range include {
		parsed, err := clause(item, path+".include["+strconv.Itoa(index)+"]")
		if err != nil {
			return nil, err
		}
		parsedInclude = append(parsedInclude, parsed)
	}
	parsedExclude := make([]any, 0, len(exclude))
	for index, item := range exclude {
		parsed, err := clause(item, path+".exclude["+strconv.Itoa(index)+"]")
		if err != nil {
			return nil, err
		}
		parsedExclude = append(parsedExclude, parsed)
	}
	text, _, err := core.Stringify(core.NewObject("include", parsedInclude, "exclude", parsedExclude))
	if err != nil {
		return nil, err
	}
	if utf16Len(text) > MaxRuleBytes {
		return nil, invalidInput(path + " is larger than " + strconv.Itoa(MaxRuleBytes) + " bytes")
	}
	var graceMs, maxGrants, maxRemovals any = core.Undefined, core.Undefined, core.Undefined
	if value := input.Get("graceMs"); !isUndefined(value) {
		number, err := Integer(value, path+".graceMs", 0, MaxGraceMs)
		if err != nil {
			return nil, err
		}
		graceMs = number
	}
	if value := input.Get("maxGrants"); !isUndefined(value) {
		number, err := Integer(value, path+".maxGrants", 1, 100_000)
		if err != nil {
			return nil, err
		}
		maxGrants = number
	}
	if value := input.Get("maxRemovals"); !isUndefined(value) {
		number, err := Integer(value, path+".maxRemovals", 1, 100_000)
		if err != nil {
			return nil, err
		}
		maxRemovals = number
	}
	result = core.NewObject("include", core.CloneValue(parsedInclude))
	if len(parsedExclude) > 0 {
		result.Set("exclude", core.CloneValue(parsedExclude))
	}
	if truthy(graceMs) {
		result.Set("graceMs", graceMs)
	}
	if !isUndefined(maxGrants) {
		result.Set("maxGrants", maxGrants)
	}
	if !isUndefined(maxRemovals) {
		result.Set("maxRemovals", maxRemovals)
	}
	return result, nil
}

// isPlainObjectPointer reports whether value is a typed nil *core.Object (an absent object in Go).
func isPlainObjectPointer(value any) bool {
	object, ok := value.(*core.Object)
	return ok && object == nil
}

// ruleList is a rule's clause list member (`include` or `exclude`) as a list of condition sets.
func ruleList(rule *core.Object, key string) []any {
	list, _ := member(rule, key).([]any)
	return list
}

// RuleInput (package-rules.ts ruleInput): The administrator-written part of a stored rule (or a rule input), without
// runtime state.
func RuleInput(rule *core.Object) (result *core.Object, err error) {
	result = core.NewObject("include", member(rule, "include"))
	if len(ruleList(rule, "exclude")) > 0 {
		result.Set("exclude", member(rule, "exclude"))
	}
	if graceMs := member(rule, "graceMs"); truthy(graceMs) {
		result.Set("graceMs", graceMs)
	}
	if maxGrants := member(rule, "maxGrants"); !isUndefined(maxGrants) {
		result.Set("maxGrants", maxGrants)
	}
	if maxRemovals := member(rule, "maxRemovals"); !isUndefined(maxRemovals) {
		result.Set("maxRemovals", maxRemovals)
	}
	return result, nil
}

// RuleProblem (package-rules.ts ruleProblem): The reason a stored rule no longer validates (an attribute declaration
// removed, a group gone), if any ("" when it validates).
func RuleProblem(rule *core.Object, env *core.Object) (result string, err error) {
	input, err := RuleInput(rule)
	if err != nil {
		return "", err
	}
	if _, failure := ParseAutoAssign(input, env, ""); failure != nil {
		return errorMessage(failure), nil
	}
	return "", nil
}

// stableJSON is stableJson: JSON with object members sorted by key and undefined members dropped.
func stableJSON(value any) (string, error) {
	text, _, err := core.Stringify(stableValue(value))
	return text, err
}

func stableValue(value any) any {
	switch v := value.(type) {
	case *core.Object:
		if v == nil {
			return nil
		}
		keys := v.Keys()
		slices.SortStableFunc(keys, compareUTF16)
		out := core.NewObject()
		for _, key := range keys {
			item := v.Get(key)
			if isUndefined(item) {
				continue
			}
			out.SetRaw(key, stableValue(item))
		}
		return out
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = stableValue(item)
		}
		return out
	}
	return value
}

// SameRuleInput (package-rules.ts sameRuleInput): Whether two rules say the same thing (runtime state ignored).
func SameRuleInput(a, b *core.Object) (bool, error) {
	left, err := RuleInput(a)
	if err != nil {
		return false, err
	}
	right, err := RuleInput(b)
	if err != nil {
		return false, err
	}
	x, err := stableJSON(left)
	if err != nil {
		return false, err
	}
	y, err := stableJSON(right)
	if err != nil {
		return false, err
	}
	return x == y, nil
}

// RuleDocument (package-rules.ts ruleDocument): Include clauses become allow statements and exclude clauses deny
// statements of one policy document.
func RuleDocument(rule *core.Object) (result *core.Object, err error) {
	statements := []any{}
	for index, conditions := range ruleList(rule, "include") {
		statements = append(statements, core.NewObject(
			"sid", "include-"+strconv.Itoa(index),
			"effect", "allow",
			"actions", []any{RuleAction},
			"resources", []any{"identity/*"},
			"conditions", conditions,
		))
	}
	for index, conditions := range ruleList(rule, "exclude") {
		statements = append(statements, core.NewObject(
			"sid", "exclude-"+strconv.Itoa(index),
			"effect", "deny",
			"actions", []any{RuleAction},
			"resources", []any{"identity/*"},
			"conditions", conditions,
		))
	}
	return core.NewObject("version", 1.0, "statements", statements), nil
}

// modelStrings reads a list member of RuleOrgFacts (a model array or a []string) as strings.
func modelStrings(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, jsString(item))
		}
		return out
	}
	return nil
}

// RuleContext (package-rules.ts ruleContext): The context a rule sees: the identity's declared attributes and fixed
// facts, and its group memberships that no access package created (so rules never chain onto another package or keep
// themselves alive). No session, request, or resource keys: a scheduler cannot replay them, and a preview must equal
// a reconcile. `org` supplies `identity.teams` and `identity.departments` where the caller evaluates them, and
// `identity.licenses` with them.
func RuleContext(identity *core.Object, directGroupIDs []string, org *core.Object) (result *core.Object, err error) {
	context := core.NewObject()
	if attributes, ok := identity.Get("attributes").(*core.Object); ok && attributes != nil {
		attributes.Entries(func(key string, value any) bool {
			context.Set("principal."+key, value)
			return true
		})
	}
	context.Set("principal.id", identity.Get("id"))
	context.Set("principal.kind", identity.Get("kind"))
	context.Set("principal.owner", identity.Get("owner"))
	if email := identity.Get("email"); truthy(email) {
		lowered := core.JSLower(jsString(email))
		context.Set("identity.email", lowered)
		context.Set("identity.emailDomain", lowered[strings.LastIndex(lowered, "@")+1:])
	}
	context.Set("identity.emailVerified", identity.Get("emailVerified"))
	if managerID := identity.Get("managerId"); truthy(managerID) {
		context.Set("identity.managerId", managerID)
	}
	context.Set("identity.groups", sortedUnique(directGroupIDs))
	context.Set("identity.guest", !isUndefined(identity.Get("guest")))
	if org != nil {
		context.Set("identity.teams", sortedUnique(modelStrings(org.Get("teams"))))
		context.Set("identity.departments", sortedUnique(modelStrings(org.Get("departments"))))
		context.Set("identity.licenses", sortedUnique(modelStrings(org.Get("licenses"))))
	}
	return context, nil
}

// testsGuest is testsGuest: whether any clause of a compiled rule tests `identity.guest`.
func testsGuest(document *core.Object) bool {
	statements, _ := document.Get("statements").([]any)
	for _, statement := range statements {
		conditions, _ := member(statement, "conditions").(*core.Object)
		found := false
		conditions.Entries(func(_ string, entries any) bool {
			if object, ok := entries.(*core.Object); ok && object != nil && object.Has("identity.guest") {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// ruleMatchResult is a RuleMatch over Go values.
type ruleMatchResult struct {
	matched    bool
	matchedBy  []string
	excludedBy []string
}

func (m ruleMatchResult) object() *core.Object {
	return core.NewObject("matched", m.matched, "matchedBy", stringsOf(m.matchedBy), "excludedBy", stringsOf(m.excludedBy))
}

// ruleMatchOf is ruleMatch over Go values.
func ruleMatchOf(document *core.Object, identity *core.Object, context *core.Object) (ruleMatchResult, error) {
	if !isUndefined(identity.Get("guest")) && !testsGuest(document) {
		return ruleMatchResult{matched: false, matchedBy: []string{}, excludedBy: []string{}}, nil
	}
	decision, err := core.EvaluatePolicy(core.EvaluationInput{
		Action:   RuleAction,
		Resource: "identity/" + jsString(identity.Get("id")),
		Context:  context,
		Grants:   []any{document},
	})
	if err != nil {
		return ruleMatchResult{}, err
	}
	result := ruleMatchResult{matched: decision.Allowed, matchedBy: []string{}, excludedBy: []string{}}
	for _, entry := range decision.Matched {
		parts := strings.Split(entry, ":")
		sid := ""
		if len(parts) > 2 {
			sid = strings.Join(parts[2:], ":")
		}
		if strings.HasPrefix(sid, "include-") {
			result.matchedBy = append(result.matchedBy, sid)
		}
		if strings.HasPrefix(sid, "exclude-") {
			result.excludedBy = append(result.excludedBy, sid)
		}
	}
	return result, nil
}

// RuleMatch (package-rules.ts ruleMatch): Evaluates a compiled rule for one identity; `matchedBy`/`excludedBy` name
// the clauses that held. Guests (guests.ts) match only rules that test `identity.guest` somewhere: a rule written
// for members (`principal.kind: user`) never reaches people from outside the organization.
func RuleMatch(document *core.Object, identity *core.Object, context *core.Object) (result *core.Object, err error) {
	match, err := ruleMatchOf(document, identity, context)
	if err != nil {
		return nil, err
	}
	return match.object(), nil
}

// ruleOperator is one `[operator, entries]` pair of a clause.
type ruleOperator struct {
	operator string
	entries  *core.Object
}

// operatorsOf is operatorsOf: Object.entries(clause).
func operatorsOf(clause any) []ruleOperator {
	object, _ := clause.(*core.Object)
	var out []ruleOperator
	object.Entries(func(operator string, value any) bool {
		entries, _ := value.(*core.Object)
		out = append(out, ruleOperator{operator, entries})
		return true
	})
	return out
}

// entriesHas is `key in entries`.
func entriesHas(entries *core.Object, key string) bool {
	return entries != nil && entries.Has(key)
}

// fixedPrincipalKeys are the keys fixed when an identity is created (or moved only by an ownership transfer); other
// `principal.` keys are attributes.
var fixedPrincipalKeys = newOrderedSet("principal.id", "principal.kind", "principal.owner")

// RuleWarnings (package-rules.ts ruleWarnings): Advice, not errors: rules that also match service accounts, email
// tests that accept unverified addresses, and clauses on facts that callers with fewer rights than the rule's owner
// control. A rule grants under its owner's authority to whoever matches, so whoever sets those facts picks the
// recipients: declared attributes and identity.managerId (iam:identities:update), and memberships of groups without
// role bindings (iam:groups:update alone; adding to a group with bindings needs their authorities). `boundGroups`
// holds the tenant's groups that have role bindings; without it, groups are not checked.
func RuleWarnings(rule *core.Object, env *core.Object) (result []string, err error) {
	warnings := []string{}
	boundGroups := envSet(member(env, "boundGroups"))
	controlled := func(clause any, path string, consequence string) {
		found := newOrderedSet()
		for _, pair := range operatorsOf(clause) {
			for _, key := range pair.entries.Keys() {
				if key == "identity.managerId" || (strings.HasPrefix(key, "principal.") && !fixedPrincipalKeys.Has(key)) {
					found.Add(key)
				}
			}
		}
		keys := found.Values()
		slices.SortStableFunc(keys, compareUTF16)
		if len(keys) > 0 {
			warnings = append(warnings, path+" tests "+strings.Join(keys, ", ")+", which anyone holding iam:identities:update can set, so "+consequence)
		}
		unbound := []string{}
		if boundGroups != nil {
			for _, groupID := range ruleValuesOf([]any{clause}, nil, "identity.groups") {
				if !boundGroups.Has(groupID) {
					unbound = append(unbound, groupID)
				}
			}
		}
		if len(unbound) > 0 {
			noun := "groups"
			if len(unbound) == 1 {
				noun = "a group"
			}
			warnings = append(warnings, path+" tests identity.groups for "+strings.Join(unbound, ", ")+", "+noun+" without role bindings whose members anyone holding iam:groups:update can change, so "+consequence)
		}
		// Seats follow license assignments (licenses.ts) and, for a product assigned to a group, that group's members:
		// the groups API asks for iam:licenses:assign there too, but a team's maintainers and directory sync change
		// members.
		if slices.ContainsFunc(operatorsOf(clause), func(pair ruleOperator) bool { return entriesHas(pair.entries, "identity.licenses") }) {
			warnings = append(warnings, path+" tests identity.licenses, which anyone holding iam:licenses:assign can change, as can whoever manages the members of a group a product is assigned to without it (a team's maintainers, directory sync), so "+consequence)
		}
	}
	include := ruleList(rule, "include")
	exclude := ruleList(rule, "exclude")
	// Testing identity.guest anywhere lets guests match the whole rule (see RuleMatch), not only that clause.
	guestTested := false
	for _, clause := range append(append([]any(nil), include...), exclude...) {
		if slices.ContainsFunc(operatorsOf(clause), func(pair ruleOperator) bool { return entriesHas(pair.entries, "identity.guest") }) {
			guestTested = true
			break
		}
	}
	for index, clause := range include {
		tests := operatorsOf(clause)
		path := "include[" + strconv.Itoa(index) + "]"
		if guestTested && !slices.ContainsFunc(tests, func(pair ruleOperator) bool { return entriesHas(pair.entries, "identity.guest") }) {
			warnings = append(warnings, path+" does not test identity.guest while the rule does elsewhere, so it also matches guests")
		}
		if !slices.ContainsFunc(tests, func(pair ruleOperator) bool {
			return strings.HasPrefix(pair.operator, "String") && entriesHas(pair.entries, "principal.kind")
		}) {
			warnings = append(warnings, path+" does not test principal.kind, so it also matches service accounts")
		}
		email := slices.ContainsFunc(tests, func(pair ruleOperator) bool {
			return entriesHas(pair.entries, "identity.email") || entriesHas(pair.entries, "identity.emailDomain")
		})
		if email && member(member(clause, "Bool"), "identity.emailVerified") != true {
			warnings = append(warnings, path+" tests an email address without requiring Bool identity.emailVerified: true, so unverified addresses match (SCIM-provisioned and administrator-set addresses are unverified)")
		}
		controlled(clause, path, "they choose who receives this package under its owner’s authority")
	}
	for index, clause := range exclude {
		controlled(clause, "exclude["+strconv.Itoa(index)+"]", "they can lift the exclusion")
	}
	return warnings, nil
}

// ruleValuesOf is ruleValues over clause lists.
func ruleValuesOf(include, exclude []any, key string) []string {
	found := newOrderedSet()
	for _, clause := range append(append([]any(nil), include...), exclude...) {
		for _, pair := range operatorsOf(clause) {
			if pair.operator != "ArrayContains" && pair.operator != "ArrayContainsAll" {
				continue
			}
			expected := member(pair.entries, key)
			values, isList := expected.([]any)
			if !isList {
				values = []any{expected}
			}
			for _, value := range values {
				if s, ok := value.(string); ok {
					found.Add(s)
				}
			}
		}
	}
	values := found.Values()
	if values == nil {
		values = []string{}
	}
	return values
}

// RuleValues (package-rules.ts ruleValues): The values a rule tests an array key (identity.groups, identity.teams,
// identity.departments) for. A nil rule tests none.
func RuleValues(rule *core.Object, key string) (result []string, err error) {
	if rule == nil {
		return []string{}, nil
	}
	return ruleValuesOf(ruleList(rule, "include"), ruleList(rule, "exclude"), key), nil
}

// RuleGroupIDs (package-rules.ts ruleGroupIds): The group IDs (or names) a rule tests with identity.groups.
func RuleGroupIDs(rule *core.Object) (result []string, err error) {
	return RuleValues(rule, "identity.groups")
}

// MapRuleValues (package-rules.ts mapRuleValues): A copy of a rule with the values it tests an array key for mapped
// (IDs to names for export, names to IDs for apply).
func MapRuleValues(rule any, key string, mapValue func(string) string) (result any, err error) {
	source, ok := rule.(*core.Object)
	if !ok || source == nil {
		return nil, errors.New("mapRuleValues: rule must be an object")
	}
	clone := source.Clone()
	for _, clause := range append(append([]any(nil), ruleList(clone, "include")...), ruleList(clone, "exclude")...) {
		for _, pair := range operatorsOf(clause) {
			if pair.operator != "ArrayContains" && pair.operator != "ArrayContainsAll" {
				continue
			}
			expected := member(pair.entries, key)
			if isUndefined(expected) {
				continue
			}
			switch v := expected.(type) {
			case []any:
				mapped := make([]any, len(v))
				for index, value := range v {
					if s, ok := value.(string); ok {
						mapped[index] = mapValue(s)
					} else {
						mapped[index] = value
					}
				}
				pair.entries.SetRaw(key, mapped)
			case string:
				pair.entries.SetRaw(key, mapValue(v))
			default:
				pair.entries.SetRaw(key, expected)
			}
		}
	}
	return clone, nil
}

// MapRuleGroups (package-rules.ts mapRuleGroups): A copy of a rule with its identity.groups values mapped (IDs to
// names for export, names to IDs for apply).
func MapRuleGroups(rule any, mapValue func(string) string) (result any, err error) {
	return MapRuleValues(rule, "identity.groups", mapValue)
}
