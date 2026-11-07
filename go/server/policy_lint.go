package server

// Port of packages/server/src/policy-lint.ts: a static linter for policy documents (statements that grant more than
// intended, conditions that never match or silently fail open, shadowed and duplicated statements).

import (
	"errors"
	"math"
	"math/bits"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// lintKeyInfo is what the linter knows about a context key.
type lintKeyInfo struct {
	// known: set by the server, declared by configuration, or supplied by the application.
	known bool
	// optional: missing from some decisions; every operator except Exists is then false.
	optional bool
	// keyType is what the key holds ("" when unknown): identifier, timestamp, string, number, boolean or list.
	keyType string
}

// lintServerKeys is every key the server derives: the shared principal and request registry plus the resource keys
// decisions add.
var lintServerKeys = func() map[string]string {
	keys := map[string]string{}
	for _, entry := range PrincipalServerKeys.Entries() {
		keys[entry.Name] = entry.Type
	}
	for _, entry := range TenantServerKeys.Entries() {
		keys[entry.Name] = entry.Type
	}
	keys["resource.tenantId"] = "identifier"
	keys["resource.relations"] = "list"
	keys["resource.parentRelations"] = "list"
	return keys
}()

// lintOptionalServerKeys are server keys absent from some decisions: API keys and role sessions have no sign-in
// method, the session attribution keys exist only when set, and request.sourceIp needs a known client address.
var lintOptionalServerKeys = func() map[string]bool {
	keys := map[string]bool{}
	for _, key := range OptionalPrincipalServerKeys.Values() {
		keys[key] = true
	}
	for _, key := range OptionalResourceServerKeys.Values() {
		keys[key] = true
	}
	return keys
}()

// lintResourceLinks are links every managed resource may carry besides its declared attributes.
var lintResourceLinks = map[string]bool{"ownerId": true, "parentId": true, "parentType": true}

// lintMissingKeyHints are keys people commonly expect but the server never sets, with the usual alternative.
var lintMissingKeyHints = map[string]string{
	"resource.type":           "or match the type in the resource pattern",
	"resource.id":             "or match the ID in the resource pattern",
	"principal.email":         "or declare it as an identity attribute",
	"principal.name":          "or declare it as an identity attribute",
	"principal.managerId":     "or declare it as an identity attribute",
	"request.ip":              "or use request.sourceIp, which the server sets from the client address",
	"principal.tokenIssuedAt": "or use principal.tokenIssueTime",
	"principal.risk":          "or use principal.riskLevel (none, low, medium, high) or principal.riskScore (0-100)",
	"principal.license":       "or use principal.licenses (the keys of the products the person holds a seat for)",
}

var lintTypeLabels = map[string]string{
	"identifier": "a string",
	"timestamp":  "a timestamp string",
	"string":     "a string",
	"number":     "a number",
	"boolean":    "a boolean",
	"list":       "a list",
}

// typeLabel is typeLabels[type] (undefined for a type outside the table).
func typeLabel(keyType string) string {
	if label, ok := lintTypeLabels[keyType]; ok {
		return label
	}
	return "undefined"
}

var lintNumericOperators = map[string]bool{
	"NumericEquals": true, "NumericNotEquals": true, "NumericLessThan": true, "NumericLessThanEquals": true,
	"NumericGreaterThan": true, "NumericGreaterThanEquals": true,
}
var lintDateOperators = map[string]bool{"DateBefore": true, "DateAfter": true}
var lintArrayOperators = map[string]bool{"ArrayContains": true, "ArrayContainsAll": true}

// lintNegatedStringOperators: an unresolved variable in their value makes the comparison true.
var lintNegatedStringOperators = map[string]bool{"StringNotEquals": true, "StringNotEqualsIgnoreCase": true, "StringNotLike": true}

var lintVariablePattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_.:-]{0,127})\}`)
var lintStarsPattern = regexp.MustCompile(`^\*+$`)
var lintWildcardPattern = regexp.MustCompile(`[*?]`)
var lintEverythingResource = regexp.MustCompile(`^(iam/)?\*+$`)
var lintServiceWildcard = regexp.MustCompile(`(^|:)\*$`)
var lintUpperCase = regexp.MustCompile(`[A-Z]`)

// lintList is `Array.isArray(value) ? value : [value]`.
func lintList(value any) []any {
	if items, ok := value.([]any); ok {
		return items
	}
	return []any{value}
}

// variablesOf is the variable names a condition value or pattern references (strings only).
func variablesOf(value any) []string {
	text, ok := value.(string)
	if !ok {
		return nil
	}
	var names []string
	for _, match := range lintVariablePattern.FindAllStringSubmatch(text, -1) {
		names = append(names, match[1])
	}
	return names
}

// lintStrings is a validated pattern list.
func lintStrings(value any) []string {
	items, _ := value.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, jsString(item))
	}
	return result
}

// hasOwn is Object.hasOwn over a model value.
func hasOwn(value any, key string) bool {
	object, ok := value.(*core.Object)
	return ok && object.Has(key)
}

func lintKeyInfoOf(key string, context *core.Object) lintKeyInfo {
	clearances := truthy(context.Get("clearances"))
	// The clearance and classification keys are the server's only with security clearances (`context.clearances`);
	// without it they are ordinary keys the application may supply.
	server := ""
	if clearances || !ClearanceServerKeys.Has(key) {
		if found, ok := lintServerKeys[key]; ok {
			server = found
		} else if clearances {
			server, _ = ResourceServerKeys.Get(key)
		}
	}
	if server != "" {
		return lintKeyInfo{known: true, optional: lintOptionalServerKeys[key], keyType: server}
	}
	// Session tags: a valid tag name is an optional server string; an invalid one can never be set.
	if strings.HasPrefix(key, SessionTagPrefix) {
		if SessionTagName(key[len(SessionTagPrefix):]) != "" {
			return lintKeyInfo{known: true, optional: true, keyType: "string"}
		}
		return lintKeyInfo{known: false, optional: true}
	}
	// The bare family name is reserved and stripped from application context before every decision, so an
	// application listing it in contextKeys still never supplies it.
	if key == SessionTagPrefix[:len(SessionTagPrefix)-1] {
		return lintKeyInfo{known: false, optional: true}
	}
	attributes := context.Get("identityAttributes")
	if nullish(attributes) {
		attributes = core.NewObject()
	}
	if strings.HasPrefix(key, "principal.") {
		attribute := key[len("principal."):]
		if hasOwn(attributes, attribute) {
			declared := member(attributes, attribute)
			keyType, isString := declared.(string)
			if !isString && truthy(declared) {
				keyType = jsString(declared)
			}
			return lintKeyInfo{known: true, optional: true, keyType: keyType}
		}
	}
	if strings.HasPrefix(key, "resource.") {
		name := key[len("resource."):]
		if lintResourceLinks[name] {
			return lintKeyInfo{known: true, optional: true, keyType: "identifier"}
		}
		var declared bool
		if resourceAttributes := context.Get("resourceAttributes"); truthy(resourceAttributes) {
			items, _ := resourceAttributes.([]any)
			declared = includesValue(items, name)
		} else {
			_, hinted := lintMissingKeyHints[key]
			declared = !hinted
		}
		if declared {
			return lintKeyInfo{known: true, optional: true}
		}
	}
	contextKeys, _ := context.Get("contextKeys").([]any)
	return lintKeyInfo{known: includesValue(contextKeys, key), optional: true}
}

// lintTypeMismatch says why an operator can never match a key of this type, or "" when the pairing is sound.
func lintTypeMismatch(operator, key, keyType string) string {
	if operator == "Exists" || keyType == "list" {
		return ""
	}
	if operator == "Bool" {
		if keyType == "boolean" {
			return ""
		}
		return "Bool never matches " + key + ", which holds " + typeLabel(keyType) + "."
	}
	if keyType == "boolean" {
		return operator + " never matches " + key + ", which is a boolean; use Bool."
	}
	if lintNumericOperators[operator] {
		if keyType == "number" {
			return ""
		}
		return operator + " never matches " + key + ", which holds " + typeLabel(keyType) + "."
	}
	if lintDateOperators[operator] {
		if keyType == "timestamp" || keyType == "string" {
			return ""
		}
		holds := "an identifier"
		if keyType == "number" {
			holds = "a number"
		}
		return operator + " compares timestamps, but " + key + " holds " + holds +
			"; only request.time, principal.tokenIssueTime, principal.authTime, principal.mfaTime, or a string attribute holding ISO timestamps works with date operators."
	}
	if lintArrayOperators[operator] {
		return operator + " never matches " + key + ", which holds a single value; compare it with a String, Numeric, or Bool operator."
	}
	if keyType == "number" {
		return operator + " never matches " + key + ", which is a number; use a Numeric operator."
	}
	return ""
}

// lintBits is a set of statement positions, 32 per word.
type lintBits []uint32

func bitWords(size int) int {
	return max(1, int(math.Ceil(float64(size)/32)))
}

func (b lintBits) add(position int) { b[position>>5] |= 1 << (position & 31) }

func (b lintBits) or(source lintBits) {
	for word := range b {
		b[word] |= source[word]
	}
}

func (b lintBits) and(source lintBits) {
	for word := range b {
		b[word] &= source[word]
	}
}

func (b lintBits) empty() bool {
	for _, word := range b {
		if word != 0 {
			return false
		}
	}
	return true
}

func (b lintBits) clone() lintBits { return append(lintBits(nil), b...) }

func subsetOf(subset, of lintBits) bool {
	for word := range subset {
		if subset[word]&^of[word] != 0 {
			return false
		}
	}
	return true
}

// firstCommon is the lowest position in both sets, or -1.
func firstCommon(a, b lintBits) int {
	for word := range a {
		if common := a[word] & b[word]; common != 0 {
			return word*32 + bits.TrailingZeros32(common)
		}
	}
	return -1
}

// lintCoverageBudget is the work one coverage index may spend, in rough character comparisons: far more than any
// realistic document needs, and a bound of tens of milliseconds on a hostile one (up to 128 statements of 128 patterns
// each).
const lintCoverageBudget = 2_000_000

type lintWildcard struct {
	pattern string
	// prefixOnly: the pattern is `{head}*`: it covers every value, wildcards included, that starts with the head.
	prefixOnly bool
	// head and tail: literal text before the first wildcard and after the last: every value the pattern matches has
	// both.
	head, tail string
	// factor bounds matchPattern's comparisons per value character: the longest run between stars, plus one.
	factor  int
	holders lintBits
}

type lintIndex struct {
	all       lintBits
	exact     map[string]lintBits
	wildcards []*lintWildcard
	resolved  map[string]lintBits
}

// lintCoverage says which of `statements` cover an action or resource, as a set of their positions. A pattern covers
// a value when it is all stars or the same text, when it matches the value as a literal (no wildcards or variables),
// or when it is `prefix*` and the value starts with that prefix. Each distinct value is resolved once against each
// distinct pattern; the lookup answers false (ok) once the matching work exceeds the budget.
func lintCoverage(statements []*core.Object) func(field, value string) (lintBits, bool) {
	words := bitWords(len(statements))
	budget := lintCoverageBudget
	index := func(field string) *lintIndex {
		result := &lintIndex{all: make(lintBits, words), exact: map[string]lintBits{}, resolved: map[string]lintBits{}}
		wildcards := map[string]*lintWildcard{}
		for position, statement := range statements {
			for _, pattern := range lintStrings(statement.Get(field)) {
				if lintStarsPattern.MatchString(pattern) {
					result.all.add(position)
					continue
				}
				same, ok := result.exact[pattern]
				if !ok {
					same = make(lintBits, words)
					result.exact[pattern] = same
				}
				same.add(position)
				if strings.Contains(pattern, "${") || !lintWildcardPattern.MatchString(pattern) {
					continue
				}
				wildcard, ok := wildcards[pattern]
				if !ok {
					head := pattern[:strings.IndexAny(pattern, "*?")]
					longest := 0
					for _, run := range strings.Split(pattern, "*") {
						longest = max(longest, utf16Len(run))
					}
					wildcard = &lintWildcard{
						pattern:    pattern,
						prefixOnly: pattern == head+"*",
						head:       head,
						tail:       pattern[max(strings.LastIndex(pattern, "*"), strings.LastIndex(pattern, "?"))+1:],
						factor:     longest + 1,
						holders:    make(lintBits, words),
					}
					wildcards[pattern] = wildcard
					result.wildcards = append(result.wildcards, wildcard)
				}
				wildcard.holders.add(position)
			}
		}
		return result
	}
	fields := map[string]*lintIndex{"actions": index("actions"), "resources": index("resources")}
	return func(field, value string) (lintBits, bool) {
		current := fields[field]
		if known, ok := current.resolved[value]; ok {
			return known, true
		}
		covered := current.all.clone()
		if same, ok := current.exact[value]; ok {
			covered.or(same)
		}
		literal := !lintWildcardPattern.MatchString(value) && !strings.Contains(value, "${")
		for _, wildcard := range current.wildcards {
			if budget -= 4; budget < 0 {
				return nil, false
			}
			if subsetOf(wildcard.holders, covered) || !(literal || wildcard.prefixOnly) {
				continue
			}
			budget -= utf16Len(wildcard.head) + utf16Len(wildcard.tail)
			if !strings.HasPrefix(value, wildcard.head) || !strings.HasSuffix(value, wildcard.tail) {
				continue
			}
			if !wildcard.prefixOnly {
				budget -= utf16Len(wildcard.pattern) + utf16Len(value)*wildcard.factor
				if budget < 0 {
					return nil, false
				}
				if !core.MatchPattern(wildcard.pattern, value, nil) {
					continue
				}
			}
			covered.or(wildcard.holders)
		}
		current.resolved[value] = covered
		return covered, true
	}
}

// absenceKey is the key a deny tests for absence when that is its only condition (Exists false), so it applies
// exactly then; "" (false) otherwise.
func absenceKey(statement *core.Object) (string, bool) {
	operators := objectEntries(statement.Get("conditions"))
	if statement.Get("effect") != "deny" || len(operators) != 1 || operators[0].key != "Exists" {
		return "", false
	}
	keys := objectEntries(operators[0].value)
	if len(keys) == 1 && includesValue(lintList(keys[0].value), false) {
		return keys[0].key, true
	}
	return "", false
}

// sortedUnique is `[...new Set(items)].sort()`.
func sortedUnique(items []string) []any {
	values := unique(items)
	sortStable(values, compareUTF16)
	return stringsOf(values)
}

// fingerprint is an order-insensitive fingerprint of a statement (its sid aside).
func fingerprint(statement *core.Object) string {
	operators := objectEntries(statement.Get("conditions"))
	conditions := make([]any, 0, len(operators))
	byKey := func(a, b objectEntry) int { return compareUTF16(a.key, b.key) }
	sortStable(operators, byKey)
	for _, operator := range operators {
		attributes := objectEntries(operator.value)
		sortStable(attributes, byKey)
		entries := make([]any, 0, len(attributes))
		for _, attribute := range attributes {
			var encoded []string
			for _, value := range lintList(attribute.value) {
				text, _, _ := core.Stringify(value)
				encoded = append(encoded, text)
			}
			entries = append(entries, []any{attribute.key, sortedUnique(encoded)})
		}
		conditions = append(conditions, []any{operator.key, entries})
	}
	text, _, _ := core.Stringify([]any{
		statement.Get("effect"),
		sortedUnique(lintStrings(statement.Get("actions"))),
		sortedUnique(lintStrings(statement.Get("resources"))),
		conditions,
	})
	return text
}

// LintPolicy (policy-lint.ts lintPolicy): Lints a policy document: validates it as storage would, then reports
// statements that grant more than intended, conditions that can never match or silently fail open, and statements
// that are shadowed or duplicated. The context ({ identityAttributes?, resourceAttributes?, contextKeys?,
// clearances? }; nil for none) tells the linter which identity attributes, resource attributes, and application keys
// exist. Pattern comparisons are budgeted: past the budget, a `shadowed-allow-skipped` note replaces the rest of the
// shadow check. The result is { valid, error?, warnings }.
func LintPolicy(document any, context *core.Object) (result *core.Object, err error) {
	if context == nil {
		context = core.NewObject()
	}
	if err := core.ValidatePolicy(document); err != nil {
		var known *core.IamError
		if errors.As(err, &known) {
			return core.NewObject("valid", false, "error", core.NewObject("code", known.Code, "message", known.Message), "warnings", []any{}), nil
		}
		return nil, err
	}
	cache := map[string]lintKeyInfo{}
	info := func(key string) lintKeyInfo {
		found, ok := cache[key]
		if !ok {
			found = lintKeyInfoOf(key, context)
			cache[key] = found
		}
		return found
	}
	value, _ := core.PolicyValue(document).(*core.Object)
	items, _ := value.Get("statements").([]any)
	statements := make([]*core.Object, len(items))
	for index, item := range items {
		statements[index] = item.(*core.Object)
	}
	warnings := []*core.Object{}
	fingerprints := map[string]int{}

	// Denies whose only condition is Exists false on one key. Such a deny makes another deny on that key safe when
	// it covers every action and resource of the other.
	var guards []*core.Object
	for _, statement := range statements {
		if _, ok := absenceKey(statement); ok {
			guards = append(guards, statement)
		}
	}
	guardsByKey := map[string]lintBits{}
	for position, guard := range guards {
		key, _ := absenceKey(guard)
		bitsOf, ok := guardsByKey[key]
		if !ok {
			bitsOf = make(lintBits, bitWords(len(guards)))
			guardsByKey[key] = bitsOf
		}
		bitsOf.add(position)
	}
	guarding := lintCoverage(guards)
	// absenceGuarded: some deny for the missing-key case covers the whole statement; false when the check runs out
	// of budget.
	absenceGuarded := func(statement *core.Object, key string) bool {
		found, ok := guardsByKey[key]
		if !ok {
			return false
		}
		candidates := found.clone()
		for _, field := range []string{"actions", "resources"} {
			for _, value := range unique(lintStrings(statement.Get(field))) {
				covering, ok := guarding(field, value)
				if !ok {
					return false
				}
				candidates.and(covering)
				if candidates.empty() {
					return false
				}
			}
		}
		return true
	}

	// Allows whose every action and resource pair an unconditional deny covers, with those denies' indexes.
	var denyIndexes []int
	var denies []*core.Object
	for index, statement := range statements {
		if statement.Get("effect") == "deny" && !truthy(statement.Get("conditions")) {
			denyIndexes = append(denyIndexes, index)
			denies = append(denies, statement)
		}
	}
	denying := lintCoverage(denies)
	// shadowingDenies answers the shadowing denies (empty: none), or false when the budget ran out.
	shadowingDenies := func(statement *core.Object) ([]int, bool) {
		var sides [][]lintBits
		for _, field := range []string{"actions", "resources"} {
			var side []lintBits
			for _, value := range unique(lintStrings(statement.Get(field))) {
				covering, ok := denying(field, value)
				if !ok {
					return nil, false
				}
				if covering.empty() {
					return []int{}, true
				}
				side = append(side, covering)
			}
			sides = append(sides, side)
		}
		shadowing := map[int]bool{}
		for _, action := range sides[0] {
			for _, resource := range sides[1] {
				first := firstCommon(action, resource)
				if first < 0 {
					return []int{}, true
				}
				shadowing[denyIndexes[first]] = true
			}
		}
		result := make([]int, 0, len(shadowing))
		for index := range shadowing {
			result = append(result, index)
		}
		sort.Ints(result)
		return result, true
	}
	shadowed := map[int][]int{}
	// unchecked is the first allow the shadow check had no budget left for (-1: none).
	unchecked := -1
	if len(denyIndexes) > 0 {
		for index, statement := range statements {
			if statement.Get("effect") != "allow" {
				continue
			}
			shadowing, ok := shadowingDenies(statement)
			if !ok {
				unchecked = index
				break
			}
			if len(shadowing) > 0 {
				shadowed[index] = shadowing
			}
		}
	}

	type conditionEntry struct {
		operator string
		key      string
		values   []any
	}
	for index, statement := range statements {
		warn := func(code, severity, message string) {
			warning := core.NewObject("code", code, "severity", severity, "statement", float64(index))
			if sid := statement.Get("sid"); !isUndefined(sid) {
				warning.SetRaw("sid", sid)
			}
			warning.Set("message", message)
			warnings = append(warnings, warning)
		}
		once := map[string]bool{}
		first := func(code, subject string) bool {
			marker := code + "\x00" + subject
			if once[marker] {
				return false
			}
			once[marker] = true
			return true
		}
		var entries []conditionEntry
		for _, operator := range objectEntries(statement.Get("conditions")) {
			for _, attribute := range objectEntries(operator.value) {
				entries = append(entries, conditionEntry{operator.key, attribute.key, lintList(attribute.value)})
			}
		}
		exists := member(statement.Get("conditions"), "Exists")
		if nullish(exists) {
			exists = core.NewObject()
		}
		var variables []string
		for _, resource := range lintStrings(statement.Get("resources")) {
			variables = append(variables, variablesOf(resource)...)
		}
		for _, entry := range entries {
			for _, value := range entry.values {
				variables = append(variables, variablesOf(value)...)
			}
		}
		actions := lintStrings(statement.Get("actions"))
		resources := lintStrings(statement.Get("resources"))

		if statement.Get("effect") == "allow" && !truthy(statement.Get("conditions")) {
			everything := false
			for _, action := range actions {
				if action == "*" || action == "iam:*" {
					for _, resource := range resources {
						if lintEverythingResource.MatchString(resource) {
							everything = true
							break
						}
					}
					break
				}
			}
			var serviceWide []string
			for _, action := range actions {
				if action != "*" && action != "iam:*" && lintServiceWildcard.MatchString(action) {
					serviceWide = append(serviceWide, action)
				}
			}
			if everything {
				warn("unrestricted-admin", "warning",
					"An unconditional allow of every action on every resource makes each holder a full administrator. Scope the actions and resources, or add conditions such as principal.mfa.")
			} else if len(serviceWide) > 0 {
				services := "those services"
				if len(serviceWide) == 1 {
					services = "that service"
				}
				warn("service-wildcard", "info", "Unconditional "+strings.Join(serviceWide, ", ")+" also grants actions added to "+services+" later. List the actions holders need.")
			}
		}

		conditionKeys := make([]string, len(entries))
		for position, entry := range entries {
			conditionKeys[position] = entry.key
		}
		for _, group := range []struct {
			kind string
			keys []string
		}{{"Condition key", conditionKeys}, {"Variable", variables}} {
			for _, key := range group.keys {
				if info(key).known || !first("unknown-context-key", key) {
					continue
				}
				hint := ""
				if text, ok := lintMissingKeyHints[key]; ok {
					hint = ", " + text
				}
				until := "Until then every operator except Exists is false for it."
				if group.kind == "Variable" {
					until = "Until then the variable never resolves."
				}
				warn("unknown-context-key", "warning", group.kind+" "+key+" is never set by the server; supply it with resolveContext"+hint+". "+until)
			}
		}

		if statement.Get("effect") == "deny" {
			for _, entry := range entries {
				if entry.operator == "Exists" || !info(entry.key).optional || hasOwn(exists, entry.key) ||
					!first("optional-key-deny", entry.key) || absenceGuarded(statement, entry.key) {
					continue
				}
				warn("optional-key-deny", "warning", "This deny tests "+entry.key+
					", which is missing from some requests; when it is missing the deny silently never applies. Add a deny whose only condition is Exists { \""+
					entry.key+"\": false } over the same actions and resources for that case, or test Exists on the key here to make the intent explicit.")
			}
		}

		for _, entry := range entries {
			operator, key, values := entry.operator, entry.key, entry.values
			keyType := info(key).keyType
			var variableKeys []string
			for _, value := range values {
				variableKeys = append(variableKeys, variablesOf(value)...)
			}
			if lintNegatedStringOperators[operator] {
				for _, variable := range variableKeys {
					guarded := false
					if hasOwn(exists, variable) {
						guarded = true
						for _, value := range lintList(member(exists, variable)) {
							if value != true {
								guarded = false
								break
							}
						}
					}
					if !info(variable).optional || guarded || !first("negated-variable", variable) {
						continue
					}
					warn("negated-variable", "warning", operator+" on "+key+" compares with ${"+variable+
						"}, which can be missing; an unresolved variable makes the negated comparison true. Add Exists { \""+variable+"\": true } to this statement.")
				}
			}
			if operator == "StringLikeIgnoreCase" {
				for _, variable := range variableKeys {
					if lintUpperCase.MatchString(variable) && first("ignorecase-variable", variable) {
						warn("ignorecase-variable", "warning", "StringLikeIgnoreCase lowercases its pattern, so ${"+variable+"} is looked up as ${"+
							core.JSLower(variable)+"} and does not resolve. Use StringLike or a lowercase key.")
					}
				}
			}
			if keyType == "list" && operator != "Exists" && !lintArrayOperators[operator] && first("array-key-string-operator", operator+":"+key) {
				warn("array-key-string-operator", "warning", operator+" never matches "+key+", which holds a list. Use ArrayContains or ArrayContainsAll.")
			}
			if keyType != "" {
				if mismatch := lintTypeMismatch(operator, key, keyType); mismatch != "" && first("type-mismatch", operator+":"+key) {
					warn("type-mismatch", "warning", mismatch)
				}
			}
			if (operator == "Bool" || operator == "Exists") && includesValue(values, true) && includesValue(values, false) {
				holds := "holds for any boolean value"
				if operator == "Exists" {
					holds = "always holds"
				}
				warn("always-true-condition", "info", operator+" lists both true and false for "+key+", so it "+holds+". Remove the condition or keep one value.")
			}
		}

		for _, variable := range variables {
			if info(variable).keyType == "list" && first("array-variable", variable) {
				warn("array-variable", "warning", "${"+variable+
					"} names a list, and variables only resolve to strings, numbers, and booleans, so it never resolves. Test the list with ArrayContains instead.")
			}
		}

		printed := fingerprint(statement)
		if earlier, ok := fingerprints[printed]; !ok {
			fingerprints[printed] = index
		} else {
			sid := ""
			if earlierSid := statements[earlier].Get("sid"); !isUndefined(earlierSid) {
				sid = " (" + jsString(earlierSid) + ")"
			}
			warn("duplicate-statement", "info", "This statement repeats statement "+strconv.Itoa(earlier)+sid+"; remove one of them.")
		}

		if shadowing, ok := shadowed[index]; ok {
			listed := make([]string, len(shadowing))
			for position, deny := range shadowing {
				listed[position] = strconv.Itoa(deny)
			}
			warn("shadowed-allow", "warning", "Every action and resource of this allow is also denied unconditionally (statement "+
				strings.Join(listed, ", ")+"), so it never grants anything.")
		}
	}

	anyAllow := false
	for _, statement := range statements {
		if statement.Get("effect") == "allow" {
			anyAllow = true
			break
		}
	}
	if !anyAllow {
		warnings = append(warnings, core.NewObject("code", "deny-only", "severity", "info", "statement", -1.0,
			"message", "The document has no allow statements, so it grants nothing; its denies still restrict every holder."))
	}
	if unchecked >= 0 {
		warnings = append(warnings, core.NewObject("code", "shadowed-allow-skipped", "severity", "info", "statement", -1.0,
			"message", "The document has too many patterns to compare every allow with the unconditional denies; allows from statement "+
				strconv.Itoa(unchecked)+" on were not checked for shadowing."))
	}
	sortStable(warnings, func(a, b *core.Object) int {
		if difference := jsNumber(a.Get("statement")) - jsNumber(b.Get("statement")); difference != 0 {
			if difference < 0 {
				return -1
			}
			return 1
		}
		if order := compareUTF16(jsString(a.Get("code")), jsString(b.Get("code"))); order != 0 {
			return order
		}
		return compareUTF16(jsString(a.Get("message")), jsString(b.Get("message")))
	})
	return core.NewObject("valid", true, "warnings", objectsOf(warnings)), nil
}
