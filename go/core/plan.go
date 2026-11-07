package core

import (
	"strings"
)

// Query planning (partial evaluation): which resources of one type may a principal perform one action on, as a
// filter over the resource's `id` and attributes that a database can apply. A resource passes the filter exactly when
// EvaluatePolicy would allow it (except refusals for exceeding the evaluation work budget).

// FilterValue is a string, float64 or bool.
type FilterValue = any

// ResourceFilter is a filter over one resource: its `id` and its attributes by name. Kind selects the members used:
//
//	true, false
//	and, or        Filters
//	not            Filter
//	exists         Field (the field is present)
//	type           Field, Type (string, number, boolean or ip)
//	equals         Field, Values, IgnoreCase
//	compare        Field, Operator (lt, le, gt, ge), Value (float64)
//	like           Field, Pattern (* any run, ? one character, \ escapes), IgnoreCase
//	date           Field, Operator (before, after), Value (an ISO 8601 string)
//	ip             Field, Network
//	contains       Field, Value (a FilterValue)
type ResourceFilter struct {
	Kind       string
	Filters    []ResourceFilter
	Filter     *ResourceFilter
	Field      string
	Type       string
	Values     []FilterValue
	IgnoreCase bool
	Operator   string
	Value      any
	Pattern    string
	Network    string
}

// ToValue is the filter as a model value, with TypeScript's member order.
func (f ResourceFilter) ToValue() *Object {
	o := NewObject("kind", f.Kind)
	switch f.Kind {
	case "and", "or":
		filters := make([]any, len(f.Filters))
		for index, item := range f.Filters {
			filters[index] = item.ToValue()
		}
		o.SetRaw("filters", filters)
	case "not":
		if f.Filter != nil {
			o.SetRaw("filter", f.Filter.ToValue())
		}
	case "exists":
		o.Set("field", f.Field)
	case "type":
		o.Set("field", f.Field).Set("type", f.Type)
	case "equals":
		o.Set("field", f.Field).SetRaw("values", append([]any{}, f.Values...))
		if f.IgnoreCase {
			o.Set("ignoreCase", true)
		}
	case "compare", "date":
		o.Set("field", f.Field).Set("operator", f.Operator).Set("value", f.Value)
	case "like":
		o.Set("field", f.Field).Set("pattern", f.Pattern)
		if f.IgnoreCase {
			o.Set("ignoreCase", true)
		}
	case "ip":
		o.Set("field", f.Field).Set("network", f.Network)
	case "contains":
		o.Set("field", f.Field).Set("value", f.Value)
	}
	return o
}

// MarshalJSON writes the filter as TypeScript does.
func (f ResourceFilter) MarshalJSON() ([]byte, error) { return f.ToValue().MarshalJSON() }

// UnmarshalJSON reads a filter.
func (f *ResourceFilter) UnmarshalJSON(data []byte) error {
	value, err := ParseJSON(data)
	if err != nil {
		return err
	}
	parsed, err := FilterFromValue(value)
	if err != nil {
		return err
	}
	*f = parsed
	return nil
}

// FilterFromValue reads a filter from a model value.
func FilterFromValue(value any) (ResourceFilter, error) {
	o, ok := value.(*Object)
	if !ok || o == nil {
		return ResourceFilter{}, NewIamError("INVALID_INPUT", "A filter must be an object")
	}
	f := ResourceFilter{}
	f.Kind, _ = o.Get("kind").(string)
	f.Field, _ = o.Get("field").(string)
	f.Type, _ = o.Get("type").(string)
	f.Operator, _ = o.Get("operator").(string)
	f.Pattern, _ = o.Get("pattern").(string)
	f.Network, _ = o.Get("network").(string)
	f.IgnoreCase, _ = o.Get("ignoreCase").(bool)
	if v := o.Get("value"); !IsUndefined(v) {
		f.Value = v
	}
	if values, ok := o.Get("values").([]any); ok {
		f.Values = append([]any{}, values...)
	}
	if filters, ok := o.Get("filters").([]any); ok {
		f.Filters = []ResourceFilter{}
		for _, item := range filters {
			child, err := FilterFromValue(item)
			if err != nil {
				return ResourceFilter{}, err
			}
			f.Filters = append(f.Filters, child)
		}
	}
	if inner := o.Get("filter"); !IsUndefined(inner) {
		child, err := FilterFromValue(inner)
		if err != nil {
			return ResourceFilter{}, err
		}
		f.Filter = &child
	}
	return f, nil
}

// ResourcePlan is the planner's answer: every resource (always), none (never), or those that pass Filter
// (conditional).
type ResourcePlan struct {
	Kind   string         `json:"kind"`
	Filter ResourceFilter `json:"filter"`
}

// PlanPath is one way a principal holds grants: the grant documents and the ceilings that bound them.
type PlanPath struct {
	Grants     []any
	Boundaries []any
}

// PlanRelation lists the relations the principal holds (directly or through a group) on one resource.
type PlanRelation struct {
	Type      string
	ID        string
	Relations []string
}

// PlanInput is what PlanResources plans. Policy documents are *PolicyDocument, PolicyDocument or model values.
type PlanInput struct {
	Action string
	// ResourceType is the type planned for; resource.type of every candidate.
	ResourceType string
	// TenantID is resource.tenantId of every candidate.
	TenantID string
	// Context holds principal, request and tenant keys (no resource keys).
	Context *Object
	// Denies are deny statements that apply across grant paths.
	Denies []any
	// Boundaries are ceilings over every path.
	Boundaries []any
	// Paths are grant paths; a resource is allowed through any one of them.
	Paths     []PlanPath
	Relations []PlanRelation
	// Mandatory (security clearances) is AND-ed with the whole plan whatever the policies allow.
	Mandatory *ResourceFilter
	// DerivedResourceKeys are resource keys the server derives per resource; statements conditioning on one refuse.
	DerivedResourceKeys []string
}

// TrueFilter is the filter every resource passes.
var TrueFilter = ResourceFilter{Kind: "true"}

// FalseFilter is the filter no resource passes.
var FalseFilter = ResourceFilter{Kind: "false"}

func filterKey(filter ResourceFilter) string { return MustStringify(filter.ToValue()) }

// orderedFilters is a Map<string, ResourceFilter> keeping insertion order.
type orderedFilters struct {
	keys  []string
	items map[string]*ResourceFilter
}

func (m *orderedFilters) set(key string, filter *ResourceFilter) {
	if m.items == nil {
		m.items = map[string]*ResourceFilter{}
	}
	if _, ok := m.items[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.items[key] = filter
}

func (m *orderedFilters) values() []ResourceFilter {
	out := make([]ResourceFilter, 0, len(m.keys))
	for _, key := range m.keys {
		out = append(out, *m.items[key])
	}
	return out
}

// AndFilter is a conjunction, simplified: nested ands flattened, true dropped, false absorbing, duplicates removed.
func AndFilter(filters []ResourceFilter) ResourceFilter {
	var kept orderedFilters
	for _, item := range filters {
		parts := []ResourceFilter{item}
		if item.Kind == "and" {
			parts = item.Filters
		}
		for _, filter := range parts {
			if filter.Kind == "false" {
				return FalseFilter
			}
			if filter.Kind == "true" {
				continue
			}
			copy := filter
			kept.set(filterKey(filter), &copy)
		}
	}
	items := kept.values()
	switch len(items) {
	case 0:
		return TrueFilter
	case 1:
		return items[0]
	}
	return ResourceFilter{Kind: "and", Filters: items}
}

// OrFilter is a disjunction, simplified: nested ors flattened, false dropped, true absorbing, duplicates removed, and
// equals on the same field (and case rule) merged into one value list.
func OrFilter(filters []ResourceFilter) ResourceFilter {
	var kept orderedFilters
	equals := map[string]*ResourceFilter{}
	for _, item := range filters {
		parts := []ResourceFilter{item}
		if item.Kind == "or" {
			parts = item.Filters
		}
		for _, filter := range parts {
			if filter.Kind == "true" {
				return TrueFilter
			}
			if filter.Kind == "false" {
				continue
			}
			if filter.Kind == "equals" {
				slot := filter.Field + "\u0000" + map[bool]string{true: "1", false: "0"}[filter.IgnoreCase]
				if merged, ok := equals[slot]; ok {
					for _, value := range filter.Values {
						found := false
						for _, existing := range merged.Values {
							if strictEquals(existing, value) {
								found = true
								break
							}
						}
						if !found {
							merged.Values = append(merged.Values, value)
						}
					}
				} else {
					copy := filter
					copy.Values = append([]any{}, filter.Values...)
					equals[slot] = &copy
					kept.set("equals:"+slot, &copy)
				}
				continue
			}
			copy := filter
			kept.set(filterKey(filter), &copy)
		}
	}
	items := kept.values()
	switch len(items) {
	case 0:
		return FalseFilter
	case 1:
		return items[0]
	}
	return ResourceFilter{Kind: "or", Filters: items}
}

// NotFilter is a negation, simplified: constants flip and a double negation cancels.
func NotFilter(filter ResourceFilter) ResourceFilter {
	switch filter.Kind {
	case "true":
		return FalseFilter
	case "false":
		return TrueFilter
	case "not":
		if filter.Filter != nil {
			return *filter.Filter
		}
	}
	copy := filter
	return ResourceFilter{Kind: "not", Filter: &copy}
}

func existsFilter(field string) ResourceFilter { return ResourceFilter{Kind: "exists", Field: field} }

func typedFilter(field, typ string) ResourceFilter {
	return ResourceFilter{Kind: "type", Field: field, Type: typ}
}

func equalsFilter(field string, values []FilterValue, ignoreCase bool) ResourceFilter {
	if len(values) == 0 {
		return FalseFilter
	}
	var unique []any
	for _, value := range values {
		if !arrayIncludes(unique, value) {
			unique = append(unique, value)
		}
	}
	return ResourceFilter{Kind: "equals", Field: field, Values: unique, IgnoreCase: ignoreCase}
}

// --- globs ---------------------------------------------------------------------------------------------------------

// constantResourceKeys are resource keys whose variables resolve the same way for every resource of a plan.
var constantResourceKeys = map[string]bool{"resource.tenantId": true, "resource.relations": true, "resource.parentRelations": true}

// rowVariable: a variable whose value is the resource's own differs from row to row.
func rowVariable(name string) bool {
	return strings.HasPrefix(name, "resource.") && !constantResourceKeys[name]
}

// hasRowVariable reports whether a pattern or condition value refers to a row-dependent variable.
func hasRowVariable(value string) bool {
	search := 0
	for {
		found := strings.Index(value[search:], variableMarker)
		if found == -1 {
			return false
		}
		index := search + found
		match := policyVariable.FindStringSubmatch(value[index:])
		if match == nil {
			search = index + len(variableMarker)
			continue
		}
		if rowVariable(match[1]) {
			return true
		}
		search = index + len(match[0])
	}
}

// planTokenize is a pattern's tokens with variables substituted from context; ok is false when unresolved. With
// rowAsStar, a row-dependent variable becomes a star: the widest pattern it could turn into.
func planTokenize(pattern string, context *Object, rowAsStar bool) ([]token, bool) {
	var tokens []token
	cursor, search := 0, 0
	for {
		found := strings.Index(pattern[search:], variableMarker)
		if found == -1 {
			break
		}
		index := search + found
		match := policyVariable.FindStringSubmatch(pattern[index:])
		if match == nil {
			search = index + len(variableMarker)
			continue
		}
		tokens = globTokens(pattern[cursor:index], tokens)
		if rowAsStar && rowVariable(match[1]) {
			tokens = append(tokens, token{kind: tokenStar})
			cursor = index + len(match[0])
			search = cursor
			continue
		}
		value, ok := scalarString(context.Get(match[1]))
		if !ok {
			return nil, false
		}
		tokens = literalTokens(value, tokens)
		cursor = index + len(match[0])
		search = cursor
	}
	tokens = globTokens(pattern[cursor:], tokens)
	return tokens, true
}

// globString is tokens as a filter glob: wildcards as * / ?, literal *, ? and \ escaped with \.
func globString(tokens []token) string {
	var b strings.Builder
	for _, t := range tokens {
		switch {
		case t.kind == tokenStar:
			b.WriteByte('*')
		case t.kind == tokenAny:
			b.WriteByte('?')
		case t.value == "*" || t.value == "?" || t.value == "\\":
			b.WriteString("\\" + t.value)
		default:
			b.WriteString(t.value)
		}
	}
	return b.String()
}

func parseGlobTokens(pattern string) []token {
	var tokens []token
	chars := CodePoints(pattern)
	for index := 0; index < len(chars); index++ {
		char := chars[index]
		switch {
		case char == "\\" && index+1 < len(chars):
			index++
			tokens = append(tokens, token{kind: tokenChar, value: chars[index]})
		case char == "*":
			tokens = append(tokens, token{kind: tokenStar})
		case char == "?":
			tokens = append(tokens, token{kind: tokenAny})
		default:
			tokens = append(tokens, token{kind: tokenChar, value: char})
		}
	}
	return tokens
}

func exportTokens(tokens []token) []GlobToken {
	out := make([]GlobToken, len(tokens))
	for index, t := range tokens {
		switch t.kind {
		case tokenStar:
			out[index] = GlobToken{Kind: "star"}
		case tokenAny:
			out[index] = GlobToken{Kind: "any"}
		default:
			out[index] = GlobToken{Kind: "char", Value: t.value}
		}
	}
	return out
}

func importTokens(tokens []GlobToken) []token {
	out := make([]token, len(tokens))
	for index, t := range tokens {
		switch t.Kind {
		case "star":
			out[index] = token{kind: tokenStar}
		case "any":
			out[index] = token{kind: tokenAny}
		default:
			out[index] = token{kind: tokenChar, value: t.Value}
		}
	}
	return out
}

// ParseGlob reads a filter glob into tokens (the inverse of the planner's glob strings).
func ParseGlob(pattern string) []GlobToken { return exportTokens(parseGlobTokens(pattern)) }

// GlobMatches is glob matching over code points, greedy with backtracking to the last star (as the engine does).
func GlobMatches(tokens []GlobToken, value string) bool {
	return matchTokens(nil, importTokens(tokens), value)
}

// globFilter is a glob filter on a field, or plain equality when the glob has no wildcard.
func globFilter(field string, tokens []token, ignoreCase bool) ResourceFilter {
	allChars, allStars := true, len(tokens) > 0
	for _, t := range tokens {
		if t.kind != tokenChar {
			allChars = false
		}
		if t.kind != tokenStar {
			allStars = false
		}
	}
	if allChars {
		var b strings.Builder
		for _, t := range tokens {
			b.WriteString(t.value)
		}
		return equalsFilter(field, []any{b.String()}, ignoreCase)
	}
	if allStars {
		return typedFilter(field, "string")
	}
	return ResourceFilter{Kind: "like", Field: field, Pattern: globString(tokens), IgnoreCase: ignoreCase}
}

// orderedStates is an insertion-ordered set of NFA states.
type orderedStates struct {
	list []int
	has  map[int]bool
}

func newStates(initial ...int) *orderedStates {
	s := &orderedStates{has: map[int]bool{}}
	for _, state := range initial {
		s.add(state)
	}
	return s
}

func (s *orderedStates) add(state int) {
	if !s.has[state] {
		s.has[state] = true
		s.list = append(s.list, state)
	}
}

// idFilter is the ids a resource pattern admits for a type: the pattern is matched against `{type}/{id}`, so after
// consuming the known `{type}/` prefix the rest of the pattern constrains the id.
func idFilter(p *planner, tokens []token, prefix string) ResourceFilter {
	closure := func(states *orderedStates) *orderedStates {
		for _, state := range append([]int(nil), states.list...) {
			at := state
			for at < len(tokens) && tokens[at].kind == tokenStar {
				at++
				states.add(at)
			}
		}
		return states
	}
	states := closure(newStates(0))
	for _, char := range CodePoints(prefix) {
		p.spend(len(states.list))
		next := newStates()
		for _, state := range states.list {
			if state >= len(tokens) {
				continue
			}
			t := tokens[state]
			if t.kind == tokenStar {
				next.add(state)
			} else if t.kind == tokenAny || t.value == char {
				next.add(state + 1)
			}
		}
		states = closure(next)
		if len(states.list) == 0 {
			return FalseFilter
		}
	}
	// Ids are nonempty strings: a residue that matches only the empty string admits none, one of stars alone all.
	options := make([]ResourceFilter, 0, len(states.list))
	for _, state := range states.list {
		rest := tokens[state:]
		p.spend(len(rest) + 1)
		if len(rest) == 0 {
			options = append(options, FalseFilter)
			continue
		}
		stars := true
		for _, t := range rest {
			if t.kind != tokenStar {
				stars = false
				break
			}
		}
		if stars {
			options = append(options, TrueFilter)
			continue
		}
		options = append(options, globFilter("id", rest, false))
	}
	return OrFilter(options)
}

// --- statements ----------------------------------------------------------------------------------------------------

// concrete evaluates one condition entry with the engine itself, for keys the context holds.
func (p *planner) concrete(operator, conditionKey string, expected any, context *Object) bool {
	statement := NewObject("effect", "allow", "actions", []any{"*"}, "resources", []any{"*"},
		"conditions", NewObject(operator, NewObject(conditionKey, expected)))
	document := NewObject("version", 1.0, "statements", []any{statement})
	decision, err := EvaluatePolicy(EvaluationInput{Action: "plan", Resource: "plan/plan", Context: context, Grants: []any{document}})
	if err != nil {
		panic(planFailure{err})
	}
	return decision.Allowed
}

func constantFilter(value bool) ResourceFilter {
	if value {
		return TrueFilter
	}
	return FalseFilter
}

// attributeCondition is a condition on a resource attribute, as a filter with the engine's semantics.
func attributeCondition(operator, field string, expected []any, context *Object) ResourceFilter {
	strs := func() []any {
		var out []any
		for _, value := range expected {
			text, ok := value.(string)
			if !ok {
				continue
			}
			if resolved, ok := ResolvePolicyValue(text, context); ok {
				out = append(out, resolved)
			}
		}
		return out
	}
	lowered := func(values []any) []any {
		out := make([]any, len(values))
		for index, value := range values {
			out[index] = JSLower(value.(string))
		}
		return out
	}
	likes := func(ignoreCase bool) []ResourceFilter {
		out := make([]ResourceFilter, 0, len(expected))
		for _, value := range expected {
			text, ok := value.(string)
			if !ok {
				out = append(out, FalseFilter)
				continue
			}
			var tokens []token
			var resolved bool
			if ignoreCase {
				tokens, resolved = planTokenize(JSLower(text), lowerCaseContext(context), false)
			} else {
				tokens, resolved = planTokenize(text, context, false)
			}
			if resolved {
				out = append(out, globFilter(field, tokens, ignoreCase))
			} else {
				out = append(out, FalseFilter)
			}
		}
		return out
	}
	var numbers []any
	for _, value := range expected {
		if _, ok := value.(float64); ok {
			numbers = append(numbers, value)
		}
	}
	switch operator {
	case "Exists":
		options := make([]ResourceFilter, 0, len(expected))
		for _, value := range expected {
			if value == true {
				options = append(options, existsFilter(field))
			} else {
				options = append(options, NotFilter(existsFilter(field)))
			}
		}
		return OrFilter(options)
	case "StringEquals":
		return equalsFilter(field, strs(), false)
	case "StringNotEquals":
		return AndFilter([]ResourceFilter{typedFilter(field, "string"), NotFilter(equalsFilter(field, strs(), false))})
	case "StringEqualsIgnoreCase":
		return equalsFilter(field, lowered(strs()), true)
	case "StringNotEqualsIgnoreCase":
		return AndFilter([]ResourceFilter{typedFilter(field, "string"), NotFilter(equalsFilter(field, lowered(strs()), true))})
	case "StringLike":
		return OrFilter(likes(false))
	case "StringNotLike":
		return AndFilter([]ResourceFilter{typedFilter(field, "string"), NotFilter(OrFilter(likes(false)))})
	case "StringLikeIgnoreCase":
		return OrFilter(likes(true))
	case "Bool":
		var booleans []any
		for _, value := range expected {
			if _, ok := value.(bool); ok {
				booleans = append(booleans, value)
			}
		}
		return equalsFilter(field, booleans, false)
	case "NumericEquals":
		return equalsFilter(field, numbers, false)
	case "NumericNotEquals":
		return AndFilter([]ResourceFilter{typedFilter(field, "number"), NotFilter(equalsFilter(field, numbers, false))})
	case "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals":
		comparison := map[string]string{"NumericLessThan": "lt", "NumericLessThanEquals": "le", "NumericGreaterThan": "gt", "NumericGreaterThanEquals": "ge"}[operator]
		options := make([]ResourceFilter, 0, len(numbers))
		for _, value := range numbers {
			options = append(options, ResourceFilter{Kind: "compare", Field: field, Operator: comparison, Value: value})
		}
		return OrFilter(options)
	case "DateBefore", "DateAfter":
		direction := "after"
		if operator == "DateBefore" {
			direction = "before"
		}
		options := make([]ResourceFilter, 0, len(expected))
		for _, value := range expected {
			if text, ok := value.(string); ok {
				options = append(options, ResourceFilter{Kind: "date", Field: field, Operator: direction, Value: text})
			} else {
				options = append(options, FalseFilter)
			}
		}
		return OrFilter(options)
	case "IpAddress", "NotIpAddress":
		options := make([]ResourceFilter, 0, len(expected))
		for _, value := range expected {
			if text, ok := value.(string); ok {
				options = append(options, ResourceFilter{Kind: "ip", Field: field, Network: text})
			} else {
				options = append(options, FalseFilter)
			}
		}
		if operator == "IpAddress" {
			return OrFilter(options)
		}
		return AndFilter([]ResourceFilter{typedFilter(field, "ip"), NotFilter(OrFilter(options))})
	case "ArrayContains", "ArrayContainsAll":
		members := make([]ResourceFilter, 0, len(expected))
		for _, value := range expected {
			wanted := value
			if text, ok := value.(string); ok {
				resolved, ok := ResolvePolicyValue(text, context)
				if !ok {
					members = append(members, FalseFilter)
					continue
				}
				wanted = resolved
			}
			members = append(members, ResourceFilter{Kind: "contains", Field: field, Value: wanted})
		}
		if operator == "ArrayContains" {
			return OrFilter(members)
		}
		return AndFilter(members)
	}
	return FalseFilter
}

type parentRef struct{ typ, id string }

type planner struct {
	input             PlanInput
	context           *Object
	idsByRelation     map[string][]string
	parentsByRelation map[string][]parentRef
	work              int
}

// PlanWorkLimit is the most work one plan may take (pattern states visited and filter atoms built); a plan that needs
// more refuses with UNSUPPORTED_FILTER.
const PlanWorkLimit = 200_000

type planFailure struct{ err error }

func (p *planner) spend(units int) {
	p.work += units
	if p.work > PlanWorkLimit {
		panic(planFailure{NewIamError("UNSUPPORTED_FILTER", "These policies are too complex to plan as a filter; check the resources with authorize")})
	}
}

// substituting are the operators whose string values substitute variables.
var substituting = map[string]bool{
	"StringEquals": true, "StringNotEquals": true, "StringEqualsIgnoreCase": true, "StringNotEqualsIgnoreCase": true,
	"StringLike": true, "StringNotLike": true, "StringLikeIgnoreCase": true, "ArrayContains": true, "ArrayContainsAll": true,
}

// relationCondition is a condition on resource.relations or resource.parentRelations.
func (p *planner) relationCondition(operator, conditionKey string, expected []any) ResourceFilter {
	context := p.context
	if operator != "ArrayContains" && operator != "ArrayContainsAll" {
		// Every other operator reads the list as a whole, and a list satisfies each one the same way whatever it holds.
		return constantFilter(p.concrete(operator, conditionKey, expected, context.Spread(NewObject(conditionKey, []any{}))))
	}
	members := make([]ResourceFilter, 0, len(expected))
	for _, value := range expected {
		wanted := value
		if text, ok := value.(string); ok {
			resolved, ok := ResolvePolicyValue(text, context)
			if !ok {
				wanted = Undefined
			} else {
				wanted = resolved
			}
		}
		name, ok := wanted.(string)
		if !ok {
			members = append(members, FalseFilter)
			continue
		}
		if conditionKey == "resource.relations" {
			ids := make([]any, 0, len(p.idsByRelation[name]))
			for _, id := range p.idsByRelation[name] {
				ids = append(ids, id)
			}
			members = append(members, equalsFilter("id", ids, false))
			continue
		}
		parents := make([]ResourceFilter, 0, len(p.parentsByRelation[name]))
		for _, parent := range p.parentsByRelation[name] {
			parents = append(parents, AndFilter([]ResourceFilter{equalsFilter("parentType", []any{parent.typ}, false), equalsFilter("parentId", []any{parent.id}, false)}))
		}
		members = append(members, OrFilter(parents))
	}
	if operator == "ArrayContains" {
		return OrFilter(members)
	}
	return AndFilter(members)
}

// withFallback: when the resource lacks an attribute, the evaluation context may still carry resource.{name}.
func withFallback(field string, present ResourceFilter, fallback *bool) ResourceFilter {
	if fallback == nil {
		return present
	}
	options := []ResourceFilter{AndFilter([]ResourceFilter{existsFilter(field), present})}
	if *fallback {
		options = append(options, NotFilter(existsFilter(field)))
	}
	return OrFilter(options)
}

func derivedKey(keys []string, key string) bool {
	for _, item := range keys {
		if item == key {
			return true
		}
	}
	return false
}

// statementFilter is when a statement matches the planned action on a resource of the planned type.
func (p *planner) statementFilter(statement compiledStatement) ResourceFilter {
	input := p.input
	matched := false
	for _, pattern := range statement.actions {
		if MatchPattern(pattern, input.Action, nil) {
			matched = true
			break
		}
	}
	if !matched {
		return FalseFilter
	}
	context := p.context
	prefix := input.ResourceType + "/"
	// A value compared with the resource's own attributes (`${resource.owner}`) differs from row to row: the planner
	// refuses rather than guess, once the statement could otherwise apply.
	rowDependent := false
	resources := make([]ResourceFilter, 0, len(statement.resources))
	for _, pattern := range statement.resources {
		if hasRowVariable(pattern) {
			if widest, ok := planTokenize(pattern, context, true); ok && idFilter(p, widest, prefix).Kind != "false" {
				rowDependent = true
			}
			resources = append(resources, FalseFilter)
			continue
		}
		if tokens, ok := planTokenize(pattern, context, false); ok {
			resources = append(resources, idFilter(p, tokens, prefix))
		} else {
			resources = append(resources, FalseFilter)
		}
	}
	resource := OrFilter(resources)
	if resource.Kind == "false" && !rowDependent {
		return FalseFilter
	}
	conditions := []ResourceFilter{resource}
	idCondition := false
	derived := ""
	for _, block := range statement.conditions {
		operator := block.operator
		for _, entry := range block.entries {
			conditionKey := entry.key
			expected := entry.values
			p.spend(len(expected))
			if substituting[operator] {
				dependent := false
				for _, value := range expected {
					if text, ok := value.(string); ok && hasRowVariable(text) {
						dependent = true
						break
					}
				}
				if dependent {
					rowDependent = true
					continue
				}
			}
			// The engine reads `resource.id` as an attribute named `id`, which a filter cannot tell from the resource's id.
			if conditionKey == "resource.id" {
				idCondition = true
				continue
			}
			// A key the server derives per resource (a classification label's) is no column of the row.
			if derivedKey(input.DerivedResourceKeys, conditionKey) {
				if derived == "" {
					derived = conditionKey
				}
				continue
			}
			var filter ResourceFilter
			switch {
			case conditionKey == "resource.tenantId":
				filter = constantFilter(p.concrete(operator, conditionKey, entry.expected, context))
			case conditionKey == "resource.relations" || conditionKey == "resource.parentRelations":
				filter = p.relationCondition(operator, conditionKey, expected)
			case strings.HasPrefix(conditionKey, "resource."):
				field := strings.TrimPrefix(conditionKey, "resource.")
				var fallback *bool
				if inherited := input.Context.Get(conditionKey); !IsUndefined(inherited) {
					value := p.concrete(operator, conditionKey, entry.expected, context)
					fallback = &value
				}
				filter = withFallback(field, attributeCondition(operator, field, expected, context), fallback)
			default:
				filter = constantFilter(p.concrete(operator, conditionKey, entry.expected, context))
			}
			if filter.Kind == "false" {
				return FalseFilter
			}
			conditions = append(conditions, filter)
		}
	}
	if rowDependent {
		panic(planFailure{NewIamError("UNSUPPORTED_FILTER", "A policy compares a value with ${resource.…}, one of the resource’s own attributes, which a filter cannot express; check the resources with authorize")})
	}
	if idCondition {
		panic(planFailure{NewIamError("UNSUPPORTED_FILTER", "A policy has a condition on resource.id, which names an attribute called id rather than the resource’s id (match ids with the statement’s resources); check the resources with authorize")})
	}
	if derived != "" {
		panic(planFailure{NewIamError("UNSUPPORTED_FILTER", "A policy has a condition on "+derived+", which the server derives for each resource rather than reading from the row; check the resources with authorize")})
	}
	return AndFilter(conditions)
}

// anyStatement is the resources some statement of `effect` in the documents matches.
func (p *planner) anyStatement(documents []compiledDocument, effect string) ResourceFilter {
	var options []ResourceFilter
	for _, document := range documents {
		for _, statement := range document.statements {
			if statement.effect == effect {
				options = append(options, p.statementFilter(statement))
			}
		}
	}
	return OrFilter(options)
}

// everyBoundary is the resources every document lets through: each has a matching allow statement.
func (p *planner) everyBoundary(documents []compiledDocument) ResourceFilter {
	options := make([]ResourceFilter, 0, len(documents))
	for _, document := range documents {
		options = append(options, p.anyStatement([]compiledDocument{document}, "allow"))
	}
	return AndFilter(options)
}

func compileAll(documents []any) []compiledDocument {
	out := make([]compiledDocument, 0, len(documents))
	for _, document := range documents {
		out = append(out, compilePolicy(PolicyValue(document).(*Object)))
	}
	return out
}

// PlanResources plans the resources of ResourceType the principal may perform Action on. The result mirrors the
// decision the server makes for each resource: no deny statement applies (across every grant path and ceiling), every
// ceiling lets the resource through, and some grant path allows it within its own ceilings.
func PlanResources(input PlanInput) (plan ResourcePlan, err error) {
	all := append(append([]any{}, input.Denies...), input.Boundaries...)
	for _, path := range input.Paths {
		all = append(all, path.Grants...)
		all = append(all, path.Boundaries...)
	}
	for _, document := range all {
		if err := ValidatePolicy(document); err != nil {
			return ResourcePlan{}, err
		}
	}
	if input.ResourceType == "" || strings.Contains(input.ResourceType, "/") {
		return ResourcePlan{}, NewIamError("INVALID_INPUT", "Invalid resource type")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if failure, ok := recovered.(planFailure); ok {
				plan, err = ResourcePlan{}, failure.err
				return
			}
			panic(recovered)
		}
	}()
	idsByRelation := map[string][]string{}
	parentsByRelation := map[string][]parentRef{}
	for _, tuple := range input.Relations {
		for _, relation := range tuple.Relations {
			if tuple.Type == input.ResourceType {
				idsByRelation[relation] = append(idsByRelation[relation], tuple.ID)
			}
			parentsByRelation[relation] = append(parentsByRelation[relation], parentRef{tuple.Type, tuple.ID})
		}
	}
	base := input.Context
	if base == nil {
		base = NewObject()
	}
	p := &planner{
		input:             input,
		context:           base.Spread(NewObject("resource.tenantId", input.TenantID, "resource.relations", []any{}, "resource.parentRelations", []any{})),
		idsByRelation:     idsByRelation,
		parentsByRelation: parentsByRelation,
	}
	denies := compileAll(input.Denies)
	boundaries := compileAll(input.Boundaries)
	var filters []ResourceFilter
	// Mandatory access control first: whatever the policies say, nothing above the principal's clearance.
	if input.Mandatory != nil {
		filters = append(filters, *input.Mandatory)
	}
	filters = append(filters, NotFilter(p.anyStatement(append(append([]compiledDocument{}, denies...), boundaries...), "deny")))
	filters = append(filters, p.everyBoundary(boundaries))
	paths := make([]ResourceFilter, 0, len(input.Paths))
	for _, path := range input.Paths {
		grants := compileAll(path.Grants)
		ceilings := compileAll(path.Boundaries)
		paths = append(paths, AndFilter([]ResourceFilter{
			NotFilter(p.anyStatement(append(append([]compiledDocument{}, grants...), ceilings...), "deny")),
			p.anyStatement(grants, "allow"),
			p.everyBoundary(ceilings),
		}))
	}
	filters = append(filters, OrFilter(paths))
	filter := AndFilter(filters)
	return ResourcePlan{Kind: planKind(filter), Filter: filter}, nil
}

func planKind(filter ResourceFilter) string {
	switch filter.Kind {
	case "true":
		return "always"
	case "false":
		return "never"
	}
	return "conditional"
}

// FixedPlan is a plan that allows everything or nothing (root override, a fixed refusal).
func FixedPlan(allowed bool) ResourcePlan {
	if allowed {
		return ResourcePlan{Kind: "always", Filter: TrueFilter}
	}
	return ResourcePlan{Kind: "never", Filter: FalseFilter}
}

// IntersectPlans is both plans at once: what each allows.
func IntersectPlans(left, right ResourcePlan) ResourcePlan {
	filter := AndFilter([]ResourceFilter{left.Filter, right.Filter})
	return ResourcePlan{Kind: planKind(filter), Filter: filter}
}
