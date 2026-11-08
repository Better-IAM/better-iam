package scim

// Port of packages/scim/src/filter.ts: RFC 7644 §3.4.2.2 filters (`and`/`or`/`not(...)`, grouping, value paths such as
// `emails[type eq "work"]`, sub-attributes, schema-qualified names, and `eq ne co sw ew pr gt ge lt le`), sorting
// (§3.4.2.3) and attribute projection (§3.4.2.5). The grammar is bounded (length, depth, comparison count); anything
// outside it receives invalidFilter, never an unfiltered result.

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// FilterNode is a parsed filter: Kind is "and" / "or" (Left, Right), "not" (Node), "compare" (Path, Op, Value; Value
// is core.Undefined for `pr`) or "valuePath" (Path, Filter).
type FilterNode struct {
	Kind   string
	Left   *FilterNode
	Right  *FilterNode
	Node   *FilterNode
	Path   []string
	Op     string
	Value  any
	Filter *FilterNode
}

// ToValue renders the node as the TypeScript FilterNode object.
func (n *FilterNode) ToValue() *core.Object {
	switch n.Kind {
	case "and", "or":
		return core.NewObject("kind", n.Kind, "left", n.Left.ToValue(), "right", n.Right.ToValue())
	case "not":
		return core.NewObject("kind", n.Kind, "node", n.Node.ToValue())
	case "valuePath":
		return core.NewObject("kind", n.Kind, "path", stringList(n.Path), "filter", n.Filter.ToValue())
	}
	out := core.NewObject("kind", n.Kind, "path", stringList(n.Path), "op", n.Op)
	if !core.IsUndefined(n.Value) {
		out.SetRaw("value", n.Value)
	}
	return out
}

const (
	maxFilterLength = 2048
	maxDepth        = 16
	maxComparisons  = 64
)

var filterOperators = map[string]bool{"eq": true, "ne": true, "co": true, "sw": true, "ew": true, "pr": true, "gt": true, "ge": true, "lt": true, "le": true}

// caseExactPaths are the case-exact attributes: identifiers compare byte-for-byte, everything else case-insensitively.
var caseExactPaths = map[string]bool{"id": true, "externalid": true, "members.value": true}

var booleanAttributes = map[string]bool{"active": true, "primary": true}

func invalidFilter(message string) error { return core.NewIamError("invalidFilter", message) }

type filterToken struct {
	kind  string // word, string, (, ), [, ]
	value string
}

func isWordUnit(u uint16) bool {
	return u >= 'A' && u <= 'Z' || u >= 'a' && u <= 'z' || u >= '0' && u <= '9' || u == '_' || u == ':' || u == '.' || u == '$' || u == '+' || u == '-'
}

func isLineTerminator(u uint16) bool { return u == '\n' || u == '\r' || u == 0x2028 || u == 0x2029 }

func tokenize(input string) ([]filterToken, error) {
	units := core.ToUTF16(input)
	var tokens []filterToken
	index := 0
	for index < len(units) {
		char := units[index]
		if jsSpace(rune(char)) {
			index++
			continue
		}
		if char == '(' || char == ')' || char == '[' || char == ']' {
			tokens = append(tokens, filterToken{kind: string(rune(char)), value: string(rune(char))})
			index++
			continue
		}
		if char == '"' {
			end := -1
			for j := index + 1; j < len(units); {
				if units[j] == '"' {
					end = j
					break
				}
				if units[j] == '\\' {
					if j+1 >= len(units) || isLineTerminator(units[j+1]) {
						break
					}
					j += 2
					continue
				}
				j++
			}
			if end < 0 {
				return nil, invalidFilter("Unterminated string in filter.")
			}
			tokens = append(tokens, filterToken{kind: "string", value: core.FromUTF16(units[index : end+1])})
			index = end + 1
			continue
		}
		end := index
		for end < len(units) && isWordUnit(units[end]) {
			end++
		}
		if end == index {
			return nil, invalidFilter(`Unexpected character "` + core.FromUTF16(units[index:index+1]) + `" in filter.`)
		}
		tokens = append(tokens, filterToken{kind: "word", value: core.FromUTF16(units[index:end])})
		index = end
	}
	return tokens, nil
}

var segmentPattern = regexp.MustCompile(`^[a-z$][a-z0-9_$-]*$`)

// AttributePath splits a (possibly schema-qualified) attribute path into lowercase segments; the enterprise extension
// is one key.
func AttributePath(raw string) ([]string, error) {
	lower := core.JSLower(raw)
	for _, schema := range []string{EnterpriseSchema, UserSchema, GroupSchema} {
		prefix := core.JSLower(schema) + ":"
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		rest := sliceUTF16(raw, utf16Len(prefix), utf16Len(raw))
		if rest == "" {
			return nil, invalidFilter("Attribute name is missing after the schema URN.")
		}
		segments, err := AttributePath(rest)
		if err != nil {
			return nil, err
		}
		if schema == EnterpriseSchema {
			return append([]string{enterpriseLower}, segments...), nil
		}
		return segments, nil
	}
	if lower == enterpriseLower {
		return []string{lower}, nil
	}
	if strings.HasPrefix(lower, "urn:") {
		return nil, invalidFilter("Unsupported schema URN.")
	}
	segments := strings.Split(lower, ".")
	invalid := len(segments) > 3
	for _, segment := range segments {
		if !segmentPattern.MatchString(segment) {
			invalid = true
		}
	}
	if invalid {
		return nil, invalidFilter(`Invalid attribute path "` + raw + `".`)
	}
	return segments, nil
}

type filterParser struct {
	tokens      []filterToken
	position    int
	comparisons int
}

func (p *filterParser) parse() (*FilterNode, error) {
	node, err := p.or(0)
	if err != nil {
		return nil, err
	}
	if p.position != len(p.tokens) {
		return nil, invalidFilter("Unexpected trailing filter content.")
	}
	return node, nil
}

func (p *filterParser) peek() *filterToken {
	if p.position < len(p.tokens) {
		return &p.tokens[p.position]
	}
	return nil
}

func (p *filterParser) keyword(word string) bool {
	token := p.peek()
	if token != nil && token.kind == "word" && core.JSLower(token.value) == word {
		p.position++
		return true
	}
	return false
}

func (p *filterParser) expect(kind string) (*filterToken, error) {
	var token *filterToken
	if p.position < len(p.tokens) {
		token = &p.tokens[p.position]
	}
	p.position++
	if token == nil || token.kind != kind {
		return nil, invalidFilter(`Expected "` + kind + `" in filter.`)
	}
	return token, nil
}

func (p *filterParser) or(depth int) (*FilterNode, error) {
	node, err := p.and(depth)
	if err != nil {
		return nil, err
	}
	for p.keyword("or") {
		right, err := p.and(depth)
		if err != nil {
			return nil, err
		}
		node = &FilterNode{Kind: "or", Left: node, Right: right}
	}
	return node, nil
}

func (p *filterParser) and(depth int) (*FilterNode, error) {
	node, err := p.unary(depth)
	if err != nil {
		return nil, err
	}
	for p.keyword("and") {
		right, err := p.unary(depth)
		if err != nil {
			return nil, err
		}
		node = &FilterNode{Kind: "and", Left: node, Right: right}
	}
	return node, nil
}

func (p *filterParser) unary(depth int) (*FilterNode, error) {
	if depth > maxDepth {
		return nil, invalidFilter("Filter is nested too deeply.")
	}
	token := p.peek()
	if token != nil && token.kind == "word" && core.JSLower(token.value) == "not" {
		if p.position+1 < len(p.tokens) && p.tokens[p.position+1].kind == "(" {
			p.position += 2
			node, err := p.or(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(")"); err != nil {
				return nil, err
			}
			return &FilterNode{Kind: "not", Node: node}, nil
		}
	}
	if token != nil && token.kind == "(" {
		p.position++
		node, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(")"); err != nil {
			return nil, err
		}
		return node, nil
	}
	return p.comparison(depth)
}

func (p *filterParser) comparison(depth int) (*FilterNode, error) {
	attribute, err := p.expect("word")
	if err != nil {
		return nil, err
	}
	path, err := AttributePath(attribute.value)
	if err != nil {
		return nil, err
	}
	if next := p.peek(); next != nil && next.kind == "[" {
		p.position++
		filter, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if _, err := p.expect("]"); err != nil {
			return nil, err
		}
		return &FilterNode{Kind: "valuePath", Path: path, Filter: filter}, nil
	}
	p.comparisons++
	if p.comparisons > maxComparisons {
		return nil, invalidFilter("Filter has too many comparisons.")
	}
	operatorToken, err := p.expect("word")
	if err != nil {
		return nil, err
	}
	operator := core.JSLower(operatorToken.value)
	if !filterOperators[operator] {
		return nil, invalidFilter(`Unsupported filter operator "` + operator + `".`)
	}
	if operator == "pr" {
		return &FilterNode{Kind: "compare", Path: path, Op: operator, Value: core.Undefined}, nil
	}
	var token *filterToken
	if p.position < len(p.tokens) {
		token = &p.tokens[p.position]
	}
	p.position++
	if token == nil || (token.kind != "string" && token.kind != "word") {
		return nil, invalidFilter("Filter comparison is missing a value.")
	}
	source := token.value
	if token.kind == "word" {
		source = core.JSLower(token.value)
	}
	value, parseErr := core.ParseJSONString(source)
	if parseErr != nil {
		return nil, invalidFilter("Invalid filter value " + token.value + ".")
	}
	switch value.(type) {
	case *core.Object, []any:
		return nil, invalidFilter("Filter values must be strings, numbers, booleans or null.")
	}
	leaf := path[len(path)-1]
	_, isBool := value.(bool)
	if booleanAttributes[leaf] && !isBool && value != nil {
		return nil, invalidFilter(leaf + " requires a boolean comparison.")
	}
	if isBool && operator != "eq" && operator != "ne" {
		return nil, invalidFilter("Booleans support only eq and ne.")
	}
	if _, isString := value.(string); (operator == "co" || operator == "sw" || operator == "ew") && !isString {
		return nil, invalidFilter(operator + " requires a string value.")
	}
	return &FilterNode{Kind: "compare", Path: path, Op: operator, Value: value}, nil
}

// ParseFilterExpression parses a filter.
func ParseFilterExpression(filter string) (*FilterNode, error) {
	if utf16Len(filter) > maxFilterLength {
		return nil, invalidFilter("Filter is too long.")
	}
	tokens, err := tokenize(filter)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, invalidFilter("Filter is empty.")
	}
	return (&filterParser{tokens: tokens}).parse()
}

// property is the case-insensitive property lookup (SCIM attribute names are case-insensitive): an own member named
// key, else (as `key in record` does) the inherited `constructor`, else the first own member whose lowercase name is
// key.
func property(value any, key string) any {
	record, ok := value.(*core.Object)
	if !ok || record == nil {
		return core.Undefined
	}
	if found, own := record.Lookup(key); own {
		return found
	}
	if key == "constructor" {
		return jsFunction{}
	}
	for _, name := range record.Keys() {
		if core.JSLower(name) == key {
			return record.Get(name)
		}
	}
	return core.Undefined
}

// flat1 is `[value].flat()`.
func flat1(value any) []any {
	if list, ok := value.([]any); ok {
		return list
	}
	return []any{value}
}

// resolve answers all leaf values at a path; multi-valued attributes fan out and a complex value compares by its
// `value`.
func resolve(value any, path []string) []any {
	current := []any{value}
	for _, segment := range path {
		var next []any
		for _, item := range current {
			for _, child := range flat1(property(item, segment)) {
				if !nullish(child) {
					next = append(next, child)
				}
			}
		}
		current = next
	}
	out := make([]any, len(current))
	for index, item := range current {
		if isObject(item) {
			out[index] = property(item, "value")
		} else {
			out[index] = item
		}
	}
	return out
}

// strictEqual is `===` over the model.
func strictEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case core.UndefinedType:
		return core.IsUndefined(b)
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case *core.Object:
		y, ok := b.(*core.Object)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		return ok && len(x) > 0 && len(y) > 0 && &x[0] == &y[0]
	case jsFunction:
		_, ok := b.(jsFunction)
		return ok
	}
	return false
}

// unitsIndex is String.prototype.indexOf over UTF-16 units.
func unitsIndex(haystack, needle []uint16) int {
	for start := 0; start+len(needle) <= len(haystack); start++ {
		match := true
		for offset := range needle {
			if haystack[start+offset] != needle[offset] {
				match = false
				break
			}
		}
		if match {
			return start
		}
	}
	return -1
}

func compareValue(actual any, op string, expected any, caseExact bool) bool {
	if nullish(actual) {
		return op == "ne" && expected != nil
	}
	normalize := func(item any) any {
		if text, ok := item.(string); ok && !caseExact {
			return core.JSLower(text)
		}
		return item
	}
	left := normalize(actual)
	right := normalize(expected)
	switch op {
	case "eq":
		return strictEqual(left, right)
	case "ne":
		return !strictEqual(left, right)
	case "co", "sw", "ew":
		text, ok := left.(string)
		if !ok {
			return false
		}
		needle, _ := right.(string)
		x, y := core.ToUTF16(text), core.ToUTF16(needle)
		switch op {
		case "co":
			return unitsIndex(x, y) >= 0
		case "sw":
			return len(y) <= len(x) && unitsIndex(x[:len(y)], y) == 0
		default:
			return len(y) <= len(x) && unitsIndex(x[len(x)-len(y):], y) == 0
		}
	}
	if typeOf(left) != typeOf(right) || (typeOf(left) != "string" && typeOf(left) != "number") {
		return false
	}
	var order int
	if a, ok := left.(string); ok {
		order = compareUTF16(a, right.(string))
	} else {
		a, b := left.(float64), right.(float64)
		switch {
		case a < b:
			order = -1
		case a > b:
			order = 1
		case a == b:
			order = 0
		default:
			return false
		}
	}
	switch op {
	case "gt":
		return order > 0
	case "ge":
		return order >= 0
	case "lt":
		return order < 0
	}
	return order <= 0
}

// EvaluateFilter evaluates a parsed filter against a rendered resource; prefix is the path of the multi-valued
// attribute a value filter is evaluated inside.
func EvaluateFilter(node *FilterNode, value any, prefix []string) bool {
	switch node.Kind {
	case "and":
		return EvaluateFilter(node.Left, value, prefix) && EvaluateFilter(node.Right, value, prefix)
	case "or":
		return EvaluateFilter(node.Left, value, prefix) || EvaluateFilter(node.Right, value, prefix)
	case "not":
		return !EvaluateFilter(node.Node, value, prefix)
	case "valuePath":
		items := []any{value}
		for _, segment := range node.Path {
			var next []any
			for _, item := range items {
				for _, child := range flat1(property(item, segment)) {
					if truthy(child) {
						next = append(next, child)
					}
				}
			}
			items = next
		}
		inner := append(append([]string{}, prefix...), node.Path...)
		for _, item := range items {
			if EvaluateFilter(node.Filter, item, inner) {
				return true
			}
		}
		return false
	}
	caseExact := caseExactPaths[strings.Join(append(append([]string{}, prefix...), node.Path...), ".")]
	if node.Op == "pr" {
		items := []any{value}
		for _, segment := range node.Path {
			var next []any
			for _, item := range items {
				next = append(next, flat1(property(item, segment))...)
			}
			items = next
		}
		for _, item := range items {
			if nullish(item) || item == "" {
				continue
			}
			if list, ok := item.([]any); ok && len(list) == 0 {
				continue
			}
			return true
		}
		return false
	}
	values := resolve(value, node.Path)
	if len(values) == 0 {
		return compareValue(core.Undefined, node.Op, node.Value, caseExact)
	}
	if node.Op == "ne" {
		for _, item := range values {
			if !compareValue(item, "ne", node.Value, caseExact) {
				return false
			}
		}
		return true
	}
	for _, item := range values {
		if compareValue(item, node.Op, node.Value, caseExact) {
			return true
		}
	}
	return false
}

// ParseScimFilter parses a filter into a predicate over rendered SCIM resources; an absent filter ("") matches
// everything.
func ParseScimFilter(filter string) (func(value *core.Object) bool, error) {
	if filter == "" {
		return func(*core.Object) bool { return true }, nil
	}
	node, err := ParseFilterExpression(filter)
	if err != nil {
		return nil, err
	}
	return func(value *core.Object) bool { return EvaluateFilter(node, value, nil) }, nil
}

// sortKey is a sort key per RFC 7644 §3.4.2.3: multi-valued attributes sort by their primary (or first) value.
func sortKey(resource any, path []string) any {
	current := resource
	for _, segment := range path {
		next := property(current, segment)
		if list, ok := next.([]any); ok {
			next = core.Undefined
			found := false
			for _, item := range list {
				if property(item, "primary") == true {
					next = item
					found = true
					break
				}
			}
			if !found && len(list) > 0 {
				next = list[0]
			}
		}
		current = next
	}
	switch current.(type) {
	case *core.Object, []any:
		if truthy(current) {
			current = property(current, "value")
		}
	}
	if text, ok := current.(string); ok {
		return core.JSLower(text)
	}
	return current
}

// SortResources sorts rendered resources by sortBy (ascending unless sortOrder is "descending"); "" sortBy keeps the
// order. sortOrder "" means absent.
func SortResources(resources []*core.Object, sortBy, sortOrder string) ([]*core.Object, error) {
	if sortBy == "" {
		return resources, nil
	}
	order := "ascending"
	if sortOrder != "" {
		order = core.JSLower(sortOrder)
	}
	if order != "ascending" && order != "descending" {
		return nil, core.NewIamError("invalidValue", "sortOrder must be ascending or descending.")
	}
	path, err := AttributePath(sortBy)
	if err != nil {
		return nil, err
	}
	direction := 1
	if order == "descending" {
		direction = -1
	}
	type row struct {
		resource *core.Object
		key      any
	}
	rows := make([]row, len(resources))
	for index, resource := range resources {
		rows[index] = row{resource: resource, key: sortKey(resource, path)}
	}
	compare := func(a, b row) int {
		// Unassigned values sort last in either direction.
		if nullish(a.key) {
			if nullish(b.key) {
				return 0
			}
			return 1
		}
		if nullish(b.key) {
			return -1
		}
		result := 0
		if jsLess(a.key, b.key) {
			result = -1
		} else if jsLess(b.key, a.key) {
			result = 1
		}
		return result * direction
	}
	sort.SliceStable(rows, func(i, j int) bool { return compare(rows[i], rows[j]) < 0 })
	out := make([]*core.Object, len(rows))
	for index, item := range rows {
		out[index] = item.resource
	}
	return out, nil
}

// ownMatch is the first own member name whose lowercase form is key, else key.
func ownMatch(resource *core.Object, key string) string {
	for _, name := range resource.Keys() {
		if core.JSLower(name) == key {
			return name
		}
	}
	return key
}

// ProjectResource applies attribute projection (§3.4.2.5); `id` and `schemas` are always returned. A nil list is
// absent.
func ProjectResource(resource *core.Object, attributes, excluded []string) (*core.Object, error) {
	if len(attributes) > 0 && len(excluded) > 0 {
		return nil, core.NewIamError("invalidValue", "attributes and excludedAttributes are mutually exclusive.")
	}
	always := map[string]bool{"id": true, "schemas": true}
	if len(attributes) > 0 {
		result := core.NewObject()
		result.SetRaw("schemas", resource.Get("schemas"))
		result.SetRaw("id", resource.Get("id"))
		for _, raw := range attributes {
			path, err := AttributePath(raw)
			if err != nil {
				return nil, err
			}
			top, rest := path[0], path[1:]
			key := ownMatch(resource, top)
			value, own := resource.Lookup(key)
			inherited := !own && key == "constructor"
			if inherited {
				value = jsFunction{}
			}
			if core.IsUndefined(value) || always[key] {
				continue
			}
			if len(rest) == 0 {
				if inherited {
					// Object itself: JSON.stringify omits it, as it omits undefined.
					result.SetRaw(key, core.Undefined)
				} else {
					result.SetRaw(key, value)
				}
				continue
			}
			pick := func(item any) *core.Object {
				picked := core.NewObject()
				source := item
				target := picked
				for index, segment := range rest {
					name := segment
					if record, ok := source.(*core.Object); ok && record != nil {
						name = ownMatch(record, segment)
					}
					child := property(source, segment)
					if core.IsUndefined(child) {
						continue
					}
					if index == len(rest)-1 {
						if _, isFunction := child.(jsFunction); isFunction {
							target.SetRaw(name, core.Undefined)
						} else {
							target.SetRaw(name, child)
						}
					} else {
						next := core.NewObject()
						target.SetRaw(name, next)
						target = next
						source = child
					}
				}
				return picked
			}
			var projected any
			if list, ok := value.([]any); ok {
				items := make([]any, len(list))
				for index, item := range list {
					items[index] = pick(item)
				}
				projected = items
			} else {
				projected = pick(value)
			}
			if existing, ok := result.Get(key).(*core.Object); ok && existing != nil {
				if picked, isObject := projected.(*core.Object); isObject {
					result.SetRaw(key, existing.Spread(picked))
				} else {
					merged := existing.Spread()
					for index, item := range projected.([]any) {
						merged.SetRaw(core.NumberString(float64(index)), item)
					}
					result.SetRaw(key, merged)
				}
			} else {
				result.SetRaw(key, projected)
			}
		}
		return result, nil
	}
	if len(excluded) > 0 {
		result := resource.Clone()
		for _, raw := range excluded {
			path, err := AttributePath(raw)
			if err != nil {
				return nil, err
			}
			top, rest := path[0], path[1:]
			key := ownMatch(resource, top)
			if always[key] {
				continue
			}
			if len(rest) == 0 {
				result.Delete(key)
				continue
			}
			for _, item := range flat1(result.Get(key)) {
				if !truthy(item) || typeOf(item) != "object" {
					continue
				}
				leaf := rest[len(rest)-1]
				parent := item
				for _, segment := range rest[:len(rest)-1] {
					parent = property(parent, segment)
				}
				if record, ok := parent.(*core.Object); ok && record != nil {
					for _, name := range record.Keys() {
						if core.JSLower(name) == leaf {
							record.Delete(name)
							break
						}
					}
				}
			}
		}
		return result, nil
	}
	return resource, nil
}

// AttributeList splits a comma-separated `attributes` / `excludedAttributes` value (a string or a list); ok is false
// when the value is absent (undefined, null or "").
func AttributeList(value any) (list []string, ok bool, err error) {
	if nullish(value) || value == "" {
		return nil, false, nil
	}
	var items []any
	if array, isArray := value.([]any); isArray {
		items = array
	} else {
		for _, part := range strings.Split(jsString(value), ",") {
			items = append(items, part)
		}
	}
	if len(items) > 50 {
		return nil, false, core.NewIamError("invalidValue", "Attribute lists hold at most 50 attribute names.")
	}
	for _, item := range items {
		if _, isString := item.(string); !isString {
			return nil, false, core.NewIamError("invalidValue", "Attribute lists hold at most 50 attribute names.")
		}
	}
	list = []string{}
	for _, item := range items {
		if trimmed := core.JSTrim(item.(string)); trimmed != "" {
			list = append(list, trimmed)
		}
	}
	return list, true, nil
}
