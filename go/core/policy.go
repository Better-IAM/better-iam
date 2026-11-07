package core

import (
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ConditionOperator names a policy condition operator.
type ConditionOperator = string

// PolicyStatement is one statement of a policy document. Conditions maps operator names to objects of context keys
// and expected values (a string, number or boolean, or a list of them); its key order is kept.
type PolicyStatement struct {
	Sid        string   `json:"sid,omitempty"`
	Effect     string   `json:"effect"`
	Actions    []string `json:"actions"`
	Resources  []string `json:"resources"`
	Conditions *Object  `json:"conditions,omitempty"`
}

// PolicyDocument is a version 1 policy document.
type PolicyDocument struct {
	Version    int               `json:"version"`
	Statements []PolicyStatement `json:"statements"`
}

// EvaluationRequest is an action on a resource with its trusted context.
type EvaluationRequest struct {
	Action   string
	Resource string
	// Context holds the trusted context keys (principal.*, request.*, resource.*); nil is undefined.
	Context *Object
}

// EvaluationInput is what EvaluatePolicy evaluates. Grants and Boundaries hold policy documents as *PolicyDocument,
// PolicyDocument or model values (*Object); each is validated before evaluation. A nil Boundaries is undefined.
type EvaluationInput struct {
	Action     string
	Resource   string
	Context    *Object
	Grants     []any
	Boundaries []any
}

// Decision is the result of EvaluatePolicy.
type Decision struct {
	Allowed bool     `json:"allowed"`
	Reason  string   `json:"reason"`
	Matched []string `json:"matched"`
}

var policyOperators = []ConditionOperator{
	"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase", "StringLike",
	"StringNotLike", "StringLikeIgnoreCase", "Bool", "NumericEquals", "NumericNotEquals", "NumericLessThan",
	"NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals", "DateBefore", "DateAfter", "IpAddress",
	"NotIpAddress", "ArrayContains", "ArrayContainsAll", "Exists",
}

func knownOperator(name string) bool {
	for _, operator := range policyOperators {
		if operator == name {
			return true
		}
	}
	return false
}

// negatedOperators succeed only when the actual value differs from every listed value; every other operator succeeds
// when any listed value matches. ArrayContainsAll requires every listed value to be present.
var negatedOperators = map[string]bool{
	"StringNotEquals": true, "StringNotEqualsIgnoreCase": true, "StringNotLike": true, "NumericNotEquals": true,
	"NotIpAddress": true,
}

func everyValue(operator string) bool {
	return negatedOperators[operator] || operator == "ArrayContainsAll"
}

var unsafeKeys = map[string]bool{"__proto__": true, "prototype": true, "constructor": true}

func invalidPolicy(message string) error { return NewIamError("INVALID_POLICY", message) }

func hasControlOrDel(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return true
		}
	}
	return false
}

// nonempty is a string of 1 to max UTF-16 code units without control characters.
func nonempty(value any, max int) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	length := UTF16Len(text)
	return length > 0 && length <= max && !hasControlOrDel(text)
}

func onlyKeys(value *Object, allowed ...string) bool {
	for _, key := range value.keys {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Policy variables: `${principal.id}` inside a resource pattern or a string condition value is replaced with the
// trusted context value of that key before matching. Substituted values always match literally. An unresolved
// variable never matches.
var policyVariable = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_.:-]{0,127})\}`)

const variableMarker = "${"

type tokenKind uint8

const (
	tokenChar tokenKind = iota
	tokenStar
	tokenAny
)

// GlobToken is one element of a glob: a star, a single-character wildcard, or a literal character (code point).
type GlobToken struct {
	Kind  string `json:"kind"` // star, any or char
	Value string `json:"value,omitempty"`
}

type token struct {
	kind  tokenKind
	value string
}

func globTokens(pattern string, into []token) []token {
	for _, char := range CodePoints(pattern) {
		switch char {
		case "*":
			into = append(into, token{kind: tokenStar})
		case "?":
			into = append(into, token{kind: tokenAny})
		default:
			into = append(into, token{kind: tokenChar, value: char})
		}
	}
	return into
}

func literalTokens(value string, into []token) []token {
	for _, char := range CodePoints(value) {
		into = append(into, token{kind: tokenChar, value: char})
	}
	return into
}

// scalarString is String(value) for a string, number or boolean; ok is false for any other value.
func scalarString(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case float64:
		return NumberString(v), true
	case bool:
		if v {
			return "true", true
		}
		return "false", true
	}
	return "", false
}

// tokenize splits a pattern into wildcard and literal tokens, substituting variables from context; ok is false when a
// variable is unresolved.
func tokenize(pattern string, context *Object) ([]token, bool) {
	var tokens []token
	cursor, search := 0, 0
	for {
		found := strings.Index(pattern[search:], variableMarker)
		if found == -1 {
			break
		}
		index := search + found
		match := policyVariable.FindStringSubmatch(pattern[index:])
		// A malformed reference is rejected by validation; at evaluation it is treated as literal text.
		if match == nil {
			search = index + len(variableMarker)
			continue
		}
		tokens = globTokens(pattern[cursor:index], tokens)
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

// budget is the work left in a running evaluation, in characters examined (roughly). evaluatePolicy sets it; matching
// outside an evaluation is unbounded (nil).
type budget struct{ left float64 }

const evaluationWork = 4_000_000

type evaluationLimit struct{}

func (b *budget) spend(units int) {
	if b == nil {
		return
	}
	b.left -= float64(units)
	if b.left < 0 {
		panic(evaluationLimit{})
	}
}

func matchTokens(b *budget, tokens []token, value string) bool {
	// Greedy wildcard matching avoids catastrophic regular-expression backtracking.
	chars := CodePoints(value)
	b.spend(len(chars) + len(tokens))
	p, v, star, retry := 0, 0, -1, 0
	for v < len(chars) {
		b.spend(1)
		if p < len(tokens) && (tokens[p].kind == tokenAny || (tokens[p].kind == tokenChar && tokens[p].value == chars[v])) {
			p++
			v++
		} else if p < len(tokens) && tokens[p].kind == tokenStar {
			star = p
			p++
			retry = v
		} else if star != -1 {
			p = star + 1
			retry++
			v = retry
		} else {
			return false
		}
	}
	for p < len(tokens) && tokens[p].kind == tokenStar {
		p++
	}
	return p == len(tokens)
}

// ValidPolicyVariables reports whether every `${...}` in a value is a well-formed variable reference.
func ValidPolicyVariables(value string) bool {
	for index := strings.Index(value, variableMarker); index != -1; {
		match := policyVariable.FindString(value[index:])
		if match == "" {
			return false
		}
		next := strings.Index(value[index+len(match):], variableMarker)
		if next == -1 {
			break
		}
		index = index + len(match) + next
	}
	return true
}

// ResolvePolicyValue resolves the variables of a string condition value; ok is false when any variable is
// unresolved.
func ResolvePolicyValue(value string, context *Object) (string, bool) {
	if !strings.Contains(value, variableMarker) {
		return value, true
	}
	tokens, ok := tokenize(value, context)
	if !ok {
		return "", false
	}
	var b strings.Builder
	for _, t := range tokens {
		switch t.kind {
		case tokenStar:
			b.WriteByte('*')
		case tokenAny:
			b.WriteByte('?')
		default:
			b.WriteString(t.value)
		}
	}
	return b.String(), true
}

// MatchPattern is anchored glob matching; only * and ? are operators and variables resolve from context (nil for
// none).
func MatchPattern(pattern, value string, context *Object) bool {
	return matchPattern(nil, pattern, value, context)
}

func matchPattern(b *budget, pattern, value string, context *Object) bool {
	if strings.Contains(pattern, variableMarker) {
		tokens, ok := tokenize(pattern, context)
		return ok && matchTokens(b, tokens, value)
	}
	// `?` is one character (code point) on every path; astral characters take the token path, which counts them so.
	if strings.Contains(pattern, "?") || hasSurrogateUnit(pattern) || hasSurrogateUnit(value) {
		return matchTokens(b, globTokens(pattern, nil), value)
	}
	return matchStars(b, pattern, value)
}

// matchStars is a glob whose only operator is `*`: the text before the first `*` and after the last must anchor the
// value, and each piece in between is found at its leftmost place after the previous one.
func matchStars(b *budget, pattern, value string) bool {
	b.spend(UTF16Len(pattern) + UTF16Len(value))
	pieces := strings.Split(pattern, "*")
	if len(pieces) == 1 {
		return pattern == value
	}
	first, last := pieces[0], pieces[len(pieces)-1]
	if len(value) < len(first)+len(last) || !strings.HasPrefix(value, first) || !strings.HasSuffix(value, last) {
		return false
	}
	end := len(value) - len(last)
	cursor := len(first)
	for index := 1; index < len(pieces)-1; index++ {
		piece := pieces[index]
		if piece == "" {
			continue
		}
		at := strings.Index(value[cursor:], piece)
		if at == -1 || cursor+at+len(piece) > end {
			return false
		}
		cursor += at + len(piece)
	}
	return true
}

// --- IP addresses --------------------------------------------------------------------------------------------------

type address struct {
	bits  int
	value *big.Int
}

var decimalOctet = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})$`)
var hexGroup = regexp.MustCompile(`^[0-9a-fA-F]{1,4}$`)

func parseIPv4(value string) *address {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return nil
	}
	result := new(big.Int)
	for _, part := range parts {
		if !decimalOctet.MatchString(part) {
			return nil
		}
		n, _ := strconv.Atoi(part)
		if n > 255 {
			return nil
		}
		result.Lsh(result, 8).Or(result, big.NewInt(int64(n)))
	}
	return &address{bits: 32, value: result}
}

func parseIP(value string) *address {
	if strings.ContainsAny(value, "%/[]") {
		return nil
	}
	if !strings.Contains(value, ":") {
		return parseIPv4(value)
	}
	normalized := value
	if strings.Contains(normalized, ".") {
		boundary := strings.LastIndex(normalized, ":")
		suffix := parseIPv4(normalized[boundary+1:])
		if suffix == nil {
			return nil
		}
		v := suffix.value.Int64()
		normalized = normalized[:boundary+1] + strconv.FormatInt(v>>16, 16) + ":" + strconv.FormatInt(v&65535, 16)
	}
	halves := strings.Split(normalized, "::")
	if len(halves) > 2 {
		return nil
	}
	var left, right []string
	if halves[0] != "" {
		left = strings.Split(halves[0], ":")
	}
	if len(halves) == 2 && halves[1] != "" {
		right = strings.Split(halves[1], ":")
	}
	for _, part := range append(append([]string(nil), left...), right...) {
		if !hexGroup.MatchString(part) {
			return nil
		}
	}
	total := len(left) + len(right)
	if (len(halves) == 1 && total != 8) || (len(halves) == 2 && total >= 8) {
		return nil
	}
	parts := left
	if len(halves) == 2 {
		parts = append(append([]string(nil), left...), make([]string, 8-total)...)
		for index := len(left); index < len(left)+8-total; index++ {
			parts[index] = "0"
		}
		parts = append(parts, right...)
	}
	result := new(big.Int)
	for _, part := range parts {
		n, _ := strconv.ParseUint(part, 16, 16)
		result.Lsh(result, 16).Or(result, new(big.Int).SetUint64(n))
	}
	return &address{bits: 128, value: result}
}

type network struct {
	address *address
	prefix  int
}

func parseCIDR(value string) *network {
	parts := strings.Split(value, "/")
	if len(parts) > 2 {
		return nil
	}
	addr := parseIP(parts[0])
	if addr == nil {
		return nil
	}
	if len(parts) == 2 && !decimalOctet.MatchString(parts[1]) {
		return nil
	}
	prefix := addr.bits
	if len(parts) == 2 {
		prefix, _ = strconv.Atoi(parts[1])
	}
	if prefix > addr.bits {
		return nil
	}
	return &network{address: addr, prefix: prefix}
}

var ffff = big.NewInt(0xffff)

// mappedIPv4 is the IPv4 address carried by an IPv4-mapped IPv6 address (::ffff:a.b.c.d), if it is one.
func mappedIPv4(addr *address) *address {
	if addr.bits == 128 && new(big.Int).Rsh(addr.value, 32).Cmp(ffff) == 0 {
		return &address{bits: 32, value: new(big.Int).And(addr.value, big.NewInt(0xffffffff))}
	}
	return nil
}

func inNetwork(actual, expected string) bool {
	addr := parseIP(actual)
	net := parseCIDR(expected)
	if addr == nil || net == nil {
		return false
	}
	base := net.address
	prefix := net.prefix
	// Across families the IPv4-mapped form stands for its IPv4 address, on either side.
	if addr.bits != base.bits {
		unmapped := mappedIPv4(addr)
		var mappedNetwork *address
		if prefix >= 96 {
			mappedNetwork = mappedIPv4(base)
		}
		switch {
		case unmapped != nil:
			addr = unmapped
		case mappedNetwork != nil:
			base = mappedNetwork
			prefix -= 96
		default:
			return false
		}
	}
	shift := uint(addr.bits - prefix)
	return new(big.Int).Rsh(addr.value, shift).Cmp(new(big.Int).Rsh(base.value, shift)) == 0
}

// IsIPRange reports whether the value is an IPv4/IPv6 address or CIDR block, as the IpAddress operator accepts.
func IsIPRange(value string) bool { return parseCIDR(value) != nil }

// IPMatches reports whether address lies inside network (an address or CIDR block). An IPv4-mapped IPv6 address
// matches the IPv4 networks containing its IPv4 address, and an IPv4 address the IPv4-mapped networks containing it.
func IPMatches(address, network string) bool { return inNetwork(address, network) }

// IPCounterKey is the key a per-address counter uses for a client: an IPv4 address as itself (the IPv4-mapped form
// folded to it), an IPv6 address as its /64. ok is false when the value is not an IP address.
func IPCounterKey(addr string) (string, bool) {
	parsed := parseIP(JSTrim(addr))
	if parsed == nil {
		return "", false
	}
	v4 := parsed
	if parsed.bits != 32 {
		v4 = mappedIPv4(parsed)
	}
	if v4 != nil {
		value := v4.value.Uint64()
		return strconv.FormatUint(value>>24&255, 10) + "." + strconv.FormatUint(value>>16&255, 10) + "." +
			strconv.FormatUint(value>>8&255, 10) + "." + strconv.FormatUint(value&255, 10), true
	}
	groups := make([]string, 0, 4)
	for _, shift := range []uint{112, 96, 80, 64} {
		group := new(big.Int).And(new(big.Int).Rsh(parsed.value, shift), ffff)
		groups = append(groups, strconv.FormatUint(group.Uint64(), 16))
	}
	return strings.Join(groups, ":") + "::/64", true
}

// --- dates ---------------------------------------------------------------------------------------------------------

var timestampPattern = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$`)

func digitsAt(value string, start, end int) int {
	n, _ := strconv.Atoi(value[start:end])
	return n
}

// policyTimestamp parses an ISO 8601 timestamp as the engine does (Date.parse plus calendar validation); ok is false
// for anything else.
func policyTimestamp(value any) (float64, bool) {
	text, isString := value.(string)
	if !isString || !timestampPattern.MatchString(text) {
		return 0, false
	}
	year := digitsAt(text, 0, 4)
	month := digitsAt(text, 5, 7)
	day := digitsAt(text, 8, 10)
	hour := digitsAt(text, 11, 13)
	minute := digitsAt(text, 14, 16)
	second := digitsAt(text, 17, 19)
	rest := text[19:]
	millis := 0
	if strings.HasPrefix(rest, ".") {
		end := 1
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		fraction := rest[1:end]
		millis, _ = strconv.Atoi((fraction + "00")[:3])
		rest = rest[end:]
	}
	offset := 0
	if rest != "Z" {
		offsetHours := digitsAt(rest, 1, 3)
		offsetMinutes := digitsAt(rest, 4, 6)
		// Date.parse refuses offsets beyond 23:59.
		if offsetHours > 23 || offsetMinutes > 59 {
			return 0, false
		}
		offset = (offsetHours*60 + offsetMinutes) * 60_000
		if rest[0] == '-' {
			offset = -offset
		}
	}
	// Date.parse refuses these outright; 24:00 and day overflow it normalizes, and the checks below reject them.
	if month < 1 || month > 12 || day < 1 || day > 31 || minute > 59 || second > 59 || hour > 24 {
		return 0, false
	}
	days := time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if day > days || hour > 23 {
		return 0, false
	}
	instant := time.Date(year, time.Month(month), day, hour, minute, second, millis*1_000_000, time.UTC).UnixMilli()
	return float64(instant - int64(offset)), true
}

// --- validation ----------------------------------------------------------------------------------------------------

func validConditionValue(operator string, value any) bool {
	switch operator {
	case "Bool", "Exists":
		_, ok := value.(bool)
		return ok
	case "NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan",
		"NumericGreaterThanEquals":
		_, ok := finiteNumber(value)
		return ok
	case "DateBefore", "DateAfter":
		_, ok := policyTimestamp(value)
		return ok
	case "IpAddress", "NotIpAddress":
		text, ok := value.(string)
		return ok && parseCIDR(text) != nil
	case "StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase", "StringLike",
		"StringNotLike", "StringLikeIgnoreCase":
		text, ok := value.(string)
		return ok && UTF16Len(text) <= 2048
	case "ArrayContains", "ArrayContainsAll":
		switch v := value.(type) {
		case string:
			return UTF16Len(v) <= 2048
		case float64:
			return !math.IsNaN(v) && !math.IsInf(v, 0)
		case bool:
			return true
		}
	}
	return false
}

// PolicyValue converts a policy document (*PolicyDocument, PolicyDocument, or any model value) into the value model.
func PolicyValue(document any) any {
	switch v := document.(type) {
	case *PolicyDocument:
		if v == nil {
			return nil
		}
		return Normalize(*v)
	}
	return Normalize(document)
}

// ValidatePolicy validates an untrusted document (before storage and again before evaluation). It accepts a
// *PolicyDocument or any model value and fails with INVALID_POLICY.
func ValidatePolicy(document any) error {
	value, ok := PolicyValue(document).(*Object)
	if !ok || value == nil {
		return invalidPolicy("Policy must be a plain object")
	}
	if !onlyKeys(value, "version", "statements") {
		return invalidPolicy("Unknown policy field")
	}
	statements, isList := value.Get("statements").([]any)
	if version, _ := value.Get("version").(float64); version != 1 || !isList || len(statements) > 128 {
		return invalidPolicy("Expected policy version 1 and at most 128 statements")
	}
	sids := map[string]bool{}
	for _, item := range statements {
		statement, ok := item.(*Object)
		if !ok || statement == nil {
			return invalidPolicy("Statement must be a plain object")
		}
		if !onlyKeys(statement, "sid", "effect", "actions", "resources", "conditions") {
			return invalidPolicy("Unknown policy field")
		}
		if effect := statement.Get("effect"); effect != "allow" && effect != "deny" {
			return invalidPolicy("Statement effect must be allow or deny")
		}
		if sid := statement.Get("sid"); !IsUndefined(sid) {
			text, _ := sid.(string)
			if !nonempty(sid, 128) || sids[text] {
				return invalidPolicy("Statement IDs must be nonempty and unique")
			}
			sids[text] = true
		}
		for _, field := range []string{"actions", "resources"} {
			items, ok := statement.Get(field).([]any)
			valid := ok && len(items) > 0 && len(items) <= 128
			if valid {
				for _, entry := range items {
					if !nonempty(entry, 512) {
						valid = false
						break
					}
				}
			}
			if !valid {
				return invalidPolicy(field + " must contain 1–128 nonempty patterns")
			}
			for _, entry := range items {
				pattern := entry.(string)
				if field == "actions" && strings.Contains(pattern, variableMarker) {
					return invalidPolicy("Policy variables are not allowed in actions")
				}
			}
			if field == "resources" {
				for _, entry := range items {
					pattern := entry.(string)
					if !ValidPolicyVariables(pattern) {
						return invalidPolicy("Malformed policy variable in resource pattern " + pattern)
					}
					if typ, _, _ := strings.Cut(pattern, "/"); strings.Contains(typ, variableMarker) {
						return invalidPolicy("Policy variables may only appear after the resource type")
					}
				}
			}
		}
		if conditions := statement.Get("conditions"); !IsUndefined(conditions) {
			operators, ok := conditions.(*Object)
			if !ok || operators == nil || operators.Len() == 0 {
				return invalidPolicy("Conditions must be a nonempty operator map")
			}
			for _, name := range operators.keys {
				entries, ok := operators.values[name].(*Object)
				if !knownOperator(name) || !ok || entries == nil || entries.Len() == 0 || entries.Len() > 64 {
					return invalidPolicy("Unknown operator or invalid condition attributes")
				}
				for _, key := range entries.keys {
					if !nonempty(key, 128) || unsafeKeys[key] {
						return invalidPolicy("Invalid condition attribute")
					}
					expected := entries.values[key]
					values, isList := expected.([]any)
					if !isList {
						values = []any{expected}
					}
					valid := len(values) > 0 && len(values) <= 64
					for _, entry := range values {
						if !valid {
							break
						}
						valid = validConditionValue(name, entry)
					}
					if !valid {
						return invalidPolicy("Invalid value for condition " + name)
					}
					for _, entry := range values {
						if text, ok := entry.(string); ok && !ValidPolicyVariables(text) {
							return invalidPolicy("Malformed policy variable in condition " + name)
						}
					}
				}
			}
		}
	}
	return nil
}

// DefinePolicy validates a document and returns a detached copy.
func DefinePolicy(document PolicyDocument) (*PolicyDocument, error) {
	if err := ValidatePolicy(&document); err != nil {
		return nil, err
	}
	var out PolicyDocument
	if err := FromRecord(PolicyValue(&document), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// compiled forms of validated documents

type conditionEntry struct {
	key      string
	values   []any
	expected any
}

type conditionBlock struct {
	operator string
	entries  []conditionEntry
}

type compiledStatement struct {
	sid        any // string, or Undefined
	effect     string
	actions    []string
	resources  []string
	conditions []conditionBlock
}

type compiledDocument struct {
	statements []compiledStatement
}

func toStrings(values []any) []string {
	out := make([]string, len(values))
	for index, value := range values {
		out[index], _ = value.(string)
	}
	return out
}

// compilePolicy reads a validated document value.
func compilePolicy(value *Object) compiledDocument {
	var document compiledDocument
	statements, _ := value.Get("statements").([]any)
	for _, item := range statements {
		statement := item.(*Object)
		actions, _ := statement.Get("actions").([]any)
		resources, _ := statement.Get("resources").([]any)
		effect, _ := statement.Get("effect").(string)
		compiled := compiledStatement{sid: statement.Get("sid"), effect: effect, actions: toStrings(actions), resources: toStrings(resources)}
		if operators, ok := statement.Get("conditions").(*Object); ok && operators != nil {
			for _, name := range operators.keys {
				block := conditionBlock{operator: name}
				entries := operators.values[name].(*Object)
				for _, key := range entries.keys {
					expected := entries.values[key]
					values, isList := expected.([]any)
					if !isList {
						values = []any{expected}
					}
					block.entries = append(block.entries, conditionEntry{key: key, values: values, expected: expected})
				}
				compiled.conditions = append(compiled.conditions, block)
			}
		}
		document.statements = append(document.statements, compiled)
	}
	return document
}

func validateAndCompile(documents []any) ([]compiledDocument, error) {
	out := make([]compiledDocument, 0, len(documents))
	for _, document := range documents {
		value := PolicyValue(document)
		if err := ValidatePolicy(value); err != nil {
			return nil, err
		}
		out = append(out, compilePolicy(value.(*Object)))
	}
	return out, nil
}

// arrayIncludes is Array.prototype.includes (SameValueZero) for a scalar.
func arrayIncludes(list []any, wanted any) bool {
	for _, item := range list {
		if strictEquals(item, wanted) {
			return true
		}
		if a, ok := item.(float64); ok {
			if b, ok := wanted.(float64); ok && math.IsNaN(a) && math.IsNaN(b) {
				return true
			}
		}
	}
	return false
}

func member(b *budget, actual []any, expected any, context *Object) bool {
	wanted := expected
	if text, ok := expected.(string); ok {
		resolved, ok := ResolvePolicyValue(text, context)
		if !ok {
			return false
		}
		wanted = resolved
	}
	b.spend(len(actual))
	return arrayIncludes(actual, wanted)
}

// compare is the positive comparison for an operator; negated operators are evaluated as its inverse.
func compare(b *budget, operator string, actual, expected any, context *Object) bool {
	switch operator {
	case "Exists":
		return strictEquals(actual, expected)
	case "StringEquals", "StringNotEquals":
		left, ok := actual.(string)
		right, ok2 := expected.(string)
		if !ok || !ok2 {
			return false
		}
		resolved, resolvedOK := ResolvePolicyValue(right, context)
		return resolvedOK && left == resolved
	case "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase":
		right, ok := expected.(string)
		if !ok {
			return false
		}
		resolved, resolvedOK := ResolvePolicyValue(right, context)
		left, ok := actual.(string)
		return ok && resolvedOK && JSLower(left) == JSLower(resolved)
	case "StringLike", "StringNotLike":
		left, ok := actual.(string)
		right, ok2 := expected.(string)
		return ok && ok2 && matchPattern(b, right, left, context)
	case "StringLikeIgnoreCase":
		left, ok := actual.(string)
		right, ok2 := expected.(string)
		return ok && ok2 && matchPattern(b, JSLower(right), JSLower(left), lowerCaseContext(context))
	case "Bool":
		left, ok := actual.(bool)
		right, ok2 := expected.(bool)
		return ok && ok2 && left == right
	case "NumericEquals", "NumericNotEquals":
		left, ok := finiteNumber(actual)
		right, ok2 := expected.(float64)
		return ok && ok2 && left == right
	case "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals":
		left, ok := finiteNumber(actual)
		right, ok2 := expected.(float64)
		if !ok || !ok2 {
			return false
		}
		switch operator {
		case "NumericLessThan":
			return left < right
		case "NumericLessThanEquals":
			return left <= right
		case "NumericGreaterThan":
			return left > right
		}
		return left >= right
	case "DateBefore", "DateAfter":
		left, ok := policyTimestamp(actual)
		right, ok2 := policyTimestamp(expected)
		if !ok || !ok2 {
			return false
		}
		if operator == "DateBefore" {
			return left < right
		}
		return left > right
	case "IpAddress", "NotIpAddress":
		left, ok := actual.(string)
		right, ok2 := expected.(string)
		return ok && ok2 && inNetwork(left, right)
	case "ArrayContains", "ArrayContainsAll":
		list, ok := actual.([]any)
		return ok && member(b, list, expected, context)
	}
	return false
}

// wellTyped: a negated operator only negates a comparison that could have succeeded.
func wellTyped(operator string, actual any) bool {
	switch operator {
	case "NumericNotEquals":
		_, ok := finiteNumber(actual)
		return ok
	case "NotIpAddress":
		text, ok := actual.(string)
		return ok && parseIP(text) != nil
	default:
		_, ok := actual.(string)
		return ok
	}
}

// lowerCaseContext lowers string context values too, so `${principal.team}-*` behaves consistently.
func lowerCaseContext(context *Object) *Object {
	if context == nil {
		return nil
	}
	lowered := NewObject()
	context.Entries(func(key string, value any) bool {
		if text, ok := value.(string); ok {
			lowered.SetRaw(key, JSLower(text))
		} else {
			lowered.SetRaw(key, value)
		}
		return true
	})
	return lowered
}

func statementMatches(b *budget, statement compiledStatement, action, resource string, context *Object) bool {
	matched := false
	for _, pattern := range statement.actions {
		if matchPattern(b, pattern, action, nil) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	matched = false
	for _, pattern := range statement.resources {
		if matchPattern(b, pattern, resource, context) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, block := range statement.conditions {
		operator := block.operator
		for _, entry := range block.entries {
			actualValue, has := context.Lookup(entry.key)
			exists := context != nil && has && !IsUndefined(actualValue)
			// Missing or wrongly typed values never satisfy a condition, including negated ones.
			if operator != "Exists" && !exists {
				return false
			}
			var actual any = actualValue
			if operator == "Exists" {
				actual = exists
			}
			if negatedOperators[operator] && !wellTyped(operator, actual) {
				return false
			}
			test := func(item any) bool {
				length := 0
				if text, ok := actual.(string); ok {
					length = UTF16Len(text)
				}
				b.spend(1 + length)
				outcome := compare(b, operator, actual, item, context)
				if negatedOperators[operator] {
					return !outcome
				}
				return outcome
			}
			var ok bool
			if everyValue(operator) {
				ok = true
				for _, item := range entry.values {
					if !test(item) {
						ok = false
						break
					}
				}
			} else {
				for _, item := range entry.values {
					if test(item) {
						ok = true
						break
					}
				}
			}
			if !ok {
				return false
			}
		}
	}
	return true
}

// EvaluatePolicy evaluates grants (a union) and boundaries (each an independent intersection; a boundary never
// grants). Callers must establish trusted context and tenant scope. Fails with INVALID_REQUEST or INVALID_POLICY.
func EvaluatePolicy(input EvaluationInput) (Decision, error) {
	if !nonempty(input.Action, 512) || !nonempty(input.Resource, 2048) {
		return Decision{}, NewIamError("INVALID_REQUEST", "Invalid policy evaluation request")
	}
	grants, err := validateAndCompile(input.Grants)
	if err != nil {
		return Decision{}, err
	}
	boundaries, err := validateAndCompile(input.Boundaries)
	if err != nil {
		return Decision{}, err
	}
	return evaluateCompiled(input.Action, input.Resource, input.Context, grants, boundaries), nil
}

func evaluateCompiled(action, resource string, context *Object, grants, boundaries []compiledDocument) (decision Decision) {
	matched := []string{}
	granted, denied := false, false
	boundaryAllows := make([]bool, len(boundaries))
	b := &budget{left: evaluationWork}
	defer func() {
		if recovered := recover(); recovered != nil {
			if _, ok := recovered.(evaluationLimit); ok {
				// Too much matching work refuses, like a deny: nothing is granted on a partial evaluation.
				decision = Decision{Allowed: false, Reason: "evaluation-limit", Matched: matched}
				return
			}
			panic(recovered)
		}
	}()
	for _, pass := range []struct {
		kind      string
		documents []compiledDocument
	}{{"grant", grants}, {"boundary", boundaries}} {
		for policyIndex, document := range pass.documents {
			for statementIndex, statement := range document.statements {
				if !statementMatches(b, statement, action, resource, context) {
					continue
				}
				label := strconv.Itoa(statementIndex)
				if sid, ok := statement.sid.(string); ok {
					label = sid
				}
				matched = append(matched, pass.kind+":"+strconv.Itoa(policyIndex)+":"+label)
				switch {
				case statement.effect == "deny":
					denied = true
				case pass.kind == "grant":
					granted = true
				default:
					boundaryAllows[policyIndex] = true
				}
			}
		}
	}
	if denied {
		return Decision{Allowed: false, Reason: "explicit-deny", Matched: matched}
	}
	if !granted {
		return Decision{Allowed: false, Reason: "no-grant", Matched: matched}
	}
	for _, allowed := range boundaryAllows {
		if !allowed {
			return Decision{Allowed: false, Reason: "boundary-deny", Matched: matched}
		}
	}
	return Decision{Allowed: true, Reason: "allowed", Matched: matched}
}

// EvaluatePolicyValue is EvaluatePolicy over an untrusted model value shaped like EvaluationInput
// ({ action, resource, context?, grants, boundaries? }), with the TypeScript request checks.
func EvaluatePolicyValue(input any) (Decision, error) {
	request, ok := Normalize(input).(*Object)
	invalid := NewIamError("INVALID_REQUEST", "Invalid policy evaluation request")
	if !ok || request == nil {
		return Decision{}, invalid
	}
	action, _ := request.Get("action").(string)
	resource, _ := request.Get("resource").(string)
	grants, grantsOK := request.Get("grants").([]any)
	boundariesValue := request.Get("boundaries")
	boundaries, boundariesOK := boundariesValue.([]any)
	contextValue := request.Get("context")
	context, contextOK := contextValue.(*Object)
	if !nonempty(request.Get("action"), 512) || !nonempty(request.Get("resource"), 2048) || !grantsOK ||
		(!IsUndefined(boundariesValue) && !boundariesOK) || (!IsUndefined(contextValue) && (!contextOK || context == nil)) {
		return Decision{}, invalid
	}
	return EvaluatePolicy(EvaluationInput{Action: action, Resource: resource, Context: context, Grants: grants, Boundaries: boundaries})
}
