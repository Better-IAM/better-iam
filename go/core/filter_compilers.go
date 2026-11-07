package core

import (
	"strconv"
	"strings"
)

// Compilers for query plans (plan.go): the same filter as an in-memory predicate, SQL for PostgreSQL and SQLite, a
// Prisma `where`, and a MongoDB query. Each atom is NULL-safe (a missing field satisfies nothing but `not exists`), so
// negations behave like the policy engine rather than like SQL's three-valued logic.

func unsupportedFilter(kind, target string) error {
	return NewIamError("UNSUPPORTED_FILTER", kind+" conditions cannot be expressed in "+target+"; filter these resources with filterMatches or authorize")
}

func isAddressValue(value any) bool {
	text, ok := value.(string)
	return ok && !strings.Contains(text, "/") && IsIPRange(text)
}

func sameFilterValue(actual any, expected FilterValue, ignoreCase bool) bool {
	if number, ok := expected.(float64); ok {
		value, finite := finiteNumber(actual)
		return finite && value == number
	}
	if typeOf(actual) != typeOf(expected) {
		return false
	}
	if text, ok := actual.(string); ok && ignoreCase {
		return JSLower(text) == JSLower(expected.(string))
	}
	return strictEquals(actual, expected)
}

// FilterMatches reports whether a resource passes a filter: record "id" is the id and every other field is read by
// name (record["tag.team"] for resource.tag.team). It is exact, with the policy engine's semantics, and supports every
// filter.
func FilterMatches(filter ResourceFilter, record *Object) bool {
	read := func(field string) any { return record.Get(field) }
	switch filter.Kind {
	case "true":
		return true
	case "false":
		return false
	case "and":
		for _, item := range filter.Filters {
			if !FilterMatches(item, record) {
				return false
			}
		}
		return true
	case "or":
		for _, item := range filter.Filters {
			if FilterMatches(item, record) {
				return true
			}
		}
		return false
	case "not":
		return filter.Filter != nil && !FilterMatches(*filter.Filter, record)
	case "exists":
		return !IsUndefined(read(filter.Field))
	case "type":
		value := read(filter.Field)
		switch filter.Type {
		case "ip":
			return isAddressValue(value)
		case "number":
			_, ok := finiteNumber(value)
			return ok
		}
		return typeOf(value) == filter.Type
	case "equals":
		value := read(filter.Field)
		for _, expected := range filter.Values {
			if sameFilterValue(value, expected, filter.IgnoreCase) {
				return true
			}
		}
		return false
	case "compare":
		value, ok := finiteNumber(read(filter.Field))
		limit, _ := filter.Value.(float64)
		if !ok {
			return false
		}
		switch filter.Operator {
		case "lt":
			return value < limit
		case "le":
			return value <= limit
		case "gt":
			return value > limit
		}
		return value >= limit
	case "like":
		value, ok := read(filter.Field).(string)
		if !ok {
			return false
		}
		if filter.IgnoreCase {
			return matchTokens(nil, parseGlobTokens(JSLower(filter.Pattern)), JSLower(value))
		}
		return matchTokens(nil, parseGlobTokens(filter.Pattern), value)
	case "date":
		left, ok := policyTimestamp(read(filter.Field))
		right, ok2 := policyTimestamp(filter.Value)
		if !ok || !ok2 {
			return false
		}
		if filter.Operator == "before" {
			return left < right
		}
		return left > right
	case "ip":
		value, ok := read(filter.Field).(string)
		return ok && IPMatches(value, filter.Network)
	case "contains":
		value, ok := read(filter.Field).([]any)
		return ok && arrayIncludes(value, filter.Value)
	}
	return false
}

// --- SQL -----------------------------------------------------------------------------------------------------------

// SqlFilterOptions configure FilterToSql.
type SqlFilterOptions struct {
	// Dialect is "postgres" or "sqlite".
	Dialect string
	// Column is the SQL expression for a field: a trusted column name or JSON path expression of your schema. Return
	// "" to refuse a field the plan names that your table does not have.
	Column func(field string) string
	// Offset: PostgreSQL placeholders start after this many parameters.
	Offset int
}

// SqlFilter is a boolean SQL expression with its parameters.
type SqlFilter struct {
	SQL    string `json:"sql"`
	Params []any  `json:"params"`
}

// sqliteGlob is a glob as a SQLite GLOB pattern: wildcards stay, literal *, ? and [ become character classes.
func sqliteGlob(pattern string, lower bool) string {
	if lower {
		pattern = JSLower(pattern)
	}
	var b strings.Builder
	for _, t := range parseGlobTokens(pattern) {
		switch {
		case t.kind == tokenStar:
			b.WriteByte('*')
		case t.kind == tokenAny:
			b.WriteByte('?')
		case t.value == "*" || t.value == "?" || t.value == "[":
			b.WriteString("[" + t.value + "]")
		default:
			b.WriteString(t.value)
		}
	}
	return b.String()
}

// likePattern is a glob as a LIKE pattern with \ as the escape character.
func likePattern(pattern string, lower bool) string {
	if lower {
		pattern = JSLower(pattern)
	}
	var b strings.Builder
	for _, t := range parseGlobTokens(pattern) {
		switch {
		case t.kind == tokenStar:
			b.WriteByte('%')
		case t.kind == tokenAny:
			b.WriteByte('_')
		case t.value == "%" || t.value == "_" || t.value == "\\":
			b.WriteString("\\" + t.value)
		default:
			b.WriteString(t.value)
		}
	}
	return b.String()
}

var sqlOperators = map[string]string{"lt": "<", "le": "<=", "gt": ">", "ge": ">="}

type compileFailure struct{ err error }

// FilterToSql is the filter as a parameterized SQL expression. PostgreSQL uses $n placeholders and SQLite ?. IP and
// array conditions refuse with UNSUPPORTED_FILTER.
func FilterToSql(filter ResourceFilter, options SqlFilterOptions) (result SqlFilter, err error) {
	params := []any{}
	postgres := options.Dialect == "postgres"
	bind := func(value any) string {
		if b, ok := value.(bool); ok && !postgres {
			if b {
				value = 1.0
			} else {
				value = 0.0
			}
		}
		params = append(params, value)
		if postgres {
			return "$" + strconv.Itoa(options.Offset+len(params))
		}
		return "?"
	}
	fail := func(e error) { panic(compileFailure{e}) }
	defer func() {
		if recovered := recover(); recovered != nil {
			if failure, ok := recovered.(compileFailure); ok {
				result, err = SqlFilter{}, failure.err
				return
			}
			panic(recovered)
		}
	}()
	column := func(field string) string {
		expression := ""
		if options.Column != nil {
			expression = options.Column(field)
		}
		if expression == "" {
			fail(NewIamError("INVALID_INPUT", "The plan filters on "+field+", which has no column"))
		}
		return expression
	}
	guarded := func(field string, predicate func(expression string) string) string {
		expression := column(field)
		return "(" + expression + " IS NOT NULL AND " + predicate(expression) + ")"
	}
	var compile func(item ResourceFilter) string
	compile = func(item ResourceFilter) string {
		switch item.Kind {
		case "true":
			if postgres {
				return "TRUE"
			}
			return "1 = 1"
		case "false":
			if postgres {
				return "FALSE"
			}
			return "1 = 0"
		case "and", "or":
			parts := make([]string, len(item.Filters))
			for index, child := range item.Filters {
				parts[index] = compile(child)
			}
			return "(" + strings.Join(parts, " "+strings.ToUpper(item.Kind)+" ") + ")"
		case "not":
			return "(NOT " + compile(*item.Filter) + ")"
		case "exists", "type":
			if item.Kind == "type" && item.Type == "ip" {
				fail(unsupportedFilter("IP address", "SQL"))
			}
			return "(" + column(item.Field) + " IS NOT NULL)"
		case "equals":
			return guarded(item.Field, func(expression string) string {
				values := item.Values
				target := expression
				if item.IgnoreCase {
					values = make([]any, len(item.Values))
					for index, value := range item.Values {
						if text, ok := value.(string); ok {
							values[index] = JSLower(text)
						} else {
							values[index] = value
						}
					}
					target = "LOWER(" + expression + ")"
				}
				placeholders := make([]string, len(values))
				for index, value := range values {
					placeholders[index] = bind(value)
				}
				return target + " IN (" + strings.Join(placeholders, ", ") + ")"
			})
		case "compare":
			return guarded(item.Field, func(expression string) string {
				return expression + " " + sqlOperators[item.Operator] + " " + bind(item.Value)
			})
		case "like":
			return guarded(item.Field, func(expression string) string {
				target := expression
				if item.IgnoreCase {
					target = "LOWER(" + expression + ")"
				}
				if postgres {
					return target + " LIKE " + bind(likePattern(item.Pattern, item.IgnoreCase)) + " ESCAPE '\\'"
				}
				return target + " GLOB " + bind(sqliteGlob(item.Pattern, item.IgnoreCase))
			})
		case "date":
			return guarded(item.Field, func(expression string) string {
				operator := ">"
				if item.Operator == "before" {
					operator = "<"
				}
				if postgres {
					return "(" + expression + ")::timestamptz " + operator + " " + bind(item.Value) + "::timestamptz"
				}
				return "julianday(" + expression + ") " + operator + " julianday(" + bind(item.Value) + ")"
			})
		case "ip":
			fail(unsupportedFilter("IP address", "SQL"))
		case "contains":
			fail(unsupportedFilter("Array", "SQL"))
		}
		return ""
	}
	sql := compile(filter)
	return SqlFilter{SQL: sql, Params: params}, nil
}

// --- Prisma --------------------------------------------------------------------------------------------------------

// PrismaFilterOptions configure FilterToPrisma.
type PrismaFilterOptions struct {
	// Field maps a plan field to the model field (default: the same name).
	Field func(field string) string
}

type simpleGlobResult struct {
	kind string
	text string
}

// simpleGlob is a glob Prisma's string filters can express: exact, a prefix, a suffix, or a substring.
func simpleGlob(pattern string) *simpleGlobResult {
	tokens := parseGlobTokens(pattern)
	var stars []int
	var text strings.Builder
	for index, t := range tokens {
		switch t.kind {
		case tokenAny:
			return nil
		case tokenStar:
			stars = append(stars, index)
		default:
			text.WriteString(t.value)
		}
	}
	last := len(tokens) - 1
	switch {
	case len(stars) == 0:
		return &simpleGlobResult{"equals", text.String()}
	case len(stars) == 1 && stars[0] == last:
		return &simpleGlobResult{"startsWith", text.String()}
	case len(stars) == 1 && stars[0] == 0:
		return &simpleGlobResult{"endsWith", text.String()}
	case len(stars) == 2 && stars[0] == 0 && stars[1] == last:
		return &simpleGlobResult{"contains", text.String()}
	}
	return nil
}

func prismaComparison(operator string) string {
	switch operator {
	case "le":
		return "lte"
	case "ge":
		return "gte"
	}
	return operator
}

// FilterToPrisma is the filter as a Prisma `where` object. Globs must be exact, a prefix, a suffix or a substring;
// dates, IP addresses, and other globs refuse with UNSUPPORTED_FILTER.
func FilterToPrisma(filter ResourceFilter, options PrismaFilterOptions) (result *Object, err error) {
	name := func(field string) string {
		if options.Field != nil {
			if mapped := options.Field(field); mapped != "" {
				return mapped
			}
		}
		return field
	}
	fail := func(e error) { panic(compileFailure{e}) }
	defer func() {
		if recovered := recover(); recovered != nil {
			if failure, ok := recovered.(compileFailure); ok {
				result, err = nil, failure.err
				return
			}
			panic(recovered)
		}
	}()
	present := func(field string) *Object { return NewObject(name(field), NewObject("not", nil)) }
	var compile func(item ResourceFilter) *Object
	compileAll := func(items []ResourceFilter) []any {
		out := make([]any, len(items))
		for index, item := range items {
			out[index] = compile(item)
		}
		return out
	}
	compile = func(item ResourceFilter) *Object {
		switch item.Kind {
		case "true":
			return NewObject()
		case "false":
			return NewObject(name("id"), NewObject("in", []any{}))
		case "and":
			return NewObject("AND", compileAll(item.Filters))
		case "or":
			return NewObject("OR", compileAll(item.Filters))
		case "not":
			return NewObject("NOT", compile(*item.Filter))
		case "exists", "type":
			if item.Kind == "type" && item.Type == "ip" {
				fail(unsupportedFilter("IP address", "Prisma"))
			}
			return present(item.Field)
		case "equals":
			var test *Object
			if item.IgnoreCase {
				options := make([]any, len(item.Values))
				for index, value := range item.Values {
					options[index] = NewObject(name(item.Field), NewObject("equals", value, "mode", "insensitive"))
				}
				test = NewObject("OR", options)
			} else {
				test = NewObject(name(item.Field), NewObject("in", append([]any{}, item.Values...)))
			}
			return NewObject("AND", []any{present(item.Field), test})
		case "compare":
			return NewObject("AND", []any{present(item.Field), NewObject(name(item.Field), NewObject(prismaComparison(item.Operator), item.Value))})
		case "like":
			simple := simpleGlob(item.Pattern)
			if simple == nil {
				fail(unsupportedFilter("This wildcard", "Prisma"))
			}
			test := NewObject(simple.kind, simple.text)
			if item.IgnoreCase {
				test.Set("mode", "insensitive")
			}
			return NewObject("AND", []any{present(item.Field), NewObject(name(item.Field), test)})
		case "contains":
			return NewObject(name(item.Field), NewObject("has", item.Value))
		case "date":
			fail(unsupportedFilter("Date", "Prisma"))
		case "ip":
			fail(unsupportedFilter("IP address", "Prisma"))
		}
		return NewObject()
	}
	return compile(filter), nil
}

// --- MongoDB -------------------------------------------------------------------------------------------------------

// MongoFilterOptions configure FilterToMongo.
type MongoFilterOptions struct {
	// Field maps a plan field to the document field (default: the same name; map id to _id if ids live there).
	Field func(field string) string
}

// RegExp is a regular expression value in a MongoDB query (a JavaScript RegExp in the TypeScript implementation).
type RegExp struct {
	Source string
	Flags  string
}

// String is the RegExp's literal form (/source/flags).
func (r RegExp) String() string { return "/" + r.Source + "/" + r.Flags }

// MarshalJSON writes the RegExp as MongoDB extended JSON ({"$regex", "$options"}).
func (r RegExp) MarshalJSON() ([]byte, error) {
	return NewObject("$regex", r.Source, "$options", r.Flags).MarshalJSON()
}

func regexEscape(text string) string {
	var b strings.Builder
	for _, char := range CodePoints(text) {
		if len(char) == 1 && strings.Contains(`.*+?^${}()|[]\/`, char) {
			b.WriteByte('\\')
		}
		b.WriteString(char)
	}
	return b.String()
}

// globRegex is a glob as an anchored regular expression source.
func globRegex(pattern string) string {
	var b strings.Builder
	b.WriteByte('^')
	for _, t := range parseGlobTokens(pattern) {
		switch t.kind {
		case tokenStar:
			b.WriteString(`[\s\S]*`)
		case tokenAny:
			b.WriteString(`[\s\S]`)
		default:
			b.WriteString(regexEscape(t.value))
		}
	}
	b.WriteByte('$')
	return b.String()
}

// FilterToMongo is the filter as a MongoDB query document. Dates and IP addresses refuse with UNSUPPORTED_FILTER.
// Case-insensitive equality values are RegExp values.
func FilterToMongo(filter ResourceFilter, options MongoFilterOptions) (result *Object, err error) {
	name := func(field string) string {
		if options.Field != nil {
			if mapped := options.Field(field); mapped != "" {
				return mapped
			}
		}
		return field
	}
	fail := func(e error) { panic(compileFailure{e}) }
	defer func() {
		if recovered := recover(); recovered != nil {
			if failure, ok := recovered.(compileFailure); ok {
				result, err = nil, failure.err
				return
			}
			panic(recovered)
		}
	}()
	var compile func(item ResourceFilter) *Object
	compileAll := func(items []ResourceFilter) []any {
		out := make([]any, len(items))
		for index, item := range items {
			out[index] = compile(item)
		}
		return out
	}
	compile = func(item ResourceFilter) *Object {
		switch item.Kind {
		case "true":
			return NewObject()
		case "false":
			return NewObject(name("id"), NewObject("$in", []any{}))
		case "and":
			return NewObject("$and", compileAll(item.Filters))
		case "or":
			return NewObject("$or", compileAll(item.Filters))
		case "not":
			return NewObject("$nor", []any{compile(*item.Filter)})
		case "exists":
			return NewObject(name(item.Field), NewObject("$exists", true, "$ne", nil))
		case "type":
			switch item.Type {
			case "ip":
				fail(unsupportedFilter("IP address", "MongoDB"))
			case "string":
				return NewObject(name(item.Field), NewObject("$type", "string"))
			case "number":
				return NewObject(name(item.Field), NewObject("$type", "number"))
			}
			return NewObject(name(item.Field), NewObject("$type", "bool"))
		case "equals":
			if item.IgnoreCase {
				values := make([]any, len(item.Values))
				for index, value := range item.Values {
					if text, ok := value.(string); ok {
						values[index] = RegExp{Source: "^" + regexEscape(text) + "$", Flags: "iu"}
					} else {
						values[index] = value
					}
				}
				return NewObject(name(item.Field), NewObject().SetRaw("$in", values))
			}
			return NewObject(name(item.Field), NewObject("$in", append([]any{}, item.Values...)))
		case "compare":
			return NewObject(name(item.Field), NewObject("$"+prismaComparison(item.Operator), item.Value))
		case "like":
			pattern := item.Pattern
			flags := "u"
			if item.IgnoreCase {
				pattern = JSLower(pattern)
				flags = "iu"
			}
			return NewObject(name(item.Field), NewObject("$regex", globRegex(pattern), "$options", flags))
		case "contains":
			return NewObject(name(item.Field), NewObject("$elemMatch", NewObject("$eq", item.Value)))
		case "date":
			fail(unsupportedFilter("Date", "MongoDB"))
		case "ip":
			fail(unsupportedFilter("IP address", "MongoDB"))
		}
		return NewObject()
	}
	return compile(filter), nil
}

// --- description ---------------------------------------------------------------------------------------------------

// DescribeFilter is a readable rendering of a filter, for logs, UIs and tests.
func DescribeFilter(filter ResourceFilter) string {
	value := func(item any) string { return MustStringify(item) }
	anyCase := ""
	if filter.IgnoreCase {
		anyCase = " (any case)"
	}
	switch filter.Kind {
	case "true", "false":
		return filter.Kind
	case "and", "or":
		other := "or"
		if filter.Kind == "or" {
			other = "and"
		}
		parts := make([]string, len(filter.Filters))
		for index, item := range filter.Filters {
			if item.Kind == other {
				parts[index] = "(" + DescribeFilter(item) + ")"
			} else {
				parts[index] = DescribeFilter(item)
			}
		}
		return strings.Join(parts, " "+filter.Kind+" ")
	case "not":
		return "not (" + DescribeFilter(*filter.Filter) + ")"
	case "exists":
		return filter.Field + " exists"
	case "type":
		return filter.Field + " is " + filter.Type
	case "equals":
		if len(filter.Values) == 1 {
			return filter.Field + " = " + value(filter.Values[0]) + anyCase
		}
		parts := make([]string, len(filter.Values))
		for index, item := range filter.Values {
			parts[index] = value(item)
		}
		return filter.Field + " in [" + strings.Join(parts, ", ") + "]" + anyCase
	case "compare":
		number, _ := scalarString(filter.Value)
		return filter.Field + " " + sqlOperators[filter.Operator] + " " + number
	case "like":
		return filter.Field + " like " + QuoteJSON(filter.Pattern) + anyCase
	case "date":
		text, _ := scalarString(filter.Value)
		return filter.Field + " " + filter.Operator + " " + text
	case "ip":
		return filter.Field + " in " + filter.Network
	case "contains":
		return filter.Field + " contains " + value(filter.Value)
	}
	return ""
}
