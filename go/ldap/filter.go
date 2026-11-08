package ldap

// Port of packages/ldap/src/filter.ts: LDAP search filters (RFC 4511 §4.5.1): the BER form a search carries, the
// string form of RFC 4515 (for clients and tests), and evaluation against an entry. Attribute names compare
// case-insensitively; values compare as caseIgnore strings.

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// Filter is a search filter. Type is and, or, not, equal, greater, less, approx, substrings, present or extensible.
type Filter struct {
	Type string
	// Filters are the operands of and / or; Inner the operand of not.
	Filters []*Filter
	Inner   *Filter
	// Attribute is the attribute (for extensible filters, present when HasAttribute).
	Attribute    string
	HasAttribute bool
	Value        string
	// Initial, Any and Final are the parts of a substrings filter (Initial / Final nil when absent).
	Initial *string
	Any     []string
	Final   *string
	// Rule is an extensible filter's matching rule (present when HasRule); DnAttributes its dnAttributes flag.
	Rule         string
	HasRule      bool
	DnAttributes bool
}

const (
	maxFilterDepth = 32
	maxFilterTerms = 256
)

type filterBudget struct{ terms int }

// DecodeFilter decodes a BER filter. Deep or huge filters are refused (a search is evaluated against every entry).
func DecodeFilter(item *BerElement) (*Filter, error) {
	return decodeFilter(item, 0, &filterBudget{})
}

func decodeFilter(item *BerElement, depth int, budget *filterBudget) (*Filter, error) {
	budget.terms++
	if depth > maxFilterDepth || budget.terms > maxFilterTerms {
		return nil, berError("Filter too complex")
	}
	parts := func() ([]*BerElement, error) { return Children(item.Value) }
	switch item.Tag {
	case 0xa0, 0xa1:
		children, err := parts()
		if err != nil {
			return nil, err
		}
		kind := "and"
		if item.Tag == 0xa1 {
			kind = "or"
		}
		filter := &Filter{Type: kind, Filters: []*Filter{}}
		for _, part := range children {
			inner, err := decodeFilter(part, depth+1, budget)
			if err != nil {
				return nil, err
			}
			filter.Filters = append(filter.Filters, inner)
		}
		return filter, nil
	case 0xa2:
		children, err := parts()
		if err != nil {
			return nil, err
		}
		if len(children) == 0 {
			return nil, berError("Empty not filter")
		}
		inner, err := decodeFilter(children[0], depth+1, budget)
		if err != nil {
			return nil, err
		}
		return &Filter{Type: "not", Inner: inner}, nil
	case 0xa3, 0xa5, 0xa6, 0xa8:
		children, err := parts()
		if err != nil {
			return nil, err
		}
		kind := map[int]string{0xa3: "equal", 0xa5: "greater", 0xa6: "less", 0xa8: "approx"}[item.Tag]
		attribute, err := ReadString(at(children, 0))
		if err != nil {
			return nil, err
		}
		value, err := ReadString(at(children, 1))
		if err != nil {
			return nil, err
		}
		return &Filter{Type: kind, Attribute: attribute, Value: value}, nil
	case 0xa4:
		children, err := parts()
		if err != nil {
			return nil, err
		}
		attribute, err := ReadString(at(children, 0))
		if err != nil {
			return nil, err
		}
		filter := &Filter{Type: "substrings", Attribute: attribute, Any: []string{}}
		substrings := at(children, 1)
		if substrings == nil || substrings.Tag != 0x30 {
			return nil, berError("Invalid substrings filter")
		}
		pieces, err := Children(substrings.Value)
		if err != nil {
			return nil, err
		}
		for _, part := range pieces {
			text := utf8Text(part.Value)
			switch part.Tag {
			case 0x80:
				filter.Initial = &text
			case 0x81:
				filter.Any = append(filter.Any, text)
			case 0x82:
				filter.Final = &text
			default:
				return nil, berError("Invalid substring")
			}
		}
		return filter, nil
	case 0x87:
		return &Filter{Type: "present", Attribute: utf8Text(item.Value)}, nil
	case 0xa9:
		children, err := parts()
		if err != nil {
			return nil, err
		}
		filter := &Filter{Type: "extensible"}
		for _, part := range children {
			switch part.Tag {
			case 0x81:
				filter.Rule, filter.HasRule = utf8Text(part.Value), true
			case 0x82:
				filter.Attribute, filter.HasAttribute = utf8Text(part.Value), true
			case 0x83:
				filter.Value = utf8Text(part.Value)
			case 0x84:
				flag, err := ReadBoolean(part, 0x84)
				if err != nil {
					return nil, err
				}
				filter.DnAttributes = flag
			}
		}
		return filter, nil
	}
	return nil, berError("Unknown filter choice 0x" + strconv.FormatInt(int64(item.Tag), 16))
}

// EncodeFilter is a filter's BER form.
func EncodeFilter(filter *Filter) []byte {
	switch filter.Type {
	case "and", "or":
		items := make([][]byte, len(filter.Filters))
		for i, inner := range filter.Filters {
			items[i] = EncodeFilter(inner)
		}
		tag := 0xa0
		if filter.Type == "or" {
			tag = 0xa1
		}
		return Set(items, tag)
	case "not":
		return Sequence([][]byte{EncodeFilter(filter.Inner)}, 0xa2)
	case "equal", "greater", "less", "approx":
		tag := map[string]int{"equal": 0xa3, "greater": 0xa5, "less": 0xa6, "approx": 0xa8}[filter.Type]
		return Sequence([][]byte{OctetString(filter.Attribute), OctetString(filter.Value)}, tag)
	case "substrings":
		var parts [][]byte
		if filter.Initial != nil {
			parts = append(parts, OctetString(*filter.Initial, 0x80))
		}
		for _, part := range filter.Any {
			parts = append(parts, OctetString(part, 0x81))
		}
		if filter.Final != nil {
			parts = append(parts, OctetString(*filter.Final, 0x82))
		}
		return Sequence([][]byte{OctetString(filter.Attribute), Sequence(parts)}, 0xa4)
	case "present":
		return OctetString(filter.Attribute, 0x87)
	case "extensible":
		var parts [][]byte
		if filter.HasRule && filter.Rule != "" {
			parts = append(parts, OctetString(filter.Rule, 0x81))
		}
		if filter.HasAttribute && filter.Attribute != "" {
			parts = append(parts, OctetString(filter.Attribute, 0x82))
		}
		parts = append(parts, OctetString(filter.Value, 0x83))
		if filter.DnAttributes {
			parts = append(parts, Boolean(true, 0x84))
		}
		return Sequence(parts, 0xa9)
	}
	return nil
}

var filterItem = regexp.MustCompile(`(?s)^([^=~<>:]+)(=|~=|>=|<=)(.*)$`)
var hexEscape = regexp.MustCompile(`\\[0-9a-fA-F]{2}`)

// unescapeFilter reads `\2a` escapes as bytes (possibly parts of one UTF-8 character); everything else is text.
func unescapeFilter(value string) string {
	var out []byte
	last := 0
	for _, match := range hexEscape.FindAllStringIndex(value, -1) {
		out = append(out, value[last:match[0]]...)
		parsed, _ := strconv.ParseUint(value[match[0]+1:match[1]], 16, 8)
		out = append(out, byte(parsed))
		last = match[1]
	}
	out = append(out, value[last:]...)
	return utf8Text(out)
}

// ParseFilter parses the RFC 4515 string form, e.g. `(&(objectClass=person)(|(uid=alice)(mail=*@acme.test)))`.
func ParseFilter(text string) (*Filter, error) {
	trimmed := core.JSTrim(text)
	if !strings.HasPrefix(trimmed, "(") {
		trimmed = "(" + trimmed + ")"
	}
	text = trimmed
	index := 0
	var parse func() (*Filter, error)
	parse = func() (*Filter, error) {
		if index >= len(text) || text[index] != '(' {
			return nil, berError("Expected (")
		}
		index++
		var head byte
		if index < len(text) {
			head = text[index]
		}
		var filter *Filter
		switch head {
		case '&', '|':
			index++
			kind := "and"
			if head == '|' {
				kind = "or"
			}
			filter = &Filter{Type: kind, Filters: []*Filter{}}
			for index < len(text) && text[index] == '(' {
				inner, err := parse()
				if err != nil {
					return nil, err
				}
				filter.Filters = append(filter.Filters, inner)
			}
		case '!':
			index++
			inner, err := parse()
			if err != nil {
				return nil, err
			}
			filter = &Filter{Type: "not", Inner: inner}
		default:
			end := strings.IndexByte(text[index:], ')')
			if end < 0 {
				return nil, berError("Expected )")
			}
			item := text[index : index+end]
			index += end
			match := filterItem.FindStringSubmatch(item)
			if match == nil {
				return nil, berError("Invalid filter item")
			}
			attribute, operator, raw := match[1], match[2], match[3]
			switch {
			case operator == "=" && raw == "*":
				filter = &Filter{Type: "present", Attribute: attribute}
			case operator == "=" && strings.Contains(raw, "*"):
				pieces := strings.Split(raw, "*")
				for i := range pieces {
					pieces[i] = unescapeFilter(pieces[i])
				}
				filter = &Filter{Type: "substrings", Attribute: attribute, Any: []string{}}
				if pieces[0] != "" {
					initial := pieces[0]
					filter.Initial = &initial
				}
				for _, part := range pieces[1 : len(pieces)-1] {
					if part != "" {
						filter.Any = append(filter.Any, part)
					}
				}
				if last := pieces[len(pieces)-1]; last != "" {
					filter.Final = &last
				}
			default:
				kind := map[string]string{"=": "equal", "~=": "approx", ">=": "greater", "<=": "less"}[operator]
				filter = &Filter{Type: kind, Attribute: attribute, Value: unescapeFilter(raw)}
			}
		}
		if index >= len(text) || text[index] != ')' {
			return nil, berError("Expected )")
		}
		index++
		return filter, nil
	}
	result, err := parse()
	if err != nil {
		return nil, err
	}
	if index != len(text) {
		return nil, berError("Trailing characters after the filter")
	}
	return result, nil
}

// EntryAttributes are an entry's attributes, keyed by lowercased attribute name.
type EntryAttributes map[string][]string

// MatchFilter evaluates a filter (RFC 4511 three-valued logic collapsed: Undefined counts as false).
func MatchFilter(filter *Filter, attributes EntryAttributes) bool {
	values := func(name string) []string { return attributes[core.JSLower(name)] }
	switch filter.Type {
	case "and":
		for _, item := range filter.Filters {
			if !MatchFilter(item, attributes) {
				return false
			}
		}
		return true
	case "or":
		for _, item := range filter.Filters {
			if MatchFilter(item, attributes) {
				return true
			}
		}
		return false
	case "not":
		return !MatchFilter(filter.Inner, attributes)
	case "present":
		return core.JSLower(filter.Attribute) == "objectclass" || len(values(filter.Attribute)) > 0
	case "equal", "approx":
		for _, value := range values(filter.Attribute) {
			if fold(value) == fold(filter.Value) {
				return true
			}
		}
		return false
	case "greater":
		for _, value := range values(filter.Attribute) {
			if compareUTF16(fold(value), fold(filter.Value)) >= 0 {
				return true
			}
		}
		return false
	case "less":
		for _, value := range values(filter.Attribute) {
			if compareUTF16(fold(value), fold(filter.Value)) <= 0 {
				return true
			}
		}
		return false
	case "substrings":
		for _, raw := range values(filter.Attribute) {
			if matchSubstrings(filter, fold(raw)) {
				return true
			}
		}
		return false
	case "extensible":
		// Only the default equality rule on a named attribute is supported; other rules match nothing.
		if (filter.HasRule && filter.Rule != "") || !filter.HasAttribute {
			return false
		}
		for _, value := range values(filter.Attribute) {
			if fold(value) == fold(filter.Value) {
				return true
			}
		}
		return false
	}
	return false
}

func matchSubstrings(filter *Filter, value string) bool {
	position := 0
	if filter.Initial != nil {
		initial := fold(*filter.Initial)
		if !strings.HasPrefix(value, initial) {
			return false
		}
		position = len(initial)
	}
	for _, part := range filter.Any {
		folded := fold(part)
		start := min(position, len(value))
		found := strings.Index(value[start:], folded)
		if found < 0 {
			return false
		}
		position = start + found + len(folded)
	}
	if filter.Final == nil {
		return true
	}
	final := fold(*filter.Final)
	return len(value)-len(final) >= position && strings.HasSuffix(value, final)
}
