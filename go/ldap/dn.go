package ldap

// Port of packages/ldap/src/dn.ts: distinguished names (RFC 4514): parsing with escapes (`\,`, `\2C`), quoting of
// values, and a normalized form for comparisons (attribute types and values lowercased, insignificant spaces trimmed).
// Multi-valued RDNs (`+`) are kept in order.

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// DnError is a malformed DN.
type DnError struct{ Message string }

func (e *DnError) Error() string { return e.Message }

func dnError(message string) error { return &DnError{Message: message} }

// Rdn is one attribute type/value pair of an RDN.
type Rdn struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

var dnSpecial = map[rune]bool{',': true, '+': true, '"': true, '\\': true, '<': true, '>': true, ';': true, '=': true}

// EscapeDnValue escapes an attribute value for use in a DN.
func EscapeDnValue(value string) string {
	var out strings.Builder
	runes := []rune(value)
	for index, char := range runes {
		switch {
		case dnSpecial[char]:
			out.WriteString("\\" + string(char))
		case char < 0x20 || char == 0x7f:
			hex := strconv.FormatInt(int64(char), 16)
			if len(hex) < 2 {
				hex = "0" + hex
			}
			out.WriteString("\\" + hex)
		case (index == 0 && (char == ' ' || char == '#')) || (index == len(runes)-1 && char == ' '):
			out.WriteString("\\" + string(char))
		default:
			out.WriteRune(char)
		}
	}
	return out.String()
}

var attributeType = regexp.MustCompile(`^(?:[a-zA-Z][a-zA-Z0-9-]*|[0-9]+(?:\.[0-9]+)*)$`)

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// ParseDn parses a DN into RDNs (each a list of type/value pairs; most have one). The empty DN is the root.
func ParseDn(dn string) ([][]Rdn, error) {
	if core.UTF16Len(dn) > 4096 {
		return nil, dnError("Invalid DN")
	}
	var rdns [][]Rdn
	if core.JSTrim(dn) == "" {
		return rdns, nil
	}
	index := 0
	var current []Rdn
	var pending []byte
	flush := func() string {
		if len(pending) == 0 {
			return ""
		}
		text := utf8Text(pending)
		pending = pending[:0]
		return text
	}
	char := func(i int) (byte, bool) {
		if i < len(dn) {
			return dn[i], true
		}
		return 0, false
	}
	for index <= len(dn) {
		// Attribute type.
		for c, ok := char(index); ok && c == ' '; c, ok = char(index) {
			index++
		}
		equals := -1
		if index <= len(dn) {
			if found := strings.IndexByte(dn[index:], '='); found >= 0 {
				equals = index + found
			}
		}
		if equals < 0 {
			return nil, dnError("Missing = in DN")
		}
		kind := core.JSTrim(dn[index:equals])
		if !attributeType.MatchString(kind) {
			return nil, dnError("Invalid attribute type in DN")
		}
		index = equals + 1
		for c, ok := char(index); ok && c == ' '; c, ok = char(index) {
			index++
		}
		// Attribute value.
		var value strings.Builder
		if c, ok := char(index); ok && c == '"' {
			index++
			for index < len(dn) && dn[index] != '"' {
				if dn[index] == '\\' {
					index++
				}
				if index < len(dn) {
					value.WriteByte(dn[index])
				}
				index++
			}
			if c, ok := char(index); !ok || c != '"' {
				return nil, dnError("Unterminated quoted value")
			}
			index++
			for c, ok := char(index); ok && c == ' '; c, ok = char(index) {
				index++
			}
		} else {
			trailing := 0
			for index < len(dn) && dn[index] != ',' && dn[index] != '+' && dn[index] != ';' {
				c := dn[index]
				if c == '\\' {
					if index+3 <= len(dn) && isHexByte(dn[index+1]) && isHexByte(dn[index+2]) {
						parsed, _ := strconv.ParseUint(dn[index+1:index+3], 16, 8)
						pending = append(pending, byte(parsed))
						index += 3
					} else if index+1 < len(dn) {
						value.WriteString(flush())
						value.WriteByte(dn[index+1])
						index += 2
					} else {
						return nil, dnError("Dangling escape in DN")
					}
					trailing = 0
					continue
				}
				value.WriteString(flush())
				value.WriteByte(c)
				if c == ' ' {
					trailing++
				} else {
					trailing = 0
				}
				index++
			}
			value.WriteString(flush())
			if trailing > 0 {
				text := value.String()
				value.Reset()
				value.WriteString(text[:len(text)-trailing])
			}
		}
		current = append(current, Rdn{Type: kind, Value: value.String()})
		separator, hasSeparator := char(index)
		index++
		if hasSeparator && separator == '+' {
			continue
		}
		rdns = append(rdns, current)
		current = nil
		if !hasSeparator {
			break
		}
	}
	return rdns, nil
}

// FormatDn formats RDNs as a DN string.
func FormatDn(rdns [][]Rdn) string {
	parts := make([]string, len(rdns))
	for i, rdn := range rdns {
		values := make([]string, len(rdn))
		for j, part := range rdn {
			values[j] = part.Type + "=" + EscapeDnValue(part.Value)
		}
		parts[i] = strings.Join(values, "+")
	}
	return strings.Join(parts, ",")
}

// fold is `value.trim().replace(/\s+/g, ' ').toLowerCase()`.
func fold(value string) string {
	return core.JSLower(collapseSpaces(core.JSTrim(value)))
}

func isJSSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\f', '\v', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

func collapseSpaces(value string) string {
	var out strings.Builder
	space := false
	for _, r := range value {
		if isJSSpace(r) {
			if !space {
				out.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		out.WriteRune(r)
	}
	return out.String()
}

// NormalizeDn is the comparison form of a DN: lowercased, re-escaped, spaces normalized. It fails on malformed DNs.
func NormalizeDn(dn string) (string, error) {
	rdns, err := ParseDn(dn)
	if err != nil {
		return "", err
	}
	parts := make([]string, len(rdns))
	for i, rdn := range rdns {
		values := make([]string, len(rdn))
		for j, part := range rdn {
			values[j] = core.JSLower(part.Type) + "=" + EscapeDnValue(fold(part.Value))
		}
		sort.SliceStable(values, func(a, b int) bool { return compareUTF16(values[a], values[b]) < 0 })
		parts[i] = strings.Join(values, "+")
	}
	return strings.Join(parts, ","), nil
}

// normalizedRdns are the normalized RDN strings of a DN, leaf first.
func normalizedRdns(dn string) ([]string, error) {
	normalized, err := NormalizeDn(dn)
	if err != nil {
		return nil, err
	}
	if normalized == "" {
		return nil, nil
	}
	rdns, err := ParseDn(normalized)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(rdns))
	for i, rdn := range rdns {
		out[i] = FormatDn([][]Rdn{rdn})
	}
	return out, nil
}

// IsUnder reports whether dn equals base or lies below it, compared RDN by RDN, never as strings:
// `cn=a\,ou=people,dc=x` is not under `ou=people,dc=x`.
func IsUnder(dn, base string) (bool, error) {
	child, err := normalizedRdns(dn)
	if err != nil {
		return false, err
	}
	parent, err := normalizedRdns(base)
	if err != nil {
		return false, err
	}
	if len(parent) > len(child) {
		return false, nil
	}
	offset := len(child) - len(parent)
	for index, rdn := range parent {
		if child[offset+index] != rdn {
			return false, nil
		}
	}
	return true, nil
}

// DepthBelow is how many RDNs dn has below base (-1 when it is not under it).
func DepthBelow(dn, base string) (int, error) {
	under, err := IsUnder(dn, base)
	if err != nil || !under {
		return -1, err
	}
	child, err := normalizedRdns(dn)
	if err != nil {
		return -1, err
	}
	parent, err := normalizedRdns(base)
	if err != nil {
		return -1, err
	}
	return len(child) - len(parent), nil
}

// ParentDn is the normalized parent of a normalized DN ("" for a single RDN).
func ParentDn(dn string) (string, error) {
	rdns, err := ParseDn(dn)
	if err != nil {
		return "", err
	}
	if len(rdns) <= 1 {
		return "", nil
	}
	return NormalizeDn(FormatDn(rdns[1:]))
}

// compareUTF16 is JavaScript's `<` on strings.
func compareUTF16(a, b string) int {
	x, y := core.ToUTF16(a), core.ToUTF16(b)
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	return len(x) - len(y)
}
