package saml

// JavaScript built-ins the TypeScript package and its libraries lean on: Date.parse and toISOString, URLSearchParams,
// querystring.stringify, encodeURIComponent and xml2js's object model.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Better-IAM/better-iam/go/core"
)

// isoString is new Date(ms).toISOString().
func isoString(ms int64) string {
	t := time.UnixMilli(ms).UTC()
	year := t.Year()
	yearText := fmt.Sprintf("%04d", year)
	if year < 0 || year > 9999 {
		sign := "+"
		if year < 0 {
			sign = "-"
			year = -year
		}
		yearText = sign + fmt.Sprintf("%06d", year)
	}
	return yearText + t.Format("-01-02T15:04:05.000Z")
}

// dateParse is Date.parse: the ECMAScript date-time string format (date-only forms are UTC, date-time forms without
// an offset local time) and the toUTCString / toString forms; anything else is NaN.
func dateParse(s string) float64 {
	if ms, ok := parseISODate(s); ok {
		return ms
	}
	t := core.JSTrim(s)
	for _, layout := range []string{
		"Mon, 02 Jan 2006 15:04:05 GMT",
		"Mon, 2 Jan 2006 15:04:05 GMT",
		"Mon Jan 02 2006 15:04:05 GMT-0700",
		"Mon Jan 02 2006",
		"Jan 2, 2006",
		"January 2, 2006",
		"2 January 2006",
		"2006/01/02",
		"2006/1/2",
		"01/02/2006",
		"1/2/2006",
	} {
		value := t
		if layout == "Mon Jan 02 2006 15:04:05 GMT-0700" {
			if index := strings.Index(value, " ("); index > 0 {
				value = value[:index]
			}
		}
		if parsed, err := time.Parse(layout, value); err == nil {
			if !strings.Contains(layout, "GMT") {
				parsed = time.Date(parsed.Year(), parsed.Month(), parsed.Day(), 0, 0, 0, 0, time.Local)
			}
			ms := float64(parsed.UnixMilli())
			if math.Abs(ms) <= 8.64e15 {
				return ms
			}
			return math.NaN()
		}
	}
	return math.NaN()
}

func parseISODate(s string) (float64, bool) {
	i := 0
	digits := func(n int) (int, bool) {
		if i+n > len(s) {
			return 0, false
		}
		v := 0
		for k := 0; k < n; k++ {
			c := s[i+k]
			if c < '0' || c > '9' {
				return 0, false
			}
			v = v*10 + int(c-'0')
		}
		i += n
		return v, true
	}
	var year int
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		negative := s[i] == '-'
		i++
		y, ok := digits(6)
		if !ok || (negative && y == 0) {
			return 0, false
		}
		year = y
		if negative {
			year = -y
		}
	} else {
		y, ok := digits(4)
		if !ok {
			return 0, false
		}
		year = y
	}
	month, day := 1, 1
	hour, minute, second, millis := 0, 0, 0, 0
	dateOnly := true
	if i < len(s) && s[i] == '-' {
		i++
		m, ok := digits(2)
		if !ok || m < 1 || m > 12 {
			return 0, false
		}
		month = m
		if i < len(s) && s[i] == '-' {
			i++
			d, ok := digits(2)
			if !ok || d < 1 || d > 31 {
				return 0, false
			}
			day = d
		}
	}
	offset := 0
	hasOffset := false
	if i < len(s) && (s[i] == 'T' || s[i] == 't') {
		dateOnly = false
		i++
		h, ok := digits(2)
		if !ok || i >= len(s) || s[i] != ':' {
			return 0, false
		}
		i++
		mi, ok := digits(2)
		if !ok {
			return 0, false
		}
		hour, minute = h, mi
		if i < len(s) && s[i] == ':' {
			i++
			sec, ok := digits(2)
			if !ok {
				return 0, false
			}
			second = sec
			if i < len(s) && (s[i] == '.' || s[i] == ',') {
				i++
				start := i
				for i < len(s) && s[i] >= '0' && s[i] <= '9' {
					i++
				}
				if i == start {
					return 0, false
				}
				fraction := s[start:i]
				for len(fraction) < 3 {
					fraction += "0"
				}
				millis, _ = strconv.Atoi(fraction[:3])
			}
		}
		if hour > 24 || minute > 59 || second > 59 || (hour == 24 && (minute != 0 || second != 0 || millis != 0)) {
			return 0, false
		}
		if i < len(s) {
			switch s[i] {
			case 'Z', 'z':
				hasOffset = true
				i++
			case '+', '-':
				sign := 1
				if s[i] == '-' {
					sign = -1
				}
				i++
				oh, ok := digits(2)
				if !ok || i >= len(s) || s[i] != ':' {
					return 0, false
				}
				i++
				om, ok := digits(2)
				if !ok || oh > 23 || om > 59 {
					return 0, false
				}
				offset = sign * (oh*60 + om)
				hasOffset = true
			}
		}
	}
	if i != len(s) {
		return 0, false
	}
	daysIn := time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if day > daysIn {
		return 0, false
	}
	location := time.UTC
	if !dateOnly && !hasOffset {
		location = time.Local
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, millis*int(time.Millisecond), location)
	ms := float64(t.UnixMilli()) - float64(offset)*60000
	if math.Abs(ms) > 8.64e15 {
		return 0, false
	}
	return ms, true
}

// randomUUID is crypto.randomUUID().
func randomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// percentEncode encodes every byte of s outside keep as %XX (uppercase).
func percentEncode(s string, keep func(byte) bool, spacePlus bool) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case keep(c):
			out.WriteByte(c)
		case c == ' ' && spacePlus:
			out.WriteByte('+')
		default:
			out.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return out.String()
}

func alnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }

// encodeURIComponent is the JavaScript built-in (lone surrogates cannot occur in Go strings).
func encodeURIComponent(s string) string {
	return percentEncode(toWellFormed(s), func(c byte) bool { return alnum(c) || strings.IndexByte("-_.!~*'()", c) >= 0 }, false)
}

// formEncode is the application/x-www-form-urlencoded serializer URLSearchParams uses.
func formEncode(s string) string {
	return percentEncode(toWellFormed(s), func(c byte) bool { return alnum(c) || strings.IndexByte("*-._", c) >= 0 }, true)
}

func toWellFormed(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

// searchParams is URLSearchParams: ordered name/value pairs.
type searchParams struct{ pairs [][2]string }

// parseSearchParams is new URLSearchParams(query) (a leading "?" is skipped).
func parseSearchParams(query string) *searchParams {
	query = strings.TrimPrefix(query, "?")
	params := &searchParams{}
	for _, part := range strings.Split(query, "&") {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		params.pairs = append(params.pairs, [2]string{formDecode(name), formDecode(value)})
	}
	return params
}

// formDecode is the application/x-www-form-urlencoded percent-decoding ("+" is a space, bad escapes stay as they are).
func formDecode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			v, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			out = append(out, byte(v))
			i += 2
			continue
		}
		out = append(out, s[i])
	}
	return decodeUTF8(out)
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// Get is URLSearchParams#get.
func (p *searchParams) Get(name string) (string, bool) {
	for _, pair := range p.pairs {
		if pair[0] == name {
			return pair[1], true
		}
	}
	return "", false
}

// GetAll is URLSearchParams#getAll.
func (p *searchParams) GetAll(name string) []string {
	var values []string
	for _, pair := range p.pairs {
		if pair[0] == name {
			values = append(values, pair[1])
		}
	}
	return values
}

// Set is URLSearchParams#set.
func (p *searchParams) Set(name, value string) {
	kept := p.pairs[:0:0]
	found := false
	for _, pair := range p.pairs {
		if pair[0] != name {
			kept = append(kept, pair)
			continue
		}
		if !found {
			kept = append(kept, [2]string{name, value})
			found = true
		}
	}
	if !found {
		kept = append(kept, [2]string{name, value})
	}
	p.pairs = kept
}

// String is URLSearchParams#toString.
func (p *searchParams) String() string {
	parts := make([]string, len(p.pairs))
	for i, pair := range p.pairs {
		parts[i] = formEncode(pair[0]) + "=" + formEncode(pair[1])
	}
	return strings.Join(parts, "&")
}

// urlWithSearch serializes u with its query replaced by search ("" removes it), keeping any fragment.
func urlWithSearch(u *url.URL, search string) string {
	copied := *u
	copied.RawQuery = ""
	copied.ForceQuery = false
	copied.Fragment = ""
	copied.RawFragment = ""
	href := copied.String()
	if search != "" {
		href += "?" + search
	}
	if u.Fragment != "" || u.RawFragment != "" {
		href += "#" + u.EscapedFragment()
	}
	return href
}

// querystringStringify is Node's querystring.stringify for string values.
func querystringStringify(pairs [][2]string) string {
	parts := make([]string, len(pairs))
	for i, pair := range pairs {
		parts[i] = encodeURIComponent(pair[0]) + "=" + encodeURIComponent(pair[1])
	}
	return strings.Join(parts, "&")
}

// --- xml2js (explicitRoot, explicitCharkey, stripPrefix) ---------------------------------------------------------

// stripPrefix is xml2js.processors.stripPrefix.
func stripPrefix(name string) string {
	if strings.HasPrefix(name, "xmlns") {
		return name
	}
	if index := strings.LastIndexByte(name, ':'); index >= 0 {
		return name[index+1:]
	}
	return name
}

// xml2jsValue is the value xml2js gives an element: an object (`$` attributes, `_` text, child arrays by name) or,
// for an element with nothing but whitespace, that whitespace as a string.
func xml2jsValue(node *Node) (any, error) {
	obj := core.NewObject("_", "")
	if len(node.Attrs) > 0 {
		attrs := core.NewObject()
		for _, attr := range node.Attrs {
			attrs.Set(attr.Name, attr.Value)
		}
		obj.Set("$", attrs)
	}
	text := ""
	cdata := false
	for _, child := range node.Children {
		switch child.Type {
		case TextNode:
			text += child.Data
		case CDATANode:
			text += child.Data
			cdata = true
		case ElementNode:
			value, err := xml2jsValue(child)
			if err != nil {
				return nil, err
			}
			name := stripPrefix(child.TagName)
			if name == "_" {
				return nil, fmt.Errorf("obj[charkey].match is not a function")
			}
			existing, ok := obj.Lookup(name)
			switch {
			case !ok:
				obj.Set(name, []any{value})
			default:
				list, isList := existing.([]any)
				if !isList {
					list = []any{existing}
				}
				obj.Set(name, append(list, value))
			}
		}
	}
	if isJSWhitespace(text) && !cdata {
		obj.Delete("_")
		if obj.Len() == 0 {
			return text, nil
		}
		return obj, nil
	}
	obj.Set("_", text)
	return obj, nil
}

// xml2jsRoot is parseXml2JsFromString: `{ <root name>: value }`.
func xml2jsRoot(xml string) (*core.Object, error) {
	doc, err := ParseXML(xml)
	if err != nil {
		return nil, err
	}
	root := doc.DocumentElement()
	value, err := xml2jsValue(root)
	if err != nil {
		return nil, err
	}
	return core.NewObject(stripPrefix(root.TagName), value), nil
}

// member is `value[key]` for an xml2js value: objects have members, strings and absent values none.
func member(value any, key string) any {
	if object, ok := value.(*core.Object); ok && object != nil {
		return object.Get(key)
	}
	return core.Undefined
}

// first is `value?.[0]` for an xml2js child array.
func first(value any) any {
	if list, ok := value.([]any); ok && len(list) > 0 {
		return list[0]
	}
	return core.Undefined
}

// textOf is `value._` read as a string ("" when absent or not a string).
func textOf(value any) string {
	text, _ := member(value, "_").(string)
	return text
}

// truthy is JavaScript truthiness for the values xml2js and profiles hold.
func truthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return v != ""
	case bool:
		return v
	case float64:
		return v != 0 && !math.IsNaN(v)
	}
	return !core.IsUndefined(value)
}
