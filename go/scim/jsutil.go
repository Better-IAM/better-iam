package scim

// JavaScript semantics the TypeScript package relies on implicitly (typeof, String(), Number(), truthiness, `<`,
// URI encoding, Date#toISOString, UTF-16 string lengths). Values follow the core value model (*core.Object, []any,
// float64, string, bool, nil, core.Undefined), exactly as the TypeScript code takes `unknown`.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"

	"github.com/Better-IAM/better-iam/go/core"
)

// jsFunction stands for a function value JavaScript finds through the prototype chain: `'constructor' in record` is
// true for every plain object, so `property(record, 'constructor')` answers Object itself.
type jsFunction struct{}

// objectConstructorSource is String(Object).
const objectConstructorSource = "function Object() { [native code] }"

// randomUUID is crypto.randomUUID(): a random (version 4) UUID in lowercase.
func randomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// randomBytes is crypto.randomBytes.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// base64url is Buffer#toString('base64url').
func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// wallClock is Date.now().
func wallClock() float64 { return float64(time.Now().UnixMilli()) }

// typeOf is JavaScript `typeof` over the model.
func typeOf(value any) string {
	switch value.(type) {
	case core.UndefinedType:
		return "undefined"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case jsFunction:
		return "function"
	}
	return "object"
}

// nullish is `value == null`.
func nullish(value any) bool { return value == nil || core.IsUndefined(value) }

// isObject is `!!value && typeof value === 'object' && !Array.isArray(value)`.
func isObject(value any) bool {
	o, ok := value.(*core.Object)
	return ok && o != nil
}

// truthy is JavaScript truthiness.
func truthy(value any) bool {
	switch v := value.(type) {
	case nil, core.UndefinedType:
		return false
	case bool:
		return v
	case float64:
		return v != 0 && !math.IsNaN(v)
	case string:
		return v != ""
	case *core.Object:
		return v != nil
	}
	return true
}

// member is `value?.[key]` for untrusted values (own members of an object; undefined otherwise).
func member(value any, key string) any {
	if o, ok := value.(*core.Object); ok && o != nil {
		return o.Get(key)
	}
	return core.Undefined
}

// jsString is String(value).
func jsString(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case core.UndefinedType:
		return "undefined"
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return core.NumberString(v)
	case string:
		return v
	case []any:
		parts := make([]string, len(v))
		for index, item := range v {
			if !nullish(item) {
				parts[index] = jsString(item)
			}
		}
		return strings.Join(parts, ",")
	case jsFunction:
		return objectConstructorSource
	}
	return "[object Object]"
}

// isInteger is Number.isInteger.
func isInteger(value any) bool {
	n, ok := value.(float64)
	return ok && !math.IsInf(n, 0) && !math.IsNaN(n) && math.Trunc(n) == n
}

// utf16Len is a string's JavaScript length.
func utf16Len(s string) int { return core.UTF16Len(s) }

// sliceUTF16 is String.prototype.slice(start, end) with non-negative bounds in UTF-16 units.
func sliceUTF16(s string, start, end int) string {
	units := core.ToUTF16(s)
	if end > len(units) {
		end = len(units)
	}
	if start > end {
		return ""
	}
	return core.FromUTF16(units[start:end])
}

// compareUTF16 compares strings by UTF-16 code units (JavaScript `<` on strings).
func compareUTF16(a, b string) int {
	if a == b {
		return 0
	}
	x, y := core.ToUTF16(a), core.ToUTF16(b)
	for index := 0; index < len(x) && index < len(y); index++ {
		if x[index] != y[index] {
			if x[index] < y[index] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(x) < len(y):
		return -1
	case len(x) > len(y):
		return 1
	}
	return 0
}

var (
	collatorMu sync.Mutex
	collator   = collate.New(language.Und)
)

// localeCompare is String.prototype.localeCompare without locales (ICU root collation).
func localeCompare(a, b string) int {
	collatorMu.Lock()
	defer collatorMu.Unlock()
	return collator.CompareString(a, b)
}

// jsSpace is the ECMAScript WhiteSpace and LineTerminator set (`\s`).
func jsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// hasJSSpace is /\s/.test(s).
func hasJSSpace(s string) bool {
	for _, r := range s {
		if jsSpace(r) {
			return true
		}
	}
	return false
}

// emailShaped is /^[^\s@]+@[^\s@]+\.[^\s@]+$/ (dotted) or /^[^\s@]+@[^\s@]+$/ (not dotted).
func emailShaped(value string, dotted bool) bool {
	if hasJSSpace(value) {
		return false
	}
	at := strings.IndexByte(value, '@')
	if at <= 0 || strings.IndexByte(value[at+1:], '@') >= 0 {
		return false
	}
	domain := value[at+1:]
	if domain == "" {
		return false
	}
	if !dotted {
		return true
	}
	for index := 1; index < len(domain)-1; index++ {
		if domain[index] == '.' {
			return true
		}
	}
	return false
}

// upperMethod is String.prototype.toUpperCase for the HTTP method names a bulk operation may give: ASCII letters, and
// the code points whose JavaScript uppercase mapping is ASCII (U+017F long s, U+0131 dotless i, U+00DF and the Latin
// ligatures). Any other code point maps to a non-ASCII result, which no method name equals.
func upperMethod(s string) string {
	var out strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			out.WriteRune(r - 'a' + 'A')
		case r == 0x17F:
			out.WriteByte('S')
		case r == 0x131:
			out.WriteByte('I')
		case r == 0xDF:
			out.WriteString("SS")
		case r == 0xFB00:
			out.WriteString("FF")
		case r == 0xFB01:
			out.WriteString("FI")
		case r == 0xFB02:
			out.WriteString("FL")
		case r == 0xFB03:
			out.WriteString("FFI")
		case r == 0xFB04:
			out.WriteString("FFL")
		case r == 0xFB05, r == 0xFB06:
			out.WriteString("ST")
		case r < utf8.RuneSelf:
			out.WriteRune(r)
		default:
			upper := unicode.ToUpper(r)
			if upper < utf8.RuneSelf {
				upper = r
			}
			out.WriteRune(upper)
		}
	}
	return out.String()
}

// errURIMalformed is the URIError encodeURIComponent and decodeURIComponent throw.
var errURIMalformed = errors.New("URI malformed")

const upperHex = "0123456789ABCDEF"

// encodeURIComponent is the global encodeURIComponent; a lone surrogate is a URIError.
func encodeURIComponent(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
				out.WriteByte(c)
			} else {
				out.WriteByte('%')
				out.WriteByte(upperHex[c>>4])
				out.WriteByte(upperHex[c&15])
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			return "", errURIMalformed
		}
		for _, b := range []byte(s[i : i+size]) {
			out.WriteByte('%')
			out.WriteByte(upperHex[b>>4])
			out.WriteByte(upperHex[b&15])
		}
		i += size
	}
	return out.String(), nil
}

// mustEncode is encodeURIComponent for values that cannot hold lone surrogates (identifiers this package created);
// a lone surrogate is percent-encoded as U+FFFD instead of failing.
func mustEncode(s string) string {
	encoded, err := encodeURIComponent(s)
	if err != nil {
		encoded, _ = encodeURIComponent(strings.ToValidUTF8(s, replacementChar))
	}
	return encoded
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// decodeURIComponent is the global decodeURIComponent: a malformed escape or an escape sequence that is not valid
// UTF-8 is a URIError.
func decodeURIComponent(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var out []byte
	for i := 0; i < len(s); {
		if s[i] != '%' {
			out = append(out, s[i])
			i++
			continue
		}
		readByte := func(at int) (byte, bool) {
			if at+2 >= len(s) || s[at] != '%' {
				return 0, false
			}
			high, ok1 := hexDigit(s[at+1])
			low, ok2 := hexDigit(s[at+2])
			if !ok1 || !ok2 {
				return 0, false
			}
			return high<<4 | low, true
		}
		first, ok := readByte(i)
		if !ok {
			return "", errURIMalformed
		}
		if first < 0x80 {
			out = append(out, first)
			i += 3
			continue
		}
		var need int
		switch {
		case first&0xE0 == 0xC0:
			need = 1
		case first&0xF0 == 0xE0:
			need = 2
		case first&0xF8 == 0xF0:
			need = 3
		default:
			return "", errURIMalformed
		}
		sequence := []byte{first}
		at := i + 3
		for k := 0; k < need; k++ {
			next, ok := readByte(at)
			if !ok || next&0xC0 != 0x80 {
				return "", errURIMalformed
			}
			sequence = append(sequence, next)
			at += 3
		}
		r, size := utf8.DecodeRune(sequence)
		if r == utf8.RuneError || size != len(sequence) {
			return "", errURIMalformed
		}
		out = append(out, sequence...)
		i = at
	}
	return string(out), nil
}

// formEncode is the application/x-www-form-urlencoded byte serializer URLSearchParams uses.
func formEncode(s string) string {
	var out strings.Builder
	for _, c := range []byte(strings.ToValidUTF8(s, replacementChar)) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '*', c == '-', c == '.', c == '_':
			out.WriteByte(c)
		case c == ' ':
			out.WriteByte('+')
		default:
			out.WriteByte('%')
			out.WriteByte(upperHex[c>>4])
			out.WriteByte(upperHex[c&15])
		}
	}
	return out.String()
}

// isoString is `new Date(ms).toISOString()`; an invalid time value is a RangeError.
func isoString(value any) (string, error) {
	ms, ok := value.(float64)
	if !ok {
		ms = jsNumber(value)
	}
	if math.IsNaN(ms) || math.IsInf(ms, 0) || math.Abs(ms) > 8.64e15 {
		return "", errors.New("Invalid time value")
	}
	ms = math.Trunc(ms)
	t := time.UnixMilli(int64(ms)).UTC()
	year := t.Year()
	yearText := ""
	switch {
	case year < 0:
		yearText = "-" + pad(-year, 6)
	case year > 9999:
		yearText = "+" + pad(year, 6)
	default:
		yearText = pad(year, 4)
	}
	return yearText + "-" + pad(int(t.Month()), 2) + "-" + pad(t.Day(), 2) + "T" + pad(t.Hour(), 2) + ":" +
		pad(t.Minute(), 2) + ":" + pad(t.Second(), 2) + "." + pad(t.Nanosecond()/1e6, 3) + "Z", nil
}

func pad(n, width int) string {
	s := strconv.Itoa(n)
	for len(s) < width {
		s = "0" + s
	}
	return s
}

// jsNumber is Number(value) for the values the package compares (numbers, booleans, null, undefined, strings).
func jsNumber(value any) float64 {
	switch v := value.(type) {
	case nil:
		return 0
	case core.UndefinedType:
		return math.NaN()
	case bool:
		if v {
			return 1
		}
		return 0
	case float64:
		return v
	case string:
		return stringToNumber(v)
	}
	return stringToNumber(jsString(value))
}

// stringToNumber is the StringToNumber abstract operation.
func stringToNumber(s string) float64 {
	text := core.JSTrim(s)
	if text == "" {
		return 0
	}
	switch text {
	case "Infinity", "+Infinity":
		return math.Inf(1)
	case "-Infinity":
		return math.Inf(-1)
	}
	if len(text) > 2 && text[0] == '0' {
		base := 0
		switch text[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base != 0 {
			value := 0.0
			for _, c := range text[2:] {
				var d int
				switch {
				case c >= '0' && c <= '9':
					d = int(c - '0')
				case c >= 'a' && c <= 'z':
					d = int(c-'a') + 10
				case c >= 'A' && c <= 'Z':
					d = int(c-'A') + 10
				default:
					return math.NaN()
				}
				if d >= base {
					return math.NaN()
				}
				value = value*float64(base) + float64(d)
			}
			return value
		}
	}
	if !decimalLiteral(text) {
		return math.NaN()
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		if numError, ok := err.(*strconv.NumError); ok && numError.Err == strconv.ErrRange {
			return value
		}
		return math.NaN()
	}
	return value
}

// decimalLiteral reports whether text is a StrDecimalLiteral.
func decimalLiteral(text string) bool {
	i := 0
	if i < len(text) && (text[i] == '+' || text[i] == '-') {
		i++
	}
	digits := 0
	for i < len(text) && text[i] >= '0' && text[i] <= '9' {
		i++
		digits++
	}
	if i < len(text) && text[i] == '.' {
		i++
		for i < len(text) && text[i] >= '0' && text[i] <= '9' {
			i++
			digits++
		}
	}
	if digits == 0 {
		return false
	}
	if i < len(text) && (text[i] == 'e' || text[i] == 'E') {
		i++
		if i < len(text) && (text[i] == '+' || text[i] == '-') {
			i++
		}
		exponent := 0
		for i < len(text) && text[i] >= '0' && text[i] <= '9' {
			i++
			exponent++
		}
		if exponent == 0 {
			return false
		}
	}
	return i == len(text)
}

// toPrimitive is ToPrimitive with the number hint over the model: objects become "[object Object]", arrays their
// joined elements, the Object constructor its source text.
func toPrimitive(value any) any {
	switch value.(type) {
	case *core.Object, []any, jsFunction:
		return jsString(value)
	}
	return value
}

// jsLess is the JavaScript `a < b` (the abstract relational comparison) over the model.
func jsLess(a, b any) bool {
	x, y := toPrimitive(a), toPrimitive(b)
	xs, xString := x.(string)
	ys, yString := y.(string)
	if xString && yString {
		return compareUTF16(xs, ys) < 0
	}
	nx, ny := jsNumber(x), jsNumber(y)
	return nx < ny
}

// headerGet is Headers#get: the values of a header joined with ", " (null when absent).
func headerGet(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	if strings.EqualFold(name, "cookie") {
		return strings.Join(values, "; "), true
	}
	return strings.Join(values, ", "), true
}

// utf8Bytes is Buffer.from(value): UTF-8 with every unpaired surrogate replaced by U+FFFD.
func utf8Bytes(s string) []byte {
	if !strings.Contains(s, "\xed") {
		return []byte(s)
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2]&0xC0 == 0x80 {
			out = append(out, 0xEF, 0xBF, 0xBD)
			i += 3
			continue
		}
		out = append(out, c)
		i++
	}
	return out
}

// decodeUTF8 is Buffer#toString('utf8'): each maximal subpart of an invalid sequence becomes one U+FFFD.
func decodeUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var out strings.Builder
	out.Grow(len(b))
	i := 0
	for i < len(b) {
		c := b[i]
		if c < 0x80 {
			out.WriteByte(c)
			i++
			continue
		}
		var need int
		lower, upper := byte(0x80), byte(0xBF)
		switch {
		case c >= 0xC2 && c <= 0xDF:
			need = 1
		case c >= 0xE0 && c <= 0xEF:
			need = 2
			if c == 0xE0 {
				lower = 0xA0
			} else if c == 0xED {
				upper = 0x9F
			}
		case c >= 0xF0 && c <= 0xF4:
			need = 3
			if c == 0xF0 {
				lower = 0x90
			} else if c == 0xF4 {
				upper = 0x8F
			}
		default:
			out.WriteString(replacementChar)
			i++
			continue
		}
		j := i + 1
		ok := true
		for k := 0; k < need; k++ {
			if j >= len(b) {
				ok = false
				break
			}
			d := b[j]
			if k == 0 {
				if d < lower || d > upper {
					ok = false
					break
				}
			} else if d < 0x80 || d > 0xBF {
				ok = false
				break
			}
			j++
		}
		if ok {
			out.Write(b[i:j])
		} else {
			out.WriteString(replacementChar)
		}
		i = j
	}
	return out.String()
}

// nodeBase64Decode is Buffer.from(value, 'base64'): both alphabets are accepted, characters outside them are skipped,
// decoding stops at the first '=', and leftover bits are dropped.
func nodeBase64Decode(s string) []byte {
	out := make([]byte, 0, len(s)*3/4)
	var acc uint32
	bits := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		var v byte
		switch {
		case c >= 'A' && c <= 'Z':
			v = c - 'A'
		case c >= 'a' && c <= 'z':
			v = c - 'a' + 26
		case c >= '0' && c <= '9':
			v = c - '0' + 52
		case c == '+' || c == '-':
			v = 62
		case c == '/' || c == '_':
			v = 63
		case c == '=':
			return out
		default:
			continue
		}
		acc = acc<<6 | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>uint(bits)))
		}
	}
	return out
}

// stringList converts strings to a model array.
func stringList(items []string) []any {
	out := make([]any, len(items))
	for index, item := range items {
		out[index] = item
	}
	return out
}

// uniqueStrings is [...new Set(items)].
func uniqueStrings(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

// containsString is Array.prototype.includes for strings.
func containsString(items []string, item string) bool {
	for _, candidate := range items {
		if candidate == item {
			return true
		}
	}
	return false
}

// replacementChar is U+FFFD.
var replacementChar = string(rune(0xFFFD))
