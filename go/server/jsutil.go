package server

// JavaScript semantics the TypeScript server relies on implicitly (typeof, String(), Number(), truthiness, `<` on
// strings, optional chaining over untrusted values). Validators in this package take values of the core value model
// (*core.Object, []any, float64, string, bool, nil, core.Undefined) exactly as the TypeScript validators take
// `unknown`, so a Go server refuses the same input with the same error.

import (
	"encoding/base64"
	"errors"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Better-IAM/better-iam/go/core"
)

// Function stands for a JavaScript function inside a model value: options values (OptionsValue) carry it where an
// option holds a callback, so the `typeof x !== 'function'` checks of the TypeScript validators read the same.
type Function struct{}

// maxSafeInteger is Number.MAX_SAFE_INTEGER.
const maxSafeInteger = 9007199254740991

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
	case Function, *Function:
		return "function"
	}
	return "object"
}

// isUndefined is `value === undefined`.
func isUndefined(value any) bool { return core.IsUndefined(value) }

// nullish is `value == null` (null or undefined).
func nullish(value any) bool { return value == nil || core.IsUndefined(value) }

// isPlainObject reports whether value is a non-null, non-array object.
func isPlainObject(value any) bool {
	o, ok := value.(*core.Object)
	return ok && o != nil
}

// isArray is Array.isArray.
func isArray(value any) bool {
	_, ok := value.([]any)
	return ok
}

// member is `value?.[key]` for untrusted values: a member of an object, or undefined for anything else.
func member(value any, key string) any {
	if o, ok := value.(*core.Object); ok && o != nil {
		return o.Get(key)
	}
	return core.Undefined
}

// coalesce is `value ?? fallback`.
func coalesce(value any, fallback any) any {
	if nullish(value) {
		return fallback
	}
	return value
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
	}
	return true
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
	case Function, *Function:
		return "function () { [native code] }"
	}
	return "[object Object]"
}

// jsNumber is Number(value).
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
	case []any:
		return stringToNumber(jsString(v))
	}
	return math.NaN()
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
			value, ok := parseRadix(text[2:], base)
			if !ok {
				return math.NaN()
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

func parseRadix(digits string, base int) (float64, bool) {
	if digits == "" {
		return 0, false
	}
	value := 0.0
	for _, c := range digits {
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'z':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'Z':
			d = int(c-'A') + 10
		default:
			return 0, false
		}
		if d >= base {
			return 0, false
		}
		value = value*float64(base) + float64(d)
	}
	return value, true
}

// decimalLiteral reports whether text is a StrDecimalLiteral: [+-] digits [. digits] [e [+-] digits], or .digits.
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

// utf16Len is a string's JavaScript length.
func utf16Len(s string) int { return core.UTF16Len(s) }

// hasControl is /[\u0000-\u001f]/.test(s).
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			return true
		}
	}
	return false
}

// compareUTF16 compares strings by UTF-16 code units (JavaScript `<`, Array.prototype.sort's default order).
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

// orderedSet is a JavaScript Set of strings: membership plus insertion order.
type orderedSet struct {
	items []string
	index map[string]int
}

func newOrderedSet(items ...string) *orderedSet {
	set := &orderedSet{index: map[string]int{}}
	for _, item := range items {
		set.Add(item)
	}
	return set
}

// Add appends the item unless it is already present.
func (s *orderedSet) Add(item string) {
	if _, ok := s.index[item]; ok {
		return
	}
	s.index[item] = len(s.items)
	s.items = append(s.items, item)
}

// Has reports membership.
func (s *orderedSet) Has(item string) bool {
	if s == nil {
		return false
	}
	_, ok := s.index[item]
	return ok
}

// Delete removes an item, keeping the order of the others.
func (s *orderedSet) Delete(item string) {
	position, ok := s.index[item]
	if !ok {
		return
	}
	s.items = append(s.items[:position], s.items[position+1:]...)
	delete(s.index, item)
	for i := position; i < len(s.items); i++ {
		s.index[s.items[i]] = i
	}
}

// Len is the set size.
func (s *orderedSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.items)
}

// Values returns the members in insertion order (a copy).
func (s *orderedSet) Values() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.items...)
}

// unique is `[...new Set(items)]`.
func unique(items []string) []string {
	return newOrderedSet(items...).Values()
}

// stringsOf converts a []string into a model array.
func stringsOf(items []string) []any {
	out := make([]any, len(items))
	for index, item := range items {
		out[index] = item
	}
	return out
}

// containsString is `items.includes(item)`.
func containsString(items []string, item string) bool {
	for _, candidate := range items {
		if candidate == item {
			return true
		}
	}
	return false
}

// invalidConfig is `new IamError('INVALID_CONFIG', message)`.
func invalidConfig(message string) *core.IamError { return core.NewIamError("INVALID_CONFIG", message) }

// invalidInput is `new IamError('INVALID_INPUT', message)`.
func invalidInput(message string) *core.IamError { return core.NewIamError("INVALID_INPUT", message) }

// notImplemented is the marked stub error of modules not ported yet (501).
func notImplemented(what string) *core.IamError {
	return core.NewIamError("NOT_IMPLEMENTED", what+" is not implemented in the Go port yet", 501)
}

// errorMessage is `(error as Error).message`.
func errorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// The byte-level helpers below are copies of go/auth/jsutil.go (unexported there).

// utf8Bytes is Buffer.from(value) / TextEncoder: UTF-8 with every unpaired surrogate replaced by U+FFFD.
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

// decodeUTF8 is the WHATWG UTF-8 decoder Node uses for Buffer#toString('utf8') and TextDecoder: each maximal
// subpart of an invalid sequence becomes one U+FFFD.
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
			out.WriteString("�")
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
			out.WriteString("�")
		}
		i = j
	}
	return out.String()
}

// base64url is Buffer#toString('base64url'): the URL-safe alphabet without padding.
func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// nodeBase64Decode is Buffer.from(value, 'base64' | 'base64url'): both alphabets are accepted, characters outside
// them are skipped, decoding stops at the first '=', and leftover bits are dropped.
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

// asIamError finds the IamError in an error chain (`error instanceof IamError`).
func asIamError(err error) (*core.IamError, bool) {
	var known *core.IamError
	if errors.As(err, &known) {
		return known, true
	}
	return nil, false
}
