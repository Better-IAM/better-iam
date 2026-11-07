package core

// JavaScript value semantics for records. The TypeScript implementation stores and compares records as JavaScript
// values: objects keep insertion order (with integer-like keys first, in ascending order), strings are UTF-16 and may
// hold unpaired surrogates, numbers are doubles, and `undefined` is distinct from `null`. This file reproduces those
// semantics so Go writes the same `data` column text as JSON.stringify and reads what TypeScript wrote unchanged.
//
// The value model used throughout package core (and by every port of a TypeScript `Record<string, unknown>`):
//
//	nil            JSON null
//	bool           true / false
//	float64        every number (JavaScript has no integers)
//	string         text, WTF-8 encoded: valid UTF-8 plus 3-byte encodings of unpaired surrogates (ED A0..BF xx)
//	[]any          arrays
//	*Object        objects (ordered as JavaScript orders them)
//	UndefinedType  JavaScript undefined (absent members, `{ field: undefined }` filters)

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// UndefinedType is the type of Undefined.
type UndefinedType struct{}

// Undefined stands for JavaScript's undefined: a member that is set to undefined, or (from Get) one that is absent.
var Undefined = UndefinedType{}

// IsUndefined reports whether v is Undefined.
func IsUndefined(v any) bool {
	_, ok := v.(UndefinedType)
	return ok
}

// Object is a JavaScript plain object: string keys in JavaScript property order (array-index keys such as "0" and
// "10" first, ascending; every other key in insertion order) mapped to values of the core value model.
type Object struct {
	keys    []string
	indexes int // the first `indexes` keys are array indexes, ascending
	values  map[string]any
}

// NewObject builds an object from key/value pairs: NewObject("id", "a", "tenantId", "t"). Values are normalized
// like Set.
func NewObject(pairs ...any) *Object {
	if len(pairs)%2 != 0 {
		panic("core.NewObject: odd number of arguments")
	}
	o := &Object{values: make(map[string]any, len(pairs)/2)}
	for index := 0; index < len(pairs); index += 2 {
		key, ok := pairs[index].(string)
		if !ok {
			panic("core.NewObject: keys must be strings")
		}
		o.Set(key, pairs[index+1])
	}
	return o
}

func (o *Object) init() {
	if o.values == nil {
		o.values = map[string]any{}
	}
}

// arrayIndex reports whether key is a canonical array index ("0", "1", ... "4294967294") and its value.
func arrayIndex(key string) (uint64, bool) {
	if key == "" || len(key) > 10 || (key[0] == '0' && len(key) > 1) {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	return n, n < 4294967295
}

// Len is the number of own keys.
func (o *Object) Len() int {
	if o == nil {
		return 0
	}
	return len(o.keys)
}

// Keys returns the keys in JavaScript order (Object.keys).
func (o *Object) Keys() []string {
	if o == nil {
		return nil
	}
	return append([]string(nil), o.keys...)
}

// Has reports whether the key is an own key (Object.hasOwn), whatever its value (Undefined included).
func (o *Object) Has(key string) bool {
	if o == nil {
		return false
	}
	_, ok := o.values[key]
	return ok
}

// Lookup returns the member and whether it exists.
func (o *Object) Lookup(key string) (any, bool) {
	if o == nil {
		return Undefined, false
	}
	value, ok := o.values[key]
	if !ok {
		return Undefined, false
	}
	return value, true
}

// Get returns the member, or Undefined when it is absent (`Object.hasOwn(o, key) ? o[key] : undefined`).
func (o *Object) Get(key string) any {
	value, _ := o.Lookup(key)
	return value
}

// String returns a string member.
func (o *Object) String(key string) (string, bool) {
	value, ok := o.Get(key).(string)
	return value, ok
}

// Number returns a number member.
func (o *Object) Number(key string) (float64, bool) {
	value, ok := o.Get(key).(float64)
	return value, ok
}

// Bool returns a boolean member.
func (o *Object) Bool(key string) (bool, bool) {
	value, ok := o.Get(key).(bool)
	return value, ok
}

// Object returns an object member.
func (o *Object) Object(key string) (*Object, bool) {
	value, ok := o.Get(key).(*Object)
	return value, ok && value != nil
}

// Array returns an array member.
func (o *Object) Array(key string) ([]any, bool) {
	value, ok := o.Get(key).([]any)
	return value, ok
}

// Set sets a member (appending a new key in JavaScript order) after normalizing the value: Go numbers become
// float64, slices []any, maps and structs objects (through encoding/json), json.RawMessage is parsed. Values that
// have no JSON form (functions, channels) are kept as they are and refused when written to a store.
func (o *Object) Set(key string, value any) *Object {
	return o.SetRaw(key, Normalize(value))
}

// SetRaw sets a member without normalizing the value.
func (o *Object) SetRaw(key string, value any) *Object {
	o.init()
	if _, exists := o.values[key]; exists {
		o.values[key] = value
		return o
	}
	o.values[key] = value
	if n, ok := arrayIndex(key); ok {
		at := sort.Search(o.indexes, func(i int) bool {
			m, _ := arrayIndex(o.keys[i])
			return m > n
		})
		o.keys = append(o.keys, "")
		copy(o.keys[at+1:], o.keys[at:])
		o.keys[at] = key
		o.indexes++
		return o
	}
	o.keys = append(o.keys, key)
	return o
}

// Delete removes a member.
func (o *Object) Delete(key string) {
	if o == nil {
		return
	}
	if _, ok := o.values[key]; !ok {
		return
	}
	delete(o.values, key)
	for index, item := range o.keys {
		if item == key {
			o.keys = append(o.keys[:index], o.keys[index+1:]...)
			if index < o.indexes {
				o.indexes--
			}
			break
		}
	}
}

// Entries calls fn for each member in JavaScript order (Object.entries); fn returning false stops.
func (o *Object) Entries(fn func(key string, value any) bool) {
	if o == nil {
		return
	}
	for _, key := range append([]string(nil), o.keys...) {
		value, ok := o.values[key]
		if !ok {
			continue
		}
		if !fn(key, value) {
			return
		}
	}
}

// Clone returns a deep copy.
func (o *Object) Clone() *Object {
	if o == nil {
		return nil
	}
	out := &Object{keys: append([]string(nil), o.keys...), indexes: o.indexes, values: make(map[string]any, len(o.values))}
	for key, value := range o.values {
		out.values[key] = CloneValue(value)
	}
	return out
}

// Assign copies every member of the other objects onto o, in order (Object.assign / spread), and returns o.
func (o *Object) Assign(others ...*Object) *Object {
	o.init()
	for _, other := range others {
		other.Entries(func(key string, value any) bool {
			o.SetRaw(key, value)
			return true
		})
	}
	return o
}

// Spread returns a shallow copy of o with the other objects' members applied (`{ ...o, ...others }`).
func (o *Object) Spread(others ...*Object) *Object {
	out := &Object{values: map[string]any{}}
	out.Assign(o)
	return out.Assign(others...)
}

// CloneValue deep-copies a value of the core model.
func CloneValue(value any) any {
	switch v := value.(type) {
	case *Object:
		return v.Clone()
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = CloneValue(item)
		}
		return out
	default:
		return v
	}
}

// MarshalJSON writes the object as JSON.stringify would.
func (o *Object) MarshalJSON() ([]byte, error) {
	text, _, err := Stringify(o)
	return []byte(text), err
}

// UnmarshalJSON reads the object as JSON.parse would.
func (o *Object) UnmarshalJSON(data []byte) error {
	value, err := ParseJSON(data)
	if err != nil {
		return err
	}
	parsed, ok := value.(*Object)
	if !ok {
		return errors.New("core: JSON value is not an object")
	}
	*o = *parsed
	return nil
}

// --- normalization -------------------------------------------------------------------------------------------------

// Normalize converts a Go value into the core value model (see the package documentation in json.go). Model values
// are returned as they are; Go numbers become float64; slices and arrays become []any; map[string]T and structs are
// converted through encoding/json (map keys sorted, struct fields in declaration order). Functions, channels and
// complex numbers have no JSON form and are returned unchanged (stores refuse them, as TypeScript refuses them).
func Normalize(value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case UndefinedType, bool, string, float64, *Object:
		return v
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = Normalize(item)
		}
		return out
	case Object:
		copy := v
		return &copy
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int8:
		return float64(v)
	case int16:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case uint:
		return float64(v)
	case uint8:
		return float64(v)
	case uint16:
		return float64(v)
	case uint32:
		return float64(v)
	case uint64:
		return float64(v)
	case json.Number:
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return v
		}
		return f
	case json.RawMessage:
		parsed, err := ParseJSON(v)
		if err != nil {
			return v
		}
		return parsed
	case []string:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = item
		}
		return out
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := &Object{values: make(map[string]any, len(v))}
		for _, key := range keys {
			out.SetRaw(key, Normalize(v[key]))
		}
		return out
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Func, reflect.Chan, reflect.Complex64, reflect.Complex128, reflect.UnsafePointer:
		return value
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil
		}
		if rv.Type().Elem().Kind() != reflect.Uint8 {
			out := make([]any, rv.Len())
			for index := range out {
				out[index] = Normalize(rv.Index(index).Interface())
			}
			return out
		}
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return value
	}
	parsed, err := ParseJSON(bytes.TrimSpace(buffer.Bytes()))
	if err != nil {
		return value
	}
	return parsed
}

// ToRecord converts a Go value (a struct with json tags, a map, an *Object) into an *Object.
func ToRecord(value any) (*Object, error) {
	switch v := Normalize(value).(type) {
	case *Object:
		return v, nil
	default:
		return nil, NewIamError("INVALID_RECORD", "Record must be an object")
	}
}

// FromRecord decodes a model value into a Go value (struct, map, slice) through its JSON text.
func FromRecord(value any, out any) error {
	text, ok, err := Stringify(value)
	if err != nil {
		return err
	}
	if !ok {
		text = "null"
	}
	return json.Unmarshal([]byte(text), out)
}

// --- strings: WTF-8 and UTF-16 ------------------------------------------------------------------------------------

// decodeUnit decodes one code point at s[i]: valid UTF-8, or a WTF-8 surrogate (returned as the code unit), or
// U+FFFD for an invalid byte.
func decodeUnit(s string, i int) (rune, int) {
	c := s[i]
	if c < utf8.RuneSelf {
		return rune(c), 1
	}
	if c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2]&0xC0 == 0x80 {
		return 0xD000 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F), 3
	}
	r, size := utf8.DecodeRuneInString(s[i:])
	return r, size
}

// ToUTF16 returns the UTF-16 code units of a (WTF-8) string, as JavaScript holds it.
func ToUTF16(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		r, size := decodeUnit(s, i)
		i += size
		if r >= 0x10000 {
			high, low := utf16.EncodeRune(r)
			out = append(out, uint16(high), uint16(low))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

// FromUTF16 builds a (WTF-8) string from UTF-16 code units: pairs become one code point, unpaired surrogates are
// kept as WTF-8 surrogate sequences (String.fromCharCode).
func FromUTF16(units []uint16) string {
	var b strings.Builder
	b.Grow(len(units))
	for i := 0; i < len(units); i++ {
		unit := units[i]
		if unit >= 0xD800 && unit <= 0xDBFF && i+1 < len(units) && units[i+1] >= 0xDC00 && units[i+1] <= 0xDFFF {
			b.WriteRune(utf16.DecodeRune(rune(unit), rune(units[i+1])))
			i++
			continue
		}
		if unit >= 0xD800 && unit <= 0xDFFF {
			b.WriteByte(0xED)
			b.WriteByte(byte(0x80 | (unit>>6)&0x3F))
			b.WriteByte(byte(0x80 | unit&0x3F))
			continue
		}
		b.WriteRune(rune(unit))
	}
	return b.String()
}

// UTF16Len is the JavaScript `length` of a string: its count of UTF-16 code units.
func UTF16Len(s string) int {
	n := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			n++
			i++
			continue
		}
		r, size := decodeUnit(s, i)
		i += size
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// CodePoints splits a string as JavaScript's string iterator does (`[...value]`): code points, with each unpaired
// surrogate as its own element.
func CodePoints(s string) []string {
	out := make([]string, 0, len(s))
	for i := 0; i < len(s); {
		_, size := decodeUnit(s, i)
		out = append(out, s[i:i+size])
		i += size
	}
	return out
}

// hasSurrogateUnit reports whether the string holds a UTF-16 surrogate code unit: an astral character (encoded as a
// pair in UTF-16) or an unpaired surrogate. It is the JavaScript test /[\uD800-\uDFFF]/ without the u flag.
func hasSurrogateUnit(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0xF0 {
			return true
		}
		if c == 0xED && i+1 < len(s) && s[i+1] >= 0xA0 {
			return true
		}
	}
	return false
}

// jsSpace reports whether r is JavaScript whitespace or a line terminator (String.prototype.trim, /\s/).
func jsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// JSTrim is String.prototype.trim.
func JSTrim(s string) string {
	start := 0
	for start < len(s) {
		r, size := decodeUnit(s, start)
		if !jsSpace(r) {
			break
		}
		start += size
	}
	end := len(s)
	for end > start {
		r, size := utf8.DecodeLastRuneInString(s[start:end])
		if !jsSpace(r) || r == utf8.RuneError {
			break
		}
		end -= size
	}
	return s[start:end]
}

// hasJSSpace reports whether the string contains JavaScript whitespace (/\s/.test).
func hasJSSpace(s string) bool {
	for i := 0; i < len(s); {
		r, size := decodeUnit(s, i)
		if jsSpace(r) {
			return true
		}
		i += size
	}
	return false
}

// cased reports whether r has the Unicode Cased property (approximately).
func cased(r rune) bool {
	return unicode.IsUpper(r) || unicode.IsLower(r) || unicode.IsTitle(r) || unicode.Is(unicode.Other_Lowercase, r) || unicode.Is(unicode.Other_Uppercase, r)
}

// caseIgnorable reports whether r has the Unicode Case_Ignorable property (approximately).
func caseIgnorable(r rune) bool {
	switch r {
	case '\'', '.', ':', '^', '`', 0xAD, 0xB7, 0x2018, 0x2019, 0x2024, 0x2027:
		return true
	}
	return unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf, unicode.Lm, unicode.Sk)
}

// JSLower is String.prototype.toLowerCase: full Unicode lowercase mapping, including U+0130 and the final sigma rule.
func JSLower(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToLower(s)
	}
	type unit struct {
		r    rune
		text string
	}
	units := make([]unit, 0, len(s))
	for i := 0; i < len(s); {
		r, size := decodeUnit(s, i)
		units = append(units, unit{r, s[i : i+size]})
		i += size
	}
	var b strings.Builder
	for index, item := range units {
		r := item.r
		switch {
		case r >= 0xD800 && r <= 0xDFFF, r == utf8.RuneError && item.text != "�":
			b.WriteString(item.text)
		case r == 0x130:
			b.WriteString("i̇")
		case r == 0x3A3:
			before := false
			for j := index - 1; j >= 0; j-- {
				if caseIgnorable(units[j].r) {
					continue
				}
				before = cased(units[j].r)
				break
			}
			after := false
			for j := index + 1; j < len(units); j++ {
				if caseIgnorable(units[j].r) {
					continue
				}
				after = cased(units[j].r)
				break
			}
			if before && !after {
				b.WriteRune(0x3C2)
			} else {
				b.WriteRune(0x3C3)
			}
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// --- numbers ------------------------------------------------------------------------------------------------------

// NumberString formats a number as JavaScript's String(number) does (Number::toString, radix 10).
func NumberString(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	repr := strconv.FormatFloat(f, 'e', -1, 64) // d.ddddde±XX, shortest round trip
	mantissa, exponent, _ := strings.Cut(repr, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exp, _ := strconv.Atoi(exponent)
	k := len(digits)
	n := exp + 1
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	e := n - 1
	expSign := "+"
	if e < 0 {
		expSign = "-"
		e = -e
	}
	if k == 1 {
		return sign + digits + "e" + expSign + strconv.Itoa(e)
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + expSign + strconv.Itoa(e)
}

// IsSafeInteger is Number.isSafeInteger.
func IsSafeInteger(value any) bool {
	f, ok := value.(float64)
	return ok && !math.IsInf(f, 0) && f == math.Trunc(f) && math.Abs(f) <= 9007199254740991
}

// finiteNumber reports whether value is a finite number.
func finiteNumber(value any) (float64, bool) {
	f, ok := value.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// --- JSON.stringify ------------------------------------------------------------------------------------------------

// QuoteJSON is JSON.stringify of a string: the well-formed JSON.stringify escaping (\" \\ \b \f \n \r \t, other
// control characters and unpaired surrogates as lowercase \uXXXX, everything else unescaped).
func QuoteJSON(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	writeQuoted(&b, s)
	return b.String()
}

const hexDigits = "0123456789abcdef"

func writeQuoted(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				b.WriteString(`\"`)
			case '\\':
				b.WriteString(`\\`)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				if c < 0x20 {
					b.WriteString(`\u00`)
					b.WriteByte(hexDigits[c>>4])
					b.WriteByte(hexDigits[c&0xF])
				} else {
					b.WriteByte(c)
				}
			}
			i++
			continue
		}
		r, size := decodeUnit(s, i)
		if r >= 0xD800 && r <= 0xDFFF {
			b.WriteString(`\u`)
			b.WriteByte(hexDigits[r>>12&0xF])
			b.WriteByte(hexDigits[r>>8&0xF])
			b.WriteByte(hexDigits[r>>4&0xF])
			b.WriteByte(hexDigits[r&0xF])
		} else if r == utf8.RuneError && size == 1 {
			b.WriteString("�")
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	b.WriteByte('"')
}

// TypeError mirrors a JavaScript TypeError (thrown by JSON serialization and a few validators).
type TypeError struct{ Message string }

func (e *TypeError) Error() string { return e.Message }

// Stringify is JSON.stringify(value): ok is false when the value has no JSON form (undefined at the top level).
// Non-finite numbers become null, Undefined members are left out and Undefined array entries become null. Values
// outside the model are normalized first. Cycles fail with a TypeError.
func Stringify(value any) (text string, ok bool, err error) {
	var b strings.Builder
	w := stringifier{b: &b, path: map[any]bool{}}
	ok, err = w.write(value)
	if err != nil || !ok {
		return "", ok, err
	}
	return b.String(), true, nil
}

// MustStringify is Stringify for values known to be serializable; it panics otherwise.
func MustStringify(value any) string {
	text, _, err := Stringify(value)
	if err != nil {
		panic(err)
	}
	return text
}

type stringifier struct {
	b    *strings.Builder
	path map[any]bool
}

func (w *stringifier) write(value any) (bool, error) {
	switch v := value.(type) {
	case nil:
		w.b.WriteString("null")
	case UndefinedType:
		return false, nil
	case bool:
		if v {
			w.b.WriteString("true")
		} else {
			w.b.WriteString("false")
		}
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			w.b.WriteString("null")
		} else {
			w.b.WriteString(NumberString(v))
		}
	case string:
		writeQuoted(w.b, v)
	case []any:
		key := reflect.ValueOf(v).Pointer()
		if len(v) > 0 {
			if w.path[key] {
				return false, &TypeError{"Converting circular structure to JSON"}
			}
			w.path[key] = true
			defer delete(w.path, key)
		}
		w.b.WriteByte('[')
		for index, item := range v {
			if index > 0 {
				w.b.WriteByte(',')
			}
			written, err := w.write(item)
			if err != nil {
				return false, err
			}
			if !written {
				w.b.WriteString("null")
			}
		}
		w.b.WriteByte(']')
	case *Object:
		if v == nil {
			w.b.WriteString("null")
			return true, nil
		}
		if w.path[v] {
			return false, &TypeError{"Converting circular structure to JSON"}
		}
		w.path[v] = true
		defer delete(w.path, v)
		w.b.WriteByte('{')
		first := true
		for _, key := range v.keys {
			item := v.values[key]
			if !jsonRepresentable(item) {
				continue
			}
			if !first {
				w.b.WriteByte(',')
			}
			first = false
			writeQuoted(w.b, key)
			w.b.WriteByte(':')
			if _, err := w.write(item); err != nil {
				return false, err
			}
		}
		w.b.WriteByte('}')
	default:
		normalized := Normalize(value)
		if !modelValue(normalized) {
			// Functions and other values without a JSON form behave like undefined.
			return false, nil
		}
		return w.write(normalized)
	}
	return true, nil
}

func modelValue(value any) bool {
	switch value.(type) {
	case nil, UndefinedType, bool, float64, string, []any, *Object:
		return true
	}
	return false
}

// jsonRepresentable reports whether an object member is written by JSON.stringify (undefined and functions are not).
func jsonRepresentable(value any) bool {
	switch value.(type) {
	case UndefinedType:
		return false
	case nil, bool, float64, string, []any, *Object:
		return true
	}
	return modelValue(Normalize(value))
}

// --- JSON.parse ----------------------------------------------------------------------------------------------------

// SyntaxError mirrors JSON.parse's SyntaxError.
type SyntaxError struct{ Message string }

func (e *SyntaxError) Error() string { return e.Message }

// ParseJSON is JSON.parse: strict JSON, numbers as float64 (out-of-range numbers become ±Infinity), duplicate keys
// keep their first position and last value, \u escapes of unpaired surrogates become WTF-8 surrogates.
func ParseJSON(data []byte) (any, error) {
	p := parser{data: data}
	p.space()
	value, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.at < len(p.data) {
		return nil, p.fail("Unexpected non-whitespace character after JSON")
	}
	return value, nil
}

// ParseJSONString is ParseJSON over a string.
func ParseJSONString(text string) (any, error) { return ParseJSON([]byte(text)) }

type parser struct {
	data []byte
	at   int
}

func (p *parser) fail(message string) error {
	return &SyntaxError{fmt.Sprintf("%s at position %d", message, p.at)}
}

func (p *parser) space() {
	for p.at < len(p.data) {
		switch p.data[p.at] {
		case ' ', '\t', '\n', '\r':
			p.at++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (any, error) {
	if depth > 10000 {
		return nil, p.fail("Maximum nesting depth exceeded")
	}
	if p.at >= len(p.data) {
		return nil, p.fail("Unexpected end of JSON input")
	}
	switch c := p.data[p.at]; {
	case c == '{':
		p.at++
		object := &Object{values: map[string]any{}}
		p.space()
		if p.at < len(p.data) && p.data[p.at] == '}' {
			p.at++
			return object, nil
		}
		for {
			p.space()
			if p.at >= len(p.data) || p.data[p.at] != '"' {
				return nil, p.fail("Expected property name")
			}
			key, err := p.string()
			if err != nil {
				return nil, err
			}
			p.space()
			if p.at >= len(p.data) || p.data[p.at] != ':' {
				return nil, p.fail("Expected ':' after property name")
			}
			p.at++
			p.space()
			item, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			object.SetRaw(key, item)
			p.space()
			if p.at >= len(p.data) {
				return nil, p.fail("Unexpected end of JSON input")
			}
			if p.data[p.at] == ',' {
				p.at++
				continue
			}
			if p.data[p.at] == '}' {
				p.at++
				return object, nil
			}
			return nil, p.fail("Expected ',' or '}' after property value")
		}
	case c == '[':
		p.at++
		list := []any{}
		p.space()
		if p.at < len(p.data) && p.data[p.at] == ']' {
			p.at++
			return list, nil
		}
		for {
			p.space()
			item, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			list = append(list, item)
			p.space()
			if p.at >= len(p.data) {
				return nil, p.fail("Unexpected end of JSON input")
			}
			if p.data[p.at] == ',' {
				p.at++
				continue
			}
			if p.data[p.at] == ']' {
				p.at++
				return list, nil
			}
			return nil, p.fail("Expected ',' or ']' after array element")
		}
	case c == '"':
		return p.string()
	case c == 't':
		return p.literal("true", true)
	case c == 'f':
		return p.literal("false", false)
	case c == 'n':
		return p.literal("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return nil, p.fail("Unexpected token")
}

func (p *parser) literal(word string, value any) (any, error) {
	if !bytes.HasPrefix(p.data[p.at:], []byte(word)) {
		return nil, p.fail("Unexpected token")
	}
	p.at += len(word)
	return value, nil
}

func (p *parser) number() (any, error) {
	start := p.at
	if p.data[p.at] == '-' {
		p.at++
	}
	digits := func() int {
		n := 0
		for p.at < len(p.data) && p.data[p.at] >= '0' && p.data[p.at] <= '9' {
			p.at++
			n++
		}
		return n
	}
	if p.at < len(p.data) && p.data[p.at] == '0' {
		p.at++
	} else if digits() == 0 {
		return nil, p.fail("No number after minus sign")
	}
	if p.at < len(p.data) && p.data[p.at] == '.' {
		p.at++
		if digits() == 0 {
			return nil, p.fail("Unterminated fractional number")
		}
	}
	if p.at < len(p.data) && (p.data[p.at] == 'e' || p.data[p.at] == 'E') {
		p.at++
		if p.at < len(p.data) && (p.data[p.at] == '+' || p.data[p.at] == '-') {
			p.at++
		}
		if digits() == 0 {
			return nil, p.fail("Exponent part is missing a number")
		}
	}
	f, err := strconv.ParseFloat(string(p.data[start:p.at]), 64)
	if err != nil {
		var numErr *strconv.NumError
		if errors.As(err, &numErr) && errors.Is(numErr.Err, strconv.ErrRange) {
			return f, nil // ±Inf or 0, as JavaScript rounds
		}
		return nil, p.fail("Invalid number")
	}
	return f, nil
}

func hexValue(c byte) (uint16, bool) {
	switch {
	case c >= '0' && c <= '9':
		return uint16(c - '0'), true
	case c >= 'a' && c <= 'f':
		return uint16(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return uint16(c-'A') + 10, true
	}
	return 0, false
}

func (p *parser) string() (string, error) {
	p.at++ // opening quote
	var b strings.Builder
	var pending []uint16 // \u escapes not yet written, so surrogate pairs written as two escapes combine
	flush := func() {
		if len(pending) > 0 {
			b.WriteString(FromUTF16(pending))
			pending = pending[:0]
		}
	}
	for {
		if p.at >= len(p.data) {
			return "", p.fail("Unterminated string in JSON")
		}
		c := p.data[p.at]
		switch {
		case c == '"':
			p.at++
			flush()
			return b.String(), nil
		case c < 0x20:
			return "", p.fail("Bad control character in string literal")
		case c == '\\':
			p.at++
			if p.at >= len(p.data) {
				return "", p.fail("Unterminated string in JSON")
			}
			escape := p.data[p.at]
			p.at++
			if escape == 'u' {
				if p.at+4 > len(p.data) {
					return "", p.fail("Bad Unicode escape")
				}
				var unit uint16
				for i := 0; i < 4; i++ {
					h, ok := hexValue(p.data[p.at+i])
					if !ok {
						return "", p.fail("Bad Unicode escape")
					}
					unit = unit<<4 | h
				}
				p.at += 4
				pending = append(pending, unit)
				continue
			}
			var char byte
			switch escape {
			case '"', '\\', '/':
				char = escape
			case 'b':
				char = '\b'
			case 'f':
				char = '\f'
			case 'n':
				char = '\n'
			case 'r':
				char = '\r'
			case 't':
				char = '\t'
			default:
				return "", p.fail("Bad escaped character")
			}
			flush()
			b.WriteByte(char)
		default:
			// Raw text: a raw surrogate (WTF-8) next to an escaped one joins it as JavaScript would.
			if c == 0xED && p.at+2 < len(p.data) && p.data[p.at+1] >= 0xA0 && p.data[p.at+1] <= 0xBF {
				unit := 0xD000 | uint16(p.data[p.at+1]&0x3F)<<6 | uint16(p.data[p.at+2]&0x3F)
				pending = append(pending, unit)
				p.at += 3
				continue
			}
			flush()
			start := p.at
			for p.at < len(p.data) {
				d := p.data[p.at]
				if d == '"' || d == '\\' || d < 0x20 || (d == 0xED && p.at+1 < len(p.data) && p.data[p.at+1] >= 0xA0 && p.data[p.at+1] <= 0xBF) {
					break
				}
				p.at++
			}
			b.Write(p.data[start:p.at])
		}
	}
}

// --- equality --------------------------------------------------------------------------------------------------

// sameValue is JavaScript `===` over the model (objects and arrays by identity).
func strictEquals(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case UndefinedType:
		return IsUndefined(b)
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case *Object:
		y, ok := b.(*Object)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		return ok && len(x) > 0 && len(x) == len(y) && &x[0] == &y[0]
	}
	return false
}

// StrictEquals is JavaScript `===` over the core value model (objects and arrays compare by identity).
func StrictEquals(a, b any) bool { return strictEquals(a, b) }

// typeOf is JavaScript `typeof` over the model.
func typeOf(value any) string {
	switch value.(type) {
	case nil, *Object, []any:
		return "object"
	case UndefinedType:
		return "undefined"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	}
	return "object"
}
