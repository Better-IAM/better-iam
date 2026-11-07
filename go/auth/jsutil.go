package auth

// JavaScript and Node.js semantics the TypeScript implementation relies on implicitly: UTF-8 encoding of strings
// that may hold unpaired surrogates (Buffer.from(string)), Node's forgiving base64 decoder, the WHATWG UTF-8 decoder
// (Buffer#toString('utf8'), TextDecoder), Number(string), String(value), truthiness, encodeURIComponent and Date.
// Strings are WTF-8 (see core/json.go): unpaired surrogates are kept as 3-byte ED A0..BF xx sequences.

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Better-IAM/better-iam/go/core"
)

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

// jsSpace reports whether r is JavaScript whitespace or a line terminator (/\s/, String#trim).
func jsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// runes splits a WTF-8 string into code points; unpaired surrogates come back as their code unit value.
func runes(s string) []rune {
	out := make([]rune, 0, len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2]&0xC0 == 0x80 {
			out = append(out, 0xD000|rune(s[i+1]&0x3F)<<6|rune(s[i+2]&0x3F))
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		out = append(out, r)
		i += size
	}
	return out
}

// sliceUTF16 is String#slice(start, end) with non-negative bounds.
func sliceUTF16(s string, start, end int) string {
	units := core.ToUTF16(s)
	if end > len(units) {
		end = len(units)
	}
	if start > end {
		return ""
	}
	if start == 0 && end == len(units) {
		return s
	}
	return core.FromUTF16(units[start:end])
}

// jsNumber is Number(string).
func jsNumber(s string) float64 {
	t := core.JSTrim(s)
	if t == "" {
		return 0
	}
	if len(t) > 2 && t[0] == '0' {
		base := 0
		switch t[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base != 0 {
			digits := t[2:]
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
	switch t {
	case "Infinity", "+Infinity":
		return math.Inf(1)
	case "-Infinity":
		return math.Inf(-1)
	}
	// StrDecimalLiteral: digits with an optional fraction and exponent; no hex floats, no underscores, no "inf".
	body := t
	if body[0] == '+' || body[0] == '-' {
		body = body[1:]
	}
	if body == "" {
		return math.NaN()
	}
	seenDigit, seenDot, seenExp := false, false, false
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= '0' && c <= '9':
			seenDigit = true
		case c == '.' && !seenDot && !seenExp:
			seenDot = true
		case (c == 'e' || c == 'E') && seenDigit && !seenExp:
			seenExp = true
			if i+1 < len(body) && (body[i+1] == '+' || body[i+1] == '-') {
				i++
			}
			if i+1 >= len(body) {
				return math.NaN()
			}
		default:
			return math.NaN()
		}
	}
	if !seenDigit {
		return math.NaN()
	}
	value, err := strconv.ParseFloat(t, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return value
		}
		return math.NaN()
	}
	return value
}

// jsString is String(value) for values of the core model.
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
	case string:
		return v
	case float64:
		return core.NumberString(v)
	case []any:
		parts := make([]string, len(v))
		for index, item := range v {
			if item == nil || core.IsUndefined(item) {
				continue
			}
			parts[index] = jsString(item)
		}
		return strings.Join(parts, ",")
	case *core.Object:
		return "[object Object]"
	}
	return jsString(core.Normalize(value))
}

// truthy is JavaScript truthiness.
func truthy(value any) bool {
	switch v := value.(type) {
	case nil, core.UndefinedType:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case float64:
		return v != 0 && !math.IsNaN(v)
	case *core.Object:
		return v != nil
	}
	return true
}

// encodeURIComponent is the JavaScript global; unpaired surrogates (a URIError there) are encoded as U+FFFD.
func encodeURIComponent(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var b strings.Builder
	for _, c := range utf8Bytes(s) {
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte("0123456789ABCDEF"[c>>4])
		b.WriteByte("0123456789ABCDEF"[c&15])
	}
	return b.String()
}

// --- Date -----------------------------------------------------------------------------------------------------------

// maxDateMs is the largest absolute time value a JavaScript Date holds.
const maxDateMs = 8.64e15

// dateValid reports whether a time value is a valid Date (not NaN, within ±8.64e15 ms).
func dateValid(ms float64) bool {
	return !math.IsNaN(ms) && math.Abs(ms) <= maxDateMs
}

func dateTime(ms float64) time.Time {
	return time.UnixMilli(int64(ms)).UTC()
}

func yearString(year int, iso bool) string {
	if year >= 0 && year <= 9999 {
		return pad(year, 4)
	}
	if iso {
		sign := "+"
		if year < 0 {
			sign = "-"
			year = -year
		}
		return sign + pad(year, 6)
	}
	if year < 0 {
		return "-" + pad(-year, 4)
	}
	return strconv.Itoa(year)
}

func pad(n, width int) string {
	s := strconv.Itoa(n)
	for len(s) < width {
		s = "0" + s
	}
	return s
}

// isoString is new Date(ms).toISOString(); ms must be a valid time value.
func isoString(ms float64) string {
	ms = math.Trunc(ms)
	t := dateTime(ms)
	return yearString(t.Year(), true) + "-" + pad(int(t.Month()), 2) + "-" + pad(t.Day(), 2) + "T" +
		pad(t.Hour(), 2) + ":" + pad(t.Minute(), 2) + ":" + pad(t.Second(), 2) + "." + pad(t.Nanosecond()/1e6, 3) + "Z"
}

var weekdays = [...]string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
var months = [...]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

// utcString is new Date(ms).toUTCString(); ms must be a valid time value.
func utcString(ms float64) string {
	t := dateTime(math.Trunc(ms))
	return weekdays[t.Weekday()] + ", " + pad(t.Day(), 2) + " " + months[t.Month()-1] + " " + yearString(t.Year(), false) +
		" " + pad(t.Hour(), 2) + ":" + pad(t.Minute(), 2) + ":" + pad(t.Second(), 2) + " GMT"
}

// parseDate is new Date(string).getTime(): the ECMAScript date-time string format (date-only forms are UTC,
// date-time forms without an offset are local time), and the toUTCString / toString forms Date produces. Other
// implementation-specific forms V8 accepts read as NaN.
func parseDate(s string) float64 {
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
			if dateValid(ms) {
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
	hour, minute, second, millis := 0, 0, 0, 0
	location := time.UTC
	if i < len(s) && (s[i] == 'T' || s[i] == 't' || (s[i] == ' ' && i+1 < len(s))) {
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
			se, ok := digits(2)
			if !ok {
				return 0, false
			}
			second = se
			if i < len(s) && s[i] == '.' {
				i++
				start := i
				for i < len(s) && s[i] >= '0' && s[i] <= '9' {
					i++
				}
				fraction := s[start:i]
				if fraction == "" {
					return 0, false
				}
				for len(fraction) < 3 {
					fraction += "0"
				}
				millis, _ = strconv.Atoi(fraction[:3])
			}
		}
		if hour > 24 || minute > 59 || second > 59 || (hour == 24 && (minute != 0 || second != 0 || millis != 0)) {
			return 0, false
		}
		location = time.Local
		if i < len(s) {
			switch s[i] {
			case 'Z', 'z':
				location = time.UTC
				i++
			case '+', '-':
				sign := 1
				if s[i] == '-' {
					sign = -1
				}
				i++
				oh, ok := digits(2)
				if !ok {
					return 0, false
				}
				if i < len(s) && s[i] == ':' {
					i++
				}
				om, ok := digits(2)
				if !ok || oh > 23 || om > 59 {
					return 0, false
				}
				location = time.FixedZone("", sign*(oh*3600+om*60))
			}
		}
	}
	if i != len(s) {
		return 0, false
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, millis*1e6, location)
	ms := float64(t.UnixMilli())
	if !dateValid(ms) {
		return math.NaN(), true
	}
	return ms, true
}

// --- record access ----------------------------------------------------------------------------------------------------

// str returns a string member, or "" when it is absent or not a string.
func str(o *core.Object, key string) string {
	value, _ := o.String(key)
	return value
}

// num returns a number member and whether it is one.
func num(o *core.Object, key string) (float64, bool) {
	return o.Number(key)
}

// numOr returns a number member, or the fallback.
func numOr(o *core.Object, key string, fallback float64) float64 {
	if value, ok := o.Number(key); ok {
		return value
	}
	return fallback
}

// flag is `Boolean(o[key])`.
func flag(o *core.Object, key string) bool {
	return truthy(o.Get(key))
}

// isTrue is `o[key] === true`.
func isTrue(o *core.Object, key string) bool {
	value, ok := o.Bool(key)
	return ok && value
}

// child returns an object member, or nil.
func child(o *core.Object, key string) *core.Object {
	value, _ := o.Object(key)
	return value
}

// nullish reports whether a member is undefined or null (`o[key] == null`).
func nullish(o *core.Object, key string) bool {
	value := o.Get(key)
	return value == nil || core.IsUndefined(value)
}

// jsUpper is String.prototype.toUpperCase (full mappings, from jsUpperTable); unpaired surrogates stay as they are.
func jsUpper(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := decodeWTF8(s, i)
		if mapped, ok := jsUpperTable[r]; ok {
			b.WriteString(string(mapped))
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}
