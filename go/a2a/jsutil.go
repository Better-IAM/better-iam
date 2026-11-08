package a2a

// JavaScript semantics the TypeScript package relies on implicitly, after go/auth/jsutil.go: TextEncoder (UTF-8 with
// unpaired surrogates replaced), the WHATWG UTF-8 decoder behind TextDecoder and Response#text (a leading BOM is
// dropped), Node's forgiving base64 decoder (WebCrypto JWK import), Date.parse, and String(value) for lookups.
// Strings are WTF-8 (see core/json.go): unpaired surrogates are kept as 3-byte ED A0..BF xx sequences.

import (
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

// textDecode is new TextDecoder().decode(bytes) (and Response#text): a leading UTF-8 BOM is dropped, invalid sequences
// become U+FFFD.
func textDecode(b []byte) string {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	return decodeUTF8(b)
}

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

// maxDateMs is the largest absolute time value a JavaScript Date holds.
const maxDateMs = 8.64e15

// dateValid reports whether a time value is a valid Date (not NaN, within ±8.64e15 ms).
func dateValid(ms float64) bool {
	return !math.IsNaN(ms) && math.Abs(ms) <= maxDateMs
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

// compareUTF16 orders strings by their UTF-16 code units (Array#sort's default order).
func compareUTF16(a, b string) int {
	x, y := core.ToUTF16(a), core.ToUTF16(b)
	for index := 0; index < len(x) && index < len(y); index++ {
		if x[index] != y[index] {
			if x[index] < y[index] {
				return -1
			}
			return 1
		}
	}
	return len(x) - len(y)
}
