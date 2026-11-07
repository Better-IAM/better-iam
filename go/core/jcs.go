package core

import (
	"math"
	"math/big"
	"sort"
	"strings"
)

// compareUTF16 orders strings by their UTF-16 code units, as JavaScript's default sort and `<` do.
func compareUTF16(a, b string) int {
	if StorableString(a) && StorableString(b) && !hasSurrogateUnit(a) && !hasSurrogateUnit(b) {
		return strings.Compare(a, b) // BMP-only valid UTF-8: byte order is code-unit order
	}
	x, y := ToUTF16(a), ToUTF16(b)
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

func sortedUTF16(keys []string) []string {
	out := append([]string(nil), keys...)
	sort.SliceStable(out, func(i, j int) bool { return compareUTF16(out[i], out[j]) < 0 })
	return out
}

// CanonicalizeJSON is the JSON Canonicalization Scheme (RFC 8785): object members sorted by the UTF-16 code units of
// their names at every depth, numbers in the ECMAScript shortest form, strings escaped as JSON.stringify does, no
// whitespace. Undefined members are left out and Undefined array entries become null. Fails with a *TypeError for
// non-finite numbers, big integers (*big.Int), cycles, and a top-level value without a JSON form.
func CanonicalizeJSON(value any) (string, error) {
	path := map[any]bool{}
	var write func(item any) (string, bool, error)
	write = func(item any) (string, bool, error) {
		switch v := item.(type) {
		case nil:
			return "null", true, nil
		case bool:
			if v {
				return "true", true, nil
			}
			return "false", true, nil
		case string:
			return QuoteJSON(v), true, nil
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return "", false, &TypeError{"JSON cannot represent a non-finite number"}
			}
			return NumberString(v), true, nil
		case *big.Int:
			return "", false, &TypeError{"JSON cannot represent a bigint"}
		case UndefinedType:
			return "", false, nil
		case []any:
			var key any = &v
			if len(v) > 0 {
				key = &v[0]
			}
			if path[key] {
				return "", false, &TypeError{"Cannot canonicalize a cyclic value"}
			}
			path[key] = true
			defer delete(path, key)
			parts := make([]string, len(v))
			for index, entry := range v {
				text, ok, err := write(entry)
				if err != nil {
					return "", false, err
				}
				if !ok {
					text = "null"
				}
				parts[index] = text
			}
			return "[" + strings.Join(parts, ",") + "]", true, nil
		case *Object:
			if v == nil {
				return "null", true, nil
			}
			if path[v] {
				return "", false, &TypeError{"Cannot canonicalize a cyclic value"}
			}
			path[v] = true
			defer delete(path, v)
			var members []string
			for _, key := range sortedUTF16(v.keys) {
				text, ok, err := write(v.values[key])
				if err != nil {
					return "", false, err
				}
				if ok {
					members = append(members, QuoteJSON(key)+":"+text)
				}
			}
			return "{" + strings.Join(members, ",") + "}", true, nil
		}
		normalized := Normalize(item)
		if !modelValue(normalized) {
			return "", false, nil
		}
		return write(normalized)
	}
	text, ok, err := write(value)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", &TypeError{"The value has no JSON representation"}
	}
	return text, nil
}
