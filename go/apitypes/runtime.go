package apitypes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
)

// Optional is a member that may be absent: the zero value is absent (omitted by omitzero), and Set with any Value,
// including a nil pointer, slice or map (written as null), is present.
type Optional[T any] struct {
	Value T
	Set   bool
}

// Some is a present Optional holding value.
func Some[T any](value T) Optional[T] { return Optional[T]{Value: value, Set: true} }

// Null is a present Optional holding null.
func Null[T any]() Optional[*T] { return Optional[*T]{Set: true} }

// IsZero reports whether the member is absent (omitzero leaves it out).
func (o Optional[T]) IsZero() bool { return !o.Set }

// Get returns the value and whether the member is present.
func (o Optional[T]) Get() (T, bool) { return o.Value, o.Set }

// MarshalJSON writes the value.
func (o Optional[T]) MarshalJSON() ([]byte, error) { return json.Marshal(o.Value) }

// UnmarshalJSON marks the member present and reads the value (null leaves a nil pointer, slice, map or interface).
func (o *Optional[T]) UnmarshalJSON(data []byte) error {
	o.Set = true
	return json.Unmarshal(data, &o.Value)
}

// --- union shapes -------------------------------------------------------------------------------------------------

type kind uint8

const (
	kindNull kind = 1 << iota
	kindBool
	kindNumber
	kindString
	kindArray
	kindObject
	kindAny = kindNull | kindBool | kindNumber | kindString | kindArray | kindObject
)

// shape is what a union variant accepts, as far as telling variants apart needs: the JSON kinds, the allowed constant
// values, required members, the members of an object (closed: no others), and the shape of map values and array items.
type shape struct {
	kinds    kind
	consts   []any
	required []string
	props    map[string]*shape
	closed   bool
	values   *shape
	items    *shape
}

func kindOf(value any) kind {
	switch value.(type) {
	case nil:
		return kindNull
	case bool:
		return kindBool
	case json.Number:
		return kindNumber
	case string:
		return kindString
	case []any:
		return kindArray
	case map[string]any:
		return kindObject
	}
	return 0
}

func constMatches(consts []any, value any) bool {
	for _, c := range consts {
		switch want := c.(type) {
		case string:
			if got, ok := value.(string); ok && got == want {
				return true
			}
		case bool:
			if got, ok := value.(bool); ok && got == want {
				return true
			}
		case float64:
			if got, ok := value.(json.Number); ok {
				if f, err := got.Float64(); err == nil && f == want {
					return true
				}
			}
		}
	}
	return false
}

// match reports whether value fits the shape; strict also refuses members a closed object does not list.
func (s *shape) match(value any, strict bool) bool {
	if s == nil {
		return true
	}
	if s.kinds&kindOf(value) == 0 {
		return false
	}
	if len(s.consts) > 0 && value != nil && !constMatches(s.consts, value) {
		return false
	}
	switch v := value.(type) {
	case map[string]any:
		for _, key := range s.required {
			if _, ok := v[key]; !ok {
				return false
			}
		}
		for key, member := range v {
			if prop, ok := s.props[key]; ok {
				if !prop.match(member, strict) {
					return false
				}
				continue
			}
			if s.closed && strict {
				return false
			}
			if s.values != nil && !s.values.match(member, strict) {
				return false
			}
		}
	case []any:
		if s.items != nil {
			for _, item := range v {
				if !s.items.match(item, strict) {
					return false
				}
			}
		}
	}
	return true
}

// UnionError reports a union value that matches none of the variants.
type UnionError struct {
	Union string
	Value string
}

func (e *UnionError) Error() string {
	return fmt.Sprintf("apitypes: %s: the value matches none of the variants: %s", e.Union, e.Value)
}

// matchVariant returns the index of the first variant the JSON value matches: first checking that closed objects
// have no unlisted members, then, when none matches, ignoring them.
func matchVariant(union string, data []byte, variants []*shape) (int, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return -1, err
	}
	for _, strict := range []bool{true, false} {
		for index, variant := range variants {
			if variant.match(value, strict) {
				return index, nil
			}
		}
	}
	text := string(data)
	if len(text) > 200 {
		text = text[:200] + "..."
	}
	return -1, &UnionError{Union: union, Value: text}
}

func errNoVariant(union string) error {
	return fmt.Errorf("apitypes: %s: no variant is set", union)
}

// --- other members ----------------------------------------------------------------------------------------------------

// marshalWithExtra writes value (a struct) and then the members of extra that are not listed, sorted by name.
func marshalWithExtra[T any](value any, known []string, extra map[string]T) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil || len(extra) == 0 {
		return data, err
	}
	keys := make([]string, 0, len(extra))
	for key := range extra {
		if !slices.Contains(known, key) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return data, nil
	}
	sort.Strings(keys)
	var buffer bytes.Buffer
	buffer.Write(data[:len(data)-1])
	empty := bytes.Equal(data, []byte("{}"))
	for _, key := range keys {
		if !empty {
			buffer.WriteByte(',')
		}
		empty = false
		name, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		member, err := json.Marshal(extra[key])
		if err != nil {
			return nil, err
		}
		buffer.Write(name)
		buffer.WriteByte(':')
		buffer.Write(member)
	}
	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

// unmarshalExtra reads the members of the JSON object that are not listed into *extra (nil when there are none).
func unmarshalExtra[T any](data []byte, known []string, extra *map[string]T) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	var out map[string]T
	for key, raw := range members {
		if slices.Contains(known, key) {
			continue
		}
		var value T
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		if out == nil {
			out = make(map[string]T)
		}
		out[key] = value
	}
	*extra = out
	return nil
}

// --- schema registry ----------------------------------------------------------------------------------------------------

// SchemaType returns the Go type of a components/schemas name.
func SchemaType(name string) (reflect.Type, bool) {
	t, ok := schemaTypes[name]
	return t, ok
}

// CoreSchemas lists the components/schemas names whose Go types are go/core types (aliases, not copies).
func CoreSchemas() []string { return slices.Clone(coreSchemas) }
