// Package spectest loads the language-neutral test vectors of spec/vectors (generated from the TypeScript
// implementation) for Go tests: it decodes the tagged values JSON cannot hold ($undefined, $number, $utf16, $bigint,
// $bytes, $set), renders Go results and errors in the vectors' shape, and compares them structurally.
package spectest

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// Set is a decoded {"$set": [...]} value (a JavaScript Set, members in insertion order).
type Set []any

// Case is one vector case.
type Case struct {
	Name string
	// Input is the decoded input (tagged values decoded).
	Input *core.Object
	// Output is the decoded expected output, or an *core.Object {"$error": {...}} kept as is.
	Output any
	// Raw is the case as written in the file.
	Raw *core.Object
}

// File is one vector file.
type File struct {
	Description string
	Source      string
	Notes       *core.Object
	Cases       []Case
}

// Root finds the repository root (the directory holding spec/vectors) from the working directory upwards.
func Root() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "spec", "vectors")); err == nil && info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("spectest: spec/vectors not found above the working directory")
		}
		dir = parent
	}
}

// Path is the absolute path of a file under spec/.
func Path(t testing.TB, parts ...string) string {
	t.Helper()
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(append([]string{root, "spec"}, parts...)...)
}

// Load reads spec/vectors/{name}.json.
func Load(t testing.TB, name string) *File {
	t.Helper()
	data, err := os.ReadFile(Path(t, "vectors", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := core.ParseJSON(data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	root := parsed.(*core.Object)
	file := &File{}
	file.Description, _ = root.String("description")
	file.Source, _ = root.String("source")
	file.Notes, _ = root.Object("notes")
	cases, _ := root.Array("cases")
	for _, item := range cases {
		raw := item.(*core.Object)
		name, _ := raw.String("name")
		input, _ := Decode(raw.Get("input")).(*core.Object)
		output := raw.Get("output")
		if !IsError(output) {
			output = Decode(output)
		}
		file.Cases = append(file.Cases, Case{Name: name, Input: input, Output: output, Raw: raw})
	}
	if len(file.Cases) == 0 {
		t.Fatalf("%s: no cases", name)
	}
	return file
}

// IsError reports whether an expected output is {"$error": {...}}.
func IsError(value any) bool {
	o, ok := value.(*core.Object)
	return ok && o != nil && o.Len() == 1 && o.Has("$error")
}

// Decode decodes the tagged values of the vector encoding.
func Decode(value any) any {
	switch v := value.(type) {
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = Decode(item)
		}
		return out
	case *core.Object:
		if v == nil {
			return v
		}
		if v.Len() == 1 {
			key := v.Keys()[0]
			item := v.Get(key)
			switch key {
			case "$undefined":
				return core.Undefined
			case "$number":
				switch item {
				case "NaN":
					return math.NaN()
				case "Infinity":
					return math.Inf(1)
				case "-Infinity":
					return math.Inf(-1)
				case "-0":
					return math.Copysign(0, -1)
				}
			case "$utf16":
				list, _ := item.([]any)
				units := make([]uint16, len(list))
				for index, unit := range list {
					units[index] = uint16(unit.(float64))
				}
				return core.FromUTF16(units)
			case "$bigint":
				n, _ := new(big.Int).SetString(item.(string), 10)
				return n
			case "$bytes":
				data, _ := base64.RawURLEncoding.DecodeString(item.(string))
				return data
			case "$set":
				list, _ := item.([]any)
				out := make(Set, len(list))
				for index, member := range list {
					out[index] = Decode(member)
				}
				return out
			}
		}
		out := core.NewObject()
		v.Entries(func(key string, item any) bool {
			out.SetRaw(key, Decode(item))
			return true
		})
		return out
	}
	return value
}

// ErrorValue renders a Go error as the vectors' {"$error": {name, code?, status?, reason?, message}}.
func ErrorValue(err error) *core.Object {
	body := core.NewObject()
	var iamError *core.IamError
	var typeError *core.TypeError
	var signalError *core.SignalFormatError
	var syntaxError *core.SyntaxError
	switch {
	case errors.As(err, &iamError):
		body.Set("name", "IamError").Set("code", iamError.Code).Set("status", iamError.Status).Set("message", iamError.Message)
	case errors.As(err, &typeError):
		body.Set("name", "TypeError").Set("message", typeError.Message)
	case errors.As(err, &signalError):
		body.Set("name", "SignalFormatError").Set("reason", signalError.Reason).Set("message", signalError.Message)
	case errors.As(err, &syntaxError):
		body.Set("name", "SyntaxError").Set("message", syntaxError.Message)
	default:
		body.Set("name", "Error").Set("message", err.Error())
	}
	return core.NewObject("$error", body)
}

// Outcome is a result as a model value, or the error as ErrorValue.
func Outcome(value any, err error) any {
	if err != nil {
		return ErrorValue(err)
	}
	return Model(value)
}

// Model converts a Go result to the core value model (structs through their JSON form; Set and []byte kept).
func Model(value any) any {
	switch v := value.(type) {
	case Set:
		out := make(Set, len(v))
		for index, item := range v {
			out[index] = Model(item)
		}
		return out
	case []byte:
		return v
	case *big.Int:
		return v
	}
	return core.Normalize(value)
}

// Equal compares two model values structurally (object key order ignored, array order kept, numbers by value with
// NaN equal to NaN). Errors compare by name, code, status, reason and message.
func Equal(got, want any) bool {
	switch w := want.(type) {
	case *core.Object:
		g, ok := got.(*core.Object)
		if !ok || g == nil || w == nil {
			return ok && g == nil && w == nil
		}
		// Members set to undefined count as absent on either side (JSON cannot tell them apart).
		defined := func(o *core.Object) []string {
			var keys []string
			for _, key := range o.Keys() {
				if !core.IsUndefined(o.Get(key)) {
					keys = append(keys, key)
				}
			}
			return keys
		}
		wantKeys := defined(w)
		if len(defined(g)) != len(wantKeys) {
			return false
		}
		for _, key := range wantKeys {
			if !g.Has(key) || !Equal(g.Get(key), w.Get(key)) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for index := range w {
			if !Equal(g[index], w[index]) {
				return false
			}
		}
		return true
	case Set:
		g, ok := got.(Set)
		if !ok || len(g) != len(w) {
			return false
		}
		for index := range w {
			if !Equal(g[index], w[index]) {
				return false
			}
		}
		return true
	case float64:
		g, ok := got.(float64)
		return ok && (g == w || (math.IsNaN(g) && math.IsNaN(w))) && math.Signbit(g) == math.Signbit(w)
	case []byte:
		g, ok := got.([]byte)
		return ok && string(g) == string(w)
	case *big.Int:
		g, ok := got.(*big.Int)
		return ok && g.Cmp(w) == 0
	}
	return core.StrictEquals(got, want)
}

// Show renders a model value for failure messages.
func Show(value any) string {
	switch v := value.(type) {
	case core.UndefinedType:
		return "undefined"
	case Set:
		parts := make([]string, len(v))
		for index, item := range v {
			parts[index] = Show(item)
		}
		return "Set(" + strings.Join(parts, ", ") + ")"
	case []byte:
		return fmt.Sprintf("bytes(%x)", v)
	case *big.Int:
		return v.String() + "n"
	case float64:
		if v == 0 && math.Signbit(v) {
			return "-0"
		}
	}
	text, ok, err := core.Stringify(value)
	if err != nil || !ok {
		return fmt.Sprintf("%#v", value)
	}
	return text
}

// Check fails the test when got differs from the case's expected output.
func Check(t testing.TB, c Case, got any) {
	t.Helper()
	if !Equal(got, c.Output) {
		t.Errorf("%s:\n  input    %s\n  expected %s\n  received %s", c.Name, Show(c.Raw.Get("input")), Show(c.Output), Show(got))
	}
}

// Ptr returns a pointer to v.
func Ptr[T any](v T) *T { return &v }
