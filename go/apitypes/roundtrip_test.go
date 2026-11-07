package apitypes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

// canonical is the JCS text of a JSON document: equal texts are the same JSON value, whatever the member order.
func canonical(data []byte) (string, error) {
	value, err := core.ParseJSON(data)
	if err != nil {
		return "", err
	}
	return core.CanonicalizeJSON(value)
}

// firstDifference names the first path where two JSON documents differ.
func firstDifference(a, b []byte) string {
	left, errA := core.ParseJSON(a)
	right, errB := core.ParseJSON(b)
	if errA != nil || errB != nil {
		return "unparsable"
	}
	var walk func(path string, x, y any) string
	walk = func(path string, x, y any) string {
		switch xv := x.(type) {
		case *core.Object:
			yv, ok := y.(*core.Object)
			if !ok {
				return fmt.Sprintf("%s: %s became %s", path, show(x), show(y))
			}
			for _, key := range xv.Keys() {
				if !yv.Has(key) {
					return fmt.Sprintf("%s.%s: dropped (%s)", path, key, show(xv.Get(key)))
				}
				if d := walk(path+"."+key, xv.Get(key), yv.Get(key)); d != "" {
					return d
				}
			}
			for _, key := range yv.Keys() {
				if !xv.Has(key) {
					return fmt.Sprintf("%s.%s: added (%s)", path, key, show(yv.Get(key)))
				}
			}
			return ""
		case []any:
			yv, ok := y.([]any)
			if !ok || len(xv) != len(yv) {
				return fmt.Sprintf("%s: %s became %s", path, show(x), show(y))
			}
			for index := range xv {
				if d := walk(fmt.Sprintf("%s[%d]", path, index), xv[index], yv[index]); d != "" {
					return d
				}
			}
			return ""
		default:
			if !core.StrictEquals(x, y) {
				return fmt.Sprintf("%s: %s became %s", path, show(x), show(y))
			}
			return ""
		}
	}
	return walk("$", left, right)
}

func show(value any) string {
	text, _, err := core.Stringify(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	if len(text) > 120 {
		text = text[:120] + "..."
	}
	return text
}

// roundTrip decodes data into a new value of type t, encodes it again and compares the two documents.
func roundTrip(t reflect.Type, data []byte) error {
	target := reflect.New(t)
	if err := json.Unmarshal(data, target.Interface()); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	again, err := json.Marshal(target.Elem().Interface())
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	want, err := canonical(data)
	if err != nil {
		return fmt.Errorf("canonicalize the original: %w", err)
	}
	got, err := canonical(again)
	if err != nil {
		return fmt.Errorf("canonicalize the re-encoding: %w", err)
	}
	if got != want {
		return fmt.Errorf("differs: %s", firstDifference(data, again))
	}
	return nil
}

type traceStep struct {
	Kind   string          `json:"kind"`
	Seq    int             `json:"seq"`
	Route  string          `json:"route"`
	Input  json.RawMessage `json:"input"`
	Output json.RawMessage `json:"output"`
	Error  json.RawMessage `json:"error"`
}

func traceFiles(t *testing.T) []string {
	t.Helper()
	dir := spectest.Path(t, "conformance", "traces")
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".jsonl") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("spec/conformance/traces is not present")
		}
		t.Fatal(err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		t.Skip("no recorded traces under spec/conformance/traces")
	}
	return files
}

// TestTraceRoundTrip decodes the request body and the answer of every successful API call recorded from the
// TypeScript test suite into the generated types, encodes them again, and requires the same JSON (member order aside).
func TestTraceRoundTrip(t *testing.T) {
	files := traceFiles(t)
	type failure struct{ where, message string }
	var failures []failure
	outputs, inputs, errorsChecked := 0, 0, 0
	routesSeen := map[string]bool{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		relative, _ := filepath.Rel(spectest.Path(t, "conformance", "traces"), file)
		for lineIndex, line := range bytes.Split(data, []byte("\n")) {
			if lineIndex == 0 || len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var step traceStep
			if err := json.Unmarshal(line, &step); err != nil {
				t.Fatalf("%s:%d: %v", relative, lineIndex+1, err)
			}
			if step.Kind != "api" {
				continue
			}
			where := fmt.Sprintf("%s#%d %s", filepath.ToSlash(relative), step.Seq, step.Route)
			op, ok := LookupOperation(step.Route)
			if !ok {
				failures = append(failures, failure{where, "the route is not in the operation table"})
				continue
			}
			routesSeen[step.Route] = true
			if step.Error != nil {
				var recorded struct {
					Code         string   `json:"code"`
					Message      string   `json:"message"`
					RetryAfterMs *float64 `json:"retryAfterMs"`
					Region       *string  `json:"region"`
					Location     *string  `json:"location"`
				}
				if err := json.Unmarshal(step.Error, &recorded); err != nil {
					t.Fatalf("%s: %v", where, err)
				}
				envelope := map[string]any{"error": map[string]any{"code": recorded.Code, "message": recorded.Message}}
				if recorded.RetryAfterMs != nil {
					envelope["error"].(map[string]any)["retryAfterMs"] = *recorded.RetryAfterMs
				}
				if recorded.Region != nil {
					envelope["error"].(map[string]any)["region"] = *recorded.Region
				}
				if recorded.Location != nil {
					envelope["error"].(map[string]any)["location"] = *recorded.Location
				}
				body, _ := json.Marshal(envelope)
				if err := roundTrip(reflect.TypeFor[ErrorEnvelope](), body); err != nil {
					failures = append(failures, failure{where + " (error envelope)", err.Error()})
				}
				errorsChecked++
				continue
			}
			if step.Output == nil {
				continue
			}
			outputs++
			if err := roundTrip(op.Output, step.Output); err != nil {
				failures = append(failures, failure{where + " output", err.Error()})
			}
			if step.Input != nil {
				inputs++
				if err := roundTrip(op.Input, step.Input); err != nil {
					failures = append(failures, failure{where + " input", err.Error()})
				}
			}
		}
	}
	t.Logf("%d answers, %d request bodies and %d error envelopes round-tripped over %d routes from %d traces",
		outputs, inputs, errorsChecked, len(routesSeen), len(files))
	if len(failures) > 0 {
		limit := min(len(failures), 60)
		var report strings.Builder
		for _, f := range failures[:limit] {
			fmt.Fprintf(&report, "\n  %s: %s", f.where, f.message)
		}
		t.Errorf("%d of %d values do not round-trip:%s", len(failures), outputs+inputs+errorsChecked, report.String())
	}
}
