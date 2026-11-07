package server

// Port of tests/metrics.test.ts (the collector part; the HTTP scrape route belongs to the HTTP port) and
// tests/observability.test.ts (the observer), plus differential checks against the TypeScript collector
// (testdata/metrics.json) and Node's String.prototype.localeCompare (testdata/locale-compare.json).

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func readFixture(t *testing.T, name string) *core.Object {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := core.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.(*core.Object)
}

func TestLocaleCompareMatchesNode(t *testing.T) {
	fixture := readFixture(t, "locale-compare.json")
	pairs, _ := fixture.Array("pairs")
	failures := 0
	for _, item := range pairs {
		pair := item.([]any)
		a, b, want := pair[0].(string), pair[1].(string), int(pair[2].(float64))
		if got := localeCompare(a, b); got != want {
			failures++
			if failures <= 10 {
				t.Errorf("localeCompare(%q, %q) = %d, Node (ICU %v) says %d", a, b, got, fixture.Get("icu"), want)
			}
		}
	}
	if failures > 0 {
		t.Fatalf("%d of %d comparisons differ from Node", failures, len(pairs))
	}
}

func spanOf(value any) IamSpan {
	span := IamSpan{Kind: jsString(member(value, "kind")), Name: jsString(member(value, "name")), Outcome: jsString(member(value, "outcome"))}
	span.DurationMs, _ = member(value, "durationMs").(float64)
	if code, ok := member(value, "code").(string); ok {
		span.Code = code
	}
	if status, ok := member(value, "status").(float64); ok {
		span.Status = int(status)
	}
	return span
}

func TestMetricsMatchTheTypeScriptCollector(t *testing.T) {
	fixture := readFixture(t, "metrics.json")
	runs, _ := fixture.Array("runs")
	for index, run := range runs {
		options := &MetricsOptions{}
		if buckets, ok := member(member(run, "options"), "buckets").([]any); ok {
			for _, bound := range buckets {
				options.Buckets = append(options.Buckets, bound.(float64))
			}
		}
		if maxSeries, ok := member(member(run, "options"), "maxSeries").(float64); ok {
			options.MaxSeries = &maxSeries
		}
		metrics := must(CreateMetrics(options))
		for _, span := range member(run, "spans").([]any) {
			metrics.OnSpan(spanOf(span))
		}
		if got, want := metrics.Render(), jsString(member(run, "render")); got != want {
			gotLines, wantLines := strings.Split(got, "\n"), strings.Split(want, "\n")
			for line := 0; line < len(gotLines) && line < len(wantLines); line++ {
				if gotLines[line] != wantLines[line] {
					t.Fatalf("run %d: render differs at line %d:\n go %s\n ts %s", index, line+1, gotLines[line], wantLines[line])
				}
			}
			t.Fatalf("run %d: render differs in length (%d vs %d lines)", index, len(gotLines), len(wantLines))
		}
		snapshot := core.Normalize(metrics.Snapshot())
		if core.CanonicalJSON(snapshot) != core.CanonicalJSON(member(run, "snapshot")) {
			t.Fatalf("run %d: snapshot differs:\n go %s\n ts %s", index, core.CanonicalJSON(snapshot), core.CanonicalJSON(member(run, "snapshot")))
		}
	}
	_, err := CreateMetrics(&MetricsOptions{Buckets: []float64{0}})
	if err == nil || err.Error() != fixture.Get("bucketError") {
		t.Fatalf("bucket error %v", err)
	}
}

func TestMetricsCollapseSeriesPastTheCapAndEscapeLabels(t *testing.T) {
	metrics := must(CreateMetrics(&MetricsOptions{MaxSeries: float(2)}))
	for _, name := range []string{"a", "b", "c\"d\\e\n"} {
		metrics.OnSpan(IamSpan{Kind: "operation", Name: name, Outcome: "ok", DurationMs: 1})
	}
	metrics.OnSpan(IamSpan{Kind: "operation", Name: "a", Outcome: "ok", DurationMs: 1})
	rendered := metrics.Render()
	for _, want := range []string{
		`better_iam_spans_total{kind="operation",name="a",outcome="ok",code=""} 2`,
		`better_iam_spans_total{kind="operation",name="(other)",outcome="ok",code=""} 1`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing %s in\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, `c"d`) {
		t.Fatal("collapsed name leaked")
	}
	metrics.Reset()
	metrics.OnSpan(IamSpan{Kind: "operation", Name: "c\"d\\e\n", Outcome: "ok", DurationMs: 1})
	if !strings.Contains(metrics.Render(), `name="c\"d\\e\n"`) {
		t.Fatal(metrics.Render())
	}
}

func TestMetricsClassifyCallerNamedSeries(t *testing.T) {
	metrics := must(CreateMetrics(nil))
	metrics.OnSpan(IamSpan{Kind: "authorize", Name: "made:up", Outcome: "denied", Code: "UNAUTHENTICATED"})
	metrics.OnSpan(IamSpan{Kind: "authorize", Name: "docs:read", Outcome: "ok", Code: "ACCESS_DENIED"})
	metrics.OnSpan(IamSpan{Kind: "operation", Name: "nope", Outcome: "error", Code: "NOT_FOUND"})
	metrics.OnSpan(IamSpan{Kind: "http", Name: "/api/iam/x", Outcome: "error", Status: 404})
	metrics.OnSpan(IamSpan{Kind: "auth", Name: strings.Repeat("x", 257), Outcome: "ok"})
	var names []string
	for _, row := range metrics.Snapshot().Spans {
		names = append(names, row.Kind+"/"+row.Name)
	}
	want := []string{"authorize/(invalid)", "authorize/docs:read", "operation/(invalid)", "http/(unknown)", "auth/(invalid)"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("%v", names)
	}
	if http := metrics.Snapshot().HTTP; len(http) != 1 || http[0] != (HTTPSeries{Path: "(unknown)", Status: 404, Count: 1}) {
		t.Fatalf("%+v", http)
	}
}

func TestObserverReportsSpans(t *testing.T) {
	var spans []IamSpan
	observer := CreateObserver(&ObservabilityOptions{OnSpan: func(span IamSpan) { spans = append(spans, span) }})
	if !observer.Enabled || CreateObserver(nil).Enabled {
		t.Fatal("enabled")
	}
	value := must(Span(observer, "operation", "iam:groups:create", "t1", func() (int, error) { return 7, nil }, nil, nil))
	if value != 7 {
		t.Fatal(value)
	}
	_, _ = Span(observer, "authorize", "docs:read", "t1", func() (bool, error) { return false, nil },
		func(allowed bool) SpanResult { return SpanResult{Outcome: "denied", Code: "ACCESS_DENIED"} }, nil)
	_, err := Span(observer, "auth", "signIn", "", func() (any, error) {
		return nil, core.NewIamError("INVALID_CREDENTIALS", "Invalid credentials", 401)
	}, nil, nil)
	if err == nil {
		t.Fatal("error must propagate")
	}
	_, _ = Span(observer, "http", "/api/iam/x", "", func() (any, error) { return nil, errors.New("boom") }, nil, &SpanExtra{RequestID: "req-1"})
	_, _ = Span(observer, "operation", "x", "", func() (any, error) { return nil, core.NewIamError("CONFLICT", "c", 409) }, nil, nil)
	got := make([]string, len(spans))
	for index, span := range spans {
		got[index] = span.Kind + " " + span.Name + " " + span.Outcome + " " + span.Code + " " + span.RequestID
		if span.DurationMs < 0 {
			t.Fatal("negative duration")
		}
	}
	want := []string{
		"operation iam:groups:create ok  ",
		"authorize docs:read denied ACCESS_DENIED ",
		"auth signIn denied INVALID_CREDENTIALS ",
		"http /api/iam/x error INTERNAL_ERROR req-1",
		"operation x error CONFLICT ",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
	// A failing handler never interferes with the request.
	panicking := CreateObserver(&ObservabilityOptions{OnSpan: func(IamSpan) { panic("observer") }})
	if must(Span(panicking, "operation", "x", "", func() (string, error) { return "ok", nil }, nil, nil)) != "ok" {
		t.Fatal("panicking handler")
	}
}
