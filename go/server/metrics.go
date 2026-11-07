package server

// Port of packages/server/src/metrics.ts: a small Prometheus-style collector fed by observability spans. The text
// exposition is byte-identical to the TypeScript one, including the series order, which TypeScript sorts with
// String.prototype.localeCompare (ICU collation): localeCompare below reproduces it with golang.org/x/text/collate
// (root collation, tertiary strength), checked against Node in metrics_test.go.

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Better-IAM/better-iam/go/core"
	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

// MetricsOptions configure the collector.
type MetricsOptions struct {
	// Buckets are histogram bucket upper bounds in seconds (ascending).
	Buckets []float64 `json:"buckets,omitzero"`
	// BearerToken serves GET {basePath}/metrics to requests carrying `Authorization: Bearer <token>`.
	BearerToken *string `json:"bearerToken,omitempty"`
	// MaxSeries is the maximum distinct label sets per metric before new ones collapse into `(other)` (default 2000).
	MaxSeries *float64 `json:"maxSeries,omitempty"`
	// Gauges also reports storage gauges on each scrape (better_iam_outbox_messages, better_iam_sessions_live).
	Gauges *bool `json:"gauges,omitempty"`
}

// SpanSeries is one counter series.
type SpanSeries struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Code    string `json:"code"`
	Count   int64  `json:"count"`
}

// DurationSeries is one latency histogram.
type DurationSeries struct {
	Kind       string       `json:"kind"`
	Count      int64        `json:"count"`
	SumSeconds float64      `json:"sumSeconds"`
	Buckets    [][2]float64 `json:"buckets"`
}

// HTTPSeries is one HTTP request counter.
type HTTPSeries struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Count  int64  `json:"count"`
}

// MetricsSnapshot is the collector's state.
type MetricsSnapshot struct {
	Spans     []SpanSeries     `json:"spans"`
	Durations []DurationSeries `json:"durations"`
	HTTP      []HTTPSeries     `json:"http"`
}

var defaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// callerNamedErrors are errors whose span name came from the caller rather than the catalog or route table.
var callerNamedErrors = map[string]bool{"NOT_FOUND": true, "INVALID_INPUT": true, "UNKNOWN_ACTION": true, "INVALID_ACTION": true}

// callerNamedKinds are span kinds named by the action the caller asked about.
var callerNamedKinds = map[string]bool{"authorize": true, "listAccessible": true}

// maxNameLength: longer names are never catalog actions or routes.
const maxNameLength = 256

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return strings.ReplaceAll(value, "\n", `\n`)
}

func labels(pairs ...[2]string) string {
	parts := make([]string, len(pairs))
	for index, pair := range pairs {
		parts[index] = pair[0] + `="` + escapeLabel(pair[1]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func seriesKey(parts ...string) string {
	quoted := make([]string, len(parts))
	for index, part := range parts {
		quoted[index] = core.QuoteJSON(part)
	}
	return "[" + strings.Join(quoted, ",") + "]"
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

type histogram struct {
	count  int64
	sum    float64
	counts []int64
}

// MetricsCollector is the Prometheus-style collector (createMetrics). It is safe for concurrent use.
type MetricsCollector struct {
	mu            sync.Mutex
	buckets       []float64
	maxSeries     int
	spans         map[string]*SpanSeries
	spanOrder     []*SpanSeries
	durations     map[string]*histogram
	durationOrder []string
	http          map[string]*HTTPSeries
	httpOrder     []*HTTPSeries
}

// CreateMetrics builds a collector; buckets must be positive numbers.
func CreateMetrics(options *MetricsOptions) (*MetricsCollector, error) {
	if options == nil {
		options = &MetricsOptions{}
	}
	buckets := append([]float64(nil), defaultBuckets...)
	if options.Buckets != nil {
		buckets = append([]float64(nil), options.Buckets...)
	}
	sort.SliceStable(buckets, func(i, j int) bool { return buckets[i]-buckets[j] < 0 })
	for _, bound := range buckets {
		if !(bound > 0) {
			return nil, errors.New("Metrics buckets must be positive numbers")
		}
	}
	maxSeries := 2000
	if options.MaxSeries != nil {
		maxSeries = int(math.Ceil(*options.MaxSeries))
	}
	collector := &MetricsCollector{buckets: buckets, maxSeries: maxSeries}
	collector.reset()
	return collector, nil
}

func (m *MetricsCollector) reset() {
	m.spans = map[string]*SpanSeries{}
	m.spanOrder = nil
	m.durations = map[string]*histogram{}
	m.durationOrder = nil
	m.http = map[string]*HTTPSeries{}
	m.httpOrder = nil
}

// nameOf classifies the span name: HTTP spans by status (unknown routes are `(unknown)`), other kinds by the error
// code, and caller-named kinds also by whether the caller was answered at all.
func nameOf(span IamSpan) string {
	if utf16Len(span.Name) > maxNameLength {
		return "(invalid)"
	}
	if span.Kind == "http" {
		if span.Status == 404 {
			return "(unknown)"
		}
		return span.Name
	}
	if span.Outcome != "ok" && span.Code != "" && callerNamedErrors[span.Code] {
		return "(invalid)"
	}
	if callerNamedKinds[span.Kind] && span.Outcome != "ok" && span.Code != "ACCESS_DENIED" {
		return "(invalid)"
	}
	return span.Name
}

// OnSpan records one span.
func (m *MetricsCollector) OnSpan(span IamSpan) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := nameOf(span)
	code := span.Code
	key := seriesKey(span.Kind, name, span.Outcome, code)
	series := m.spans[key]
	if series == nil {
		collapsed := len(m.spans) >= m.maxSeries
		lookup := key
		if collapsed {
			lookup = seriesKey(span.Kind, "(other)", span.Outcome, code)
		}
		series = m.spans[lookup]
		if series == nil {
			series = &SpanSeries{Kind: span.Kind, Name: name, Outcome: span.Outcome, Code: code}
			if collapsed {
				series.Name = "(other)"
			}
			m.spans[lookup] = series
			m.spanOrder = append(m.spanOrder, series)
		}
	}
	series.Count++
	h := m.durations[span.Kind]
	if h == nil {
		h = &histogram{counts: make([]int64, len(m.buckets))}
		m.durations[span.Kind] = h
		m.durationOrder = append(m.durationOrder, span.Kind)
	}
	seconds := math.Max(0, span.DurationMs) / 1000
	h.count++
	h.sum += seconds
	for index, bound := range m.buckets {
		if seconds <= bound {
			h.counts[index]++
		}
	}
	if span.Kind == "http" && span.Status != 0 {
		httpKey := seriesKey(name, strconv.Itoa(span.Status))
		row := m.http[httpKey]
		if row == nil {
			collapsed := len(m.http) >= m.maxSeries
			lookup := httpKey
			if collapsed {
				lookup = seriesKey("(other)", strconv.Itoa(span.Status))
			}
			row = m.http[lookup]
			if row == nil {
				row = &HTTPSeries{Path: name, Status: span.Status}
				if collapsed {
					row.Path = "(other)"
				}
				m.http[lookup] = row
				m.httpOrder = append(m.httpOrder, row)
			}
		}
		row.Count++
	}
}

// Snapshot returns a copy of the collector's state.
func (m *MetricsCollector) Snapshot() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	snapshot := MetricsSnapshot{Spans: []SpanSeries{}, Durations: []DurationSeries{}, HTTP: []HTTPSeries{}}
	for _, row := range m.spanOrder {
		snapshot.Spans = append(snapshot.Spans, *row)
	}
	for _, kind := range m.durationOrder {
		h := m.durations[kind]
		buckets := make([][2]float64, len(m.buckets))
		for index, bound := range m.buckets {
			buckets[index] = [2]float64{bound, float64(h.counts[index])}
		}
		snapshot.Durations = append(snapshot.Durations, DurationSeries{Kind: kind, Count: h.count, SumSeconds: h.sum, Buckets: buckets})
	}
	for _, row := range m.httpOrder {
		snapshot.HTTP = append(snapshot.HTTP, *row)
	}
	return snapshot
}

// Render is the Prometheus text exposition format.
func (m *MetricsCollector) Render() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	lines := []string{
		"# HELP better_iam_spans_total Units of work by kind, name, outcome, and error code.",
		"# TYPE better_iam_spans_total counter",
	}
	spans := append([]*SpanSeries(nil), m.spanOrder...)
	sort.SliceStable(spans, func(i, j int) bool {
		a, b := spans[i], spans[j]
		return localeCompare(a.Kind+a.Name+a.Outcome+a.Code, b.Kind+b.Name+b.Outcome+b.Code) < 0
	})
	for _, row := range spans {
		lines = append(lines, "better_iam_spans_total"+labels(
			[2]string{"kind", row.Kind}, [2]string{"name", row.Name}, [2]string{"outcome", row.Outcome},
			[2]string{"code", row.Code})+" "+strconv.FormatInt(row.Count, 10))
	}
	lines = append(lines,
		"# HELP better_iam_span_duration_seconds Latency of units of work by kind.",
		"# TYPE better_iam_span_duration_seconds histogram",
	)
	kinds := append([]string(nil), m.durationOrder...)
	sort.SliceStable(kinds, func(i, j int) bool { return localeCompare(kinds[i], kinds[j]) < 0 })
	for _, kind := range kinds {
		h := m.durations[kind]
		for index, bound := range m.buckets {
			lines = append(lines, "better_iam_span_duration_seconds_bucket"+labels(
				[2]string{"kind", kind}, [2]string{"le", core.NumberString(bound)})+" "+strconv.FormatInt(h.counts[index], 10))
		}
		lines = append(lines,
			"better_iam_span_duration_seconds_bucket"+labels([2]string{"kind", kind}, [2]string{"le", "+Inf"})+" "+strconv.FormatInt(h.count, 10),
			"better_iam_span_duration_seconds_sum"+labels([2]string{"kind", kind})+" "+core.NumberString(h.sum),
			"better_iam_span_duration_seconds_count"+labels([2]string{"kind", kind})+" "+strconv.FormatInt(h.count, 10),
		)
	}
	lines = append(lines,
		"# HELP better_iam_http_requests_total HTTP requests to the IAM handler by route and status.",
		"# TYPE better_iam_http_requests_total counter",
	)
	rows := append([]*HTTPSeries(nil), m.httpOrder...)
	sort.SliceStable(rows, func(i, j int) bool {
		if order := localeCompare(rows[i].Path, rows[j].Path); order != 0 {
			return order < 0
		}
		return rows[i].Status < rows[j].Status
	})
	for _, row := range rows {
		lines = append(lines, "better_iam_http_requests_total"+labels(
			[2]string{"path", row.Path}, [2]string{"status", strconv.Itoa(row.Status)})+" "+strconv.FormatInt(row.Count, 10))
	}
	return strings.Join(lines, "\n") + "\n"
}

// Reset clears every series.
func (m *MetricsCollector) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reset()
}
