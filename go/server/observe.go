package server

// Port of packages/server/src/observe.ts.

import (
	"errors"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// SpanKind is operation, authorize, authorizeMany, listAccessible, auth or http.
type SpanKind = string

// IamSpan is one timed unit of work: an operation, an authorization query, an authentication call, or an HTTP request.
type IamSpan struct {
	Kind SpanKind `json:"kind"`
	// Name is the action, authentication method, or request path.
	Name     string `json:"name"`
	TenantID string `json:"tenantId,omitempty"`
	// Outcome is ok, denied or error.
	Outcome string `json:"outcome"`
	// Code is the IamError code for denied and error outcomes.
	Code string `json:"code,omitempty"`
	// Status is the HTTP status of http spans (0: none).
	Status int `json:"status,omitempty"`
	// RequestID is the caller's X-Request-Id on http spans.
	RequestID  string  `json:"requestId,omitempty"`
	DurationMs float64 `json:"durationMs"`
}

// ObservabilityOptions configure span reporting and metrics.
type ObservabilityOptions struct {
	// OnSpan receives every span after it completes. Panics are recovered and ignored.
	OnSpan func(span IamSpan) `json:"-"`
	// Metrics keeps Prometheus-style counters and latency histograms (iam.metrics).
	Metrics *Toggle[MetricsOptions] `json:"metrics,omitempty"`
}

// SpanResult classifies a successful result (outcomeOf): empty members keep the defaults.
type SpanResult struct {
	Outcome string
	Status  int
	Code    string
}

// SpanExtra are extra span members (the request id of http spans).
type SpanExtra struct {
	RequestID string
}

// Observer times units of work and reports them.
type Observer struct {
	// Enabled is true when a span handler is configured.
	Enabled bool
	handler func(IamSpan)
}

// DeniedStatuses: authentication and authorization refusals (401, 403, 429) are `denied`; everything else that
// fails is an `error`.
var DeniedStatuses = map[int]bool{401: true, 403: true, 429: true}

// CreateObserver builds the observer for the options (nil: no handler).
func CreateObserver(options *ObservabilityOptions) *Observer {
	observer := &Observer{}
	if options != nil && options.OnSpan != nil {
		observer.handler = options.OnSpan
		observer.Enabled = true
	}
	return observer
}

func (o *Observer) emit(span IamSpan) {
	defer func() { _ = recover() }() // observability never interferes with the request
	o.handler(span)
}

// Span times fn, then reports the span; outcomeOf classifies a successful result (for advisory denials).
func Span[T any](o *Observer, kind SpanKind, name, tenantID string, fn func() (T, error), outcomeOf func(T) SpanResult, extra *SpanExtra) (T, error) {
	if o == nil || o.handler == nil {
		return fn()
	}
	started := time.Now()
	value, err := fn()
	span := IamSpan{Kind: kind, Name: name, TenantID: tenantID}
	if extra != nil {
		span.RequestID = extra.RequestID
	}
	if err == nil {
		span.Outcome = "ok"
		if outcomeOf != nil {
			result := outcomeOf(value)
			if result.Outcome != "" {
				span.Outcome = result.Outcome
			}
			if result.Status != 0 {
				span.Status = result.Status
			}
			if result.Code != "" {
				span.Code = result.Code
			}
		}
		span.DurationMs = float64(time.Since(started).Nanoseconds()) / 1e6
		o.emit(span)
		return value, nil
	}
	var known *core.IamError
	if errors.As(err, &known) {
		span.Outcome = "error"
		if DeniedStatuses[known.Status] {
			span.Outcome = "denied"
		}
		span.Code = known.Code
	} else {
		span.Outcome = "error"
		span.Code = "INTERNAL_ERROR"
	}
	span.DurationMs = float64(time.Since(started).Nanoseconds()) / 1e6
	o.emit(span)
	return value, err
}
