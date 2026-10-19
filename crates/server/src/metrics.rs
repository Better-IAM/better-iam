//! Port of `packages/server/src/metrics.ts`: a small Prometheus-style collector fed by observability spans.
//!
//! A counter per (kind, name, outcome, code), a latency histogram per kind, and an HTTP counter per (path, status).
//! It keeps no tenant labels, collapses names the caller controls (unknown routes and rejected input), and caps the
//! number of series so a hostile client cannot grow memory without bound. The text exposition is byte-identical to
//! the TypeScript collector's, including its `String.prototype.localeCompare` (ICU root collation) ordering.

use std::cmp::Ordering;
use std::sync::{LazyLock, Mutex};

use icu_collator::{CollatorBorrowed, options::CollatorOptions};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::js::{ThrownError, number_to_string, stringify, utf16_len};
use crate::observe::{IamSpan, SpanKind, SpanOutcome};

/// `MetricsOptions`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsOptions {
    /// Histogram bucket upper bounds in seconds (ascending).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buckets: Option<Vec<f64>>,
    /// Serves `GET {basePath}/metrics` to requests carrying `Authorization: Bearer <token>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,
    /// Maximum distinct label sets per metric before new ones collapse into `(other)` (default 2000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_series: Option<f64>,
    /// Also report storage gauges on each scrape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gauges: Option<bool>,
}

/// One counter series of a [`MetricsSnapshot`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SpanSeries {
    pub kind: String,
    pub name: String,
    pub outcome: String,
    pub code: String,
    pub count: f64,
}

/// One histogram of a [`MetricsSnapshot`].
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurationSeries {
    pub kind: String,
    pub count: f64,
    pub sum_seconds: f64,
    pub buckets: Vec<(f64, f64)>,
}

/// One HTTP series of a [`MetricsSnapshot`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HttpSeries {
    pub path: String,
    pub status: u16,
    pub count: f64,
}

/// `MetricsSnapshot`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MetricsSnapshot {
    pub spans: Vec<SpanSeries>,
    pub durations: Vec<DurationSeries>,
    pub http: Vec<HttpSeries>,
}

const DEFAULT_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
/// Errors whose span name came from the caller rather than the catalog or route table.
const CALLER_NAMED_ERRORS: [&str; 4] = [
    "NOT_FOUND",
    "INVALID_INPUT",
    "UNKNOWN_ACTION",
    "INVALID_ACTION",
];
/// Span kinds named by the action the caller asked about.
const CALLER_NAMED_KINDS: [SpanKind; 2] = [SpanKind::Authorize, SpanKind::ListAccessible];
/// Longer names are never catalog actions or routes (both cap at 256 characters).
const MAX_NAME_LENGTH: usize = 256;

static COLLATOR: LazyLock<CollatorBorrowed<'static>> = LazyLock::new(|| {
    CollatorBorrowed::try_new(Default::default(), CollatorOptions::default())
        .expect("the root collation is compiled in")
});

/// `a.localeCompare(b)` without locales: ICU root collation.
pub fn locale_compare(a: &str, b: &str) -> Ordering {
    COLLATOR.compare(a, b)
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn labels(pairs: &[(&str, &str)]) -> String {
    let inner: Vec<String> = pairs
        .iter()
        .map(|(key, value)| format!("{key}=\"{}\"", escape_label(value)))
        .collect();
    format!("{{{}}}", inner.join(","))
}

/// `seriesKey(parts)`: `JSON.stringify(parts)`.
fn series_key(parts: &[serde_json::Value]) -> String {
    stringify(&serde_json::Value::Array(parts.to_vec()))
}

#[derive(Debug, Clone)]
struct Histogram {
    count: f64,
    sum: f64,
    counts: Vec<f64>,
}

#[derive(Default)]
struct State {
    spans: IndexMap<String, SpanSeries>,
    durations: IndexMap<String, Histogram>,
    http: IndexMap<String, HttpSeries>,
}

/// `MetricsCollector`.
pub struct MetricsCollector {
    buckets: Vec<f64>,
    max_series: f64,
    state: Mutex<State>,
}

/// `createMetrics(options = {})`. Fails with `Error: Metrics buckets must be positive numbers` (a plain JavaScript
/// `Error` in TypeScript) when a bucket bound is not a positive number.
pub fn create_metrics(options: &MetricsOptions) -> Result<MetricsCollector, ThrownError> {
    let mut buckets = options
        .buckets
        .clone()
        .unwrap_or_else(|| DEFAULT_BUCKETS.to_vec());
    // `(a, b) => a - b`: NaN comparisons count as equal (and fail the check below anyway).
    buckets.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    if buckets.iter().any(|bound| bound.is_nan() || *bound <= 0.0) {
        return Err(ThrownError::error(
            "Metrics buckets must be positive numbers",
        ));
    }
    Ok(MetricsCollector {
        buckets,
        max_series: options.max_series.unwrap_or(2000.0),
        state: Mutex::new(State::default()),
    })
}

/// The series name of a span (`nameOf`).
fn name_of(span: &IamSpan) -> String {
    if utf16_len(&span.name) > MAX_NAME_LENGTH {
        return "(invalid)".to_owned();
    }
    if span.kind == SpanKind::Http {
        return if span.status == Some(404) {
            "(unknown)".to_owned()
        } else {
            span.name.clone()
        };
    }
    if span.outcome != SpanOutcome::Ok
        && span
            .code
            .as_deref()
            .is_some_and(|code| !code.is_empty() && CALLER_NAMED_ERRORS.contains(&code))
    {
        return "(invalid)".to_owned();
    }
    if CALLER_NAMED_KINDS.contains(&span.kind)
        && span.outcome != SpanOutcome::Ok
        && span.code.as_deref() != Some("ACCESS_DENIED")
    {
        return "(invalid)".to_owned();
    }
    span.name.clone()
}

impl MetricsCollector {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The bucket bounds in use (sorted).
    pub fn buckets(&self) -> &[f64] {
        &self.buckets
    }

    /// `onSpan(span)`.
    pub fn on_span(&self, span: &IamSpan) {
        let name = name_of(span);
        let code = span.code.clone().unwrap_or_default();
        let kind = span.kind.as_str();
        let outcome = span.outcome.as_str();
        let mut state = self.lock();
        let key = series_key(&[
            kind.into(),
            name.clone().into(),
            outcome.into(),
            code.clone().into(),
        ]);
        if !state.spans.contains_key(&key) {
            let collapsed = state.spans.len() as f64 >= self.max_series;
            let lookup = if collapsed {
                series_key(&[
                    kind.into(),
                    "(other)".into(),
                    outcome.into(),
                    code.clone().into(),
                ])
            } else {
                key.clone()
            };
            let entry = state
                .spans
                .entry(lookup.clone())
                .or_insert_with(|| SpanSeries {
                    kind: kind.to_owned(),
                    name: if collapsed {
                        "(other)".to_owned()
                    } else {
                        name.clone()
                    },
                    outcome: outcome.to_owned(),
                    code: code.clone(),
                    count: 0.0,
                });
            entry.count += 1.0;
        } else if let Some(series) = state.spans.get_mut(&key) {
            series.count += 1.0;
        }
        let buckets = &self.buckets;
        let histogram = state
            .durations
            .entry(kind.to_owned())
            .or_insert_with(|| Histogram {
                count: 0.0,
                sum: 0.0,
                counts: vec![0.0; buckets.len()],
            });
        let seconds = span.duration_ms.max(0.0) / 1000.0;
        let seconds = if span.duration_ms.is_nan() {
            f64::NAN
        } else {
            seconds
        };
        histogram.count += 1.0;
        histogram.sum += seconds;
        for (index, bound) in buckets.iter().enumerate() {
            if seconds <= *bound {
                histogram.counts[index] += 1.0;
            }
        }
        if span.kind == SpanKind::Http
            && let Some(status) = span.status
        {
            let http_key = series_key(&[name.clone().into(), status.into()]);
            if let Some(row) = state.http.get_mut(&http_key) {
                row.count += 1.0;
            } else {
                let collapsed = state.http.len() as f64 >= self.max_series;
                let lookup = if collapsed {
                    series_key(&["(other)".into(), status.into()])
                } else {
                    http_key
                };
                let row = state.http.entry(lookup).or_insert_with(|| HttpSeries {
                    path: if collapsed {
                        "(other)".to_owned()
                    } else {
                        name
                    },
                    status,
                    count: 0.0,
                });
                row.count += 1.0;
            }
        }
    }

    /// `snapshot()`.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let state = self.lock();
        MetricsSnapshot {
            spans: state.spans.values().cloned().collect(),
            durations: state
                .durations
                .iter()
                .map(|(kind, histogram)| DurationSeries {
                    kind: kind.clone(),
                    count: histogram.count,
                    sum_seconds: histogram.sum,
                    buckets: self
                        .buckets
                        .iter()
                        .zip(&histogram.counts)
                        .map(|(bound, count)| (*bound, *count))
                        .collect(),
                })
                .collect(),
            http: state.http.values().cloned().collect(),
        }
    }

    /// `render()`: Prometheus text exposition format.
    pub fn render(&self) -> String {
        let state = self.lock();
        let mut lines: Vec<String> = vec![
            "# HELP better_iam_spans_total Units of work by kind, name, outcome, and error code."
                .into(),
            "# TYPE better_iam_spans_total counter".into(),
        ];
        let mut spans: Vec<&SpanSeries> = state.spans.values().collect();
        spans.sort_by(|a, b| {
            locale_compare(
                &format!("{}{}{}{}", a.kind, a.name, a.outcome, a.code),
                &format!("{}{}{}{}", b.kind, b.name, b.outcome, b.code),
            )
        });
        for row in spans {
            lines.push(format!(
                "better_iam_spans_total{} {}",
                labels(&[
                    ("kind", &row.kind),
                    ("name", &row.name),
                    ("outcome", &row.outcome),
                    ("code", &row.code),
                ]),
                number_to_string(row.count)
            ));
        }
        lines.push(
            "# HELP better_iam_span_duration_seconds Latency of units of work by kind.".into(),
        );
        lines.push("# TYPE better_iam_span_duration_seconds histogram".into());
        let mut durations: Vec<(&String, &Histogram)> = state.durations.iter().collect();
        durations.sort_by(|(a, _), (b, _)| locale_compare(a, b));
        for (kind, histogram) in durations {
            for (index, bound) in self.buckets.iter().enumerate() {
                lines.push(format!(
                    "better_iam_span_duration_seconds_bucket{} {}",
                    labels(&[("kind", kind), ("le", &number_to_string(*bound))]),
                    number_to_string(histogram.counts[index])
                ));
            }
            lines.push(format!(
                "better_iam_span_duration_seconds_bucket{} {}",
                labels(&[("kind", kind), ("le", "+Inf")]),
                number_to_string(histogram.count)
            ));
            lines.push(format!(
                "better_iam_span_duration_seconds_sum{} {}",
                labels(&[("kind", kind)]),
                number_to_string(histogram.sum)
            ));
            lines.push(format!(
                "better_iam_span_duration_seconds_count{} {}",
                labels(&[("kind", kind)]),
                number_to_string(histogram.count)
            ));
        }
        lines.push(
            "# HELP better_iam_http_requests_total HTTP requests to the IAM handler by route and status."
                .into(),
        );
        lines.push("# TYPE better_iam_http_requests_total counter".into());
        let mut http: Vec<&HttpSeries> = state.http.values().collect();
        http.sort_by(|a, b| locale_compare(&a.path, &b.path).then(a.status.cmp(&b.status)));
        for row in http {
            lines.push(format!(
                "better_iam_http_requests_total{} {}",
                labels(&[("path", &row.path), ("status", &row.status.to_string())]),
                number_to_string(row.count)
            ));
        }
        format!("{}\n", lines.join("\n"))
    }

    /// `reset()`.
    pub fn reset(&self) {
        *self.lock() = State::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(kind: SpanKind, name: &str, outcome: SpanOutcome, code: Option<&str>) -> IamSpan {
        IamSpan {
            kind,
            name: name.to_owned(),
            tenant_id: None,
            request_id: None,
            outcome,
            code: code.map(str::to_owned),
            status: None,
            duration_ms: 12.0,
        }
    }

    #[test]
    fn bucket_validation() {
        let error = create_metrics(&MetricsOptions {
            buckets: Some(vec![1.0, 0.0]),
            ..MetricsOptions::default()
        })
        .err()
        .unwrap();
        assert_eq!(error.message, "Metrics buckets must be positive numbers");
        let metrics = create_metrics(&MetricsOptions {
            buckets: Some(vec![1.0, 0.1]),
            ..MetricsOptions::default()
        })
        .unwrap();
        assert_eq!(metrics.buckets(), &[0.1, 1.0]);
    }

    #[test]
    fn names_collapse() {
        let metrics = create_metrics(&MetricsOptions {
            max_series: Some(2.0),
            ..MetricsOptions::default()
        })
        .unwrap();
        metrics.on_span(&span(
            SpanKind::Operation,
            "iam:groups:create",
            SpanOutcome::Ok,
            None,
        ));
        metrics.on_span(&span(
            SpanKind::Authorize,
            "made:up",
            SpanOutcome::Denied,
            Some("UNAUTHENTICATED"),
        ));
        metrics.on_span(&span(
            SpanKind::Operation,
            "iam:roles:create",
            SpanOutcome::Ok,
            None,
        ));
        metrics.on_span(&span(
            SpanKind::Operation,
            "iam:roles:read",
            SpanOutcome::Ok,
            None,
        ));
        let snapshot = metrics.snapshot();
        let names: Vec<&str> = snapshot.spans.iter().map(|row| row.name.as_str()).collect();
        assert_eq!(names, ["iam:groups:create", "(invalid)", "(other)"]);
        assert_eq!(snapshot.spans[2].count, 2.0);
        metrics.reset();
        assert!(metrics.snapshot().spans.is_empty());
    }
}
