import type { IamSpan } from './observe.js';

/**
 * A small Prometheus-style collector fed by observability spans: a counter per (kind, name, outcome, code), a
 * latency histogram per kind, and an HTTP counter per (path, status). It keeps no tenant labels, collapses names the
 * caller controls (unknown routes and rejected input), and caps the number of series so a hostile client cannot
 * grow memory without bound.
 */
export interface MetricsOptions {
  /** Histogram bucket upper bounds in seconds (ascending). */
  buckets?: number[];
  /** Serves `GET {basePath}/metrics` to requests carrying `Authorization: Bearer <token>`; otherwise metrics are programmatic only. */
  bearerToken?: string;
  /** Maximum distinct label sets per metric before new ones collapse into `(other)` (default 2000). */
  maxSeries?: number;
  /**
   * Also report storage gauges on each scrape (`better_iam_outbox_messages{state}`, `better_iam_sessions_live{kind}`).
   * Each scrape then reads the outbox and session collections; leave off for very large deployments.
   */
  gauges?: boolean;
}
export interface MetricsSnapshot {
  spans: { kind: string; name: string; outcome: string; code: string; count: number }[];
  durations: { kind: string; count: number; sumSeconds: number; buckets: [number, number][] }[];
  http: { path: string; status: number; count: number }[];
}
export interface MetricsCollector {
  onSpan(span: IamSpan): void;
  /** Prometheus text exposition format. */
  render(): string;
  snapshot(): MetricsSnapshot;
  reset(): void;
}

const defaultBuckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
/** Errors whose span name came from the caller rather than the catalog or route table. */
const callerNamedErrors = new Set([
  'NOT_FOUND',
  'INVALID_INPUT',
  'UNKNOWN_ACTION',
  'INVALID_ACTION',
]);
/**
 * Span kinds named by the action the caller asked about. The name is kept only for an answered decision (allowed,
 * or an advisory `ACCESS_DENIED`); a refused caller (unauthenticated, blocked, invalid input) never names a series,
 * so anonymous requests with made-up actions cannot fill the series budget.
 */
const callerNamedKinds = new Set(['authorize', 'listAccessible']);
/** Longer names are never catalog actions or routes (both cap at 256 characters). */
const maxNameLength = 256;

const escapeLabel = (value: string) =>
  value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
const labels = (pairs: [string, string][]) =>
  `{${pairs.map(([key, value]) => `${key}="${escapeLabel(value)}"`).join(',')}}`;
const seriesKey = (parts: (string | number)[]) => JSON.stringify(parts);

export function createMetrics(options: MetricsOptions = {}): MetricsCollector {
  const buckets = [...(options.buckets ?? defaultBuckets)].sort((a, b) => a - b);
  if (buckets.some((bound) => !(bound > 0)))
    throw new Error('Metrics buckets must be positive numbers');
  const maxSeries = options.maxSeries ?? 2000;
  let spans = new Map<
    string,
    { kind: string; name: string; outcome: string; code: string; count: number }
  >();
  let durations = new Map<string, { count: number; sum: number; counts: number[] }>();
  let http = new Map<string, { path: string; status: number; count: number }>();

  // HTTP spans are classified by status (the handler already names unknown routes `(unknown)`); other kinds by the
  // error code, and caller-named kinds also by whether the caller was answered at all.
  const nameOf = (span: IamSpan) => {
    if (typeof span.name !== 'string' || span.name.length > maxNameLength) return '(invalid)';
    if (span.kind === 'http') return span.status === 404 ? '(unknown)' : span.name;
    if (span.outcome !== 'ok' && span.code && callerNamedErrors.has(span.code)) return '(invalid)';
    if (callerNamedKinds.has(span.kind) && span.outcome !== 'ok' && span.code !== 'ACCESS_DENIED')
      return '(invalid)';
    return span.name;
  };

  return {
    onSpan(span) {
      const name = nameOf(span);
      const code = span.code ?? '';
      const key = seriesKey([span.kind, name, span.outcome, code]);
      let series = spans.get(key);
      if (!series) {
        const collapsed = spans.size >= maxSeries;
        const lookup = collapsed ? seriesKey([span.kind, '(other)', span.outcome, code]) : key;
        series = spans.get(lookup);
        if (!series) {
          series = {
            kind: span.kind,
            name: collapsed ? '(other)' : name,
            outcome: span.outcome,
            code,
            count: 0,
          };
          spans.set(lookup, series);
        }
      }
      series.count++;
      let histogram = durations.get(span.kind);
      if (!histogram) {
        histogram = { count: 0, sum: 0, counts: buckets.map(() => 0) };
        durations.set(span.kind, histogram);
      }
      const seconds = Math.max(0, span.durationMs) / 1000;
      histogram.count++;
      histogram.sum += seconds;
      for (let index = 0; index < buckets.length; index++)
        if (seconds <= buckets[index]!) histogram.counts[index]!++;
      if (span.kind === 'http' && typeof span.status === 'number') {
        const httpKey = seriesKey([name, span.status]);
        let row = http.get(httpKey);
        if (!row) {
          const collapsed = http.size >= maxSeries;
          const lookup = collapsed ? seriesKey(['(other)', span.status]) : httpKey;
          row = http.get(lookup);
          if (!row) {
            row = { path: collapsed ? '(other)' : name, status: span.status, count: 0 };
            http.set(lookup, row);
          }
        }
        row.count++;
      }
    },
    snapshot() {
      return {
        spans: [...spans.values()].map((row) => ({ ...row })),
        durations: [...durations.entries()].map(([kind, histogram]) => ({
          kind,
          count: histogram.count,
          sumSeconds: histogram.sum,
          buckets: buckets.map(
            (bound, index) => [bound, histogram.counts[index]!] as [number, number],
          ),
        })),
        http: [...http.values()].map((row) => ({ ...row })),
      };
    },
    render() {
      const lines: string[] = [
        '# HELP better_iam_spans_total Units of work by kind, name, outcome, and error code.',
        '# TYPE better_iam_spans_total counter',
      ];
      for (const row of [...spans.values()].sort((a, b) =>
        `${a.kind}${a.name}${a.outcome}${a.code}`.localeCompare(
          `${b.kind}${b.name}${b.outcome}${b.code}`,
        ),
      ))
        lines.push(
          `better_iam_spans_total${labels([
            ['kind', row.kind],
            ['name', row.name],
            ['outcome', row.outcome],
            ['code', row.code],
          ])} ${row.count}`,
        );
      lines.push(
        '# HELP better_iam_span_duration_seconds Latency of units of work by kind.',
        '# TYPE better_iam_span_duration_seconds histogram',
      );
      for (const [kind, histogram] of [...durations.entries()].sort(([a], [b]) =>
        a.localeCompare(b),
      )) {
        buckets.forEach((bound, index) => {
          lines.push(
            `better_iam_span_duration_seconds_bucket${labels([
              ['kind', kind],
              ['le', String(bound)],
            ])} ${histogram.counts[index]!}`,
          );
        });
        lines.push(
          `better_iam_span_duration_seconds_bucket${labels([
            ['kind', kind],
            ['le', '+Inf'],
          ])} ${histogram.count}`,
          `better_iam_span_duration_seconds_sum${labels([['kind', kind]])} ${histogram.sum}`,
          `better_iam_span_duration_seconds_count${labels([['kind', kind]])} ${histogram.count}`,
        );
      }
      lines.push(
        '# HELP better_iam_http_requests_total HTTP requests to the IAM handler by route and status.',
        '# TYPE better_iam_http_requests_total counter',
      );
      for (const row of [...http.values()].sort(
        (a, b) => a.path.localeCompare(b.path) || a.status - b.status,
      ))
        lines.push(
          `better_iam_http_requests_total${labels([
            ['path', row.path],
            ['status', String(row.status)],
          ])} ${row.count}`,
        );
      return `${lines.join('\n')}\n`;
    },
    reset() {
      spans = new Map();
      durations = new Map();
      http = new Map();
    },
  };
}
