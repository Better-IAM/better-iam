import { Alert, Badge, Card, KeyValues, PageHeader, Stat, Table } from '@/components/ui';
import { getIam } from '@/lib/iam';
import { requireRootSession } from '@/lib/session';

// The fields this page reads from the two storage collections; the umbrella package does not re-export the records.
interface OutboxRow {
  id: string;
  tenantId: string;
  deliveredAt?: number;
  failedAt?: number;
  attempts: number;
  [key: string]: unknown;
}
interface SessionRow {
  id: string;
  tenantId: string;
  kind: 'user' | 'role' | 'api-key' | 'session-token';
  expiresAt: number;
  [key: string]: unknown;
}

/** Approximates a quantile from cumulative histogram buckets (upper bound of the first bucket reaching it). */
function quantile(buckets: [number, number][], count: number, q: number): string {
  if (!count) return '—';
  const target = Math.ceil(count * q);
  for (const [bound, cumulative] of buckets)
    if (cumulative >= target) return `≤ ${bound * 1000} ms`;
  return `> ${(buckets.at(-1)?.[0] ?? 0) * 1000} ms`;
}

export default async function Operations() {
  await requireRootSession();
  const iam = await getIam();
  const started = Date.now();
  let database: { ok: boolean; latencyMs: number };
  try {
    await iam.store.find('tenants', { parentId: null });
    database = { ok: true, latencyMs: Date.now() - started };
  } catch {
    database = { ok: false, latencyMs: Date.now() - started };
  }
  const now = Date.now();
  const [outbox, sessions] = await Promise.all([
    iam.store.find<OutboxRow>('outbox'),
    iam.store.find<SessionRow>('sessions'),
  ]);
  const pending = outbox.filter((message) => !message.deliveredAt && !message.failedAt);
  const failed = outbox.filter((message) => message.failedAt);
  const retrying = pending.filter((message) => message.attempts > 0);
  const live = sessions.filter((session) => session.expiresAt > now);
  const byKind = (kind: SessionRow['kind']) =>
    live.filter((session) => session.kind === kind).length;
  // Configuration, durability, and job-backlog findings (read-only; `better-iam doctor` prints the same).
  const check = await iam.selfCheck().catch(() => undefined);
  const snapshot = iam.metrics?.snapshot();
  const spans = snapshot ? [...snapshot.spans].sort((a, b) => b.count - a.count) : [];
  const total = spans.reduce((sum, row) => sum + row.count, 0);
  const denied = spans
    .filter((row) => row.outcome === 'denied')
    .reduce((sum, row) => sum + row.count, 0);
  const errors = spans
    .filter((row) => row.outcome === 'error')
    .reduce((sum, row) => sum + row.count, 0);
  return (
    <>
      <PageHeader
        title="Operations"
        description="Liveness of this process: database reachability, the delivery outbox, live sessions, and the same counters and latency histograms that GET /api/iam/metrics serves to Prometheus."
      />
      <div className="stack">
        <div className="grid cols-4">
          <Stat
            label="Database"
            value={
              database.ok ? (
                <Badge tone="success">reachable</Badge>
              ) : (
                <Badge tone="danger">error</Badge>
              )
            }
            hint={`${database.latencyMs} ms for one read`}
          />
          <Stat
            label="Outbox backlog"
            value={String(pending.length)}
            hint={`${retrying.length} retrying · ${failed.length} abandoned`}
          />
          <Stat
            label="Live sessions"
            value={String(live.length)}
            hint={`${byKind('user')} people · ${byKind('api-key')} API keys · ${byKind('role')} assumed roles · ${byKind('session-token')} session tokens`}
          />
          <Stat
            label="Units of work"
            value={String(total)}
            hint={
              total
                ? `${((denied / total) * 100).toFixed(1)}% denied · ${((errors / total) * 100).toFixed(1)}% errors`
                : 'since this process started'
            }
          />
        </div>
        <Card
          title="Deployment self-check"
          description={
            check
              ? check.ok
                ? 'No errors. Warnings and notes below are worth a look before production.'
                : 'Errors below need fixing before this deployment is safe to run.'
              : 'The self-check could not run.'
          }
          actions={
            check && (
              <Badge tone={check.ok ? (check.findings.length ? 'warning' : 'success') : 'danger'}>
                {check.ok ? (check.findings.length ? 'warnings' : 'healthy') : 'errors'}
              </Badge>
            )
          }
          flush
        >
          {check && (
            <Table
              head={['Severity', 'Check', 'Finding', 'Next step']}
              rows={check.findings.map((finding) => [
                <Badge
                  key="s"
                  tone={
                    finding.severity === 'error'
                      ? 'danger'
                      : finding.severity === 'warning'
                        ? 'warning'
                        : 'neutral'
                  }
                >
                  {finding.severity}
                </Badge>,
                <code key="c" className="small">
                  {finding.check}
                </code>,
                <span key="m">
                  {finding.message}
                  {finding.count !== undefined && (
                    <span className="small muted"> ({finding.count})</span>
                  )}
                </span>,
                <span key="f" className="small">
                  {finding.fix}
                </span>,
              ])}
              empty="Every check passed."
            />
          )}
        </Card>
        {!snapshot ? (
          <Alert tone="warning">
            Metrics are off: set <code>observability.metrics</code> in{' '}
            <code>better-iam.config.mjs</code> to collect them. Set <code>METRICS_TOKEN</code> to
            expose them to a scraper at <code>GET /api/iam/metrics</code>.
          </Alert>
        ) : (
          <>
            <div className="grid cols-2">
              <Card
                title="Latency by kind"
                description="Quantiles are bucket upper bounds; counts are since the process started."
                flush
              >
                <Table
                  head={['Kind', 'Count', 'Mean', 'p50', 'p95', 'p99']}
                  rows={[...snapshot.durations]
                    .sort((a, b) => b.count - a.count)
                    .map((row) => [
                      <code key="k">{row.kind}</code>,
                      String(row.count),
                      row.count ? `${((row.sumSeconds / row.count) * 1000).toFixed(1)} ms` : '—',
                      quantile(row.buckets, row.count, 0.5),
                      quantile(row.buckets, row.count, 0.95),
                      quantile(row.buckets, row.count, 0.99),
                    ])}
                  empty="Nothing recorded yet."
                />
              </Card>
              <Card title="HTTP requests" description="By route and status." flush>
                <Table
                  head={['Route', 'Status', 'Count']}
                  rows={[...snapshot.http]
                    .sort((a, b) => b.count - a.count)
                    .slice(0, 50)
                    .map((row) => [
                      <code key="p" className="small">
                        {row.path}
                      </code>,
                      <Badge
                        key="s"
                        tone={
                          row.status >= 500 ? 'danger' : row.status >= 400 ? 'warning' : 'success'
                        }
                      >
                        {row.status}
                      </Badge>,
                      String(row.count),
                    ])}
                  empty="No HTTP requests through the handler yet."
                />
              </Card>
            </div>
            <Card
              title="Units of work"
              description="Operations (by action), authorization queries, authentication calls, and HTTP requests, with outcome and error code. Names the caller controls are collapsed."
              flush
            >
              <Table
                head={['Kind', 'Name', 'Outcome', 'Code', 'Count']}
                rows={spans.slice(0, 100).map((row) => [
                  <code key="k">{row.kind}</code>,
                  <code key="n" className="small">
                    {row.name}
                  </code>,
                  <Badge
                    key="o"
                    tone={
                      row.outcome === 'ok'
                        ? 'success'
                        : row.outcome === 'denied'
                          ? 'warning'
                          : 'danger'
                    }
                  >
                    {row.outcome}
                  </Badge>,
                  row.code ? <code key="c">{row.code}</code> : '',
                  String(row.count),
                ])}
                empty="Nothing recorded yet."
              />
            </Card>
          </>
        )}
        <Card title="Scraping" description="Pointers for monitoring this deployment.">
          <KeyValues
            items={[
              ['Health', <code key="h">GET /api/iam/health</code>],
              [
                'Metrics',
                <span key="m">
                  <code>GET /api/iam/metrics</code> with{' '}
                  <code>Authorization: Bearer $METRICS_TOKEN</code>
                </span>,
              ],
              [
                'Workers',
                'The console dispatches the outbox and audit hooks once per second in-process.',
              ],
            ]}
          />
        </Card>
      </div>
    </>
  );
}
