import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, createMetrics } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';

const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

const json = { 'content-type': 'application/json', 'x-better-iam': '1' };

describe('metrics and health', () => {
  it('counts spans, buckets latency, serves Prometheus text to the bearer token, and reports health', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    databases.push(database);
    const iam = betterIam({
      database,
      secret: 'metrics-test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
      observability: {
        metrics: { bearerToken: 'scrape-me', buckets: [0.001, 1, 10], gauges: true },
      },
    });
    await iam.initialize();
    const root = await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    // Health needs no credential and one database read.
    const health = await iam.handler(new Request('http://localhost:3000/api/iam/health'));
    expect(health.status).toBe(200);
    expect(await health.json()).toMatchObject({ status: 'ok', database: 'ok' });
    // A failed sign-in, an unknown route, and a rejected action all leave bounded series.
    await expect(
      iam.api.auth.signIn({ tenantId: root.tenant.id, email: 'root@example.test', password: 'no' }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    const unknown = await iam.handler(
      new Request('http://localhost:3000/api/iam/nope/whatever', {
        method: 'POST',
        headers: json,
        body: '{}',
      }),
    );
    expect(unknown.status).toBe(404);
    const snapshot = iam.metrics!.snapshot();
    expect(snapshot.spans).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'auth',
          name: 'signIn',
          outcome: 'denied',
          code: 'INVALID_CREDENTIALS',
          count: 1,
        }),
        expect.objectContaining({ kind: 'http', name: '(unknown)', outcome: 'error', count: 1 }),
      ]),
    );
    expect(snapshot.http).toEqual([{ path: '(unknown)', status: 404, count: 1 }]);
    const auth = snapshot.durations.find((row) => row.kind === 'auth')!;
    expect(auth.count).toBe(1);
    expect(auth.buckets.map(([bound]) => bound)).toEqual([0.001, 1, 10]);
    expect(auth.buckets.at(-1)![1]).toBe(1);
    // The scrape endpoint is token-gated and speaks the text exposition format.
    const anonymous = await iam.handler(new Request('http://localhost:3000/api/iam/metrics'));
    expect(anonymous.status).toBe(401);
    const wrong = await iam.handler(
      new Request('http://localhost:3000/api/iam/metrics', {
        headers: { authorization: 'Bearer nope' },
      }),
    );
    expect(wrong.status).toBe(401);
    const scrape = await iam.handler(
      new Request('http://localhost:3000/api/iam/metrics', {
        headers: { authorization: 'Bearer scrape-me' },
      }),
    );
    expect(scrape.status).toBe(200);
    expect(scrape.headers.get('content-type')).toContain('text/plain');
    const body = await scrape.text();
    expect(body).toContain('# TYPE better_iam_spans_total counter');
    expect(body).toContain(
      'better_iam_spans_total{kind="auth",name="signIn",outcome="denied",code="INVALID_CREDENTIALS"} 1',
    );
    expect(body).toContain('better_iam_span_duration_seconds_bucket{kind="auth",le="+Inf"} 1');
    expect(body).toContain('better_iam_http_requests_total{path="(unknown)",status="404"} 1');
    // Storage gauges ride along when enabled: nothing queued, and no live session yet (the sign-in failed).
    expect(body).toContain('better_iam_outbox_messages{state="pending"} 0');
    expect(body).toContain('better_iam_sessions_live{kind="user"} 0');
    // Scraping itself is not a span; other GETs are 404 and no cookie or CSRF rule applies to GET.
    expect(iam.metrics!.snapshot().http.length).toBe(1);
    const other = await iam.handler(new Request('http://localhost:3000/api/iam/auth/signIn'));
    expect(other.status).toBe(404);
    iam.metrics!.reset();
    expect(iam.metrics!.render()).not.toContain('signIn');
  });

  it('collapses series past the cap and escapes label values', () => {
    const metrics = createMetrics({ maxSeries: 2 });
    for (const name of ['a', 'b', 'c"d\\e\n']) {
      metrics.onSpan({ kind: 'operation', name, outcome: 'ok', durationMs: 1 });
    }
    metrics.onSpan({ kind: 'operation', name: 'a', outcome: 'ok', durationMs: 1 });
    const rendered = metrics.render();
    expect(rendered).toContain(
      'better_iam_spans_total{kind="operation",name="a",outcome="ok",code=""} 2',
    );
    expect(rendered).toContain(
      'better_iam_spans_total{kind="operation",name="(other)",outcome="ok",code=""} 1',
    );
    expect(rendered).not.toContain('c"d');
    metrics.reset();
    metrics.onSpan({ kind: 'operation', name: 'c"d\\e\n', outcome: 'ok', durationMs: 1 });
    expect(metrics.render()).toContain('name="c\\"d\\\\e\\n"');
    expect(() => createMetrics({ buckets: [0] })).toThrow();
    const disabled = betterIam({
      database: sqliteAdapter({ filename: ':memory:' }),
      secret: 'metrics-test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
    });
    expect(disabled.metrics).toBeUndefined();
  });
});
