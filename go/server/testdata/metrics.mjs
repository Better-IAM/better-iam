// Writes metrics.json: span streams fed to the TypeScript createMetrics and the exact text it renders and the
// snapshot it reports, for the Go metrics differential test (metrics_test.go).
// Regenerate (after building the TypeScript packages): node go/server/testdata/metrics.mjs > go/server/testdata/metrics.json
import { createMetrics } from '../../../packages/server/dist/metrics.js';

const kinds = ['operation', 'authorize', 'authorizeMany', 'listAccessible', 'auth', 'http'];
const names = ['iam:groups:create', 'iam:Groups:read', 'documents:read', 'signIn', 'getSession', '/api/iam/groups/create',
  '/api/iam/auth/signIn', 'Zeta', 'alpha', '_private', '(other)', 'a"b\c\nd', 'x'.repeat(257), 'é', 'e', 'E', 'b-a', 'b_a', 'ba'];
const outcomes = ['ok', 'denied', 'error'];
const codes = [undefined, 'ACCESS_DENIED', 'INVALID_INPUT', 'NOT_FOUND', 'UNAUTHENTICATED', 'RATE_LIMITED', 'INTERNAL_ERROR'];
const statuses = [200, 201, 400, 401, 403, 404, 429, 500];
let seed = 7;
const next = () => ((seed = (seed * 1103515245 + 12345) % 2147483648), seed);
const pick = (list) => list[next() % list.length];
const spans = [];
for (let i = 0; i < 600; i++) {
  const kind = pick(kinds);
  const outcome = pick(outcomes);
  const span = { kind, name: pick(names), outcome, durationMs: (next() % 20000) / 7 - 5 };
  const code = outcome === 'ok' ? (next() % 5 === 0 ? 'ACCESS_DENIED' : undefined) : pick(codes);
  if (code !== undefined) span.code = code;
  if (kind === 'http') span.status = pick(statuses);
  spans.push(span);
}
const runs = [
  { options: {}, spans },
  { options: { maxSeries: 12 }, spans },
  { options: { buckets: [10, 0.001, 1] }, spans: spans.slice(0, 50) },
  { options: { maxSeries: 2 }, spans: [
    { kind: 'operation', name: 'a', outcome: 'ok', durationMs: 1 },
    { kind: 'operation', name: 'b', outcome: 'ok', durationMs: 1 },
    { kind: 'operation', name: 'c"d\e\n', outcome: 'ok', durationMs: 1 },
    { kind: 'operation', name: 'a', outcome: 'ok', durationMs: 1 },
  ] },
];
const results = runs.map(({ options, spans }) => {
  const metrics = createMetrics(options);
  for (const span of spans) metrics.onSpan(span);
  return { options, spans, render: metrics.render(), snapshot: metrics.snapshot() };
});
let bucketError;
try {
  createMetrics({ buckets: [0] });
} catch (error) {
  bucketError = error.message;
}
process.stdout.write(JSON.stringify({ node: process.version, runs: results, bucketError }) + '\n');
