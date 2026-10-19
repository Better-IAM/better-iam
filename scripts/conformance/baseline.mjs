#!/usr/bin/env node
// Writes spec/conformance/BASELINE.md from a replay report (`replay.mjs --json`) and the trace directory: how many
// traces were recorded, how many replay, how the reference (TypeScript) server fares against its own traces, per API
// group, and why the rest does not replay, by category.
//
//   node scripts/conformance/baseline.mjs --report <report.json> [--traces spec/conformance/traces]
//        [--out spec/conformance/BASELINE.md] [--runs <n>] [--command "<how the report was made>"]
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const args = { traces: join(root, 'spec', 'conformance', 'traces') };
const argv = process.argv.slice(2);
for (let index = 0; index < argv.length; index++) {
  const key = argv[index].replace(/^--/, '');
  args[key] = argv[++index];
}
if (!args.report) {
  console.error(
    'Usage: node scripts/conformance/baseline.mjs --report <report.json> [--traces dir] [--out file]',
  );
  process.exit(2);
}
const out = resolve(args.out ?? join(root, 'spec', 'conformance', 'BASELINE.md'));
const report = JSON.parse(readFileSync(resolve(args.report), 'utf8'));

// --- Traces on disk ---------------------------------------------------------------------------------------------------
function walk(dir) {
  const files = [];
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) files.push(...walk(path));
    else if (name.endsWith('.jsonl') || name.endsWith('.jsonl.gz')) files.push(path);
  }
  return files;
}
function walkTests(dir, prefix = 'tests') {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...walkTests(path, `${prefix}/${name}`));
    else if (/\.test\.tsx?$/.test(name)) out.push(`${prefix}/${name}`);
  }
  return out;
}
const files = walk(resolve(args.traces));
let bytes = 0;
const headers = [];
const testFiles = new Set();
let recordedSteps = 0;
let replayableSteps = 0;
for (const file of files) {
  const raw = readFileSync(file);
  bytes += raw.length;
  const text = file.endsWith('.gz') ? gunzipSync(raw).toString('utf8') : raw.toString('utf8');
  const header = JSON.parse(text.slice(0, text.indexOf('\n')));
  headers.push(header);
  testFiles.add(header.file);
  recordedSteps += header.steps ?? 0;
  if (header.replayable) replayableSteps += header.replayableSteps ?? 0;
}
const replayable = headers.filter((header) => header.replayable);
const partial = replayable.filter((header) => (header.replayableSteps ?? 0) < (header.steps ?? 0));

// --- Categories of what does not replay -------------------------------------------------------------------------------
const categories = [
  [
    /opened by more than one handle/,
    'CLI and multi-handle tests: another handle (a CLI command, a second adapter) writes the database file',
  ],
  [
    /shared with another instance|another instance opened the same database/,
    'Several instances on one database (restarts, multi-instance fixtures)',
  ],
  [
    /not opened through the SQLite adapter/,
    'Wrapped or custom stores (fault injection, other adapters)',
  ],
  [/plugins is set/, 'Plugins (code without a JSON form)'],
  [
    /protocols is set|useProtocol|protocolHost/,
    'Protocol services and mounts given as code (OAuth/OIDC, SAML, SCIM services built on iam.protocolHost, custom mounts)',
  ],
  [
    /clientInfo is a function|no HTTP request can carry|header holds characters/,
    'Client details no HTTP request can carry (clientInfo code, constant or non-header client fields)',
  ],
  [
    /WebAuthn|JWT the test signed/,
    'Credentials the test signed over server-generated values (WebAuthn, device proofs, OpenID4VCI proofs, hand-made JWTs)',
  ],
  [
    /sent a request to|delivered over the network/,
    'Network services the test runs (JWKS, discovery, poll and webhook endpoints on localhost)',
  ],
  [
    /transaction callback calls/,
    'Library calls inside a test transaction callback that are not instance members taking the transaction',
  ],
  [/keyset cursor/, 'Keyset paging by generated IDs'],
  [/audit hash chain itself/, 'Audit hash chains the test builds itself'],
  [/replaced the database's methods/, "Tests that hook the database's methods"],
  [
    /web framework|larger than the Node transport|larger than the HTTP router/,
    'Transport-specific exchanges (framework middleware, bodies over the router limits)',
  ],
  [
    /reports counters that depend on the transport/,
    'Metrics snapshots (counts depend on the transport)',
  ],
  [/time range by instants/, "Time ranges bounded by the test's own clock readings"],
  [
    /held the .* callback open|callback threw|writes to the store|callback calls|called outside a recorded step|answer repeats|returned a function/,
    'Test callbacks with side effects or test-controlled timing',
  ],
  [
    /is called with a function|returns a function/,
    'Function-valued arguments or results (events.subscribe, inference.gateway, …)',
  ],
  [/never awaited/, 'Calls the test never awaited'],
  [/call inside auth.withClient/, 'Non-routed calls inside auth.withClient'],
  [/is not a JSON object/, 'Inputs that are not JSON objects'],
  [/^\(no steps\)$/, 'Instances the test built but never used (no steps)'],
  [/recorder could not/, 'Values the recorder could not serialize'],
  [
    /is a function|is a .* object|is not a finite number|not a known option/,
    'Other option code without a JSON form',
  ],
];
const categorize = (reason) =>
  categories.find(([pattern]) => pattern.test(reason))?.[1] ?? `Other: ${reason}`;
const tally = (list, pick) => {
  const counts = new Map();
  for (const header of list)
    for (const category of new Set(pick(header).map(categorize)))
      counts.set(category, (counts.get(category) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
};
const whole = tally(
  headers.filter((header) => !header.replayable),
  (header) => (header.reasons?.length ? header.reasons : ['(no steps)']),
);
const tails = tally(partial, (header) =>
  (header.reasons ?? []).filter((reason) => reason.startsWith('replay stops')),
);

// --- Replay results ---------------------------------------------------------------------------------------------------
const reports = report.reports ?? [];
const passed = reports.filter((item) => item.status === 'pass');
const failed = reports.filter((item) => item.status !== 'pass');
const steps = reports.flatMap((item) => item.steps ?? []);
const byKind = new Map();
for (const step of steps) byKind.set(step.kind, (byKind.get(step.kind) ?? 0) + 1);
const tolerated = steps.filter((step) => step.tolerated).length;
const groups = report.groups ?? [];

const lines = [];
const push = (...items) => lines.push(...items);
push(
  '# Conformance baseline: the TypeScript server against its own traces',
  '',
  `Generated by \`scripts/conformance/baseline.mjs\` on ${new Date().toISOString().slice(0, 10)} from a replay of`,
  '`spec/conformance/traces/` against the TypeScript server (`scripts/conformance/serve.mjs`). Every failure here is a',
  'harness defect or nondeterminism of the reference itself; the Rust and Go servers are measured against these numbers.',
  '',
  '## Summary',
  '',
  '| Measure | Count |',
  '| --- | --- |',
  `| Test files with traces | ${testFiles.size} |`,
  `| Traces recorded | ${headers.length} |`,
  `| Steps recorded | ${recordedSteps} |`,
  `| Replayable traces | ${replayable.length} (${partial.length} of them replay only up to a step that cannot be replayed) |`,
  `| Replayable steps | ${replayableSteps} |`,
  `| Not replayable traces | ${headers.length - replayable.length} |`,
  `| **TS-vs-TS passing traces** | **${passed.length} of ${reports.length}** (${reports.length ? ((100 * passed.length) / reports.length).toFixed(2) : '0'}%) |`,
  `| Failing traces | ${failed.length} |`,
  `| Steps replayed | ${steps.length} (${[...byKind.entries()].map(([kind, count]) => `${count} ${kind}`).join(', ')}) |`,
  `| Steps with a tolerance applied (\`tolerances.json\`) | ${tolerated} |`,
  `| Trace data | ${(bytes / 1024 / 1024).toFixed(1)} MB in ${files.length} files |`,
  '',
);
if (args.command) push('Command:', '', '```', args.command, '```', '');
if (args.runs) push(`The result was identical in ${args.runs} consecutive full replays.`, '');
if (failed.length) {
  push('## Failing traces', '', '| Trace | Test | First failing step |', '| --- | --- | --- |');
  for (const item of failed)
    push(
      `| \`${item.id}\` | ${String(item.test ?? '').replace(/\|/g, '\\|')} | ${item.failure ?? ''} |`,
    );
  push('');
}
push(
  '## Per API group',
  '',
  'Replayed steps by group: `api` steps by route group, `http:<group>` for raw HTTP exchanges under the base path,',
  '`http:(protocol)` for other paths, `call:<member>` for control-plane calls, `store` and `outbox`.',
  '',
  '| Group | Passed | Steps | Failed |',
  '| --- | ---: | ---: | ---: |',
);
for (const group of groups)
  push(`| \`${group.group}\` | ${group.passed} | ${group.steps} | ${group.failed} |`);
push(
  '',
  '## Not replayable traces, by category',
  '',
  'A trace counts once per category its reasons fall into.',
  '',
  '| Category | Traces |',
  '| --- | ---: |',
);
for (const [category, count] of whole) push(`| ${category} | ${count} |`);
push(
  '',
  '## Replayable traces that stop early, by category',
  '',
  'The replay runs these traces up to the first step that cannot be replayed (FORMAT.md, "Replayability").',
  '',
  '| Category | Traces |',
  '| --- | ---: |',
);
for (const [category, count] of tails) push(`| ${category} | ${count} |`);
// Test files that build no better-iam instance (protocol packages driven directly, UI and framework packages, pure
// helpers) have no traces; their behavior is covered by the ports' own unit tests and the vectors.
const allTests = walkTests(join(root, 'tests'));
const untraced = allTests.filter((file) => !testFiles.has(file));
push(
  '',
  '## Test files without traces',
  '',
  `${untraced.length} of ${allTests.length} test files build no better-iam instance through \`betterIam()\` (they drive`,
  'the protocol, client, UI or CLI packages directly, or test pure helpers), so they record nothing:',
  '',
  untraced.map((file) => `\`${file.replace(/^tests\//, '')}\``).join(', '),
  '',
);
writeFileSync(out, `${lines.join('\n')}\n`);
console.log(`Wrote ${out}`);
