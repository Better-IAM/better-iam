#!/usr/bin/env node
// Replays recorded conformance traces (spec/conformance/FORMAT.md) over HTTP against any better-iam server.
//
//   node scripts/conformance/replay.mjs [--server "<command with {config} and {port}>"] [--traces <dir>]
//        [--filter <text>]... [--json <report.json>] [--jobs <n>] [--max-diffs <n>] [--verbose] [--no-reuse]
//
// For each replayable trace a fresh server (or a reset of an idle one with the same configuration: a fresh database
// and instance) gets the trace's configuration; the steps are replayed in order with generated values bound by
// position and substituted into later inputs; each response is compared, normalized, with the recording.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer, request as httpRequest, Agent } from 'node:http';
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { gunzipSync } from 'node:zlib';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Bindings,
  compareValues,
  getPath,
  setPath,
  substitute,
  shape,
  substituteString,
} from './lib/compare.mjs';
import { totp } from './lib/totp.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const usage = `Usage: node scripts/conformance/replay.mjs [options]
  --server "<cmd>"   server command; {config} and {port} are replaced (default: the TypeScript server,
                     node scripts/conformance/serve.mjs --conformance --config {config} --port {port})
  --traces <dir>     trace directory (default spec/conformance/traces)
  --filter <text>    only traces whose id, file, test or API groups contain <text>; "group:<name>" matches a
                     group exactly; repeatable (any match)
  --json <file>      write the full report as JSON
  --jobs <n>         servers replaying in parallel (default 1)
  --max-diffs <n>    differences shown per failing step (default 5)
  --store <url>      replay on postgres://… or libsql/file: URLs instead of in-memory SQLite (one database per trace
                     is the caller's job: the URL must point at an empty database, reset between traces)
  --no-reuse         start a new server for every trace instead of resetting an idle one
  --verbose          print every step
  --dump <dir>       write the recorded step and the actual answer of every failing step to <dir>
  --keep-going       replay past the first failing step of a trace (default: stop the trace there)
  --tolerances <f>   known nondeterministic differences to ignore (default spec/conformance/tolerances.json)`;

function parseArgs(argv) {
  const args = { filters: [], jobs: 1, maxDiffs: 5, reuse: true, verbose: false, keepGoing: false };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    const value = () => {
      const next = argv[++index];
      if (next === undefined) throw new Error(`${arg} needs a value`);
      return next;
    };
    switch (arg) {
      case '--server':
        args.server = value();
        break;
      case '--traces':
        args.traces = value();
        break;
      case '--filter':
        args.filters.push(value());
        break;
      case '--json':
        args.json = value();
        break;
      case '--jobs':
        args.jobs = Math.max(1, Number(value()) || 1);
        break;
      case '--max-diffs':
        args.maxDiffs = Math.max(1, Number(value()) || 5);
        break;
      case '--store':
        args.store = value();
        break;
      case '--no-reuse':
        args.reuse = false;
        break;
      case '--verbose':
        args.verbose = true;
        break;
      case '--tolerances':
        args.tolerances = value();
        break;
      case '--dump':
        args.dump = value();
        break;
      case '--keep-going':
        args.keepGoing = true;
        break;
      case '--help':
      case '-h':
        console.log(usage);
        process.exit(0);
      default:
        throw new Error(`Unknown argument ${arg}`);
    }
  }
  return args;
}

let args;
try {
  args = parseArgs(process.argv.slice(2));
} catch (error) {
  console.error(`${error.message}\n\n${usage}`);
  process.exit(2);
}

const serverCommand =
  args.server ??
  `"${process.execPath}" "${join(root, 'scripts', 'conformance', 'serve.mjs')}" --conformance --config {config} --port {port}`;
const traceDir = resolve(args.traces ?? join(root, 'spec', 'conformance', 'traces'));
const workDir = join(tmpdir(), `better-iam-conformance-${process.pid}`);
mkdirSync(workDir, { recursive: true });

// --- Traces -------------------------------------------------------------------------------------------------------------

function listTraceFiles(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...listTraceFiles(path));
    else if (name.endsWith('.jsonl') || name.endsWith('.jsonl.gz')) out.push(path);
  }
  return out;
}

function loadTrace(path) {
  // Traces may be stored gzipped (`.jsonl.gz`) to keep the checked-in set small.
  const raw = readFileSync(path);
  const text = path.endsWith('.gz') ? gunzipSync(raw).toString('utf8') : raw.toString('utf8');
  const lines = text.split('\n').filter(Boolean);
  const header = JSON.parse(lines[0]);
  const steps = lines.slice(1).map((line) => JSON.parse(line));
  return { path, header, steps };
}

const stepGroup = (step, basePath) => {
  if (step.kind === 'api') return step.group;
  if (step.kind === 'http') {
    const path = (step.request?.path ?? '').split('?')[0];
    if (path.startsWith(`${basePath}/`)) {
      const [group] = path.slice(basePath.length + 1).split('/');
      return `http:${group || '/'}`;
    }
    return 'http:(protocol)';
  }
  if (step.kind === 'call') return `call:${String(step.method).split('.')[0]}`;
  return step.kind;
};

function matchesFilter(trace) {
  if (!args.filters.length) return true;
  const basePath = trace.header.config?.basePath ?? '/api/iam';
  const groups = new Set(trace.steps.map((step) => stepGroup(step, basePath)));
  return args.filters.some((filter) => {
    if (filter.startsWith('group:')) return groups.has(filter.slice(6));
    const haystack = [
      trace.header.id,
      trace.header.file,
      ...(trace.header.tests ?? []),
      ...groups,
    ].join('\n');
    return haystack.includes(filter);
  });
}

// --- Server processes -----------------------------------------------------------------------------------------------------

function splitCommand(command) {
  const parts = [];
  let current = '';
  let quote;
  let started = false;
  for (const char of command) {
    if (quote) {
      if (char === quote) quote = undefined;
      else current += char;
    } else if (char === '"' || char === "'") {
      quote = char;
      started = true;
    } else if (/\s/.test(char)) {
      if (started || current) parts.push(current);
      current = '';
      started = false;
    } else current += char;
  }
  if (started || current) parts.push(current);
  return parts;
}

function freePort() {
  return new Promise((resolvePort, reject) => {
    const probe = createServer();
    probe.unref();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolvePort(port));
    });
  });
}

const agent = new Agent({ keepAlive: true, maxSockets: 16 });

/** One HTTP exchange with the server (no User-Agent unless the step sends one). */
function exchange(port, { method = 'POST', path, headers = {}, body }) {
  return new Promise((resolveExchange, reject) => {
    const payload =
      body === undefined ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
    const finalHeaders = { ...headers };
    if (payload) finalHeaders['content-length'] = String(payload.length);
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port,
        method,
        path,
        headers: finalHeaders,
        agent,
        setHost: !('host' in finalHeaders),
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolveExchange({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks),
          }),
        );
        res.on('error', reject);
      },
    );
    req.setTimeout(60_000, () => req.destroy(new Error(`timeout on ${method} ${path}`)));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function control(port, path, body) {
  const response = await exchange(port, {
    method: body === undefined ? 'GET' : 'POST',
    path: `/__conformance/${path}`,
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = response.body.toString('utf8');
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`control ${path} answered ${response.status}: ${text.slice(0, 200)}`);
  }
  if (response.status !== 200)
    throw new Error(`control ${path} answered ${response.status}: ${text.slice(0, 300)}`);
  return json;
}

class ServerProcess {
  constructor(configText) {
    this.configText = configText;
  }
  async start({ expectFailure = false } = {}) {
    this.port = await freePort();
    this.configPath = join(workDir, `config-${this.port}-${Date.now()}.json`);
    writeFileSync(this.configPath, this.configText);
    const argv = splitCommand(serverCommand).map((part) =>
      part.replaceAll('{config}', this.configPath).replaceAll('{port}', String(this.port)),
    );
    this.stderr = '';
    this.stdout = '';
    this.child = spawn(argv[0], argv.slice(1), {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    this.child.stdout.on('data', (chunk) => (this.stdout = (this.stdout + chunk).slice(-20000)));
    this.child.stderr.on('data', (chunk) => (this.stderr = (this.stderr + chunk).slice(-20000)));
    this.exited = new Promise((resolveExit) =>
      this.child.on('exit', (code) => resolveExit(code ?? 1)),
    );
    let exitCode;
    this.exited.then((code) => (exitCode = code));
    const deadline = Date.now() + (expectFailure ? 30_000 : 60_000);
    while (Date.now() < deadline) {
      if (exitCode !== undefined) {
        if (expectFailure) return { exited: exitCode };
        throw new Error(
          `server exited with ${exitCode} before it was ready:\n${this.stderr || this.stdout}`,
        );
      }
      try {
        await control(this.port, 'ready');
        if (expectFailure) return { ready: true };
        return {};
      } catch {
        await new Promise((resolveWait) => setTimeout(resolveWait, 100));
      }
    }
    await this.stop();
    throw new Error(
      `server did not become ready within the deadline:\n${this.stderr || this.stdout}`,
    );
  }
  /** A fresh database and instance; `initialize: false` leaves running migrations to the trace (as the test did). */
  async reset(body = {}) {
    await control(this.port, 'reset', body);
  }
  async stop() {
    if (!this.child || this.child.exitCode !== null) return;
    try {
      await control(this.port, 'shutdown', {});
    } catch {
      /* Killed below. */
    }
    const timeout = new Promise((resolveTimeout) =>
      setTimeout(() => resolveTimeout('timeout'), 5000),
    );
    if ((await Promise.race([this.exited, timeout])) === 'timeout') this.child.kill('SIGKILL');
  }
}

// --- Replay -------------------------------------------------------------------------------------------------------------

const ignoredResponseHeaders = new Set([
  'date',
  'connection',
  'keep-alive',
  'transfer-encoding',
  'content-length',
  'x-response-time',
]);
const droppedRequestHeaders = new Set([
  'content-length',
  'connection',
  'transfer-encoding',
  'keep-alive',
  'expect',
]);

let databaseFiles = 0;
/** A fresh SQLite file for a trace recorded on a database file (`store.path` other than `:memory:`). */
const freshDatabase = () => join(workDir, `trace-${++databaseFiles}.db`);
const onFile = (config) =>
  config.store?.kind === 'sqlite' &&
  config.store.path !== undefined &&
  config.store.path !== ':memory:';

function configFor(trace) {
  const config = structuredClone(trace.header.config);
  if (!args.store && onFile(config)) config.store.path = freshDatabase();
  if (args.store) {
    if (/^postgres(ql)?:/i.test(args.store)) config.store = { kind: 'postgres', url: args.store };
    else if (/^(libsql|wss?|https?|file):/i.test(args.store))
      config.store = { kind: 'libsql', url: args.store };
    else config.store = { kind: 'sqlite', path: args.store };
  }
  return JSON.stringify(config, null, 2);
}

/**
 * A form or query string with bindings substituted per value as well, so short bound values (a 6-digit PIN, a
 * one-time code) are replaced too, not only runs of 12+ characters. Unchanged text is kept byte for byte.
 */
function substituteForm(text, bindings, context) {
  const outer = substituteString(text, bindings, context);
  let changed = false;
  const params = new URLSearchParams(outer);
  const out = new URLSearchParams();
  for (const [key, value] of params) {
    const bound = bindings.get(value);
    if (typeof bound === 'string' && bound !== value) changed = true;
    out.append(key, typeof bound === 'string' ? bound : value);
  }
  return changed ? out.toString() : outer;
}
function substitutePath(path, bindings, context) {
  const at = path.indexOf('?');
  const base = substituteString(at < 0 ? path : path.slice(0, at), bindings, context);
  return at < 0 ? base : `${base}?${substituteForm(path.slice(at + 1), bindings, context)}`;
}

/** The recorded response body, parsed when it is JSON. */
function parseBody(text, type) {
  if (text === undefined) return undefined;
  if (/json/i.test(type ?? '') || /^[[{]/.test(text.trim())) {
    try {
      return { json: JSON.parse(text) };
    } catch {
      /* Fall through to text. */
    }
  }
  return { text };
}

function headerValue(headers, name) {
  const value = headers?.[name];
  return Array.isArray(value) ? value.join(', ') : value;
}

async function replayStep(step, state) {
  const { port, bindings, context, basePath, host } = state;
  const diffs = [];
  const compare = (recorded, actual, path) =>
    compareValues(recorded, actual, bindings, context, path, '', diffs);
  // Values the test computed from earlier outputs: TOTP codes from returned secrets, SHA-256 hashes of returned tokens.
  const derived = (derive) => {
    if (derive.kind === 'totp') {
      const secret = substituteString(derive.secret, bindings, context);
      const base =
        state.clockControlled && state.clock !== undefined
          ? state.clock
          : (step.wall ?? Date.now());
      return totp(secret, base, { window: derive.window ?? 0 });
    }
    if (derive.kind === 'sha256')
      return createHash('sha256')
        .update(substituteString(derive.of, bindings, context))
        .digest('hex');
    return undefined;
  };
  const applyDerive = (value, target = 'input', list = step.derive) => {
    for (const derive of list ?? [])
      if ((derive.target ?? 'input') === target) {
        const replacement = derived(derive);
        if (replacement !== undefined) value = setPath(value, derive.path, replacement);
      }
    return value;
  };
  switch (step.kind) {
    case 'api': {
      const input = applyDerive(substitute(step.input ?? {}, bindings, context));
      const headers = {
        host,
        'content-type': 'application/json',
        'x-better-iam': '1',
        ...substitute(step.headers ?? {}, bindings, context),
      };
      const response = await exchange(port, {
        path: `${basePath}/${step.route}`,
        headers,
        body: JSON.stringify(input),
      });
      const text = response.body.toString('utf8');
      let body;
      try {
        body = JSON.parse(text);
        state.actual = body;
      } catch {
        diffs.push({
          path: '$',
          problem: `non-JSON answer (${response.status})`,
          recorded: '',
          actual: text.slice(0, 160),
        });
        break;
      }
      if (step.error) {
        if (!body.error) {
          diffs.push({
            path: '$',
            problem: `expected error ${step.error.code} (${step.error.status}), got success ${response.status}`,
            recorded: JSON.stringify(step.error),
            actual: JSON.stringify(body.data)?.slice(0, 160),
          });
          break;
        }
        compare(step.error.code, body.error.code, '$.error.code');
        compare(step.error.status, response.status, '$.error.status');
        if (step.error.code !== 'INTERNAL_ERROR')
          compare(step.error.message, body.error.message, '$.error.message');
        if (step.error.retryAfterMs !== undefined && body.error.retryAfterMs === undefined)
          diffs.push({
            path: '$.error.retryAfterMs',
            problem: 'missing',
            recorded: String(step.error.retryAfterMs),
            actual: 'absent',
          });
        break;
      }
      if (body.error) {
        diffs.push({
          path: '$',
          problem: `expected success, got ${body.error.code} (${response.status})`,
          recorded: JSON.stringify(step.output)?.slice(0, 160),
          actual: body.error.message,
        });
        break;
      }
      compare(step.output ?? null, body.data ?? null, '$.data');
      break;
    }
    case 'http': {
      const request = step.request;
      const headers = {};
      for (const [key, value] of Object.entries(request.headers ?? {}))
        if (!droppedRequestHeaders.has(key))
          headers[key] = substituteString(String(value), bindings, context);
      headers.host ??= host;
      let body;
      if (request.body !== undefined) {
        const parsed = parseBody(request.body, headers['content-type']);
        body =
          parsed?.json !== undefined
            ? JSON.stringify(applyDerive(substitute(parsed.json, bindings, context), 'body'))
            : /x-www-form-urlencoded/i.test(headers['content-type'] ?? '')
              ? substituteForm(request.body, bindings, context)
              : substituteString(request.body, bindings, context);
      } else if (request.bodyBase64 !== undefined) body = Buffer.from(request.bodyBase64, 'base64');
      const response = await exchange(port, {
        method: request.method,
        path: substitutePath(request.path, bindings, context),
        headers,
        body,
      });
      state.actual = {
        status: response.status,
        headers: response.headers,
        body: response.body.toString('utf8').slice(0, 200000),
      };
      if (!step.response) break;
      compare(step.response.status, response.status, '$.status');
      for (const [key, value] of Object.entries(step.response.headers ?? {})) {
        if (ignoredResponseHeaders.has(key)) continue;
        const actual = response.headers[key];
        if (actual === undefined) {
          diffs.push({
            path: `$.headers.${key}`,
            problem: 'missing',
            recorded: JSON.stringify(value),
            actual: 'absent',
          });
          continue;
        }
        if (key === 'set-cookie')
          compare(
            [value].flat(),
            cookieLifetimes([value].flat(), [actual].flat(), state.context),
            '$.headers.set-cookie',
          );
        else
          compare(
            headerValue(step.response.headers, key),
            headerValue(response.headers, key),
            `$.headers.${key}`,
          );
      }
      for (const key of Object.keys(response.headers))
        if (!ignoredResponseHeaders.has(key) && !(key in (step.response.headers ?? {})))
          diffs.push({
            path: `$.headers.${key}`,
            problem: 'unexpected header',
            recorded: 'absent',
            actual: JSON.stringify(response.headers[key]),
          });
      const type = headerValue(step.response.headers, 'content-type');
      if (step.response.body !== undefined) {
        const recorded = parseBody(step.response.body, type);
        const actualText = response.body.toString('utf8');
        const actual = parseBody(actualText, headerValue(response.headers, 'content-type'));
        if (recorded.json !== undefined && actual.json !== undefined)
          compare(recorded.json, actual.json, '$.body');
        else if (isPrometheus(type) && isPrometheus(headerValue(response.headers, 'content-type')))
          compare(prometheusShape(step.response.body), prometheusShape(actualText), '$.body');
        else compare(step.response.body, actualText, '$.body');
      } else if (step.response.bodyBase64 !== undefined) {
        const same = Buffer.from(step.response.bodyBase64, 'base64').equals(response.body);
        if (!same && step.response.bodyBase64.length !== response.body.toString('base64').length)
          diffs.push({
            path: '$.body',
            problem: 'binary body differs',
            recorded: `${step.response.bodyBase64.length} b64 chars`,
            actual: `${response.body.toString('base64').length} b64 chars`,
          });
      } else if (response.body.length)
        diffs.push({
          path: '$.body',
          problem: 'unexpected body',
          recorded: 'empty',
          actual: response.body.toString('utf8').slice(0, 160),
        });
      break;
    }
    case 'outbox': {
      const result = await control(
        port,
        'outbox/dispatch',
        substitute(step.input ?? {}, bindings, context),
      );
      if (step.error) {
        if (!result.error)
          diffs.push({
            path: '$',
            problem: 'expected a dispatch error',
            recorded: JSON.stringify(step.error),
            actual: 'success',
          });
        else compare(step.error.code, result.error.code, '$.error.code');
      } else if (result.error)
        diffs.push({
          path: '$',
          problem: `dispatch failed: ${result.error.code}`,
          recorded: '',
          actual: result.error.message,
        });
      compare(step.messages ?? [], result.messages ?? [], '$.messages');
      if (step.output !== undefined && result.result !== undefined)
        compare(step.output, result.result, '$.result');
      break;
    }
    case 'call': {
      const result = await control(port, 'call', {
        method: step.method,
        args: applyDerive(substitute(step.args ?? [], bindings, context), 'args'),
      });
      state.actual = result;
      if (step.error) {
        if (!result.error) {
          diffs.push({
            path: '$',
            problem: `expected error ${step.error.code}`,
            recorded: JSON.stringify(step.error),
            actual: JSON.stringify(result.data)?.slice(0, 160),
          });
          break;
        }
        compare(step.error.code, result.error.code, '$.error.code');
        if (step.error.code !== 'INTERNAL_ERROR') {
          compare(step.error.status, result.error.status, '$.error.status');
          compare(step.error.message, result.error.message, '$.error.message');
        }
        break;
      }
      if (result.error) {
        diffs.push({
          path: '$',
          problem: `expected success, got ${result.error.code}`,
          recorded: JSON.stringify(step.output)?.slice(0, 160),
          actual: result.error.message,
        });
        break;
      }
      compare(step.output, result.data, '$.data');
      break;
    }
    case 'store': {
      if (step.method === 'transaction') {
        const produced = producedValues(step.ops ?? []);
        const opsWith = (table) =>
          (step.ops ?? []).map((op, index) => ({
            method: op.method,
            ...(op.method === 'call' ? { path: op.path } : {}),
            args: applyDerive(
              substitute(referenceResults(op.args ?? [], index, produced), table, context),
              'args',
              op.derive,
            ),
            ...(op.propagate ? { propagate: true } : {}),
          }));
        // A write may carry values the same transaction read first (the test read a record and wrote it back). The
        // batch cannot bind those in between, so it is first run and rolled back until its inputs stop changing.
        const readsBeforeWrite = (step.ops ?? []).some(
          (op, index) =>
            ['get', 'find', 'findOrdered', 'call'].includes(op.method) &&
            (step.ops ?? [])
              .slice(index + 1)
              .some((later) => ['insert', 'put', 'delete', 'call'].includes(later.method)),
        );
        let ops = opsWith(bindings);
        for (let round = 0; readsBeforeWrite && round < 8; round++) {
          const dry = await control(port, 'store', { method: 'transaction', ops, rollback: true });
          const trialTable = bindings.child();
          (step.ops ?? []).forEach((op, index) => {
            const actual = dry.data?.results?.[index];
            // Only reads teach bindings: a write answers with what it was given.
            if (!['get', 'find', 'findOrdered', 'call'].includes(op.method)) return;
            if (op.output !== undefined && actual && !actual.error)
              compareValues(
                op.output,
                actual.data,
                trialTable,
                { ...context, maxDiffs: 1000 },
                '$',
                '',
                [],
              );
          });
          const next = opsWith(trialTable);
          if (JSON.stringify(next) === JSON.stringify(ops)) break;
          ops = next;
        }
        const result = await control(port, 'store', {
          method: 'transaction',
          ops,
          rollback: Boolean(step.rollback),
        });
        const results = result.data?.results ?? [];
        state.actual = result;
        (step.ops ?? []).forEach((op, index) => {
          const actual = results[index];
          if (!actual) {
            diffs.push({
              path: `$.ops[${index}]`,
              problem: 'not executed',
              recorded: op.method,
              actual: 'absent',
            });
            return;
          }
          if (op.error) {
            if (!actual.error)
              diffs.push({
                path: `$.ops[${index}]`,
                problem: 'expected an error',
                recorded: JSON.stringify(op.error),
                actual: 'success',
              });
            else {
              compare(op.error.code, actual.error.code, `$.ops[${index}].error.code`);
              // A library call inside the transaction fails like a `call` step: code, status and message.
              if (op.method === 'call' && op.error.code !== 'INTERNAL_ERROR') {
                compare(op.error.status, actual.error.status, `$.ops[${index}].error.status`);
                compare(op.error.message, actual.error.message, `$.ops[${index}].error.message`);
              }
            }
          } else if (actual.error)
            diffs.push({
              path: `$.ops[${index}]`,
              problem: `failed: ${actual.error.code}`,
              recorded: '',
              actual: actual.error.message,
            });
          else if (op.output !== undefined) compare(op.output, actual.data, `$.ops[${index}].data`);
        });
        break;
      }
      const result = await control(port, 'store', {
        method: step.method,
        args: applyDerive(substitute(step.args ?? [], bindings, context), 'args'),
      });
      state.actual = result;
      if (step.error) {
        if (!result.error)
          diffs.push({
            path: '$',
            problem: 'expected a store error',
            recorded: JSON.stringify(step.error),
            actual: 'success',
          });
        else compare(step.error.code, result.error.code, '$.error.code');
      } else if (result.error)
        diffs.push({
          path: '$',
          problem: `store ${step.method} failed: ${result.error.code}`,
          recorded: '',
          actual: result.error.message,
        });
      else compare(step.output, result.data, '$.data');
      break;
    }
    default:
      diffs.push({
        path: '$',
        problem: `unknown step kind ${step.kind}`,
        recorded: '',
        actual: '',
      });
  }
  return diffs;
}

/**
 * Values the library calls of a transaction returned (records, generated IDs), by their JSON, with the operation and
 * path that produced them: a later operation that passes one on refers to it (`{"$result": [n, ...path]}`), because
 * the IDs the server generates inside one batched transaction cannot be bound before it runs.
 */
function producedValues(ops) {
  const produced = new Map();
  ops.forEach((op, index) => {
    if (op.method !== 'call' || op.output === undefined) return;
    const visit = (value, path, depth) => {
      if (depth > 8) return;
      const generated =
        typeof value === 'string'
          ? value.length >= 12 && shape(value).tokens.length > 0
          : Boolean(value) && typeof value === 'object';
      if (generated) {
        const json = JSON.stringify(value);
        if (!produced.has(json)) produced.set(json, { index, path });
      }
      if (value && typeof value === 'object')
        for (const [key, item] of Object.entries(value))
          visit(item, [...path, Array.isArray(value) ? Number(key) : key], depth + 1);
    };
    visit(op.output, [], 0);
  });
  return produced;
}

function referenceResults(value, before, produced) {
  if (!produced.size) return value;
  const hit = produced.get(JSON.stringify(value));
  if (hit && hit.index < before) return { $result: [hit.index, ...hit.path] };
  if (Array.isArray(value)) return value.map((item) => referenceResults(item, before, produced));
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, referenceResults(item, before, produced)]),
    );
  return value;
}

/**
 * The arguments the server under test passed to the scripted callbacks, compared with the recorded ones (binding the
 * values the server generated, such as a rotated secret it hands to a rotator); a recorded call the server never made,
 * or a call no recorded answer covers, is a difference.
 */
async function compareCallbacks(step, state, diffs) {
  const recorded = (step.callbacks ?? []).map(({ callback, args }) => ({ callback, args }));
  const { calls = [] } = await control(state.port, 'script');
  // The order of the calls may follow generated IDs (one call per person, say): compared as an unordered list.
  compareValues(
    recorded,
    calls.map(({ callback, args }) => ({ callback, args })),
    state.bindings,
    state.context,
    '$.callbacks',
    '',
    diffs,
  );
}

/**
 * A cookie's `Max-Age` and `Expires` are computed from the clock when the answer is written, so they may be a second
 * or so apart between runs: within the time tolerance the actual value takes the recorded one (per cookie name).
 */
function cookieLifetimes(recorded, actual, context) {
  const tolerance = (context.timeToleranceMs ?? 30_000) / 1000;
  const byName = new Map(recorded.map((cookie) => [String(cookie).split('=')[0], String(cookie)]));
  return actual.map((cookie) => {
    const original = byName.get(String(cookie).split('=')[0]);
    if (!original) return cookie;
    let out = String(cookie);
    const recordedAge = /;\s*Max-Age=(\d+)/i.exec(original)?.[1];
    out = out.replace(/(;\s*Max-Age=)(\d+)/i, (match, prefix, age) =>
      recordedAge !== undefined && Math.abs(Number(age) - Number(recordedAge)) <= tolerance
        ? `${prefix}${recordedAge}`
        : match,
    );
    const recordedExpires = /;\s*Expires=([^;]+)/i.exec(original)?.[1];
    out = out.replace(/(;\s*Expires=)([^;]+)/i, (match, prefix, when) =>
      recordedExpires !== undefined &&
      Math.abs(Date.parse(when) - Date.parse(recordedExpires)) <= tolerance * 1000
        ? `${prefix}${recordedExpires}`
        : match,
    );
    return out;
  });
}

/**
 * Prometheus text is compared by its metric families only: counts and durations depend on how the calls arrived
 * (in-process while recording, over HTTP while replaying) and on timing.
 */
const isPrometheus = (type) => /text\/plain/.test(type ?? '') && /version=0\.0\.4/.test(type ?? '');
function prometheusShape(text) {
  const families = new Set();
  for (const line of text.split('\n'))
    if (line.startsWith('# TYPE ') || line.startsWith('# HELP ')) families.add(line);
  return [...families].sort();
}

// --- Tolerances: known nondeterministic spots of the reference implementation ------------------------------------------

const tolerancePath = resolve(
  args.tolerances ?? join(root, 'spec', 'conformance', 'tolerances.json'),
);
const tolerances = existsSync(tolerancePath)
  ? (JSON.parse(readFileSync(tolerancePath, 'utf8')).tolerances ?? [])
  : [];
/** `*` matches within one path member or step name segment; `[*]` (written as is) matches any array index. */
const globToRegExp = (glob) =>
  new RegExp(
    `^${glob
      .split('*')
      .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
      .join('.*?')}$`,
  );
const compiledTolerances = tolerances.map((entry) => ({
  ...entry,
  tracePattern: globToRegExp(entry.trace ?? '*'),
  testPattern: globToRegExp(entry.test ?? '*'),
  stepPattern: globToRegExp(entry.step ?? '*'),
  pathPatterns: (entry.paths ?? []).map(globToRegExp),
}));
/** The tolerance entries for a step of a trace. */
const tolerancesFor = (traceId, test, name, seq) =>
  compiledTolerances.filter(
    (entry) =>
      entry.tracePattern.test(traceId) &&
      entry.testPattern.test(test ?? '') &&
      entry.stepPattern.test(name) &&
      // `concurrent: true`: only steps that ran alongside another step (a race the test starts on purpose).
      (!entry.concurrent || seq === true),
  );
/** Drops the differences a tolerance entry names for this step; returns how many were dropped. */
function tolerate(applicable, diffs) {
  if (!applicable.length) return 0;
  const before = diffs.length;
  const normalized = (path) => path.replace(/\[\d+\]/g, '[*]');
  const kept = diffs.filter(
    (diff) =>
      !applicable.some((entry) =>
        entry.pathPatterns.some((pattern) => pattern.test(normalized(diff.path))),
      ),
  );
  diffs.splice(0, diffs.length, ...kept);
  return before - kept.length;
}

const describeStep = (step) =>
  step.kind === 'api'
    ? step.route
    : step.kind === 'http'
      ? `${step.request?.method} ${step.request?.path?.split('?')[0]}`
      : step.kind === 'outbox'
        ? 'outbox/dispatch'
        : `${step.kind} ${step.method}`;

/**
 * The reset before a trace: the instance a test builds is not initialized until the test says so (`call
 * initialize`, or never), and a trace recorded on a database file gets a new, empty one.
 */
function resetBody(configText) {
  const config = JSON.parse(configText);
  if (!onFile(config)) return { initialize: false };
  config.store.path = freshDatabase();
  return { initialize: false, config };
}

async function replayTrace(trace, servers) {
  const { header } = trace;
  const basePath = header.config?.basePath ?? '/api/iam';
  const report = {
    id: header.id,
    file: header.file,
    test: header.test,
    path: relative(root, trace.path).replace(/\\/g, '/'),
    status: 'pass',
    steps: [],
    replayed: 0,
    total: header.steps,
  };
  const configText = configFor(trace);
  if (header.construction) {
    // Construction must fail the same way: the server exits non-zero and reports the error code on stderr.
    const server = new ServerProcess(configText);
    const outcome = await server.start({ expectFailure: true });
    if (outcome.ready) {
      await server.stop();
      report.status = 'fail';
      report.failure = `expected the server to refuse the configuration with ${header.construction.error.code}, but it started`;
      return report;
    }
    const line = server.stderr.split('\n').find((item) => item.trim().startsWith('{'));
    let reported;
    try {
      reported = JSON.parse(line ?? '').error;
    } catch {
      /* Reported below. */
    }
    if (
      !reported ||
      reported.code !== header.construction.error.code ||
      reported.message !== header.construction.error.message
    ) {
      report.status = 'fail';
      report.failure = `construction: expected ${JSON.stringify(header.construction.error)}, got ${line?.trim() ?? server.stderr.slice(-300)}`;
    }
    return report;
  }
  let server = args.reuse
    ? servers.find((item) => item.idle && item.configText === configText)
    : undefined;
  try {
    if (server) {
      server.idle = false;
      await server.reset(resetBody(configText));
    } else {
      // Stop an idle server with another configuration before starting one for this trace.
      const idle = servers.findIndex((item) => item.idle);
      if (idle >= 0) {
        const [old] = servers.splice(idle, 1);
        await old.stop();
      }
      server = new ServerProcess(configText);
      await server.start();
      await server.reset(resetBody(configText));
      servers.push(server);
    }
  } catch (error) {
    report.status = 'error';
    report.failure = `server: ${error.message}`;
    return report;
  }
  const state = {
    port: server.port,
    bindings: new Bindings(),
    context: {
      maxDiffs: args.maxDiffs,
      clockControlled: Boolean(header.clock?.controlled),
      wallDriftMs: Date.now() - Date.parse(header.recordedAt ?? new Date().toISOString()),
      timeToleranceMs: 30_000,
      records: new Map(),
      wallReplayed: trace.steps.some((step) => step.wall !== undefined),
    },
    basePath,
    host: new URL(header.config.baseURL).host,
    clockControlled: Boolean(header.clock?.controlled),
    clock: undefined,
    scripted: JSON.stringify(header.config).includes('"$scripted"'),
  };
  const limit = header.replayableSteps ?? trace.steps.length;
  const steps = trace.steps.slice(0, limit);
  const settled = new Map();
  let stop = false;
  // Steps that ran alongside others: their callback calls cannot be told apart, so they are not compared.
  const concurrentSteps = new Set(
    steps.flatMap((step) =>
      step.concurrentWith?.length ? [step.seq, ...step.concurrentWith] : [],
    ),
  );
  let previous;
  const runOne = async (step) => {
    // The test waited in real time between two steps (for a flush timer, say): the replay waits as long, since the
    // server's timers run on real time, not on the controlled clocks. Capped at 10 s.
    if (previous && step.wall !== undefined && !concurrentSteps.has(step.seq)) {
      const wait = step.wall - previous.wall - (Date.now() - previous.started);
      if (wait > 100)
        await new Promise((resolveWait) => setTimeout(resolveWait, Math.min(wait, 10_000)));
    }
    if (step.wall !== undefined) previous = { wall: step.wall, started: Date.now() };
    // Both clocks as the recording saw them: the injected clock (when the test controlled it) and the wall clock.
    const clock = {};
    if (state.clockControlled && step.at !== undefined && step.at !== state.clock)
      clock.set = step.at;
    // The wall clock only moves forward: a server refuses records it stamped "in the future" (an authentication a
    // few milliseconds after the clock was set back), so a slower replay runs a little ahead of the recording.
    if (step.wall !== undefined) clock.wall = step.wall;
    if (Object.keys(clock).length) {
      await control(state.port, 'clock', clock);
      if (clock.set !== undefined) state.clock = clock.set;
      state.wall = step.wall;
    }
    // Refused sign-ins write their bookkeeping after the answer; the recording settled it before this step.
    if (step.settle)
      await control(state.port, 'call', { method: 'auth.settleBookkeeping', args: [] });
    // The application's callbacks answer this step as they answered while recording (CONTROL.md, "Script").
    if (state.scripted)
      await control(state.port, 'script', {
        answers: substitute(step.callbacks ?? [], state.bindings, state.context).map(
          (answer, index) => ({ ...answer, id: `${step.seq}:${index}` }),
        ),
        ...(step.concurrentWith?.length ? { append: true } : {}),
      });
    let diffs;
    let tolerated = 0;
    state.context.stepAt = state.clockControlled ? state.clock : undefined;
    const applicable = tolerancesFor(
      header.id,
      step.test,
      describeStep(step),
      concurrentSteps.has(step.seq),
    );
    state.context.ignore = applicable.flatMap((entry) => entry.pathPatterns);
    state.context.tolerated = 0;
    try {
      diffs = await replayStep(step, state);
      if (step.settleAfter)
        await control(state.port, 'call', { method: 'auth.settleBookkeeping', args: [] });
      if (state.scripted && !concurrentSteps.has(step.seq))
        await compareCallbacks(step, state, diffs);
      tolerated = tolerate(applicable, diffs) + state.context.tolerated;
    } catch (error) {
      diffs = [
        {
          path: '$',
          problem: `replay error: ${error.message}`,
          recorded: '',
          actual: args.verbose ? String(error.stack).split('\n').slice(1, 6).join(' | ') : '',
        },
      ];
    }
    const entry = {
      seq: step.seq,
      kind: step.kind,
      group: stepGroup(step, basePath),
      name: describeStep(step),
      test: step.test,
      ok: diffs.length === 0,
      ...(tolerated ? { tolerated } : {}),
      ...(diffs.length ? { diffs } : {}),
    };
    if ((!entry.ok || process.env.CONFORMANCE_DUMP_ALL) && args.dump) {
      mkdirSync(resolve(args.dump), { recursive: true });
      writeFileSync(
        join(resolve(args.dump), `${header.id.replace(/[^A-Za-z0-9.-]+/g, '_')}-${step.seq}.json`),
        JSON.stringify({ trace: header.id, diffs, step, actual: state.actual }, null, 1),
      );
    }
    state.actual = undefined;
    report.steps.push(entry);
    report.replayed++;
    if (args.verbose) console.log(`  ${entry.ok ? 'ok  ' : 'FAIL'} #${step.seq} ${entry.name}`);
    if (!entry.ok && !args.keepGoing) stop = true;
    return entry;
  };
  try {
    for (const step of steps) {
      if (stop) break;
      // Steps the test ran concurrently replay concurrently; everything else waits for what came before.
      const concurrent = new Set(step.concurrentWith ?? []);
      const waits = [];
      for (const [seq, promise] of settled) if (!concurrent.has(seq)) waits.push(promise);
      await Promise.all(waits);
      if (stop) break;
      const promise = runOne(step);
      settled.set(step.seq, promise);
      if (!concurrent.size && !steps.some((other) => other.concurrentWith?.includes(step.seq)))
        await promise;
    }
    await Promise.all(settled.values());
  } finally {
    server.idle = true;
    if (!args.reuse) {
      servers.splice(servers.indexOf(server), 1);
      await server.stop();
    }
  }
  report.steps.sort((a, b) => a.seq - b.seq);
  const failed = report.steps.filter((entry) => !entry.ok);
  if (failed.length) {
    report.status = 'fail';
    report.failure = `step ${failed[0].seq} ${failed[0].name}`;
  }
  return report;
}

// --- Main ---------------------------------------------------------------------------------------------------------------

const files = listTraceFiles(traceDir);
if (!files.length) {
  console.error(
    `No traces under ${traceDir}. Record some with: node scripts/conformance/record.mjs <test files>`,
  );
  process.exit(2);
}
const traces = files.map(loadTrace).filter(matchesFilter);
const replayable = traces.filter((trace) => trace.header.replayable);
console.log(
  `${traces.length} trace(s) selected, ${replayable.length} replayable, server: ${serverCommand}\n`,
);

const reports = [];
const queue = [...replayable];
const workers = Array.from({ length: Math.min(args.jobs, queue.length) }, async () => {
  const servers = [];
  try {
    while (queue.length) {
      const trace = queue.shift();
      const started = Date.now();
      const report = await replayTrace(trace, servers);
      report.ms = Date.now() - started;
      reports.push(report);
      const label = report.status === 'pass' ? 'PASS' : report.status === 'fail' ? 'FAIL' : 'ERR ';
      const counts = `${report.steps.filter((entry) => entry.ok).length}/${report.replayed} steps`;
      console.log(
        `${label} ${report.id} (${counts}${report.total > report.replayed && report.status === 'pass' ? `, ${report.total - (trace.header.replayableSteps ?? 0)} not replayable` : ''}) ${report.ms}ms`,
      );
      if (report.status !== 'pass') {
        console.log(`     ${trace.header.test ?? ''}`);
        console.log(`     ${report.failure}`);
        for (const entry of report.steps.filter((item) => !item.ok).slice(0, 2))
          for (const diff of entry.diffs.slice(0, args.maxDiffs))
            console.log(
              `       #${entry.seq} ${entry.name} ${diff.path}: ${diff.problem}\n         recorded ${diff.recorded}\n         actual   ${diff.actual}`,
            );
      }
    }
  } finally {
    for (const server of servers) await server.stop();
  }
});
await Promise.all(workers);

// Per-group summary over replayed steps, plus traces per test file.
const groups = new Map();
for (const report of reports)
  for (const entry of report.steps) {
    const group = groups.get(entry.group) ?? { group: entry.group, steps: 0, passed: 0, failed: 0 };
    group.steps++;
    if (entry.ok) group.passed++;
    else group.failed++;
    groups.set(entry.group, group);
  }
const notReplayable = traces.filter((trace) => !trace.header.replayable);
const reasons = new Map();
for (const trace of [
  ...notReplayable,
  ...replayable.filter((item) => (item.header.replayableSteps ?? 0) < item.steps.length),
])
  for (const reason of trace.header.reasons ?? []) {
    const key = reason.replace(/step \d+/, 'step N').replace(/[0-9a-f]{8}-[0-9a-f-]{27}/g, '…');
    reasons.set(key, (reasons.get(key) ?? 0) + 1);
  }
const passed = reports.filter((report) => report.status === 'pass').length;
console.log('\nPer API group (replayed steps):');
const rows = [...groups.values()].sort((a, b) => a.group.localeCompare(b.group));
const width = Math.max(10, ...rows.map((row) => row.group.length));
for (const row of rows)
  console.log(
    `  ${row.group.padEnd(width)}  ${String(row.passed).padStart(5)}/${String(row.steps).padEnd(5)} ${row.failed ? `${row.failed} failed` : 'ok'}`,
  );
if (reasons.size) {
  console.log('\nNot replayed (traces, or the rest of a trace), by reason:');
  for (const [reason, count] of [...reasons.entries()].sort((a, b) => b[1] - a[1]).slice(0, 25))
    console.log(`  ${String(count).padStart(4)}  ${reason}`);
}
console.log(
  `\nTraces: ${passed} passed, ${reports.length - passed} failed, ${notReplayable.length} not replayable (of ${traces.length}).`,
);
if (args.json) {
  writeFileSync(
    resolve(args.json),
    JSON.stringify(
      {
        server: serverCommand,
        traces: traceDir,
        summary: {
          selected: traces.length,
          replayed: reports.length,
          passed,
          failed: reports.length - passed,
          notReplayable: notReplayable.length,
        },
        groups: rows,
        reasons: Object.fromEntries(reasons),
        reports,
        notReplayable: notReplayable.map((trace) => ({
          id: trace.header.id,
          reasons: trace.header.reasons,
        })),
      },
      null,
      2,
    ),
  );
  console.log(`Report written to ${args.json}`);
}
try {
  rmSync(workDir, { recursive: true, force: true });
} catch {
  /* A file a server still holds open stays in the temporary directory. */
}
process.exit(reports.length - passed ? 1 : 0);
