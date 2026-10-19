#!/usr/bin/env node
// The standalone TypeScript better-iam server, started from a JSON configuration (spec/conformance/CONFIG.md).
//
//   node scripts/conformance/serve.mjs --config better-iam.json --port 4100 [--host 127.0.0.1] [--conformance]
//
// It serves the built packages (`pnpm build` first). With --conformance it also answers the test-control endpoints
// under /__conformance/ (spec/conformance/CONTROL.md): ready, clock, outbox, events, script, reset, call, store, shutdown. Rust and
// Go servers implement the same flags, configuration and control endpoints.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { optionsFromConfig } from './lib/config.mjs';
import { decodeValue, encodeValue, errorShape } from './lib/encode.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const dist = (name, file = 'index.js') =>
  pathToFileURL(resolve(root, 'packages', name, 'dist', file)).href;

function parseArgs(argv) {
  const args = { host: '127.0.0.1', conformance: false };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    const value = () => {
      const next = argv[++index];
      if (next === undefined) throw new Error(`${arg} needs a value`);
      return next;
    };
    if (arg === '--config') args.config = value();
    else if (arg === '--port') args.port = Number(value());
    else if (arg === '--host') args.host = value();
    else if (arg === '--conformance') args.conformance = true;
    else if (arg === '--help' || arg === '-h') args.help = true;
    else throw new Error(`Unknown argument ${arg}`);
  }
  return args;
}

const usage =
  'Usage: node scripts/conformance/serve.mjs --config <better-iam.json> --port <port> [--host 127.0.0.1] [--conformance]';

let args;
try {
  args = parseArgs(process.argv.slice(2));
} catch (error) {
  console.error(`${error.message}\n${usage}`);
  process.exit(2);
}
if (args.help) {
  console.log(usage);
  process.exit(0);
}
if (!args.config || !Number.isInteger(args.port) || args.port < 0 || args.port > 65535) {
  console.error(usage);
  process.exit(2);
}

const server = await import(dist('server'));
const { sqliteAdapter } = await import(dist('adapter-sqlite'));
const { IamError } = await import(dist('core'));
// Configuration file errors (lib/config.mjs) are shaped like IamError without depending on the package.
const isIamError = (error) => error instanceof IamError || error?.name === 'IamError';

const adapters = {
  sqliteAdapter,
  get postgresAdapter() {
    return lazy.postgres;
  },
  get libsqlAdapter() {
    return lazy.libsql;
  },
};
const lazy = {};

async function loadAdapters(config) {
  const kind = config?.store?.kind;
  if (kind === 'postgres' && !lazy.postgres)
    lazy.postgres = (await import(dist('adapter-postgres'))).postgresAdapter;
  if (kind === 'libsql' && !lazy.libsql)
    lazy.libsql = (await import(dist('adapter-libsql'))).libsqlAdapter;
}

// --- Conformance state: the server clock and the captured deliveries. -----------------------------------------------
// Two clocks (CONTROL.md, "Clock"): the injected clock (`authentication.now`), frozen once set, and the wall clock
// (`Date.now()`, which some modules read directly), which keeps moving in real time from the value it was set to.
const realNow = Date.now.bind(Date);
/** The injected clock's frozen value; undefined while it follows the wall clock. */
let frozen;
/** The wall clock's offset from real time. */
let wallOffset = 0;
const wallNow = () => realNow() + wallOffset;
/** The injected clock (`authentication.now`). */
const now = () => frozen ?? wallNow();
const setClock = (value) => {
  frozen = value;
};
/** Once set, the wall clock never runs backwards: setting an earlier time than it shows keeps the current time. */
let wallSet = false;
const setWall = (value) => {
  wallOffset = wallSet ? Math.max(wallOffset, value - realNow()) : value - realNow();
  wallSet = true;
};
if (args.conformance) Date.now = wallNow;
/** Every delivery captured since the last reset or clear, in delivery order. */
let outbox = [];
/** Deliveries made during the dispatch in progress (`POST /__conformance/outbox/dispatch`). */
let dispatching;
/** Audit events handed to `events.onEvent` (the `events` delivery channel), in order. */
let events = [];
const deliver = async (kind, message) => {
  if (kind === 'events') {
    events.push(encodeValue(message));
    return;
  }
  const captured = { kind, ...structuredClone(message) };
  outbox.push(captured);
  dispatching?.push(captured);
};

// --- Scripted callbacks (CONTROL.md, "Script"): the application's callbacks answer what the recording answered. -------
/** Answers for the steps in progress: {callback, args, result | error, async}, consumed once each. */
let script = [];
/** Every scripted call since the last replacing `script` request: {callback, args, answer (the answer's id)}. */
let scriptCalls = [];
const canonical = (value) =>
  Array.isArray(value)
    ? value.map(canonical)
    : value && typeof value === 'object'
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((key) => [key, canonical(value[key])]),
        )
      : value;
/** A value with epoch-millisecond numbers, ISO-8601 instants and password hashes (random salts) blanked out. */
const timeless = (value) =>
  Array.isArray(value)
    ? value.map(timeless)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, timeless(item)]))
      : typeof value === 'number' && value >= 1e12 && value < 1e13
        ? 0
        : typeof value === 'string' &&
            (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(value) ||
              value.startsWith('$argon2'))
          ? ''
          : value;
const sameValue = (left, right) =>
  JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
/** A thrown value as the recording saw it: an IamError keeps its code, status and message. */
const rethrow = (error) => {
  if (error?.iam) throw new IamError(error.code, error.message, error.status);
  const thrown = new Error(error?.message ?? 'Scripted callback failed');
  if (error?.name) thrown.name = error.name;
  throw thrown;
};
/** The function standing in for the callback at `name` (its option path, e.g. `authentication.requireMfa`). */
const scripted = (name) =>
  function scriptedCallback(...callArgs) {
    const encoded = encodeValue(callArgs);
    let answer = script.find(
      (item) => !item.used && item.callback === name && sameValue(item.args, encoded),
    );
    // Records in the arguments carry clock readings that differ between runs: compare without instants next.
    answer ??= script.find(
      (item) =>
        !item.used && item.callback === name && sameValue(timeless(item.args), timeless(encoded)),
    );
    answer ??= script.find((item) => !item.used && item.callback === name);
    scriptCalls.push({ callback: name, args: encoded, answer: answer?.id ?? null });
    if (!answer) {
      const error = new Error(`No scripted answer for ${name}`);
      error.name = 'ConformanceScriptError';
      throw error;
    }
    answer.used = true;
    const settle = () => ('error' in answer ? rethrow(answer.error) : decodeValue(answer.result));
    return answer.async ? Promise.resolve().then(settle) : settle();
  };

let configText = await readFile(args.config, 'utf8');
let iam;
let database;

async function start(text, { initialize = true } = {}) {
  const config = JSON.parse(text);
  await loadAdapters(config);
  const options = await optionsFromConfig(config, {
    adapters,
    ...(args.conformance ? { now, deliver, scripted } : {}),
  });
  database = options.database;
  iam = server.betterIam(options);
  if (initialize) await iam.initialize();
}

async function stop() {
  const [oldIam, oldDatabase] = [iam, database];
  iam = undefined;
  database = undefined;
  try {
    await oldIam?.flushAccessUsage?.();
  } catch {
    /* Buffered usage of a discarded instance does not matter. */
  }
  await oldDatabase?.close?.().catch(() => {});
}

try {
  await start(configText);
} catch (error) {
  // One JSON line, so a conformance runner can compare why construction failed (CONTROL.md, "Startup").
  console.error(JSON.stringify({ error: errorShape(error, isIamError) }));
  process.exit(1);
}

// --- Control endpoints. ---------------------------------------------------------------------------------------------
const reserved = new Set(['__proto__', 'prototype', 'constructor']);

/** Resolves `bootstrap`, `billing.closePeriod`, `auth.settleBookkeeping` or `api.roles.create` on the instance. */
function resolveMethod(path) {
  if (typeof path !== 'string' || !/^[A-Za-z][\w]*(\.[A-Za-z][\w]*){0,3}$/.test(path))
    throw new IamError('INVALID_INPUT', 'method must be a dotted member path', 400);
  const parts = path.split('.');
  let owner = iam;
  let value = iam;
  for (const part of parts) {
    if (reserved.has(part) || value === null || value === undefined)
      throw new IamError('NOT_FOUND', `Unknown method ${path}`, 404);
    owner = value;
    value = value[part];
  }
  if (typeof value !== 'function') throw new IamError('NOT_FOUND', `Unknown method ${path}`, 404);
  return value.bind(owner);
}

const storeMethods = new Set([
  'get',
  'find',
  'findOrdered',
  'insert',
  'put',
  'delete',
  'collections',
  'describe',
]);

/** `{"$tx": true}` in the arguments of a transaction's `call` operation stands for the transaction itself. */
const withTransaction = (value, tx) =>
  Array.isArray(value)
    ? value.map((item) => withTransaction(item, tx))
    : value && typeof value === 'object' && value.$tx === true && Object.keys(value).length === 1
      ? tx
      : value;

/**
 * `{"$result": [n, ...path]}` in a transaction operation's arguments stands for (a member of) what operation `n` of the
 * same transaction returned: a record a library call created and the test passed on (`issueSession(tx, identity)`).
 */
function withResults(value, earlier) {
  if (Array.isArray(value)) return value.map((item) => withResults(item, earlier));
  if (!value || typeof value !== 'object') return value;
  const keys = Object.keys(value);
  if (keys.length === 1 && keys[0] === '$result' && Array.isArray(value.$result)) {
    const [index, ...path] = value.$result;
    if (!Number.isInteger(index) || index < 0 || index >= earlier.length)
      throw new IamError(
        'INVALID_INPUT',
        `$result names operation ${index}, which has not run`,
        400,
      );
    let node = earlier[index];
    for (const part of path) node = node?.[part];
    return node;
  }
  return Object.fromEntries(keys.map((key) => [key, withResults(value[key], earlier)]));
}

async function storeOp(target, method, rawArgs, op, earlier = []) {
  const decoded = withResults(decodeValue(rawArgs ?? []), earlier);
  // A library call the test made inside its transaction callback (`auth.createIdentity(tx, …)`).
  if (method === 'call' && op) {
    const fn = resolveMethod(op.path);
    return fn(...withTransaction(decoded, target));
  }
  if (!storeMethods.has(method) || typeof target[method] !== 'function')
    throw new IamError('INVALID_INPUT', `Unknown store method ${method}`, 400);
  return target[method](...decoded);
}

class Rollback extends Error {}

async function control(path, body) {
  switch (path) {
    case 'ready':
      return { ready: true, implementation: 'typescript', conformance: 1 };
    case 'clock': {
      if (body) {
        for (const key of ['set', 'advance', 'wall'])
          if (body[key] !== undefined && !Number.isFinite(body[key]))
            throw new IamError('INVALID_INPUT', `${key} must be a number`, 400);
        if (body.real === true) {
          frozen = undefined;
          wallOffset = 0;
          wallSet = false;
        }
        if (body.set !== undefined) setClock(body.set);
        else if (body.advance !== undefined) setClock(now() + body.advance);
        // Without its own value the wall clock moves with the injected clock.
        if (body.wall !== undefined) setWall(body.wall);
        else if (body.set !== undefined || body.advance !== undefined) setWall(now());
      }
      return { now: now(), wall: wallNow(), frozen: frozen !== undefined };
    }
    case 'outbox':
      return { messages: outbox };
    case 'script': {
      if (body === undefined) return { calls: scriptCalls };
      if (!Array.isArray(body?.answers))
        throw new IamError('INVALID_INPUT', 'answers must be an array', 400);
      const answers = body.answers.map((item) => ({ ...item, used: false }));
      script = body.append ? [...script.filter((item) => !item.used), ...answers] : answers;
      if (!body.append) scriptCalls = [];
      return { answers: script.length };
    }
    case 'events':
      return { events };
    case 'events/clear': {
      const cleared = events.length;
      events = [];
      return { cleared };
    }
    case 'outbox/clear': {
      const cleared = outbox.length;
      outbox = [];
      return { cleared };
    }
    case 'outbox/dispatch': {
      if (dispatching) throw new IamError('CONFLICT', 'A dispatch is already running', 409);
      dispatching = [];
      try {
        const result =
          body?.limit === undefined
            ? await iam.auth.dispatchOutbox()
            : await iam.auth.dispatchOutbox(body.limit);
        return { result: encodeValue(result), messages: dispatching };
      } catch (error) {
        return { error: errorShape(error, isIamError), messages: dispatching };
      } finally {
        dispatching = undefined;
      }
    }
    case 'reset': {
      await stop();
      outbox = [];
      events = [];
      script = [];
      scriptCalls = [];
      frozen = undefined;
      wallOffset = 0;
      wallSet = false;
      if (body?.config !== undefined) configText = JSON.stringify(body.config);
      await start(configText, { initialize: body?.initialize !== false });
      return { reset: true };
    }
    case 'call': {
      const fn = resolveMethod(body?.method);
      try {
        const result = await fn(...decodeValue(Array.isArray(body?.args) ? body.args : []));
        return { data: encodeValue(result) };
      } catch (error) {
        return { error: errorShape(error, isIamError) };
      }
    }
    case 'store': {
      if (body?.method === 'transaction') {
        const results = [];
        try {
          await database.transaction(async (tx) => {
            const earlier = [];
            for (const op of body.ops ?? []) {
              try {
                const value = await storeOp(tx, op.method, op.args, op, earlier);
                earlier.push(value);
                results.push({ data: encodeValue(value) });
              } catch (error) {
                if (error instanceof Rollback) throw error;
                earlier.push(undefined);
                results.push({ error: errorShape(error, isIamError) });
                if (op.propagate) throw new Rollback();
              }
            }
            if (body.rollback) throw new Rollback();
          });
          return { data: { results, rolledBack: false } };
        } catch (error) {
          if (error instanceof Rollback) return { data: { results, rolledBack: true } };
          return { error: errorShape(error, isIamError), data: { results, rolledBack: true } };
        }
      }
      try {
        return { data: encodeValue(await storeOp(database, body?.method, body?.args)) };
      } catch (error) {
        return { error: errorShape(error, isIamError) };
      }
    }
    case 'shutdown':
      setImmediate(() => {
        httpServer.close();
        stop().finally(() => process.exit(0));
      });
      return { shutdown: true };
    default:
      throw new IamError('NOT_FOUND', 'Unknown control endpoint', 404);
  }
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString('utf8');
  return text ? JSON.parse(text) : undefined;
}

const send = (res, status, value) => {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.setHeader('cache-control', 'no-store');
  res.end(JSON.stringify(value));
};

/** Requests wait while a reset swaps the instance. */
let resetting = Promise.resolve();

const httpServer = createServer(async (req, res) => {
  const pathname = (req.url ?? '/').split('?')[0];
  if (args.conformance && pathname.startsWith('/__conformance/')) {
    const path = pathname.slice('/__conformance/'.length);
    try {
      const body = req.method === 'POST' ? await readBody(req) : undefined;
      if (req.method !== 'POST' && req.method !== 'GET')
        throw new IamError('METHOD_NOT_ALLOWED', 'Use GET or POST', 405);
      await resetting;
      if (path !== 'reset') {
        send(res, 200, await control(path, body));
        return;
      }
      let release;
      resetting = new Promise((resolve) => (release = resolve));
      try {
        send(res, 200, await control(path, body));
      } finally {
        release();
      }
    } catch (error) {
      const shape = errorShape(error, isIamError);
      send(res, error instanceof SyntaxError ? 400 : shape.status, { error: shape });
    }
    return;
  }
  await resetting;
  return iam.nodeHandler(req, res);
});

httpServer.listen(args.port, args.host, () => {
  const address = httpServer.address();
  console.log(
    `better-iam (typescript) listening on http://${args.host}:${address.port}${args.conformance ? ' (conformance mode)' : ''}`,
  );
});

for (const signal of ['SIGINT', 'SIGTERM'])
  process.on(signal, () => {
    httpServer.close();
    stop().finally(() => process.exit(0));
  });
