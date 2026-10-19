/**
 * The conformance trace recorder (spec/conformance/FORMAT.md). Loaded only when BETTER_IAM_RECORD=<dir> is set:
 * vitest.config.ts then points `@better-iam/server` at ./recording-server.ts, whose `betterIam()` wraps every
 * instance with `recordInstance` and registers ./record-setup.ts, which names the running test and writes the traces.
 *
 * The wrappers return the very promises the library returns and only observe them, so a recorded run behaves like a
 * normal one. Every instance becomes one trace: its options as a JSON configuration, then one step per call the test
 * made on the public surface (`iam.api.*`, `authorize*`/`listAccessible`, HTTP requests through `handler` /
 * `nodeHandler`, outbox dispatches, top-level jobs and helpers, direct store access), each with the clock value the
 * server saw, the HTTP form of the credential, the input, and the output or error.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { isIP } from 'node:net';
import { join, relative, resolve } from 'node:path';
import { IamError } from '@better-iam/core';
import {
  authenticatedAuthMethods,
  publicApiMethods,
  publicAuthMethods,
  routeGroups,
} from '../../packages/server/src/http.ts';
// @ts-expect-error plain ESM helpers shared with the replay runner
import { configFromOptions } from '../../scripts/conformance/lib/config.mjs';
// @ts-expect-error plain ESM helpers shared with the replay runner
import {
  containsFunction,
  encodeValue,
  errorShape,
  httpJson,
  publicResult,
} from '../../scripts/conformance/lib/encode.mjs';
// @ts-expect-error plain ESM helpers shared with the replay runner
import { looksLikeTotpSecret, otpauthSecret, totp } from '../../scripts/conformance/lib/totp.mjs';

type Json = unknown;
type Fn = (...args: any[]) => any;

interface ClientInfo {
  ip?: string;
  userAgent?: string;
  label?: string;
}

interface Derive {
  /** Which part of the step the path points into: input (api), args (call, store), ops (transaction), body (http JSON). */
  target: 'input' | 'args' | 'ops' | 'body';
  path: (string | number)[];
  kind: 'totp' | 'sha256';
  /** totp: the recorded base32 secret. */
  secret?: string;
  /** sha256: the recorded value whose lowercase hex SHA-256 the test sent. */
  of?: string;
  /** totp: 30-second steps relative to the server clock at the step (the replay computes the code the same way). */
  window?: number;
  /** Recorder-internal: the absolute TOTP counter matched, and the time basis before the step ran. */
  counter?: number;
  basis?: number;
}

interface Step {
  type: 'step';
  seq: number;
  test?: string;
  kind: 'api' | 'http' | 'outbox' | 'call' | 'store';
  route?: string;
  group?: string;
  method?: string;
  /** The injected clock (`authentication.now`) the first time the step read it. */
  at?: number;
  /** Wall-clock time (`Date.now()`) when the step started. */
  wall?: number;
  headers?: Record<string, string>;
  input?: Json;
  args?: Json[];
  ops?: StoreOp[];
  rollback?: boolean;
  request?: HttpRecord;
  response?: HttpRecord & { status: number };
  output?: Json;
  error?: Json;
  messages?: Json[];
  concurrentWith?: number[];
  derive?: Derive[];
  /** Why the replay must stop before this step. */
  skip?: string;
  pending?: boolean;
  /** Clock values seen inside the step after the first (an `authentication.now` that is not a plain read). */
  clockMoves?: number;
  /** Refused sign-ins' deferred bookkeeping was settled before the step ran (the replay settles it too). */
  settle?: boolean;
  /** The step's own deferred bookkeeping was settled before the test saw its answer (the replay settles it too). */
  settleAfter?: boolean;
  /** Calls of scripted application callbacks during the step, in call order (CONTROL.md, "Script"). */
  callbacks?: CallbackCall[];
}

interface CallbackCall {
  callback: string;
  args: Json[];
  result?: Json;
  error?: Json;
  async?: boolean;
}

interface StoreOp {
  method: string;
  /** `call` operations: the instance member the transaction callback called with the transaction. */
  path?: string;
  args: Json[];
  /** Hashes or codes inside `args` the test derived from earlier outputs (target `args`). */
  derive?: Derive[];
  output?: Json;
  error?: Json;
  propagate?: boolean;
}

interface HttpRecord {
  method?: string;
  path?: string;
  headers: Record<string, string | string[]>;
  body?: string;
  bodyBase64?: string;
  status?: number;
}

interface Trace {
  index: number;
  file: string;
  test?: string;
  tests: Set<string>;
  options: Json;
  config: Record<string, any>;
  reasons: string[];
  dropped: string[];
  clock: boolean;
  steps: Step[];
  seq: number;
  inflight: Set<Step>;
  lastClock?: number;
  totpSecrets: Set<string>;
  /** SHA-256 hex of every string the server returned, to recognize hashes a test computed from them. */
  digests: Map<string, string>;
  /** Every string (8 to 4096 characters) the server returned: what a test-signed JWT may not carry. */
  outputs: Set<string>;
  /** Every epoch-millisecond number the server returned. */
  outputInstants: Set<number>;
  clientHeaders: boolean;
  baseOrigin: string;
  /** Wall-clock time the instance was created (the replay's reference for wall-clock drift). */
  startedAt: number;
  /** Set when a later instance shares this trace's database: the replay stops at this step count. */
  cutAt?: number;
  cutReason?: string;
  /** A database the test opened that no instance uses yet (see `watchStore`). */
  placeholder?: boolean;
  /** The error `betterIam(options)` threw, when construction failed. */
  construction?: Json;
  /** The instance (for its pending sign-in bookkeeping). */
  instance?: any;
  /** The database the instance was built on, when the recorder observes it. */
  database?: any;
  /** Scripted callbacks still running, with the step count when each was called. */
  heldCallbacks: Set<{ seq: number; name: string; step?: Step }>;
}

interface Scope {
  step?: Step;
  trace?: Trace;
  internal?: boolean;
  client?: ClientInfo;
  /** The store transaction step whose callback (test code) is running. */
  transaction?: Step;
  /** That transaction's recorded operations, and the wrapped transaction handle the callback received. */
  ops?: StoreOp[];
  /** A library call inside a test transaction: the transaction step whose `at` its clock reads set. */
  clockStep?: Step;
  clockTrace?: Trace;
  /** A test callback the library is running (delivery, onEvent): it must not touch the library or the store. */
  callback?: { name: string; trace: Trace; step?: Step };
}

/** A test callback that reached the store or the library: the replay's capture cannot do that, so it stops there. */
function callbackSideEffect(callback: NonNullable<Scope['callback']>, what: string) {
  const reason = `${callback.name} ${what}`;
  if (callback.step) cut(callback.step, reason);
  else {
    callback.trace.cutAt ??= callback.trace.steps.length;
    callback.trace.cutReason ??= reason;
  }
}

const scope = new AsyncLocalStorage<Scope>();
const traces: Trace[] = [];

// --- Outbound network requests -----------------------------------------------------------------------------------------
// A request the server makes while a step runs reaches a service the test started (a JWKS or poll endpoint on
// localhost, a webhook receiver) only while recording: the replay cannot reach it, so the replay stops there. Requests
// to names that do not resolve (`idp.example.test`) fail the same way in every run and stay replayable.

const privateHost = (host: string) => {
  const name = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (name === 'localhost' || name.endsWith('.localhost')) return true;
  if (isIP(name) === 4) {
    const [a, b] = name.split('.').map(Number);
    return (
      a === 127 ||
      a === 10 ||
      a === 0 ||
      (a === 192 && b === 168) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 169 && b === 254)
    );
  }
  if (isIP(name) === 6) return name === '::1' || /^f[cd]/.test(name) || name.startsWith('fe80');
  return false;
};

function outboundHost(target: unknown): string {
  try {
    if (target instanceof URL) return target.hostname;
    if (typeof target === 'string') return new URL(target).hostname;
    if (typeof Request !== 'undefined' && target instanceof Request)
      return new URL(target.url).hostname;
    if (target && typeof target === 'object') {
      const options = target as { hostname?: string; host?: string };
      return options.hostname ?? (options.host ?? '').replace(/:\d+$/, '');
    }
  } catch {
    /* Not a URL. */
  }
  return '';
}

function noteOutbound(target: unknown, via: string) {
  const outer = scope.getStore();
  // Test code (and test callbacks) may talk to whatever it likes; only the server's own requests matter.
  if (!outer?.trace || outer.callback) return;
  const host = outboundHost(target);
  if (!privateHost(host)) return;
  const reason = `the server sent a request to ${host} (${via}), a service the test runs that the replay cannot reach`;
  if (outer.step) cut(outer.step, reason);
  else {
    outer.trace.cutAt ??= outer.trace.steps.length;
    outer.trace.cutReason ??= reason;
  }
}

{
  const nodeRequire = createRequire(import.meta.url);
  for (const name of ['node:http', 'node:https']) {
    const transport = nodeRequire(name);
    for (const member of ['request', 'get']) {
      const original = transport[member];
      transport[member] = function (this: unknown, ...args: any[]) {
        noteOutbound(args[0], name.slice(5));
        return original.apply(this, args);
      };
    }
  }
  syncBuiltinESMExports();
  const originalFetch = globalThis.fetch;
  if (typeof originalFetch === 'function')
    globalThis.fetch = function (this: unknown, input: any, init?: any) {
      noteOutbound(input, 'fetch');
      return originalFetch.call(this, input, init);
    } as typeof fetch;
}

/** Wrapped transaction handles given to test callbacks, with the operations recorded for them. */
const transactionOps = new WeakMap<object, StoreOp[]>();
let currentTest: string | undefined;
let currentFile: string | undefined;
const patchedStores = new WeakMap<object, Trace>();
const isIamError = (error: unknown) => error instanceof IamError;
const isPlainObject = (value: unknown): value is Record<string, any> =>
  Boolean(value) &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));

/** Called by record-setup.ts before each test (and with undefined after it). */
export function setCurrentTest(name: string | undefined, file?: string) {
  currentTest = name;
  if (file) currentFile = file;
}

// --- Credentials and clients -----------------------------------------------------------------------------------------

function headerObject(init: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!init) return out;
  try {
    new Headers(init as HeadersInit).forEach((value, key) => (out[key] = value));
  } catch {
    /* Not a header list. */
  }
  return out;
}

/** Whether the router would trust an Origin: the deployment's own, a configured one, or (with `hosts`) maybe one. */
function trustedOrigin(trace: Trace, origin: string) {
  if (origin === trace.baseOrigin || trace.config.hosts) return true;
  const configured = trace.config.trustedOrigins;
  return Array.isArray(configured) && configured.includes(origin);
}

/** The HTTP request headers that carry an in-process credential (`{ token }` or `{ headers }`). */
function credentialHeaders(credential: unknown, trace: Trace): Record<string, string> {
  if (!credential || typeof credential !== 'object') return {};
  const record = credential as { token?: unknown; headers?: unknown };
  const headers = headerObject(record.headers);
  // `auth.authenticate` reads `token` before any header, so it decides the bearer credential.
  if (typeof record.token === 'string') {
    headers.authorization = `Bearer ${record.token}`;
    delete headers.cookie;
  }
  // In-process calls never look at the Origin, but the router refuses any request from an untrusted one (CSRF and
  // CORS): the HTTP form carries the deployment's own origin instead, which in-process behavior equals.
  if (headers.origin && !trustedOrigin(trace, headers.origin)) {
    if (headers.cookie) headers.origin = trace.baseOrigin;
    else delete headers.origin;
  }
  // The router requires an Origin on cookie requests (CSRF); in-process calls never check it.
  if (headers.cookie && !headers.origin) headers.origin = trace.baseOrigin;
  return headers;
}

/**
 * The request headers that carry an `auth.withClient` client: the ones the test's own `clientInfo` reads (its JSON
 * form, inferred by configFromOptions), else the conformance headers the trace's configuration then reads. `missing`
 * names client fields the test's `clientInfo` never reads from a request, which no HTTP request can carry.
 */
function clientHeaders(
  client: ClientInfo | undefined,
  trace: Trace,
): { headers: Record<string, string>; missing: string[] } {
  const headers: Record<string, string> = {};
  const missing: string[] = [];
  if (!client) return { headers, missing };
  // Values an HTTP header cannot carry (Node refuses characters outside Latin-1): no request could send them.
  for (const field of ['userAgent', 'ip', 'label'] as const) {
    const value = client[field];
    if (typeof value === 'string' && /[^\t\x20-\x7e\x80-\xff]/.test(value))
      missing.push(`${field} (not a valid header value)`);
  }
  const own = trace.config.http?.clientInfo as
    | { userAgent?: boolean; ipHeader?: string; labelHeader?: string }
    | undefined;
  if (client.userAgent) {
    if (own && own.userAgent === false) missing.push('userAgent (its clientInfo never reads it)');
    headers['user-agent'] = client.userAgent;
  }
  if (client.ip) {
    if (own && !own.ipHeader) missing.push('ip (its clientInfo never reads it)');
    headers[own?.ipHeader ?? 'x-conformance-client-ip'] = client.ip;
    if (!own) trace.clientHeaders = true;
  }
  if (client.label) {
    if (own && !own.labelHeader) missing.push('label (its clientInfo never reads it)');
    headers[own?.labelHeader ?? 'x-conformance-client-label'] = client.label;
    if (!own) trace.clientHeaders = true;
  }
  return { headers, missing };
}

// --- TOTP codes a test derived from a secret the server returned ----------------------------------------------------

function collectSecrets(value: unknown, trace: Trace, key = '', depth = 0, output = true) {
  if (depth > 12) return;
  if (typeof value === 'string') {
    if (output && value.length >= 8 && value.length <= 4096) trace.outputs.add(value);
    if (looksLikeTotpSecret(value) && /secret/i.test(key)) trace.totpSecrets.add(value);
    const fromUri = otpauthSecret(value);
    if (fromUri) trace.totpSecrets.add(fromUri);
    if (value.length >= 16 && value.length <= 4096)
      trace.digests.set(createHash('sha256').update(value).digest('hex'), value);
    return;
  }
  if (output && typeof value === 'number' && value >= 1e12 && value < 1e13)
    trace.outputInstants.add(value);
  if (!value || typeof value !== 'object') return;
  for (const [k, v] of Object.entries(value)) collectSecrets(v, trace, k, depth + 1, output);
}

function deriveCodes(input: unknown, trace: Trace, target: Derive['target'] = 'input'): Derive[] {
  if (!trace.totpSecrets.size && !trace.digests.size) return [];
  const found: Derive[] = [];
  const base = trace.clock && trace.lastClock !== undefined ? trace.lastClock : Date.now();
  const bases = [...new Set([base, Date.now()])];
  const visit = (value: unknown, path: (string | number)[], depth: number) => {
    if (depth > 12) return;
    if (typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)) {
      const of = trace.digests.get(value);
      if (of !== undefined) found.push({ target, path, kind: 'sha256', of });
      return;
    }
    if (typeof value === 'string' && /^\d{6}$/.test(value)) {
      for (const secret of trace.totpSecrets)
        for (const time of bases)
          for (let window = -2; window <= 2; window++)
            if (totp(secret, time, { window }) === value) {
              const counter = Math.floor(time / 30000) + window;
              found.push({ target, path, kind: 'totp', secret, window: 0, counter, basis: base });
              return;
            }
      return;
    }
    if (!value || typeof value !== 'object') return;
    for (const [k, v] of Object.entries(value))
      visit(v, [...path, Array.isArray(value) ? Number(k) : k], depth + 1);
  };
  visit(input, [], 0);
  return found;
}

/**
 * A WebAuthn response (`clientDataJSON` naming `webauthn.create` / `webauthn.get`): the test's authenticator signed the
 * server's challenge, which differs in every run, and no replay can sign the new one.
 */
function containsWebAuthn(value: unknown, depth = 0): boolean {
  if (depth > 12) return false;
  if (typeof value === 'string') {
    if (value.length < 40 || value.length > 8192 || !/^[A-Za-z0-9_-]+={0,2}$/.test(value))
      return false;
    try {
      return /"type"\s*:\s*"webauthn\.(create|get)"/.test(
        Buffer.from(value, 'base64url').toString('utf8'),
      );
    } catch {
      return false;
    }
  }
  if (!value || typeof value !== 'object') return false;
  return Object.values(value).some((item) => containsWebAuthn(item, depth + 1));
}
const webAuthnReason =
  'the input is a WebAuthn response the test signed over a server challenge, which the replay cannot sign';

/**
 * A JWT the test made (not one the server returned) whose header or claims carry a value the server generated (a
 * session ID, a nonce, a key ID): its signature covers values that differ in every run, and only the test's key could
 * sign the replay's. Device proofs, OpenID4VCI proofs and tampered tokens are such JWTs.
 */
function containsTestSignedJwt(value: unknown, trace: Trace, depth = 0): boolean {
  if (depth > 12) return false;
  if (typeof value === 'string') {
    for (const [token] of value.matchAll(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g)) {
      if (trace.outputs.has(token) || [...trace.outputs].some((known) => known.includes(token)))
        continue;
      const [header, payload] = token.split('.');
      let decoded: unknown[];
      try {
        decoded = [header, payload].map((part) =>
          JSON.parse(Buffer.from(part, 'base64url').toString('utf8')),
        );
      } catch {
        continue;
      }
      const strings: string[] = [];
      const collect = (item: unknown, level: number) => {
        if (level > 8) return;
        if (typeof item === 'string') strings.push(item);
        else if (item && typeof item === 'object')
          for (const inner of Object.values(item)) collect(inner, level + 1);
      };
      // A claim or header member that came from an answer, or a header naming a server key (`<key id>.1`).
      const ids = (item: string) =>
        item.match(
          /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z][a-z0-9]{1,15}_[A-Za-z0-9_-]{22}/gi,
        ) ?? [];
      const headerStrings: string[] = [];
      collect(decoded[0], 0);
      headerStrings.push(...strings.splice(0));
      collect(decoded[1], 0);
      if (
        [...headerStrings, ...strings].some(
          (item) => item.length >= 8 && trace.outputs.has(item),
        ) ||
        headerStrings.some((item) => ids(item).some((id) => trace.outputs.has(id)))
      )
        return true;
    }
    return false;
  }
  if (!value || typeof value !== 'object') return false;
  return Object.values(value).some((item) => containsTestSignedJwt(item, trace, depth + 1));
}
/**
 * A time-range bound (`from`, `until`, …) the test read from its own clock rather than from an answer: records the
 * server stamps with the wall clock land a little later in a replay that runs slower than the recording did.
 */
function testClockRange(value: unknown, trace: Trace, depth = 0): boolean {
  if (depth > 8 || !value || typeof value !== 'object') return false;
  return Object.entries(value).some(
    ([key, item]) =>
      (typeof item === 'number' &&
        item >= 1e12 &&
        item < 1e13 &&
        /^(from|to|since|until|before|after|start|end)(At|Time|Timestamp)?$/.test(key) &&
        !trace.outputInstants.has(item)) ||
      testClockRange(item, trace, depth + 1),
  );
}

const testJwtReason =
  'the input is a JWT the test signed over values the server generated, which only the test could sign again';

// --- Steps ------------------------------------------------------------------------------------------------------------

function cut(step: Step, reason: string) {
  if (!step.skip) step.skip = reason;
}

/**
 * Records one top-level step around `invoke` (which runs inside the step's scope). Nested calls — the library calling
 * itself, protocol mounts, framework integrations inside a recorded request — run unrecorded.
 */
function runStep<T>(
  trace: Trace,
  base: Omit<Step, 'type' | 'seq'>,
  invoke: () => T,
  settle: (step: Step, outcome: { ok: true; value: any } | { ok: false; error: unknown }) => void,
): T {
  const outer = scope.getStore();
  if (outer?.callback) {
    callbackSideEffect(outer.callback, `calls ${base.method ?? base.route ?? base.kind}`);
    return invoke();
  }
  if (outer?.step || outer?.internal) return invoke();
  // Test code inside a store transaction callback that calls the library (`auth.createIdentity(tx, …)`): the
  // transaction is then not plain store access, and the call is part of it.
  if (outer?.transaction) {
    cut(
      outer.transaction,
      `the transaction callback calls ${base.method ?? base.route ?? base.kind}`,
    );
    return invoke();
  }
  const step: Step = { type: 'step', seq: ++trace.seq, ...base, wall: Date.now() };
  // A refused sign-in writes its bookkeeping after the answer (`deferSignInFailure`); a step that starts while that
  // write is pending would see either state. It is settled first, here and in the replay, so both see it written.
  // A test that swapped the database's methods for its own steers what the library reads and writes from here on.
  if (storeHooked(trace)) cut(step, "the test replaced the database's methods with its own hooks");
  const pending = trace.instance?.auth?.bookkeeping;
  if (
    pending instanceof Set &&
    pending.size &&
    ['api', 'store', 'outbox', 'http'].includes(base.kind)
  ) {
    step.settle = true;
    const run = invoke;
    invoke = (() => trace.instance.auth.settleBookkeeping().then(() => run())) as () => T;
  }
  if (currentTest) {
    step.test = currentTest;
    trace.tests.add(currentTest);
  }
  if (outer?.client && step.kind !== 'store' && step.kind !== 'outbox') {
    const extra = clientHeaders(outer.client, trace);
    if (step.kind === 'http') {
      // A request through the handler carries its own headers; the client scope does not change it.
    } else if (step.kind === 'call') cut(step, 'call inside auth.withClient');
    else {
      step.headers = { ...step.headers, ...extra.headers };
      if (extra.missing.length)
        cut(
          step,
          `auth.withClient sets a client no HTTP request can carry: ${extra.missing.join(', ')}`,
        );
    }
  }
  const derive = [
    ...(step.input !== undefined ? deriveCodes(step.input, trace, 'input') : []),
    ...(step.args !== undefined ? deriveCodes(step.args, trace, 'args') : []),
  ];
  if (derive.length) step.derive = derive;
  if (containsWebAuthn(step.input) || containsWebAuthn(step.args)) cut(step, webAuthnReason);
  if (
    containsTestSignedJwt(step.input, trace) ||
    containsTestSignedJwt(step.args, trace) ||
    containsTestSignedJwt(step.headers, trace) ||
    containsTestSignedJwt(step.request?.headers, trace)
  )
    cut(step, testJwtReason);
  if (testClockRange(step.input, trace) || testClockRange(step.args, trace))
    cut(
      step,
      'the test bounds a time range by instants it read from its own clock, not from an answer',
    );
  // What the test sent is known from here on (a callback that echoes it back is then replayable).
  collectSecrets(step.input ?? step.args, trace, '', 0, false);
  if (trace.inflight.size) step.concurrentWith = [...trace.inflight].map((other) => other.seq);
  trace.steps.push(step);
  trace.inflight.add(step);
  step.pending = true;
  const done = (outcome: { ok: true; value: any } | { ok: false; error: unknown }) => {
    trace.inflight.delete(step);
    delete step.pending;
    // A later step finished while a scripted callback was still running: the test held the callback open (a sink it
    // blocks until it says so), an interleaving the replay's immediate answers cannot reproduce.
    for (const held of trace.heldCallbacks)
      if (step.seq > held.seq) {
        // The step that called it saw what those other steps did: the replay stops before it.
        const caller = held.step ?? trace.steps.find((item) => item.seq === held.seq + 1);
        if (caller)
          cut(caller, `the test held the ${held.name} callback open while other steps ran`);
      }
    try {
      settle(step, outcome);
    } catch (error) {
      cut(step, `recorder could not serialize the result: ${(error as Error).message}`);
    }
    if (step.output !== undefined) collectSecrets(step.output, trace);
    if (step.response?.body) collectSecrets(tryJson(step.response.body), trace);
    if (step.messages) collectSecrets(step.messages, trace);
  };
  let result: T;
  try {
    result = scope.run({ step, trace, client: outer?.client }, invoke);
  } catch (error) {
    done({ ok: false, error });
    throw error;
  }
  if (result && typeof (result as any).then === 'function') {
    (result as any).then(
      (value: unknown) => done({ ok: true, value }),
      (error: unknown) => done({ ok: false, error }),
    );
    // A refusal's bookkeeping is written right after the answer (`deferSignInFailure`): over HTTP that happens before
    // the next request arrives, in process it may run after the test moved its clock on. The recording lets it finish
    // before the test sees the answer (`settleAfter`), as the replay does.
    if (step.kind === 'api') {
      const pendingAfter = () => {
        const set = trace.instance?.auth?.bookkeeping;
        return set instanceof Set && set.size > 0;
      };
      const settleThen = <V>(finish: () => V) => {
        if (!pendingAfter()) return finish();
        step.settleAfter = true;
        return trace.instance.auth.settleBookkeeping().then(finish);
      };
      return (result as any).then(
        (value: unknown) => settleThen(() => value),
        (error: unknown) =>
          settleThen(() => {
            throw error;
          }),
      );
    }
  } else done({ ok: true, value: result });
  return result;
}

const tryJson = (text: string) => {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
};

/** Settles an `api` step the way the HTTP router answers: `publicResult` as JSON, or the error code and status. */
function settleApi(step: Step, outcome: { ok: true; value: any } | { ok: false; error: unknown }) {
  if (outcome.ok) step.output = httpJson(publicResult(outcome.value)) ?? null;
  else step.error = errorShape(outcome.error, isIamError);
}

function settleCall(step: Step, outcome: { ok: true; value: any } | { ok: false; error: unknown }) {
  if (outcome.ok) {
    step.output = encodeValue(outcome.value);
    if (containsFunction(outcome.value)) cut(step, `${step.method} returns a function`);
  } else step.error = errorShape(outcome.error, isIamError);
}

/** An `api` step for a routable call, or a `call` step for anything the router does not expose. */
/**
 * With several regions configured the HTTP router refuses requests for organizations homed in another region
 * (`WRONG_REGION`), a rule in-process calls never meet: those traces replay their API calls in process (`call`).
 */
const inProcessOnly = (trace: Trace) =>
  Boolean(trace.config.regions && typeof trace.config.regions === 'object');

/** The HTTP router's body limit under the API base path. */
const routerBodyLimit = 65536;

function apiStep(
  trace: Trace,
  group: string,
  method: string,
  fn: Fn,
  self: unknown,
  args: any[],
  member = `api.${group}.${method}`,
) {
  const invoke = () => fn.apply(self, args);
  const route = `${group}/${method}`;
  if (inProcessOnly(trace))
    return runStep(
      trace,
      { kind: 'call', method: member, args: encodeArgs(args) },
      invoke,
      settleCall,
    );
  const shape = (headers: Record<string, string>, input: unknown): Omit<Step, 'type' | 'seq'> => {
    const step: Omit<Step, 'type' | 'seq'> = { kind: 'api', route, group, method };
    if (Object.keys(headers).length) step.headers = headers;
    const body = httpJson(input);
    step.input = body === undefined ? {} : body;
    if (input !== undefined && !isPlainObject(input))
      (step as Step).skip = 'input is not a JSON object (the router requires one)';
    else if (Buffer.byteLength(JSON.stringify(step.input)) > routerBodyLimit)
      (step as Step).skip = 'the input is larger than the HTTP router accepts (64 KiB)';
    return step;
  };
  let base: Omit<Step, 'type' | 'seq'>;
  if (group === 'auth') {
    if (method === 'beginMfa') {
      const first = args[0];
      base =
        first && typeof first === 'object' && typeof first.challenge === 'string'
          ? shape({}, { tenantId: first.tenantId, challenge: first.challenge })
          : shape(credentialHeaders(first, trace), {});
    } else if (method === 'confirmMfa') {
      const first = args[0] ?? {};
      const credential = first.credential;
      const body: Record<string, unknown> = { code: first.code };
      if (first.rememberDevice !== undefined) body.rememberDevice = first.rememberDevice;
      if (credential && typeof credential.challenge === 'string') {
        body.credential = { tenantId: credential.tenantId, challenge: credential.challenge };
        base = shape({}, body);
      } else base = shape(credentialHeaders(credential, trace), body);
    } else if (publicAuthMethods.has(method)) base = shape({}, args[0]);
    else if (authenticatedAuthMethods.has(method))
      base = shape(credentialHeaders(args[0], trace), args[1]);
    else
      return runStep(
        trace,
        { kind: 'call', method: `api.auth.${method}`, args: encodeArgs(args) },
        invoke,
        settleCall,
      );
  } else if (routeGroups.has(group)) {
    base = publicApiMethods.has(route)
      ? shape({}, args[0])
      : shape(credentialHeaders(args[0], trace), args[1]);
  } else
    return runStep(
      trace,
      { kind: 'call', method: `api.${group}.${method}`, args: encodeArgs(args) },
      invoke,
      settleCall,
    );
  return runStep(trace, base, invoke, settleApi);
}

function encodeArgs(args: unknown[]) {
  return args.map((arg) => encodeValue(arg));
}

function callStep(trace: Trace, path: string, fn: Fn, self: unknown, args: any[]) {
  // A library call the test makes inside its own store transaction, with that transaction (`auth.createIdentity(tx,
  // …)`): one operation of the transaction step, replayed by the control endpoint with the replay's transaction.
  const outer = scope.getStore();
  const ops = args.length ? transactionOps.get(args[0]) : undefined;
  if (
    ops &&
    outer?.transaction &&
    outer.ops === ops &&
    !outer.step &&
    !outer.internal &&
    !outer.callback &&
    !containsFunction(args.slice(1)) &&
    !args.slice(1).some((arg) => transactionOps.has(arg))
  ) {
    const op: StoreOp = {
      method: 'call',
      path,
      args: [{ $tx: true }, ...encodeArgs(args.slice(1))],
    };
    const derive = deriveCodes(op.args, trace, 'args');
    if (derive.length) op.derive = derive;
    ops.push(op);
    const settle = (value: unknown) => {
      op.output = encodeValue(value);
      if (containsFunction(value)) cut(outer.transaction!, `${path} returns a function`);
      return value;
    };
    const fail = (error: unknown) => {
      op.error = errorShape(error, isIamError);
      op.propagate = true;
      throw error;
    };
    let result: any;
    try {
      // The call reads the clock for the transaction step (its `at`), though it is not a step of its own.
      result = scope.run({ internal: true, clockStep: outer.transaction, clockTrace: trace }, () =>
        fn.apply(self, args),
      );
    } catch (error) {
      return fail(error);
    }
    if (result && typeof result.then === 'function') return result.then(settle, fail);
    return settle(result);
  }
  const base: Omit<Step, 'type' | 'seq'> = { kind: 'call', method: path, args: encodeArgs(args) };
  if (containsFunction(args)) (base as Step).skip = `${path} is called with a function`;
  // Span counts and latencies depend on how calls arrived: in-process while recording, over HTTP while replaying.
  else if (path.startsWith('metrics.'))
    (base as Step).skip = `${path} reports counters that depend on the transport the calls used`;
  return runStep(trace, base, () => fn.apply(self, args), settleCall);
}

/** `iam.authorize` / `authorizeMany` / `listAccessible`: the credential travels in the request object. */
function routeStep(trace: Trace, route: string, fn: Fn, self: unknown, args: any[]) {
  if (inProcessOnly(trace))
    return runStep(
      trace,
      { kind: 'call', method: route, args: encodeArgs(args) },
      () => fn.apply(self, args),
      settleCall,
    );
  const request = args[0] ?? {};
  const { token, headers, ...rest } = request as Record<string, unknown>;
  const base: Omit<Step, 'type' | 'seq'> = {
    kind: 'api',
    route,
    group: route,
    method: route,
    input: httpJson(rest) ?? {},
  };
  const credential = credentialHeaders({ token, headers }, trace);
  if (Object.keys(credential).length) base.headers = credential;
  return runStep(trace, base, () => fn.apply(self, args), settleApi);
}

// --- HTTP transports --------------------------------------------------------------------------------------------------

function bodyRecord(buffer: Buffer | undefined): Pick<HttpRecord, 'body' | 'bodyBase64'> {
  if (!buffer || !buffer.length) return {};
  const text = buffer.toString('utf8');
  return Buffer.from(text, 'utf8').equals(buffer)
    ? { body: text }
    : { bodyBase64: buffer.toString('base64') };
}

/** Codes and hashes inside a JSON request body (target `body`). */
function deriveBody(step: Step, trace: Trace) {
  const body = step.request?.body;
  if (body === undefined || !/^\s*[[{]/.test(body)) return;
  const parsed = tryJson(body);
  if (containsWebAuthn(parsed)) cut(step, webAuthnReason);
  if (containsTestSignedJwt(parsed ?? body, trace)) cut(step, testJwtReason);
  const derive = deriveCodes(parsed, trace, 'body');
  if (derive.length) step.derive = [...(step.derive ?? []), ...derive];
}

function wrapHandler(trace: Trace, handler: Fn) {
  return function recordedHandler(this: unknown, request: Request, ...rest: any[]) {
    const outer = scope.getStore();
    if (outer?.step || outer?.internal || !(request instanceof Request))
      return handler.call(this, request, ...rest);
    const url = new URL(request.url);
    const headers = headerObject(request.headers);
    headers.host ??= url.host;
    const base: Omit<Step, 'type' | 'seq'> = {
      kind: 'http',
      request: { method: request.method, path: url.pathname + url.search, headers },
    };
    // A fetch Request may carry header values no HTTP/1.1 client sends (characters outside Latin-1).
    if (Object.values(headers).some((value) => /[^\t\x20-\x7e\x80-\xff]/.test(value)))
      (base as Step).skip = 'a request header holds characters no HTTP request can carry';
    let bodyPromise: Promise<ArrayBuffer> | undefined;
    if (request.body && !request.bodyUsed) bodyPromise = request.clone().arrayBuffer();
    return runStep(
      trace,
      base,
      () => handler.call(this, request, ...rest),
      () => {},
    ).then(async (response: Response) => {
      const step = trace.steps.find((item) => item.request === base.request);
      if (!step) return response;
      try {
        if (bodyPromise) {
          const bytes = Buffer.from(await bodyPromise);
          Object.assign(step.request!, bodyRecord(bytes));
          // The standalone server reads requests the way `nodeHandler` does, which refuses bodies over 64 KiB under
          // the API base path (2 MiB elsewhere) before the fetch handler sees them.
          const basePath = trace.config.basePath ?? '/api/iam';
          const limit = url.pathname.startsWith(`${basePath}/`) ? 65536 : 2097152;
          if (bytes.length > limit)
            cut(
              step,
              'the request body is larger than the Node transport accepts (recorded through the fetch handler)',
            );
        }
        deriveBody(step, trace);
        const responseHeaders: Record<string, string | string[]> = headerObject(response.headers);
        const cookies = response.headers.getSetCookie?.() ?? [];
        if (cookies.length) responseHeaders['set-cookie'] = cookies;
        step.response = { status: response.status, headers: responseHeaders };
        const type = response.headers.get('content-type') ?? '';
        if (!type.includes('event-stream') && response.body)
          Object.assign(
            step.response,
            bodyRecord(Buffer.from(await response.clone().arrayBuffer())),
          );
        if (step.response.body) collectSecrets(tryJson(step.response.body), trace);
      } catch (error) {
        cut(step, `recorder could not read the HTTP exchange: ${(error as Error).message}`);
      }
      return response;
    });
  };
}

function wrapNodeHandler(trace: Trace, handler: Fn) {
  return function recordedNodeHandler(this: unknown, req: any, res: any, ...rest: any[]) {
    const outer = scope.getStore();
    if (outer?.step || outer?.internal) return handler.call(this, req, res, ...rest);
    const requestChunks: Buffer[] = [];
    const responseChunks: Buffer[] = [];
    // A web framework (Express, Fastify, Nest) that ran first may have set response headers or read the body: the
    // exchange is then partly the framework's, which the standalone server does not reproduce.
    const framework =
      (typeof res.getHeaderNames === 'function' && res.getHeaderNames().length > 0) ||
      req.readableEnded === true ||
      req.body !== undefined;
    // The body arrives after this synchronous call returns (the parser pushes it), so observing `push` sees all of it.
    const push = req.push;
    req.push = function (chunk: unknown, encoding?: BufferEncoding) {
      if (chunk) requestChunks.push(Buffer.from(chunk as Buffer));
      return push.call(this, chunk, encoding);
    };
    const capture = (chunk: unknown, encoding?: unknown) => {
      if (chunk && typeof chunk !== 'function')
        responseChunks.push(
          Buffer.from(
            chunk as string,
            typeof encoding === 'string' ? (encoding as BufferEncoding) : undefined,
          ),
        );
    };
    const write = res.write;
    const end = res.end;
    res.write = function (chunk: unknown, encoding?: unknown, ...more: unknown[]) {
      capture(chunk, encoding);
      return write.call(this, chunk, encoding, ...more);
    };
    res.end = function (chunk: unknown, encoding?: unknown, ...more: unknown[]) {
      capture(chunk, encoding);
      return end.call(this, chunk, encoding, ...more);
    };
    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers ?? {}))
      if (value !== undefined)
        headers[key] = Array.isArray(value) ? value.join(', ') : String(value);
    const request: HttpRecord = { method: req.method, path: req.url, headers };
    let step: Step | undefined;
    const finished = new Promise<void>((resolveFinished) => {
      res.once('finish', resolveFinished);
      res.once('close', resolveFinished);
    });
    const result = runStep(
      trace,
      { kind: 'http', request },
      () => {
        step = scope.getStore()?.step;
        return handler.call(this, req, res, ...rest);
      },
      () => {},
    );
    void Promise.resolve(result)
      .catch(() => {})
      .then(() => finished)
      .then(() => {
        if (!step) return;
        req.push = push;
        Object.assign(request, bodyRecord(Buffer.concat(requestChunks)));
        const declared = Number(headers['content-length'] ?? 0);
        if (framework || (declared > 0 && !requestChunks.length))
          cut(
            step,
            'the request passed through a web framework before nodeHandler (its headers or body handling are part of the exchange)',
          );
        deriveBody(step, trace);
        const responseHeaders: Record<string, string | string[]> = {};
        for (const [key, value] of Object.entries(res.getHeaders?.() ?? {}))
          responseHeaders[key] = Array.isArray(value) ? value.map(String) : String(value);
        step.response = {
          status: res.statusCode,
          headers: responseHeaders,
          ...bodyRecord(Buffer.concat(responseChunks)),
        };
        if (step.response.body) collectSecrets(tryJson(step.response.body), trace);
      });
    return result;
  };
}

// --- Store access from tests ------------------------------------------------------------------------------------------

const storeMethods = [
  'get',
  'find',
  'findOrdered',
  'insert',
  'put',
  'delete',
  'collections',
  'describe',
] as const;

/**
 * Keyset paging by a generated ID (`find(c, where, { after: <last id of the previous page> })`): which records fall on
 * which page follows random IDs, so every run pages differently and the pages cannot be compared one by one.
 */
const pagesByGeneratedId = (args: unknown[]) =>
  args.some(
    (arg) =>
      isPlainObject(arg) &&
      typeof arg.after === 'string' &&
      /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|^[a-z][a-z0-9]{1,15}_[A-Za-z0-9_-]{22}$/i.test(
        arg.after,
      ),
  );
const pagingReason =
  'the test pages through records by generated IDs (a keyset cursor), so pages differ per run';

/**
 * The test appends to the audit hash chain itself (`appendAuditEvent(tx, …)` from @better-iam/core): the hashes it
 * computed cover the chain head and IDs of this run, so the replay's chain would break where the recording's did not.
 */
const appendsAuditChain = (method: string, args: unknown[]) =>
  (method === 'insert' &&
    args[0] === 'audit' &&
    isPlainObject(args[1]) &&
    typeof args[1].hash === 'string') ||
  (method === 'put' && args[0] === 'auditChains');
const chainReason =
  'the test appends to the audit hash chain itself, with hashes that cover values of its own run';

function recordingTx(tx: any, ops: StoreOp[], trace: Trace): any {
  const wrapped: any = Object.create(tx);
  transactionOps.set(wrapped, ops);
  for (const method of storeMethods) {
    if (typeof tx[method] !== 'function') continue;
    wrapped[method] = (...args: any[]) => {
      // The library's own reads and writes through the handle (a `call` operation running) are part of that call.
      const outer = scope.getStore();
      if (outer?.internal || outer?.step) return tx[method](...args);
      const op: StoreOp = { method, args: encodeArgs(args) };
      if (outer?.transaction && pagesByGeneratedId(args)) cut(outer.transaction, pagingReason);
      if (outer?.transaction && appendsAuditChain(method, args))
        cut(outer.transaction, chainReason);
      const derive = deriveCodes(op.args, trace, 'args');
      if (derive.length) op.derive = derive;
      ops.push(op);
      const promise = scope.run({ internal: true }, () => tx[method](...args));
      return Promise.resolve(promise).then(
        (value) => {
          op.output = encodeValue(value);
          return value;
        },
        (error) => {
          op.error = errorShape(error, isIamError);
          op.propagate = true;
          throw error;
        },
      );
    };
  }
  wrapped.transaction = (fn: Fn) => {
    const outerTransaction = scope.getStore()?.transaction;
    return scope.run({ internal: true }, () =>
      tx.transaction((inner: any) => {
        const handle = recordingTx(inner, ops, trace);
        return scope.run({ transaction: outerTransaction, ops }, () => fn(handle));
      }),
    );
  };
  return wrapped;
}

/** Records the test's own reads and writes of the instance's database (`iam.store` or the adapter it passed). */
function patchStore(trace: Trace, database: any) {
  const owner = patchedStores.get(database);
  if (owner && owner !== trace) {
    // Two instances on one database: neither replays past this point.
    owner.cutAt ??= owner.steps.length;
    owner.cutReason ??= 'another instance opened the same database';
    trace.reasons.push('the database is shared with another instance');
    return;
  }
  if (owner) return;
  patchedStores.set(database, trace);
  for (const method of [...storeMethods, 'transaction'] as const) {
    const original = database[method];
    if (typeof original !== 'function') continue;
    database[method] = function (this: unknown, ...args: any[]) {
      // The database's current owner: a failed construction hands it back to a placeholder.
      const trace = patchedStores.get(database) as Trace;
      const outer = scope.getStore();
      const self = this ?? database;
      if (outer?.callback && ['insert', 'put', 'delete', 'transaction'].includes(method))
        callbackSideEffect(outer.callback, 'writes to the store');
      if (
        outer?.callback ||
        outer?.step ||
        outer?.internal ||
        (outer?.trace !== undefined && outer.trace !== trace)
      )
        return original.apply(self, args);
      if (method === 'transaction') {
        const ops: StoreOp[] = [];
        const fn = args[0] as Fn;
        return runStep(
          trace,
          { kind: 'store', method: 'transaction', ops },
          () =>
            original.call(self, (tx: any) => {
              const handle = recordingTx(tx, ops, trace);
              return scope.run({ transaction: scope.getStore()?.step, ops }, () => fn(handle));
            }),
          (step, outcome) => {
            if (outcome.ok) step.output = encodeValue(outcome.value);
            else {
              step.error = errorShape(outcome.error, isIamError);
              step.rollback = true;
            }
          },
        );
      }
      return runStep(
        trace,
        {
          kind: 'store',
          method,
          args: encodeArgs(args),
          ...(pagesByGeneratedId(args)
            ? { skip: pagingReason }
            : appendsAuditChain(method, args)
              ? { skip: chainReason }
              : {}),
        },
        () => original.apply(self, args),
        (step, outcome) => {
          if (outcome.ok) step.output = encodeValue(outcome.value);
          else step.error = errorShape(outcome.error, isIamError);
        },
      );
    };
    patchedMethods.set(database, { ...patchedMethods.get(database), [method]: database[method] });
  }
}

/** The recording wrappers installed on each database, to notice a test that swaps the methods for its own. */
const patchedMethods = new WeakMap<object, Record<string, unknown>>();

/** True when the test replaced a recorded database's methods with its own (fault injection, read hooks). */
function storeHooked(trace: Trace): boolean {
  const database = trace.database;
  const installed = database ? patchedMethods.get(database) : undefined;
  return Boolean(
    installed && Object.entries(installed).some(([method, fn]) => database[method] !== fn),
  );
}

// --- The instance proxy -----------------------------------------------------------------------------------------------

const routeMembers = new Set(['authorize', 'authorizeMany', 'listAccessible']);
/** Members that never become steps (plain data, or transports wrapped separately). */
const passthrough = new Set(['store', 'endpoint', 'then']);

function proxyApi(trace: Trace, api: any) {
  const groups = new Map<string, any>();
  return new Proxy(api, {
    get(target, group, receiver) {
      const value = Reflect.get(target, group, receiver);
      if (typeof group !== 'string' || !value || typeof value !== 'object') return value;
      let proxied = groups.get(group);
      if (!proxied) {
        const methods = new Map<string, Fn>();
        proxied = new Proxy(value, {
          get(groupTarget, method, groupReceiver) {
            const fn = Reflect.get(groupTarget, method, groupReceiver);
            if (typeof method !== 'string' || typeof fn !== 'function') return fn;
            let wrapped = methods.get(method);
            if (!wrapped) {
              wrapped = function (this: unknown, ...args: any[]) {
                return apiStep(trace, group, method, fn, groupTarget, args);
              };
              methods.set(method, wrapped);
            }
            return wrapped;
          },
        });
        groups.set(group, proxied);
      }
      return proxied;
    },
  });
}

/** `iam.auth`: HTTP-exposed methods become `api` steps, `dispatchOutbox` an `outbox` step, the rest `call` steps. */
function proxyAuth(trace: Trace, auth: any) {
  const cache = new Map<string, Fn>();
  return new Proxy(auth, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof prop !== 'string' || typeof value !== 'function') return value;
      let wrapped = cache.get(prop);
      if (wrapped) return wrapped;
      if (prop === 'dispatchOutbox')
        wrapped = (...args: any[]) =>
          runStep(
            trace,
            {
              kind: 'outbox',
              method: 'dispatch',
              input: args[0] === undefined ? {} : { limit: args[0] },
              messages: [],
            },
            () => value.apply(target, args),
            (step, outcome) => {
              if (outcome.ok) {
                step.output = encodeValue(outcome.value);
                // Attempts the observed callbacks did not see went through the built-in webhook transport, to an
                // endpoint (usually the test's own HTTP server) the replay cannot reach.
                const attempts = (outcome.value?.delivered ?? 0) + (outcome.value?.failed ?? 0);
                if (attempts > (step.messages?.length ?? 0))
                  cut(step, 'webhooks were delivered over the network by the built-in transport');
              } else step.error = errorShape(outcome.error, isIamError);
            },
          );
      else if (prop === 'withClient')
        wrapped = (client: ClientInfo | undefined, fn: Fn) =>
          scope.run({ ...scope.getStore(), client: client ?? undefined }, () =>
            value.call(target, client, fn),
          );
      else if (
        publicAuthMethods.has(prop) ||
        authenticatedAuthMethods.has(prop) ||
        prop === 'beginMfa' ||
        prop === 'confirmMfa'
      )
        wrapped = (...args: any[]) =>
          apiStep(trace, 'auth', prop, value, target, args, `auth.${prop}`);
      else if (['currentClient', 'withRequestHost'].includes(prop)) wrapped = value.bind(target);
      else wrapped = (...args: any[]) => callStep(trace, `auth.${prop}`, value, target, args);
      cache.set(prop, wrapped);
      return wrapped;
    },
  });
}

function proxyNamespace(trace: Trace, name: string, namespace: any) {
  const cache = new Map<string, Fn>();
  return new Proxy(namespace, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof prop !== 'string' || typeof value !== 'function') return value;
      let wrapped = cache.get(prop);
      if (!wrapped) {
        wrapped = function (this: unknown, ...args: any[]) {
          return callStep(trace, `${name}.${prop}`, value, target, args);
        };
        cache.set(prop, wrapped);
      }
      return wrapped;
    },
  });
}

function proxyInstance(trace: Trace, iam: any) {
  const cache = new Map<string, unknown>();
  return new Proxy(iam, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof prop !== 'string' || passthrough.has(prop)) return value;
      if (cache.has(prop) && (cache.get(prop) as any)?.__source === value)
        return (cache.get(prop) as any).proxy;
      let proxied: unknown = value;
      if (prop === 'api') proxied = proxyApi(trace, value);
      else if (prop === 'auth') proxied = proxyAuth(trace, value);
      else if (prop === 'handler' && typeof value === 'function')
        proxied = wrapHandler(trace, value);
      else if (prop === 'nodeHandler' && typeof value === 'function')
        proxied = wrapNodeHandler(trace, value);
      else if (routeMembers.has(prop) && typeof value === 'function')
        proxied = function (this: unknown, ...args: any[]) {
          return routeStep(trace, prop, value, target, args);
        };
      else if (typeof value === 'function')
        proxied = function (this: unknown, ...args: any[]) {
          return callStep(trace, prop, value, target, args);
        };
      else if (
        value &&
        typeof value === 'object' &&
        Object.values(value).some((item) => typeof item === 'function')
      )
        proxied = proxyNamespace(trace, prop, value);
      cache.set(prop, { __source: value, proxy: proxied });
      return proxied;
    },
  });
}

// --- Instances --------------------------------------------------------------------------------------------------------

function serializeOptions(options: Record<string, any>) {
  const { database, ...rest } = options;
  return {
    ...(encodeValue(rest) as object),
    database: database ? { $store: database.constructor?.name ?? 'store' } : undefined,
  };
}

/** Observes a delivery callback: the replay's captured outbox never fails, so a throwing callback ends the replay. */
function observeDelivery(trace: Trace, kind: string, fn: Fn): Fn {
  return async function (this: unknown, message: any) {
    const step = scope.getStore()?.step;
    const captured = { kind, ...(encodeValue(message) as object) };
    try {
      const result = await scope.run(
        { ...scope.getStore(), callback: { name: `${kind} delivery callback`, trace, step } },
        () => fn.call(this, message),
      );
      step?.messages?.push(captured);
      return result;
    } catch (error) {
      if (step) cut(step, `${kind} delivery callback threw`);
      else trace.reasons.push(`${kind} delivery callback threw outside a recorded step`);
      throw error;
    }
  };
}

function observeCallback(trace: Trace, name: string, fn: Fn): Fn {
  return function (this: unknown, ...args: any[]) {
    try {
      const callback = { name, trace, step: scope.getStore()?.step };
      const result = scope.run({ ...scope.getStore(), callback }, () => fn.apply(this, args));
      if (result && typeof result.then === 'function')
        return result.then(undefined, (error: unknown) => {
          trace.cutAt ??= trace.steps.length;
          trace.cutReason ??= `${name} threw`;
          throw error;
        });
      return result;
    } catch (error) {
      trace.cutAt ??= trace.steps.length;
      trace.cutReason ??= `${name} threw`;
      throw error;
    }
  };
}

/**
 * An application callback the JSON configuration writes as `{"$scripted": true}`: each call, with its arguments and
 * its result or error, becomes part of the running step (`callbacks`), and the replay hands those answers to the
 * server under test. A call outside a recorded step (or a callback that reaches the library) ends the replay there.
 */
function scriptedCallback(trace: Trace, name: string, fn: Fn): Fn {
  return function (this: unknown, ...args: any[]) {
    const outer = scope.getStore();
    const step = outer?.trace === trace ? outer.step : undefined;
    const call: CallbackCall = { callback: name, args: encodeArgs(args) };
    if (step) (step.callbacks ??= []).push(call);
    else {
      trace.cutAt ??= trace.steps.length;
      trace.cutReason ??= `the ${name} callback was called outside a recorded step`;
    }
    // A value the server generated for this very call (a rotated secret handed to a rotator), repeated in the answer:
    // the replay's answer is prepared before the call, so it would carry the recorded value instead of the new one.
    const echoesNewValue = (answer: unknown) => {
      const text = JSON.stringify(answer) ?? '';
      const known = new Set(trace.digests.values());
      const fresh: string[] = [];
      const visit = (value: unknown, depth: number) => {
        if (depth > 12) return;
        if (typeof value === 'string') {
          if (value.length >= 12 && !/\s/.test(value) && !known.has(value)) fresh.push(value);
        } else if (value && typeof value === 'object')
          for (const item of Object.values(value)) visit(item, depth + 1);
      };
      visit(call.args, 0);
      if (fresh.some((value) => text.includes(JSON.stringify(value).slice(1, -1)))) {
        const reason = `the ${name} callback's answer repeats a value the server generated for the call`;
        if (step) cut(step, reason);
        else trace.cutAt ??= trace.steps.length;
      }
    };
    const thrown = (error: unknown) => {
      const shape = errorShape(error, isIamError);
      call.error = isIamError(error)
        ? { iam: true, code: shape.code, status: shape.status, message: shape.message }
        : {
            name: (error as Error)?.name ?? 'Error',
            message: String((error as Error)?.message ?? error),
          };
      echoesNewValue(call.error);
    };
    const settled = (value: unknown) => {
      call.result = encodeValue(value);
      echoesNewValue(call.result);
      if (containsFunction(value)) {
        if (step) cut(step, `the ${name} callback returned a function`);
        else trace.cutAt ??= trace.steps.length;
      }
      return value;
    };
    const callback = { name: `the ${name} callback`, trace, step };
    let result: any;
    try {
      result = scope.run({ ...outer, callback }, () => fn.apply(this, args));
    } catch (error) {
      thrown(error);
      throw error;
    }
    if (result && typeof result.then === 'function') {
      call.async = true;
      const held = { seq: trace.seq, name, step };
      trace.heldCallbacks.add(held);
      return result.then(
        (value: unknown) => {
          trace.heldCallbacks.delete(held);
          return settled(value);
        },
        (error: unknown) => {
          trace.heldCallbacks.delete(held);
          thrown(error);
          throw error;
        },
      );
    }
    return settled(result);
  };
}

/** Replaces the function at an option path (`authentication.requireMfa`, `vault.rotators.pg.rotate`) in a copy. */
function wrapScripted(trace: Trace, options: Record<string, any>, path: string) {
  const parts = path.split('.');
  let node: Record<string, any> = options;
  for (const part of parts.slice(0, -1)) {
    const next = node[part];
    if (!next || typeof next !== 'object') return;
    node[part] = Array.isArray(next) ? [...next] : { ...next };
    node = node[part];
  }
  const last = parts[parts.length - 1];
  if (typeof node[last] === 'function') node[last] = scriptedCallback(trace, path, node[last]);
}

/** Wraps `betterIam(options)`: the instance the test gets records every call it makes into a new trace. */
/**
 * Called by recording-adapter-sqlite.ts for every database the tests open: what a test writes before it builds an
 * instance on the database (legacy rows for a migration test, say) becomes the first steps of that instance's trace.
 */
export function watchStore(database: any, adapterOptions?: Record<string, unknown>) {
  if (!database || typeof database !== 'object' || patchedStores.has(database)) return;
  const filename =
    typeof adapterOptions?.filename === 'string' ? adapterOptions.filename : undefined;
  databaseOptions.set(database, adapterOptions ?? {});
  const placeholder = blankTrace();
  placeholder.placeholder = true;
  if (filename && filename !== ':memory:') {
    // A database file other handles can write to (another adapter instance, the CLI): the replay's fresh database
    // would not have what they wrote.
    const key = resolve(filename);
    placeholder.file = key;
    openFiles.set(key, (openFiles.get(key) ?? 0) + 1);
    databaseFiles.set(database, key);
  }
  patchStore(placeholder, database);
}

/** Database files the tests opened (by path) and how many handles; and each watched database's file. */
const openFiles = new Map<string, number>();
/** The `sqliteAdapter` options each watched database was opened with. */
const databaseOptions = new WeakMap<object, Record<string, unknown>>();

/**
 * The trace's `store` member: the adapter settings the test chose, with a database file as `"file"` (the replay runner
 * gives every trace a fresh file; settings such as the journal mode only apply to files, and a self-check reports
 * an in-memory database).
 */
function storeConfig(database: object): Record<string, unknown> {
  const adapter = databaseOptions.get(database) ?? {};
  const store: Record<string, unknown> = {
    kind: 'sqlite',
    path: adapter.filename === ':memory:' || adapter.filename === undefined ? ':memory:' : 'file',
  };
  for (const key of ['busyTimeoutMs', 'journalMode', 'durability'])
    if (adapter[key] !== undefined) store[key] = adapter[key];
  return store;
}
const databaseFiles = new WeakMap<object, string>();

function blankTrace(): Trace {
  return {
    index: -1,
    file: currentFile ?? 'unknown',
    test: currentTest,
    tests: new Set(currentTest ? [currentTest] : []),
    options: undefined,
    config: {},
    reasons: [],
    dropped: [],
    clock: false,
    steps: [],
    seq: 0,
    inflight: new Set(),
    totpSecrets: new Set(),
    digests: new Map(),
    outputs: new Set(),
    outputInstants: new Set(),
    heldCallbacks: new Set(),
    clientHeaders: false,
    startedAt: Date.now(),
    baseOrigin: 'http://localhost',
  };
}

export function recordInstance<T>(betterIam: (options: any) => T, options: any): T {
  const described = configFromOptions(options);
  const existing = options?.database ? patchedStores.get(options.database) : undefined;
  const reuse = existing?.placeholder ? existing : undefined;
  const storeReasons: string[] = [];
  if (options?.database && !existing)
    storeReasons.push(
      'the database was not opened through the SQLite adapter (a wrapped or custom store): writes through other handles cannot be recorded',
    );
  const databaseFile = options?.database ? databaseFiles.get(options.database) : undefined;
  if (databaseFile && (openFiles.get(databaseFile) ?? 0) > 1)
    storeReasons.push('the database file is opened by more than one handle');
  const fields: Partial<Trace> = {
    index: traces.length,
    file: currentFile ?? 'unknown',
    test: currentTest,
    tests: new Set(currentTest ? [currentTest] : []),
    options: serializeOptions(options ?? {}),
    config: described.config,
    reasons: [...described.reasons],
    dropped: [...described.dropped],
    clock: described.clock,
    steps: [],
    seq: 0,
    inflight: new Set(),
    totpSecrets: new Set(),
    digests: new Map(),
    outputs: new Set(),
    outputInstants: new Set(),
    heldCallbacks: new Set(),
    clientHeaders: false,
    startedAt: Date.now(),
    baseOrigin: (() => {
      try {
        return new URL(options.baseURL).origin;
      } catch {
        return 'http://localhost';
      }
    })(),
  };
  // A database the test wrote to before building the instance keeps those steps (and their state) at the front.
  if (reuse)
    for (const key of [
      'steps',
      'seq',
      'inflight',
      'tests',
      'totpSecrets',
      'digests',
      'outputs',
      'outputInstants',
      'heldCallbacks',
      'startedAt',
    ] as const)
      delete fields[key];
  const trace: Trace = Object.assign(reuse ?? blankTrace(), fields);
  delete trace.placeholder;
  trace.reasons.push(...storeReasons);
  if (existing && options?.database) trace.config.store = storeConfig(options.database);
  if (reuse) {
    trace.file = currentFile ?? trace.file;
    trace.test = currentTest ?? trace.test;
    if (currentTest) trace.tests.add(currentTest);
  }
  traces.push(trace);
  const patched = { ...options };
  if (options?.authentication && typeof options.authentication === 'object') {
    const authentication = { ...options.authentication };
    const now = authentication.now;
    if (typeof now === 'function')
      authentication.now = function (this: unknown) {
        const value = now.call(this);
        trace.lastClock = value;
        const store = scope.getStore();
        const step =
          store?.step && store.trace === trace
            ? store.step
            : store?.clockTrace === trace
              ? store.clockStep
              : undefined;
        if (step) {
          if (step.at === undefined) step.at = value;
          else if (step.at !== value) step.clockMoves = (step.clockMoves ?? 0) + 1;
        }
        return value;
      };
    for (const [key, kind] of [
      ['sendEmail', 'email'],
      ['sendSms', 'sms'],
    ] as const)
      if (typeof authentication[key] === 'function')
        authentication[key] = observeDelivery(trace, kind, authentication[key]);
    patched.authentication = authentication;
  }
  if (options?.events && typeof options.events === 'object') {
    const events = { ...options.events };
    if (typeof events.deliverWebhook === 'function')
      events.deliverWebhook = observeDelivery(trace, 'webhook', events.deliverWebhook);
    if (typeof events.onEvent === 'function')
      events.onEvent = observeCallback(trace, 'events.onEvent', events.onEvent);
    patched.events = events;
  }
  for (const path of described.scripted as string[]) wrapScripted(trace, patched, path);
  if (options?.observability && typeof options.observability.onSpan === 'function')
    patched.observability = {
      ...options.observability,
      onSpan: observeCallback(trace, 'observability.onSpan', options.observability.onSpan),
    };
  // Only databases the SQLite adapter opened are observed: a wrapper (often a Proxy over such a database) would have
  // the patched methods written through to its target, and its trace is not replayable anyway.
  if (options?.database && typeof options.database === 'object' && existing) {
    patchStore(trace, options.database);
    trace.database = options.database;
  }
  // Construction (and any timer it starts) belongs to the library, not to the test.
  let instance: T;
  try {
    instance = scope.run({ internal: true }, () => betterIam(patched));
  } catch (error) {
    trace.construction = errorShape(error, isIamError);
    // The database never served this instance: the next instance on it starts from what was written so far.
    if (options?.database && patchedStores.get(options.database) === trace) {
      const next = blankTrace();
      next.placeholder = true;
      next.steps = [...trace.steps];
      next.seq = trace.seq;
      patchedStores.set(options.database, next);
    }
    throw error;
  }
  trace.instance = instance;
  return proxyInstance(trace, instance) as T;
}

// --- Writing ----------------------------------------------------------------------------------------------------------

const slug = (text: string) =>
  text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'trace';

/** Writes this test file's traces to `<dir>/<test file>/<NNN>-<test>.jsonl` (called from afterAll). */
export function flushTraces(directory: string, root: string, testFile?: string) {
  if (!traces.length) return;
  const file = testFile ?? traces.find((trace) => trace.file !== 'unknown')?.file ?? 'unknown';
  for (const trace of traces) if (trace.file === 'unknown') trace.file = file;
  const folder = join(
    directory,
    relative(resolve(root, 'tests'), file)
      .replace(/\.(test|spec)\.tsx?$/, '')
      .replace(/[\\/]/g, '__'),
  );
  mkdirSync(folder, { recursive: true });
  for (const name of readdirSync(folder)) if (name.endsWith('.jsonl')) rmSync(join(folder, name));
  for (const trace of traces) {
    const steps = trace.steps;
    let replayable = trace.reasons.length === 0;
    // A TOTP window is relative to the time the replay computes the code at: the injected clock it last set (the
    // latest `at` so far) for a controlled clock, else the step's wall-clock time.
    let lastAt: number | undefined;
    for (const step of steps) {
      if (step.at !== undefined) lastAt = step.at;
      for (const derive of [
        ...(step.derive ?? []),
        ...(step.ops ?? []).flatMap((op) => op.derive ?? []),
      ]) {
        if (derive.kind !== 'totp') continue;
        const base = trace.clock && lastAt !== undefined ? lastAt : (step.wall ?? derive.basis!);
        derive.window = derive.counter! - Math.floor(base / 30000);
        delete derive.counter;
        delete derive.basis;
      }
    }
    const firstSkip = steps.findIndex((step) => step.skip || step.pending);
    let prefix = firstSkip < 0 ? steps.length : firstSkip;
    if (trace.cutAt !== undefined && trace.cutAt < prefix) prefix = trace.cutAt;
    for (const step of steps) {
      if (step.pending && !step.skip) step.skip = 'the test never awaited this step';
    }
    if (trace.clientHeaders && !trace.config.http?.clientInfo)
      trace.config.http = {
        ...trace.config.http,
        clientInfo: {
          userAgent: true,
          ipHeader: 'x-conformance-client-ip',
          labelHeader: 'x-conformance-client-label',
        },
      };
    if (prefix === 0 && steps.length) replayable = false;
    if (!steps.length && !trace.construction) replayable = false;
    const header = {
      type: 'trace',
      format: 1,
      id: `${relative(root, file).replace(/\\/g, '/')}#${String(trace.index + 1).padStart(3, '0')}`,
      file: relative(root, file).replace(/\\/g, '/'),
      test: trace.test ?? null,
      tests: [...trace.tests],
      replayable,
      reasons: [
        ...trace.reasons,
        ...(prefix < steps.length
          ? [
              `replay stops before step ${prefix + 1}: ${steps[prefix]?.skip ?? trace.cutReason ?? 'cut'}`,
            ]
          : []),
      ],
      replayableSteps: replayable ? prefix : 0,
      ...(trace.construction ? { construction: { error: trace.construction } } : {}),
      steps: steps.length,
      clock: trace.clock ? { controlled: true } : { controlled: false },
      dropped: trace.dropped,
      config: trace.config,
      options: trace.options,
      recordedAt: new Date(trace.startedAt).toISOString(),
    };
    const lines = [JSON.stringify(header), ...steps.map((step) => JSON.stringify(step))];
    const name = `${String(trace.index + 1).padStart(3, '0')}-${slug(trace.test ?? 'setup')}.jsonl`;
    writeFileSync(join(folder, name), `${lines.join('\n')}\n`);
  }
  traces.length = 0;
}
