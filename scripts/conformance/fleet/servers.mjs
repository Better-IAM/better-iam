#!/usr/bin/env node
// Server-level mixed fleet (parity layer 5, spec/BUILDOUT.md): the TypeScript, Rust and Go servers run at the same time
// on ONE SQLite database (WAL), with the same deployment secret, base URL and session JWT keys, and a scenario walks
// across them over HTTP. Each step goes to a different server, rotating, and the answers are checked on the others:
// records written by one are read, updated and audited by the others, sessions issued by one validate on another, and
// every tenant's audit hash chain verifies end to end across writers.
//
//   node scripts/conformance/fleet/servers.mjs [--ts-root <dir>] [--rust <bin>] [--go <bin>] [--only ts,rust,go]
//                                              [--keep] [--verbose]
//
//   --ts-root  repository whose built packages and node_modules serve TypeScript (default: this repository;
//              env FLEET_TS_ROOT). It must have run `pnpm build`.
//   --rust     the Rust server binary (default: $CARGO_TARGET_DIR or target/, debug/better-iam-server; env FLEET_RUST_BIN)
//   --go       the Go server binary (default: target/go/better-iam-server; env FLEET_GO_BIN)
//   --only     a subset of the implementations (at least one; with one, the run checks a fleet of that server alone)
//   --keep     keep the temporary directory (database, configuration, server logs) and print its path
//   --verbose  print every request and answer
//
// The servers run in conformance mode (spec/conformance/CONTROL.md): the scenario bootstraps through
// /__conformance/call and reads delivered invitations from /__conformance/outbox. Exit status 0 when every check
// passed, 1 otherwise; the report names the server that answered differently.
import { spawn } from 'node:child_process';
import { createPublicKey, generateKeyPairSync, verify as verifySignature } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { totp } from '../lib/totp.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const exe = process.platform === 'win32' ? '.exe' : '';

// --- Arguments -----------------------------------------------------------------------------------------------------
function parseArgs(argv) {
  const args = {
    tsRoot: process.env.FLEET_TS_ROOT ?? repo,
    rust:
      process.env.FLEET_RUST_BIN ??
      join(
        process.env.CARGO_TARGET_DIR ?? join(repo, 'target'),
        'debug',
        `better-iam-server${exe}`,
      ),
    go: process.env.FLEET_GO_BIN ?? join(repo, 'target', 'go', `better-iam-server${exe}`),
    only: ['ts', 'rust', 'go'],
    keep: false,
    verbose: false,
  };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    const value = () => {
      const next = argv[++index];
      if (next === undefined) throw new Error(`${arg} needs a value`);
      return next;
    };
    if (arg === '--ts-root') args.tsRoot = resolve(value());
    else if (arg === '--rust') args.rust = resolve(value());
    else if (arg === '--go') args.go = resolve(value());
    else if (arg === '--only')
      args.only = value()
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
    else if (arg === '--keep') args.keep = true;
    else if (arg === '--verbose') args.verbose = true;
    else if (arg === '--help' || arg === '-h') args.help = true;
    else throw new Error(`Unknown argument ${arg}`);
  }
  if (!args.only.length || args.only.some((name) => !['ts', 'rust', 'go'].includes(name)))
    throw new Error('--only takes a comma-separated subset of ts,rust,go');
  return args;
}

let args;
try {
  args = parseArgs(process.argv.slice(2));
} catch (error) {
  console.error(error.message);
  process.exit(2);
}
if (args.help) {
  console.log(
    'Usage: node scripts/conformance/fleet/servers.mjs [--ts-root <dir>] [--rust <bin>] [--go <bin>] [--only ts,rust,go] [--keep] [--verbose]',
  );
  process.exit(0);
}

// --- Fleet configuration -------------------------------------------------------------------------------------------
const ORIGIN = 'http://localhost:3000';
const BASE_PATH = '/api/iam';
const SECRET = 'fleet-servers-deployment-secret-with-more-than-32-characters';
const COOKIE = 'better-iam.session';
const ROOT = {
  email: 'root@fleet.test',
  name: 'Fleet Root',
  password: 'a strong fleet root password',
};
const OWNER_PASSWORD = 'a strong fleet owner password';
const password = (name) => `a strong ${name} fleet password`;

const work = mkdtempSync(join(tmpdir(), 'better-iam-fleet-'));
const databasePath = join(work, 'iam.db');
const configPath = join(work, 'better-iam.json');

/** One Ed25519 signing key shared by every server, so a session JWT issued by one verifies on all (JWKS). */
const signingKey = (() => {
  const { privateKey } = generateKeyPairSync('ed25519');
  return { ...privateKey.export({ format: 'jwk' }), kid: 'fleet-1', alg: 'EdDSA', use: 'sig' };
})();

const config = {
  store: { kind: 'sqlite', path: databasePath, journalMode: 'wal', busyTimeoutMs: 15000 },
  secret: SECRET,
  baseURL: ORIGIN,
  basePath: BASE_PATH,
  trustedOrigins: [ORIGIN],
  authentication: { sessionLifetimeMs: 7 * 86400000, sessionIdleTimeoutMs: 7 * 86400000 },
  delivery: { email: { kind: 'capture' } },
  permissions: { actions: ['documents:read', 'documents:write'] },
  resolveResource: { kind: 'echo' },
  sts: { jwt: { signingKeys: [signingKey] } },
};
writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);

// --- Servers -------------------------------------------------------------------------------------------------------
const LABEL = { ts: 'typescript', rust: 'rust', go: 'go' };

function freePort() {
  return new Promise((resolvePort, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolvePort(port));
    });
  });
}

function command(name, port) {
  const flags = [
    '--config',
    configPath,
    '--port',
    String(port),
    '--host',
    '127.0.0.1',
    '--conformance',
  ];
  if (name === 'ts') {
    const serve = join(args.tsRoot, 'scripts', 'conformance', 'serve.mjs');
    if (!existsSync(join(args.tsRoot, 'packages', 'server', 'dist', 'index.js')))
      throw new Error(
        `${args.tsRoot} has no built packages (run pnpm build there, or pass --ts-root)`,
      );
    return { file: process.execPath, argv: [serve, ...flags], cwd: args.tsRoot };
  }
  const file = name === 'rust' ? args.rust : args.go;
  if (!existsSync(file))
    throw new Error(`The ${LABEL[name]} server binary ${file} does not exist (pass --${name})`);
  return { file, argv: flags, cwd: work };
}

async function startServer(name) {
  const port = await freePort();
  const { file, argv, cwd } = command(name, port);
  const child = spawn(file, argv, { cwd, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  const server = {
    name,
    label: LABEL[name],
    port,
    url: `http://127.0.0.1:${port}`,
    child,
    log: [],
    exited: null,
  };
  const keep = (stream) => (chunk) => {
    const text = chunk.toString();
    server.log.push(
      ...text
        .split(/\r?\n/)
        .filter(Boolean)
        .map((line) => `[${stream}] ${line}`),
    );
    if (server.log.length > 400) server.log.splice(0, server.log.length - 400);
  };
  child.stdout.on('data', keep('out'));
  child.stderr.on('data', keep('err'));
  child.on('exit', (code, signal) => {
    server.exited = { code, signal };
  });
  const deadline = Date.now() + 120000;
  for (;;) {
    if (server.exited)
      throw new Error(
        `The ${server.label} server exited (${JSON.stringify(server.exited)}) before it was ready:\n${server.log.slice(-20).join('\n')}`,
      );
    try {
      const response = await fetch(`${server.url}/__conformance/ready`);
      if (response.ok) {
        const body = await response.json();
        if (body.ready) {
          server.implementation = body.implementation;
          return server;
        }
      }
    } catch {
      // Not listening yet.
    }
    if (Date.now() > deadline)
      throw new Error(`The ${server.label} server was not ready within 120 s`);
    await new Promise((done) => setTimeout(done, 150));
  }
}

async function stopServer(server) {
  if (server.exited) return;
  try {
    await fetch(`${server.url}/__conformance/shutdown`, {
      method: 'POST',
      body: '{}',
      headers: { 'content-type': 'application/json' },
    });
  } catch {
    // Closed already.
  }
  const deadline = Date.now() + 5000;
  while (!server.exited && Date.now() < deadline) await new Promise((done) => setTimeout(done, 50));
  if (!server.exited) server.child.kill();
}

// --- HTTP ----------------------------------------------------------------------------------------------------------
/**
 * POST {basePath}/{path} on a server. `auth` is `{ token }` (bearer) or `{ cookie }` (the session cookie value, sent
 * with the Origin header the CSRF rule wants). Answers `{ status, data, error, cookie }` where `cookie` is the session
 * cookie the answer set (`''` when it cleared it).
 */
async function rpc(server, path, body = {}, auth = {}) {
  const headers = { 'content-type': 'application/json', 'x-better-iam': '1' };
  if (auth.token) headers.authorization = `Bearer ${auth.token}`;
  if (auth.cookie !== undefined) {
    headers.cookie = `${COOKIE}=${auth.cookie}`;
    headers.origin = ORIGIN;
  }
  const response = await fetch(`${server.url}${BASE_PATH}/${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let json;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = { error: { code: 'NOT_JSON', message: text.slice(0, 200) } };
  }
  let cookie;
  for (const line of response.headers.getSetCookie()) {
    const [pair] = line.split(';');
    const at = pair.indexOf('=');
    if (pair.slice(0, at).trim() === COOKIE) cookie = pair.slice(at + 1).trim();
  }
  const answer = { status: response.status, data: json?.data, error: json?.error, cookie };
  if (args.verbose)
    console.log(
      `    ${server.label} POST ${path} ${JSON.stringify(body).slice(0, 160)} -> ${response.status} ${text.slice(0, 240)}`,
    );
  return answer;
}

async function control(server, path, body) {
  const response = await fetch(`${server.url}/__conformance/${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json();
  if (args.verbose)
    console.log(
      `    ${server.label} control ${path} -> ${response.status} ${JSON.stringify(json).slice(0, 240)}`,
    );
  return json;
}

async function get(server, path) {
  const response = await fetch(`${server.url}${BASE_PATH}/${path}`);
  return {
    status: response.status,
    headers: response.headers,
    body: await response.json().catch(() => undefined),
  };
}

// --- Report --------------------------------------------------------------------------------------------------------
const results = [];
let current;

class Abort extends Error {}

/** Runs one scenario step; checks record failures, a thrown error fails the step (and `fatal` stops the run). */
async function step(title, servers, run, { fatal = false } = {}) {
  current = { title, servers: servers.map((server) => server.label), failures: [], notes: [] };
  results.push(current);
  try {
    await run();
  } catch (error) {
    current.failures.push(
      error instanceof Abort ? error.message : `threw: ${error.stack ?? error}`,
    );
  }
  const ok = current.failures.length === 0;
  const where = current.servers.join(' -> ');
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${title}  [${where}]`);
  for (const note of current.notes) console.log(`        ${note}`);
  for (const failure of current.failures)
    console.log(`        x ${failure.split('\n').join('\n          ')}`);
  if (!ok && fatal) throw new Abort(`Stopped: "${title}" is needed by every later step`);
}

const note = (text) => current.notes.push(text);
const fail = (text) => current.failures.push(text);
/** Records a failure unless `condition`; answers `condition`. */
function check(condition, text) {
  if (!condition) fail(text);
  return Boolean(condition);
}
const show = (value) => JSON.stringify(value)?.slice(0, 400);
/** The answer's data, or a failure (and an abort) that names the server and its error. */
function ok(server, answer, what) {
  if (answer.status === 200 && answer.data !== undefined) return answer.data;
  throw new Abort(
    `${server.label}: ${what} answered ${answer.status} ${show(answer.error ?? answer.data)}`,
  );
}
/** The answer must be an error with this code (and status). */
function refused(server, answer, code, status, what) {
  return check(
    answer.status === status && answer.error?.code === code,
    `${server.label}: ${what} should be refused with ${status} ${code}, got ${answer.status} ${show(answer.error ?? answer.data)}`,
  );
}

/** The paths at which two JSON values differ (at most 8). */
function differences(a, b, path = '$', out = []) {
  if (out.length >= 8) return out;
  if (isDeepStrictEqual(a, b)) return out;
  if (
    a &&
    b &&
    typeof a === 'object' &&
    typeof b === 'object' &&
    Array.isArray(a) === Array.isArray(b)
  ) {
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const key of keys)
      differences(a[key], b[key], Array.isArray(a) ? `${path}[${key}]` : `${path}.${key}`, out);
    return out;
  }
  out.push(`${path}: ${show(a)} vs ${show(b)}`);
  return out;
}

/** Every server's answer must equal the first server's (after `project`). */
function same(answers, what, project = (value) => value) {
  const [first, ...rest] = answers;
  const reference = project(first.value);
  for (const other of rest) {
    const diff = differences(reference, project(other.value));
    check(
      !diff.length,
      `${what}: ${other.server.label} differs from ${first.server.label}:\n${diff.join('\n')}`,
    );
  }
}

// --- Scenario ------------------------------------------------------------------------------------------------------
const servers = [];
let turn = 0;
/** The next server in rotation. */
const next = () => servers[turn++ % servers.length];
/** The servers other than `server` (all of them when the fleet has one server). */
const others = (server) =>
  servers.length > 1 ? servers.filter((item) => item !== server) : servers;

const state = {};

function decodeJwt(token) {
  const [header, payload, signature] = token.split('.');
  const json = (part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  return {
    header: json(header),
    payload: json(payload),
    signed: Buffer.from(`${header}.${payload}`),
    signature: Buffer.from(signature, 'base64url'),
  };
}

async function scenario() {
  await step(
    'start every server on one SQLite file (WAL); migrations run once and the others find them applied',
    args.only.map((name) => ({ label: LABEL[name] })),
    async () => {
      // One after the other: initialize() migrates, and the later servers must accept the schema the first wrote.
      for (const name of args.only) {
        const server = await startServer(name);
        servers.push(server);
        check(
          server.implementation === server.label,
          `${server.label}: /__conformance/ready names implementation ${show(server.implementation)}`,
        );
        note(`${server.label} on ${server.url} (pid ${server.child.pid})`);
      }
      for (const server of servers) {
        const health = await get(server, 'health');
        check(
          health.status === 200,
          `${server.label}: GET health answered ${health.status} ${show(health.body)}`,
        );
      }
    },
    { fatal: true },
  );

  {
    const a = next();
    const b = others(a)[0];
    await step(
      'bootstrap the deployment; a second bootstrap elsewhere is refused',
      [a, b],
      async () => {
        const answer = await control(a, 'call', { method: 'bootstrap', args: [ROOT] });
        if (!answer.data) throw new Abort(`${a.label}: bootstrap failed ${show(answer.error)}`);
        state.root = answer.data;
        check(
          answer.data.tenant?.type === 'root',
          `${a.label}: bootstrap tenant ${show(answer.data.tenant)}`,
        );
        const again = await control(b, 'call', { method: 'bootstrap', args: [ROOT] });
        check(
          again.error?.code === 'ALREADY_INITIALIZED' && again.error?.status === 409,
          `${b.label}: second bootstrap should be 409 ALREADY_INITIALIZED, got ${show(again)}`,
        );
      },
      { fatal: true },
    );
  }

  {
    const [a, b, c] = [next(), next(), next()];
    await step(
      'root signs in with a password on one server, enrolls TOTP on the next, confirms on the third',
      [a, b, c],
      async () => {
        const tenantId = state.root.tenant.id;
        const challenge = ok(
          a,
          await rpc(a, 'auth/signIn', { tenantId, email: ROOT.email, password: ROOT.password }),
          'auth/signIn',
        );
        if (!challenge.mfaRequired)
          throw new Abort(`${a.label}: root sign-in should require MFA, got ${show(challenge)}`);
        const enrollment = ok(
          b,
          await rpc(b, 'auth/beginMfa', { tenantId, challenge: challenge.challenge }),
          'auth/beginMfa',
        );
        const session = ok(
          c,
          await rpc(c, 'auth/confirmMfa', {
            credential: { tenantId, challenge: challenge.challenge },
            code: totp(enrollment.secret, Date.now()),
          }),
          'auth/confirmMfa',
        );
        state.rootToken = session.token;
        state.rootSecret = enrollment.secret;
        for (const server of servers) {
          const who = ok(
            server,
            await rpc(server, 'auth/getSession', {}, { token: state.rootToken }),
            'auth/getSession (root)',
          );
          check(
            who.identity?.email === ROOT.email,
            `${server.label}: root session resolves to ${show(who.identity)}`,
          );
        }
      },
      { fatal: true },
    );
  }

  {
    const [a, b, c] = [next(), next(), next()];
    await step(
      'create a tenant; the invitation queued by one server is delivered by another and accepted on a third',
      [a, b, c],
      async () => {
        const created = ok(
          a,
          await rpc(
            a,
            'tenants/create',
            {
              parentId: state.root.tenant.id,
              name: 'Acme',
              type: 'organization',
              ownerEmail: 'owner@acme.test',
            },
            { token: state.rootToken },
          ),
          'tenants/create',
        );
        state.tenantId = created.tenant.id;
        const dispatched = await control(b, 'outbox/dispatch', {});
        const invitation = (dispatched.messages ?? []).find(
          (message) =>
            message.template === 'owner-invitation' && message.tenantId === state.tenantId,
        );
        if (!invitation)
          throw new Abort(
            `${b.label}: outbox dispatch delivered no owner invitation: ${show(dispatched)}`,
          );
        const owner = ok(
          c,
          await rpc(c, 'tenants/acceptInvitation', {
            tenantId: state.tenantId,
            token: invitation.payload.token,
            name: 'Acme Owner',
            password: OWNER_PASSWORD,
          }),
          'tenants/acceptInvitation',
        );
        if (!owner.token)
          throw new Abort(`${c.label}: acceptInvitation gave no session ${show(owner)}`);
        state.ownerToken = owner.token;
        state.ownerId = owner.identity.id;
        const answers = [];
        for (const server of servers) {
          const tenant = ok(
            server,
            await rpc(
              server,
              'tenants/get',
              { tenantId: state.tenantId },
              { token: state.rootToken },
            ),
            'tenants/get',
          );
          answers.push({ server, value: tenant });
        }
        same(answers, 'tenants/get');
      },
      { fatal: true },
    );
  }

  const people = ['alice', 'bob', 'carol'];
  {
    const writers = people.map(() => next());
    await step(
      'create one identity on each server; every server reads all three identically',
      writers,
      async () => {
        state.people = {};
        for (const [index, name] of people.entries()) {
          const server = writers[index];
          const identity = ok(
            server,
            await rpc(
              server,
              'identities/create',
              {
                tenantId: state.tenantId,
                email: `${name}@acme.test`,
                name,
                password: password(name),
              },
              { token: state.ownerToken },
            ),
            `identities/create ${name}`,
          );
          state.people[name] = identity;
        }
        for (const name of people) {
          const answers = [];
          for (const server of servers)
            answers.push({
              server,
              value: ok(
                server,
                await rpc(
                  server,
                  'identities/get',
                  { tenantId: state.tenantId, identityId: state.people[name].id },
                  { token: state.ownerToken },
                ),
                `identities/get ${name}`,
              ),
            });
          same(answers, `identities/get ${name}`);
          check(
            answers[0].value.email === `${name}@acme.test`,
            `identities/get ${name}: ${show(answers[0].value)}`,
          );
        }
      },
      { fatal: true },
    );
  }

  {
    const [a, b] = [next(), next()];
    await step(
      'create a role on one server and bind it on another; every server decides the same',
      [a, b, ...servers],
      async () => {
        const role = ok(
          a,
          await rpc(
            a,
            'roles/create',
            {
              tenantId: state.tenantId,
              name: 'Document readers',
              permissions: ['documents:read', 'iam:session-tokens:create'],
            },
            { token: state.ownerToken },
          ),
          'roles/create',
        );
        state.roleId = role.id;
        const binding = ok(
          b,
          await rpc(
            b,
            'bindings/create',
            {
              tenantId: state.tenantId,
              roleId: role.id,
              subjectType: 'identity',
              subjectId: state.people.alice.id,
            },
            { token: state.ownerToken },
          ),
          'bindings/create',
        );
        state.bindingId = binding.id;
        // Each person signs in on a different server; their sessions are then checked on every server.
        state.sessions = {};
        for (const name of ['alice', 'bob']) {
          const server = next();
          const signedIn = ok(
            server,
            await rpc(server, 'auth/signIn', {
              tenantId: state.tenantId,
              email: `${name}@acme.test`,
              password: password(name),
            }),
            `auth/signIn ${name}`,
          );
          state.sessions[name] = signedIn.token;
          note(`${name} signed in on ${server.label}`);
        }
        const cases = [
          ['alice', 'documents:read', true],
          ['alice', 'documents:write', false],
          ['bob', 'documents:read', false],
        ];
        for (const [name, action, expected] of cases) {
          const answers = [];
          for (const server of servers) {
            const decision = ok(
              server,
              await rpc(
                server,
                'authorize',
                { tenantId: state.tenantId, action, resource: { type: 'document', id: 'doc-1' } },
                { token: state.sessions[name] },
              ),
              `authorize ${name} ${action}`,
            );
            check(
              decision.allowed === expected,
              `${server.label}: authorize ${name} ${action} allowed=${decision.allowed}, expected ${expected}`,
            );
            answers.push({ server, value: decision });
          }
          same(answers, `authorize ${name} ${action}`);
        }
      },
    );
  }

  {
    const issuer = next();
    await step(
      'a session cookie and a bearer token issued by one server are accepted by the others',
      [issuer, ...others(issuer)],
      async () => {
        const signedIn = await rpc(issuer, 'auth/signIn', {
          tenantId: state.tenantId,
          email: 'carol@acme.test',
          password: password('carol'),
        });
        ok(issuer, signedIn, 'auth/signIn carol');
        if (!signedIn.cookie)
          throw new Abort(`${issuer.label}: auth/signIn set no ${COOKIE} cookie`);
        check(
          signedIn.cookie === signedIn.data.token,
          `${issuer.label}: the session cookie is not the session token`,
        );
        state.carolCookie = signedIn.cookie;
        state.carolCookieServer = issuer;
        const viaCookie = [];
        const viaBearer = [];
        for (const server of servers) {
          viaCookie.push({
            server,
            value: ok(
              server,
              await rpc(server, 'auth/getSession', {}, { cookie: signedIn.cookie }),
              'auth/getSession (cookie)',
            ),
          });
          viaBearer.push({
            server,
            value: ok(
              server,
              await rpc(server, 'auth/getSession', {}, { token: signedIn.data.token }),
              'auth/getSession (bearer)',
            ),
          });
        }
        const project = (value) => ({
          session: value.session?.id,
          identity: value.identity?.id,
          tenant: value.session?.tenantId,
        });
        same(viaCookie, 'auth/getSession by cookie', project);
        same(viaBearer, 'auth/getSession by bearer', project);
        check(
          viaCookie[0].value.session?.id === signedIn.data.session?.id,
          `getSession names session ${viaCookie[0].value.session?.id}, sign-in issued ${signedIn.data.session?.id}`,
        );
        for (const { server, value } of viaCookie)
          check(
            value.session && !('tokenHash' in value.session),
            `${server.label}: getSession leaks session.tokenHash`,
          );
      },
    );
  }

  {
    const [a, b] = [next(), next()];
    await step(
      'an API key issued on one server (for a service account made on another) works on every server',
      [a, b, ...servers],
      async () => {
        const account = ok(
          a,
          await rpc(
            a,
            'serviceAccounts/create',
            { tenantId: state.tenantId, name: 'fleet-bot' },
            { token: state.ownerToken },
          ),
          'serviceAccounts/create',
        );
        ok(
          a,
          await rpc(
            a,
            'bindings/create',
            {
              tenantId: state.tenantId,
              roleId: state.roleId,
              subjectType: 'identity',
              subjectId: account.id,
            },
            { token: state.ownerToken },
          ),
          'bindings/create (service account)',
        );
        const key = ok(
          b,
          await rpc(
            b,
            'credentials/create',
            { tenantId: state.tenantId, identityId: account.id, name: 'fleet key' },
            { token: state.ownerToken },
          ),
          'credentials/create',
        );
        state.apiKey = key;
        state.serviceAccountId = account.id;
        const answers = [];
        for (const server of servers) {
          const decision = ok(
            server,
            await rpc(
              server,
              'authorize',
              {
                tenantId: state.tenantId,
                action: 'documents:read',
                resource: { type: 'document', id: 'doc-1' },
              },
              { token: key.token },
            ),
            'authorize (API key)',
          );
          check(
            decision.allowed === true,
            `${server.label}: the API key's authorize allowed=${decision.allowed}`,
          );
          answers.push({ server, value: decision });
        }
        same(answers, 'authorize (API key)');
      },
    );
  }

  {
    const issuer = next();
    await step(
      "a session JWT issued on one server verifies against every server's JWKS and is accepted as a bearer",
      [issuer, ...others(issuer)],
      async () => {
        const issued = ok(
          issuer,
          await rpc(
            issuer,
            'sts/getSessionToken',
            { format: 'jwt' },
            { token: state.sessions.alice },
          ),
          'sts/getSessionToken',
        );
        check(
          issued.format === 'jwt',
          `${issuer.label}: getSessionToken format ${show(issued.format)}`,
        );
        state.jwt = issued.token;
        const jwt = decodeJwt(issued.token);
        check(jwt.payload.iss === `${ORIGIN}${BASE_PATH}`, `iss ${show(jwt.payload.iss)}`);
        check(
          jwt.header.kid === signingKey.kid && jwt.header.alg === 'EdDSA',
          `header ${show(jwt.header)}`,
        );
        const sets = [];
        for (const server of servers) {
          const answer = await get(server, '.well-known/jwks.json');
          if (
            !check(
              answer.status === 200,
              `${server.label}: GET .well-known/jwks.json answered ${answer.status} ${show(answer.body)}`,
            )
          )
            continue;
          check(
            answer.headers.get('content-type') === 'application/jwk-set+json',
            `${server.label}: JWKS content-type ${answer.headers.get('content-type')}`,
          );
          sets.push({ server, value: answer.body });
          const jwk = answer.body.keys?.find((key) => key.kid === jwt.header.kid);
          if (!check(jwk, `${server.label}: JWKS has no key ${jwt.header.kid}`)) continue;
          check(!('d' in jwk), `${server.label}: JWKS publishes the private key`);
          const valid = verifySignature(
            null,
            jwt.signed,
            createPublicKey({ key: jwk, format: 'jwk' }),
            jwt.signature,
          );
          check(valid, `${server.label}: the JWT signature does not verify with the published key`);
        }
        if (sets.length === servers.length) same(sets, 'JWKS');
        const answers = [];
        for (const server of servers) {
          const decision = ok(
            server,
            await rpc(
              server,
              'authorize',
              {
                tenantId: state.tenantId,
                action: 'documents:read',
                resource: { type: 'document', id: 'doc-1' },
              },
              { token: issued.token },
            ),
            'authorize (session JWT)',
          );
          check(
            decision.allowed === true,
            `${server.label}: the JWT's authorize allowed=${decision.allowed}`,
          );
          answers.push({ server, value: decision });
        }
        same(answers, 'authorize (session JWT)');
        // auth/* takes person sessions only: TypeScript refuses a session JWT there, and so must every server.
        const sessions = [];
        for (const server of servers) {
          const answer = await rpc(server, 'auth/getSession', {}, { token: issued.token });
          sessions.push({
            server,
            value: { status: answer.status, error: answer.error, data: answer.data },
          });
        }
        same(sessions, 'auth/getSession with a session JWT');
      },
    );
  }

  {
    const writers = [next(), next(), next()];
    await step(
      'update the same identity from each server in turn; each change is visible everywhere',
      writers,
      async () => {
        const changes = [
          { name: 'Alice A.' },
          { managerId: state.people.bob.id },
          { name: 'Alice Fleet', managerId: state.people.carol.id },
        ];
        for (const [index, change] of changes.entries()) {
          const server = writers[index];
          const updated = ok(
            server,
            await rpc(
              server,
              'identities/update',
              { tenantId: state.tenantId, identityId: state.people.alice.id, ...change },
              { token: state.ownerToken },
            ),
            `identities/update #${index + 1}`,
          );
          const answers = [{ server, value: updated }];
          for (const reader of others(server))
            answers.push({
              server: reader,
              value: ok(
                reader,
                await rpc(
                  reader,
                  'identities/get',
                  { tenantId: state.tenantId, identityId: state.people.alice.id },
                  { token: state.ownerToken },
                ),
                'identities/get',
              ),
            });
          same(answers, `after update #${index + 1} on ${server.label}`);
          for (const { server: reader, value } of answers) {
            if (change.name)
              check(
                value.name === change.name,
                `${reader.label}: name ${show(value.name)} after update #${index + 1}`,
              );
            if (change.managerId)
              check(
                value.managerId === change.managerId,
                `${reader.label}: managerId ${show(value.managerId)} after update #${index + 1}`,
              );
          }
        }
        // A role renamed on one server, read on the others.
        const server = next();
        const renamed = ok(
          server,
          await rpc(
            server,
            'roles/update',
            {
              tenantId: state.tenantId,
              roleId: state.roleId,
              description: `updated by ${server.label}`,
            },
            { token: state.ownerToken },
          ),
          'roles/update',
        );
        const answers = [{ server, value: renamed }];
        for (const reader of others(server))
          answers.push({
            server: reader,
            value: ok(
              reader,
              await rpc(
                reader,
                'roles/get',
                { tenantId: state.tenantId, roleId: state.roleId },
                { token: state.ownerToken },
              ),
              'roles/get',
            ),
          });
        same(answers, 'roles/get after roles/update');
      },
    );
  }

  {
    const [a, b, c] = [next(), next(), next()];
    await step(
      'seal a secret on one server, reveal it on another, add a version on a third',
      [a, b, c],
      async () => {
        const name = 'fleet/db/password';
        const created = ok(
          a,
          await rpc(
            a,
            'vault/create',
            { tenantId: state.tenantId, name, value: 'first-fleet-value' },
            { token: state.ownerToken },
          ),
          'vault/create',
        );
        check(
          !JSON.stringify(created).includes('first-fleet-value'),
          `${a.label}: vault/create echoes the value`,
        );
        const revealed = ok(
          b,
          await rpc(
            b,
            'vault/reveal',
            { tenantId: state.tenantId, name },
            { token: state.ownerToken },
          ),
          'vault/reveal',
        );
        check(
          revealed.value === 'first-fleet-value' && revealed.version === 1,
          `${b.label}: revealed ${show(revealed)}`,
        );
        ok(
          c,
          await rpc(
            c,
            'vault/put',
            { tenantId: state.tenantId, name, value: 'second-fleet-value' },
            { token: state.ownerToken },
          ),
          'vault/put',
        );
        for (const server of servers) {
          const current = ok(
            server,
            await rpc(
              server,
              'vault/reveal',
              { tenantId: state.tenantId, name },
              { token: state.ownerToken },
            ),
            'vault/reveal',
          );
          check(
            current.value === 'second-fleet-value' && current.version === 2,
            `${server.label}: current ${show(current)}`,
          );
          const previous = ok(
            server,
            await rpc(
              server,
              'vault/reveal',
              { tenantId: state.tenantId, name, stage: 'previous' },
              { token: state.ownerToken },
            ),
            'vault/reveal previous',
          );
          check(
            previous.value === 'first-fleet-value',
            `${server.label}: previous ${show(previous)}`,
          );
        }
        const answers = [];
        for (const server of servers)
          answers.push({
            server,
            value: ok(
              server,
              await rpc(
                server,
                'vault/get',
                { tenantId: state.tenantId, name },
                { token: state.ownerToken },
              ),
              'vault/get',
            ),
          });
        same(answers, 'vault/get');
      },
    );
  }

  {
    const writers = servers.flatMap((server) => [server, server, server, server]);
    await step(
      'concurrent writes: four identities created on every server at once',
      servers,
      async () => {
        const answers = await Promise.all(
          writers.map((server, index) =>
            rpc(
              server,
              'identities/create',
              {
                tenantId: state.tenantId,
                email: `burst${index}@acme.test`,
                name: `burst ${index}`,
              },
              { token: state.ownerToken },
            ).then((answer) => ({ server, answer })),
          ),
        );
        for (const { server, answer } of answers)
          check(
            answer.status === 200,
            `${server.label}: concurrent identities/create answered ${answer.status} ${show(answer.error)}`,
          );
        const listed = [];
        for (const server of servers)
          listed.push({
            server,
            value: ok(
              server,
              await rpc(
                server,
                'identities/list',
                { tenantId: state.tenantId, limit: 100 },
                { token: state.ownerToken },
              ),
              'identities/list',
            ),
          });
        const emails = (value) =>
          (Array.isArray(value) ? value : (value.items ?? value.identities ?? []))
            .map((identity) => identity.email ?? `(${identity.kind}) ${identity.name}`)
            .sort();
        same(listed, 'identities/list', emails);
        check(
          emails(listed[0].value).filter((email) => email.startsWith('burst')).length ===
            writers.length,
          `identities/list has ${show(emails(listed[0].value))}`,
        );
      },
    );
  }

  {
    const [a, b, c] = [next(), next(), next()];
    await step(
      'revoke on one server, refused on the others: API key, signed-out cookie, revoked sessions and JWT',
      [a, b, c],
      async () => {
        // The API key, revoked on a.
        ok(
          a,
          await rpc(
            a,
            'credentials/revoke',
            { tenantId: state.tenantId, credentialId: state.apiKey.credentialId },
            { token: state.ownerToken },
          ),
          'credentials/revoke',
        );
        for (const server of servers)
          refused(
            server,
            await rpc(server, 'auth/getSession', {}, { token: state.apiKey.token }),
            'UNAUTHENTICATED',
            401,
            'the revoked API key',
          );
        // Carol's cookie session, signed out on b (not the server that issued it).
        const signOutServer = servers.length > 1 && b === state.carolCookieServer ? c : b;
        const signedOut = await rpc(
          signOutServer,
          'auth/signOut',
          {},
          { cookie: state.carolCookie },
        );
        ok(signOutServer, signedOut, 'auth/signOut');
        check(
          signedOut.cookie === '',
          `${signOutServer.label}: auth/signOut did not clear the cookie (${show(signedOut.cookie)})`,
        );
        for (const server of servers)
          refused(
            server,
            await rpc(server, 'auth/getSession', {}, { cookie: state.carolCookie }),
            'UNAUTHENTICATED',
            401,
            'the signed-out cookie',
          );
        // Every session of Alice (her sign-in and the JWT minted from it), revoked by the owner on c.
        const revoked = ok(
          c,
          await rpc(
            c,
            'identities/revokeSessions',
            { tenantId: state.tenantId, identityId: state.people.alice.id },
            { token: state.ownerToken },
          ),
          'identities/revokeSessions',
        );
        note(`identities/revokeSessions on ${c.label}: ${show(revoked)}`);
        for (const server of servers) {
          refused(
            server,
            await rpc(server, 'auth/getSession', {}, { token: state.sessions.alice }),
            'UNAUTHENTICATED',
            401,
            "Alice's revoked session",
          );
          refused(
            server,
            await rpc(
              server,
              'authorize',
              {
                tenantId: state.tenantId,
                action: 'documents:read',
                resource: { type: 'document', id: 'doc-1' },
              },
              { token: state.jwt },
            ),
            'UNAUTHENTICATED',
            401,
            "Alice's session JWT after her sessions were revoked",
          );
        }
        // Bob's session is untouched.
        for (const server of servers)
          ok(
            server,
            await rpc(server, 'auth/getSession', {}, { token: state.sessions.bob }),
            "auth/getSession (Bob's session)",
          );
      },
    );
  }

  {
    const unbinder = next();
    await step(
      'a binding deleted on one server stops access on every server',
      [unbinder, ...others(unbinder)],
      async () => {
        const fresh = ok(
          unbinder,
          await rpc(unbinder, 'auth/signIn', {
            tenantId: state.tenantId,
            email: 'alice@acme.test',
            password: password('alice'),
          }),
          'auth/signIn alice',
        );
        ok(
          unbinder,
          await rpc(
            unbinder,
            'bindings/delete',
            { tenantId: state.tenantId, bindingId: state.bindingId },
            { token: state.ownerToken },
          ),
          'bindings/delete',
        );
        for (const server of servers) {
          const decision = ok(
            server,
            await rpc(
              server,
              'authorize',
              {
                tenantId: state.tenantId,
                action: 'documents:read',
                resource: { type: 'document', id: 'doc-1' },
              },
              { token: fresh.token },
            ),
            'authorize after bindings/delete',
          );
          check(
            decision.allowed === false,
            `${server.label}: authorize after the binding was deleted allowed=${decision.allowed}`,
          );
        }
      },
    );
  }

  await step(
    'every server reads the same audit log, and every hash chain verifies across writers',
    servers,
    async () => {
      for (const [tenantId, token, label] of [
        [state.tenantId, state.ownerToken, 'Acme'],
        [state.root.tenant.id, state.rootToken, 'root'],
      ]) {
        const lists = [];
        const verifications = [];
        for (const server of servers) {
          lists.push({
            server,
            value: ok(
              server,
              await rpc(server, 'audit/list', { tenantId, limit: 1000 }, { token }),
              `audit/list ${label}`,
            ),
          });
          verifications.push({
            server,
            value: ok(
              server,
              await rpc(server, 'audit/verify', { tenantId }, { token }),
              `audit/verify ${label}`,
            ),
          });
        }
        // audit/list and audit/verify themselves may be audited reads; compare the events up to the first server's list.
        const events = (value) =>
          Array.isArray(value) ? value : (value.events ?? value.items ?? []);
        const ids = (value) => events(value).map((event) => event.id);
        const firstIds = new Set(ids(lists[0].value));
        same(lists, `audit/list ${label}`, (value) =>
          events(value).filter((event) => firstIds.has(event.id)),
        );
        for (const { server, value } of verifications)
          check(value.valid === true, `${server.label}: audit/verify ${label} ${show(value)}`);
        same(verifications, `audit/verify ${label}`, (value) => ({ valid: value.valid }));
        const actions = events(lists[0].value).map((event) => event.action);
        const sequences = events(lists[0].value)
          .map((event) => event.sequence)
          .filter((value) => value !== undefined);
        note(
          `${label}: ${actions.length} events, sequences ${Math.min(...sequences)}..${Math.max(...sequences)}; verify ${show(verifications[0].value)}`,
        );
        if (label === 'Acme') {
          for (const action of [
            'iam:identities:create',
            'iam:identities:update',
            'iam:roles:create',
            'iam:bindings:create',
            'iam:credentials:create',
            'session-token:issued',
            'vault:create',
            'vault:put',
            'vault:reveal',
            'iam:credentials:revoke',
            'identity:revoke-sessions',
            'iam:bindings:delete',
          ])
            check(
              actions.includes(action),
              `audit/list Acme has no ${action} event (actions: ${show([...new Set(actions)])})`,
            );
        }
      }
    },
  );
}

// --- Main ----------------------------------------------------------------------------------------------------------
console.log(
  `better-iam mixed fleet: ${args.only.map((name) => LABEL[name]).join(', ')} on ${databasePath}\n`,
);
let aborted;
try {
  await scenario();
} catch (error) {
  aborted = error instanceof Abort ? error.message : (error.stack ?? String(error));
} finally {
  await Promise.all(servers.map(stopServer));
}
const failed = results.filter((result) => result.failures.length);
console.log('');
if (aborted) console.log(aborted);
for (const server of servers) {
  const errors = server.log.filter(
    (line) => /panic|fatal|error/i.test(line) && !/"delivery"/.test(line),
  );
  if (errors.length)
    console.log(`${server.label} server log (errors):\n  ${errors.slice(-10).join('\n  ')}`);
}
console.log(
  `${failed.length ? 'FAIL' : 'PASS'}: ${results.length - failed.length}/${results.length} steps passed${failed.length ? `; failing: ${failed.map((result) => `"${result.title}"`).join(', ')}` : ''}`,
);
if (args.keep || failed.length) {
  for (const server of servers)
    writeFileSync(join(work, `${server.name}.log`), `${server.log.join('\n')}\n`);
  console.log(`Kept ${work} (database, configuration, server logs).`);
} else rmSync(work, { recursive: true, force: true });
process.exit(failed.length || aborted ? 1 : 0);
