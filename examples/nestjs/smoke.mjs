// Runs the compiled example (`pnpm build` first) against a fresh SQLite file and checks the NestJS integration:
// the global guard, @Authorize, @FilterAccessible, @RequireMfa, the mounted IAM API, CSRF, and @OnIamEvent.
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import assert from 'node:assert/strict';

const here = import.meta.dirname;
const port = await new Promise((done) => {
  const probe = createServer().listen(0, '127.0.0.1', () => {
    const { port: free } = probe.address();
    probe.close(() => done(free));
  });
});
const base = `http://127.0.0.1:${port}`;
const directory = await mkdtemp(join(tmpdir(), 'better-iam-nestjs-'));
const server = spawn(process.execPath, [resolve(here, 'dist/main.js')], {
  cwd: here,
  env: {
    ...process.env,
    PORT: String(port),
    HOST: '127.0.0.1',
    BETTER_IAM_SECRET: 'nestjs-smoke-secret-with-at-least-32-characters',
    BETTER_IAM_BASE_URL: `http://localhost:${port}`,
    BETTER_IAM_DATABASE: join(directory, 'iam.db'),
    DEMO_SEED: '1',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let output = '';
server.stdout.on('data', (chunk) => (output += chunk));
server.stderr.on('data', (chunk) => (output += chunk));

async function ready() {
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      const body = await (await fetch(`${base}/status`)).json();
      if (body.tenantId) return body;
    } catch {
      /* not listening yet */
    }
    await new Promise((done) => setTimeout(done, 200));
  }
  throw new Error(`Server did not become ready:\n${output}`);
}

try {
  const status = await ready();
  assert.equal(status.iam.status, 'up');
  const { tenantId } = status;
  const get = (path, headers = {}) => fetch(`${base}${path}`, { headers });

  // The global guard: anonymous callers get the IAM error envelope.
  const anonymous = await get('/projects');
  assert.equal(anonymous.status, 401);
  assert.equal((await anonymous.json()).error.code, 'UNAUTHENTICATED');

  // Sign in through the IAM API that the Nest app serves.
  const signIn = await fetch(`${base}/api/iam/auth/signIn`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
    body: JSON.stringify({
      tenantId,
      email: 'member@example.test',
      password: 'demo member password for nestjs',
    }),
  });
  assert.equal(signIn.status, 200, await signIn.clone().text());
  const cookie = signIn.headers.getSetCookie()[0].split(';')[0];
  const { token } = (await signIn.json()).data;

  const me = await (await get('/me', { cookie })).json();
  assert.equal(me.email, 'member@example.test');
  assert.equal(me.canReadMembers, false);

  // Mia may read Apollo and Gemini only: the list is filtered and the detail route enforced.
  assert.deepEqual(
    (await (await get('/projects', { cookie })).json()).map((project) => project.id),
    ['apollo', 'gemini'],
  );
  assert.equal((await get('/projects/apollo', { cookie })).status, 200);
  const denied = await get('/projects/mercury', { cookie });
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).error.code, 'ACCESS_DENIED');

  // Unsafe cookie requests from another site are refused before authorization; bearer tokens are not ambient.
  const crossSite = await fetch(`${base}/projects/apollo/archive`, {
    method: 'POST',
    headers: { cookie, origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' },
  });
  assert.equal((await crossSite.json()).error.code, 'CSRF_REJECTED');
  const archive = await fetch(`${base}/projects/apollo/archive`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(archive.status, 403);
  assert.equal((await archive.json()).error.code, 'MFA_REQUIRED');

  assert.equal((await (await get('/api/iam/health')).json()).status, 'ok');

  // Audit events reach the @OnIamEvent listener through the module's dispatch loop.
  let events = [];
  for (let attempt = 0; attempt < 25 && !events.includes('auth:sign-in:allow'); attempt++) {
    await new Promise((done) => setTimeout(done, 200));
    events = await (await get('/events')).json();
  }
  assert.ok(
    events.some((event) => event.startsWith('auth:')),
    JSON.stringify(events),
  );
  console.log('NestJS example: guard, authorization, filtering, mount, CSRF, and events passed.');
} catch (error) {
  console.error(output);
  throw error;
} finally {
  server.kill();
  await new Promise((done) => server.once('exit', done));
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
