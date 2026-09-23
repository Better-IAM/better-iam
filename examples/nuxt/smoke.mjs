// Runs the production build (`nuxt build` first) against a fresh SQLite file and checks the Better IAM integration:
// server-rendered sessions, hydrated IamCan decisions, page-meta access control, and the auto-imported server utils.
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
const origin = `http://localhost:${port}`;
const base = `http://127.0.0.1:${port}`;
const directory = await mkdtemp(join(tmpdir(), 'better-iam-nuxt-'));
const server = spawn(process.execPath, [resolve(here, '.output/server/index.mjs')], {
  cwd: here,
  env: {
    ...process.env,
    PORT: String(port),
    HOST: '127.0.0.1',
    BETTER_IAM_SECRET: 'nuxt-smoke-secret-with-at-least-32-characters',
    BETTER_IAM_BASE_URL: origin,
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
      const response = await fetch(`${base}/api/demo`);
      const body = await response.json();
      if (body.tenantId) return body.tenantId;
    } catch {
      /* not listening yet */
    }
    await new Promise((done) => setTimeout(done, 200));
  }
  throw new Error(`Server did not become ready:\n${output}`);
}

try {
  const tenantId = await ready();
  const page = (path, headers = {}) => fetch(`${base}${path}`, { headers, redirect: 'manual' });

  // Anonymous: the home page renders signed out; protected pages redirect with ?next=.
  const anonymousHome = await (await page('/')).text();
  assert.match(anonymousHome, /id="greeting"[^>]*>Signed out</);
  const redirected = await page('/account');
  assert.equal(redirected.status, 302);
  assert.equal(redirected.headers.get('location'), '/login?next=/account');
  const anonymousApi = await page('/api/me');
  assert.equal(anonymousApi.status, 401);
  assert.equal((await anonymousApi.json()).data.code, 'UNAUTHENTICATED');

  // Sign in through the mounted IAM API; the cookie drives everything that follows.
  const signIn = await fetch(`${base}/api/iam/auth/signIn`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-better-iam': '1', origin },
    body: JSON.stringify({
      tenantId,
      email: 'member@example.test',
      password: 'demo member password for nuxt',
    }),
  });
  assert.equal(signIn.status, 200, await signIn.clone().text());
  const cookie = signIn.headers.get('set-cookie').split(';')[0];

  // Server rendering knows the session and resolves the IamCan decision before sending HTML.
  const home = await (await page('/', { cookie })).text();
  assert.match(home, /Signed in as member@example\.test/);
  assert.match(home, /id="whoami"[^>]*>[^<]*Mia Member/);
  assert.match(home, /id="members-denied"/);
  assert.doesNotMatch(home, /Checking access/);
  assert.match(home, /better-iam:hydration/);
  assert.match(home, /better-iam:authorize:/);

  const account = await page('/account', { cookie });
  assert.equal(account.status, 200);
  assert.match(await account.text(), /id="account-email"[^>]*>member@example\.test</);

  // The admin page needs iam:identities:read on the tenant, which a plain member lacks.
  const admin = await page('/admin', { cookie });
  assert.equal(admin.status, 403);
  assert.doesNotMatch(await admin.text(), /id="admin-title"/);

  const me = await page('/api/me', { cookie });
  assert.equal(me.status, 200);
  assert.deepEqual(Object.keys(await me.json()).sort(), ['canReadMembers', 'email', 'id']);

  // The mounted handler keeps the IAM API's own routes, including health.
  assert.equal((await (await page('/api/iam/health')).json()).status, 'ok');
  console.log(
    'Nuxt example: SSR session, hydrated decisions, page access, and server utils passed.',
  );
} catch (error) {
  console.error(output);
  throw error;
} finally {
  server.kill();
  await new Promise((done) => server.once('exit', done));
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
