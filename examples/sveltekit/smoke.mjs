// Runs the production build (`vite build` first) against a fresh SQLite file and checks the Better IAM integration:
// the mounted API, `protect` rules in `handle` (pages and client-side data requests), sign-in and sign-out through form
// actions and the in-process client, server-rendered sessions and seeded decisions, guarded loads and actions.
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
const directory = await mkdtemp(join(tmpdir(), 'better-iam-sveltekit-'));
const server = spawn(process.execPath, [resolve(here, 'build/index.js')], {
  cwd: here,
  env: {
    ...process.env,
    PORT: String(port),
    HOST: '127.0.0.1',
    ORIGIN: origin,
    BETTER_IAM_SECRET: 'sveltekit-smoke-secret-with-at-least-32-characters',
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
      const body = await (await fetch(`${base}/api/demo`)).json();
      if (body.tenantId) return body.tenantId;
    } catch {
      /* not listening yet */
    }
    await new Promise((done) => setTimeout(done, 200));
  }
  throw new Error(`Server did not become ready:\n${output}`);
}
const page = (path, headers = {}) => fetch(`${base}${path}`, { headers, redirect: 'manual' });
const post = (path, fields, headers = {}) =>
  fetch(`${base}${path}`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'text/html',
      origin,
      ...headers,
    },
    body: new URLSearchParams(fields).toString(),
  });
const sessionCookie = (response) =>
  response.headers
    .getSetCookie()
    .find((header) => header.startsWith('better-iam.session='))
    ?.split(';')[0];

try {
  await ready();

  // Anonymous: the home page renders signed out; protected pages redirect with ?next=, data requests too.
  const anonymousHome = await (await page('/')).text();
  assert.match(anonymousHome, /id="greeting"[^>]*>Signed out</);
  assert.match(anonymousHome, /id="members-denied"/);
  const redirected = await page('/account');
  assert.equal(redirected.status, 303);
  assert.equal(redirected.headers.get('location'), '/login?next=%2Faccount');
  const data = await page('/account/__data.json');
  assert.deepEqual(
    { type: (await data.json()).type, status: data.status },
    { type: 'redirect', status: 200 },
  );

  // A wrong password comes back as the action's fail() with the form re-rendered.
  const wrong = await post('/login', { email: 'member@example.test', password: 'nope' });
  assert.equal(wrong.status, 400);
  assert.match(await wrong.text(), /id="login-error"/);

  // Signing in through the form action: the in-process client sets the cookie, then the action redirects to ?next.
  const signIn = await post('/login?next=%2Faccount', {
    email: 'member@example.test',
    password: 'demo member password for sveltekit',
  });
  assert.equal(signIn.status, 303, await signIn.clone().text());
  assert.equal(signIn.headers.get('location'), '/account');
  const cookie = sessionCookie(signIn);
  assert.ok(cookie, 'the sign-in response sets the session cookie');
  assert.match(signIn.headers.getSetCookie().join('\n'), /HttpOnly/i);

  // Server rendering knows the session; the member lacks iam:identities:read, decided on the server.
  const home = await (await page('/', { cookie })).text();
  assert.match(home, /Signed in as member@example\.test/);
  assert.match(home, /id="members-denied"/);

  const account = await page('/account', { cookie });
  assert.equal(account.status, 200);
  assert.match(await account.text(), /id="account-email"[^>]*>member@example\.test</);

  // The guarded action refuses a member without iam:identities:update: fail(403) rendered in the form.
  const rename = await post('/account?/rename', { name: 'Someone Else' }, { cookie });
  assert.equal(rename.status, 403);
  assert.match(await rename.text(), /id="rename-error"[^>]*>ACCESS_DENIED</);

  // The admin section needs iam:identities:read on the tenant.
  const admin = await page('/admin', { cookie });
  assert.equal(admin.status, 403);
  assert.doesNotMatch(await admin.text(), /id="admin-title"/);

  const me = await page('/api/me', { cookie });
  assert.equal(me.status, 200);
  const body = await me.json();
  assert.deepEqual(Object.keys(body).sort(), ['canReadMembers', 'email', 'id']);
  assert.equal(body.canReadMembers, false);

  // The IAM API itself is served from handle.
  assert.equal((await (await page('/api/iam/health')).json()).status, 'ok');
  const apiSession = await fetch(`${base}/api/iam/auth/getSession`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-better-iam': '1', origin, cookie },
    body: '{}',
  });
  assert.equal(apiSession.status, 200);

  // Signing out ends the session on the server and clears the cookie.
  const signOut = await post('/logout', {}, { cookie });
  assert.equal(signOut.status, 303);
  assert.match(signOut.headers.getSetCookie().join('\n'), /better-iam\.session=;.*Max-Age=0/i);
  assert.equal((await page('/api/me', { cookie })).status, 401);
  console.log(
    'SvelteKit example: API mount, protect rules, form actions, SSR session and decisions passed.',
  );
} catch (error) {
  console.error(output);
  throw error;
} finally {
  server.kill();
  await new Promise((done) => server.once('exit', done));
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
