import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli, type CliIO } from '@better-iam/cli';
import type { Identity, Tenant } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

const work = resolve('work');
const created: string[] = [];
afterEach(async () => {
  await closeFixtures();
  for (const folder of created.splice(0)) {
    if (!resolve(folder).startsWith(work + sep)) throw new Error('Unsafe test cleanup');
    await rm(folder, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }).catch(
      () => undefined,
    );
  }
});
async function directory() {
  await mkdir(work, { recursive: true });
  const folder = await mkdtemp(join(work, 'cli-remote-test-'));
  created.push(folder);
  return folder;
}
const url = 'http://localhost:3000';

/**
 * Runs the CLI against the fixture's HTTP handler through an injected fetch: `--url` (or a saved profile) calls a
 * running server exactly as it would over the network, with a private credentials file per test.
 */
async function harness(f: OrganizationFixture) {
  const folder = await directory();
  const credentials = join(folder, 'credentials.json');
  const output: string[] = [];
  const io = (env: NodeJS.ProcessEnv = {}, more: Partial<CliIO> = {}): CliIO => ({
    out: (message) => output.push(message),
    env: { BETTER_IAM_CREDENTIALS: credentials, ...env },
    cwd: folder,
    fetch: (input, init) => f.iam.handler(new Request(input as string | URL, init)),
    ...more,
  });
  return {
    folder,
    credentials,
    output,
    run: (argv: string[], env?: NodeJS.ProcessEnv, more?: Partial<CliIO>) =>
      runCli(argv, io(env, more)),
    last: () => JSON.parse(output.at(-1)!),
  };
}

async function readers(f: OrganizationFixture) {
  const owner = f.ownerCredential;
  const role = await f.iam.api.roles.create(owner, {
    tenantId: f.tenantId,
    name: 'Reader',
    permissions: ['documents:read'],
  });
  const group = await f.iam.api.groups.create(owner, { tenantId: f.tenantId, name: 'Readers' });
  await f.iam.api.bindings.create(owner, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'group',
    subjectId: group.id,
  });
  const alice = await f.member('alice');
  const bob = await f.member('bob');
  await f.iam.api.groups.addMember(owner, {
    tenantId: f.tenantId,
    groupId: group.id,
    identityId: alice.id,
  });
  return {
    alice,
    bob,
    aliceToken: (await f.signIn('alice')).token,
    bobToken: (await f.signIn('bob')).token,
  };
}

describe('remote CLI', () => {
  it('calls any API route against a running server with key=value, JSON, file, and stdin input', async () => {
    const f = await organizationFixture();
    const h = await harness(f);
    const asOwner = { BETTER_IAM_TOKEN: f.ownerCredential.token };
    const tenant = ['--url', url, '--tenant', f.tenantId];

    await h.run(
      ['api', 'roles.create', 'name=Reader', 'permissions:=["documents:read"]', ...tenant],
      asOwner,
    );
    expect(h.last()).toMatchObject({ name: 'Reader', tenantId: f.tenantId });
    await h.run(['api', 'roles.list', ...tenant, '--query', '[].name'], asOwner);
    expect(h.last()).toContain('Reader');
    await h.run(['api', 'roles.list', ...tenant, '--format', 'table'], asOwner);
    expect(h.output.at(-1)).toMatch(/^ID\s+TENANTID\s+NAME/);

    await writeFile(
      join(h.folder, 'group.json'),
      JSON.stringify({ name: 'Writers', description: 'From a file' }),
    );
    await h.run(['api', 'groups.create', '--data', '@group.json', ...tenant], asOwner);
    expect(h.last()).toMatchObject({ name: 'Writers', description: 'From a file' });
    await h.run(
      ['api', 'groups.create', '--data', '-', 'description=Overridden', ...tenant],
      asOwner,
      {
        stdin: async () => JSON.stringify({ name: 'Piped', description: 'stdin' }),
      },
    );
    expect(h.last()).toMatchObject({ name: 'Piped', description: 'Overridden' });

    // Top-level routes and nested keys; tenantId comes from --tenant.
    await h.run(
      [
        'api',
        'authorize',
        'action=documents:read',
        'resource.type=documents',
        'resource.id=a',
        ...tenant,
      ],
      asOwner,
    );
    expect(h.last()).toHaveProperty('allowed');

    // Public routes need no token at all.
    await f.iam.api.tenants.setSlug(await f.ownerSignIn(), { tenantId: f.tenantId, slug: 'acme' });
    await h.run(['api', 'tenants.lookup', 'slug=acme', '--url', url]);
    expect(h.last()).toMatchObject({ tenantId: f.tenantId, slug: 'acme' });

    // The route table, readable and machine-readable, without a token.
    await h.run(['api', '--list', 'roles', '--url', url]);
    expect(h.output.at(-1)).toContain('roles.create');
    expect(h.output.at(-1)).toContain('POST /api/iam/roles/create');
    await h.run(['api', '--list', '--url', url, '--format', 'json']);
    expect(h.last()).toContainEqual({
      method: 'tenants.lookup',
      access: 'public',
      http: 'POST /api/iam/tenants/lookup',
    });

    const printed = h.output.length;
    for (const [argv, code] of [
      [['api', 'roles.nope', ...tenant], 'NOT_FOUND'],
      [['api', 'roles', ...tenant], 'INVALID_ARGUMENT'],
      [['api', '../etc', ...tenant], 'INVALID_ARGUMENT'],
      [['api', 'roles.create', 'name', ...tenant], 'INVALID_ARGUMENT'],
      [['api', 'roles.create', '__proto__.polluted=1', ...tenant], 'INVALID_ARGUMENT'],
      [['api', 'roles.create', 'limit:=not-json', ...tenant], 'INVALID_ARGUMENT'],
      [['api', 'roles.create', '--data', '[1]', ...tenant], 'INVALID_ARGUMENT'],
      [['api', '--list', 'nothing', '--url', url], 'NOT_FOUND'],
      [
        ['api', 'roles.list', '--url', 'ftp://example.test', '--tenant', f.tenantId],
        'INVALID_ARGUMENT',
      ],
    ] as const)
      await expect(h.run([...argv], asOwner), argv.join(' ')).rejects.toMatchObject({ code });
    await expect(h.run(['api', 'roles.list', ...tenant])).rejects.toMatchObject({
      code: 'MISSING_ENV',
    });
    expect(h.output).toHaveLength(printed);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('answers can, explain, and who-can questions', async () => {
    const f = await organizationFixture();
    const h = await harness(f);
    const { alice, bob, aliceToken, bobToken } = await readers(f);
    const tenant = ['--url', url, '--tenant', f.tenantId];

    await h.run(['can', 'documents:read', 'documents/a', ...tenant], {
      BETTER_IAM_TOKEN: aliceToken,
    });
    expect(h.last()).toMatchObject({ allowed: true });
    await expect(
      h.run(['can', 'documents:read', 'documents:a', ...tenant], { BETTER_IAM_TOKEN: bobToken }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(h.last()).toMatchObject({ allowed: false });
    await expect(
      h.run(['can', 'documents:read', 'no-separator', ...tenant], { BETTER_IAM_TOKEN: bobToken }),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      h.run(['can', 'documents:read', ...tenant], { BETTER_IAM_TOKEN: bobToken }),
    ).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });

    const asOwner = { BETTER_IAM_TOKEN: f.ownerCredential.token };
    await h.run(
      ['explain', 'documents:read', 'documents/a', '--identity', 'bob@acme.test', ...tenant],
      asOwner,
    );
    expect(h.last()).toMatchObject({ allowed: false });
    await h.run(
      ['explain', 'documents:read', 'documents/a', '--identity', alice.id, ...tenant],
      asOwner,
    );
    expect(h.last()).toMatchObject({ allowed: true });
    await expect(
      h.run(
        ['explain', 'documents:read', 'documents/a', '--identity', 'nobody@acme.test', ...tenant],
        asOwner,
      ),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    await h.run(
      ['who-can', 'documents:read', 'documents/a', ...tenant, '--query', 'identities[].identityId'],
      asOwner,
    );
    const holders = h.last() as string[];
    expect(holders).toContain(alice.id);
    expect(holders).not.toContain(bob.id);
  });

  it('logs in once and later commands act as the saved session, per profile', async () => {
    const f = await organizationFixture();
    const h = await harness(f);
    const { alice } = await readers(f);
    const password = { BETTER_IAM_PASSWORD: 'a strong alice password' };

    await expect(
      h.run(['login', '--url', url, '--tenant', f.tenantId, '--email', 'alice@acme.test']),
    ).rejects.toMatchObject({ code: 'MISSING_ENV' });
    await expect(
      h.run(['login', '--url', url, '--tenant', f.tenantId, '--email', 'alice@acme.test'], {
        BETTER_IAM_PASSWORD: 'not her password at all',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });

    await h.run(
      ['login', '--url', url, '--tenant', f.tenantId, '--email', 'alice@acme.test'],
      password,
    );
    expect(h.last()).toMatchObject({
      profile: 'default',
      url: `${url}/api/iam`,
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    const file = JSON.parse(await readFile(h.credentials, 'utf8'));
    expect(file).toMatchObject({ version: 1, current: 'default' });
    expect(file.profiles.default).toMatchObject({ email: 'alice@acme.test', kind: 'user' });
    expect(JSON.stringify(file)).not.toContain('a strong alice password');
    expect(JSON.stringify(h.output)).not.toContain(file.profiles.default.token);

    // No token, URL, or tenant: the profile supplies all three.
    await h.run(['whoami']);
    expect(h.last()).toMatchObject({ identityId: alice.id, tenantId: f.tenantId });
    await h.run(['can', 'documents:read', 'documents/a']);
    expect(h.last()).toMatchObject({ allowed: true });
    await h.run(['token']);
    expect(h.output.at(-1)).toBe(file.profiles.default.token);

    // A second profile from a token on standard input (an API key in CI works the same way).
    const ownerSession = await f.ownerSignIn();
    await h.run(
      ['login', '--with-token', '--url', url, '--profile', 'ops'],
      {},
      {
        stdin: async () => `${ownerSession.token}\n`,
      },
    );
    expect(h.last()).toMatchObject({ profile: 'ops', identityId: f.ownerId });
    await h.run(['whoami']);
    expect(h.last().identityId).toBe(f.ownerId);
    await h.run(['whoami', '--profile', 'default']);
    expect(h.last().identityId).toBe(alice.id);
    await h.run(['whoami'], { BETTER_IAM_PROFILE: 'default' });
    expect(h.last().identityId).toBe(alice.id);
    await h.run(['profiles', '--format', 'json']);
    expect(h.last()).toEqual([
      expect.objectContaining({ name: 'default', current: false, identityId: alice.id }),
      expect.objectContaining({ name: 'ops', current: true, identityId: f.ownerId }),
    ]);
    expect(h.output.at(-1)).not.toContain('token');
    await h.run(['profiles']);
    expect(h.output.at(-1)).toMatch(/NAME\s+CURRENT/);

    // An explicit token wins over every profile.
    await h.run(['whoami', '--url', url], { BETTER_IAM_TOKEN: (await f.signIn('bob')).token });
    expect(h.last().identityId).not.toBe(f.ownerId);

    await h.run(['profiles', 'use', 'default']);
    await h.run(['logout']);
    expect(h.last()).toEqual({ profile: 'default', revoked: true, forgotten: true });
    await expect(
      h.run(['whoami', '--url', url], { BETTER_IAM_TOKEN: file.profiles.default.token }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    await expect(h.run(['whoami'])).rejects.toMatchObject({ code: 'MISSING_ENV' });
    await h.run(['profiles', 'use', 'ops']);
    await h.run(['whoami']);
    expect(h.last().identityId).toBe(f.ownerId);
    await expect(h.run(['profiles', 'use', 'missing'])).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    await expect(h.run(['profiles', 'use', '../escape'])).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
    await expect(h.run(['logout', '--profile', 'missing'])).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });

    // A saved session past its end is refused before any request.
    const saved = JSON.parse(await readFile(h.credentials, 'utf8'));
    saved.profiles.ops.expiresAt = 1;
    await writeFile(h.credentials, JSON.stringify(saved));
    await expect(h.run(['whoami'])).rejects.toMatchObject({ code: 'SESSION_EXPIRED' });
    await h.run(['profiles', 'remove', 'ops']);
    expect(h.last()).toEqual({ removed: 'ops' });

    // Organizations by slug.
    await f.iam.api.tenants.setSlug(await f.ownerSignIn(), { tenantId: f.tenantId, slug: 'acme' });
    await h.run(['login', '--url', url, '--org', 'acme', '--email', 'bob@acme.test'], {
      BETTER_IAM_PASSWORD: 'a strong bob password',
    });
    expect(h.last()).toMatchObject({ tenantId: f.tenantId, profile: 'default' });
    await expect(
      h.run(['login', '--url', url, '--org', 'acme', '--tenant', f.tenantId], password),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });

  it('never sends a saved session to another deployment than the one that issued it', async () => {
    const f = await organizationFixture();
    const h = await harness(f);
    await readers(f);
    const hosts: string[] = [];
    // Every host reaches the fixture here, so only the CLI's own checks keep a token at home.
    const recording = (input: string | URL | Request, init?: RequestInit) => {
      hosts.push(new URL(input instanceof Request ? input.url : input).host);
      return f.iam.handler(new Request(input as string | URL, init));
    };
    const run = (argv: string[], env: NodeJS.ProcessEnv = {}, more: Partial<CliIO> = {}) =>
      h.run(argv, env, { fetch: recording, ...more });
    const password = { BETTER_IAM_PASSWORD: 'a strong alice password' };
    await run(
      ['login', '--url', url, '--tenant', f.tenantId, '--email', 'alice@acme.test'],
      password,
    );
    hosts.length = 0;

    for (const [argv, env] of [
      [['whoami', '--url', 'http://other.localhost:3000'], {}],
      [['api', 'roles.list'], { BETTER_IAM_URL: 'http://other.localhost:3000' }],
      [['whoami', '--url', `${url}/other/base`], {}],
    ] as const)
      await expect(run([...argv], env), argv.join(' ')).rejects.toMatchObject({
        code: 'MISSING_ENV',
        hint: expect.stringContaining('belongs to http://localhost:3000/api/iam'),
      });
    expect(hosts).toEqual([]);
    // The same server written differently is the same deployment.
    await run(['whoami', '--url', 'http://localhost:3000/api/iam/']);
    expect(hosts).toEqual(['localhost:3000']);

    // A login elsewhere never replaces the saved session silently; it needs its own profile name.
    await expect(
      run(
        [
          'login',
          '--url',
          'http://other.localhost:3000',
          '--tenant',
          f.tenantId,
          '--email',
          'bob@acme.test',
        ],
        {
          BETTER_IAM_PASSWORD: 'a strong bob password',
        },
      ),
    ).rejects.toMatchObject({ code: 'PROFILE_IN_USE' });
    expect(hosts).toEqual(['localhost:3000']);
    await run(
      [
        'login',
        '--url',
        'http://other.localhost:3000',
        '--tenant',
        f.tenantId,
        '--email',
        'bob@acme.test',
        '--profile',
        'other',
      ],
      { BETTER_IAM_PASSWORD: 'a strong bob password' },
    );
    expect(h.last()).toMatchObject({
      profile: 'other',
      url: 'http://other.localhost:3000/api/iam',
    });

    // Environment defaults never conflict with what the command line says.
    await run(
      ['login', '--with-token', '--url', url, '--profile', 'ci'],
      { BETTER_IAM_TENANT: 'ignored' },
      {
        stdin: async () => (await f.signIn('bob')).token,
      },
    );
    expect(h.last()).toMatchObject({ profile: 'ci', tenantId: f.tenantId });
    await f.iam.api.tenants.setSlug(await f.ownerSignIn(), { tenantId: f.tenantId, slug: 'acme' });
    await run(
      [
        'login',
        '--url',
        url,
        '--org',
        'acme',
        '--email',
        'alice@acme.test',
        '--profile',
        'default',
      ],
      {
        ...password,
        BETTER_IAM_TENANT: 'not-a-tenant',
      },
    );
    expect(h.last()).toMatchObject({ tenantId: f.tenantId });

    // Clear text is for local development only.
    await expect(
      run(['whoami', '--url', 'http://iam.example.test'], { BETTER_IAM_TOKEN: 'x'.repeat(43) }),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      run(['whoami', '--url', url, '--config', 'x.mjs'], { BETTER_IAM_TOKEN: 'x'.repeat(43) }),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });

    // Enrolling an authenticator for your own session goes through api with your token.
    await run(['api', 'auth.beginMfa', '--profile', 'default']);
    expect(h.last()).toHaveProperty('secret');
  });

  it('completes a required second factor with an emailed code during login', async () => {
    const f = await organizationFixture();
    const h = await harness(f);
    const alice = await f.member('alice');
    // Emailed codes go to verified addresses only.
    await f.iam.store.transaction(async (tx) => {
      const realm = (await tx.get<Tenant>('tenants', f.tenantId))!;
      await tx.put('tenants', { ...realm, authPolicy: { requireMfa: true, mfaEmailCodes: true } });
      const person = (await tx.get<Identity>('identities', alice.id))!;
      await tx.put('identities', { ...person, emailVerified: true });
    });
    const login = ['login', '--url', url, '--tenant', f.tenantId, '--email', 'alice@acme.test'];
    const password = { BETTER_IAM_PASSWORD: 'a strong alice password' };
    await expect(h.run(login, password)).rejects.toMatchObject({ code: 'MFA_ENROLLMENT_REQUIRED' });

    const questions: string[] = [];
    await h.run([...login, '--email-code'], password, {
      prompt: async (question) => {
        questions.push(question);
        await f.iam.auth.dispatchOutbox();
        return f.inbox.filter((message) => message.template === 'mfa-code').at(-1)!.payload.code!;
      },
    });
    expect(questions).toEqual(['Emailed code: ']);
    expect(h.last()).toMatchObject({ identityId: alice.id });
    await h.run(['whoami']);
    expect(h.last()).toMatchObject({ identityId: alice.id, mfa: true });
  });
});
