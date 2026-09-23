import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { hashToken, newCredentialToken } from '@better-iam/auth';
import type { PolicyDocument, PolicyStatement, Session, StoredRecord } from '@better-iam/core';
import type { BetterIamOptions } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);

afterEach(closeFixtures);

/**
 * Session-aware condition keys (principal.sessionId, tokenIssueTime, authTime, mfaTime, sessionTagKeys,
 * sessionTags.<key>, sourceTenantId, sessionName, sourceIdentity, request.sourceIp) as decisions derive them for real
 * user sessions, API keys and role sessions. Fields that later waves' issuers set (session names, tags, source
 * identities, source policies) are patched onto stored rows through `iam.store`; principals ignores them for role and
 * API-key rows. Application and plugin context can never supply server-owned keys, and a trust with
 * passSourceAttributes false keeps the source identity's attributes out of its role sessions.
 */

const MINUTE = 60_000;

function allow(
  actions: string[],
  resources: string[],
  conditions?: PolicyStatement['conditions'],
): PolicyStatement {
  return { effect: 'allow', actions, resources, ...(conditions ? { conditions } : {}) };
}

/**
 * One allow of documents:read per probe resource, each on the condition the probe names, plus documents:write and
 * documents:delete (the latter denied for sessions issued before `cutoff`), and iam:roles:assume.
 */
function probeDocument(since: string, cutoff: string): PolicyDocument {
  const read = (id: string, conditions?: PolicyStatement['conditions']) =>
    allow(['documents:read'], [`document/${id}`], conditions);
  return {
    version: 1,
    statements: [
      allow(['iam:roles:assume', 'documents:write', 'documents:delete'], ['*']),
      {
        effect: 'deny',
        actions: ['documents:delete'],
        resources: ['*'],
        conditions: { DateBefore: { 'principal.tokenIssueTime': cutoff } },
      },
      read('sid-${principal.sessionId}'),
      read('issued', {
        Exists: {
          'principal.tokenIssueTime': true,
          'principal.authTime': true,
          'principal.sessionTagKeys': true,
        },
        DateAfter: { 'principal.tokenIssueTime': since, 'principal.authTime': since },
      }),
      read('mfa-time', { Exists: { 'principal.mfaTime': true } }),
      read('mfa-recent', { DateAfter: { 'principal.mfaTime': since } }),
      read('name', { StringEquals: { 'principal.sessionName': 'build-42' } }),
      read('any-name', { Exists: { 'principal.sessionName': true } }),
      read('source-identity', { StringEquals: { 'principal.sourceIdentity': 'alice.ci' } }),
      read('team', { StringEquals: { 'principal.sessionTags.team': 'blue' } }),
      read('any-team', { Exists: { 'principal.sessionTags.team': true } }),
      read('tag-keys', { ArrayContainsAll: { 'principal.sessionTagKeys': ['env', 'team'] } }),
      read('stid-${principal.sourceTenantId}'),
      read('auth-method', { Exists: { 'principal.authMethod': true } }),
      read('office', { IpAddress: { 'request.sourceIp': '203.0.113.0/24' } }),
      read('any-ip', { Exists: { 'request.sourceIp': true } }),
      read('custom', { StringEquals: { 'app.custom': 'kept' } }),
      read('department', { StringEquals: { 'principal.department': 'eng' } }),
      read('web', { Exists: { 'principal.webIdentityProvider': true } }),
      read('owner', { Bool: { 'principal.owner': true } }),
      read('root-admin', { Bool: { 'principal.rootAdmin': true } }),
      read('agreements-owed', { NumericGreaterThan: { 'principal.pendingAgreements': 0 } }),
    ],
  };
}

async function probeFixture(overrides: Partial<BetterIamOptions> = {}) {
  const f = await organizationFixture({
    permissions: {
      actions: ['documents:read', 'documents:write', 'documents:delete'],
      identityAttributes: { department: 'string' },
    },
    ...overrides,
  });
  const since = new Date(f.now() - MINUTE).toISOString();
  const cutoff = new Date(f.now() + MINUTE).toISOString();
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Probe',
    document: probeDocument(since, cutoff),
  });
  const alice = await f.member('alice');
  await f.iam.api.identities.update(f.ownerCredential, {
    tenantId: f.tenantId,
    identityId: alice.id,
    attributes: { department: 'eng' },
  });
  const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'ci',
  });
  for (const subjectId of [alice.id, account.id])
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId,
    });
  // Alice may assume the probe role itself, so her role sessions carry the same probes.
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: alice.id,
    roleId: role.id,
    requireMfa: false,
  });
  return { ...f, role, alice, account, trust };
}
type ProbeFixture = Awaited<ReturnType<typeof probeFixture>>;

/** Whether `token` may read the probe document `id` (or perform `action` on it). */
async function probe(
  f: OrganizationFixture,
  token: string,
  id: string,
  action = 'documents:read',
): Promise<boolean> {
  return (
    await f.iam.authorize({
      token,
      tenantId: f.tenantId,
      action,
      resource: { type: 'document', id },
    })
  ).allowed;
}

/** The probes out of `ids` that `token` passes. */
async function passing(f: OrganizationFixture, token: string, ids: string[]): Promise<string[]> {
  const passed: string[] = [];
  for (const id of ids) if (await probe(f, token, id)) passed.push(id);
  return passed;
}

async function storedSession(f: OrganizationFixture, token: string): Promise<Session> {
  const rows = await f.iam.store.find<Session>('sessions', { tokenHash: hashToken(token) });
  expect(rows).toHaveLength(1);
  return rows[0]!;
}

async function patch(f: OrganizationFixture, collection: string, id: string, fields: object) {
  await f.iam.store.transaction(async (tx) => {
    const row = (await tx.get<StoredRecord>(collection, id))!;
    await tx.put(collection, { ...row, ...fields });
  });
}

async function apiKey(f: ProbeFixture) {
  const key = await f.iam.api.credentials.create(f.ownerCredential, {
    tenantId: f.tenantId,
    identityId: f.account.id,
  });
  return { token: key.token, session: await storedSession(f, key.token) };
}

async function roleSession(f: ProbeFixture, source?: { token: string }) {
  const credential = source ?? (await f.signIn('alice'));
  const assumed = await f.iam.api.roles.assume(
    { token: credential.token },
    {
      tenantId: f.tenantId,
      trustId: f.trust.id,
    },
  );
  return { token: assumed.token, session: await storedSession(f, assumed.token) };
}

/** Seeds a session token minted from `source`, as sts.getSessionToken stores it. */
async function sessionToken(f: OrganizationFixture, source: Session): Promise<string> {
  const token = newCredentialToken('sts');
  const now = f.now();
  const row: Session = {
    id: randomUUID(),
    tenantId: source.tenantId,
    identityId: source.identityId,
    kind: 'session-token',
    sourceSessionId: source.id,
    tokenHash: hashToken(token),
    createdAt: now,
    lastSeenAt: now,
    authenticatedAt: source.authenticatedAt,
    expiresAt: Math.min(source.expiresAt, now + 60 * MINUTE),
    mfa: source.mfa,
  };
  await f.iam.store.transaction((tx) =>
    tx.insert('sessions', { ...row, uniqueKey: row.tokenHash } as never),
  );
  return token;
}

const optionalProbes = [
  'mfa-time',
  'name',
  'any-name',
  'source-identity',
  'team',
  'any-team',
  'tag-keys',
  'auth-method',
  'any-ip',
  'web',
];

describe('session context keys', () => {
  it('derives the always-present keys for every kind and the optional ones only when set', async () => {
    const f = await probeFixture();
    const user = await f.signIn('alice');
    const key = await apiKey(f);
    const role = await roleSession(f);

    for (const [token, id] of [
      [user.token, user.session.id],
      [key.token, key.session.id],
      [role.token, role.session.id],
    ] as const) {
      expect(await probe(f, token, `sid-${id}`)).toBe(true);
      expect(await probe(f, token, 'sid-simulation')).toBe(false);
      expect(await probe(f, token, 'issued')).toBe(true);
    }
    // Only a password sign-in has a method; nothing optional is set on a plain key or role session.
    expect(await passing(f, user.token, optionalProbes)).toEqual(['auth-method']);
    expect(await passing(f, key.token, optionalProbes)).toEqual([]);
    expect(await passing(f, role.token, optionalProbes)).toEqual([]);
    // principal.sourceTenantId names the source tenant of role sessions only.
    expect(await probe(f, role.token, `stid-${f.tenantId}`)).toBe(true);
    expect(await probe(f, user.token, `stid-${f.tenantId}`)).toBe(false);
    expect(await probe(f, key.token, `stid-${f.tenantId}`)).toBe(false);

    // Role-session attribution fields and tags, as issuers record them.
    await patch(f, 'sessions', role.session.id, {
      sessionName: 'build-42',
      sourceIdentity: 'alice.ci',
      sessionTags: { team: 'blue', env: 'prod' },
    });
    expect(await passing(f, role.token, optionalProbes)).toEqual([
      'name',
      'any-name',
      'source-identity',
      'team',
      'any-team',
      'tag-keys',
    ]);
    // Tag values are matched exactly, and keys case-sensitively.
    await patch(f, 'sessions', role.session.id, { sessionTags: { Team: 'blue', env: 'prod' } });
    expect(await passing(f, role.token, ['team', 'any-team', 'tag-keys'])).toEqual([]);
  });

  it('denies sessions issued before a DateBefore cutoff on principal.tokenIssueTime', async () => {
    const f = await probeFixture();
    const older = await f.signIn('alice');
    const olderKey = await apiKey(f);
    expect(await probe(f, older.token, 'x', 'documents:delete')).toBe(false);
    expect(await probe(f, olderKey.token, 'x', 'documents:delete')).toBe(false);
    expect(await probe(f, older.token, 'x', 'documents:write')).toBe(true);

    f.advance(2 * MINUTE);
    const newer = await f.signIn('alice');
    const newerKey = await apiKey(f);
    expect(await probe(f, newer.token, 'x', 'documents:delete')).toBe(true);
    expect(await probe(f, newerKey.token, 'x', 'documents:delete')).toBe(true);
    // The older credentials still work, but stay refused where the cutoff applies.
    expect(await probe(f, older.token, 'x', 'documents:delete')).toBe(false);
    expect(await probe(f, older.token, 'x', 'documents:write')).toBe(true);
  });

  it('sets principal.mfaTime only after a first-hand second factor', async () => {
    const f = await probeFixture();
    const bob = await f.member('bob');
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: f.role.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const first = await f.signIn('bob');
    const enrollment = await f.iam.api.auth.beginMfa({ token: first.token });
    const generator = authenticator.clone();
    generator.options = { epoch: f.now() };
    const confirmed = await f.iam.api.auth.confirmMfa({
      credential: { token: first.token },
      code: generator.generate(enrollment.secret),
    });
    expect(confirmed.session.mfa).toBe(true);
    expect(await passing(f, confirmed.token, ['mfa-time', 'mfa-recent'])).toEqual([
      'mfa-time',
      'mfa-recent',
    ]);

    // Password-only people and API keys have no MFA time, so DateAfter fails rather than passing.
    const password = await f.signIn('alice');
    const key = await apiKey(f);
    for (const token of [password.token, key.token])
      expect(await passing(f, token, ['mfa-time', 'mfa-recent'])).toEqual([]);

    // A role session copies its source's MFA time; the flag alone, or a remembered device, is not enough.
    const role = await roleSession(f);
    await patch(f, 'sessions', role.session.id, { mfa: true });
    expect(await passing(f, role.token, ['mfa-time'])).toEqual([]);
    await patch(f, 'sessions', role.session.id, { mfaAuthenticatedAt: f.now() });
    expect(await passing(f, role.token, ['mfa-time', 'mfa-recent'])).toEqual([
      'mfa-time',
      'mfa-recent',
    ]);
    await patch(f, 'sessions', role.session.id, { trustedDeviceId: 'device' });
    expect(await passing(f, role.token, ['mfa-time'])).toEqual([]);
    await patch(f, 'sessions', role.session.id, { trustedDeviceId: undefined, mfa: false });
    expect(await passing(f, role.token, ['mfa-time'])).toEqual([]);
  });

  it('leaves principal.mfaTime absent for remembered-device and impersonation sessions', async () => {
    const f = await probeFixture();
    const bob = await f.member('bob');
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: f.role.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const first = await f.signIn('bob');
    const enrollment = await f.iam.api.auth.beginMfa({ token: first.token });
    const code = () => {
      const generator = authenticator.clone();
      generator.options = { epoch: f.now() };
      return generator.generate(enrollment.secret) as string;
    };
    await f.iam.api.auth.confirmMfa({ credential: { token: first.token }, code: code() });
    const signIn = (deviceToken?: string) =>
      f.iam.api.auth.signIn({
        tenantId: f.tenantId,
        email: 'bob@acme.test',
        password: 'a strong bob password',
        ...(deviceToken ? { deviceToken } : {}),
      });
    const challenge = await signIn();
    if (!('mfaRequired' in challenge)) throw new Error('Bob must require MFA after enrolling');
    f.advance(30_000);
    const verified = await f.iam.api.auth.verifyMfa({
      tenantId: f.tenantId,
      challenge: challenge.challenge,
      code: code(),
      rememberDevice: true,
    });
    // The first-hand ceremony sets it...
    expect(await passing(f, verified.token, ['mfa-time', 'mfa-recent'])).toEqual([
      'mfa-time',
      'mfa-recent',
    ]);
    // ...a remembered device satisfies MFA without it, even if a factor time were recorded on the row.
    f.advance(MINUTE);
    const remembered = await signIn(verified.deviceToken!);
    if (!('token' in remembered)) throw new Error('The device token should skip MFA');
    const deviceRow = await storedSession(f, remembered.token);
    expect(deviceRow).toMatchObject({ mfa: true, trustedDeviceId: expect.any(String) });
    expect(await probe(f, remembered.token, 'issued')).toBe(true);
    expect(await passing(f, remembered.token, ['mfa-time', 'mfa-recent'])).toEqual([]);
    await patch(f, 'sessions', deviceRow.id, { mfaAuthenticatedAt: f.now() });
    expect(await passing(f, remembered.token, ['mfa-time', 'mfa-recent'])).toEqual([]);

    // Impersonation never exposes a factor time, even with an MFA flag and a recorded time on the row. (The owner
    // signs in with a password only, so the member viewed is Alice, who requires no MFA.)
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const viewAs = await f.iam.api.identities.impersonate(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: f.alice.id,
      reason: 'ticket 42',
    });
    const impersonation = await storedSession(f, viewAs.token);
    expect(impersonation.impersonatorId).toBe(f.ownerId);
    expect(await probe(f, viewAs.token, 'issued')).toBe(true);
    expect(await passing(f, viewAs.token, ['mfa-time', 'mfa-recent'])).toEqual([]);
    await patch(f, 'sessions', impersonation.id, { mfa: true, mfaAuthenticatedAt: f.now() });
    expect(await passing(f, viewAs.token, ['mfa-time', 'mfa-recent'])).toEqual([]);
  });

  it('names a cross-tenant source tenant in principal.sourceTenantId, apart from principal.tenantId', async () => {
    const f = await probeFixture();
    const platform = f.root.tenant.id;
    const password = 'a strong operator test password';
    const ops = await f.iam.api.identities.create(f.rootCredential, {
      tenantId: platform,
      email: 'ops@example.test',
      name: 'Ops',
      password,
    });
    const assumer = await f.iam.api.roles.create(f.rootCredential, {
      tenantId: platform,
      name: 'Assumer',
      document: { version: 1, statements: [allow(['iam:roles:assume'], ['*'])] },
    });
    await f.iam.api.bindings.create(f.rootCredential, {
      tenantId: platform,
      roleId: assumer.id,
      subjectType: 'identity',
      subjectId: ops.id,
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Tenant probe',
      document: {
        version: 1,
        statements: [
          allow(['documents:read'], ['document/stid-${principal.sourceTenantId}']),
          allow(['documents:read'], ['document/tid-${principal.tenantId}']),
          allow(['documents:read'], ['document/cross'], {
            StringEquals: {
              'principal.sourceTenantId': platform,
              'principal.tenantId': f.tenantId,
            },
          }),
        ],
      },
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: platform,
      sourceIdentityId: ops.id,
      roleId: role.id,
      requireMfa: false,
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: platform,
      email: 'ops@example.test',
      password,
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    const assumed = await f.iam.api.roles.assume(
      { token: login.token },
      { tenantId: f.tenantId, trustId: trust.id },
    );
    expect(platform).not.toBe(f.tenantId);
    expect(
      await passing(f, assumed.token, [
        `stid-${platform}`,
        `tid-${f.tenantId}`,
        'cross',
        `stid-${f.tenantId}`,
        `tid-${platform}`,
      ]),
    ).toEqual([`stid-${platform}`, `tid-${f.tenantId}`, 'cross']);
  });

  it('sets request.sourceIp from the client address, never without one or for simulations', async () => {
    const f = await probeFixture();
    const user = await f.signIn('alice');
    const key = await apiKey(f);
    const within = <T>(ip: string, run: () => Promise<T>) =>
      f.iam.auth.withClient({ ip, userAgent: 'test' }, run);

    for (const token of [user.token, key.token]) {
      expect(await probe(f, token, 'any-ip')).toBe(false);
      expect(await within('203.0.113.7', () => passing(f, token, ['office', 'any-ip']))).toEqual([
        'office',
        'any-ip',
      ]);
      expect(await within('198.51.100.7', () => passing(f, token, ['office', 'any-ip']))).toEqual([
        'any-ip',
      ]);
      // A value that is not an address is never exposed.
      expect(await within('not-an-address', () => passing(f, token, ['any-ip']))).toEqual([]);
    }

    // Simulations describe no real request, so the key stays absent even inside a client scope.
    const simulate = (id: string) =>
      f.iam.api.policies.simulate(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: f.alice.id,
        action: 'documents:read',
        resource: { type: 'document', id },
      });
    expect((await simulate('sid-simulation')).allowed).toBe(true);
    expect((await simulate('issued')).allowed).toBe(true);
    expect((await within('203.0.113.7', () => simulate('any-ip'))).allowed).toBe(false);
  });

  it('removes server-owned keys supplied by resolveContext or plugins', async () => {
    const f = await probeFixture({
      resolveContext: async () => ({
        'principal.sessionName': 'build-42',
        'principal.sessionTags.team': 'blue',
        'principal.sessionTags': { team: 'blue' },
        'principal.sessionTagKeys': ['env', 'team'],
        'principal.authMethod': 'password',
        'principal.mfaTime': '2099-01-01T00:00:00.000Z',
        'request.sourceIp': '203.0.113.9',
        'app.custom': 'kept',
      }),
      plugins: [
        {
          id: 'spoofing-plugin',
          resolveContext: async () => ({
            'principal.sourceIdentity': 'alice.ci',
            'principal.webIdentityProvider': 'provider',
            'principal.sessionId': 'simulation',
          }),
        },
      ],
    });
    const user = await f.signIn('alice');
    const key = await apiKey(f);
    const role = await roleSession(f);
    for (const token of [user.token, key.token, role.token]) {
      // Application keys that are not server-owned still arrive.
      expect(await probe(f, token, 'custom')).toBe(true);
      expect(await probe(f, token, 'sid-simulation')).toBe(false);
      expect(await probe(f, token, 'issued')).toBe(true);
    }
    expect(await passing(f, user.token, optionalProbes)).toEqual(['auth-method']);
    // An API key has no sign-in method, and the application's value no longer stands in for it.
    expect(await passing(f, key.token, optionalProbes)).toEqual([]);
    expect(await passing(f, role.token, optionalProbes)).toEqual([]);
    // The server's own values replace the application's.
    await patch(f, 'sessions', role.session.id, { sessionName: 'nightly' });
    expect(await passing(f, role.token, ['name', 'any-name'])).toEqual(['any-name']);
  });

  it("keeps the source identity's attributes out of role sessions when the trust says so", async () => {
    const f = await probeFixture();
    const user = await f.signIn('alice');
    const role = await roleSession(f, user);
    expect(await probe(f, user.token, 'department')).toBe(true);
    // Legacy trusts, without the field, pass attributes.
    await f.iam.store.transaction(async (tx) => {
      const legacy = { ...(await tx.get<StoredRecord>('trusts', f.trust.id))! };
      delete legacy.passSourceAttributes;
      await tx.put('trusts', legacy);
    });
    expect(await probe(f, role.token, 'department')).toBe(true);
    await patch(f, 'trusts', f.trust.id, { passSourceAttributes: false });
    expect(await probe(f, role.token, 'department')).toBe(false);
    // The person's own session is unaffected, and the role session keeps its other grants.
    expect(await probe(f, user.token, 'department')).toBe(true);
    expect(await probe(f, role.token, 'issued')).toBe(true);
    await patch(f, 'trusts', f.trust.id, { passSourceAttributes: true });
    expect(await probe(f, role.token, 'department')).toBe(true);
  });

  it("bounds a credential by its source's policy (sourcePolicy)", async () => {
    const f = await probeFixture();
    const key = await apiKey(f);
    expect(await probe(f, key.token, 'x', 'documents:write')).toBe(true);
    await patch(f, 'sessions', key.session.id, {
      sourcePolicy: {
        version: 1,
        statements: [allow(['documents:read'], ['*'])],
      } satisfies PolicyDocument,
    });
    expect(await probe(f, key.token, 'x', 'documents:write')).toBe(false);
    expect(await probe(f, key.token, 'issued')).toBe(true);
  });

  it("never makes a session token or role session the owner or a root admin, but keeps a token's agreements", async () => {
    const f = await probeFixture();
    const user = await f.signIn('alice');
    const token = await sessionToken(f, await storedSession(f, user.token));
    const role = await roleSession(f, user);
    // Alice's account now carries both flags (set after sign-in, as rootAdmin would demand MFA there; her tenant
    // is not the root, so she never gets a root override).
    await patch(f, 'identities', f.alice.id, { owner: true, rootAdmin: true });
    for (const credential of [user.token, token, role.token])
      await patch(f, 'sessions', (await storedSession(f, credential)).id, { mfa: true });
    expect((await f.iam.authenticate({ token })).session.kind).toBe('session-token');

    const flags = ['owner', 'root-admin'];
    expect(await passing(f, user.token, flags)).toEqual(flags);
    expect(await passing(f, token, flags)).toEqual([]);
    expect(await passing(f, role.token, flags)).toEqual([]);
    // The token keeps its identity grants otherwise.
    expect(await probe(f, token, 'issued')).toBe(true);
    expect(await probe(f, token, `sid-${(await storedSession(f, token)).id}`)).toBe(true);

    // A required agreement she has not accepted is owed by her own session and by her session token alike.
    expect(await passing(f, token, ['agreements-owed'])).toEqual([]);
    await f.iam.api.agreements.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Acceptable use',
      content: 'Be nice.',
    });
    expect(await passing(f, user.token, ['agreements-owed'])).toEqual(['agreements-owed']);
    expect(await passing(f, token, ['agreements-owed'])).toEqual(['agreements-owed']);
    // An assumed role describes the role, not the person, so nothing is owed there.
    expect(await passing(f, role.token, ['agreements-owed'])).toEqual([]);
  });
});
