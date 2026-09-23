import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import type { IamStore, StoredRecord } from '@better-iam/core';
import type { AuthService, NetworkBlock } from '@better-iam/auth';
import type { BetterIamOptions } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);

afterEach(closeFixtures);

/** The deployment reads the client address from `x-real-ip`, as behind a trusted proxy. */
const proxied: Partial<BetterIamOptions> = {
  http: {
    clientInfo: (request) => {
      const ip = request.headers.get('x-real-ip');
      return ip ? { ip } : {};
    },
  },
};

async function fixture(overrides: Partial<BetterIamOptions> = {}) {
  const f = await organizationFixture({ ...proxied, ...overrides });
  const from = <T>(ip: string, fn: () => Promise<T>) =>
    f.iam.auth.withClient({ ip, userAgent: 'test' }, fn);
  return { ...f, from, api: f.iam.api };
}

describe('API keys and assumed roles honour network controls', () => {
  it('refuses an API key presented from a blocked network, directly or through request headers', async () => {
    const f = await fixture();
    const account = await f.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci-bot',
    });
    const key = await f.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
    });
    await f.api.security.blockNetwork(f.ownerCredential, {
      tenantId: f.tenantId,
      network: '198.51.100.0/24',
      reason: 'leaked key in use',
    });
    await expect(
      f.from('198.51.100.7', () => f.iam.authenticate({ token: key.token })),
    ).rejects.toMatchObject({ code: 'IP_BLOCKED', status: 403 });
    await expect(
      f.from('198.51.100.7', () =>
        f.api.serviceAccounts.list({ token: key.token }, { tenantId: f.tenantId }),
      ),
    ).rejects.toMatchObject({ code: 'IP_BLOCKED' });
    // Framework integrations pass the request's headers; the address comes from http.clientInfo.
    await expect(
      f.iam.authenticate({
        headers: { authorization: `Bearer ${key.token}`, 'x-real-ip': '198.51.100.7' },
      }),
    ).rejects.toMatchObject({ code: 'IP_BLOCKED' });
    // Elsewhere, and without a known address, the key works.
    const elsewhere = await f.from('203.0.113.5', () => f.iam.authenticate({ token: key.token }));
    expect(elsewhere.identity.id).toBe(account.id);
    expect((await f.iam.authenticate({ token: key.token })).session.kind).toBe('api-key');
  });

  it("ends a role session with its source session's network and honours the target's blocks and allowlist", async () => {
    const f = await fixture();
    const platform = f.root.tenant.id;
    const ops = await f.api.identities.create(f.rootCredential, {
      tenantId: platform,
      email: 'ops@example.test',
      name: 'Ops',
      password: 'a strong operator test password',
    });
    const assumers = await f.api.roles.create(f.rootCredential, {
      tenantId: platform,
      name: 'Assumers',
      permissions: ['iam:roles:assume'],
    });
    await f.api.bindings.create(f.rootCredential, {
      tenantId: platform,
      roleId: assumers.id,
      subjectType: 'identity',
      subjectId: ops.id,
    });
    const reader = await f.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const trust = await f.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: platform,
      sourceIdentityId: ops.id,
      roleId: reader.id,
      requireMfa: false,
    });
    const login = await f.from('198.51.100.7', () =>
      f.api.auth.signIn({
        tenantId: platform,
        email: 'ops@example.test',
        password: 'a strong operator test password',
      }),
    );
    if (!('token' in login)) throw new Error('Unexpected MFA');
    const role = await f.api.roles.assume(
      { token: login.token },
      { tenantId: f.tenantId, trustId: trust.id, durationSeconds: 3600 },
    );
    const read = (ip: string) =>
      f.from(ip, () =>
        f.iam.authorize({
          token: role.token,
          tenantId: f.tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'a' },
        }),
      );
    expect((await read('203.0.113.5')).allowed).toBe(true);

    // Root blocks the network the operator signed in from: the source session and the role end together.
    const block = await f.api.security.blockNetwork(f.rootCredential, {
      tenantId: platform,
      network: '198.51.100.0/24',
      reason: 'compromised office',
    });
    await expect(f.api.auth.getSession({ token: login.token })).rejects.toMatchObject({
      code: 'IP_BLOCKED',
    });
    await expect(read('203.0.113.5')).rejects.toMatchObject({ code: 'IP_BLOCKED' });
    await f.api.security.unblockNetwork(f.rootCredential, {
      tenantId: platform,
      blockId: block.id,
    });
    expect((await read('203.0.113.5')).allowed).toBe(true);

    // The organization the role acts in blocks the presenting network.
    await f.api.security.blockNetwork(f.ownerCredential, {
      tenantId: f.tenantId,
      network: '192.0.2.0/24',
      reason: 'scanner',
    });
    await expect(read('192.0.2.1')).rejects.toMatchObject({ code: 'IP_BLOCKED' });
    expect((await read('203.0.113.5')).allowed).toBe(true);

    // ... and allows only its office network.
    await f.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowedIpRanges: ['203.0.113.0/24'] },
    });
    await expect(read('198.51.100.8')).rejects.toMatchObject({ code: 'IP_NOT_ALLOWED' });
    expect((await read('203.0.113.5')).allowed).toBe(true);
  });
});

describe('session binding for framework integrations', () => {
  it('judges a bound session presented through request headers by the address in them', async () => {
    const f = await fixture();
    await f.member('alice');
    const alice = await f.from('203.0.113.7', () => f.signIn('alice'));
    await f.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { bindSessionsToIp: true },
    });
    const headers = (ip: string) => ({
      authorization: `Bearer ${alice.token}`,
      'x-real-ip': ip,
    });
    // What Next's route(), Nuxt, and the NestJS guard do: authenticate the incoming headers.
    await expect(f.iam.authenticate({ headers: headers('198.51.100.9') })).rejects.toMatchObject({
      code: 'SESSION_NETWORK_MISMATCH',
    });
    await expect(
      f.api.identities.list({ headers: headers('198.51.100.9') }, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'SESSION_NETWORK_MISMATCH' });
    expect((await f.iam.authenticate({ headers: headers('203.0.113.7') })).session.id).toBe(
      alice.session.id,
    );
    // An explicit client scope still wins over the headers.
    expect(
      (await f.from('203.0.113.7', () => f.iam.authenticate({ headers: headers('198.51.100.9') })))
        .session.id,
    ).toBe(alice.session.id);
  });
});

describe('self-lockout guards', () => {
  it("refuses a block covering the caller's current address as well as the recorded one", async () => {
    const f = await fixture();
    const owner = await f.from('10.0.0.5', () => f.ownerSignIn());
    await expect(
      f.from('198.51.100.7', () =>
        f.api.security.blockNetwork(owner, {
          tenantId: f.tenantId,
          network: '198.51.100.0/24',
          reason: 'would lock me out of lifting it',
        }),
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT', message: expect.stringContaining('own') });
    await expect(
      f.api.security.blockNetwork(owner, {
        tenantId: f.tenantId,
        network: '10.0.0.0/8',
        reason: 'would end my session',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(
      await f.from('10.0.0.5', () =>
        f.api.security.blockNetwork(owner, {
          tenantId: f.tenantId,
          network: '198.51.100.0/24',
          reason: 'attackers',
        }),
      ),
    ).toMatchObject({ network: '198.51.100.0/24', active: true });
  });

  it("refuses an allowlist that leaves out the caller's own address", async () => {
    const f = await fixture();
    const owner = await f.from('198.51.100.7', () => f.ownerSignIn());
    const allow = (
      credential: { token: string },
      allowedIpRanges: string[],
      tenantId = f.tenantId,
    ) => f.api.tenants.setAuthPolicy(credential, { tenantId, authPolicy: { allowedIpRanges } });
    // The session's recorded address would be refused at its next use.
    await expect(allow(owner, ['10.0.0.0/8'])).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringContaining('own address'),
    });
    // The current address would be refused at the next sign-in.
    await expect(
      f.from('203.0.113.9', () => allow(owner, ['198.51.100.0/24'])),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.from('203.0.113.9', () => allow(owner, ['198.51.100.0/24', '203.0.113.0/24']));
    expect((await f.from('203.0.113.9', () => f.api.auth.getSession(owner))).identity.id).toBe(
      f.ownerId,
    );
    // The root tenant has no parent to undo a typo.
    await expect(
      f.from('192.0.2.1', () => allow(f.rootCredential, ['10.0.0.0/32'], f.root.tenant.id)),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Root's own address is not judged by an organization's allowlist.
    await f.from('192.0.2.1', () => allow(f.rootCredential, ['203.0.113.0/24']));
  });
});

describe('network block cache', () => {
  it('is cleared once a block change has committed, not only inside its transaction', async () => {
    // Stands in for a concurrent request on another connection that reads the committed (pre-change) list
    // between the in-transaction invalidation and the commit, and caches it.
    const racing: { auth?: AuthService; rows: NetworkBlock[] } = { rows: [] };
    const stale = { find: async () => racing.rows } as unknown as IamStore;
    const f = await fixture({
      plugins: [
        {
          id: 'racing-reader',
          hooks: {
            afterOperation: async ({ action, tenantId }) => {
              if (action === 'iam:security:manage')
                await racing.auth?.blockedNetwork(stale, tenantId, '192.0.2.9');
            },
          },
        },
      ],
    });
    racing.auth = f.iam.auth;
    await f.member('alice');
    const block = await f.api.security.blockNetwork(f.ownerCredential, {
      tenantId: f.tenantId,
      network: '192.0.2.0/24',
      reason: 'scanner',
    });
    await expect(f.from('192.0.2.9', () => f.signIn('alice'))).rejects.toMatchObject({
      code: 'IP_BLOCKED',
    });
    racing.rows = [block];
    await f.api.security.unblockNetwork(f.ownerCredential, {
      tenantId: f.tenantId,
      blockId: block.id,
    });
    expect('token' in (await f.from('192.0.2.9', () => f.signIn('alice')))).toBe(true);
  });
});

describe('tenant-wide session revocation', () => {
  it('also forgets remembered devices, so MFA is required again', async () => {
    const f = await fixture();
    await f.member('alice');
    const totp = (secret: string) => {
      const generator = authenticator.clone();
      generator.options = { epoch: f.now() };
      return generator.generate(secret);
    };
    const first = await f.signIn('alice');
    const enrollment = await f.api.auth.beginMfa({ token: first.token });
    await f.api.auth.confirmMfa({
      credential: { token: first.token },
      code: totp(enrollment.secret),
    });
    const password = () =>
      f.api.auth.signIn({
        tenantId: f.tenantId,
        email: 'alice@acme.test',
        password: 'a strong alice password',
      });
    const challenge = await password();
    if (!('mfaRequired' in challenge)) throw new Error('MFA expected');
    f.advance(30_000);
    const remembered = await f.api.auth.verifyMfa({
      tenantId: f.tenantId,
      challenge: challenge.challenge,
      code: totp(enrollment.secret),
      rememberDevice: true,
    });
    const withDevice = () =>
      f.api.auth.signIn({
        tenantId: f.tenantId,
        email: 'alice@acme.test',
        password: 'a strong alice password',
        deviceToken: remembered.deviceToken!,
      });
    expect('token' in (await withDevice())).toBe(true);

    await f.api.tenants.revokeSessions(f.ownerCredential, { tenantId: f.tenantId });
    expect('mfaRequired' in (await withDevice())).toBe(true);
    expect(await f.database.find('authDevices', { tenantId: f.tenantId })).toHaveLength(0);
    // The caller keeps their own session.
    expect((await f.api.auth.getSession(f.ownerCredential)).identity.id).toBe(f.ownerId);
  });
});

describe('retention worker', () => {
  it('deletes expired rate-limit counters, challenges, and lapsed blocks in every tenant', async () => {
    const f = await fixture();
    // Anonymous failures leave counters, including for tenants that do not exist.
    for (let attempt = 0; attempt < 3; attempt++)
      await expect(
        f.api.auth.signIn({
          tenantId: f.tenantId,
          email: `nobody-${attempt}@acme.test`,
          password: 'wrong password entirely',
        }),
      ).rejects.toBeDefined();
    await expect(
      f.api.auth.signIn({ tenantId: 'ghost-tenant', email: 'x@y.test', password: 'whatever pw 1' }),
    ).rejects.toMatchObject({ code: 'TENANT_UNAVAILABLE' });
    const challenge = (idSuffix: string) => ({
      id: `ch_${idSuffix}`,
      tenantId: f.tenantId,
      identityId: '',
      purpose: 'passkey-authenticate',
      tokenHash: `hash-${idSuffix}`,
      payload: { discovery: '1' },
      expiresAt: f.now() + 5 * 60_000,
    });
    await f.database.transaction(async (tx) => {
      await tx.insert('authChallenges', challenge('stale'));
    });
    const lapsing = await f.api.security.blockNetwork(f.ownerCredential, {
      tenantId: f.tenantId,
      network: '192.0.2.0/24',
      reason: 'one minute',
      durationMs: 60_000,
    });
    const lasting = await f.api.security.blockNetwork(f.ownerCredential, {
      tenantId: f.tenantId,
      network: '198.51.100.0/24',
      reason: 'a year',
      durationMs: 365 * 86_400_000,
    });
    const permanent = await f.api.security.blockNetwork(f.ownerCredential, {
      tenantId: f.tenantId,
      network: '203.0.113.0/24',
      reason: 'until lifted',
    });
    const counters = await f.database.find<StoredRecord>('authRateLimits');
    expect(counters.some((row) => row.tenantId === 'ghost-tenant')).toBe(true);

    f.advance(86_400_000);
    // Fresh rows written after the clock moved stay.
    await f.database.transaction(async (tx) => {
      await tx.insert('authChallenges', challenge('fresh'));
      await tx.insert('authRateLimits', {
        id: 'fresh-counter',
        tenantId: 'ghost-tenant',
        count: 1,
        resetAt: f.now() + 15 * 60_000,
      });
    });
    await f.iam.purgeDeleted();
    expect((await f.database.find<StoredRecord>('authRateLimits')).map((row) => row.id)).toEqual([
      'fresh-counter',
    ]);
    expect((await f.database.find<StoredRecord>('authChallenges')).map((row) => row.id)).toEqual([
      'ch_fresh',
    ]);
    const blocks = (await f.database.find<StoredRecord>('authBlocks')).map((row) => row.id);
    expect(blocks).not.toContain(lapsing.id);
    expect(blocks.sort()).toEqual([lasting.id, permanent.id].sort());
  });
});
