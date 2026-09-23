import { createHash, randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, PolicyDocument, Session } from '@better-iam/core';
import type { BetterIamOptions } from '@better-iam/server';
import type { Role, Trust } from '../packages/server/src/models.js';
import { generateTestKey } from './support/jwt-keys.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * Revoking role sessions issued before a time (AWS "revoke older sessions"): `roles.revokeSessions` and
 * `trust.revokeSessions` move a monotonic `sessionsRevokedBefore` watermark forward and delete the matching rows,
 * `trust.revoke` deletes the trust's sessions, and `identities.revokeSessions({ keepApiKeys })` ends every other
 * credential of an identity while its API keys stay valid.
 */

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const readDocuments: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
};

/** A reader role in Acme and a same-tenant trust (no MFA) from the owner to it. */
async function ownerTrust(f: OrganizationFixture, name = 'Reader') {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name,
    document: readDocuments,
  });
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: f.ownerId,
    roleId: role.id,
    requireMfa: false,
  });
  return { role, trust };
}

async function assume(f: OrganizationFixture, trustId: string, extra: { format?: 'jwt' } = {}) {
  return f.iam.api.roles.assume(await f.ownerSignIn(), {
    tenantId: f.tenantId,
    trustId,
    ...extra,
  });
}

async function works(f: OrganizationFixture, token: string): Promise<boolean> {
  try {
    return (await f.iam.authenticate({ token })).session.kind === 'role';
  } catch {
    return false;
  }
}

async function row(f: OrganizationFixture, sessionId: string): Promise<Session | undefined> {
  return f.iam.store.get<Session>('sessions', sessionId);
}

async function auditOf(f: OrganizationFixture, action: string): Promise<AuditEvent[]> {
  return (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId })).filter(
    (event) => event.action === action,
  );
}

describe('roles.revokeSessions', () => {
  it('refuses and deletes sessions issued before the time while newer ones keep working', async () => {
    const f = await organizationFixture();
    const { role, trust } = await ownerTrust(f);
    const older = await assume(f, trust.id);
    f.advance(1000);
    const before = f.now();
    f.advance(1000);
    const newer = await assume(f, trust.id);
    const result = await f.iam.api.roles.revokeSessions(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      roleId: role.id,
      before,
    });
    expect(result).toEqual({ roleId: role.id, sessionsRevokedBefore: before, revoked: 1 });
    expect(await row(f, older.session.id)).toBeUndefined();
    await expect(f.iam.authenticate({ token: older.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    expect(await works(f, newer.token)).toBe(true);
    expect((await f.iam.store.get<Role>('roles', role.id))?.sessionsRevokedBefore).toBe(before);
  });

  it('revokes everything issued so far by default and never blocks later issuance', async () => {
    const f = await organizationFixture();
    const { role, trust } = await ownerTrust(f);
    const first = await assume(f, trust.id);
    const second = await assume(f, trust.id);
    const result = await f.iam.api.roles.revokeSessions(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      roleId: role.id,
    });
    expect(result).toEqual({ roleId: role.id, sessionsRevokedBefore: f.now() + 1, revoked: 2 });
    expect(await works(f, first.token)).toBe(false);
    expect(await works(f, second.token)).toBe(false);
    // The watermark is never in the future: one millisecond later, new sessions work.
    f.advance(1);
    expect(await works(f, (await assume(f, trust.id)).token)).toBe(true);
  });

  it('validates before and never moves the watermark back', async () => {
    const f = await organizationFixture();
    const { role } = await ownerTrust(f);
    const owner = await f.ownerSignIn();
    for (const before of [f.now() + 2, -1, 1.5, '1000', Number.MAX_SAFE_INTEGER + 1])
      await expect(
        f.iam.api.roles.revokeSessions(owner, {
          tenantId: f.tenantId,
          roleId: role.id,
          before: before as number,
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const high = f.now();
    await f.iam.api.roles.revokeSessions(owner, {
      tenantId: f.tenantId,
      roleId: role.id,
      before: high,
    });
    f.advance(1000);
    const lower = await f.iam.api.roles.revokeSessions(owner, {
      tenantId: f.tenantId,
      roleId: role.id,
      before: high - 5000,
    });
    expect(lower.sessionsRevokedBefore).toBe(high);
    // now + 1 is the latest allowed time.
    const latest = await f.iam.api.roles.revokeSessions(owner, {
      tenantId: f.tenantId,
      roleId: role.id,
      before: f.now() + 1,
    });
    expect(latest.sessionsRevokedBefore).toBe(f.now() + 1);
  });

  it('requires recent authentication and iam:roles:revoke-sessions', async () => {
    const f = await organizationFixture();
    const { role } = await ownerTrust(f);
    // A role session allowed to revoke sessions still never passes the recent-authentication check.
    const revoker = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Revoker',
      permissions: ['iam:roles:revoke-sessions'],
    });
    const revokerTrust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: revoker.id,
      requireMfa: false,
    });
    const assumed = await assume(f, revokerTrust.id);
    await expect(
      f.iam.api.roles.revokeSessions(
        { token: assumed.token },
        { tenantId: f.tenantId, roleId: role.id },
      ),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    const owner = await f.ownerSignIn();
    await f.member('alice');
    const alice = await f.signIn('alice');
    await expect(
      f.iam.api.roles.revokeSessions(
        { token: alice.token },
        { tenantId: f.tenantId, roleId: role.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.roles.revokeSessions(owner, { tenantId: f.tenantId, roleId: randomUUID() }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    f.advance(6 * 60_000);
    await expect(
      f.iam.api.roles.revokeSessions(owner, { tenantId: f.tenantId, roleId: role.id }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    expect((await f.iam.store.get<Role>('roles', role.id))?.sessionsRevokedBefore).toBeUndefined();
  });

  it("records 'role:sessions-revoked' alongside the operation", async () => {
    const f = await organizationFixture();
    const { role, trust } = await ownerTrust(f);
    await assume(f, trust.id);
    const result = await f.iam.api.roles.revokeSessions(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      roleId: role.id,
    });
    const [event] = await auditOf(f, 'role:sessions-revoked');
    expect(event).toMatchObject({
      tenantId: f.tenantId,
      actorId: f.ownerId,
      resourceId: role.id,
      outcome: 'allow',
      metadata: { sessionsRevokedBefore: result.sessionsRevokedBefore, revoked: 1 },
    });
    expect(await auditOf(f, 'iam:roles:revoke-sessions')).toHaveLength(1);
  });

  it('refuses a session seeded afterwards with an older creation time', async () => {
    const f = await organizationFixture();
    const { role, trust } = await ownerTrust(f);
    const { sessionsRevokedBefore } = await f.iam.api.roles.revokeSessions(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      roleId: role.id,
    });
    f.advance(1000);
    const assumed = await assume(f, trust.id);
    expect(await works(f, assumed.token)).toBe(true);
    // A row the eager deletion never saw (a concurrent issuance) still falls under the watermark.
    await f.iam.store.transaction(async (tx) => {
      const current = (await tx.get<Session>('sessions', assumed.session.id))!;
      await tx.put('sessions', { ...current, createdAt: sessionsRevokedBefore - 1 });
    });
    await expect(f.iam.authenticate({ token: assumed.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      message: 'Role credential revoked',
    });
  });

  it('keeps the watermark through roles.update and config.apply', async () => {
    const f = await organizationFixture();
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const owner = await f.ownerSignIn();
    const { sessionsRevokedBefore } = await f.iam.api.roles.revokeSessions(owner, {
      tenantId: f.tenantId,
      roleId: role.id,
    });
    await f.iam.api.roles.update(owner, {
      tenantId: f.tenantId,
      roleId: role.id,
      description: 'Reads documents',
    });
    expect(
      (await f.iam.api.roles.get(owner, { tenantId: f.tenantId, roleId: role.id }))
        .sessionsRevokedBefore,
    ).toBe(sessionsRevokedBefore);
    await f.iam.api.config.apply(owner, {
      tenantId: f.tenantId,
      config: {
        version: 1,
        roles: [{ name: 'Reader', permissions: ['documents:read', 'documents:write'] }],
      },
    });
    const synced = (await f.iam.store.get<Role>('roles', role.id))!;
    expect(JSON.stringify(synced.document)).toContain('documents:write');
    expect(synced.sessionsRevokedBefore).toBe(sessionsRevokedBefore);
  });

  it('ends a JWT-format role session inside IAM at once', async () => {
    const key = generateTestKey('EdDSA', 'revoke-key');
    const sts: BetterIamOptions['sts'] = { jwt: { signingKeys: [key.privateJwk as never] } };
    const f = await organizationFixture({ sts });
    const { role, trust } = await ownerTrust(f);
    const assumed = await assume(f, trust.id, { format: 'jwt' });
    expect(assumed.token.split('.')).toHaveLength(3);
    expect((await row(f, assumed.session.id))?.tokenHash).toBe(sha256(assumed.token));
    expect(await works(f, assumed.token)).toBe(true);
    const result = await f.iam.api.roles.revokeSessions(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      roleId: role.id,
    });
    expect(result.revoked).toBe(1);
    // The signature is still valid until exp, but IAM re-validates the stored row on every use.
    await expect(f.iam.authenticate({ token: assumed.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
  });
});

describe('trust.revokeSessions', () => {
  it("revokes one trust's sessions and leaves the role's other trusts alone", async () => {
    const f = await organizationFixture();
    const { role, trust } = await ownerTrust(f);
    const sibling = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: role.id,
      requireMfa: false,
    });
    const revokedSession = await assume(f, trust.id);
    const kept = await assume(f, sibling.id);
    const result = await f.iam.api.trust.revokeSessions(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect(result).toEqual({ trustId: trust.id, sessionsRevokedBefore: f.now() + 1, revoked: 1 });
    expect(await row(f, revokedSession.session.id)).toBeUndefined();
    expect(await works(f, revokedSession.token)).toBe(false);
    expect(await works(f, kept.token)).toBe(true);
    expect((await f.iam.store.get<Trust>('trusts', trust.id))?.sessionsRevokedBefore).toBe(
      f.now() + 1,
    );
    // The trust itself stays usable for new sessions.
    f.advance(1);
    expect(await works(f, (await assume(f, trust.id)).token)).toBe(true);
    const [event] = await auditOf(f, 'role:sessions-revoked');
    expect(event).toMatchObject({
      resourceId: trust.id,
      metadata: { sessionsRevokedBefore: result.sessionsRevokedBefore, revoked: 1 },
    });
  });

  it('validates input and requires recent authentication and the permission on the role', async () => {
    const f = await organizationFixture();
    const { trust } = await ownerTrust(f);
    const owner = await f.ownerSignIn();
    await expect(
      f.iam.api.trust.revokeSessions(owner, {
        tenantId: f.tenantId,
        trustId: trust.id,
        before: f.now() + 60_000,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.trust.revokeSessions(owner, { tenantId: f.tenantId, trustId: randomUUID() }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.iam.api.trust.revokeSessions(owner, { tenantId: f.root.tenant.id, trustId: trust.id }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await f.member('alice');
    const alice = await f.signIn('alice');
    await expect(
      f.iam.api.trust.revokeSessions(
        { token: alice.token },
        { tenantId: f.tenantId, trustId: trust.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    f.advance(6 * 60_000);
    await expect(
      f.iam.api.trust.revokeSessions(owner, { tenantId: f.tenantId, trustId: trust.id }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
  });

  it('lets a target-tenant administrator end sessions under a platform-controlled cross-tenant trust', async () => {
    const f = await organizationFixture();
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
      permissions: ['iam:roles:assume'],
    });
    await f.iam.api.bindings.create(f.rootCredential, {
      tenantId: platform,
      roleId: assumer.id,
      subjectType: 'identity',
      subjectId: ops.id,
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Support',
      document: readDocuments,
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
    expect(await works(f, assumed.token)).toBe(true);
    // The owner is not root: the trust itself stays out of reach, but its sessions can be ended.
    const owner = await f.ownerSignIn();
    await expect(
      f.iam.api.trust.revoke(owner, { tenantId: f.tenantId, trustId: trust.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const result = await f.iam.api.trust.revokeSessions(owner, {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect(result.revoked).toBe(1);
    expect(await works(f, assumed.token)).toBe(false);
    expect((await f.iam.store.get<Trust>('trusts', trust.id))?.revoked).toBe(false);
  });
});

describe('trust.revoke', () => {
  it("deletes the trust's live sessions", async () => {
    const f = await organizationFixture();
    const { role, trust } = await ownerTrust(f);
    const other = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: role.id,
      requireMfa: false,
    });
    const first = await assume(f, trust.id);
    const second = await assume(f, trust.id);
    const kept = await assume(f, other.id);
    const revoked = await f.iam.api.trust.revoke(f.rootCredential, {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect(revoked).toMatchObject({ id: trust.id, revoked: true, kind: 'identity' });
    expect(revoked).not.toHaveProperty('externalIdHash');
    expect(await row(f, first.session.id)).toBeUndefined();
    expect(await row(f, second.session.id)).toBeUndefined();
    expect(await works(f, kept.token)).toBe(true);
    await expect(assume(f, trust.id)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});

describe('identities.revokeSessions keepApiKeys', () => {
  /** A service account that may assume a reader role through a same-tenant trust, with two API keys. */
  async function serviceAccount(f: OrganizationFixture) {
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'deployer',
    });
    const own = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Deployer',
      permissions: ['iam:roles:assume', 'documents:write'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: own.id,
      subjectType: 'identity',
      subjectId: account.id,
    });
    const reader = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Reader',
      document: readDocuments,
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: account.id,
      roleId: reader.id,
      requireMfa: false,
    });
    const first = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
    });
    const second = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
    });
    const assumed = await f.iam.api.roles.assume(
      { token: first.token },
      { tenantId: f.tenantId, trustId: trust.id },
    );
    // A session token minted from the first key, seeded as GetSessionToken stores it.
    const now = f.now();
    const sessionToken: Session = {
      id: randomUUID(),
      tenantId: f.tenantId,
      identityId: account.id,
      originalIdentityId: account.id,
      sourceSessionId: first.credentialId,
      kind: 'session-token',
      tokenHash: sha256(`seeded-${randomUUID()}`),
      createdAt: now,
      lastSeenAt: now,
      authenticatedAt: now,
      expiresAt: now + 3_600_000,
      mfa: false,
    };
    sessionToken.uniqueKey = sessionToken.tokenHash;
    await f.iam.store.transaction((tx) => tx.insert('sessions', sessionToken));
    return { account, first, second, assumed, sessionToken };
  }

  it('ends every other credential while the API keys stay valid', async () => {
    const f = await organizationFixture();
    const { account, first, second, assumed, sessionToken } = await serviceAccount(f);
    const result = await f.iam.api.identities.revokeSessions(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: account.id,
      keepApiKeys: true,
    });
    // The role session and the session token.
    expect(result).toEqual({ revoked: 2 });
    for (const key of [first, second])
      expect((await f.iam.authenticate({ token: key.token })).session.kind).toBe('api-key');
    expect(await row(f, assumed.session.id)).toBeUndefined();
    expect(await row(f, sessionToken.id)).toBeUndefined();
    expect(await works(f, assumed.token)).toBe(false);
    const [event] = await auditOf(f, 'identity:revoke-sessions');
    expect(event?.metadata).toEqual({ revoked: 2, keptApiKeys: true });
    // A kept key can still assume the role afterwards.
    const again = await f.iam.api.roles.assume(
      { token: first.token },
      { tenantId: f.tenantId, trustId: assumed.session.trustId },
    );
    expect(await works(f, again.token)).toBe(true);
  });

  it('still deletes API keys by default', async () => {
    const f = await organizationFixture();
    const { account, first, second, assumed, sessionToken } = await serviceAccount(f);
    const result = await f.iam.api.identities.revokeSessions(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: account.id,
    });
    expect(result).toEqual({ revoked: 4 });
    for (const token of [first.token, second.token, assumed.token])
      await expect(f.iam.authenticate({ token })).rejects.toMatchObject({
        code: 'UNAUTHENTICATED',
      });
    expect(await row(f, sessionToken.id)).toBeUndefined();
    const [event] = await auditOf(f, 'identity:revoke-sessions');
    expect(event?.metadata).toEqual({ revoked: 4, keptApiKeys: false });
  });

  it("ends a person's sessions and the role sessions they assumed", async () => {
    const f = await organizationFixture();
    const { trust } = await ownerTrust(f);
    const aliceIdentity = await f.member('alice');
    const alice = await f.signIn('alice');
    const other = await f.signIn('alice');
    const roleSession = await assume(f, trust.id);
    const result = await f.iam.api.identities.revokeSessions(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: aliceIdentity.id,
      keepApiKeys: true,
    });
    expect(result).toEqual({ revoked: 2 });
    for (const token of [alice.token, other.token])
      await expect(f.iam.authenticate({ token })).rejects.toMatchObject({
        code: 'UNAUTHENTICATED',
      });
    // Someone else's role session is untouched.
    expect(await works(f, roleSession.token)).toBe(true);
    await expect(
      f.iam.api.identities.revokeSessions(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: aliceIdentity.id,
        keepApiKeys: 'yes' as never,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('removes the role sessions a person assumed, with keepApiKeys', async () => {
    const f = await organizationFixture();
    const { role } = await ownerTrust(f);
    const aliceIdentity = await f.member('alice');
    const assumer = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Assumer',
      permissions: ['iam:roles:assume'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: assumer.id,
      subjectType: 'identity',
      subjectId: aliceIdentity.id,
    });
    const aliceTrust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: aliceIdentity.id,
      roleId: role.id,
      requireMfa: false,
    });
    const alice = await f.signIn('alice');
    const aliceRole = await f.iam.api.roles.assume(
      { token: alice.token },
      { tenantId: f.tenantId, trustId: aliceTrust.id },
    );
    expect(await works(f, aliceRole.token)).toBe(true);
    expect((await row(f, aliceRole.session.id))?.identityId).toBe(aliceIdentity.id);
    // The owner's own role session under the same role must survive.
    const ownerRole = await assume(f, (await ownerTrust(f, 'Other reader')).trust.id);

    const result = await f.iam.api.identities.revokeSessions(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: aliceIdentity.id,
      keepApiKeys: true,
    });
    // Her user session and the role session she assumed.
    expect(result).toEqual({ revoked: 2 });
    expect(await row(f, aliceRole.session.id)).toBeUndefined();
    expect(await works(f, aliceRole.token)).toBe(false);
    await expect(f.iam.authenticate({ token: alice.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    expect(await works(f, ownerRole.token)).toBe(true);
    const [event] = await auditOf(f, 'identity:revoke-sessions');
    expect(event?.metadata).toEqual({ revoked: 2, keptApiKeys: true });
  });
});
