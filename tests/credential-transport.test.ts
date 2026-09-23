import { afterEach, describe, expect, it } from 'vitest';
import {
  isServerOwnedKey,
  optionalPrincipalServerKeys,
  principalServerKeys,
  reservedSessionPrincipalNames,
  sessionScopedPrincipalKeys,
  sessionTagName,
  sessionTagPrefix,
  tagKeyPattern,
} from '../packages/server/src/context-keys.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

describe('API key plumbing', () => {
  it('credentials.revoke deletes only API keys and leaves user sessions alone', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const session = await f.iam.api.auth.getSession(owner);
    await expect(
      f.iam.api.credentials.revoke(owner, { tenantId, credentialId: session.session.id }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIAL', message: 'Not an API key credential' });
    // The refused call deleted nothing: the session still authenticates.
    expect((await f.iam.api.auth.getSession(owner)).session.id).toBe(session.session.id);
    expect(await f.iam.store.get('sessions', session.session.id)).toBeTruthy();
    // A member's session is refused the same way.
    await f.member('alice');
    const alice = await f.signIn('alice');
    const aliceSession = await f.iam.api.auth.getSession({ token: alice.token });
    await expect(
      f.iam.api.credentials.revoke(owner, { tenantId, credentialId: aliceSession.session.id }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIAL' });
    expect((await f.iam.api.auth.getSession({ token: alice.token })).identity.id).toBe(
      aliceSession.identity.id,
    );
    // A role session is refused the same way, and its token keeps working.
    const role = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId,
      sourceTenantId: tenantId,
      sourceIdentityId: f.ownerId,
      roleId: role.id,
      requireMfa: false,
    });
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId,
      trustId: trust.id,
    });
    expect(assumed.session.kind).toBe('role');
    await expect(
      f.iam.api.credentials.revoke(owner, { tenantId, credentialId: assumed.session.id }),
    ).rejects.toMatchObject({
      code: 'INVALID_CREDENTIAL',
      status: 400,
      message: 'Not an API key credential',
    });
    expect(await f.iam.store.get('sessions', assumed.session.id)).toBeTruthy();
    expect((await f.iam.authenticate({ token: assumed.token })).session.id).toBe(
      assumed.session.id,
    );
    // API keys still revoke, and stop working at once.
    const account = await f.iam.api.serviceAccounts.create(owner, { tenantId, name: 'ci' });
    const key = await f.iam.api.credentials.create(owner, { tenantId, identityId: account.id });
    expect((await f.iam.authenticate({ token: key.token })).identity.id).toBe(account.id);
    expect(
      await f.iam.api.credentials.revoke(owner, { tenantId, credentialId: key.credentialId }),
    ).toEqual({ revoked: true });
    await expect(f.iam.authenticate({ token: key.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    // Unknown and foreign ids stay NOT_FOUND.
    await expect(
      f.iam.api.credentials.revoke(owner, { tenantId, credentialId: 'missing' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('stamps key creation, expiry and rotation with the injected clock', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId,
      name: 'ci',
    });
    f.advance(5 * day);
    const owner = await f.ownerSignIn();
    const issued = await f.iam.api.credentials.create(owner, {
      tenantId,
      identityId: account.id,
      name: 'deploy',
    });
    expect(issued.expiresAt).toBe(f.now() + 90 * day);
    const summary = await f.iam.api.credentials.get(owner, {
      tenantId,
      credentialId: issued.credentialId,
    });
    expect(summary).toMatchObject({ createdAt: f.now(), expiresAt: f.now() + 90 * day });
    expect(summary.lastUsedAt).toBeUndefined();
    const row = (await f.iam.store.get('sessions', issued.credentialId))!;
    expect(row).toMatchObject({
      createdAt: f.now(),
      lastSeenAt: f.now(),
      authenticatedAt: f.now(),
      expiresAt: f.now() + 90 * day,
    });
    // An explicit lifetime counts from the injected clock too.
    const short = await f.iam.api.credentials.create(owner, {
      tenantId,
      identityId: account.id,
      expiresInSeconds: 3600,
    });
    expect(short.expiresAt).toBe(f.now() + 3_600_000);
    // The key works right up to its expiry on the fixture clock (a wall-clock stamp would end it days early).
    const use = () =>
      f.iam.authorize({
        token: issued.token,
        tenantId,
        action: 'documents:read',
        resource: { type: 'documents', id: 'a' },
      });
    const created = f.now();
    f.advance(89 * day);
    await use();
    // Rotation stamps the replacement with the current clock and keeps the expiry.
    const admin = await f.ownerSignIn();
    const rotated = await f.iam.api.credentials.rotate(admin, {
      tenantId,
      credentialId: issued.credentialId,
    });
    expect(rotated.expiresAt).toBe(created + 90 * day);
    const replacement = await f.iam.api.credentials.get(admin, {
      tenantId,
      credentialId: rotated.credentialId,
    });
    expect(replacement).toMatchObject({ createdAt: f.now(), expiresAt: created + 90 * day });
    expect(replacement.lastUsedAt).toBeUndefined();
    // authenticatedAt (principal.authTime) restarts too, so it never trails createdAt.
    expect(await f.iam.store.get('sessions', rotated.credentialId)).toMatchObject({
      createdAt: f.now(),
      lastSeenAt: f.now(),
      authenticatedAt: f.now(),
    });
    f.advance(day);
    await expect(
      f.iam.authorize({
        token: rotated.token,
        tenantId,
        action: 'documents:read',
        resource: { type: 'documents', id: 'a' },
      }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });
});

describe('context-key registry', () => {
  it('knows which keys only the server may set', () => {
    expect(isServerOwnedKey('principal.sessionTags.team')).toBe(true);
    expect(isServerOwnedKey('request.sourceIp')).toBe(true);
    expect(isServerOwnedKey('principal.authMethod')).toBe(true);
    expect(isServerOwnedKey('principal.sessionId')).toBe(true);
    expect(isServerOwnedKey('request.time')).toBe(true);
    expect(isServerOwnedKey('principal.department')).toBe(false);
    expect(isServerOwnedKey('request.ip')).toBe(false);
    expect(isServerOwnedKey('resource.tenantId')).toBe(false);
  });

  it('validates session tag names', () => {
    expect(sessionTagName('team')).toBe('principal.sessionTags.team');
    expect(sessionTagName('Cost_Center2')).toBe('principal.sessionTags.Cost_Center2');
    expect(sessionTagName('bad-name')).toBeUndefined();
    expect(sessionTagName('9lives')).toBeUndefined();
    expect(sessionTagName('')).toBeUndefined();
    expect(sessionTagName('a'.repeat(64))).toBeDefined();
    expect(sessionTagName('a'.repeat(65))).toBeUndefined();
    expect(sessionTagPrefix).toBe('principal.sessionTags.');
    expect(tagKeyPattern.test('team')).toBe(true);
  });

  it('types every derived key and marks the optional ones', () => {
    expect(principalServerKeys.get('principal.tokenIssueTime')).toBe('timestamp');
    expect(principalServerKeys.get('principal.authTime')).toBe('timestamp');
    expect(principalServerKeys.get('principal.mfaTime')).toBe('timestamp');
    expect(principalServerKeys.get('principal.sessionTagKeys')).toBe('list');
    expect(principalServerKeys.get('principal.webIdentitySubject')).toBe('string');
    expect(principalServerKeys.get('principal.pendingAgreements')).toBe('number');
    expect(principalServerKeys.get('principal.sessionKind')).toBe('identifier');
    for (const key of optionalPrincipalServerKeys) expect(principalServerKeys.has(key)).toBe(true);
    expect(optionalPrincipalServerKeys.has('principal.sessionId')).toBe(false);
    expect(optionalPrincipalServerKeys.has('request.sourceIp')).toBe(true);
    // Resource keys are not principal or request keys.
    expect([...principalServerKeys.keys()].every((key) => /^(principal|request)\./.test(key))).toBe(
      true,
    );
    expect(reservedSessionPrincipalNames).toContain('sessionTags');
    expect(sessionScopedPrincipalKeys).toHaveLength(reservedSessionPrincipalNames.length - 1);
    expect(sessionScopedPrincipalKeys).not.toContain('principal.sessionTags');
    for (const key of sessionScopedPrincipalKeys) expect(principalServerKeys.has(key)).toBe(true);
  });
});
