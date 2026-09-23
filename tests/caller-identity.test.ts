import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, Session, StoredRecord } from '@better-iam/core';
import type { CallerIdentity, BetterIamOptions } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';
import { generateTestKey } from './support/jwt-keys.js';

afterEach(closeFixtures);

/**
 * GetCallerIdentity (`sts.getCallerIdentity`): an allowlist projection of the verified principal for every session
 * kind, re-validated like any other use, with no permission and no audit event.
 */
const ORIGIN = 'http://localhost:3000';
const ISSUER = `${ORIGIN}/api/iam`;
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const projectionKeys = new Set([
  'identityId',
  'identityTenantId',
  'identityKind',
  'tenantId',
  'sessionId',
  'sessionKind',
  'format',
  'mfa',
  'authenticatedAt',
  'issuedAt',
  'expiresAt',
  'method',
  'roleId',
  'trustId',
  'sourceTenantId',
  'sessionName',
  'sourceIdentity',
  'sessionTags',
  'audience',
  'webIdentity',
  'impersonatorId',
]);
const forbidden = [
  'tokenHash',
  'uniqueKey',
  'policy',
  'sourcePolicy',
  'credentialAuthorityId',
  'sourceAuthorityIds',
  'sourceSessionId',
  'originalIdentityId',
  'client',
];

async function rowOf(f: OrganizationFixture, token: string): Promise<Session> {
  const [row] = await f.iam.store.find<Session>('sessions', { tokenHash: sha256(token) });
  if (!row) throw new Error('No session for this token');
  return row;
}

/** Calls getCallerIdentity and checks the result is exactly the allowlist projection, with no secret material. */
async function caller(f: OrganizationFixture, token: string): Promise<CallerIdentity> {
  const result = await f.iam.api.sts.getCallerIdentity({ token });
  for (const key of Object.keys(result)) expect(projectionKeys.has(key)).toBe(true);
  const serialized = JSON.stringify(result);
  for (const field of forbidden) expect(serialized).not.toContain(`"${field}"`);
  expect(serialized).not.toContain(sha256(token));
  expect(serialized).not.toContain(token);
  return result;
}

async function grant(f: OrganizationFixture, subjectId: string, permissions: string[]) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Grant for ${subjectId}`,
    permissions,
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId,
  });
}

/** A scoped API key of a service account allowed to mint session tokens. */
async function scopedKey(f: OrganizationFixture) {
  const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'caller-bot',
  });
  await grant(f, account.id, ['iam:session-tokens:create', 'documents:read']);
  const key = await f.iam.api.credentials.create(await f.ownerSignIn(), {
    tenantId: f.tenantId,
    identityId: account.id,
    scopes: ['iam:session-tokens:create', 'documents:read'],
  });
  return { account, token: key.token, credentialId: key.credentialId };
}

/** A same-tenant trust from the owner that admits a `team` tag and an optional source identity. */
async function openTrust(f: OrganizationFixture) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Deployer',
    permissions: ['documents:read'],
  });
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: f.ownerId,
    roleId: role.id,
    requireMfa: false,
  });
  await f.iam.store.transaction(async (tx) => {
    const record = await tx.get<StoredRecord>('trusts', trust.id);
    await tx.put('trusts', {
      ...record!,
      allowedTagKeys: ['team'],
      sourceIdentityMode: 'optional',
    });
  });
  return { role, trust };
}

function jwtOptions(): Partial<BetterIamOptions> {
  return { sts: { jwt: { signingKeys: [generateTestKey('EdDSA', 'k1').privateJwk as never] } } };
}

describe('sts.getCallerIdentity', () => {
  it('describes user, impersonation and API-key credentials', async () => {
    const f = await organizationFixture();
    const row = await rowOf(f, f.ownerCredential.token);
    expect(await caller(f, f.ownerCredential.token)).toEqual({
      identityId: f.ownerId,
      identityTenantId: f.tenantId,
      identityKind: 'user',
      tenantId: f.tenantId,
      sessionId: row.id,
      sessionKind: 'user',
      format: 'opaque',
      mfa: row.mfa,
      authenticatedAt: row.authenticatedAt,
      issuedAt: row.createdAt,
      expiresAt: row.expiresAt,
      ...(row.method ? { method: row.method } : {}),
    });

    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const alice = await f.member('alice');
    const viewAs = await f.iam.api.identities.impersonate(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: alice.id,
      reason: 'ticket 9',
    });
    expect(await caller(f, viewAs.token)).toMatchObject({
      identityId: alice.id,
      identityKind: 'user',
      sessionKind: 'user',
      impersonatorId: f.ownerId,
    });

    const key = await scopedKey(f);
    const keyRow = await rowOf(f, key.token);
    expect(await caller(f, key.token)).toEqual({
      identityId: key.account.id,
      identityTenantId: f.tenantId,
      identityKind: 'service',
      tenantId: f.tenantId,
      sessionId: keyRow.id,
      sessionKind: 'api-key',
      format: 'opaque',
      mfa: false,
      authenticatedAt: keyRow.authenticatedAt,
      issuedAt: keyRow.createdAt,
      expiresAt: keyRow.expiresAt,
    });
  });

  it('describes role sessions, session tokens and session JWTs', async () => {
    const f = await organizationFixture(jwtOptions());
    const { role, trust } = await openTrust(f);
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
      sessionName: 'deploy-42',
      sourceIdentity: 'alice@corp',
      tags: { team: 'blue' },
      policy: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    const roleRow = await rowOf(f, assumed.token);
    expect(await caller(f, assumed.token)).toEqual({
      identityId: f.ownerId,
      identityTenantId: f.tenantId,
      identityKind: 'user',
      tenantId: f.tenantId,
      sessionId: roleRow.id,
      sessionKind: 'role',
      format: 'opaque',
      mfa: roleRow.mfa,
      authenticatedAt: roleRow.authenticatedAt,
      issuedAt: roleRow.createdAt,
      expiresAt: roleRow.expiresAt,
      roleId: role.id,
      trustId: trust.id,
      sourceTenantId: f.tenantId,
      sessionName: 'deploy-42',
      sourceIdentity: 'alice@corp',
      sessionTags: { team: 'blue' },
    });

    const key = await scopedKey(f);
    const token = await f.iam.api.sts.getSessionToken(
      { token: key.token },
      { sessionName: 'nightly-sync' },
    );
    expect(await caller(f, token.token)).toMatchObject({
      identityId: key.account.id,
      identityKind: 'service',
      sessionId: token.session.id,
      sessionKind: 'session-token',
      format: 'opaque',
      sessionName: 'nightly-sync',
      mfa: false,
    });

    const jwtRole = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
      format: 'jwt',
    });
    expect(jwtRole.token.split('.')).toHaveLength(3);
    expect(await caller(f, jwtRole.token)).toMatchObject({
      sessionId: jwtRole.session.id,
      sessionKind: 'role',
      format: 'jwt',
      audience: [ISSUER],
      roleId: role.id,
      trustId: trust.id,
    });
    // A bearer header works the same way.
    expect(
      (
        await f.iam.api.sts.getCallerIdentity({
          headers: { authorization: `Bearer ${jwtRole.token}` },
        })
      ).sessionId,
    ).toBe(jwtRole.session.id);
    const jwtToken = await f.iam.api.sts.getSessionToken(f.ownerCredential, { format: 'jwt' });
    expect(await caller(f, jwtToken.token)).toMatchObject({
      sessionKind: 'session-token',
      format: 'jwt',
      audience: [ISSUER],
    });
  });

  it('refuses revoked credentials, and auth.getSession stays user-only', async () => {
    const f = await organizationFixture();
    const person = await f.ownerSignIn();
    const fromPerson = await f.iam.api.sts.getSessionToken(person);
    expect((await caller(f, fromPerson.token)).sessionKind).toBe('session-token');
    await f.iam.api.auth.signOut(person);
    for (const token of [person.token, fromPerson.token])
      await expect(f.iam.api.sts.getCallerIdentity({ token })).rejects.toMatchObject({
        code: 'UNAUTHENTICATED',
        status: 401,
      });

    const { trust } = await openTrust(f);
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
    });
    expect((await caller(f, assumed.token)).sessionKind).toBe('role');
    await f.iam.api.trust.revoke(f.rootCredential, { tenantId: f.tenantId, trustId: trust.id });
    await expect(f.iam.api.sts.getCallerIdentity({ token: assumed.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });

    const key = await scopedKey(f);
    expect((await caller(f, key.token)).sessionKind).toBe('api-key');
    await expect(f.iam.api.auth.getSession({ token: key.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await f.iam.api.credentials.revoke(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      credentialId: key.credentialId,
    });
    await expect(f.iam.api.sts.getCallerIdentity({ token: key.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
  });

  it('needs no permission, writes no audit event, and answers over HTTP', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const login = await f.signIn('alice');
    const before = (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId })).length;
    const result = await caller(f, login.token);
    expect(result).toMatchObject({ identityId: alice.id, sessionKind: 'user' });
    expect((await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId })).length).toBe(
      before,
    );
    const response = await f.iam.handler(
      new Request(`${ORIGIN}/api/iam/sts/getCallerIdentity`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${login.token}`,
        },
        body: '{}',
      }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(((await response.json()) as { data: CallerIdentity }).data).toEqual(result);
  });
});
