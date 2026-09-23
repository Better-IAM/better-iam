import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { PolicyDocument, Session } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * Pins the boundary model that docs/security.md and docs/temporary-credentials.md describe: a session token keeps its
 * source's policy (API-key scopes, as `sourcePolicy`) and credential authority as boundaries, while a role session does
 * not inherit them. A role session acts with the role's permissions, bounded by the trust ceiling and its own session
 * policy; the source's scopes and policy bound only the live `iam:roles:assume` decision.
 */
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
let names = 0;

function allow(actions: string[]): PolicyDocument {
  return { version: 1, statements: [{ effect: 'allow', actions, resources: ['*'] }] };
}

async function rowOf(f: OrganizationFixture, token: string): Promise<Session> {
  const [row] = await f.iam.store.find<Session>('sessions', { tokenHash: sha256(token) });
  if (!row) throw new Error('No session for this token');
  return row;
}

async function allowed(f: OrganizationFixture, token: string, action: string) {
  return (
    await f.iam.authorize({
      token,
      tenantId: f.tenantId,
      action,
      resource: { type: 'document', id: 'boundary-document' },
    })
  ).allowed;
}

/**
 * A read-write role, a service account allowed to assume it and mint session tokens, an API key scoped to exactly
 * those two actions, and a same-tenant trust (no MFA) from the account to the role.
 */
async function setup(options: { ceiling?: PolicyDocument; scopes?: string[] } = {}) {
  const f = await organizationFixture();
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Writer ${++names}`,
    permissions: ['documents:read', 'documents:write'],
  });
  const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `svc-${++names}`,
  });
  const grant = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Assumer ${++names}`,
    permissions: ['iam:roles:assume', 'iam:session-tokens:create'],
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: grant.id,
    subjectType: 'identity',
    subjectId: account.id,
  });
  const key = await f.iam.api.credentials.create(await f.ownerSignIn(), {
    tenantId: f.tenantId,
    identityId: account.id,
    scopes: options.scopes ?? ['iam:roles:assume', 'iam:session-tokens:create'],
  });
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: account.id,
    roleId: role.id,
    requireMfa: false,
    ...(options.ceiling ? { ceiling: options.ceiling } : {}),
  });
  const assume = (token: string, policy?: PolicyDocument) =>
    f.iam.api.roles.assume({ token }, { tenantId: f.tenantId, trustId: trust.id, policy });
  return { f, key: key.token, assume };
}

describe('role session boundaries', () => {
  it('does not carry the source API key scopes into the role session', async () => {
    const { f, key, assume } = await setup();
    // The key itself is limited to its scopes.
    expect(await allowed(f, key, 'documents:write')).toBe(false);
    const role = await assume(key);
    // The role session acts with the role's permissions, beyond the key's scopes.
    expect(await allowed(f, role.token, 'documents:read')).toBe(true);
    expect(await allowed(f, role.token, 'documents:write')).toBe(true);
    const row = await rowOf(f, role.token);
    expect(row).not.toHaveProperty('sourcePolicy');
    expect(row).not.toHaveProperty('policy');
    expect(row).not.toHaveProperty('credentialAuthorityId');
  });

  it('bounds a role session by its own session policy and the trust ceiling', async () => {
    const { f, key, assume } = await setup({ ceiling: allow(['documents:read']) });
    const ceiled = await assume(key);
    expect(await allowed(f, ceiled.token, 'documents:read')).toBe(true);
    expect(await allowed(f, ceiled.token, 'documents:write')).toBe(false);

    const open = await setup();
    const narrowed = await open.assume(open.key, allow(['documents:read']));
    expect(await allowed(open.f, narrowed.token, 'documents:read')).toBe(true);
    expect(await allowed(open.f, narrowed.token, 'documents:write')).toBe(false);
  });

  it('lets the source scopes and policy bound only what may be assumed', async () => {
    // A key whose scopes leave out iam:roles:assume cannot assume at all.
    const narrow = await setup({ scopes: ['iam:session-tokens:create'] });
    await expect(narrow.assume(narrow.key)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    const { f, key, assume } = await setup();
    // A session token keeps the key's scopes as its sourcePolicy boundary.
    const minted = await f.iam.api.sts.getSessionToken({ token: key });
    const mintedRow = await rowOf(f, minted.token);
    expect(mintedRow.sourcePolicy).toEqual((await rowOf(f, key)).policy);
    expect(await allowed(f, minted.token, 'documents:write')).toBe(false);
    // Its policy decides whether it may assume ...
    const blocked = await f.iam.api.sts.getSessionToken(
      { token: key },
      { policy: allow(['iam:session-tokens:create']) },
    );
    await expect(assume(blocked.token)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // ... but not what the resulting role session may do.
    const role = await assume(minted.token);
    expect(await allowed(f, role.token, 'documents:write')).toBe(true);
    expect(await rowOf(f, role.token)).not.toHaveProperty('sourcePolicy');
  });
});
