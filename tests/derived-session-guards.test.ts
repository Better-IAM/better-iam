import { createHash, randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { actsInOwnRight } from '@better-iam/server';
import { newCredentialToken } from '@better-iam/auth';
import type { Session, StoredRecord } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * Self-service guards for derived credentials: accepting agreements, reviewing as a manager, activating eligible
 * bindings, requesting access or packages, setting package rules and finding access paths act in the identity's own
 * right, so role sessions and session tokens are refused with each operation's existing error while user sessions
 * and API keys keep working. Session-token rows are seeded through `iam.store` (their issuing API ships in another
 * track), sourced from a real user session; role sessions come from a real `roles.assume`.
 */
type Credential = { token: string };
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

async function rowOf(f: OrganizationFixture, token: string): Promise<Session> {
  const [row] = await f.iam.store.find<Session>('sessions', { tokenHash: sha256(token) });
  if (!row) throw new Error('No session for this token');
  return row;
}

/** Seeds a session token minted from `source`, as sts.getSessionToken would store it. */
async function sessionToken(f: OrganizationFixture, source: Session): Promise<Credential> {
  const token = newCredentialToken('sts');
  const now = f.now();
  const row: Session = {
    id: randomUUID(),
    tenantId: source.tenantId,
    identityId: source.identityId,
    kind: 'session-token',
    sourceSessionId: source.id,
    tokenHash: sha256(token),
    uniqueKey: sha256(token),
    createdAt: now,
    lastSeenAt: now,
    authenticatedAt: source.authenticatedAt,
    expiresAt: Math.min(source.expiresAt, now + 3600_000),
    mfa: source.mfa,
  } as Session;
  await f.iam.store.transaction((tx) => tx.insert('sessions', row as never));
  return { token };
}

/**
 * Acme with: Alice (managed by the owner) holding Readers; an eligible Writer binding for the owner and for a service
 * account whose API key holds the self-service permissions; a requestable package; an agreement; a manager-mode
 * certification campaign over Readers; and two derived credentials of the owner: a session token sourced from a
 * user session, and a role session of an all-powerful role through a same-tenant trust.
 */
async function scenario() {
  const f = await organizationFixture();
  const { tenantId, ownerCredential: owner } = f;
  const api = f.iam.api;
  const alice = await f.member('alice');
  await api.identities.update(owner, { tenantId, identityId: alice.id, managerId: f.ownerId });
  const readers = await api.roles.create(owner, {
    tenantId,
    name: 'Readers',
    permissions: ['documents:read'],
  });
  await api.bindings.create(owner, {
    tenantId,
    roleId: readers.id,
    subjectType: 'identity',
    subjectId: alice.id,
  });
  const writers = await api.roles.create(owner, {
    tenantId,
    name: 'Writers',
    permissions: ['documents:write'],
  });
  const ownerEligible = await api.bindings.create(owner, {
    tenantId,
    roleId: writers.id,
    subjectType: 'identity',
    subjectId: f.ownerId,
    eligible: true,
  });

  const account = await api.serviceAccounts.create(owner, { tenantId, name: 'automation' });
  const selfService = await api.roles.create(owner, {
    tenantId,
    name: 'Self-service',
    permissions: ['iam:access-requests:create', 'iam:bindings:activate', 'iam:packages:request'],
  });
  await api.bindings.create(owner, {
    tenantId,
    roleId: selfService.id,
    subjectType: 'identity',
    subjectId: account.id,
  });
  const accountEligible = await api.bindings.create(owner, {
    tenantId,
    roleId: writers.id,
    subjectType: 'identity',
    subjectId: account.id,
    eligible: true,
  });
  const apiKey: Credential = {
    token: (await api.credentials.create(owner, { tenantId, identityId: account.id })).token,
  };

  const pkg = await api.packages.create(owner, {
    tenantId,
    name: 'Readers kit',
    roleIds: [readers.id],
    requestable: true,
  });
  const ruled = await api.packages.create(owner, {
    tenantId,
    name: 'Rule kit',
    roleIds: [writers.id],
  });
  const agreement = await api.agreements.create(owner, {
    tenantId,
    name: 'Acceptable use',
    content: 'Be nice.',
  });
  const campaign = await api.certifications.create(owner, {
    tenantId,
    name: 'Manager review',
    reviewerMode: 'manager',
    roleIds: [readers.id],
  });
  const [item] = (await api.certifications.get(owner, { tenantId, campaignId: campaign.id })).items;
  if (item?.reviewerId !== f.ownerId) throw new Error('The owner must review Alice');

  const everything = await api.roles.create(owner, {
    tenantId,
    name: 'Everything',
    document: { version: 1, statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }] },
  });
  const trust = await api.trust.create(f.rootCredential, {
    tenantId,
    sourceTenantId: tenantId,
    sourceIdentityId: f.ownerId,
    roleId: everything.id,
    requireMfa: false,
  });
  const role: Credential = {
    token: (await api.roles.assume(await f.ownerSignIn(), { tenantId, trustId: trust.id })).token,
  };
  const user = await f.ownerSignIn();
  const sts = await sessionToken(f, await rowOf(f, user.token));
  expect((await f.iam.authenticate(sts)).session.kind).toBe('session-token');
  expect((await f.iam.authenticate(role)).session.kind).toBe('role');

  const rule = { include: [{ StringLikeIgnoreCase: { 'identity.email': '*@partner.test' } }] };
  /** Every guarded operation, called for the owner (or the service account's own eligible binding). */
  const operations = {
    'accessPaths.find': {
      code: 'ACCESS_DENIED',
      message: 'Access paths are for an ordinary session of the tenant',
      call: (credential: Credential) =>
        api.accessPaths.find(credential, {
          tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'd1' },
        }),
    },
    'accessRequests.create': {
      code: 'INVALID_INPUT',
      message: 'Requests are made from an ordinary session of the target tenant',
      call: (credential: Credential) =>
        api.accessRequests.create(credential, { tenantId, roleIds: [readers.id] }),
    },
    'agreements.listMine': {
      code: 'ACCESS_DENIED',
      message: 'Agreements are accepted from an ordinary session of their tenant',
      call: (credential: Credential) => api.agreements.listMine(credential, { tenantId }),
    },
    'agreements.accept': {
      code: 'ACCESS_DENIED',
      message: 'Agreements are accepted from an ordinary session of their tenant',
      call: (credential: Credential) =>
        api.agreements.accept(credential, { tenantId, agreementId: agreement.id, version: 1 }),
    },
    'bindings.activate': {
      code: 'INVALID_INPUT',
      message: 'Activations are made from an ordinary session of the target tenant',
      call: (credential: Credential) =>
        api.bindings.activate(credential, {
          tenantId,
          bindingId: credential === apiKey ? accountEligible.id : ownerEligible.id,
        }),
    },
    'bindings.listMine': {
      code: 'INVALID_INPUT',
      message: 'Bindings are listed from an ordinary session of the target tenant',
      call: (credential: Credential) => api.bindings.listMine(credential, { tenantId }),
    },
    'certifications.review': {
      code: 'ACCESS_DENIED',
      message: 'Reviews are made from an ordinary session of the campaign tenant',
      call: (credential: Credential) =>
        api.certifications.review(credential, {
          tenantId,
          campaignId: campaign.id,
          decisions: [{ itemId: item.id, decision: 'keep' }],
        }),
    },
    'certifications.listMine': {
      code: 'ACCESS_DENIED',
      message: 'Reviews are made from an ordinary session of the campaign tenant',
      call: (credential: Credential) => api.certifications.listMine(credential, { tenantId }),
    },
    'packages.request': {
      code: 'INVALID_INPUT',
      message: 'Requests are made from an ordinary session of the target tenant',
      call: (credential: Credential) =>
        api.packages.request(credential, { tenantId, packageId: pkg.id }),
    },
    'packages.update (rule)': {
      code: 'INVALID_INPUT',
      message: 'Package rules are set from an ordinary session or API key of the tenant',
      call: (credential: Credential) =>
        api.packages.update(credential, {
          tenantId,
          packageId: ruled.id,
          autoAssign: rule as never,
        }),
    },
  };
  return { f, api, tenantId, owner, user, sts, role, apiKey, account, operations };
}

describe('derived-session self-service guards', () => {
  it('refuses session tokens and role sessions with each operation’s existing error', async () => {
    const s = await scenario();
    for (const [credentialName, credential] of [
      ['session token', s.sts],
      ['role session', s.role],
    ] as const)
      for (const [name, operation] of Object.entries(s.operations))
        await expect(
          operation.call(credential),
          `${name} with a ${credentialName}`,
        ).rejects.toMatchObject({ code: operation.code, message: operation.message });

    // Nothing was recorded by the refused calls.
    const count = async (collection: string) =>
      (await s.f.iam.store.find(collection, { tenantId: s.tenantId })).length;
    for (const collection of [
      'accessRequests',
      'agreementAcceptances',
      'bindingActivations',
      'packageRequests',
    ])
      expect(await count(collection), collection).toBe(0);
    const [item] = await s.f.iam.store.find<StoredRecord & { decision?: string }>(
      'certificationItems',
      {
        tenantId: s.tenantId,
      },
    );
    expect(item?.decision).toBeUndefined();
    const ruled = await s.api.packages.list(s.owner, { tenantId: s.tenantId });
    expect(ruled.find((pkg) => pkg.name === 'Rule kit')?.autoAssign).toBeUndefined();
  });

  it('still serves the same operations for a user session', async () => {
    const s = await scenario();
    const { operations: o, user } = s;
    expect(await o['accessPaths.find'].call(user)).toMatchObject({ allowed: true });
    expect(await o['accessRequests.create'].call(user)).toMatchObject({ status: 'pending' });
    expect(await o['agreements.listMine'].call(user)).toHaveLength(1);
    expect(await o['agreements.accept'].call(user)).toMatchObject({ accepted: true, version: 1 });
    expect(await o['bindings.activate'].call(user)).toBeDefined();
    expect((await o['bindings.listMine'].call(user)).length).toBeGreaterThan(0);
    expect(await o['certifications.listMine'].call(user)).toHaveLength(1);
    expect(await o['certifications.review'].call(user)).toEqual({ recorded: 1 });
    expect(await o['packages.request'].call(user)).toMatchObject({ status: 'pending' });
    expect((await o['packages.update (rule)'].call(user)).autoAssign).toMatchObject({
      ownerId: s.f.ownerId,
    });
  });

  it('still serves API keys where they were allowed', async () => {
    const s = await scenario();
    const { operations: o, apiKey } = s;
    expect(await o['accessPaths.find'].call(apiKey)).toMatchObject({ allowed: false });
    expect(await o['accessRequests.create'].call(apiKey)).toMatchObject({
      status: 'pending',
      requesterId: s.account.id,
    });
    expect(await o['agreements.listMine'].call(apiKey)).toHaveLength(1);
    // Passes the session guard and meets the unchanged people-only rule.
    await expect(o['agreements.accept'].call(apiKey)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: 'Only people accept agreements',
    });
    expect(await o['bindings.activate'].call(apiKey)).toBeDefined();
    expect((await o['bindings.listMine'].call(apiKey)).length).toBeGreaterThan(0);
    expect(await o['certifications.listMine'].call(apiKey)).toEqual([]);
    expect(await o['packages.request'].call(apiKey)).toMatchObject({ status: 'pending' });
    const activations = await s.f.iam.store.find<StoredRecord & { identityId: string }>(
      'bindingActivations',
      {
        tenantId: s.tenantId,
      },
    );
    expect(activations.map((activation) => activation.identityId)).toEqual([s.account.id]);
  });

  it("lets an API key set a package rule through the author checks, as the rule's owner", async () => {
    const s = await scenario();
    const { api, tenantId, owner, account, apiKey, operations: o } = s;
    // Without the rights the author checks need, the key passes the session guard and meets them.
    await expect(o['packages.update (rule)'].call(apiKey)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    const packager = await api.roles.create(owner, {
      tenantId,
      name: 'Packager',
      permissions: ['iam:packages:update', 'iam:packages:assign', 'iam:bindings:create'],
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: packager.id,
      subjectType: 'identity',
      subjectId: account.id,
    });
    // Still no grant authority of its own.
    await expect(o['packages.update (rule)'].call(apiKey)).rejects.toMatchObject({
      code: 'GRANT_AUTHORITY_REQUIRED',
    });
    await api.authorities.create(owner, {
      tenantId,
      identityId: account.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['*'] }],
      },
    });
    const updated = await o['packages.update (rule)'].call(apiKey);
    expect(updated.autoAssign).toMatchObject({ ownerId: account.id });
    const stored = (await api.packages.list(owner, { tenantId })).find(
      (pkg) => pkg.name === 'Rule kit',
    );
    expect(stored?.autoAssign).toMatchObject({ ownerId: account.id });
  });

  it('treats only user sessions and API keys as acting in their own right', () => {
    expect(actsInOwnRight({ kind: 'user' })).toBe(true);
    expect(actsInOwnRight({ kind: 'api-key' })).toBe(true);
    expect(actsInOwnRight({ kind: 'role' })).toBe(false);
    expect(actsInOwnRight({ kind: 'session-token' })).toBe(false);
    expect(actsInOwnRight({ kind: 'gizmo' as Session['kind'] })).toBe(false);
  });
});
