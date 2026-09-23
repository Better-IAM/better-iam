import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const doc = { type: 'document', id: 'd1' };

async function scenario() {
  const f = await organizationFixture({
    permissions: {
      actions: ['documents:read', 'documents:write', 'documents:delete', 'documents:share'],
    },
  });
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const alice = await f.member('alice');
  await f.member('bob');
  const role = (name: string, statements: unknown[]) =>
    f.iam.api.roles.create(owner, {
      tenantId,
      name,
      document: { version: 1, statements } as never,
    });
  const bind = (roleId: string, subjectId: string, extra: Record<string, unknown> = {}) =>
    f.iam.api.bindings.create(owner, {
      tenantId,
      roleId,
      subjectType: 'identity',
      subjectId,
      ...extra,
    });
  const member = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Member',
    permissions: ['iam:packages:request', 'iam:bindings:activate'],
  });
  await bind(member.id, alice.id);
  // Reading needs MFA.
  const reader = await role('MFA reader', [
    {
      effect: 'allow',
      actions: ['documents:read'],
      resources: ['*'],
      conditions: { Bool: { 'principal.mfa': true } },
    },
  ]);
  await bind(reader.id, alice.id);
  // Writing through a just-in-time binding.
  const writer = await role('Writer', [
    { effect: 'allow', actions: ['documents:write'], resources: ['*'] },
  ]);
  const eligible = await bind(writer.id, alice.id, {
    eligible: true,
    requireJustification: true,
  });
  // Deleting through a requestable package.
  const deleter = await role('Deleter', [
    { effect: 'allow', actions: ['documents:delete'], resources: ['*'] },
  ]);
  const pkg = await f.iam.api.packages.create(owner, {
    tenantId,
    name: 'Cleanup crew',
    roleIds: [deleter.id],
    requestable: true,
  });
  // Sharing once the acceptable-use policy is accepted.
  const sharer = await role('Sharer', [
    { effect: 'allow', actions: ['documents:share'], resources: ['*'] },
    {
      effect: 'deny',
      actions: ['documents:share'],
      resources: ['*'],
      conditions: { NumericGreaterThan: { 'principal.pendingAgreements': 0 } },
    },
  ]);
  await bind(sharer.id, alice.id);
  const agreement = await f.iam.api.agreements.create(owner, {
    tenantId,
    name: 'Acceptable use',
    content: 'Be nice.',
  });
  const aliceToken = { token: (await f.signIn('alice')).token };
  const bobToken = { token: (await f.signIn('bob')).token };
  return { f, tenantId, owner, alice, aliceToken, bobToken, eligible, pkg, agreement, writer };
}

describe('self-service access paths', () => {
  it('finds the step-up, agreement, activation, and package that would each grant access', async () => {
    const s = await scenario();
    const find = (action: string, credential = s.aliceToken) =>
      s.f.iam.api.accessPaths.find(credential, { tenantId: s.tenantId, action, resource: doc });

    expect(await find('documents:read')).toEqual({
      allowed: false,
      reason: expect.any(String),
      paths: [{ kind: 'mfa' }],
    });
    expect((await find('documents:share')).paths).toEqual([
      {
        kind: 'accept-agreements',
        agreements: [{ id: s.agreement.id, name: 'Acceptable use', version: 1 }],
      },
    ]);
    expect((await find('documents:write')).paths).toEqual([
      {
        kind: 'activate',
        bindingId: s.eligible.id,
        role: { id: s.writer.id, name: 'Writer' },
        requireApproval: false,
        requireJustification: true,
        requireMfa: false,
      },
    ]);
    expect((await find('documents:delete')).paths).toEqual([
      {
        kind: 'request-package',
        package: { id: s.pkg.id, name: 'Cleanup crew' },
        requireJustification: false,
      },
    ]);
    // Someone with none of these options gets no paths.
    expect(await find('documents:delete', s.bobToken)).toMatchObject({
      allowed: false,
      paths: [],
    });

    // Nothing was saved by the simulations.
    expect(await s.f.iam.api.bindings.listActivations(s.owner, { tenantId: s.tenantId })).toEqual(
      [],
    );
    const status = await s.f.iam.api.agreements.status(s.owner, {
      tenantId: s.tenantId,
      agreementId: s.agreement.id,
    });
    expect(status.accepted).toEqual([]);
    const bindings = await s.f.iam.api.bindings.list(s.owner, { tenantId: s.tenantId });
    expect(bindings.some((binding) => binding.uniqueKey?.startsWith('simulation:'))).toBe(false);
    expect(
      (
        await s.f.iam.authorize({
          ...s.aliceToken,
          tenantId: s.tenantId,
          action: 'documents:delete',
          resource: doc,
        })
      ).allowed,
    ).toBe(false);

    // Taking a path works: accepting the agreement allows sharing, and then no paths are needed.
    await s.f.iam.api.agreements.accept(s.aliceToken, {
      tenantId: s.tenantId,
      agreementId: s.agreement.id,
      version: 1,
    });
    expect(await find('documents:share')).toEqual({
      allowed: true,
      reason: expect.any(String),
      paths: [],
    });
  });

  it('only serves ordinary sessions of the tenant and known actions', async () => {
    const s = await scenario();
    await expect(
      s.f.iam.api.accessPaths.find(s.f.rootCredential, {
        tenantId: s.tenantId,
        action: 'documents:read',
        resource: doc,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      s.f.iam.api.accessPaths.find(s.aliceToken, {
        tenantId: s.tenantId,
        action: 'documents:fly',
        resource: doc,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
  });
});
