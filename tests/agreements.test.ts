import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const doc = { type: 'document', id: 'd1' };

async function scenario() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const alice = await f.member('alice');
  const reader = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Reader',
    document: {
      version: 1,
      statements: [
        { effect: 'allow', actions: ['documents:read'], resources: ['*'] },
        // No document access until every required agreement is accepted.
        {
          effect: 'deny',
          actions: ['documents:*'],
          resources: ['*'],
          conditions: { NumericGreaterThan: { 'principal.pendingAgreements': 0 } },
        },
      ],
    },
  });
  await f.iam.api.bindings.create(owner, {
    tenantId,
    roleId: reader.id,
    subjectType: 'identity',
    subjectId: alice.id,
  });
  const aliceToken = { token: (await f.signIn('alice')).token };
  const canRead = async () =>
    (
      await f.iam.authorize({
        ...aliceToken,
        tenantId,
        action: 'documents:read',
        resource: doc,
      })
    ).allowed;
  return { f, tenantId, owner, alice, aliceToken, canRead };
}

describe('terms of use', () => {
  it('holds back access until required agreements are accepted, and again after a new version', async () => {
    const s = await scenario();
    expect(await s.canRead()).toBe(true);
    const agreement = await s.f.iam.api.agreements.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Acceptable use',
      content: 'Be nice.\n\n1. Report incidents.\r\n2.\tLock your screen.',
      url: 'https://acme.test/aup',
    });
    expect(agreement).toMatchObject({ version: 1, required: true });
    expect(await s.canRead()).toBe(false);

    const mine = await s.f.iam.api.agreements.listMine(s.aliceToken, { tenantId: s.tenantId });
    expect(mine).toEqual([
      expect.objectContaining({
        id: agreement.id,
        accepted: false,
        version: 1,
        content: 'Be nice.\n\n1. Report incidents.\r\n2.\tLock your screen.',
      }),
    ]);
    // Accepting an outdated version is refused.
    await expect(
      s.f.iam.api.agreements.accept(s.aliceToken, {
        tenantId: s.tenantId,
        agreementId: agreement.id,
        version: 2,
      }),
    ).rejects.toMatchObject({ code: 'VERSION_CONFLICT' });
    await s.f.iam.api.agreements.accept(s.aliceToken, {
      tenantId: s.tenantId,
      agreementId: agreement.id,
      version: 1,
    });
    expect(await s.canRead()).toBe(true);
    const simulated = await s.f.iam.api.policies.simulate(s.owner, {
      tenantId: s.tenantId,
      identityId: s.alice.id,
      action: 'documents:read',
      resource: doc,
    });
    expect(simulated.allowed).toBe(true);

    // A typo fix keeps acceptances; a new version asks again.
    await s.f.iam.api.agreements.update(s.owner, {
      tenantId: s.tenantId,
      agreementId: agreement.id,
      content: 'Be kind.',
    });
    expect(await s.canRead()).toBe(true);
    const v2 = await s.f.iam.api.agreements.update(s.owner, {
      tenantId: s.tenantId,
      agreementId: agreement.id,
      content: 'Be kind and careful.',
      newVersion: true,
    });
    expect(v2.version).toBe(2);
    expect(await s.canRead()).toBe(false);
    const status = await s.f.iam.api.agreements.status(s.owner, {
      tenantId: s.tenantId,
      agreementId: agreement.id,
    });
    expect(status.accepted).toEqual([]);
    expect(status.pending).toContainEqual({
      identity: { id: s.alice.id, name: 'alice@acme.test' },
      acceptedVersion: 1,
    });
    await s.f.iam.api.agreements.accept(s.aliceToken, {
      tenantId: s.tenantId,
      agreementId: agreement.id,
      version: 2,
    });
    expect(await s.canRead()).toBe(true);
    const after = await s.f.iam.api.agreements.status(s.owner, {
      tenantId: s.tenantId,
      agreementId: agreement.id,
    });
    expect(after.accepted.map((entry) => entry.identity.id)).toEqual([s.alice.id]);

    // Annual re-acceptance: acceptance lapses.
    await s.f.iam.api.agreements.update(s.owner, {
      tenantId: s.tenantId,
      agreementId: agreement.id,
      reacceptAfterDays: 365,
    });
    s.f.advance(366 * 86_400_000);
    const fresh = { token: (await s.f.signIn('alice')).token };
    expect(
      (
        await s.f.iam.authorize({
          ...fresh,
          tenantId: s.tenantId,
          action: 'documents:read',
          resource: doc,
        })
      ).allowed,
    ).toBe(false);
    const events = await s.f.iam.api.audit.list(await s.f.ownerSignIn(), {
      tenantId: s.tenantId,
    });
    const list = Array.isArray(events) ? events : (events as { events: unknown[] }).events;
    expect(JSON.stringify(list)).toContain('agreement:accept');
  });

  it('exposes accepted names to policies, skips optional agreements, and guards self-service', async () => {
    const s = await scenario();
    const optional = await s.f.iam.api.agreements.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Beta program',
      content: 'Features may change.',
      required: false,
    });
    // Optional agreements never hold anything back.
    expect(await s.canRead()).toBe(true);
    const beta = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Beta writer',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:write'],
            resources: ['*'],
            conditions: { ArrayContains: { 'principal.agreements': ['Beta program'] } },
          },
        ],
      },
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: beta.id,
      subjectType: 'identity',
      subjectId: s.alice.id,
    });
    const canWrite = async () =>
      (
        await s.f.iam.authorize({
          ...s.aliceToken,
          tenantId: s.tenantId,
          action: 'documents:write',
          resource: doc,
        })
      ).allowed;
    expect(await canWrite()).toBe(false);
    await s.f.iam.api.agreements.accept(s.aliceToken, {
      tenantId: s.tenantId,
      agreementId: optional.id,
      version: 1,
    });
    expect(await canWrite()).toBe(true);
    // The linter knows the new keys.
    const lint = await s.f.iam.api.analysis.lintPolicy(s.owner, {
      tenantId: s.tenantId,
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['*'],
            conditions: { NumericEquals: { 'principal.pendingAgreements': 0 } },
          },
        ],
      },
    });
    expect(lint.warnings.map((warning) => warning.code)).not.toContain('unknown-context-key');

    // Management needs permissions; names are unique; members only accept for themselves.
    await expect(
      s.f.iam.api.agreements.create(s.aliceToken, {
        tenantId: s.tenantId,
        name: 'Mine',
        content: 'x',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      s.f.iam.api.agreements.create(s.owner, {
        tenantId: s.tenantId,
        name: 'beta PROGRAM',
        content: 'x',
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      s.f.iam.api.agreements.create(s.owner, {
        tenantId: s.tenantId,
        name: 'Linked',
        content: 'x',
        url: 'javascript:alert(1)',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      s.f.iam.api.agreements.create(s.owner, {
        tenantId: s.tenantId,
        name: 'Controls',
        content: 'bell \u0007',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      s.f.iam.api.agreements.listMine(s.f.rootCredential, { tenantId: s.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await s.f.iam.api.agreements.delete(s.owner, {
      tenantId: s.tenantId,
      agreementId: optional.id,
    });
    expect(await canWrite()).toBe(false);
    expect(await s.f.iam.api.agreements.list(s.owner, { tenantId: s.tenantId })).toEqual([]);
  });
});
