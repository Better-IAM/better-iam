import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('configuration as code: invariants and terms of use', () => {
  it('exports, plans, applies, and prunes invariants and agreements by name', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    // A tenant without either kind exports neither key.
    const empty = await f.iam.api.config.export(owner, { tenantId });
    expect(empty).not.toHaveProperty('invariants');
    expect(empty).not.toHaveProperty('agreements');

    const document = {
      version: 1 as const,
      groups: [{ name: 'Contractors', members: ['alice@acme.test'] }],
      agreements: [{ name: 'Acceptable use', content: 'Be nice.\nReally.' }],
      invariants: [
        {
          name: 'Contractors never write d1',
          subject: { group: 'Contractors' },
          action: 'documents:write',
          resource: { type: 'document', id: 'd1' },
          expect: 'deny' as const,
          mode: 'enforce' as const,
        },
        {
          name: 'Alice reads nothing',
          subject: { identity: 'ALICE@acme.test' },
          action: 'documents:read',
          resource: { type: 'document', id: 'd1' },
          expect: 'deny' as const,
        },
      ],
    };
    const plan = await f.iam.api.config.plan(owner, { tenantId, config: document });
    expect(plan.changes.map((change) => `${change.action} ${change.kind} ${change.name}`)).toEqual([
      'create group Contractors',
      'create agreement Acceptable use',
      'create invariant Alice reads nothing',
      'create invariant Contractors never write d1',
    ]);
    await f.iam.api.config.apply(owner, { tenantId, config: document });
    const invariants = await f.iam.api.invariants.list(owner, { tenantId });
    expect(invariants.map((invariant) => [invariant.name, invariant.mode])).toEqual([
      ['Alice reads nothing', 'monitor'],
      ['Contractors never write d1', 'enforce'],
    ]);
    expect(invariants[0]!.subject).toEqual({ identityId: alice.id });
    // The applied invariant is enforced right away.
    const writer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Writer',
      permissions: ['documents:write'],
    });
    await expect(
      f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: writer.id,
        subjectType: 'identity',
        subjectId: alice.id,
      }),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });

    // Round trip: the export applies with no changes.
    const exported = await f.iam.api.config.export(owner, { tenantId });
    expect(exported.invariants).toContainEqual({
      name: 'Contractors never write d1',
      subject: { group: 'Contractors' },
      action: 'documents:write',
      resource: { type: 'document', id: 'd1' },
      expect: 'deny',
      mode: 'enforce',
      assumeMfa: true,
    });
    expect(exported.agreements).toEqual([
      { name: 'Acceptable use', content: 'Be nice.\nReally.', required: true },
    ]);
    const again = await f.iam.api.config.plan(owner, { tenantId, config: exported });
    expect(again.summary).toMatchObject({ create: 0, update: 0, delete: 0 });

    // A content change publishes a new version; a URL change does not.
    const [agreement] = await f.iam.api.agreements.list(owner, { tenantId });
    await f.iam.api.config.apply(owner, {
      tenantId,
      config: {
        version: 1,
        agreements: [
          { name: 'Acceptable use', content: 'Be nice.\nReally.', url: 'https://acme.test/aup' },
        ],
      },
    });
    expect((await f.iam.api.agreements.list(owner, { tenantId }))[0]!.version).toBe(
      agreement!.version,
    );
    const edited = await f.iam.api.config.plan(owner, {
      tenantId,
      config: { version: 1, agreements: [{ name: 'Acceptable use', content: 'Be kind.' }] },
    });
    expect(edited.changes[0]).toMatchObject({
      kind: 'agreement',
      action: 'update',
      fields: ['content', 'url'],
    });
    await f.iam.api.config.apply(owner, {
      tenantId,
      config: { version: 1, agreements: [{ name: 'Acceptable use', content: 'Be kind.' }] },
    });
    expect((await f.iam.api.agreements.list(owner, { tenantId }))[0]).toMatchObject({
      version: agreement!.version + 1,
      content: 'Be kind.',
    });
    expect((await f.iam.api.agreements.list(owner, { tenantId }))[0]).not.toHaveProperty('url');

    // Invariant updates and pruning.
    await f.iam.api.config.apply(owner, {
      tenantId,
      prune: true,
      config: {
        version: 1,
        invariants: [{ ...document.invariants[0]!, mode: 'monitor' }],
        agreements: [],
      },
    });
    expect(
      (await f.iam.api.invariants.list(owner, { tenantId })).map((invariant) => [
        invariant.name,
        invariant.mode,
      ]),
    ).toEqual([['Contractors never write d1', 'monitor']]);
    expect(await f.iam.api.agreements.list(owner, { tenantId })).toEqual([]);

    // References are checked while planning.
    await expect(
      f.iam.api.config.plan(owner, {
        tenantId,
        config: {
          version: 1,
          invariants: [{ ...document.invariants[0]!, subject: { group: 'Nobody' } }],
        },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.config.plan(owner, {
        tenantId,
        config: {
          version: 1,
          invariants: [{ ...document.invariants[1]!, subject: { identity: 'ghost@acme.test' } }],
        },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.config.plan(owner, {
        tenantId,
        config: {
          version: 1,
          agreements: [
            { name: 'A', content: 'x' },
            { name: 'a', content: 'y' },
          ],
        },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
