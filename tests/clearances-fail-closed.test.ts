import { afterEach, describe, expect, it } from 'vitest';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';
import { administrator } from './support/guests.js';

afterEach(closeFixtures);

/**
 * Security clearances at the edges where the domain and the decision paths meet, each failing closed: a label written
 * under another scheme, plans for application types while labels pass down to children, `iam/{type}/{id}` naming a
 * resource whose type requires a label, and revocation never blocked by an "expect allow" access invariant.
 */
async function setup() {
  const f = await organizationFixture({
    clearances: {},
    permissions: {
      resourceTypes: {
        document: { managed: true, actions: ['documents:read'] },
        note: { actions: ['notes:read'] },
      },
    },
  });
  for (const id of ['d1', 'd2'])
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'document',
      id,
    });
  const alice = await administrator(f, 'alice', [
    'documents:read',
    'notes:read',
    'iam:classifications:declassify',
  ]);
  await f.iam.api.clearances.defineScheme(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Acme',
    template: 'us',
  });
  await f.iam.api.clearances.grant(f.ownerCredential, {
    tenantId: f.tenantId,
    identityId: alice.identity.id,
    level: 'S',
    citizenship: ['USA'],
  });
  return { f, alice };
}

const can = async (
  f: OrganizationFixture,
  credential: { token: string },
  type: string,
  id: string,
  action: string,
) =>
  (await f.iam.authorize({ ...credential, tenantId: f.tenantId, action, resource: { type, id } }))
    .allowed;

describe('clearances fail closed', () => {
  it('refuses a label written under another scheme until it is declassified', async () => {
    const { f, alice } = await setup();
    await f.database.transaction((tx) =>
      tx.insert('resourceLabels', {
        id: 'label-d1',
        tenantId: f.tenantId,
        uniqueKey: 'document/d1',
        type: 'document',
        resourceId: 'd1',
        label: { level: 'U' },
        inheritToChildren: false,
        schemeTenantId: 'a-scheme-no-longer-in-force',
        labeledBy: f.ownerId,
        labeledAt: f.now(),
        version: 1,
      }),
    );
    expect(await can(f, alice.credential, 'document', 'd1', 'documents:read')).toBe(false);
    expect(
      (
        await f.iam.listAccessible({
          ...alice.credential,
          tenantId: f.tenantId,
          action: 'documents:read',
          type: 'document',
        })
      ).resources.map((item) => item.resourceId),
    ).toEqual(['d2']);
    // Raising it is no way out: replacing a label that refuses everyone is a declassification.
    await expect(
      f.iam.api.clearances.label(f.ownerCredential, {
        tenantId: f.tenantId,
        type: 'document',
        id: 'd1',
        label: { level: 'TS' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await f.iam.api.clearances.declassify(alice.credential, {
      tenantId: f.tenantId,
      type: 'document',
      id: 'd1',
      label: { level: 'C' },
      reason: 'relabeled under the scheme in force',
    });
    expect(await can(f, alice.credential, 'document', 'd1', 'documents:read')).toBe(true);
  });

  it('stops planning application types while a label passes down to children', async () => {
    const { f, alice } = await setup();
    await f.iam.api.clearances.label(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'note',
      id: 'n1',
      label: { level: 'TS' },
    });
    const plan = (action: string, type: string) =>
      f.iam.planResources({ ...alice.credential, tenantId: f.tenantId, action, type });
    expect((await plan('notes:read', 'note')).filter).toEqual({
      kind: 'not',
      filter: { kind: 'equals', field: 'id', values: ['n1'] },
    });
    await f.iam.api.clearances.label(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'f1',
      label: { level: 'TS' },
      inheritToChildren: true,
    });
    await expect(plan('notes:read', 'note')).rejects.toMatchObject({ code: 'UNSUPPORTED_FILTER' });
    // Registered resources inherit only through registered parents, which the plan follows.
    expect((await plan('documents:read', 'document')).kind).toBe('always');
  });

  it('refuses an application action on iam/{type}/{id} like the resource it names', async () => {
    const { f } = await setup();
    expect(await can(f, f.ownerCredential, 'iam', 'document/d1', 'documents:read')).toBe(true);
    await f.iam.api.clearances.updateScheme(f.ownerCredential, {
      tenantId: f.tenantId,
      requireLabels: ['document'],
    });
    expect(await can(f, f.ownerCredential, 'document', 'd1', 'documents:read')).toBe(false);
    expect(await can(f, f.ownerCredential, 'iam', 'document/d1', 'documents:read')).toBe(false);
    expect(await can(f, f.ownerCredential, 'iam', 'document/d1', 'iam:resources:read')).toBe(true);
  });

  it('revokes and debriefs past "expect allow" invariants, but widens past no "expect deny" one', async () => {
    const { f, alice } = await setup();
    const { tenantId } = f;
    await f.iam.api.clearances.updateScheme(f.ownerCredential, {
      tenantId,
      definition: {
        ...(await f.iam.api.clearances.getScheme(f.ownerCredential, { tenantId }))!.definition,
        compartments: [{ id: 'GAMMA', name: 'Gamma' }],
      },
    });
    await f.iam.api.clearances.readIn(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      compartmentId: 'GAMMA',
    });
    for (const [id, label] of [
      ['d1', { level: 'TS' }],
      ['d2', { level: 'S', compartments: ['GAMMA'] }],
    ] as const)
      await f.iam.api.clearances.label(f.ownerCredential, {
        tenantId,
        type: 'document',
        id,
        label,
      });
    for (const [name, id, expected] of [
      ['Alice reads d2', 'd2', 'allow'],
      ['Alice never reads d1', 'd1', 'deny'],
    ] as const)
      await f.iam.api.invariants.create(f.ownerCredential, {
        tenantId,
        name,
        subject: { identityId: alice.identity.id },
        action: 'documents:read',
        resource: { type: 'document', id },
        expect: expected,
        mode: 'enforce',
      });
    await expect(
      f.iam.api.clearances.update(f.ownerCredential, {
        tenantId,
        identityId: alice.identity.id,
        level: 'TS',
      }),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });
    await f.iam.api.clearances.debrief(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      compartmentId: 'GAMMA',
    });
    expect(await can(f, alice.credential, 'document', 'd2', 'documents:read')).toBe(false);
    await f.iam.api.clearances.readIn(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      compartmentId: 'GAMMA',
    });
    expect(await can(f, alice.credential, 'document', 'd2', 'documents:read')).toBe(true);
    const revoked = await f.iam.api.clearances.revoke(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      reason: 'for cause',
    });
    expect(revoked.status).toBe('revoked');
    expect(await can(f, alice.credential, 'document', 'd2', 'documents:read')).toBe(false);
    // The exemption lasted for that operation only: the next widening change is checked again.
    await f.iam.api.clearances.grant(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      level: 'S',
      citizenship: ['USA'],
    });
    await expect(
      f.iam.api.clearances.update(f.ownerCredential, {
        tenantId,
        identityId: alice.identity.id,
        level: 'TS',
      }),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });
  });
});
