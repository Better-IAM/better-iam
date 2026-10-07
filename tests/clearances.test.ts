import { afterEach, describe, expect, it } from 'vitest';
import { renderDeliveryMessage } from '@better-iam/auth';
import { classificationTemplates, type AuditEvent } from '@better-iam/core';
import { routeGroups } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';
import { addGuest, administrator, otherOrganization } from './support/guests.js';

afterEach(closeFixtures);

const officerPermissions = [
  'iam:clearances:read',
  'iam:clearances:adjudicate',
  'iam:clearances:suspend',
  'iam:classifications:label',
  'iam:classifications:declassify',
];

const usWithCompartments = () => ({
  ...JSON.parse(JSON.stringify(classificationTemplates.us)),
  compartments: [
    { id: 'GAMMA', name: 'Gamma codeword' },
    { id: 'HCS', name: 'Humint control' },
  ],
});

async function auditOf(f: OrganizationFixture, action: string): Promise<AuditEvent[]> {
  return f.database.transaction((tx) =>
    tx.find<AuditEvent>('audit', { tenantId: f.tenantId, action }),
  );
}

async function canRead(f: OrganizationFixture, credential: { token: string }, id: string) {
  return (
    await f.iam.authorize({
      ...credential,
      tenantId: f.tenantId,
      action: 'documents:read',
      resource: { type: 'document', id },
    })
  ).allowed;
}

/**
 * The clearances API (decision-path enforcement is covered in clearances-decision-paths.test.ts, offboarding, deletion,
 * reminders and emails in clearances-integrations.test.ts): schemes and their guarded changes, permissions and recent
 * sign-in, adjudication (never one's own, within-own with the bootstrap exception), NDA-backed read-ins, the guest
 * ceiling, interim and expiry, suspension and revocation, list/get/mine/explain, labels (raise only, declassify by the
 * cleared), tenant isolation, and FEATURE_DISABLED without the option.
 */
describe('clearances API', () => {
  it('answers FEATURE_DISABLED for every method without the option', async () => {
    const f = await organizationFixture();
    const api = f.iam.api.clearances as unknown as Record<
      string,
      (credential: unknown, input: unknown) => Promise<unknown>
    >;
    expect(Object.keys(api).length).toBeGreaterThan(15);
    for (const method of Object.keys(api))
      await expect(
        api[method]!(f.ownerCredential, {
          tenantId: f.tenantId,
          identityId: f.ownerId,
          type: 'document',
          id: 'x',
        }),
      ).rejects.toMatchObject({ code: 'FEATURE_DISABLED', status: 403 });
    await expect(f.iam.clearances.sendReminders()).rejects.toMatchObject({
      code: 'FEATURE_DISABLED',
    });
  });

  it('is routed over HTTP', async () => {
    expect(routeGroups.has('clearances')).toBe(true);
    const call = (f: OrganizationFixture, method: string, body: unknown) =>
      f.iam.handler(
        new Request(`http://localhost:3000/api/iam/clearances/${method}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-better-iam': '1',
            authorization: `Bearer ${f.ownerCredential.token}`,
          },
          body: JSON.stringify(body),
        }),
      );
    const off = await organizationFixture();
    const refused = await call(off, 'getScheme', { tenantId: off.tenantId });
    expect(refused.status).toBe(403);
    expect(((await refused.json()) as { error: { code: string } }).error.code).toBe(
      'FEATURE_DISABLED',
    );
    const on = await organizationFixture({ clearances: {} });
    const defined = await call(on, 'defineScheme', {
      tenantId: on.tenantId,
      name: 'Acme',
      template: 'corporate',
    });
    expect(defined.status).toBe(200);
    const mine = await call(on, 'mine', { tenantId: on.tenantId });
    expect(((await mine.json()) as { data: unknown }).data).toMatchObject({
      scheme: { tenantId: on.tenantId, name: 'Acme' },
      clearance: null,
    });
  });

  it('defines schemes closest to the root and guards changes in use', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    expect((await api.templates(f.ownerCredential)).map((template) => template.id)).toEqual([
      'us',
      'uk',
      'nato',
      'corporate',
    ]);
    expect(await api.getScheme(f.ownerCredential, { tenantId })).toBeNull();
    await expect(
      api.defineScheme(f.ownerCredential, { tenantId, name: 'Acme' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const scheme = await api.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      definition: usWithCompartments(),
      requireLabels: ['document'],
    });
    expect(scheme).toMatchObject({
      tenantId,
      inherited: false,
      guestCeiling: null,
      interimAllowed: false,
      adjudication: 'within-own',
      requireLabels: ['document'],
      version: 1,
    });
    await expect(
      api.defineScheme(f.ownerCredential, { tenantId, name: 'Again', template: 'uk' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    // A scheme above one already defined below would re-interpret its clearances and labels.
    await expect(
      api.defineScheme(f.rootCredential, {
        tenantId: f.root.tenant.id,
        name: 'Platform',
        template: 'nato',
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const [define] = await auditOf(f, 'classification:scheme-define');
    expect(define?.metadata).toMatchObject({
      levels: ['U', 'C', 'S', 'TS'],
      compartments: ['GAMMA', 'HCS'],
    });
    expect(JSON.stringify(define?.metadata)).not.toContain('Gamma codeword');

    // Put levels and a compartment in use.
    const alice = await administrator(f, 'alice', officerPermissions);
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      level: 'S',
      citizenship: ['USA'],
    });
    await api.readIn(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      compartmentId: 'GAMMA',
    });
    await api.label(alice.credential, {
      tenantId,
      type: 'document',
      id: 'plan',
      label: { level: 'C' },
    });
    const base = usWithCompartments();
    await expect(
      api.updateScheme(f.ownerCredential, {
        tenantId,
        definition: {
          ...base,
          levels: base.levels.filter((level: { id: string }) => level.id !== 'S'),
        },
      }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    await expect(
      api.updateScheme(f.ownerCredential, {
        tenantId,
        definition: {
          ...base,
          levels: base.levels.map((level: { id: string; rank: number }) =>
            level.id === 'C'
              ? { ...level, rank: 1 }
              : level.id === 'U'
                ? level
                : { ...level, rank: level.rank + 1 },
          ),
        },
      }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    await expect(
      api.updateScheme(f.ownerCredential, {
        tenantId,
        definition: { ...base, compartments: [{ id: 'HCS', name: 'Humint control' }] },
      }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    // New levels go above every level kept.
    await expect(
      api.updateScheme(f.ownerCredential, {
        tenantId,
        definition: {
          ...base,
          levels: [
            { id: 'U', name: 'UNCLASSIFIED', rank: 0 },
            { id: 'X', name: 'EXTRA', rank: 1 },
            { id: 'C', name: 'CONFIDENTIAL', rank: 2 },
            { id: 'S', name: 'SECRET', rank: 3 },
            { id: 'TS', name: 'TOP SECRET', rank: 4 },
          ],
        },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const updated = await api.updateScheme(f.ownerCredential, {
      tenantId,
      version: 1,
      definition: {
        ...base,
        levels: [...base.levels, { id: 'SCI', name: 'SCI', rank: 4 }],
        compartments: [...base.compartments, { id: 'TK', name: 'Talent' }],
      },
      interimAllowed: true,
      guestCeiling: 'C',
    });
    expect(updated).toMatchObject({ version: 2, interimAllowed: true, guestCeiling: 'C' });
    await expect(
      api.updateScheme(f.ownerCredential, { tenantId, version: 1, interimAllowed: false }),
    ).rejects.toMatchObject({ code: 'VERSION_CONFLICT' });
  });

  it('lets a child inherit the root’s scheme and refuses root its own clearance', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const rootTenant = f.root.tenant.id;
    const rootId = (await f.iam.api.auth.getSession(f.rootCredential)).identity.id;
    await api.defineScheme(f.rootCredential, {
      tenantId: rootTenant,
      name: 'Platform',
      template: 'corporate',
      adjudication: 'unrestricted',
    });
    // Nobody adjudicates their own clearance, root included.
    await expect(
      api.grant(f.rootCredential, {
        tenantId: rootTenant,
        identityId: rootId,
        level: 'restricted',
        citizenship: [],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const denied = await f.database.transaction((tx) =>
      tx.find<AuditEvent>('audit', {
        tenantId: rootTenant,
        action: 'iam:clearances:adjudicate',
        outcome: 'deny',
      }),
    );
    expect(denied).toHaveLength(1);
    expect(await api.getScheme(f.ownerCredential, { tenantId: f.tenantId })).toMatchObject({
      tenantId: rootTenant,
      inherited: true,
    });
    await expect(
      api.defineScheme(f.ownerCredential, { tenantId: f.tenantId, name: 'Acme', template: 'us' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      api.updateScheme(f.ownerCredential, { tenantId: f.tenantId, interimAllowed: true }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    // Members of the organization are cleared under the inherited scheme.
    const dave = await f.member('dave');
    const granted = await api.grant(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: dave.id,
      level: 'internal',
      citizenship: [],
    });
    expect(granted).toMatchObject({
      schemeTenantId: rootTenant,
      effectiveStatus: 'active',
      effectiveLevel: 'internal',
    });
  });

  it('adjudicates within one’s own clearance, bootstraps once, and backs read-ins with NDAs', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    await api.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      definition: usWithCompartments(),
    });
    const alice = await administrator(f, 'alice', officerPermissions);
    const bob = await administrator(f, 'bob', officerPermissions);
    const carol = await administrator(f, 'carol', ['documents:read']);
    // Not even an owner grants themselves a clearance.
    await expect(
      api.grant(f.ownerCredential, {
        tenantId,
        identityId: f.ownerId,
        level: 'TS',
        citizenship: [],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // The owner holds no clearance but may bootstrap TS: nobody holds it yet.
    const first = await api.grant(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      level: 'TS',
      citizenship: ['USA'],
    });
    expect(first).toMatchObject({
      status: 'active',
      effectiveStatus: 'active',
      effectiveLevel: 'TS',
    });
    const [grant] = await auditOf(f, 'clearance:grant');
    expect(grant?.metadata).toEqual({ level: 'TS', status: 'active', bootstrap: true });
    expect(grant?.resourceId).toBe(alice.identity.id);
    // Once someone holds it, only cleared officers grant it.
    await expect(
      api.grant(f.ownerCredential, {
        tenantId,
        identityId: bob.identity.id,
        level: 'S',
        citizenship: ['USA'],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await api.grant(alice.credential, {
      tenantId,
      identityId: bob.identity.id,
      level: 'S',
      citizenship: ['GBR'],
    });
    await expect(
      api.grant(bob.credential, {
        tenantId,
        identityId: carol.identity.id,
        level: 'TS',
        citizenship: ['USA'],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await api.grant(bob.credential, {
      tenantId,
      identityId: carol.identity.id,
      level: 'S',
      citizenship: ['USA'],
    });
    await expect(
      api.grant(alice.credential, {
        tenantId,
        identityId: carol.identity.id,
        level: 'C',
        citizenship: ['USA'],
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    // Nobody changes their own.
    await expect(
      api.update(alice.credential, {
        tenantId,
        identityId: alice.identity.id,
        citizenship: ['GBR'],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      api.grant(alice.credential, {
        tenantId,
        identityId: carol.identity.id,
        level: 'S',
        citizenship: [],
        interim: true,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // Compartments: alice is not read into GAMMA, so she cannot read others in; the owner bootstraps it once.
    await expect(
      api.readIn(alice.credential, {
        tenantId,
        identityId: carol.identity.id,
        compartmentId: 'GAMMA',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const bootstrapped = await api.readIn(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      compartmentId: 'GAMMA',
    });
    expect(bootstrapped.readIns).toMatchObject([
      { compartmentId: 'GAMMA', compartmentName: 'Gamma codeword', current: true },
    ]);
    await expect(
      api.readIn(f.ownerCredential, {
        tenantId,
        identityId: bob.identity.id,
        compartmentId: 'GAMMA',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const nda = await f.iam.api.agreements.create(f.ownerCredential, {
      tenantId,
      name: 'Compartment NDA',
      content: 'I will not disclose.',
      required: false,
    });
    const readIn = await api.readIn(alice.credential, {
      tenantId,
      identityId: carol.identity.id,
      compartmentId: 'GAMMA',
      agreementId: nda.id,
    });
    expect(readIn.readIns).toMatchObject([
      { compartmentId: 'GAMMA', agreementId: nda.id, current: false },
    ]);
    const readInEvents = await auditOf(f, 'clearance:read-in');
    expect(readInEvents.map((event) => event.metadata)).toContainEqual({
      compartmentId: 'GAMMA',
      level: 'S',
      agreementId: nda.id,
    });
    expect(JSON.stringify(readInEvents)).not.toContain('Gamma codeword');

    // A compartmented document: carol reads it only once her NDA acceptance is current.
    const labeled = await api.label(alice.credential, {
      tenantId,
      type: 'document',
      id: 'gamma-1',
      label: { level: 'C', compartments: ['GAMMA'] },
    });
    expect(labeled).toMatchObject({ levelName: 'CONFIDENTIAL', version: 1 });
    expect(await canRead(f, carol.credential, 'gamma-1')).toBe(false);
    await f.iam.api.agreements.accept(carol.credential, {
      tenantId,
      agreementId: nda.id,
      version: 1,
    });
    expect(await canRead(f, carol.credential, 'gamma-1')).toBe(true);
    expect(await api.mine(carol.credential, { tenantId })).toMatchObject({
      scheme: { tenantId, name: 'Acme' },
      clearance: {
        level: { id: 'S', name: 'SECRET' },
        effectiveStatus: 'active',
        citizenship: ['USA'],
        readIns: [{ compartmentId: 'GAMMA', compartmentName: 'Gamma codeword', current: true }],
      },
    });
    // Explain, for officers: bob holds S but no GAMMA.
    expect(
      await api.explain(alice.credential, {
        tenantId,
        identityId: bob.identity.id,
        type: 'document',
        id: 'gamma-1',
      }),
    ).toMatchObject({
      allowed: false,
      failure: 'compartment',
      label: { level: 'C', compartments: ['GAMMA'] },
      party: { identityId: bob.identity.id, level: 'S', rank: 2, compartments: [] },
    });
    // Without a permission nobody explains or reads clearances.
    await expect(
      api.explain(carol.credential, {
        tenantId,
        identityId: bob.identity.id,
        type: 'document',
        id: 'gamma-1',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      api.get(carol.credential, { tenantId, identityId: bob.identity.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // Debrief takes the compartment away at once.
    await api.debrief(bob.credential, {
      tenantId,
      identityId: carol.identity.id,
      compartmentId: 'GAMMA',
    });
    expect(await canRead(f, carol.credential, 'gamma-1')).toBe(false);

    const page = await api.list(f.ownerCredential, { tenantId, status: 'active' });
    expect(page.total).toBe(3);
    expect(page.clearances.map((item) => item.identity.name)).toEqual(['alice', 'bob', 'carol']);
  });

  it('raises labels freely and lets only the cleared declassify', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    await api.defineScheme(f.ownerCredential, { tenantId, name: 'Acme', template: 'us' });
    const alice = await administrator(f, 'alice', officerPermissions);
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      level: 'S',
      citizenship: ['USA'],
    });
    await api.label(alice.credential, {
      tenantId,
      type: 'document',
      id: 'memo',
      label: { level: 'C' },
    });
    const raised = await api.label(f.ownerCredential, {
      tenantId,
      type: 'document',
      id: 'memo',
      label: { level: 'C', noforn: true },
    });
    expect(raised).toMatchObject({ label: { level: 'C', noforn: true }, version: 2 });
    // Lowering any dimension through label is refused (and audited as a denial).
    for (const label of [{ level: 'U', noforn: true }, { level: 'C' }])
      await expect(
        api.label(alice.credential, { tenantId, type: 'document', id: 'memo', label }),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      api.label(alice.credential, {
        tenantId,
        type: 'document',
        id: 'memo',
        label: { level: 'C', compartments: ['NOPE'] },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      api.label(alice.credential, { tenantId, type: 'iam', id: 'x', label: { level: 'C' } }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The owner holds no clearance: declassifying what they could not read is refused.
    await expect(
      api.declassify(f.ownerCredential, {
        tenantId,
        type: 'document',
        id: 'memo',
        label: null,
        reason: 'release',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const lowered = await api.declassify(alice.credential, {
      tenantId,
      type: 'document',
      id: 'memo',
      label: { level: 'U' },
      reason: 'reviewed for release',
    });
    expect(lowered).toMatchObject({ label: { level: 'U' }, version: 3 });
    expect(
      await api.getLabel(alice.credential, { tenantId, type: 'document', id: 'memo' }),
    ).toMatchObject({ label: { label: { level: 'U' } }, inherited: null });
    expect(
      await api.declassify(alice.credential, {
        tenantId,
        type: 'document',
        id: 'memo',
        label: null,
        reason: 'public',
      }),
    ).toBeNull();
    expect(
      (await api.getLabel(alice.credential, { tenantId, type: 'document', id: 'memo' })).label,
    ).toBeNull();
    const declassified = (await auditOf(f, 'classification:declassify')).find(
      (event) => event.metadata?.reason === 'reviewed for release',
    );
    expect(declassified?.metadata).toMatchObject({
      type: 'document',
      previous: { level: 'C', noforn: true },
      label: { level: 'U' },
      reason: 'reviewed for release',
    });
    // An id too long for a natural key (over 512 bytes with its type) is keyed by its hash and still labels and lists.
    const longId = 'é'.repeat(256);
    await api.label(alice.credential, {
      tenantId,
      type: 'document',
      id: longId,
      label: { level: 'S' },
    });
    const listed = await api.listLabels(alice.credential, { tenantId, type: 'document' });
    expect(listed.labels.map((item) => item.id)).toEqual([longId]);
    expect(await canRead(f, f.ownerCredential, longId)).toBe(false);
  });

  it('passes labels down managed parents, and keeps them when resources are deleted', async () => {
    const f = await organizationFixture({
      clearances: {},
      permissions: {
        actions: ['documents:read'],
        resourceTypes: {
          folder: { managed: true, actions: ['folders:read'] },
          doc: { managed: true, parent: 'folder', actions: ['docs:read'] },
        },
      },
    });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    await api.defineScheme(f.ownerCredential, { tenantId, name: 'Acme', template: 'us' });
    const reader = await administrator(f, 'rita', ['docs:read', 'folders:read']);
    const register = (type: string, id: string, parentId?: string) =>
      f.iam.api.resources.register(f.ownerCredential, {
        tenantId,
        type,
        id,
        ...(parentId ? { parentId } : {}),
      });
    await register('folder', 'vault');
    await register('folder', 'lobby');
    await register('doc', 'plans', 'vault');
    await register('doc', 'menu', 'lobby');
    const read = async (type: string, id: string) =>
      (
        await f.iam.authorize({
          ...reader.credential,
          tenantId,
          action: `${type}s:read`,
          resource: { type, id },
        })
      ).allowed;
    expect(await read('doc', 'plans')).toBe(true);
    // Labeling the folder alone protects it; marking the label inherited protects what it holds.
    await api.label(f.ownerCredential, {
      tenantId,
      type: 'folder',
      id: 'vault',
      label: { level: 'S' },
    });
    expect(await read('folder', 'vault')).toBe(false);
    expect(await read('doc', 'plans')).toBe(true);
    await api.label(f.ownerCredential, {
      tenantId,
      type: 'folder',
      id: 'vault',
      label: { level: 'S' },
      inheritToChildren: true,
    });
    expect(await read('doc', 'plans')).toBe(false);
    expect(await read('doc', 'menu')).toBe(true);
    expect(
      await api.getLabel(f.ownerCredential, { tenantId, type: 'doc', id: 'plans' }),
    ).toMatchObject({ label: null, inherited: { level: 'S' } });
    const listed = await f.iam.listAccessible({
      ...reader.credential,
      tenantId,
      action: 'docs:read',
      type: 'doc',
    });
    expect(listed.resources.map((item) => item.resourceId)).toEqual(['menu']);
    // Turning inheritance off is a declassification.
    await expect(
      api.label(f.ownerCredential, {
        tenantId,
        type: 'folder',
        id: 'vault',
        label: { level: 'S' },
        inheritToChildren: false,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Deleting and registering again (elsewhere) cannot declassify.
    await api.label(f.ownerCredential, {
      tenantId,
      type: 'doc',
      id: 'plans',
      label: { level: 'C' },
    });
    await f.iam.api.resources.delete(f.ownerCredential, { tenantId, type: 'doc', id: 'plans' });
    await register('doc', 'plans', 'lobby');
    expect(await read('doc', 'plans')).toBe(false);
    expect(
      (await api.getLabel(f.ownerCredential, { tenantId, type: 'doc', id: 'plans' })).label,
    ).toMatchObject({ label: { level: 'C' } });
  });

  it('caps guests, suspends, reinstates and revokes', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    await api.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      definition: usWithCompartments(),
      adjudication: 'unrestricted',
    });
    const guest = await addGuest(f, 'gina');
    await expect(
      api.grant(f.ownerCredential, {
        tenantId,
        identityId: guest.identity.id,
        level: 'U',
        citizenship: ['USA'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await api.updateScheme(f.ownerCredential, { tenantId, guestCeiling: 'C' });
    await expect(
      api.grant(f.ownerCredential, {
        tenantId,
        identityId: guest.identity.id,
        level: 'S',
        citizenship: ['USA'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: guest.identity.id,
      level: 'C',
      citizenship: ['USA'],
    });
    await expect(
      api.readIn(f.ownerCredential, {
        tenantId,
        identityId: guest.identity.id,
        compartmentId: 'HCS',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The ceiling applies at decision time: lowering it lowers the guest at once.
    await api.updateScheme(f.ownerCredential, { tenantId, guestCeiling: 'U' });
    expect(
      await api.get(f.ownerCredential, { tenantId, identityId: guest.identity.id }),
    ).toMatchObject({ level: { id: 'C' }, effectiveLevel: 'U' });
    await api.updateScheme(f.ownerCredential, { tenantId, guestCeiling: null });
    expect(
      await api.get(f.ownerCredential, { tenantId, identityId: guest.identity.id }),
    ).toMatchObject({ effectiveStatus: 'none' });

    // Suspension stops access at once, needs no recent sign-in, and only another officer reinstates.
    const officer = await administrator(f, 'olga', officerPermissions);
    const carol = await administrator(f, 'carol', ['documents:read']);
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: carol.identity.id,
      level: 'S',
      citizenship: ['USA'],
    });
    await api.readIn(f.ownerCredential, {
      tenantId,
      identityId: carol.identity.id,
      compartmentId: 'HCS',
    });
    await api.label(officer.credential, {
      tenantId,
      type: 'document',
      id: 'brief',
      label: { level: 'U' },
    });
    expect(await canRead(f, carol.credential, 'brief')).toBe(true);
    f.advance(3_600_000);
    const suspended = await api.suspend(officer.credential, {
      tenantId,
      identityId: carol.identity.id,
      reason: 'incident under investigation',
      incidentId: 'inc-1',
    });
    expect(suspended).toMatchObject({
      status: 'suspended',
      effectiveStatus: 'suspended',
      suspended: { reason: 'incident under investigation', incidentId: 'inc-1' },
    });
    expect(await canRead(f, carol.credential, 'brief')).toBe(false);
    await expect(
      api.suspend(officer.credential, { tenantId, identityId: carol.identity.id, reason: 'again' }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    // Reinstating needs a recent sign-in.
    await expect(
      api.reinstate(officer.credential, { tenantId, identityId: carol.identity.id }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    const fresh = { token: (await f.signIn('olga')).token };
    const reinstated = await api.reinstate(fresh, { tenantId, identityId: carol.identity.id });
    expect(reinstated).toMatchObject({ status: 'active', effectiveStatus: 'active' });
    expect(reinstated.readIns.map((item) => item.compartmentId)).toEqual(['HCS']);
    expect(await canRead(f, carol.credential, 'brief')).toBe(true);
    const revoked = await api.revoke(fresh, {
      tenantId,
      identityId: carol.identity.id,
      reason: 'no longer needed',
    });
    expect(revoked).toMatchObject({ status: 'revoked', effectiveStatus: 'revoked', readIns: [] });
    const [revoke] = await auditOf(f, 'clearance:revoke');
    expect(revoke?.metadata).toEqual({
      level: 'S',
      reason: 'no longer needed',
      debriefed: ['HCS'],
    });
    expect(await canRead(f, carol.credential, 'brief')).toBe(false);
    // The person is told, level name only.
    await f.iam.auth.dispatchOutbox();
    const statuses = f.inbox.filter((message) => message.template === 'clearance-status');
    expect(statuses.map((message) => message.payload.status).sort()).toEqual([
      'reinstated',
      'revoked',
      'suspended',
    ]);
    expect(statuses.every((message) => message.to === 'carol@acme.test')).toBe(true);
    const rendered = renderDeliveryMessage(
      statuses.find((message) => message.payload.status === 'suspended')!,
    )!;
    expect(rendered.subject).toBe('Your security clearance at Acme was suspended');
    expect(rendered.text).toContain('(level: SECRET)');
    expect(JSON.stringify(statuses)).not.toContain('Humint');
    expect(JSON.stringify(statuses)).not.toContain('incident under investigation');
  });

  it('validates schemes and their settings, and changes only what nothing uses', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    const define = (input: Record<string, unknown>) =>
      api.defineScheme(f.ownerCredential, { tenantId, name: 'Acme', ...input } as never);
    for (const input of [
      {},
      { template: 'us', definition: usWithCompartments() },
      { template: 'secret-service' },
      { definition: { levels: [{ id: 'U', name: 'UNCLASSIFIED', rank: 0 }] } },
      { definition: { ...usWithCompartments(), colour: 'red' } },
      { template: 'us', name: '' },
      { template: 'us', requireLabels: ['iam'] },
      { template: 'us', requireLabels: 'document' },
      { template: 'us', guestCeiling: 'COSMIC' },
      { template: 'us', guestCeiling: 2 },
      { template: 'us', adjudication: 'anyone' },
      { template: 'us', interimAllowed: 'yes' },
      { template: 'us', defaultLabel: { level: 'Q' } },
      { template: 'us', defaultLabel: { level: 'C', compartments: ['GAMMA'] } },
      { template: 'corporate', defaultLabel: { level: 'internal', noforn: true } },
      { template: 'us', notify: { emails: ['not an address'] } },
    ])
      await expect(define(input)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(await api.getScheme(f.ownerCredential, { tenantId })).toBeNull();
    await expect(
      api.updateScheme(f.ownerCredential, { tenantId, interimAllowed: true }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    const scheme = await define({
      definition: usWithCompartments(),
      requireLabels: ['document', '*', 'document'],
      defaultLabel: { level: 'C' },
      guestCeiling: 'C',
      notify: { emails: ['Security@Acme.test', 'security@acme.test'] },
    });
    expect(scheme).toMatchObject({
      name: 'Acme',
      requireLabels: ['*', 'document'],
      defaultLabel: { level: 'C' },
      guestCeiling: 'C',
      notify: { emails: ['security@acme.test'] },
    });
    await expect(
      api.updateScheme(f.ownerCredential, { tenantId, template: 'uk' } as never),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const base = usWithCompartments();
    const withoutC = {
      ...base,
      levels: base.levels.filter((level: { id: string }) => level.id !== 'C'),
    };
    // Settings that name a level must follow the definition: drop them first.
    await expect(
      api.updateScheme(f.ownerCredential, { tenantId, definition: withoutC }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      api.updateScheme(f.ownerCredential, { tenantId, definition: withoutC, defaultLabel: null }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // Levels and compartments that only ended clearances used are free to go; a suspended one still holds them.
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: bob.id,
      level: 'C',
      citizenship: ['USA'],
    });
    await api.readIn(f.ownerCredential, { tenantId, identityId: bob.id, compartmentId: 'HCS' });
    await api.revoke(f.ownerCredential, {
      tenantId,
      identityId: bob.id,
      reason: 'left the program',
    });
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: carol.id,
      level: 'TS',
      citizenship: ['USA'],
    });
    await api.suspend(f.ownerCredential, {
      tenantId,
      identityId: carol.id,
      reason: 'review',
      notifyPerson: false,
    });
    await expect(
      api.updateScheme(f.ownerCredential, {
        tenantId,
        definition: {
          ...withoutC,
          levels: withoutC.levels.filter((level: { id: string }) => level.id !== 'TS'),
        },
        defaultLabel: null,
        guestCeiling: null,
      }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    const updated = await api.updateScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme programs',
      definition: {
        ...withoutC,
        compartments: [{ id: 'GAMMA', name: 'Gamma renamed' }],
      },
      defaultLabel: null,
      guestCeiling: null,
      notify: null,
      requireLabels: [],
    });
    expect(updated.definition.levels.map((level) => [level.id, level.rank])).toEqual([
      ['U', 0],
      ['S', 2],
      ['TS', 3],
    ]);
    expect(updated.definition.compartments).toEqual([{ id: 'GAMMA', name: 'Gamma renamed' }]);
    expect(updated).toMatchObject({ name: 'Acme programs', requireLabels: [], guestCeiling: null });
    expect(updated).not.toHaveProperty('defaultLabel');
    expect(updated).not.toHaveProperty('notify');
    // A level removed cannot come back below the levels kept.
    await expect(
      api.updateScheme(f.ownerCredential, { tenantId, definition: base }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const [update] = (await auditOf(f, 'classification:scheme-update')).filter(
      (event) => event.metadata?.version === 2,
    );
    expect(update?.metadata).toMatchObject({
      changed: ['definition', 'name', 'requireLabels', 'defaultLabel', 'guestCeiling', 'notify'],
      levels: ['U', 'S', 'TS'],
      compartments: ['GAMMA'],
    });
    expect(JSON.stringify(update?.metadata)).not.toContain('Gamma renamed');
  });

  it('requires its permissions, and a recent sign-in for everything that widens access', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    await api.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      definition: usWithCompartments(),
      adjudication: 'unrestricted',
    });
    const officer = await administrator(f, 'olga', officerPermissions);
    const mallory = await administrator(f, 'mallory', ['documents:read']);
    const sam = await administrator(f, 'sam', ['iam:clearances:suspend']);
    const carol = await f.member('carol');
    const dave = await f.member('dave');
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: carol.id,
      level: 'S',
      citizenship: ['USA'],
    });
    await api.readIn(f.ownerCredential, { tenantId, identityId: carol.id, compartmentId: 'GAMMA' });
    await api.label(officer.credential, {
      tenantId,
      type: 'document',
      id: 'brief',
      label: { level: 'S' },
    });

    const m = mallory.credential;
    const person = { tenantId, identityId: carol.id };
    const document = { tenantId, type: 'document', id: 'brief' };
    for (const call of [
      () => api.getScheme(m, { tenantId }),
      () => api.defineScheme(m, { tenantId, name: 'Mine', template: 'uk' }),
      () => api.updateScheme(m, { tenantId, interimAllowed: true }),
      () => api.grant(m, { tenantId, identityId: dave.id, level: 'C', citizenship: [] }),
      () => api.update(m, { ...person, citizenship: [] }),
      () => api.readIn(m, { ...person, compartmentId: 'HCS' }),
      () => api.debrief(m, { ...person, compartmentId: 'GAMMA' }),
      () => api.suspend(m, { ...person, reason: 'curious' }),
      () => api.reinstate(m, person),
      () => api.revoke(m, { ...person, reason: 'curious' }),
      () => api.get(m, person),
      () => api.list(m, { tenantId }),
      () => api.explain(m, { ...person, type: 'document', id: 'brief' }),
      () => api.label(m, { ...document, label: { level: 'TS' } }),
      () => api.declassify(m, { ...document, label: null, reason: 'curious' }),
      () => api.getLabel(m, document),
      () => api.listLabels(m, { tenantId }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
    const refusals = await f.database.transaction((tx) =>
      tx.find<AuditEvent>('audit', { tenantId, actorId: mallory.identity.id, outcome: 'deny' }),
    );
    expect(refusals.length).toBeGreaterThanOrEqual(17);
    // The templates and one's own clearance need no permission.
    expect(await api.templates(m)).toHaveLength(4);
    expect(await api.mine(m, { tenantId })).toMatchObject({ clearance: null });
    // Officers change no scheme: that is iam:classifications:manage.
    await expect(
      api.updateScheme(officer.credential, { tenantId, interimAllowed: true }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // iam:clearances:suspend alone suspends, and nothing else.
    await expect(
      api.grant(sam.credential, { tenantId, identityId: dave.id, level: 'C', citizenship: [] }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // Past the recent sign-in window: what widens access is refused, what narrows it or reads still works.
    f.advance(6 * 60_000);
    const o = officer.credential;
    for (const call of [
      () => api.updateScheme(f.ownerCredential, { tenantId, interimAllowed: true }),
      () => api.grant(o, { tenantId, identityId: dave.id, level: 'C', citizenship: [] }),
      () => api.update(o, { ...person, citizenship: ['GBR', 'USA'] }),
      () => api.readIn(o, { ...person, compartmentId: 'HCS' }),
      () => api.revoke(o, { ...person, reason: 'done' }),
      () => api.declassify(o, { ...document, label: { level: 'C' }, reason: 'reviewed' }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    expect(await api.label(o, { ...document, label: { level: 'TS' } })).toMatchObject({
      version: 2,
    });
    expect(await api.debrief(o, { ...person, compartmentId: 'GAMMA' })).toMatchObject({
      readIns: [],
    });
    expect(await api.suspend(sam.credential, { ...person, reason: 'incident' })).toMatchObject({
      status: 'suspended',
    });
    expect(await api.get(o, person)).toMatchObject({ effectiveStatus: 'suspended' });
    expect((await api.list(o, { tenantId })).total).toBe(1);
  });

  it('never lets anyone adjudicate their own clearance, nor guests or impersonators adjudicate', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    await api.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      template: 'us',
      adjudication: 'unrestricted',
    });
    const alice = await administrator(f, 'alice', officerPermissions);
    const carol = await f.member('carol');
    const dave = await f.member('dave');
    const erin = await f.member('erin');
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      level: 'S',
      citizenship: ['USA'],
    });
    await api.grant(alice.credential, {
      tenantId,
      identityId: carol.id,
      level: 'C',
      citizenship: ['USA'],
    });
    // Taking one's own access away is allowed; giving it back is another officer's call.
    await api.suspend(alice.credential, {
      tenantId,
      identityId: alice.identity.id,
      reason: 'self-report',
      notifyPerson: false,
    });
    for (const call of [
      () => api.reinstate(alice.credential, { tenantId, identityId: alice.identity.id }),
      () =>
        api.update(alice.credential, {
          tenantId,
          identityId: alice.identity.id,
          level: 'TS',
        }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      await api.reinstate(f.ownerCredential, { tenantId, identityId: alice.identity.id }),
    ).toMatchObject({ status: 'active', updatedBy: f.ownerId });

    // An agent's sessions include its sponsor: it adjudicates others, never the sponsor or itself.
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId,
      name: 'Alice’s clerk',
      sponsorId: alice.identity.id,
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId,
      roleId: alice.role.id,
      subjectType: 'identity',
      subjectId: agent.id,
    });
    const key = {
      token: (
        await f.iam.api.credentials.create(f.ownerCredential, { tenantId, identityId: agent.id })
      ).token,
    };
    expect(
      await api.grant(key, { tenantId, identityId: dave.id, level: 'C', citizenship: [] }),
    ).toMatchObject({ grantedBy: agent.id });
    for (const call of [
      () => api.update(key, { tenantId, identityId: alice.identity.id, citizenship: [] }),
      () => api.grant(key, { tenantId, identityId: agent.id, level: 'C', citizenship: [] }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // Guests may hold an officer's role, yet never act as one (reading is not adjudicating).
    const guest = await addGuest(f, 'gina', { roleIds: [alice.role.id] });
    expect(await api.get(guest.credential, { tenantId, identityId: carol.id })).toMatchObject({
      level: { id: 'C' },
    });
    for (const call of [
      () => api.suspend(guest.credential, { tenantId, identityId: carol.id, reason: 'x' }),
      () =>
        api.grant(guest.credential, { tenantId, identityId: erin.id, level: 'U', citizenship: [] }),
      () => api.debrief(guest.credential, { tenantId, identityId: carol.id, compartmentId: 'X' }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await api.get(f.ownerCredential, { tenantId, identityId: carol.id })).toMatchObject({
      status: 'active',
    });
    expect(await api.get(f.ownerCredential, { tenantId, identityId: erin.id })).toBeNull();

    // Nothing changes while viewing as a member.
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const viewAs = {
      token: (
        await f.iam.api.identities.impersonate(await f.ownerSignIn(), {
          tenantId,
          identityId: alice.identity.id,
          reason: 'support',
        })
      ).token,
    };
    for (const call of [
      () => api.suspend(viewAs, { tenantId, identityId: carol.id, reason: 'x' }),
      () => api.debrief(viewAs, { tenantId, identityId: carol.id, compartmentId: 'X' }),
      () => api.label(viewAs, { tenantId, type: 'document', id: 'x', label: { level: 'C' } }),
      () => api.mine(viewAs, { tenantId }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED' });
    expect(await api.get(f.ownerCredential, { tenantId, identityId: carol.id })).toMatchObject({
      status: 'active',
    });
  });

  it('bootstraps only for owners and root, while nobody able to use the level holds it', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    await api.defineScheme(f.ownerCredential, { tenantId, name: 'Acme', template: 'us' });
    const rootId = (await f.iam.api.auth.getSession(f.rootCredential)).identity.id;
    const bob = await administrator(f, 'bob', officerPermissions);
    const alice = await f.member('alice');
    const carol = await f.member('carol');
    const dave = await f.member('dave');
    // An officer holding nothing cannot bootstrap: only an owner of the tenant or root may.
    await expect(
      api.grant(bob.credential, {
        tenantId,
        identityId: alice.id,
        level: 'TS',
        citizenship: ['USA'],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      await api.grant(f.rootCredential, {
        tenantId,
        identityId: alice.id,
        level: 'TS',
        citizenship: ['USA'],
      }),
    ).toMatchObject({ grantedBy: rootId, effectiveLevel: 'TS' });
    // Once someone holds it (or more), root and the owner hold no more authority than any uncleared officer.
    for (const credential of [f.rootCredential, f.ownerCredential])
      await expect(
        api.grant(credential, {
          tenantId,
          identityId: carol.id,
          level: 'U',
          citizenship: ['USA'],
        }),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // A disabled holder holds nothing, and neither does an ended clearance.
    await f.iam.api.identities.setStatus(f.ownerCredential, {
      tenantId,
      identityId: alice.id,
      status: 'disabled',
    });
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: carol.id,
      level: 'TS',
      citizenship: ['USA'],
      expiresAt: f.now() + 3_600_000,
    });
    await expect(
      api.grant(f.ownerCredential, {
        tenantId,
        identityId: dave.id,
        level: 'TS',
        citizenship: ['USA'],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    f.advance(2 * 3_600_000);
    await api.grant(await f.ownerSignIn(), {
      tenantId,
      identityId: dave.id,
      level: 'TS',
      citizenship: ['USA'],
    });
    const grants = await auditOf(f, 'clearance:grant');
    expect(
      grants
        .map((event) => [event.resourceId, event.actorId, event.metadata?.bootstrap])
        .sort((a, b) => String(a[0]).localeCompare(String(b[0]))),
    ).toEqual(
      [
        [alice.id, rootId, true],
        [carol.id, f.ownerId, true],
        [dave.id, f.ownerId, true],
      ].sort((a, b) => String(a[0]).localeCompare(String(b[0]))),
    );
  });

  it('counts interim clearances and expiry at decision time', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    const day = 86_400_000;
    await api.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      template: 'us',
      adjudication: 'unrestricted',
      interimAllowed: true,
    });
    const officer = await administrator(f, 'olga', officerPermissions);
    const carol = await administrator(f, 'carol', ['documents:read']);
    const dave = await f.member('dave');
    await api.label(officer.credential, {
      tenantId,
      type: 'document',
      id: 'brief',
      label: { level: 'S' },
    });
    const person = { tenantId, identityId: carol.identity.id };
    const expiresAt = f.now() + 2 * day;
    expect(
      await api.grant(f.ownerCredential, {
        ...person,
        level: 'S',
        citizenship: ['USA'],
        interim: true,
        expiresAt,
        reinvestigationDue: f.now() + 365 * day,
        investigation: { kind: 'Tier 3', completedAt: f.now() - day },
      }),
    ).toMatchObject({
      status: 'interim',
      effectiveStatus: 'interim',
      effectiveLevel: 'S',
      expiresAt,
      investigation: { kind: 'Tier 3' },
    });
    expect(await canRead(f, carol.credential, 'brief')).toBe(true);
    // A scheme that stops allowing interim clearances stops counting them at once.
    await api.updateScheme(f.ownerCredential, { tenantId, interimAllowed: false });
    expect(await api.get(f.ownerCredential, person)).toMatchObject({
      status: 'interim',
      effectiveStatus: 'none',
    });
    expect(await canRead(f, carol.credential, 'brief')).toBe(false);
    expect(await api.mine(carol.credential, { tenantId })).toMatchObject({
      clearance: { status: 'interim', effectiveStatus: 'none', expiresAt },
    });
    await expect(api.update(f.ownerCredential, { ...person, interim: true })).rejects.toMatchObject(
      { code: 'INVALID_INPUT' },
    );
    expect(await api.update(officer.credential, { ...person, interim: false })).toMatchObject({
      status: 'active',
      effectiveStatus: 'active',
    });
    expect(await canRead(f, carol.credential, 'brief')).toBe(true);
    const [promoted] = await auditOf(f, 'clearance:update');
    expect(promoted?.metadata).toEqual({ level: 'S', status: 'active', changed: ['interim'] });

    // Expiry is computed against the clock, not by a job.
    f.advance(3 * day);
    expect(await api.get(officer.credential, person)).toMatchObject({
      status: 'active',
      effectiveStatus: 'expired',
    });
    expect(await canRead(f, carol.credential, 'brief')).toBe(false);
    expect(
      (await api.list(officer.credential, { tenantId, expiringWithinDays: 1 })).clearances.map(
        (item) => item.identityId,
      ),
    ).toEqual([carol.identity.id]);
    const fresh = await f.ownerSignIn();
    const renewed = await api.update(fresh, { ...person, expiresAt: null });
    expect(renewed).toMatchObject({ effectiveStatus: 'active' });
    expect(renewed).not.toHaveProperty('expiresAt');
    expect(await canRead(f, carol.credential, 'brief')).toBe(true);
    expect((await api.list(fresh, { tenantId, expiringWithinDays: 1 })).total).toBe(0);

    const grantDave = (input: Record<string, unknown>) =>
      api.grant(fresh, {
        tenantId,
        identityId: dave.id,
        level: 'C',
        citizenship: ['USA'],
        ...input,
      } as never);
    for (const input of [
      { expiresAt: f.now() - 1 },
      { expiresAt: f.now() + 21 * 365 * day },
      { reinvestigationDue: f.now() + 21 * 365 * day },
      { investigation: { kind: 'Tier 5', completedAt: f.now() + 2 * day } },
      { investigation: { kind: '', completedAt: f.now() } },
      { citizenship: ['usa'] },
      { citizenship: 'USA' },
      {
        citizenship: ['AAA', 'BBB', 'CCC', 'DDD', 'EEE', 'FFF', 'GGG', 'HHH', 'III', 'JJJ', 'KKK'],
      },
      { level: 'COSMIC' },
      { interim: 'yes' },
      { interim: true },
    ])
      await expect(grantDave(input)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.api.identities.setStatus(fresh, {
      tenantId,
      identityId: dave.id,
      status: 'disabled',
    });
    await expect(grantDave({})).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(await api.get(fresh, { tenantId, identityId: dave.id })).toBeNull();
  });

  it('lists, gets and explains, dimension by dimension', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    await api.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      template: 'us',
      adjudication: 'unrestricted',
      requireLabels: ['report'],
    });
    const officer = await administrator(f, 'olga', officerPermissions);
    const alice = await administrator(f, 'alice', ['documents:read']);
    const bob = await administrator(f, 'bob', ['documents:read']);
    const carol = await f.member('carol');
    const dave = await administrator(f, 'dave', ['documents:read']);
    const o = officer.credential;
    await api.grant(o, {
      tenantId,
      identityId: alice.identity.id,
      level: 'TS',
      citizenship: ['USA'],
    });
    await api.grant(o, { tenantId, identityId: bob.identity.id, level: 'S', citizenship: ['GBR'] });
    await api.grant(o, { tenantId, identityId: carol.id, level: 'C', citizenship: ['CAN', 'USA'] });
    await api.revoke(o, {
      tenantId,
      identityId: carol.id,
      reason: 'moved on',
      notifyPerson: false,
    });
    expect(await api.get(o, { tenantId, identityId: dave.identity.id })).toBeNull();
    await expect(api.get(o, { tenantId, identityId: 'nobody' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });

    const ids = (page: { clearances: Array<{ identityId: string }> }) =>
      page.clearances.map((item) => item.identityId);
    expect(ids(await api.list(o, { tenantId }))).toEqual([
      alice.identity.id,
      bob.identity.id,
      carol.id,
    ]);
    expect(ids(await api.list(o, { tenantId, status: 'active' }))).toEqual([
      alice.identity.id,
      bob.identity.id,
    ]);
    expect(ids(await api.list(o, { tenantId, status: 'revoked' }))).toEqual([carol.id]);
    expect(ids(await api.list(o, { tenantId, level: 'S' }))).toEqual([bob.identity.id]);
    const page = await api.list(o, { tenantId, limit: 1, offset: 1 });
    expect([ids(page), page.total]).toEqual([[bob.identity.id], 3]);
    for (const input of [
      { status: 'expired' },
      { expiringWithinDays: 0 },
      { limit: 0 },
      { limit: 501 },
      { offset: -1 },
    ])
      await expect(api.list(o, { tenantId, ...input } as never)).rejects.toMatchObject({
        code: 'INVALID_INPUT',
      });

    await api.label(o, {
      tenantId,
      type: 'document',
      id: 'nf',
      label: { level: 'S', noforn: true },
    });
    await api.label(o, {
      tenantId,
      type: 'document',
      id: 'rel',
      label: { level: 'S', releasableTo: ['AUS'] },
    });
    await api.label(o, { tenantId, type: 'document', id: 'top', label: { level: 'TS' } });
    const explain = (identityId: string, id: string, type = 'document') =>
      api.explain(o, { tenantId, identityId, type, id });
    expect(await explain(bob.identity.id, 'nf')).toMatchObject({
      allowed: false,
      failure: 'noforn',
      label: { level: 'S', noforn: true },
      party: {
        identityId: bob.identity.id,
        status: 'active',
        level: 'S',
        rank: 2,
        compartments: [],
        citizenship: ['GBR'],
      },
    });
    expect(await explain(bob.identity.id, 'rel')).toMatchObject({
      allowed: false,
      failure: 'releasability',
    });
    expect(await explain(bob.identity.id, 'top')).toMatchObject({
      allowed: false,
      failure: 'level',
    });
    // Owner countries may always read what is releasable to others.
    expect(await explain(alice.identity.id, 'rel')).toMatchObject({ allowed: true });
    expect(await explain(alice.identity.id, 'nf')).toMatchObject({ allowed: true });
    const uncleared = await explain(dave.identity.id, 'nf');
    expect(uncleared).toMatchObject({
      allowed: false,
      failure: 'level',
      party: { identityId: dave.identity.id, status: 'none', rank: -1 },
    });
    expect(uncleared.party).not.toHaveProperty('level');
    expect(await explain(carol.id, 'top')).toMatchObject({
      failure: 'level',
      party: { status: 'revoked', rank: -1 },
    });
    expect(await explain(dave.identity.id, 'plain')).toMatchObject({ allowed: true, label: null });
    // A required label that is missing refuses everyone; explain says so to officers only.
    expect(await explain(alice.identity.id, 'r-1', 'report')).toMatchObject({
      allowed: false,
      failure: 'invalid-label',
      label: null,
    });
    await expect(explain('nobody', 'nf')).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // Decisions agree, and say nothing about the dimension.
    expect(await canRead(f, bob.credential, 'nf')).toBe(false);
    expect(await canRead(f, alice.credential, 'nf')).toBe(true);
    expect(await canRead(f, alice.credential, 'top')).toBe(true);
    expect(await canRead(f, bob.credential, 'rel')).toBe(false);
  });

  it('counts read-ins only while their NDA acceptance is current', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    const day = 86_400_000;
    await api.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      definition: usWithCompartments(),
      adjudication: 'unrestricted',
    });
    const officer = await administrator(f, 'olga', officerPermissions);
    const carol = await administrator(f, 'carol', ['documents:read']);
    const dave = await f.member('dave');
    const person = { tenantId, identityId: carol.identity.id };
    await api.grant(officer.credential, { ...person, level: 'S', citizenship: ['USA'] });
    await api.label(officer.credential, {
      tenantId,
      type: 'document',
      id: 'gamma-1',
      label: { level: 'C', compartments: ['GAMMA'] },
    });
    const nda = await f.iam.api.agreements.create(f.ownerCredential, {
      tenantId,
      name: 'Gamma NDA',
      content: 'I will not disclose.',
      required: false,
      reacceptAfterDays: 30,
    });
    // Accepted before the read-in: the acceptance is recorded as evidence on the read-in.
    await f.iam.api.agreements.accept(carol.credential, {
      tenantId,
      agreementId: nda.id,
      version: 1,
    });
    const readIn = await api.readIn(officer.credential, {
      ...person,
      compartmentId: 'GAMMA',
      agreementId: nda.id,
    });
    expect(readIn.readIns).toEqual([
      expect.objectContaining({
        compartmentId: 'GAMMA',
        agreementId: nda.id,
        acceptedAt: expect.any(Number),
        current: true,
      }),
    ]);
    expect(await canRead(f, carol.credential, 'gamma-1')).toBe(true);
    // A new version of the NDA must be accepted again.
    await f.iam.api.agreements.update(f.ownerCredential, {
      tenantId,
      agreementId: nda.id,
      content: 'I will not disclose, ever.',
      newVersion: true,
    });
    expect(await canRead(f, carol.credential, 'gamma-1')).toBe(false);
    expect((await api.get(officer.credential, person))?.readIns[0]?.current).toBe(false);
    await f.iam.api.agreements.accept(carol.credential, {
      tenantId,
      agreementId: nda.id,
      version: 2,
    });
    expect(await canRead(f, carol.credential, 'gamma-1')).toBe(true);
    // An acceptance older than reacceptAfterDays no longer counts.
    f.advance(31 * day);
    const again = { token: (await f.signIn('carol')).token };
    expect(await canRead(f, again, 'gamma-1')).toBe(false);
    expect(await api.mine(again, { tenantId })).toMatchObject({
      clearance: { readIns: [{ compartmentId: 'GAMMA', current: false }] },
    });
    await f.iam.api.agreements.accept(again, { tenantId, agreementId: nda.id, version: 2 });
    expect(await canRead(f, again, 'gamma-1')).toBe(true);
    // Deleting the NDA takes its acceptances with it: the read-in no longer counts.
    const fresh = await f.ownerSignIn();
    await f.iam.api.agreements.delete(fresh, { tenantId, agreementId: nda.id });
    expect(await canRead(f, again, 'gamma-1')).toBe(false);

    for (const [input, code] of [
      [{ ...person, compartmentId: 'GAMMA' }, 'CONFLICT'],
      [{ ...person, compartmentId: 'NOPE' }, 'INVALID_INPUT'],
      [{ ...person, compartmentId: 'HCS', agreementId: 'missing' }, 'NOT_FOUND'],
      [{ tenantId, identityId: dave.id, compartmentId: 'HCS' }, 'NOT_FOUND'],
    ] as const)
      await expect(api.readIn(fresh, input)).rejects.toMatchObject({ code });
    await expect(api.debrief(fresh, { ...person, compartmentId: 'HCS' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    await api.suspend(fresh, { ...person, reason: 'review', notifyPerson: false });
    await expect(api.readIn(fresh, { ...person, compartmentId: 'HCS' })).rejects.toMatchObject({
      code: 'INVALID_TRANSITION',
    });
    // Debriefing needs no recent sign-in and works on a suspended clearance too.
    f.advance(6 * 60_000);
    expect(
      await api.debrief(fresh, { ...person, compartmentId: 'GAMMA', reason: 'program closed' }),
    ).toMatchObject({ status: 'suspended', readIns: [] });
    expect((await auditOf(f, 'clearance:debrief'))[0]?.metadata).toEqual({
      compartmentId: 'GAMMA',
      reason: 'program closed',
    });
  });

  it('holds reinstatement and updates to the officer’s own clearance, compartments included', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    await api.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      definition: usWithCompartments(),
    });
    const alice = await administrator(f, 'alice', officerPermissions);
    const bob = await administrator(f, 'bob', officerPermissions);
    const dan = await administrator(f, 'dan', officerPermissions);
    const carol = await administrator(f, 'carol', ['documents:read']);
    const person = { tenantId, identityId: carol.identity.id };
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      level: 'TS',
      citizenship: ['USA'],
    });
    await api.readIn(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      compartmentId: 'GAMMA',
    });
    await api.grant(alice.credential, {
      tenantId,
      identityId: bob.identity.id,
      level: 'TS',
      citizenship: ['USA'],
    });
    await api.grant(alice.credential, {
      tenantId,
      identityId: dan.identity.id,
      level: 'S',
      citizenship: ['USA'],
    });
    await api.grant(alice.credential, { ...person, level: 'S', citizenship: ['USA'] });
    await api.readIn(alice.credential, { ...person, compartmentId: 'GAMMA' });
    await api.label(alice.credential, {
      tenantId,
      type: 'document',
      id: 'gamma-1',
      label: { level: 'S', compartments: ['GAMMA'] },
    });
    expect(await canRead(f, carol.credential, 'gamma-1')).toBe(true);
    // Raising beyond one's own level is refused, and so is changing what one could not grant.
    await expect(api.update(dan.credential, { ...person, level: 'TS' })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(
      api.update(dan.credential, {
        tenantId,
        identityId: bob.identity.id,
        citizenship: ['GBR'],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      await api.update(dan.credential, { ...person, citizenship: ['CAN', 'USA'] }),
    ).toMatchObject({ citizenship: ['CAN', 'USA'] });
    // Reinstating gives back the compartments too: an officer outside GAMMA cannot.
    await api.suspend(dan.credential, { ...person, reason: 'review', notifyPerson: false });
    expect(await canRead(f, carol.credential, 'gamma-1')).toBe(false);
    for (const credential of [bob.credential, dan.credential, f.ownerCredential])
      await expect(api.reinstate(credential, person)).rejects.toMatchObject({
        code: 'ACCESS_DENIED',
      });
    expect(await api.get(alice.credential, person)).toMatchObject({ status: 'suspended' });
    expect(await api.reinstate(alice.credential, person)).toMatchObject({
      status: 'active',
      readIns: [expect.objectContaining({ compartmentId: 'GAMMA', current: true })],
    });
    expect(await canRead(f, carol.credential, 'gamma-1')).toBe(true);
  });

  it('labels: raises in every dimension, declassifies only on purpose', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    const officer = await administrator(f, 'olga', officerPermissions);
    const o = officer.credential;
    const document = (id: string) => ({ tenantId, type: 'document', id });
    // Without a scheme there is nothing to label against.
    await expect(api.label(o, { ...document('a'), label: { level: 'C' } })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    await api.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      definition: usWithCompartments(),
      adjudication: 'unrestricted',
    });
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: officer.identity.id,
      level: 'TS',
      citizenship: ['USA'],
    });
    await api.readIn(f.ownerCredential, {
      tenantId,
      identityId: officer.identity.id,
      compartmentId: 'HCS',
    });
    const first = await api.label(o, {
      ...document('a'),
      label: { level: 'C', releasableTo: ['GBR', 'AUS'] },
    });
    expect(first).toMatchObject({
      label: { level: 'C', releasableTo: ['AUS', 'GBR'] },
      levelName: 'CONFIDENTIAL',
      inheritToChildren: false,
      labeledBy: officer.identity.id,
      version: 1,
    });
    // Releasable to fewer countries, NOFORN, a compartment: all raise.
    for (const label of [
      { level: 'C', releasableTo: ['AUS'] },
      { level: 'C', releasableTo: [] },
      { level: 'C', noforn: true },
      { level: 'S', noforn: true, compartments: ['HCS'] },
    ])
      await api.label(o, { ...document('a'), label });
    const same = await api.label(o, {
      ...document('a'),
      label: { level: 'S', noforn: true, compartments: ['HCS'] },
    });
    expect(same.version).toBe(5);
    // Releasable again, or to more, or without the compartment: declassifications.
    for (const label of [
      { level: 'S', compartments: ['HCS'] },
      { level: 'S', noforn: true },
      { level: 'C', noforn: true, compartments: ['HCS'] },
      { level: 'S', compartments: ['HCS'], releasableTo: ['AUS'] },
    ])
      await expect(api.label(o, { ...document('a'), label })).rejects.toMatchObject({
        code: 'ACCESS_DENIED',
      });
    for (const label of [
      { level: 'Q' },
      { level: 'C', releasableTo: ['gbr'] },
      { level: 'C', caveats: ['NOFORN'] },
      'C',
    ])
      await expect(api.label(o, { ...document('b'), label: label as never })).rejects.toMatchObject(
        { code: 'INVALID_INPUT' },
      );
    // Declassifying: a reason, a label (or null) and an existing label.
    for (const [input, code] of [
      [{ ...document('a'), label: { level: 'C' } }, 'INVALID_INPUT'],
      [{ ...document('a'), reason: 'x' }, 'INVALID_INPUT'],
      [{ ...document('none'), label: null, reason: 'x' }, 'NOT_FOUND'],
      [{ ...document('a'), label: { level: 'Q' }, reason: 'x' }, 'INVALID_INPUT'],
    ] as const)
      await expect(api.declassify(o, input as never)).rejects.toMatchObject({ code });
    expect(
      await api.declassify(o, { ...document('a'), label: { level: 'C' }, reason: 'reviewed' }),
    ).toMatchObject({ label: { level: 'C' }, version: 6 });
    // An officer cleared below the label cannot declassify it, even with the permission.
    await api.label(o, { ...document('t'), label: { level: 'TS', compartments: ['GAMMA'] } });
    await expect(
      api.declassify(o, { ...document('t'), label: null, reason: 'x' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await api.readIn(f.ownerCredential, {
      tenantId,
      identityId: officer.identity.id,
      compartmentId: 'GAMMA',
    });
    expect(await api.declassify(o, { ...document('t'), label: null, reason: 'done' })).toBeNull();

    for (const id of ['c', 'd', 'e'])
      await api.label(o, { ...document(id), label: { level: id === 'd' ? 'S' : 'U' } });
    await api.label(o, { tenantId, type: 'memo', id: 'm', label: { level: 'U' } });
    const all = await api.listLabels(o, { tenantId });
    expect(all.labels.map((item) => `${item.type}/${item.id}`)).toEqual([
      'document/a',
      'document/c',
      'document/d',
      'document/e',
      'memo/m',
    ]);
    expect(
      (await api.listLabels(o, { tenantId, type: 'document', level: 'U' })).labels.map(
        (item) => item.id,
      ),
    ).toEqual(['c', 'e']);
    const second = await api.listLabels(o, { tenantId, limit: 2, offset: 2 });
    expect([second.labels.map((item) => item.id), second.total]).toEqual([['d', 'e'], 5]);
    await expect(api.listLabels(o, { tenantId, type: 'iam' })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
  });

  it('keeps organizations apart and child tenants under their ancestor’s scheme', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    const globex = await otherOrganization(f, 'Globex', 'globex');
    // Sibling organizations each define their own.
    await api.defineScheme(f.ownerCredential, { tenantId, name: 'Acme', template: 'us' });
    await api.defineScheme(globex.ownerCredential, {
      tenantId: globex.tenantId,
      name: 'Globex',
      template: 'uk',
    });
    const alice = await administrator(f, 'alice', ['documents:read']);
    const gus = await f.iam.api.identities.create(globex.ownerCredential, {
      tenantId: globex.tenantId,
      email: 'gus@globex.test',
      name: 'gus',
      password: 'a strong gus password',
    });
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      level: 'S',
      citizenship: ['USA'],
    });
    await api.grant(globex.ownerCredential, {
      tenantId: globex.tenantId,
      identityId: gus.id,
      level: 'SECRET',
      citizenship: ['GBR'],
    });
    // Another organization's people and records are not found from here, and its tenant is not ours to act in.
    for (const call of [
      () => api.get(f.ownerCredential, { tenantId, identityId: gus.id }),
      () =>
        api.grant(f.ownerCredential, {
          tenantId,
          identityId: gus.id,
          level: 'S',
          citizenship: ['USA'],
        }),
      () => api.suspend(f.ownerCredential, { tenantId, identityId: gus.id, reason: 'x' }),
      () =>
        api.explain(f.ownerCredential, {
          tenantId,
          identityId: gus.id,
          type: 'document',
          id: 'x',
        }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'NOT_FOUND' });
    for (const call of [
      () => api.get(f.ownerCredential, { tenantId: globex.tenantId, identityId: gus.id }),
      () => api.list(f.ownerCredential, { tenantId: globex.tenantId }),
      () => api.getScheme(f.ownerCredential, { tenantId: globex.tenantId }),
      () =>
        api.label(f.ownerCredential, {
          tenantId: globex.tenantId,
          type: 'document',
          id: 'x',
          label: { level: 'OFFICIAL' },
        }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(api.mine(alice.credential, { tenantId: globex.tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // An NDA of another organization cannot back a read-in here.
    await api.updateScheme(f.ownerCredential, {
      tenantId,
      definition: usWithCompartments(),
    });
    const foreign = await f.iam.api.agreements.create(globex.ownerCredential, {
      tenantId: globex.tenantId,
      name: 'Globex NDA',
      content: 'Theirs.',
      required: false,
    });
    await expect(
      api.readIn(f.ownerCredential, {
        tenantId,
        identityId: alice.identity.id,
        compartmentId: 'GAMMA',
        agreementId: foreign.id,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // Labels are per tenant.
    await api.label(f.ownerCredential, {
      tenantId,
      type: 'document',
      id: 'shared-id',
      label: { level: 'S' },
    });
    expect(
      (await api.listLabels(globex.ownerCredential, { tenantId: globex.tenantId })).total,
    ).toBe(0);
    expect(
      (
        await api.getLabel(globex.ownerCredential, {
          tenantId: globex.tenantId,
          type: 'document',
          id: 'shared-id',
        })
      ).label,
    ).toBeNull();
    expect(
      (await api.list(globex.ownerCredential, { tenantId: globex.tenantId })).clearances.map(
        (item) => item.identityId,
      ),
    ).toEqual([gus.id]);

    // A project below Acme lives under Acme’s scheme, and keeps its own records.
    const project = await f.iam.api.tenants.create(f.ownerCredential, {
      parentId: tenantId,
      name: 'Apollo',
      type: 'project',
      ownerEmail: 'apollo@acme.test',
    });
    await f.iam.auth.dispatchOutbox();
    const invitation = f.inbox.find(
      (message) =>
        message.tenantId === project.tenant.id && message.template === 'owner-invitation',
    )!;
    const apollo = await f.iam.api.tenants.acceptInvitation({
      tenantId: project.tenant.id,
      token: invitation.payload.token!,
      name: 'Apollo owner',
      password: 'a strong apollo owner password',
    });
    if (!('token' in apollo)) throw new Error('Unexpected MFA');
    const projectOwner = { token: apollo.token };
    const projectId = project.tenant.id;
    expect(await api.getScheme(projectOwner, { tenantId: projectId })).toMatchObject({
      tenantId,
      inherited: true,
      name: 'Acme',
    });
    await expect(
      api.defineScheme(projectOwner, { tenantId: projectId, name: 'Apollo', template: 'uk' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const pat = await f.iam.api.identities.create(projectOwner, {
      tenantId: projectId,
      email: 'pat@apollo.test',
      name: 'pat',
      password: 'a strong pat password',
    });
    // Nobody in Acme’s subtree holds TS yet, so the project owner may bootstrap it.
    expect(
      await api.grant(projectOwner, {
        tenantId: projectId,
        identityId: pat.id,
        level: 'TS',
        citizenship: ['USA'],
      }),
    ).toMatchObject({ schemeTenantId: tenantId, effectiveStatus: 'active' });
    await expect(
      api.get(f.ownerCredential, { tenantId, identityId: pat.id }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(
      (await api.list(f.ownerCredential, { tenantId })).clearances.map((item) => item.identityId),
    ).toEqual([alice.identity.id]);
    // ...and that TS now counts across the subtree: Acme's owner can no longer bootstrap it.
    await expect(
      api.update(await f.ownerSignIn(), {
        tenantId,
        identityId: alice.identity.id,
        level: 'TS',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});
