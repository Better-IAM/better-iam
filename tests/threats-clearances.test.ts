import { afterEach, describe, expect, it } from 'vitest';
import { classificationTemplates, type AuditEvent } from '@better-iam/core';
import type {
  BetterIamOptions,
  ThreatDetection,
  ThreatPlaybook,
  ThreatResponse,
} from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';
import { administrator } from './support/guests.js';

afterEach(closeFixtures);

/**
 * Threat detection meets security clearances: the `classified-access-attempts` rule counts clearance refusals (deny
 * events with the server's `{ mandatory: 'clearance' }` marker) per responsible actor, and the `suspend-clearance`
 * response suspends a person's clearance by hand (with `iam:clearances:suspend` as well) or from a playbook (written
 * only by someone who may suspend clearances, and never touching owners or root administrators). Only an officer's
 * `clearances.reinstate` lifts it.
 */

const minute = 60_000;
const hour = 60 * minute;
const day = 24 * hour;

type Credential = { token: string };

const resourceTypes = {
  document: { actions: ['documents:read', 'documents:write', 'documents:delete'] },
};

const officerPermissions = [
  'iam:clearances:read',
  'iam:clearances:adjudicate',
  'iam:clearances:suspend',
];

/** Acme with clearances, a US scheme any officer adjudicates, and documents `secret` and `secret-2` (TS), `memo` (C). */
async function setup(overrides: Partial<BetterIamOptions> = {}) {
  const f = await organizationFixture({
    clearances: {},
    permissions: { resourceTypes },
    ...overrides,
  });
  const { tenantId } = f;
  const owner = f.ownerCredential;
  await f.iam.api.clearances.defineScheme(owner, {
    tenantId,
    name: 'Acme',
    definition: {
      ...JSON.parse(JSON.stringify(classificationTemplates.us)),
      compartments: [{ id: 'GAMMA', name: 'Gamma codeword' }],
    },
    adjudication: 'unrestricted',
  });
  for (const [id, level] of [
    ['secret', 'TS'],
    ['secret-2', 'TS'],
    ['memo', 'C'],
  ] as const)
    await f.iam.api.clearances.label(owner, {
      tenantId,
      type: 'document',
      id,
      label: { level },
    });
  const readers = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Readers',
    permissions: ['documents:read'],
  });
  /** A member holding the readers role, signed in. */
  const reader = async (name: string) => {
    const identity = await f.member(name);
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: readers.id,
      subjectType: 'identity',
      subjectId: identity.id,
    });
    return { identity, credential: { token: (await f.signIn(name)).token } };
  };
  const officer = await administrator(f, 'officer', officerPermissions);
  const grant = (identityId: string, level: string) =>
    f.iam.api.clearances.grant(officer.credential, {
      tenantId,
      identityId,
      level,
      citizenship: ['USA'],
    });
  const reads = async (credential: Credential, id: string, action = 'documents:read') =>
    (
      await f.iam.authorize({
        ...credential,
        tenantId,
        action,
        resource: { type: 'document', id },
      })
    ).allowed;
  return { f, tenantId, reader, officer, grant, reads };
}

async function detect(f: OrganizationFixture) {
  await f.iam.auth.settleBookkeeping();
  return f.iam.detectThreats({ tenantId: f.tenantId });
}

async function detections(f: OrganizationFixture, ruleId: string): Promise<ThreatDetection[]> {
  return (
    await f.iam.store.find<ThreatDetection>('threatDetections', { tenantId: f.tenantId, ruleId })
  ).sort((a, b) => a.occurredAt - b.occurredAt || a.detectedAt - b.detectedAt);
}

async function audit(f: OrganizationFixture, action: string): Promise<AuditEvent[]> {
  return (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId, action })).sort(
    (a, b) => (a.sequence ?? 0) - (b.sequence ?? 0),
  );
}

async function responsesOf(f: OrganizationFixture, incidentId: string) {
  return (
    await f.iam.api.threats.getIncident(f.ownerCredential, { tenantId: f.tenantId, incidentId })
  ).responses;
}

describe('threat detection with security clearances', () => {
  it('lists the classified-access-attempts rule and tunes it within its bounds', async () => {
    const { f, tenantId } = await setup();
    const threats = f.iam.api.threats;
    const rules = await threats.rules(f.ownerCredential, { tenantId });
    expect(rules.find((rule) => rule.id === 'classified-access-attempts')).toMatchObject({
      category: 'activity',
      subject: 'identity',
      technique: 'T1213',
      defaults: { enabled: true, severity: 'high', threshold: 3, windowMs: hour },
      tunable: { threshold: [1, 1000], windowMs: [minute, 7 * day] },
      enabled: true,
      threshold: 3,
      windowMs: hour,
    });
    const owner = await f.ownerSignIn();
    for (const bad of [{ threshold: 0 }, { threshold: 1001 }, { windowMs: 8 * day }])
      await expect(
        threats.configure(owner, { tenantId, rules: { 'classified-access-attempts': bad } }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const view = await threats.configure(owner, {
      tenantId,
      rules: { 'classified-access-attempts': { threshold: 1, windowMs: 7 * day } },
    });
    expect(view.rules['classified-access-attempts']).toMatchObject({
      threshold: 1,
      windowMs: 7 * day,
    });
  });

  it('counts clearance refusals per responsible actor, never other denials, and names no label', async () => {
    const { f, tenantId, reader, grant, reads } = await setup();
    const alice = await reader('alice');
    await grant(alice.identity.id, 'S');
    await detect(f);

    // Ordinary refusals (no grant for the action, on unlabeled and labeled documents alike) are not clearance ones.
    for (const id of ['plain', 'plain', 'memo', 'memo'])
      expect(await reads(alice.credential, id, 'documents:write')).toBe(false);
    expect(await reads(alice.credential, 'memo')).toBe(true);
    expect(await reads(alice.credential, 'secret')).toBe(false);
    expect(await reads(alice.credential, 'secret')).toBe(false);
    await detect(f);
    expect(await detections(f, 'classified-access-attempts')).toEqual([]);
    // Each clearance refusal is a denial of the requested action marked as such, and nothing else.
    const refusals = (await audit(f, 'documents:read')).filter((event) => event.outcome === 'deny');
    expect(refusals.map((event) => [event.resourceId, event.metadata])).toEqual([
      ['secret', { mandatory: 'clearance' }],
      ['secret', { mandatory: 'clearance' }],
    ]);
    expect((await audit(f, 'documents:write')).every((event) => event.metadata === undefined)).toBe(
      true,
    );

    // The third within the hour trips it.
    expect(await reads(alice.credential, 'secret-2')).toBe(false);
    expect((await detect(f)).detections).toBe(1);
    const [detection] = await detections(f, 'classified-access-attempts');
    expect(detection).toMatchObject({
      severity: 'high',
      status: 'open',
      identityId: alice.identity.id,
      subject: { type: 'identity', id: alice.identity.id, name: 'alice (alice@acme.test)' },
      metadata: { peak: 3, threshold: 3, windowMs: hour, resources: 2, agent: false },
      evidence: { count: 3, actions: ['documents:read'] },
    });
    expect(detection!.title).toBe('Repeated classified access attempts: alice (alice@acme.test)');
    expect(detection!.summary).toBe(
      'alice (alice@acme.test) was refused 3 times for want of a clearance within 1 hour, on 2 classified resources.',
    );
    // Neither the label nor the clearance shows: no level, compartment, or label field anywhere in the detection.
    const stored = JSON.stringify(detection);
    for (const secret of ['"TS"', 'TOP SECRET', 'GAMMA', 'Gamma', '"S"', 'classification'])
      expect(stored).not.toContain(secret);
    // One burst, one detection: a fourth refusal joins it.
    expect(await reads(alice.credential, 'secret')).toBe(false);
    expect((await detect(f)).detections).toBe(0);
    expect(
      await f.iam.api.threats.getRisk(f.ownerCredential, {
        tenantId,
        identityId: alice.identity.id,
      }),
    ).toMatchObject({ level: 'medium', score: 50 });
    // The burst stayed below the general denial-burst threshold.
    expect(await detections(f, 'denial-burst')).toEqual([]);
  });

  it('holds the administrator behind a "view as" session responsible, not the member', async () => {
    const { f, tenantId, reader, grant, reads } = await setup();
    const alice = await reader('alice');
    await grant(alice.identity.id, 'TS');
    const owner = await f.ownerSignIn();
    await f.iam.api.tenants.setAuthPolicy(owner, {
      tenantId,
      authPolicy: { allowImpersonation: true },
    });
    await detect(f);
    const viewing = await f.iam.api.identities.impersonate(owner, {
      tenantId,
      identityId: alice.identity.id,
      reason: 'what can alice read?',
    });
    // Alice is cleared for everything; the owner behind the session is cleared for nothing.
    expect(await reads(alice.credential, 'secret')).toBe(true);
    for (const id of ['secret', 'secret-2', 'memo'])
      expect(await reads({ token: viewing.token }, id)).toBe(false);
    const refusals = (await audit(f, 'documents:read')).filter((event) => event.outcome === 'deny');
    expect(refusals).toHaveLength(3);
    expect(
      refusals.every(
        (event) =>
          event.actorId === alice.identity.id &&
          event.impersonatorId === f.ownerId &&
          event.metadata?.mandatory === 'clearance',
      ),
    ).toBe(true);
    expect((await detect(f)).detections).toBe(1);
    const [detection] = await detections(f, 'classified-access-attempts');
    expect(detection).toMatchObject({
      identityId: f.ownerId,
      subject: { type: 'identity', id: f.ownerId },
      metadata: { peak: 3, resources: 3, viewedAs: [alice.identity.id] },
    });
    expect(detection!.summary).toContain('while viewing as someone else');
    expect(
      await f.iam.api.threats.getRisk(f.ownerCredential, {
        tenantId,
        identityId: alice.identity.id,
      }),
    ).toMatchObject({ level: 'none', score: 0 });
  });

  it('suspends the clearance from a playbook; owners are protected; only reinstate lifts it', async () => {
    const { f, tenantId, reader, officer, grant, reads } = await setup();
    const alice = await reader('alice');
    const carol = await reader('carol');
    await grant(alice.identity.id, 'S');
    await grant(f.ownerId, 'C');
    const owner = await f.ownerSignIn();
    const playbook = await f.iam.api.threats.createPlaybook(owner, {
      tenantId,
      name: 'Suspend on classified probing',
      trigger: { ruleIds: ['classified-access-attempts'] },
      actions: [{ kind: 'suspend-clearance' }],
    });
    await detect(f);

    expect(await reads(alice.credential, 'memo')).toBe(true);
    for (const id of ['secret', 'secret-2', 'secret']) {
      expect(await reads(alice.credential, id)).toBe(false);
      expect(await reads(carol.credential, id)).toBe(false);
      expect(await reads(owner, id)).toBe(false);
    }
    const run = await detect(f);
    expect(run).toMatchObject({ detections: 3, responses: 1 });
    const found = await detections(f, 'classified-access-attempts');
    const about = (identityId: string) => found.find((item) => item.identityId === identityId)!;

    // Alice: suspended under the threat-detection actor, filed under the incident.
    const aliceIncident = about(alice.identity.id).incidentId!;
    const [suspension] = await responsesOf(f, aliceIncident);
    expect(suspension).toMatchObject({
      action: 'suspend-clearance',
      outcome: 'applied',
      actorId: 'threat-detection',
      playbookId: playbook.id,
      detectionId: about(alice.identity.id).id,
      subject: { type: 'identity', id: alice.identity.id },
    });
    expect(suspension).not.toHaveProperty('details');
    const record = await f.iam.api.clearances.get(officer.credential, {
      tenantId,
      identityId: alice.identity.id,
    });
    expect(record).toMatchObject({
      status: 'suspended',
      effectiveStatus: 'suspended',
      suspended: { by: 'threat-detection', at: f.now(), incidentId: aliceIncident },
    });
    expect(record?.suspended?.reason).toContain('Playbook Suspend on classified probing');
    expect(await reads(alice.credential, 'memo')).toBe(false);
    const [audited] = await audit(f, 'threat:suspend-clearance');
    expect(audited).toMatchObject({
      actorId: 'threat-detection',
      resourceId: alice.identity.id,
      outcome: 'allow',
      metadata: {
        level: 'S',
        incidentId: aliceIncident,
        detectionId: about(alice.identity.id).id,
        playbookId: playbook.id,
      },
    });
    expect(JSON.stringify(audited!.metadata)).not.toContain('GAMMA');
    // The clearance's own history records it as clearances.suspend does.
    expect(await audit(f, 'clearance:suspend')).toMatchObject([
      {
        actorId: 'threat-detection',
        resourceId: alice.identity.id,
        metadata: { level: 'S', incidentId: aliceIncident },
      },
    ]);
    // The person is not told by the threats module (an investigation must not tip them off).
    await f.iam.auth.dispatchOutbox();
    expect(f.inbox.some((message) => message.template === 'clearance-status')).toBe(false);

    // Carol holds no clearance; the owner is protected from automatic responses.
    expect(await responsesOf(f, about(carol.identity.id).incidentId!)).toMatchObject([
      { action: 'suspend-clearance', outcome: 'skipped', reason: 'no-clearance' },
    ]);
    expect(await responsesOf(f, about(f.ownerId).incidentId!)).toMatchObject([
      { action: 'suspend-clearance', outcome: 'skipped', reason: 'protected' },
    ]);
    expect(
      await f.iam.api.clearances.get(officer.credential, { tenantId, identityId: f.ownerId }),
    ).toMatchObject({ status: 'active' });
    expect(await reads(owner, 'memo')).toBe(true);

    // The engine never reads its own response back, and the suspension holds until an officer reinstates it.
    expect((await detect(f)).detections).toBe(0);
    await expect(
      f.iam.api.threats.release(owner, { tenantId, identityId: alice.identity.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    expect(
      await f.iam.api.clearances.reinstate(officer.credential, {
        tenantId,
        identityId: alice.identity.id,
        reason: 'Investigated: a mistyped link',
      }),
    ).toMatchObject({ status: 'active' });
    expect(await reads(alice.credential, 'memo')).toBe(true);
  });

  it('needs iam:clearances:suspend to suspend by hand, and release never restores a clearance', async () => {
    const { f, tenantId, reader, officer, grant, reads } = await setup();
    const alice = await reader('alice');
    const bob = await reader('bob');
    const carol = await reader('carol');
    await grant(alice.identity.id, 'S');
    await grant(bob.identity.id, 'S');
    const responder = await administrator(f, 'responder', [
      'iam:threats:read',
      'iam:threats:respond',
    ]);
    const handler = await administrator(f, 'handler', [
      'iam:threats:read',
      'iam:threats:respond',
      'iam:clearances:suspend',
    ]);
    const respond = (credential: Credential, identityId: string, kinds: string[]) =>
      f.iam.api.threats.respond(credential, {
        tenantId,
        identityId,
        actions: kinds.map((kind) => ({ kind })) as never,
        reason: 'Probing classified folders',
      });

    // A threats responder alone cannot suspend clearances: an audited refusal, nothing changed, and nothing about
    // whether the person holds a clearance is given away.
    for (const target of [alice.identity.id, carol.identity.id])
      await expect(
        respond(responder.credential, target, ['suspend-clearance']),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const denied = (await audit(f, 'iam:threats:respond')).filter(
      (event) => event.outcome === 'deny' && event.actorId === responder.identity.id,
    );
    expect(denied).toHaveLength(2);
    expect(
      await f.iam.api.clearances.get(officer.credential, {
        tenantId,
        identityId: alice.identity.id,
      }),
    ).toMatchObject({ status: 'active' });

    // With iam:clearances:suspend it applies, under the responder's name.
    const [applied] = await respond(handler.credential, alice.identity.id, ['suspend-clearance']);
    expect(applied).toMatchObject({
      action: 'suspend-clearance',
      outcome: 'applied',
      actorId: handler.identity.id,
    });
    expect(
      await f.iam.api.clearances.get(officer.credential, {
        tenantId,
        identityId: alice.identity.id,
      }),
    ).toMatchObject({
      status: 'suspended',
      suspended: { by: handler.identity.id, reason: 'Probing classified folders' },
    });
    expect(await reads(alice.credential, 'memo')).toBe(false);
    const [audited] = await audit(f, 'threat:suspend-clearance');
    expect(audited).toMatchObject({
      actorId: handler.identity.id,
      resourceId: alice.identity.id,
      metadata: { level: 'S', reason: 'Probing classified folders' },
    });
    expect(await audit(f, 'clearance:suspend')).toMatchObject([
      {
        actorId: handler.identity.id,
        resourceId: alice.identity.id,
        metadata: { level: 'S', reason: 'Probing classified folders' },
      },
    ]);
    // Again, or for someone without a clearance: skipped, not an error.
    expect(
      await respond(handler.credential, alice.identity.id, ['suspend-clearance']),
    ).toMatchObject([{ outcome: 'skipped', reason: 'already-applied' }]);
    expect(
      await respond(handler.credential, carol.identity.id, ['suspend-clearance']),
    ).toMatchObject([{ outcome: 'skipped', reason: 'no-clearance' }]);

    // Contained and suspended together: releasing the containment gives the account back, not the clearance.
    const both = await respond(handler.credential, bob.identity.id, [
      'contain',
      'suspend-clearance',
    ]);
    expect(both.map((response) => [response.action, response.outcome])).toEqual([
      ['contain', 'applied'],
      ['suspend-clearance', 'applied'],
    ]);
    expect(
      await f.iam.api.threats.release(handler.credential, {
        tenantId,
        identityId: bob.identity.id,
      }),
    ).toMatchObject({ action: 'release', outcome: 'applied' });
    expect(
      await f.iam.api.clearances.get(officer.credential, { tenantId, identityId: bob.identity.id }),
    ).toMatchObject({ status: 'suspended', identity: { status: 'active' } });
    const bobAgain = { token: (await f.signIn('bob')).token };
    expect(await reads(bobAgain, 'memo')).toBe(false);
    expect(await reads(bobAgain, 'plain')).toBe(true);
  });

  it('lets only people who may suspend clearances write playbooks that do', async () => {
    const { f, tenantId } = await setup();
    const manager = await administrator(f, 'manager', ['iam:threats:read', 'iam:threats:manage']);
    const threats = f.iam.api.threats;
    const suspend = [{ kind: 'suspend-clearance' as const }];
    const deniedFor = async () =>
      (await audit(f, 'iam:threats:manage')).filter(
        (event) => event.outcome === 'deny' && event.actorId === manager.identity.id,
      ).length;

    await expect(
      threats.createPlaybook(manager.credential, {
        tenantId,
        name: 'Suspend everyone',
        trigger: {},
        actions: suspend,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await deniedFor()).toBe(1);
    const notify = await threats.createPlaybook(manager.credential, {
      tenantId,
      name: 'Notify',
      trigger: {},
      actions: [{ kind: 'notify' }],
    });
    await expect(
      threats.updatePlaybook(manager.credential, {
        tenantId,
        playbookId: notify.id,
        actions: [{ kind: 'notify' }, ...suspend],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const stored = async (id: string) =>
      (await f.iam.store.get<ThreatPlaybook>('threatPlaybooks', id))!;
    expect((await stored(notify.id)).actions).toEqual([{ kind: 'notify' }]);

    // Written by someone who may (the owner), it can be renamed, described and switched off by the manager, but not
    // switched back on or retriggered.
    const owner = await f.ownerSignIn();
    const written = await threats.createPlaybook(owner, {
      tenantId,
      name: 'Suspend on probing',
      trigger: { ruleIds: ['classified-access-attempts'] },
      actions: suspend,
    });
    const update = (change: Record<string, unknown>) =>
      threats.updatePlaybook(manager.credential, {
        tenantId,
        playbookId: written.id,
        ...change,
      });
    await update({ name: 'Suspend on classified probing', description: 'Owner-approved' });
    expect(await update({ enabled: false })).toMatchObject({ enabled: false });
    for (const change of [{ enabled: true }, { trigger: {} }])
      await expect(update(change)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await stored(written.id)).toMatchObject({
      name: 'Suspend on classified probing',
      enabled: false,
      trigger: { ruleIds: ['classified-access-attempts'] },
      actions: suspend,
    });
    // Taking the suspension out only narrows what it does.
    expect(await update({ actions: [{ kind: 'notify' }] })).toMatchObject({
      actions: [{ kind: 'notify' }],
    });
    expect(await deniedFor()).toBe(4);
  });

  it('without the clearances option: the rule never fires and the response is refused or skipped', async () => {
    const f = await organizationFixture({ permissions: { resourceTypes } });
    const { tenantId } = f;
    const threats = f.iam.api.threats;
    const alice = await f.member('alice');
    expect((await threats.rules(f.ownerCredential, { tenantId })).map((rule) => rule.id)).toContain(
      'classified-access-attempts',
    );
    const owner = await f.ownerSignIn();
    await expect(
      threats.respond(owner, {
        tenantId,
        identityId: alice.id,
        actions: [{ kind: 'suspend-clearance' }],
        reason: 'x',
      }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
    await expect(
      threats.createPlaybook(owner, {
        tenantId,
        name: 'Suspend',
        trigger: {},
        actions: [{ kind: 'suspend-clearance' }],
      }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });

    // A playbook kept from when the option was on: its suspension is skipped.
    const now = f.now();
    await f.iam.store.transaction((tx) =>
      tx.insert<ThreatPlaybook>('threatPlaybooks', {
        id: 'pb-legacy',
        tenantId,
        uniqueKey: 'name:legacy',
        name: 'Legacy',
        enabled: true,
        trigger: {},
        actions: [{ kind: 'suspend-clearance' }],
        createdAt: now,
        createdBy: f.ownerId,
        updatedAt: now,
        updatedBy: f.ownerId,
        runs: 0,
      }),
    );
    const session = await f.signIn('alice');
    const report = await threats.reportSuspicious({ token: session.token }, { tenantId });
    const responses: ThreatResponse[] = await responsesOf(f, report.incidentId);
    expect(responses.find((response) => response.playbookId === 'pb-legacy')).toMatchObject({
      action: 'suspend-clearance',
      outcome: 'skipped',
      reason: 'feature-disabled',
    });

    // Denials carry no clearance marker, so the rule has nothing to count.
    await detect(f);
    for (let index = 0; index < 5; index++)
      expect(
        (
          await f.iam.authorize({
            token: session.token,
            tenantId,
            action: 'documents:read',
            resource: { type: 'document', id: 'secret' },
          })
        ).allowed,
      ).toBe(false);
    await detect(f);
    expect(await detections(f, 'classified-access-attempts')).toEqual([]);
    expect((await audit(f, 'documents:read')).every((event) => event.metadata === undefined)).toBe(
      true,
    );
  });
});
