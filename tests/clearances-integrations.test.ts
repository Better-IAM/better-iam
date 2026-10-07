import { afterEach, describe, expect, it } from 'vitest';
import { renderDeliveryMessage, type DeliveryMessage } from '@better-iam/auth';
import { classificationTemplates, type AuditEvent } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';
import { administrator } from './support/guests.js';

afterEach(closeFixtures);

const day = 86_400_000;

const usWithCompartments = () => ({
  ...JSON.parse(JSON.stringify(classificationTemplates.us)),
  compartments: [
    { id: 'GAMMA', name: 'Gamma codeword' },
    { id: 'HCS', name: 'Humint control' },
  ],
});

async function auditOf(
  f: OrganizationFixture,
  action: string,
  tenantId = f.tenantId,
): Promise<AuditEvent[]> {
  const events = await f.database.transaction((tx) =>
    tx.find<AuditEvent>('audit', { tenantId, action }),
  );
  return events.sort((a, b) => (a.sequence ?? 0) - (b.sequence ?? 0));
}

/** Acme with a scheme of two compartments that any officer may adjudicate. */
async function cleared(options: { interimAllowed?: boolean; notify?: string[] } = {}) {
  const f = await organizationFixture({ clearances: {} });
  await f.iam.api.clearances.defineScheme(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Acme',
    definition: usWithCompartments(),
    adjudication: 'unrestricted',
    ...(options.interimAllowed ? { interimAllowed: true } : {}),
    ...(options.notify ? { notify: { emails: options.notify } } : {}),
  });
  return f;
}

/** A project below Acme whose owner accepted the invitation. */
async function project(f: OrganizationFixture, name = 'Apollo') {
  const created = await f.iam.api.tenants.create(f.ownerCredential, {
    parentId: f.tenantId,
    name,
    type: 'project',
    ownerEmail: `${name.toLowerCase()}@acme.test`,
  });
  await f.iam.auth.dispatchOutbox();
  const invitation = f.inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await f.iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: `${name} owner`,
    password: `a strong ${name} owner password`,
  });
  if (!('token' in owner)) throw new Error('Unexpected MFA');
  return { tenantId: created.tenant.id, credential: { token: owner.token } };
}

const byFirst = <T extends unknown[]>(rows: T[]) =>
  [...rows].sort((a, b) => String(a[0]).localeCompare(String(b[0])));

/**
 * How clearances meet the rest of the identity lifecycle: offboarding terminates them, deletion keeps them as
 * terminated history, `iam.clearances.sendReminders` tells the scheme's owners what is due (level names only), and the
 * person hears about suspension, revocation and reinstatement (`clearance-status`).
 */
describe('clearances across the identity lifecycle', () => {
  it('terminates the clearance on offboarding and debriefs every compartment', async () => {
    const f = await cleared();
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    const [alice, bob, carol, dave] = [
      await f.member('alice'),
      await f.member('bob'),
      await f.member('carol'),
      await f.member('dave'),
    ];
    const grant = (identityId: string, level: string) =>
      api.grant(f.ownerCredential, { tenantId, identityId, level, citizenship: ['USA'] });
    await grant(alice.id, 'TS');
    for (const compartmentId of ['HCS', 'GAMMA'])
      await api.readIn(f.ownerCredential, { tenantId, identityId: alice.id, compartmentId });
    await grant(bob.id, 'S');
    await api.suspend(f.ownerCredential, {
      tenantId,
      identityId: bob.id,
      reason: 'review',
      notifyPerson: false,
    });
    await grant(carol.id, 'C');
    await api.revoke(f.ownerCredential, {
      tenantId,
      identityId: carol.id,
      reason: 'security violation',
      notifyPerson: false,
    });

    const fresh = await f.ownerSignIn();
    const offboard = (identityId: string, reason: string) =>
      f.iam.api.identities.offboard(fresh, { tenantId, identityId, reason });
    expect(await offboard(alice.id, 'left the company')).toMatchObject({
      identity: { status: 'disabled' },
      clearancesTerminated: 1,
    });
    expect(await api.get(fresh, { tenantId, identityId: alice.id })).toMatchObject({
      status: 'terminated',
      effectiveStatus: 'terminated',
      level: { id: 'TS' },
      readIns: [],
      terminated: { by: f.ownerId, at: f.now(), reason: 'left the company' },
      identity: { status: 'disabled' },
    });
    const debriefs = await auditOf(f, 'clearance:debrief');
    expect(
      byFirst(debriefs.map((event) => [event.metadata?.compartmentId, event.resourceId])),
    ).toEqual([
      ['GAMMA', alice.id],
      ['HCS', alice.id],
    ]);
    expect(debriefs.every((event) => event.metadata?.reason === 'terminated')).toBe(true);
    expect(debriefs.every((event) => event.actorId === f.ownerId)).toBe(true);
    const [offboarded] = (await auditOf(f, 'identity:offboard')).filter(
      (event) => event.resourceId === alice.id,
    );
    expect(offboarded?.metadata).toMatchObject({ clearancesTerminated: 1 });

    // A suspended clearance ends too, and the suspension goes with it.
    expect(await offboard(bob.id, 'contract ended')).toMatchObject({ clearancesTerminated: 1 });
    const bobs = await api.get(fresh, { tenantId, identityId: bob.id });
    expect(bobs).toMatchObject({ status: 'terminated', terminated: { reason: 'contract ended' } });
    expect(bobs).not.toHaveProperty('suspended');
    // A clearance revoked for cause stays revoked: offboarding does not rewrite why it ended.
    const plain = await offboard(carol.id, 'left');
    expect(plain).not.toHaveProperty('clearancesTerminated');
    const carols = await api.get(fresh, { tenantId, identityId: carol.id });
    expect(carols).toMatchObject({
      status: 'revoked',
      revoked: { reason: 'security violation' },
    });
    expect(carols).not.toHaveProperty('terminated');
    // Without a clearance the result keeps its shape.
    expect(await offboard(dave.id, 'left')).not.toHaveProperty('clearancesTerminated');
    expect(
      (await auditOf(f, 'clearance:terminate')).map((event) => [
        event.resourceId,
        event.metadata?.previousStatus,
        event.metadata?.level,
      ]),
    ).toEqual([
      [alice.id, 'active', 'TS'],
      [bob.id, 'suspended', 'S'],
    ]);
    expect(
      (await api.list(fresh, { tenantId, status: 'revoked' })).clearances.map(
        (item) => item.identityId,
      ),
    ).toEqual([carol.id]);

    // Re-enabled, the person holds nothing until an officer grants a new clearance.
    await f.iam.api.identities.setStatus(fresh, {
      tenantId,
      identityId: alice.id,
      status: 'active',
    });
    expect(await api.get(fresh, { tenantId, identityId: alice.id })).toMatchObject({
      effectiveStatus: 'terminated',
    });
    expect(
      await api.grant(fresh, { tenantId, identityId: alice.id, level: 'C', citizenship: ['USA'] }),
    ).toMatchObject({ status: 'active', level: { id: 'C' }, readIns: [] });
  });

  it('keeps the clearance as terminated history when the identity is deleted', async () => {
    const f = await cleared();
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: bob.id,
      level: 'S',
      citizenship: ['USA'],
    });
    await api.readIn(f.ownerCredential, { tenantId, identityId: bob.id, compartmentId: 'GAMMA' });
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: carol.id,
      level: 'C',
      citizenship: ['USA'],
    });
    await api.revoke(f.ownerCredential, {
      tenantId,
      identityId: carol.id,
      reason: 'security violation',
      notifyPerson: false,
    });
    const fresh = await f.ownerSignIn();
    await f.iam.api.identities.delete(fresh, { tenantId, identityId: bob.id });
    expect(await api.get(fresh, { tenantId, identityId: bob.id })).toMatchObject({
      status: 'terminated',
      effectiveStatus: 'terminated',
      level: { id: 'S' },
      readIns: [],
      terminated: { by: f.ownerId, at: f.now(), reason: 'identity deleted' },
      identity: { status: 'deleted' },
    });
    await f.iam.api.identities.delete(fresh, { tenantId, identityId: carol.id });
    const carols = await api.get(fresh, { tenantId, identityId: carol.id });
    expect(carols).toMatchObject({ status: 'revoked', revoked: { reason: 'security violation' } });
    expect(carols).not.toHaveProperty('terminated');
    const listed = await api.list(fresh, { tenantId });
    expect(listed.clearances.map((item) => [item.identityId, item.status])).toEqual([
      [bob.id, 'terminated'],
      [carol.id, 'revoked'],
    ]);
    // A deleted identity is never cleared again.
    await expect(
      api.grant(fresh, { tenantId, identityId: bob.id, level: 'S', citizenship: ['USA'] }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('leaves clearance records alone without the option', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const stored = (identityId: string) => ({
      id: identityId,
      tenantId,
      uniqueKey: `identity:${identityId}`,
      identityId,
      schemeTenantId: tenantId,
      level: 'S',
      citizenship: ['USA'],
      status: 'active',
      readIns: [{ compartmentId: 'GAMMA', readInAt: 1, readInBy: f.ownerId }],
      grantedAt: 1,
      grantedBy: f.ownerId,
      updatedAt: 1,
      updatedBy: f.ownerId,
    });
    await f.database.transaction(async (tx) => {
      for (const identityId of [alice.id, bob.id])
        await tx.insert('clearances', stored(identityId));
    });
    const fresh = await f.ownerSignIn();
    expect(
      await f.iam.api.identities.offboard(fresh, {
        tenantId,
        identityId: alice.id,
        reason: 'left',
      }),
    ).not.toHaveProperty('clearancesTerminated');
    await f.iam.api.identities.delete(fresh, { tenantId, identityId: bob.id });
    for (const identityId of [alice.id, bob.id])
      expect(await f.database.transaction((tx) => tx.get('clearances', identityId))).toMatchObject(
        stored(identityId),
      );
    const events = await f.database.transaction((tx) => tx.find<AuditEvent>('audit', { tenantId }));
    expect(events.some((event) => event.action.startsWith('clearance:'))).toBe(false);
  });

  it('reminds the scheme’s owners of what is due, once per date, naming the level only', async () => {
    const f = await cleared({ interimAllowed: true, notify: ['Security@Acme.test'] });
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    const now = f.now();
    const people: Record<string, { id: string }> = {};
    for (const name of ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'gwen'])
      people[name] = await f.member(name);
    const grant = (name: string, level: string, extra: Record<string, unknown> = {}) =>
      api.grant(f.ownerCredential, {
        tenantId,
        identityId: people[name]!.id,
        level,
        citizenship: ['USA'],
        ...extra,
      });
    await grant('alice', 'TS', { reinvestigationDue: now + 30 * day });
    await api.readIn(f.ownerCredential, {
      tenantId,
      identityId: people.alice!.id,
      compartmentId: 'GAMMA',
    });
    await grant('bob', 'C', { interim: true, expiresAt: now + 10 * day });
    await grant('carol', 'S', { expiresAt: now + 90 * day });
    await grant('dave', 'S', { reinvestigationDue: now - day });
    // Suspended and disabled people are not reminded about; neither is a clearance with nothing due.
    await grant('erin', 'S', { reinvestigationDue: now + 5 * day });
    await api.suspend(f.ownerCredential, {
      tenantId,
      identityId: people.erin!.id,
      reason: 'review',
      notifyPerson: false,
    });
    await grant('frank', 'S', { reinvestigationDue: now + 5 * day });
    await f.iam.api.identities.setStatus(f.ownerCredential, {
      tenantId,
      identityId: people.frank!.id,
      status: 'disabled',
    });
    await grant('gwen', 'S');
    // A project's clearances are under Acme's scheme, so Acme's owners hear about them.
    const apollo = await project(f);
    const pat = await f.iam.api.identities.create(apollo.credential, {
      tenantId: apollo.tenantId,
      email: 'pat@apollo.test',
      name: 'pat',
      password: 'a strong pat password',
    });
    await api.grant(apollo.credential, {
      tenantId: apollo.tenantId,
      identityId: pat.id,
      level: 'S',
      citizenship: ['USA'],
      reinvestigationDue: now + 20 * day,
    });

    for (const withinDays of [0, 366, 1.5])
      await expect(f.iam.clearances.sendReminders({ withinDays })).rejects.toMatchObject({
        code: 'INVALID_INPUT',
      });
    // One tenant at a time, if asked.
    expect(await f.iam.clearances.sendReminders({ tenantId: apollo.tenantId })).toEqual({
      sent: [
        { tenantId: apollo.tenantId, identityId: pat.id, dueAt: now + 20 * day, recipients: 2 },
      ],
      skipped: { inactive: 0, noRecipients: 0 },
    });
    const first = await f.iam.clearances.sendReminders();
    expect(first.skipped).toEqual({ inactive: 0, noRecipients: 0 });
    expect(
      byFirst(
        first.sent.map((item) => [item.identityId, item.tenantId, item.dueAt, item.recipients]),
      ),
    ).toEqual(
      byFirst([
        [people.alice!.id, tenantId, now + 30 * day, 2],
        [people.bob!.id, tenantId, now + 10 * day, 2],
        [people.dave!.id, tenantId, now - day, 2],
      ]),
    );
    expect((await f.iam.clearances.sendReminders()).sent).toEqual([]);
    // A longer window reaches carol's end, still once.
    expect(
      (await f.iam.clearances.sendReminders({ withinDays: 120 })).sent.map(
        (item) => item.identityId,
      ),
    ).toEqual([people.carol!.id]);
    expect((await f.iam.clearances.sendReminders({ withinDays: 120 })).sent).toEqual([]);

    await f.iam.auth.dispatchOutbox();
    const emails = f.inbox.filter((message) => message.template === 'clearance-reminder');
    expect(emails).toHaveLength(10);
    expect([...new Set(emails.map((message) => message.to))].sort()).toEqual([
      'owner@acme.test',
      'security@acme.test',
    ]);
    // Never a compartment, by name or id.
    expect(JSON.stringify(emails)).not.toMatch(/gamma/i);
    const about = (identityId: string) =>
      emails.find((message) => message.payload.identityId === identityId)!;
    const iso = (at: number) => new Date(at).toISOString();
    expect(about(people.alice!.id).payload).toEqual({
      tenantId,
      tenantName: 'Acme',
      identityId: people.alice!.id,
      personName: 'alice',
      levelName: 'TOP SECRET',
      status: 'active',
      dueAt: iso(now + 30 * day),
      reinvestigationDue: iso(now + 30 * day),
    });
    expect(about(pat.id).payload).toMatchObject({
      tenantId: apollo.tenantId,
      tenantName: 'Apollo',
      levelName: 'SECRET',
    });

    const links = {
      clearances: (input: { tenantId: string; identityId?: string }) =>
        `https://console.acme.test/${input.tenantId}/clearances/${input.identityId ?? ''}`,
      account: (input: { tenantId: string }) => `https://console.acme.test/${input.tenantId}/me`,
    };
    const render = (message: DeliveryMessage, withLinks = true) =>
      renderDeliveryMessage(message, withLinks ? { links } : {})!;
    const alices = render(about(people.alice!.id));
    expect(alices.subject).toBe('Clearance review due at Acme');
    expect(alices.text).toContain('alice holds a security clearance at Acme (level: TOP SECRET).');
    expect(alices.text).toContain(
      `Their periodic reinvestigation is due on ${new Date(now + 30 * day).toUTCString()}.`,
    );
    expect(alices.text).toContain(
      `Review the clearance: https://console.acme.test/${tenantId}/clearances/${people.alice!.id}`,
    );
    expect(alices.html).toContain(`/clearances/${people.alice!.id}`);
    expect(
      renderDeliveryMessage(about(people.alice!.id), { links: { account: links.account } })!.text,
    ).toContain(`Review the clearance: https://console.acme.test/${tenantId}/me`);
    expect(render(about(people.alice!.id), false).text).not.toContain('https://');
    const bobs = render(about(people.bob!.id)).text;
    expect(bobs).toContain(
      'bob holds an interim security clearance at Acme (level: CONFIDENTIAL).',
    );
    expect(bobs).toContain(
      `The interim clearance ends on ${new Date(now + 10 * day).toUTCString()} unless it is renewed.`,
    );
    expect(render(about(people.carol!.id)).text).toContain(
      `The clearance ends on ${new Date(now + 90 * day).toUTCString()} unless it is renewed.`,
    );
    expect(render(about(people.dave!.id)).text).toContain(
      `is due on ${new Date(now - day).toUTCString()}`,
    );

    // Each date is marked once, kept past the date so the purge cannot send it again while it is due.
    const marks = await f.database.transaction((tx) =>
      tx.find<{ uniqueKey: string; identityId: string; expiresAt: number }>('expiryReminderMarks', {
        tenantId,
      }),
    );
    expect(
      marks.find(
        (mark) => mark.uniqueKey === `clearance-reminder:${people.alice!.id}:${now + 30 * day}`,
      ),
    ).toMatchObject({ identityId: people.alice!.id, expiresAt: now + 90 * day });
    expect(
      marks.find((mark) => mark.uniqueKey === `clearance-reminder:${people.dave!.id}:${now - day}`),
    ).toMatchObject({ expiresAt: now + 60 * day });
    // The audit trail records what was due and how many were told, by the deployment, without compartments.
    const audited = await auditOf(f, 'clearance:reminder');
    expect(audited.every((event) => event.actorId === 'deployment-operator')).toBe(true);
    expect(JSON.stringify(audited)).not.toMatch(/gamma/i);
    expect(
      byFirst(
        audited.map((event) => [event.resourceId, event.metadata?.kinds, event.metadata?.level]),
      ),
    ).toEqual(
      byFirst([
        [people.alice!.id, ['reinvestigation'], 'TS'],
        [people.bob!.id, ['interim-end'], 'C'],
        [people.carol!.id, ['expiry'], 'S'],
        [people.dave!.id, ['reinvestigation'], 'S'],
      ]),
    );
    expect(
      (await auditOf(f, 'clearance:reminder', apollo.tenantId)).map((event) => event.resourceId),
    ).toEqual([pat.id]);

    // A new date is a new reminder.
    await api.update(f.ownerCredential, {
      tenantId,
      identityId: people.alice!.id,
      reinvestigationDue: now + 40 * day,
    });
    expect((await f.iam.clearances.sendReminders()).sent.map((item) => item.identityId)).toEqual([
      people.alice!.id,
    ]);
    // Tenants that are not active are skipped.
    await api.update(f.ownerCredential, {
      tenantId,
      identityId: people.alice!.id,
      reinvestigationDue: now + 45 * day,
    });
    await f.iam.api.tenants.setStatus(f.rootCredential, { tenantId, status: 'suspended' });
    expect(await f.iam.clearances.sendReminders()).toEqual({
      sent: [],
      skipped: { inactive: 1, noRecipients: 0 },
    });
  });

  it('tells the person about suspension, revocation and reinstatement, never why', async () => {
    const f = await cleared();
    const api = f.iam.api.clearances;
    const { tenantId } = f;
    const officer = await administrator(f, 'olga', [
      'iam:clearances:read',
      'iam:clearances:adjudicate',
      'iam:clearances:suspend',
    ]);
    const o = officer.credential;
    const carol = await f.member('carol');
    const person = { tenantId, identityId: carol.id };
    await api.grant(o, { ...person, level: 'S', citizenship: ['USA'] });
    await api.readIn(o, { ...person, compartmentId: 'HCS' });
    await api.suspend(o, {
      ...person,
      reason: 'incident 42 under investigation',
      incidentId: 'inc-42',
    });
    await api.reinstate(o, { ...person, reason: 'cleared by the investigation' });
    // An investigation that must not tip the person off suspends silently; reinstating always tells them.
    await api.suspend(o, { ...person, reason: 'quiet look', notifyPerson: false });
    await api.reinstate(o, person);
    await api.revoke(o, { ...person, reason: 'quiet end', notifyPerson: false });
    await api.grant(o, { ...person, level: 'C', citizenship: ['USA'] });
    await api.revoke(o, { ...person, reason: 'foreign contact not reported' });
    // People without an email address (agents) are not emailed.
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId,
      name: 'Clerk',
      sponsorId: officer.identity.id,
    });
    await api.grant(o, { tenantId, identityId: agent.id, level: 'C', citizenship: [] });
    await api.suspend(o, { tenantId, identityId: agent.id, reason: 'x' });

    await f.iam.auth.dispatchOutbox();
    const statuses = f.inbox.filter((message) => message.template === 'clearance-status');
    expect(statuses.every((message) => message.to === 'carol@acme.test')).toBe(true);
    expect(statuses.map((message) => JSON.stringify(message.payload)).sort()).toEqual(
      [
        { tenantId, tenantName: 'Acme', status: 'suspended', levelName: 'SECRET' },
        { tenantId, tenantName: 'Acme', status: 'reinstated', levelName: 'SECRET' },
        { tenantId, tenantName: 'Acme', status: 'reinstated', levelName: 'SECRET' },
        { tenantId, tenantName: 'Acme', status: 'revoked', levelName: 'CONFIDENTIAL' },
      ]
        .map((payload) => JSON.stringify(payload))
        .sort(),
    );
    expect(JSON.stringify(statuses)).not.toMatch(
      /incident|inc-42|investigation|foreign|HCS|Humint/,
    );

    const account = (input: { tenantId: string }) => `https://app.acme.test/${input.tenantId}/me`;
    const rendered = (status: string) =>
      renderDeliveryMessage(statuses.find((message) => message.payload.status === status)!, {
        links: { account },
      })!;
    const [suspended, reinstated, revoked] = ['suspended', 'reinstated', 'revoked'].map(rendered);
    expect(suspended!.subject).toBe('Your security clearance at Acme was suspended');
    expect(suspended!.text).toContain(
      'Your security clearance at Acme (level: SECRET) was suspended.',
    );
    expect(suspended!.text).toContain(
      'Access to classified resources that depends on it has stopped.',
    );
    expect(suspended!.text).toContain(`Review your account: https://app.acme.test/${tenantId}/me`);
    expect(reinstated!.subject).toBe('Your security clearance at Acme was reinstated');
    expect(reinstated!.text).toContain('Access that depends on it is available again.');
    expect(revoked!.subject).toBe('Your security clearance at Acme was revoked');
    expect(revoked!.text).toContain('(level: CONFIDENTIAL) was revoked.');
  });
});
