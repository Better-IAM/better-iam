import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '@better-iam/core';
import { routeGroups } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const doc = { type: 'document', id: 'd1' };

describe('threats API', () => {
  it('rules, settings, guardrail detection, validation', async () => {
    const f = await organizationFixture();
    const threats = f.iam.api.threats;
    expect(routeGroups.has('threats')).toBe(true);
    const rules = await threats.rules(f.ownerCredential, { tenantId: f.tenantId });
    expect(rules).toHaveLength(21);
    expect(rules.find((rule) => rule.id === 'new-network')).toMatchObject({
      everyone: false,
      customized: false,
    });
    expect(await threats.getSettings(f.ownerCredential, { tenantId: f.tenantId })).toMatchObject({
      configured: false,
      dormantDays: 90,
    });
    const owner = await f.ownerSignIn();
    for (const bad of [
      { rules: { nope: { enabled: false } } },
      { rules: { 'brute-force': { threshold: 1 } } },
      { rules: { 'session-hijack': { threshold: 5 } } },
      { rules: { 'brute-force': { everyone: true } } },
      { rules: { 'brute-force': { colour: 'red' } } },
      { trustedNetworks: ['0.0.0.0/0'] },
      { trustedNetworks: ['::ffff:0:0/96'] },
      { trustedNetworks: ['not an ip'] },
      { dormantDays: 3 },
      { notify: { emails: ['nope'] } },
    ])
      await expect(
        threats.configure(owner, { tenantId: f.tenantId, ...(bad as object) }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const view = await threats.configure(owner, {
      tenantId: f.tenantId,
      rules: {
        'brute-force': { enabled: false, threshold: 20 },
        'new-network': { everyone: true },
      },
      trustedNetworks: ['10.0.0.0/8'],
      notify: { owners: true },
    });
    expect(view).toMatchObject({ configured: true, trustedNetworks: ['10.0.0.0/8'] });
    expect(view.rules['brute-force']).toMatchObject({ enabled: false, threshold: 20 });
    const audit = await f.iam.store.find<AuditEvent>('audit', {
      tenantId: f.tenantId,
      action: 'threat:settings',
    });
    expect(audit[0]?.metadata).toMatchObject({
      changed: ['rules', 'trustedNetworks', 'notify'],
      disabledRules: ['brute-force'],
    });
    const detections = await threats.listDetections(f.ownerCredential, {
      tenantId: f.tenantId,
      ruleId: 'guardrail-weakened',
    });
    expect(detections.total).toBe(1);
    expect(detections.detections[0]).toMatchObject({
      identityId: f.ownerId,
      subject: { type: 'tenant' },
    });
    // A null rule clears its adjustments; re-enabling raises nothing.
    await threats.configure(owner, { tenantId: f.tenantId, rules: { 'brute-force': null } });
    expect(
      (await threats.rules(f.ownerCredential, { tenantId: f.tenantId })).find(
        (rule) => rule.id === 'brute-force',
      ),
    ).toMatchObject({ enabled: true, threshold: 10, customized: false });
    // Nobody dismisses a detection about themselves.
    await expect(
      threats.dismissDetection(owner, {
        tenantId: f.tenantId,
        detectionId: detections.detections[0]!.id,
        reason: 'mine',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const summary = await threats.summary(f.ownerCredential, { tenantId: f.tenantId });
    expect(summary).toMatchObject({ detections24h: 1, byRule24h: { 'guardrail-weakened': 1 } });
    expect(summary.openIncidents.medium).toBe(1);
    expect(summary.riskyIdentities.low).toBe(1);
  });

  it('report, risk, incidents, respond, release, playbooks', async () => {
    const f = await organizationFixture();
    const threats = f.iam.api.threats;
    const alice = await f.member('alice');
    const first = await f.signIn('alice');
    const second = await f.signIn('alice');
    const report = await threats.reportSuspicious(
      { token: second.token },
      {
        tenantId: f.tenantId,
        note: 'line one\r\nline two\u0007',
      },
    );
    expect(report).toMatchObject({ sessionsEnded: 1, devicesForgotten: 0 });
    await expect(f.iam.api.auth.getSession({ token: first.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await f.iam.api.auth.getSession({ token: second.token });
    await expect(
      threats.listDetections({ token: second.token }, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const detection = await threats.getDetection(f.ownerCredential, {
      tenantId: f.tenantId,
      detectionId: report.detectionId,
    });
    expect(detection.metadata).toEqual({ note: 'line one\nline two' });
    const risk = await threats.getRisk(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    expect(risk).toMatchObject({ level: 'medium', score: 50, kind: 'user' });

    // principal.riskLevel reaches decisions.
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Readers while safe',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['*'],
            conditions: { StringEquals: { 'principal.riskLevel': 'none' } },
          },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const canRead = async () =>
      (
        await f.iam.authorize({
          token: second.token,
          tenantId: f.tenantId,
          action: 'documents:read',
          resource: doc,
        })
      ).allowed;
    expect(await canRead()).toBe(false);

    const owner = await f.ownerSignIn();
    const incident = await threats.getIncident(f.ownerCredential, {
      tenantId: f.tenantId,
      incidentId: report.incidentId,
    });
    expect(incident.detections).toHaveLength(1);
    expect(incident.responses.map((response) => response.action).sort()).toEqual([
      'forget-devices',
      'revoke-sessions',
    ]);
    expect(incident.risk).toMatchObject({ level: 'medium' });
    await threats.addNote(f.ownerCredential, {
      tenantId: f.tenantId,
      incidentId: report.incidentId,
      body: 'Called alice.\nConfirmed.',
    });
    const updated = await threats.updateIncident(f.ownerCredential, {
      tenantId: f.tenantId,
      incidentId: report.incidentId,
      status: 'investigating',
      assigneeId: f.ownerId,
    });
    expect(updated).toMatchObject({ status: 'investigating', assigneeId: f.ownerId });
    expect(
      await threats.updateIncident(f.ownerCredential, {
        tenantId: f.tenantId,
        incidentId: report.incidentId,
        assigneeId: null,
      }),
    ).not.toHaveProperty('assigneeId');

    await expect(
      threats.setRisk(owner, {
        tenantId: f.tenantId,
        identityId: f.ownerId,
        level: 'none',
        reason: 'x',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      await threats.setRisk(owner, {
        tenantId: f.tenantId,
        identityId: alice.id,
        level: 'high',
        reason: 'confirmed',
        expiresInMs: 3_600_000,
      }),
    ).toMatchObject({ level: 'high', override: { level: 'high', active: true } });
    const listed = await threats.listRisk(f.ownerCredential, {
      tenantId: f.tenantId,
      minLevel: 'high',
    });
    expect(listed.identities.map((entry) => entry.identityId)).toEqual([alice.id]);

    const contained = await threats.respond(owner, {
      tenantId: f.tenantId,
      identityId: alice.id,
      actions: [{ kind: 'contain' }, { kind: 'notify' }],
      reason: 'compromised',
    });
    expect(
      contained.map((response) => [response.action, response.outcome, response.reason]),
    ).toEqual([
      ['contain', 'applied', undefined],
      ['notify', 'skipped', 'no-recipients'],
    ]);
    expect(contained[0]!.incidentId).toBe(report.incidentId);
    await expect(f.iam.api.auth.getSession({ token: second.token })).rejects.toBeDefined();
    const released = await threats.release(owner, {
      tenantId: f.tenantId,
      identityId: alice.id,
      note: 'ok',
    });
    expect(released).toMatchObject({ action: 'release', outcome: 'applied' });
    await expect(
      threats.release(owner, { tenantId: f.tenantId, identityId: alice.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });

    const resolved = await threats.resolveIncident(owner, {
      tenantId: f.tenantId,
      incidentId: report.incidentId,
      resolution: 'false-positive',
      note: 'Was the VPN.',
    });
    expect(resolved).toMatchObject({ status: 'resolved', resolution: 'false-positive' });
    expect(resolved).not.toHaveProperty('uniqueKey');
    const after = await threats.getRisk(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    expect(after.contributions).toHaveLength(0);
    expect(after.level).toBe('high'); // the override still holds
    await threats.setRisk(owner, {
      tenantId: f.tenantId,
      identityId: alice.id,
      level: 'none',
      reason: 'clear',
    });
    expect(
      (await threats.getRisk(f.ownerCredential, { tenantId: f.tenantId, identityId: alice.id }))
        .level,
    ).toBe('none');
    await expect(
      threats.resolveIncident(owner, {
        tenantId: f.tenantId,
        incidentId: report.incidentId,
        resolution: 'benign',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION', status: 409 });
    const timeline = await threats.timeline(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    expect(timeline.some((event) => event.action === 'threat:user-report')).toBe(true);

    const playbook = await threats.createPlaybook(owner, {
      tenantId: f.tenantId,
      name: 'Contain reporters',
      trigger: { ruleIds: ['user-reported'], minSeverity: 'high' },
      actions: [
        { kind: 'revoke-sessions', keepApiKeys: false },
        { kind: 'block-network', durationMs: 60_000 },
      ],
    });
    await expect(
      threats.createPlaybook(owner, {
        tenantId: f.tenantId,
        name: 'contain REPORTERS',
        trigger: {},
        actions: [{ kind: 'notify' }],
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      threats.createPlaybook(owner, {
        tenantId: f.tenantId,
        name: 'dup',
        trigger: {},
        actions: [{ kind: 'notify' }, { kind: 'notify' }],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const renamed = await threats.updatePlaybook(owner, {
      tenantId: f.tenantId,
      playbookId: playbook.id,
      name: 'Sign reporters out',
      description: 'd',
      enabled: false,
    });
    expect(renamed).toMatchObject({ name: 'Sign reporters out', enabled: false, description: 'd' });
    expect(await threats.listPlaybooks(f.ownerCredential, { tenantId: f.tenantId })).toHaveLength(
      1,
    );
    expect(
      await threats.deletePlaybook(owner, { tenantId: f.tenantId, playbookId: playbook.id }),
    ).toEqual({ deleted: true });

    const run = await threats.detect(f.ownerCredential, { tenantId: f.tenantId });
    expect(run.tenants).toBe(1);
    const incidents = await threats.listIncidents(f.ownerCredential, {
      tenantId: f.tenantId,
      status: 'resolved',
    });
    expect(incidents.total).toBe(1);
  });
});

type Fixture = Awaited<ReturnType<typeof organizationFixture>>;
type Stored<T> = T & { id: string; tenantId: string };
const hour = 3_600_000;
const threatsAdministration = [
  { effect: 'allow', actions: ['iam:threats:*'], resources: ['iam/threats/*'] },
];

/** A person of the fixture tenant holding a role of `statements`, freshly signed in. */
async function memberWith(f: Fixture, name: string, statements: unknown[]) {
  const person = await f.member(name);
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `${name} role`,
    document: { version: 1, statements } as never,
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: person.id,
  });
  return { id: person.id, credential: { token: (await f.signIn(name)).token } };
}

const statusOf = async (f: Fixture, identityId: string) =>
  (await f.iam.store.get<Stored<{ status: string }>>('identities', identityId))?.status;

describe('threats API protections', () => {
  it('contains an owner only for an owner in person or root', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = await f.ownerSignIn();
    const coOwner = await f.member('coowner');
    await f.iam.api.identities.setOwner(owner, { tenantId, identityId: coOwner.id, owner: true });
    const analyst = await memberWith(f, 'analyst', threatsAdministration);
    await expect(
      f.iam.api.threats.respond(analyst.credential, {
        tenantId,
        identityId: coOwner.id,
        actions: [{ kind: 'contain' }],
        reason: 'looks odd',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await statusOf(f, coOwner.id)).toBe('active');
    const [contained] = await f.iam.api.threats.respond(owner, {
      tenantId,
      identityId: coOwner.id,
      actions: [{ kind: 'contain' }],
      reason: 'confirmed',
    });
    expect(contained).toMatchObject({ action: 'contain', outcome: 'applied' });
    expect(await statusOf(f, coOwner.id)).toBe('disabled');
  });

  it('leaves network blocks on the root tenant to root, by hand and by playbook', async () => {
    const f = await organizationFixture();
    const rootTenantId = f.root.tenant.id;
    const api = f.iam.api;
    const analyst = await api.serviceAccounts.create(f.rootCredential, {
      tenantId: rootTenantId,
      name: 'soc-bot',
    });
    const role = await api.roles.create(f.rootCredential, {
      tenantId: rootTenantId,
      name: 'Platform SOC',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['iam:threats:*'], resources: ['*'] }],
      },
    });
    await api.bindings.create(f.rootCredential, {
      tenantId: rootTenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: analyst.id,
    });
    const key = {
      token: (
        await api.credentials.create(f.rootCredential, {
          tenantId: rootTenantId,
          identityId: analyst.id,
        })
      ).token,
    };
    const blocks = async () =>
      (
        await f.iam.store.find<Stored<{ network: string }>>('authBlocks', {
          tenantId: rootTenantId,
        })
      ).map((block) => block.network);
    await expect(
      api.threats.respond(key, {
        tenantId: rootTenantId,
        network: '198.51.100.0/24',
        actions: [{ kind: 'block-network', durationMs: 30 * 24 * hour }],
        reason: 'suspicious',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await blocks()).toEqual([]);
    const [byRoot] = await api.threats.respond(f.rootCredential, {
      tenantId: rootTenantId,
      network: '198.51.100.0/24',
      actions: [{ kind: 'block-network', durationMs: 60_000 }],
      reason: 'confirmed',
    });
    expect(byRoot).toMatchObject({ outcome: 'applied' });

    // A playbook on the root tenant (anyone with iam:threats:manage may write one) never blocks a network.
    await api.threats.configure(f.rootCredential, {
      tenantId: rootTenantId,
      rules: { 'brute-force': { threshold: 3 } },
    });
    await api.threats.createPlaybook(f.rootCredential, {
      tenantId: rootTenantId,
      name: 'Block guessers',
      trigger: { ruleIds: ['brute-force'] },
      actions: [{ kind: 'block-network' }],
    });
    await f.iam.detectThreats({ tenantId: rootTenantId });
    for (let attempt = 0; attempt < 3; attempt++)
      await f.iam.auth
        .withClient({ ip: '203.0.113.77', userAgent: 'test' }, () =>
          api.auth.signIn({
            tenantId: rootTenantId,
            email: 'root@example.test',
            password: 'not the root password at all',
          }),
        )
        .catch(() => undefined);
    await f.iam.auth.settleBookkeeping();
    expect((await f.iam.detectThreats({ tenantId: rootTenantId })).detections).toBeGreaterThan(0);
    const automatic = (
      await f.iam.store.find<Stored<{ outcome: string; reason?: string; playbookId?: string }>>(
        'threatResponses',
        { tenantId: rootTenantId, action: 'block-network' },
      )
    ).filter((response) => response.playbookId);
    expect(automatic.map((response) => [response.outcome, response.reason])).toEqual([
      ['skipped', 'protected'],
    ]);
    expect(await blocks()).toEqual(['198.51.100.0/24']);
  });

  it('never releases what another path disabled, suspended, or re-enabled since', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const api = f.iam.api;
    const owner = await f.ownerSignIn();
    const contain = (identityId: string) =>
      api.threats.respond(owner, {
        tenantId,
        identityId,
        actions: [{ kind: 'contain' }],
        reason: 'test',
      });
    const release = (identityId: string) => api.threats.release(owner, { tenantId, identityId });
    const containedMark = async (identityId: string) =>
      (await f.iam.store.get<Stored<{ contained?: unknown }>>('identityRisk', identityId))
        ?.contained;

    // Disabled again by an administrator.
    const alice = await f.member('alice');
    await contain(alice.id);
    await api.identities.setStatus(owner, { tenantId, identityId: alice.id, status: 'disabled' });
    await expect(release(alice.id)).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    expect(await statusOf(f, alice.id)).toBe('disabled');
    // Offboarded.
    const bob = await f.member('bob');
    await contain(bob.id);
    await api.identities.offboard(owner, { tenantId, identityId: bob.id, reason: 'left' });
    await expect(release(bob.id)).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    expect(await statusOf(f, bob.id)).toBe('disabled');
    // Re-enabled, then disabled for another reason.
    const carol = await f.member('carol');
    await contain(carol.id);
    await api.identities.setStatus(owner, { tenantId, identityId: carol.id, status: 'active' });
    expect(await containedMark(carol.id)).toBeUndefined();
    await api.identities.setStatus(owner, { tenantId, identityId: carol.id, status: 'disabled' });
    await expect(release(carol.id)).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    // An agent its sponsor suspended as well.
    const agent = await api.agents.create(owner, {
      tenantId,
      name: 'Triage bot',
      sponsorId: f.ownerId,
    } as never);
    await contain(agent.id);
    await api.agents.suspend(owner, { tenantId, agentId: agent.id, reason: 'prompt injection' });
    await expect(release(agent.id)).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    expect((await api.agents.get(owner, { tenantId, agentId: agent.id })).standing).toBe(
      'suspended',
    );
    // A containment nothing else touched is still released.
    const dave = await f.member('dave');
    await contain(dave.id);
    expect(await release(dave.id)).toMatchObject({ action: 'release', outcome: 'applied' });
    expect(await statusOf(f, dave.id)).toBe('active');
  });

  it('revokes the invitations a contained identity sent, and they stay revoked after release', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const inviter = await memberWith(f, 'inviter', [
      { effect: 'allow', actions: ['iam:identities:create'], resources: ['*'] },
    ]);
    await f.iam.api.identities.invite(inviter.credential, {
      tenantId,
      email: 'attacker@evil.example',
    });
    const owner = await f.ownerSignIn();
    await f.iam.api.threats.respond(owner, {
      tenantId,
      identityId: inviter.id,
      actions: [{ kind: 'contain' }],
      reason: 'taken over',
    });
    await f.iam.api.threats.release(owner, { tenantId, identityId: inviter.id });
    const invitations = await f.iam.store.find<Stored<{ revoked?: boolean }>>('memberInvitations', {
      inviterId: inviter.id,
    });
    expect(invitations.map((invitation) => invitation.revoked)).toEqual([true]);
    await f.iam.auth.dispatchOutbox();
    const message = f.inbox.find((sent) => sent.to === 'attacker@evil.example');
    expect(message?.payload.token).toBeDefined();
    await expect(
      f.iam.api.identities.acceptInvitation({
        tenantId,
        token: message!.payload.token!,
        password: 'a strong attacker password',
      }),
    ).rejects.toBeDefined();
  });

  it('names nobody on a tenant incident once two people are behind it', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const alice = await memberWith(f, 'alice', threatsAdministration);
    const mallory = await memberWith(f, 'mallory', threatsAdministration);
    await f.iam.api.threats.configure(alice.credential, {
      tenantId,
      rules: { 'recon-burst': { enabled: false } },
    });
    const [opened] = (await f.iam.api.threats.listIncidents(f.ownerCredential, { tenantId }))
      .incidents;
    expect(opened).toMatchObject({ subject: { type: 'tenant' }, identityId: alice.id });
    await f.iam.api.threats.configure(mallory.credential, {
      tenantId,
      rules: { 'denial-burst': { enabled: false } },
    });
    const detail = await f.iam.api.threats.getIncident(f.ownerCredential, {
      tenantId,
      incidentId: opened!.id,
    });
    expect(detail.incident.detectionCount).toBe(2);
    expect(detail.incident).not.toHaveProperty('identityId');
    expect(detail.incident.severalIdentities).toBe(true);
    expect(detail.risk).toBeUndefined();
    // Containing "the incident" no longer contains whoever came first.
    const [response] = await f.iam.api.threats.respond(await f.ownerSignIn(), {
      tenantId,
      incidentId: opened!.id,
      actions: [{ kind: 'contain' }],
      reason: 'settings tampering',
    });
    expect(response).toMatchObject({ outcome: 'skipped', reason: 'not-identity' });
    expect(await statusOf(f, alice.id)).toBe('active');
    expect(await statusOf(f, mallory.id)).toBe('active');
  });

  it('reports weakened settings and keeps people from decaying their own risk', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const threats = f.iam.api.threats;
    const sec = await memberWith(f, 'sec', threatsAdministration);
    // A detection about sec raises their risk; shortening the half-life would erase it at once.
    await threats.reportSuspicious(sec.credential, { tenantId });
    await expect(
      threats.configure(sec.credential, { tenantId, riskHalfLifeHours: 1 }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await threats.getSettings(f.ownerCredential, { tenantId })).riskHalfLifeHours).toBe(24);

    const owner = await f.ownerSignIn();
    await threats.configure(owner, {
      tenantId,
      riskHalfLifeHours: 2,
      trustedNetworks: ['198.51.100.0/24'],
      maxAutomaticContainments: 0,
      rules: { 'brute-force': { threshold: 1000 } },
    });
    const guardrails = async () =>
      (await threats.listDetections(f.ownerCredential, { tenantId, ruleId: 'guardrail-weakened' }))
        .detections;
    const [weakened, ...others] = await guardrails();
    expect(others).toEqual([]);
    expect(weakened).toMatchObject({
      identityId: f.ownerId,
      title: 'Threat detection weakened',
      metadata: {
        disabledRules: [],
        weakened: [
          'rules.brute-force.threshold',
          'riskHalfLifeHours',
          'trustedNetworks',
          'maxAutomaticContainments',
        ],
      },
    });
    // Strengthening them again raises nothing.
    await threats.configure(owner, {
      tenantId,
      riskHalfLifeHours: 24,
      trustedNetworks: [],
      maxAutomaticContainments: 3,
      rules: { 'brute-force': null },
    });
    expect(await guardrails()).toHaveLength(1);
  });

  it('keeps risk contributions through a shortened half-life', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const threats = f.iam.api.threats;
    const alice = await f.member('alice');
    await threats.reportSuspicious({ token: (await f.signIn('alice')).token }, { tenantId });
    await threats.configure(await f.ownerSignIn(), { tenantId, riskHalfLifeHours: 1 });
    f.advance(12 * hour);
    // A new detection recomputes the risk under the one-hour half-life: the older contribution is kept.
    await threats.reportSuspicious({ token: (await f.signIn('alice')).token }, { tenantId });
    const risk = () => threats.getRisk(f.ownerCredential, { tenantId, identityId: alice.id });
    expect((await risk()).contributions).toHaveLength(2);
    // Restoring the half-life brings the earlier detection's weight back.
    await threats.configure(await f.ownerSignIn(), { tenantId, riskHalfLifeHours: 24 });
    expect(await risk()).toMatchObject({ level: 'high', score: 85 });
  });
});
