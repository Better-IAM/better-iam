import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, Identity, Session } from '@better-iam/core';
import { appendAuditEvent, type IamStore } from '@better-iam/core';
import { renderDeliveryMessage } from '@better-iam/auth';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('threat detection engine', () => {
  it('verifies the chain, reports tampering once, and survives a prune', async () => {
    const f = await organizationFixture();
    const first = await f.iam.detectThreats();
    expect(first.chainBreaks).toBe(0);
    expect(first.tenants).toBeGreaterThanOrEqual(2);
    const again = await f.iam.detectThreats();
    expect(again.chainBreaks).toBe(0);

    await f.member('alice');
    const events = (await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId })).sort(
      (a, b) => b.sequence! - a.sequence!,
    );
    const newest = events[0]!;
    await f.database.transaction((tx) =>
      tx.put('audit', { ...newest, metadata: { forged: true } }),
    );
    const tampered = await f.iam.detectThreats({ tenantId: f.tenantId });
    expect(tampered.chainBreaks).toBe(1);
    expect(tampered.detections).toBe(1);
    expect(tampered.incidentsOpened).toBe(1);
    const detections = await f.database.find<
      { ruleId: string; metadata?: unknown } & { id: string; tenantId: string }
    >('threatDetections', { tenantId: f.tenantId });
    expect(detections.map((d) => d.ruleId)).toEqual(['audit-tampering']);
    const next = await f.iam.detectThreats({ tenantId: f.tenantId });
    expect(next.chainBreaks).toBe(0);
    const audit = await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId });
    expect(audit.some((event) => event.action === 'threat:detection')).toBe(true);
    expect(audit.some((event) => event.action === 'threat:incident-open')).toBe(true);

    await f.member('bob');
    await wait(5);
    await f.iam.pruneAudit({ tenantId: f.tenantId, retentionMs: 0 });
    const afterPrune = await f.iam.detectThreats({ tenantId: f.tenantId });
    expect(afterPrune.chainBreaks).toBe(0);
    expect(afterPrune.eventsScanned).toBeGreaterThanOrEqual(1);
    // Rolling the chain head back behind the cursor is reported.
    await f.database.transaction(async (tx) => {
      const head = await tx.get<{ sequence: number } & { id: string; tenantId: string }>(
        'auditChains',
        f.tenantId,
      );
      await tx.put('auditChains', { ...head!, sequence: 1 });
    });
    const rolled = await f.iam.detectThreats({ tenantId: f.tenantId });
    expect(rolled.chainBreaks).toBe(1);
    expect(rolled.detections).toBe(1);
  });

  it('contains, releases, blocks and notifies through responses', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const signedIn = await f.signIn('alice');
    const owner = await f.ownerSignIn();
    const [contained] = await f.iam.api.threats.respond(owner, {
      tenantId: f.tenantId,
      identityId: alice.id,
      actions: [{ kind: 'contain' }],
      reason: 'smoke',
    });
    expect(contained!.outcome).toBe('applied');
    const disabled = await f.database.get<Identity>('identities', alice.id);
    expect(disabled!.status).toBe('disabled');
    await expect(f.iam.api.auth.getSession({ token: signedIn.token })).rejects.toBeTruthy();
    await expect(f.signIn('alice')).rejects.toBeTruthy();
    const risk = await f.database.get<{ contained?: unknown } & { id: string; tenantId: string }>(
      'identityRisk',
      alice.id,
    );
    expect(risk!.contained).toBeTruthy();
    const [again] = await f.iam.api.threats.respond(owner, {
      tenantId: f.tenantId,
      identityId: alice.id,
      actions: [{ kind: 'contain' }],
      reason: 'smoke',
    });
    expect(again!.outcome).toBe('skipped');
    expect(again!.reason).toBe('already-applied');
    await expect(
      f.iam.api.threats.respond(owner, {
        tenantId: f.tenantId,
        identityId: f.ownerId,
        actions: [{ kind: 'contain' }],
        reason: 'smoke',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const released = await f.iam.api.threats.release(owner, {
      tenantId: f.tenantId,
      identityId: alice.id,
      note: 'ok',
    });
    expect(released.action).toBe('release');
    expect((await f.database.get<Identity>('identities', alice.id))!.status).toBe('active');
    await f.signIn('alice');
    await expect(
      f.iam.api.threats.release(owner, { tenantId: f.tenantId, identityId: alice.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });

    await f.iam.api.threats.configure(owner, {
      tenantId: f.tenantId,
      trustedNetworks: ['203.0.113.0/24'],
      notify: { owners: true, emails: ['soc@example.test'] },
    });
    const [trusted] = await f.iam.api.threats.respond(owner, {
      tenantId: f.tenantId,
      network: '203.0.113.7',
      actions: [{ kind: 'block-network' }],
      reason: 'smoke',
    });
    expect(trusted!.reason).toBe('trusted-network');
    const [blocked] = await f.iam.api.threats.respond(owner, {
      tenantId: f.tenantId,
      network: '198.51.100.7',
      actions: [{ kind: 'block-network', durationMs: 3_600_000 }],
      reason: 'smoke',
    });
    expect(blocked!.outcome).toBe('applied');
    const blocks = await f.database.find<{ network: string } & { id: string; tenantId: string }>(
      'authBlocks',
      { tenantId: f.tenantId },
    );
    expect(blocks.map((b) => b.network)).toEqual(['198.51.100.7']);
    const [redundant] = await f.iam.api.threats.respond(owner, {
      tenantId: f.tenantId,
      network: '198.51.100.7',
      actions: [{ kind: 'block-network', durationMs: 60_000 }],
      reason: 'smoke',
    });
    expect(redundant!.reason).toBe('already-applied');

    // A playbook emails new incidents once.
    await f.iam.api.threats.createPlaybook(owner, {
      tenantId: f.tenantId,
      name: 'Email the SOC',
      trigger: {},
      actions: [{ kind: 'notify' }, { kind: 'contain' }],
    });
    await f.iam.detectThreats({ tenantId: f.tenantId });
    await f.member('dave');
    const events = (await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId })).sort(
      (a, b) => b.sequence! - a.sequence!,
    );
    await f.database.transaction((tx) =>
      tx.put('audit', { ...events[0]!, metadata: { forged: true } }),
    );
    const run = await f.iam.detectThreats({ tenantId: f.tenantId });
    expect(run.detections).toBe(1);
    await f.iam.auth.dispatchOutbox();
    const alerts = f.inbox.filter((message) => message.template === 'threat-alert');
    expect(alerts.map((m) => m.to).sort()).toEqual(['owner@acme.test', 'soc@example.test']);
    const rendered = renderDeliveryMessage(alerts[0]!, {
      links: { threats: ({ tenantId, incidentId }) => `https://x.test/${tenantId}/${incidentId}` },
    })!;
    expect(rendered.subject).toContain('Critical security incident at Acme');
    expect(rendered.text).toContain('https://x.test/');
    const responses = await f.database.find<
      { action: string; outcome: string; reason?: string } & { id: string; tenantId: string }
    >('threatResponses', { tenantId: f.tenantId });
    // The tenant subject has no identity: contain is skipped.
    expect(responses.find((r) => r.action === 'contain' && r.playbookId)?.reason).toBe(
      'not-identity',
    );
  });

  it('contains automatically, protects owners, and brakes', async () => {
    const f = await organizationFixture();
    await f.member('erin');
    await f.member('frank');
    const owner = await f.ownerSignIn();
    await f.iam.api.threats.configure(owner, {
      tenantId: f.tenantId,
      maxAutomaticContainments: 1,
      rules: { 'brute-force': { threshold: 5 } },
    });
    await f.iam.api.threats.createPlaybook(owner, {
      tenantId: f.tenantId,
      name: 'Contain guessing',
      trigger: { ruleIds: ['brute-force'] },
      actions: [{ kind: 'revoke-sessions' }, { kind: 'contain' }],
    });
    await f.iam.detectThreats();
    const fail = async (email: string) => {
      for (let attempt = 0; attempt < 6; attempt++)
        await f.iam.auth
          .withClient({ ip: '198.51.100.30', userAgent: 'test' }, () =>
            f.iam.api.auth.signIn({ tenantId: f.tenantId, email, password: 'wrong password here' }),
          )
          .catch(() => undefined);
    };
    await fail('erin@acme.test');
    await fail('frank@acme.test');
    await fail('owner@acme.test');
    await f.iam.auth.settleBookkeeping();
    const run = await f.iam.detectThreats({ tenantId: f.tenantId });
    expect(run.braked).toBe(1);
    const responses = await f.database.find<
      { action: string; outcome: string; reason?: string; subject: { id: string } } & {
        id: string;
        tenantId: string;
      }
    >('threatResponses', { tenantId: f.tenantId });
    const contains = responses.filter((r) => r.action === 'contain');
    expect(contains.map((r) => r.reason ?? r.outcome).sort()).toEqual([
      'applied',
      'braked',
      'protected',
    ]);
    const audit = await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId });
    expect(audit.filter((e) => e.action === 'threat:response-braked')).toHaveLength(1);
    expect(audit.filter((e) => e.action === 'threat:contain')).toHaveLength(1);
    expect(audit.filter((e) => e.action === 'threat:revoke-sessions')).toHaveLength(3);
    const risky = await f.database.find<
      { level: string; score: number } & { id: string; tenantId: string }
    >('identityRisk', { tenantId: f.tenantId });
    expect(risky).toHaveLength(3);
    expect(audit.filter((e) => e.action === 'threat:risk-change').length).toBeGreaterThanOrEqual(3);
    const again = await f.iam.detectThreats({ tenantId: f.tenantId });
    expect(again.detections).toBe(0);
  });

  it('raises brute force from failed sign-ins through the rules', async () => {
    const f = await organizationFixture();
    await f.member('carol');
    await f.iam.detectThreats();
    for (let attempt = 0; attempt < 10; attempt++)
      await f.iam.auth
        .withClient({ ip: '198.51.100.20', userAgent: 'test' }, () =>
          f.iam.api.auth.signIn({
            tenantId: f.tenantId,
            email: 'carol@acme.test',
            password: 'wrong password here',
          }),
        )
        .catch(() => undefined);
    await f.iam.auth.settleBookkeeping();
    const run = await f.iam.detectThreats({ tenantId: f.tenantId });
    const detections = await f.database.find<{ ruleId: string } & { id: string; tenantId: string }>(
      'threatDetections',
      { tenantId: f.tenantId },
    );
    expect(run.detections).toBeGreaterThanOrEqual(1);
    expect(detections.map((d) => d.ruleId)).toContain('brute-force');
    const risk = await f.database.find<{ level: string } & { id: string; tenantId: string }>(
      'identityRisk',
      { tenantId: f.tenantId },
    );
    expect(risk.length).toBe(1);
  });
});

type Stored<T> = T & { id: string; tenantId: string };

/** Appends events to the fixture tenant's audit chain as the recorders would (no fan-out). */
async function append(
  f: Awaited<ReturnType<typeof organizationFixture>>,
  events: Omit<AuditEvent, 'tenantId'>[],
) {
  await f.database.transaction(async (tx) => {
    for (const event of events) await appendAuditEvent(tx, { ...event, tenantId: f.tenantId });
  });
}

describe('threat detection engine robustness', () => {
  it('never counts refused web identity tokens as the trust account’s denials', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId,
      name: 'ci',
    });
    await f.iam.detectThreats({ tenantId });
    await f.iam.detectThreats({ tenantId });
    const denials = (action: string, from: number) =>
      Array.from({ length: 40 }, (_, index) => ({
        id: `${action}-${from + index}`,
        actorId: account.id,
        action,
        resourceId: 'role-deploy',
        timestamp: f.now() + from + index,
        outcome: 'deny' as const,
        rootOverride: false,
        metadata: { reason: 'malformed' },
      }));
    // Anyone may post junk tokens for a trust: they are recorded under its service account, never as its burst.
    await append(f, denials('role:assumed-with-web-identity', 0));
    expect((await f.iam.detectThreats({ tenantId })).detections).toBe(0);
    // The account's own refusals still are.
    await append(f, denials('documents:read', 100));
    expect((await f.iam.detectThreats({ tenantId })).detections).toBe(1);
    const [burst] = await f.database.find<Stored<{ ruleId: string; evidence: { count: number } }>>(
      'threatDetections',
      { tenantId, ruleId: 'denial-burst' },
    );
    expect(burst?.evidence.count).toBe(40);
  });

  it('reports an event stripped of its fields as tampering and keeps detecting', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    await f.iam.detectThreats({ tenantId });
    await f.member('alice');
    const [newest] = (await f.database.find<AuditEvent>('audit', { tenantId })).sort(
      (a, b) => b.sequence! - a.sequence!,
    );
    const { timestamp: _timestamp, action: _action, ...stripped } = newest!;
    await f.database.transaction((tx) => tx.put('audit', stripped as AuditEvent));
    const tampered = await f.iam.detectThreats({ tenantId });
    expect(tampered).toMatchObject({ chainBreaks: 1, detections: 1 });
    const [tampering] = await f.database.find<Stored<{ occurredAt: unknown }>>('threatDetections', {
      tenantId,
      ruleId: 'audit-tampering',
    });
    expect(tampering?.occurredAt).toEqual(expect.any(Number));
    // The cursor moved past it: the next run reads new events.
    await f.member('bob');
    const next = await f.iam.detectThreats({ tenantId });
    expect(next.chainBreaks).toBe(0);
    expect(next.eventsScanned).toBeGreaterThan(0);
  });

  it('writes the sign-in baselines of at most 500 people per run and continues in the next', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    await f.iam.detectThreats({ tenantId });
    await f.iam.detectThreats({ tenantId });
    await append(
      f,
      Array.from({ length: 501 }, (_, index) => ({
        id: `sign-in-${index}`,
        actorId: `person-${index}`,
        action: 'auth:session:create',
        resourceId: `person-${index}`,
        timestamp: f.now(),
        outcome: 'allow' as const,
        metadata: { ip: '192.0.2.10' },
      })),
    );
    expect(await f.iam.detectThreats({ tenantId })).toMatchObject({
      eventsScanned: 500,
      pending: 1,
    });
    expect(await f.iam.detectThreats({ tenantId })).toMatchObject({
      eventsScanned: 1,
      pending: 0,
    });
  });

  it('records nothing from a run whose settings changed while it evaluated', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const erin = await f.member('erin');
    const owner = await f.ownerSignIn();
    await f.iam.api.threats.configure(owner, {
      tenantId,
      rules: { 'brute-force': { threshold: 5 } },
    });
    await f.iam.api.threats.createPlaybook(owner, {
      tenantId,
      name: 'Contain guessing',
      trigger: { ruleIds: ['brute-force'] },
      actions: [{ kind: 'contain' }],
    });
    await f.iam.detectThreats({ tenantId });
    for (let attempt = 0; attempt < 6; attempt++)
      await f.iam.auth
        .withClient({ ip: '198.51.100.31', userAgent: 'test' }, () =>
          f.iam.api.auth.signIn({ tenantId, email: 'erin@acme.test', password: 'wrong password' }),
        )
        .catch(() => undefined);
    await f.iam.auth.settleBookkeeping();

    // An administrator turns the rule off after the run read the settings and before it writes.
    const store = f.database as IamStore;
    const { get, transaction } = store;
    let settingsRead = false;
    let changed = false;
    store.get = (async (collection: string, id: string) => {
      if (collection === 'threatSettings' && id === tenantId) settingsRead = true;
      return get.call(store, collection, id);
    }) as IamStore['get'];
    store.transaction = (async (fn: (tx: IamStore) => Promise<unknown>) => {
      if (settingsRead && !changed) {
        changed = true;
        await transaction.call(store, async (tx) => {
          const stored = await tx.get<Stored<{ rules: object; updatedAt: number }>>(
            'threatSettings',
            tenantId,
          );
          await tx.put('threatSettings', {
            ...stored!,
            rules: { ...stored!.rules, 'brute-force': { enabled: false } },
            updatedAt: stored!.updatedAt + 1,
          });
        });
      }
      return transaction.call(store, fn);
    }) as IamStore['transaction'];
    let run;
    try {
      run = await f.iam.detectThreats({ tenantId });
    } finally {
      store.get = get;
      store.transaction = transaction;
    }
    expect(changed).toBe(true);
    expect(run).toMatchObject({ detections: 0, responses: 0 });
    expect((await f.database.get<Identity>('identities', erin.id))!.status).toBe('active');
    // The next run reads the same events under the new settings: the rule is off.
    const next = await f.iam.detectThreats({ tenantId });
    expect(next.eventsScanned).toBeGreaterThan(0);
    expect(next.detections).toBe(0);
    expect((await f.database.get<Identity>('identities', erin.id))!.status).toBe('active');
  });
});
