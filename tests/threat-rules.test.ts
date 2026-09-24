import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '@better-iam/core';
import type {
  IdentityRisk,
  ThreatBaseline,
  ThreatDetection,
  ThreatIncident,
} from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';
import { evaluateThreatRules, type RuleFacts } from '../packages/server/src/threat-rules.js';
import { resolveThreatSettings } from '../packages/server/src/threats.js';

/**
 * Rule coverage for identity threat detection (threat-rules.ts, threat-engine.ts): every scenario is produced through
 * the public API (sign-ins from simulated client addresses, administration calls) and judged by `iam.detectThreats()`,
 * so what is asserted is what a scheduled run would record.
 */

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);

afterEach(closeFixtures);

const minute = 60_000;
const day = 24 * 60 * minute;
const doc = { type: 'document', id: 'd1' };

/** Runs `fn` as a request from `ip`. */
function from<T>(f: OrganizationFixture, ip: string, fn: () => Promise<T>): Promise<T> {
  return f.iam.auth.withClient({ ip, userAgent: 'threat-rules-test' }, fn);
}

/** Wrong-password sign-ins for `{name}@acme.test` from `ip`; each must be refused as a bad credential (not rate limited). */
async function failPassword(f: OrganizationFixture, name: string, ip: string, times = 1) {
  for (let attempt = 0; attempt < times; attempt++)
    await expect(
      from(f, ip, () =>
        f.iam.api.auth.signIn({
          tenantId: f.tenantId,
          email: `${name}@acme.test`,
          password: 'not the right password',
        }),
      ),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
}

/** The current authenticator code for an enrolled secret, on the fixture's clock. */
function totp(f: OrganizationFixture, secret: string): string {
  const generator = authenticator.clone();
  generator.options = { epoch: f.now() };
  return generator.generate(secret);
}

/** Enrolls an authenticator app for the session's person; returns its secret. */
async function enrollAuthenticator(f: OrganizationFixture, token: string): Promise<string> {
  const { secret } = await f.iam.api.auth.beginMfa({ token });
  await f.iam.api.auth.confirmMfa({ credential: { token }, code: totp(f, secret) });
  return secret;
}

/** Writes the deferred sign-in failure bookkeeping, then runs detection for the fixture tenant. */
async function detect(f: OrganizationFixture) {
  await f.iam.auth.settleBookkeeping();
  return f.iam.detectThreats({ tenantId: f.tenantId });
}

/** The fixture tenant's detections, optionally of one rule, oldest first. */
async function detections(f: OrganizationFixture, ruleId?: string): Promise<ThreatDetection[]> {
  return (
    await f.iam.store.find<ThreatDetection>('threatDetections', {
      tenantId: f.tenantId,
      ...(ruleId ? { ruleId } : {}),
    })
  ).sort((a, b) => a.occurredAt - b.occurredAt || a.detectedAt - b.detectedAt);
}

/** Creates `{prefix}{n}@acme.test` people with passwords (`f.member`) and returns their names and ids. */
async function members(f: OrganizationFixture, prefix: string, count: number) {
  const created: { name: string; id: string }[] = [];
  for (let index = 0; index < count; index++) {
    const name = `${prefix}${index}`;
    created.push({ name, id: (await f.member(name)).id });
  }
  return created;
}

describe('threat rules', () => {
  it('password-spray: one network failing for ten people, one detection per burst', async () => {
    const f = await organizationFixture();
    const people = await members(f, 'spray', 10);
    await detect(f);

    for (const person of people.slice(0, 9)) await failPassword(f, person.name, '203.0.113.50');
    expect((await detect(f)).detections).toBe(0);

    // The tenth account completes the burst; the nine before it are read back from the lookback window.
    await failPassword(f, people[9]!.name, '203.0.113.50');
    const run = await detect(f);
    expect(run.detections).toBe(1);
    expect(run.incidentsOpened).toBe(1);
    const [spray, ...others] = await detections(f);
    expect(others).toEqual([]);
    expect(spray).toMatchObject({
      ruleId: 'password-spray',
      severity: 'high',
      subject: { type: 'network', id: '203.0.113.50' },
      network: '203.0.113.50',
      status: 'open',
      metadata: { peak: 10, threshold: 10, accounts: 10 },
    });
    expect(spray!.identityId).toBeUndefined();
    expect([...spray!.evidence.identityIds!].sort()).toEqual(people.map((p) => p.id).sort());
    expect(spray!.evidence).toMatchObject({ count: 10, networks: ['203.0.113.50'] });
    // A network is nobody's risk.
    expect(await f.iam.store.find('identityRisk', { tenantId: f.tenantId })).toEqual([]);

    // The burst goes on in the next run: it keeps its dedupe key, so nothing new is recorded.
    await failPassword(f, people[0]!.name, '203.0.113.50');
    await failPassword(f, people[1]!.name, '203.0.113.50');
    expect((await detect(f)).detections).toBe(0);
    expect(await detections(f, 'password-spray')).toHaveLength(1);
  });

  it('password-spray: trusted networks and a disabled rule report nothing', async () => {
    const f = await organizationFixture();
    const people = await members(f, 'trusted', 10);
    const owner = await f.ownerSignIn();
    await f.iam.api.threats.configure(owner, {
      tenantId: f.tenantId,
      trustedNetworks: ['203.0.113.0/24'],
    });
    await detect(f);

    for (const person of people) await failPassword(f, person.name, '203.0.113.60');
    expect((await detect(f)).detections).toBe(0);

    await f.iam.api.threats.configure(owner, {
      tenantId: f.tenantId,
      rules: { 'password-spray': { enabled: false } },
    });
    for (const person of people) await failPassword(f, person.name, '198.51.100.60');
    await detect(f);
    expect(await detections(f, 'password-spray')).toEqual([]);
    // Trusting a network and turning a rule off are each a weakened guardrail (raised by the settings API, not the
    // engine).
    const guardrails = (await detections(f, 'guardrail-weakened')).map(
      (detection) => detection.metadata,
    );
    expect(guardrails).toHaveLength(2);
    expect(guardrails).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ disabledRules: [], weakened: ['trustedNetworks'] }),
        expect.objectContaining({ disabledRules: ['password-spray'], weakened: [] }),
      ]),
    );

    // Enabled again, the next failure from the untrusted network judges the window it closes.
    await f.iam.api.threats.configure(owner, {
      tenantId: f.tenantId,
      rules: { 'password-spray': null },
    });
    await failPassword(f, people[0]!.name, '198.51.100.60');
    expect((await detect(f)).detections).toBe(1);
    const sprays = await detections(f, 'password-spray');
    expect(sprays.map((detection) => detection.network)).toEqual(['198.51.100.60']);
    expect(sprays[0]!.evidence.networks).toEqual(['198.51.100.60']);
  });

  it('brute-force-success: high from the failing network, lower from another', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    // Alice was signed in before the attack began.
    await from(f, '192.0.2.10', () => f.signIn('alice'));
    await detect(f);

    await failPassword(f, 'alice', '198.51.100.7', 5);
    await from(f, '198.51.100.7', () => f.signIn('alice'));
    await failPassword(f, 'bob', '198.51.100.8', 5);
    await from(f, '192.0.2.44', () => f.signIn('bob'));
    // Four failures stay below the threshold.
    await failPassword(f, 'carol', '198.51.100.9', 4);
    await from(f, '198.51.100.9', () => f.signIn('carol'));
    const run = await detect(f);
    expect(run.detections).toBe(2);

    const found = await detections(f, 'brute-force-success');
    const byIdentity = new Map(found.map((detection) => [detection.identityId, detection]));
    expect(byIdentity.get(alice.id)).toMatchObject({
      severity: 'high',
      network: '198.51.100.7',
      subject: { type: 'identity', id: alice.id },
      metadata: { failures: 5, threshold: 5, fromFailingNetwork: true },
      evidence: { count: 6 },
    });
    expect(byIdentity.get(bob.id)).toMatchObject({
      severity: 'medium',
      network: '192.0.2.44',
      metadata: { failures: 5, fromFailingNetwork: false },
    });
    expect(byIdentity.has(carol.id)).toBe(false);
    // Five failures are not password guessing (ten are).
    expect(await detections(f, 'brute-force')).toEqual([]);

    // The flagged sign-in opens the account-takeover window on the baseline.
    const baseline = await f.iam.store.get<ThreatBaseline>('threatBaselines', alice.id);
    expect(baseline?.riskySignIn).toMatchObject({
      ruleId: 'brute-force-success',
      detectionId: byIdentity.get(alice.id)!.id,
    });

    // The sign-in ended the streak: signing in again raises nothing.
    await from(f, '198.51.100.7', () => f.signIn('alice'));
    expect((await detect(f)).detections).toBe(0);
  });

  it('mfa-bombardment: wrong second-factor codes after a correct password', async () => {
    const f = await organizationFixture();
    const frank = await f.member('frank');
    const secret = await enrollAuthenticator(f, (await f.signIn('frank')).token);
    await detect(f);

    const ip = '203.0.113.70';
    const challenge = await from(f, ip, () =>
      f.iam.api.auth.signIn({
        tenantId: f.tenantId,
        email: 'frank@acme.test',
        password: 'a strong frank password',
      }),
    );
    if (!('mfaRequired' in challenge)) throw new Error('Expected an MFA challenge');
    const wrong = totp(f, secret) === '000000' ? '111111' : '000000';
    for (let attempt = 0; attempt < 5; attempt++)
      await expect(
        from(f, ip, () =>
          f.iam.api.auth.verifyMfa({
            tenantId: f.tenantId,
            challenge: challenge.challenge,
            code: wrong,
          }),
        ),
      ).rejects.toMatchObject({ code: 'INVALID_MFA' });
    expect((await detect(f)).detections).toBe(1);
    const [bombardment] = await detections(f, 'mfa-bombardment');
    expect(bombardment).toMatchObject({
      severity: 'high',
      identityId: frank.id,
      network: ip,
      metadata: { peak: 5, threshold: 5, networks: 1 },
    });
    // Wrong codes are not wrong passwords.
    expect(await detections(f, 'brute-force')).toEqual([]);
  });

  it('new-network: learns the first network, then reports a new one for the owner', async () => {
    const f = await organizationFixture();
    await f.member('alice');
    // The fixture's own sign-ins carry no address: the owner's baseline starts without networks.
    await detect(f);
    const initial = await f.iam.store.get<ThreatBaseline>('threatBaselines', f.ownerId);
    expect(initial?.networks).toEqual([]);

    await from(f, '198.51.100.20', () => f.ownerSignIn());
    expect((await detect(f)).detections).toBe(0);
    const learned = await f.iam.store.get<ThreatBaseline>('threatBaselines', f.ownerId);
    expect(learned?.networks.map((network) => network.key)).toEqual(['198.51.100.20']);
    expect(learned?.userAgents.map((agent) => agent.value)).toEqual(['threat-rules-test']);

    await from(f, '198.51.100.20', () => f.ownerSignIn());
    await from(f, '203.0.113.21', () => f.ownerSignIn());
    const run = await detect(f);
    expect(run.detections).toBe(1);
    const [unfamiliar] = await detections(f, 'new-network');
    expect(unfamiliar).toMatchObject({
      severity: 'medium',
      identityId: f.ownerId,
      network: '203.0.113.21',
      subject: { type: 'identity', id: f.ownerId },
      metadata: { privileged: true, knownNetworks: 1 },
    });
    // Once seen, the network is familiar.
    await from(f, '203.0.113.21', () => f.ownerSignIn());
    expect((await detect(f)).detections).toBe(0);
    // A trusted network is never reported, though it is learned.
    await f.iam.api.threats.configure(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustedNetworks: ['192.0.2.0/24'],
    });
    await from(f, '192.0.2.5', () => f.ownerSignIn());
    expect((await detect(f)).detections).toBe(0);
    expect(
      (await f.iam.store.get<ThreatBaseline>('threatBaselines', f.ownerId))?.networks.map(
        (network) => network.key,
      ),
    ).toEqual(['198.51.100.20', '203.0.113.21', '192.0.2.5']);

    // A person without administrator access is reported only when the tenant asks for everyone (at low severity).
    await from(f, '198.51.100.22', () => f.signIn('alice'));
    await detect(f);
    await from(f, '198.51.100.23', () => f.signIn('alice'));
    expect((await detect(f)).detections).toBe(0);
    await f.iam.api.threats.configure(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      rules: { 'new-network': { everyone: true } },
    });
    await from(f, '198.51.100.24', () => f.signIn('alice'));
    expect((await detect(f)).detections).toBe(1);
    const everyone = (await detections(f, 'new-network')).find(
      (detection) => detection.identityId !== f.ownerId,
    );
    expect(everyone).toMatchObject({
      severity: 'low',
      network: '198.51.100.24',
      metadata: { privileged: false, knownNetworks: 2 },
    });
  });

  it('session-hijack: a bound session presented from another network, once per session', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    await f.iam.api.tenants.setAuthPolicy(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      authPolicy: { bindSessionsToIp: true },
    });
    await detect(f);

    const signedIn = await from(f, '198.51.100.30', () => f.signIn('alice'));
    const credential = { token: signedIn.token };
    await from(f, '198.51.100.30', () => f.iam.api.auth.getSession(credential));
    expect((await detect(f)).detections).toBe(0);

    for (let attempt = 0; attempt < 2; attempt++)
      await expect(
        from(f, '203.0.113.31', () => f.iam.api.auth.getSession(credential)),
      ).rejects.toMatchObject({ code: 'SESSION_NETWORK_MISMATCH' });
    const run = await detect(f);
    expect(run.detections).toBe(1);
    const [hijack] = await detections(f, 'session-hijack');
    expect(hijack).toMatchObject({
      severity: 'high',
      identityId: alice.id,
      network: '203.0.113.31',
      metadata: {
        sessionId: signedIn.session.id,
        sessionIp: '198.51.100.30',
        ip: '203.0.113.31',
      },
    });
    expect([...hijack!.evidence.networks!].sort()).toEqual(['198.51.100.30', '203.0.113.31']);

    // The same stolen session presented again later is the same detection.
    await expect(
      from(f, '203.0.113.32', () => f.iam.api.auth.getSession(credential)),
    ).rejects.toMatchObject({ code: 'SESSION_NETWORK_MISMATCH' });
    expect((await detect(f)).detections).toBe(0);
  });

  it('account-takeover-persistence: a password change after a risky sign-in, within the window', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    await f.member('carol');
    await f.member('dave');
    await detect(f);

    // Alice: the risky sign-in and the change are read in the same run.
    await failPassword(f, 'alice', '198.51.100.40', 5);
    const aliceSession = await from(f, '198.51.100.40', () => f.signIn('alice'));
    await f.iam.api.auth.changePassword(
      { token: aliceSession.token },
      { currentPassword: 'a strong alice password', password: 'a brand new alice password' },
    );
    // Bob: the risky sign-in now, the change in a later run.
    await failPassword(f, 'bob', '198.51.100.41', 5);
    const bobSession = await from(f, '198.51.100.41', () => f.signIn('bob'));
    // Dave changes his password without any risky sign-in.
    const daveSession = await f.signIn('dave');
    await f.iam.api.auth.changePassword(
      { token: daveSession.token },
      { currentPassword: 'a strong dave password', password: 'a brand new dave password' },
    );
    await detect(f);
    const first = await detections(f, 'account-takeover-persistence');
    expect(first).toHaveLength(1);
    const aliceSuccess = (await detections(f, 'brute-force-success')).find(
      (detection) => detection.identityId === alice.id,
    )!;
    expect(first[0]).toMatchObject({
      identityId: alice.id,
      severity: 'high',
      metadata: {
        changedAction: 'auth:password:change',
        riskySignInRuleId: 'brute-force-success',
        riskySignInKey: aliceSuccess.uniqueKey,
      },
    });
    expect(first[0]!.evidence.actions).toEqual(['auth:session:create', 'auth:password:change']);
    // Same person, same incident.
    expect(first[0]!.incidentId).toBe(aliceSuccess.incidentId);

    f.advance(2 * minute);
    await f.iam.api.auth.changePassword(
      { token: bobSession.token },
      { currentPassword: 'a strong bob password', password: 'a brand new bob password' },
    );
    expect((await detect(f)).detections).toBe(1);
    const bobSuccess = (await detections(f, 'brute-force-success')).find(
      (detection) => detection.identityId === bob.id,
    )!;
    const bobChange = (await detections(f, 'account-takeover-persistence')).find(
      (detection) => detection.identityId === bob.id,
    );
    expect(bobChange?.metadata).toMatchObject({
      changedAction: 'auth:password:change',
      riskySignInDetectionId: bobSuccess.id,
    });

    // Carol: the change comes more than an hour after the risky sign-in.
    await failPassword(f, 'carol', '198.51.100.42', 5);
    await from(f, '198.51.100.42', () => f.signIn('carol'));
    expect((await detect(f)).detections).toBe(1);
    f.advance(61 * minute);
    const carolLater = await from(f, '198.51.100.42', () => f.signIn('carol'));
    await f.iam.api.auth.changePassword(
      { token: carolLater.token },
      { currentPassword: 'a strong carol password', password: 'a brand new carol password' },
    );
    expect((await detect(f)).detections).toBe(0);
    expect(await detections(f, 'account-takeover-persistence')).toHaveLength(2);
  });

  it('account-takeover-persistence: enrolling an authenticator after a risky sign-in', async () => {
    const f = await organizationFixture();
    const erin = await f.member('erin');
    await detect(f);

    await failPassword(f, 'erin', '198.51.100.43', 5);
    const session = await from(f, '198.51.100.43', () => f.signIn('erin'));
    await enrollAuthenticator(f, session.token);
    await detect(f);
    const [persistence] = await detections(f, 'account-takeover-persistence');
    expect(persistence).toMatchObject({
      identityId: erin.id,
      severity: 'high',
      metadata: { changedAction: 'auth:mfa:enable', riskySignInRuleId: 'brute-force-success' },
    });
    expect(persistence!.summary).toContain('enrolled an authenticator app');
  });

  it('counting rules hold the administrator behind a "view as" session responsible', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const owner = await f.ownerSignIn();
    await f.iam.api.tenants.setAuthPolicy(owner, {
      tenantId: f.tenantId,
      authPolicy: { allowImpersonation: true },
    });
    await detect(f);

    // Support staff checking what a member cannot do produce the member's refusals, not the member.
    const viewing = await f.iam.api.identities.impersonate(owner, {
      tenantId: f.tenantId,
      identityId: alice.id,
      reason: 'why can alice not read documents?',
    });
    for (let index = 0; index < 30; index++)
      expect(
        (
          await f.iam.authorize({
            token: viewing.token,
            tenantId: f.tenantId,
            action: 'documents:read',
            resource: doc,
          })
        ).allowed,
      ).toBe(false);
    expect((await detect(f)).detections).toBe(1);
    const [denials] = await detections(f, 'denial-burst');
    expect(denials).toMatchObject({
      identityId: f.ownerId,
      subject: { type: 'identity', id: f.ownerId },
      metadata: { peak: 30, viewedAs: [alice.id] },
    });
    expect(denials!.summary).toContain('while viewing as someone else');
    expect(
      await f.iam.api.threats.getRisk(owner, { tenantId: f.tenantId, identityId: alice.id }),
    ).toMatchObject({ level: 'none', score: 0 });
  });

  it('mass-deletion: twenty identities and roles removed by one person', async () => {
    const f = await organizationFixture();
    const owner = await f.ownerSignIn();
    const roles: string[] = [];
    for (let index = 0; index < 15; index++)
      roles.push(
        (
          await f.iam.api.roles.create(owner, {
            tenantId: f.tenantId,
            name: `Disposable ${index}`,
            document: {
              version: 1,
              statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
            },
          })
        ).id,
      );
    const people: string[] = [];
    for (let index = 0; index < 5; index++)
      people.push(
        (
          await f.iam.api.identities.create(owner, {
            tenantId: f.tenantId,
            email: `leaver${index}@acme.test`,
            name: `Leaver ${index}`,
          })
        ).id,
      );
    await detect(f);

    for (const roleId of roles)
      await f.iam.api.roles.delete(owner, { tenantId: f.tenantId, roleId });
    for (const identityId of people.slice(0, 4))
      await f.iam.api.identities.delete(owner, { tenantId: f.tenantId, identityId });
    // Nineteen: below the threshold. Identity deletion counts once, not also as its operation envelope.
    expect((await detect(f)).detections).toBe(0);

    await f.iam.api.identities.delete(owner, { tenantId: f.tenantId, identityId: people[4]! });
    expect((await detect(f)).detections).toBe(1);
    const [deletion] = await detections(f, 'mass-deletion');
    expect(deletion).toMatchObject({
      severity: 'high',
      identityId: f.ownerId,
      subject: { type: 'identity', id: f.ownerId },
      metadata: { peak: 20, threshold: 20, identities: 5 },
    });
    expect([...deletion!.evidence.identityIds!].sort()).toEqual([...people].sort());
    expect([...deletion!.evidence.actions!].sort()).toEqual([
      'iam:roles:delete',
      'identity:delete',
    ]);
    expect(deletion!.evidence.eventIds).toHaveLength(20);
  });

  it('impersonation-burst: five "view as" sessions in a day; impersonated sign-ins teach nothing', async () => {
    const f = await organizationFixture();
    const people = await members(f, 'viewed', 5);
    const owner = await f.ownerSignIn();
    await f.iam.api.tenants.setAuthPolicy(owner, {
      tenantId: f.tenantId,
      authPolicy: { allowImpersonation: true },
    });
    await detect(f);

    const impersonate = (identityId: string) =>
      from(f, '198.51.100.50', () =>
        f.iam.api.identities.impersonate(owner, {
          tenantId: f.tenantId,
          identityId,
          reason: 'support ticket',
        }),
      );
    for (const person of people.slice(0, 4)) await impersonate(person.id);
    expect((await detect(f)).detections).toBe(0);
    await impersonate(people[4]!.id);
    expect((await detect(f)).detections).toBe(1);
    const [burst] = await detections(f, 'impersonation-burst');
    expect(burst).toMatchObject({
      severity: 'medium',
      identityId: f.ownerId,
      metadata: { peak: 5, threshold: 5, targets: 5 },
    });
    expect([...burst!.evidence.identityIds!].sort()).toEqual(people.map((p) => p.id).sort());
    // Sessions opened by an administrator are not the members' own sign-ins.
    for (const person of people)
      expect(await f.iam.store.get('threatBaselines', person.id)).toBeUndefined();
  });

  it('denial-burst: thirty refusals of one person in ten minutes', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const session = await f.signIn('alice');
    await detect(f);
    const attempt = async () =>
      (
        await f.iam.authorize({
          token: session.token,
          tenantId: f.tenantId,
          action: 'documents:read',
          resource: doc,
        })
      ).allowed;
    for (let index = 0; index < 29; index++) expect(await attempt()).toBe(false);
    expect((await detect(f)).detections).toBe(0);
    expect(await attempt()).toBe(false);
    expect((await detect(f)).detections).toBe(1);
    const [denials] = await detections(f, 'denial-burst');
    expect(denials).toMatchObject({
      severity: 'medium',
      identityId: alice.id,
      metadata: { peak: 30, threshold: 30, agent: false },
      evidence: { actions: ['documents:read'] },
    });
  });

  it('recon-burst: administrative reads over a lowered threshold; the threats console is not counted', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const owner = await f.ownerSignIn();
    await f.iam.api.threats.configure(owner, {
      tenantId: f.tenantId,
      rules: { 'recon-burst': { threshold: 20 } },
    });
    await detect(f);

    for (let index = 0; index < 25; index++)
      await f.iam.api.threats.rules(owner, { tenantId: f.tenantId });
    for (let index = 0; index < 19; index++)
      await f.iam.api.identities.get(owner, { tenantId: f.tenantId, identityId: alice.id });
    expect((await detect(f)).detections).toBe(0);

    await f.iam.api.identities.get(owner, { tenantId: f.tenantId, identityId: alice.id });
    expect((await detect(f)).detections).toBe(1);
    const [recon] = await detections(f, 'recon-burst');
    expect(recon).toMatchObject({
      severity: 'low',
      identityId: f.ownerId,
      metadata: { kind: 'reads', peak: 20, threshold: 20 },
      evidence: { actions: ['iam:identities:read'] },
    });
  });

  it('guardrail-weakened: the tenant sign-in policy loses a protection', async () => {
    const f = await organizationFixture();
    await detect(f);

    // Tightening is not reported. Root sets it: an owner without a second factor would lock themselves out.
    await f.iam.api.tenants.setAuthPolicy(f.rootCredential, {
      tenantId: f.tenantId,
      authPolicy: { requireMfa: true, notifyNewSignIn: true },
    });
    expect((await detect(f)).detections).toBe(0);

    await f.iam.api.tenants.setAuthPolicy(f.rootCredential, {
      tenantId: f.tenantId,
      authPolicy: { notifyNewSignIn: true },
    });
    expect((await detect(f)).detections).toBe(1);
    const [dropped] = await detections(f, 'guardrail-weakened');
    expect(dropped).toMatchObject({
      severity: 'medium',
      subject: { type: 'tenant', id: f.tenantId },
      metadata: { change: 'auth-policy', weakened: ['requireMfa'] },
    });
    // A root administrator is not an identity of this tenant: nobody's risk here.
    expect(dropped!.identityId).toBeUndefined();

    // Set and dropped again within one run, by the owner: judged in chain order.
    const owner = await f.ownerSignIn();
    await f.iam.api.tenants.setAuthPolicy(owner, {
      tenantId: f.tenantId,
      authPolicy: { notifyNewSignIn: true, bindSessionsToIp: true },
    });
    await f.iam.api.tenants.setAuthPolicy(owner, { tenantId: f.tenantId, authPolicy: null });
    expect((await detect(f)).detections).toBe(1);
    const latest = (await detections(f, 'guardrail-weakened')).at(-1);
    expect(latest).toMatchObject({
      identityId: f.ownerId,
      metadata: { weakened: ['bindSessionsToIp', 'notifyNewSignIn'] },
    });
  });

  it('dormant-reactivated: a sign-in after the dormancy period', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    await f.member('bob');
    await from(f, '198.51.100.70', () => f.signIn('alice'));
    await from(f, '198.51.100.71', () => f.signIn('bob'));
    await detect(f);

    f.advance(60 * day);
    await from(f, '198.51.100.71', () => f.signIn('bob'));
    expect((await detect(f)).detections).toBe(0);

    f.advance(31 * day);
    await from(f, '198.51.100.70', () => f.signIn('alice'));
    await from(f, '198.51.100.71', () => f.signIn('bob'));
    expect((await detect(f)).detections).toBe(1);
    const [dormant] = await detections(f, 'dormant-reactivated');
    expect(dormant).toMatchObject({
      severity: 'medium',
      identityId: alice.id,
      network: '198.51.100.70',
      metadata: { idleDays: 91, dormantDays: 90 },
    });
    expect(
      (await f.iam.store.get<ThreatBaseline>('threatBaselines', alice.id))?.riskySignIn,
    ).toMatchObject({ ruleId: 'dormant-reactivated', detectionId: dormant!.id });
  });

  it('is idempotent across runs, including a full re-read of the trail', async () => {
    const f = await organizationFixture();
    const carol = await f.member('carol');
    await detect(f);

    await failPassword(f, 'carol', '198.51.100.80', 10);
    expect((await detect(f)).detections).toBe(1);
    // Past the sign-in rate limit window, still inside the brute-force-success window.
    f.advance(16 * minute);
    const session = await from(f, '198.51.100.80', () => f.signIn('carol'));
    await f.iam.api.auth.changePassword(
      { token: session.token },
      { currentPassword: 'a strong carol password', password: 'a brand new carol password' },
    );
    expect((await detect(f)).detections).toBe(2);
    expect((await detect(f)).detections).toBe(0);

    const snapshot = async () => ({
      detections: (await detections(f)).map((detection) => detection.uniqueKey).sort(),
      incidents: (
        await f.iam.store.find<ThreatIncident>('threatIncidents', { tenantId: f.tenantId })
      ).map((incident) => [incident.id, incident.detectionCount]),
      risk: (await f.iam.store.get<IdentityRisk>('identityRisk', carol.id))?.contributions,
    });
    const before = await snapshot();
    expect(before.detections).toHaveLength(3);
    // Forget how far the engine read: the next run starts a day back and reads everything again.
    await f.database.transaction((tx) => tx.delete('threatCursors', f.tenantId));
    const reread = await detect(f);
    expect(reread.eventsScanned).toBeGreaterThan(20);
    expect(reread.detections).toBe(0);
    expect(await snapshot()).toEqual(before);
  });

  it('principal.riskLevel flips a policy once detections make the person high risk', async () => {
    const f = await organizationFixture();
    const mallory = await f.member('mallory');
    const owner = await f.ownerSignIn();
    const role = await f.iam.api.roles.create(owner, {
      tenantId: f.tenantId,
      name: 'Readers unless risky',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['documents:read'], resources: ['*'] },
          {
            effect: 'deny',
            actions: ['documents:read'],
            resources: ['*'],
            conditions: { StringEquals: { 'principal.riskLevel': 'high' } },
          },
        ],
      },
    });
    await f.iam.api.bindings.create(owner, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: mallory.id,
    });
    await f.iam.api.threats.configure(owner, {
      tenantId: f.tenantId,
      rules: { 'brute-force': { threshold: 5 } },
    });
    await detect(f);

    await failPassword(f, 'mallory', '198.51.100.90', 5);
    const session = await from(f, '198.51.100.90', () => f.signIn('mallory'));
    const canRead = async () =>
      (
        await f.iam.authorize({
          token: session.token,
          tenantId: f.tenantId,
          action: 'documents:read',
          resource: doc,
        })
      ).allowed;
    expect(await canRead()).toBe(true);

    // Password guessing (medium, 25) and the sign-in that followed (high, 50): 75 points, high risk.
    expect((await detect(f)).detections).toBe(2);
    const risk = await f.iam.api.threats.getRisk(owner, {
      tenantId: f.tenantId,
      identityId: mallory.id,
    });
    expect(risk).toMatchObject({ level: 'high', score: 75 });
    expect(await canRead()).toBe(false);
    const changes = (
      await f.iam.store.find<AuditEvent>('audit', {
        tenantId: f.tenantId,
        action: 'threat:risk-change',
        resourceId: mallory.id,
      })
    ).sort((a, b) => a.sequence! - b.sequence!);
    expect(changes.at(-1)?.metadata).toMatchObject({ to: 'high', score: 75 });

    // Closing the incident as a false positive takes the points back.
    const [guessing] = await detections(f, 'brute-force');
    await f.iam.api.threats.resolveIncident(owner, {
      tenantId: f.tenantId,
      incidentId: guessing!.incidentId!,
      resolution: 'false-positive',
    });
    expect(await canRead()).toBe(true);
  });
});

describe('threat rules: stable judgments', () => {
  it('account-takeover-persistence: a risky sign-in judged harmless opens no window', async () => {
    const f = await organizationFixture();
    await f.member('bob');
    await detect(f);
    await failPassword(f, 'bob', '198.51.100.43', 5);
    const bobSession = await from(f, '198.51.100.43', () => f.signIn('bob'));
    expect((await detect(f)).detections).toBe(1);
    const [risky] = await detections(f, 'brute-force-success');
    await f.iam.api.threats.dismissDetection(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      detectionId: risky!.id,
      reason: 'Bob mistyped his new password',
    });
    f.advance(2 * minute);
    await f.iam.api.auth.changePassword(
      { token: bobSession.token },
      { currentPassword: 'a strong bob password', password: 'a brand new bob password' },
    );
    expect((await detect(f)).detections).toBe(0);
    expect(await detections(f, 'account-takeover-persistence')).toEqual([]);
  });

  it('counting rules keep a burst’s dedupe key when the lookback is cut short', async () => {
    const tenantId = 'tenant-cut';
    const midnight = Date.UTC(2026, 8, 24);
    // An integration denied every 12 seconds since midnight: a burst that never pauses.
    const events: AuditEvent[] = Array.from({ length: 3600 }, (_, index) => ({
      id: `deny-${index}`,
      tenantId,
      actorId: 'integration-7',
      action: 'documents:read',
      resourceId: 'd1',
      timestamp: midnight + index * 12_000,
      sequence: index + 1,
      outcome: 'deny',
    }));
    const facts: RuleFacts = {
      identity: async () => undefined,
      isPrivileged: async () => false,
      isAdminRole: async () => false,
      holdsRole: async () => false,
    };
    /** One run over [from, to) whose lookback the engine's cap cut at `historyFrom`. */
    const run = async (from: number, to: number, historyFrom: number) => {
      const { candidates } = await evaluateThreatRules({
        tenantId,
        events: events.filter((event) => event.timestamp >= from && event.timestamp < to),
        history: events.filter((event) => event.timestamp >= historyFrom && event.timestamp < from),
        historyFrom,
        settings: resolveThreatSettings(),
        baselines: new Map(),
        state: {},
        facts,
        now: to,
      });
      return candidates
        .filter((candidate) => candidate.ruleId === 'denial-burst')
        .map((candidate) => candidate.dedupeKey);
    };
    // Two runs five minutes apart near noon; the cut moves with the newest events, two hours behind them.
    const noon = midnight + 12 * 60 * minute - minute;
    const first = await run(noon - 10 * minute, noon - 5 * minute, noon - 130 * minute);
    const second = await run(noon - 5 * minute, noon, noon - 125 * minute);
    expect(first).toHaveLength(1);
    expect(second).toEqual(first);
  });
});
