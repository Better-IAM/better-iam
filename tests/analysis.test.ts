import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, type AccessFinding } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { AuditEvent, IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';
import { closeFixtures, organizationFixture } from './support/organization.js';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});
afterEach(closeFixtures);

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'analysis-test-secret-with-at-least-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
      sessionLifetimeMs: 30 * 86_400_000,
      sessionIdleTimeoutMs: 30 * 86_400_000,
    },
    permissions: { actions: ['documents:read', 'documents:write'] },
    resolveResource: async (reference) => reference,
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const challenge = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const generator = authenticator.clone();
  generator.options = { epoch: clock };
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: generator.generate(enrollment.secret),
  });
  const created = await iam.api.tenants.create(
    { token: session.token },
    { parentId: root.tenant.id, name: 'Acme', type: 'organization', ownerEmail: 'owner@acme.test' },
  );
  await iam.auth.dispatchOutbox();
  const invitation = inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: 'Owner',
    password: 'a strong tenant owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  return {
    iam,
    tenantId: created.tenant.id,
    owner: { token: owner.token },
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

const kinds = (findings: AccessFinding[]) =>
  findings.map((finding) => `${finding.kind}:${finding.subject.name ?? finding.subject.id}`).sort();

describe('access analysis', () => {
  it('reports risky and stale configuration, ordered by severity', async () => {
    const f = await fixture();
    const { tenantId, owner } = f;
    const api = f.iam.api;
    const admin = await api.policies.create(owner, {
      tenantId,
      name: 'Everything',
      document: { version: 1, statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }] },
    });
    const broad = await api.policies.create(owner, {
      tenantId,
      name: 'Documents',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['*'] }],
      },
    });
    await api.policies.create(owner, {
      tenantId,
      name: 'Scoped admin',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['*'],
            resources: ['*'],
            conditions: { Bool: { 'principal.mfa': true } },
          },
        ],
      },
    });
    const admins = await api.roles.create(owner, {
      tenantId,
      name: 'Admins',
      policyIds: [admin.id],
    });
    const editors = await api.roles.create(owner, {
      tenantId,
      name: 'Editors',
      policyIds: [broad.id],
    });
    await api.roles.create(owner, { tenantId, name: 'Unused', permissions: ['documents:read'] });
    const alice = await api.identities.create(owner, {
      tenantId,
      email: 'alice@acme.test',
      name: 'Alice',
      password: 'a strong alice password',
    });
    const bot = await api.serviceAccounts.create(owner, { tenantId, name: 'deploy-bot' });
    await api.bindings.create(owner, {
      tenantId,
      roleId: admins.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: admins.id,
      subjectType: 'identity',
      subjectId: bot.id,
    });
    const ghosts = await api.groups.create(owner, { tenantId, name: 'Ghosts' });
    await api.bindings.create(owner, {
      tenantId,
      roleId: editors.id,
      subjectType: 'group',
      subjectId: ghosts.id,
    });
    // Alice signs in once so she is not yet dormant.
    await api.auth.signIn({
      tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });

    const report = await api.analysis.findings(owner, { tenantId });
    // Alice's direct, permanent Admins binding is standing administrator access. Everything's only lint warning
    // (unrestricted-admin) already has its own finding, so no separate policy-lint finding is reported.
    expect(kinds(report.findings)).toEqual(
      [
        'admin-without-mfa:alice@acme.test',
        'admin-without-mfa:owner@acme.test',
        'broad-action-wildcard:Documents',
        'empty-group-with-access:Ghosts',
        'service-account-admin:deploy-bot',
        'standing-privileged-access:alice@acme.test',
        'unattached-policy:Scoped admin',
        'unrestricted-admin-policy:Everything',
        'unused-role:Unused',
      ].sort(),
    );
    expect(report.findings.map((finding) => finding.severity)).toEqual(
      [...report.findings.map((finding) => finding.severity)].sort(
        (a, b) => ['high', 'medium', 'low'].indexOf(a) - ['high', 'medium', 'low'].indexOf(b),
      ),
    );
    expect(report.summary).toEqual({ high: 3, medium: 3, low: 3, suppressed: 0 });

    // Findings are stable across runs, so they can be suppressed with a reason.
    const again = await api.analysis.findings(owner, { tenantId });
    expect(again.findings.map((finding) => finding.id)).toEqual(
      report.findings.map((finding) => finding.id),
    );
    const unused = report.findings.find((finding) => finding.kind === 'unused-role')!;
    await api.analysis.suppress(owner, {
      tenantId,
      findingId: unused.id,
      reason: 'Kept for the upcoming audit team',
    });
    const suppressed = await api.analysis.findings(owner, { tenantId });
    expect(suppressed.findings.some((finding) => finding.id === unused.id)).toBe(false);
    expect(suppressed.summary.suppressed).toBe(1);
    const all = await api.analysis.findings(owner, { tenantId, includeSuppressed: true });
    expect(all.findings.find((finding) => finding.id === unused.id)?.suppressed).toMatchObject({
      reason: 'Kept for the upcoming audit team',
    });
    await api.analysis.unsuppress(owner, { tenantId, findingId: unused.id });
    expect(
      (await api.analysis.findings(owner, { tenantId })).findings.some(
        (finding) => finding.id === unused.id,
      ),
    ).toBe(true);
    await expect(
      api.analysis.suppress(owner, { tenantId, findingId: 'not-a-finding', reason: 'x' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('reports dormant members who still hold access', async () => {
    const f = await fixture();
    const { tenantId, owner } = f;
    const readers = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Readers',
      permissions: ['documents:read'],
    });
    const bob = await f.iam.api.identities.create(owner, {
      tenantId,
      email: 'bob@acme.test',
      name: 'Bob',
      password: 'a strong bob password',
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: readers.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const robot = await f.iam.api.serviceAccounts.create(owner, { tenantId, name: 'nightly' });
    await f.iam.api.credentials.create(owner, { tenantId, identityId: robot.id, name: 'backup' });
    const fresh = await f.iam.api.analysis.findings(owner, { tenantId });
    expect(fresh.findings.some((finding) => finding.kind === 'dormant-access')).toBe(false);
    expect(fresh.findings.some((finding) => finding.kind === 'stale-api-key')).toBe(false);
    f.advance(10 * 86_400_000);
    // The owner keeps their session alive; Bob never signed in.
    const later = await f.iam.api.analysis.findings(owner, { tenantId, dormantDays: 7 });
    const dormant = later.findings.filter((finding) => finding.kind === 'dormant-access');
    expect(dormant.map((finding) => finding.subject.name).sort()).toEqual([
      'bob@acme.test',
      'owner@acme.test',
    ]);
    expect(dormant.find((finding) => finding.subject.name === 'bob@acme.test')?.title).toContain(
      'never signed in',
    );
    expect(later.findings.filter((finding) => finding.kind === 'stale-api-key')).toEqual([
      expect.objectContaining({
        severity: 'medium',
        title: 'API key backup has never been used',
        subject: expect.objectContaining({ type: 'credential', name: 'backup' }),
      }),
    ]);
    await expect(
      f.iam.api.analysis.findings(owner, { tenantId, dormantDays: 0 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // Members without iam:analysis:read cannot run the analysis.
    const login = await f.iam.api.auth.signIn({
      tenantId,
      email: 'bob@acme.test',
      password: 'a strong bob password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    await expect(
      f.iam.api.analysis.findings({ token: login.token }, { tenantId }),
    ).rejects.toMatchObject({ status: 403 });
  });

  it('reports standing administrator bindings, not eligible, temporary, service, or group ones', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const api = f.iam.api;
    const admins = await api.roles.create(owner, {
      tenantId,
      name: 'Admins',
      document: { version: 1, statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }] },
    });
    const readers = await api.roles.create(owner, {
      tenantId,
      name: 'Readers',
      permissions: ['documents:read'],
    });
    const [alice, bob, carol, dave] = [
      await f.member('alice'),
      await f.member('bob'),
      await f.member('carol'),
      await f.member('dave'),
    ];
    const bot = await api.serviceAccounts.create(owner, { tenantId, name: 'deploy-bot' });
    const team = await api.groups.create(owner, { tenantId, name: 'Team' });
    const bind = (roleId: string, subjectId: string, extra: Record<string, unknown> = {}) =>
      api.bindings.create(owner, {
        tenantId,
        roleId,
        subjectType: 'identity',
        subjectId,
        ...extra,
      });
    const standing = await bind(admins.id, alice.id);
    await bind(admins.id, bob.id, { eligible: true });
    await bind(admins.id, carol.id, { expiresAt: f.now() + 86_400_000 });
    await bind(readers.id, dave.id);
    await bind(admins.id, bot.id);
    await bind(admins.id, team.id, { subjectType: 'group' });

    const found = (await api.analysis.findings(owner, { tenantId })).findings.filter(
      (finding) => finding.kind === 'standing-privileged-access',
    );
    // The owner's protected Owner binding is not reported either.
    expect(found).toEqual([
      expect.objectContaining({
        severity: 'medium',
        title: 'alice@acme.test holds Admins as standing administrator access',
        subject: { type: 'identity', id: alice.id, name: 'alice@acme.test' },
      }),
    ]);
    expect(found[0]!.detail).toContain('eligible');
    await api.bindings.update(owner, { tenantId, bindingId: standing.id, eligible: true });
    expect(
      (await api.analysis.findings(owner, { tenantId })).findings.some(
        (finding) => finding.kind === 'standing-privileged-access',
      ),
    ).toBe(false);
  });

  it('reports eligible bindings nobody has activated once they outlive the dormant window', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const api = f.iam.api;
    const auditors = await api.roles.create(owner, {
      tenantId,
      name: 'Auditors',
      permissions: ['iam:audit:read'],
    });
    const elevators = await api.roles.create(owner, {
      tenantId,
      name: 'Elevators',
      permissions: ['iam:bindings:activate'],
    });
    const [alice, bob, carol] = [
      await f.member('alice'),
      await f.member('bob'),
      await f.member('carol'),
    ];
    const team = await api.groups.create(owner, { tenantId, name: 'Team' });
    const eligible = (subjectId: string, extra: Record<string, unknown> = {}) =>
      api.bindings.create(owner, {
        tenantId,
        roleId: auditors.id,
        subjectType: 'identity',
        subjectId,
        eligible: true,
        ...extra,
      });
    for (const person of [bob, carol])
      await api.bindings.create(owner, {
        tenantId,
        roleId: elevators.id,
        subjectType: 'identity',
        subjectId: person.id,
      });
    await eligible(alice.id);
    const used = await eligible(bob.id);
    const requested = await eligible(carol.id, { requireApproval: true });
    await eligible(team.id, { subjectType: 'group' });
    await api.bindings.activate(
      { token: (await f.signIn('bob')).token },
      {
        tenantId,
        bindingId: used.id,
      },
    );
    // Carol only asks; a request that is never approved is not an activation.
    await api.bindings.activate(
      { token: (await f.signIn('carol')).token },
      {
        tenantId,
        bindingId: requested.id,
      },
    );
    const unused = async (credential: { token: string }) =>
      (await api.analysis.findings(credential, { tenantId, dormantDays: 7 })).findings.filter(
        (finding) => finding.kind === 'unused-eligible-binding',
      );

    // Bindings as young as their subjects are not reported yet.
    expect(await unused(owner)).toEqual([]);
    f.advance(10 * 86_400_000);
    const later = await unused(await f.ownerSignIn());
    expect(
      later.map((finding) => `${finding.subject.type}:${finding.subject.name}`).sort(),
    ).toEqual(['group:Team', 'identity:alice@acme.test', 'identity:carol@acme.test']);
    expect(later.find((finding) => finding.subject.id === alice.id)).toMatchObject({
      severity: 'low',
      title: 'Eligible Auditors binding for alice@acme.test has no recorded activation',
      detail: expect.stringContaining('no activation'),
    });
    // Carol's request dates the binding from the audit trail.
    expect(later.find((finding) => finding.subject.id === carol.id)?.detail).toMatch(
      /existed for at least \d+ days/,
    );
    expect(new Set(later.map((finding) => finding.id)).size).toBe(3);
  });

  it('counts only activations the bindings API recorded, not audit events a member can provoke', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const api = f.iam.api;
    const auditors = await api.roles.create(f.ownerCredential, {
      tenantId,
      name: 'Auditors',
      permissions: ['iam:audit:read'],
    });
    const alice = await f.member('alice');
    const binding = await api.bindings.create(f.ownerCredential, {
      tenantId,
      roleId: auditors.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
    });
    f.advance(10 * 86_400_000);
    const unused = async () =>
      (await api.analysis.findings(await f.ownerSignIn(), { tenantId, dormantDays: 7 })).findings
        .filter((finding) => finding.kind === 'unused-eligible-binding')
        .map((finding) => finding.subject.id);
    expect(await unused()).toEqual([alice.id]);

    // Alice holds no permissions, yet authorize() audits each denial under the action and resource ID she names.
    const { token } = await f.signIn('alice');
    const forged = ['binding:activate', 'binding:activation-approved', 'binding:break-glass'];
    for (const action of forged)
      expect(
        await f.iam.authorize({
          token,
          tenantId,
          action,
          resource: { type: 'anything', id: binding.id },
        }),
      ).toMatchObject({ allowed: false });
    const audited = await f.database.find<AuditEvent>('audit', {
      tenantId,
      resourceId: binding.id,
    });
    expect(audited.map((event) => event.action).sort()).toEqual([...forged].sort());
    // None of those denials is an activation, so the dormant grant stays reported.
    expect(await unused()).toEqual([alice.id]);
  });

  it('reports manager links to missing or inactive people and manager loops', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const api = f.iam.api;
    const people: Record<string, { id: string }> = {};
    for (const name of ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'gina', 'hank'])
      people[name] = await f.member(name);
    const manage = (name: string, manager: string) =>
      api.identities.update(owner, {
        tenantId,
        identityId: people[name]!.id,
        managerId: people[manager]!.id,
      });
    // Links the API refuses (loops, unknown people) can still arrive through direct writes or imports.
    const link = (name: string, managerId: string) =>
      f.database.transaction(async (tx) =>
        tx.put('identities', {
          ...(await tx.get('identities', people[name]!.id))!,
          managerId,
        }),
      );
    await manage('alice', 'bob');
    await api.identities.setStatus(owner, {
      tenantId,
      identityId: people.bob!.id,
      status: 'disabled',
    });
    await link('carol', 'no-such-identity');
    await manage('gina', 'dave');
    await manage('dave', 'erin');
    await link('erin', people.dave!.id);
    await link('frank', people.frank!.id);
    await manage('hank', 'gina');

    const report = await api.analysis.findings(owner, { tenantId });
    const of = (kind: string) => report.findings.filter((finding) => finding.kind === kind);
    expect(
      of('orphaned-manager')
        .map((finding) => finding.title)
        .sort(),
    ).toEqual([
      "alice@acme.test's manager bob@acme.test is disabled",
      "carol@acme.test's manager no longer exists",
    ]);
    expect(of('orphaned-manager').every((finding) => finding.severity === 'low')).toBe(true);
    // Gina and Hank report into the loop without being part of it.
    const cycles = of('manager-cycle');
    expect(cycles.map((finding) => finding.subject.name).sort()).toEqual([
      'dave@acme.test',
      'erin@acme.test',
      'frank@acme.test',
    ]);
    expect(cycles.every((finding) => finding.severity === 'medium')).toBe(true);
    expect(cycles.find((finding) => finding.subject.id === people.dave!.id)?.detail).toContain(
      'dave@acme.test → erin@acme.test → dave@acme.test',
    );
    expect(cycles.find((finding) => finding.subject.id === people.frank!.id)?.title).toBe(
      "frank@acme.test's manager chain loops back to them",
    );
  });

  it('finds a manager loop at the end of a very deep reporting chain in linear time', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    // 10,000 people in one reporting chain whose last 30 form a loop, written directly (the API refuses loops).
    const size = 10_000;
    const loop = 30;
    const createdAt = f.now();
    await f.database.transaction(async (tx) => {
      for (let index = 0; index < size; index++)
        await tx.insert('identities', {
          id: `person-${index}`,
          tenantId,
          kind: 'user',
          name: `person-${index}`,
          status: 'active',
          emailVerified: false,
          rootAdmin: false,
          owner: false,
          createdAt,
          managerId: `person-${index + 1 < size ? index + 1 : size - loop}`,
        });
    });
    const started = performance.now();
    const cycles = (
      await f.iam.api.analysis.findings(f.ownerCredential, { tenantId })
    ).findings.filter((finding) => finding.kind === 'manager-cycle');
    expect(performance.now() - started).toBeLessThan(5000);
    // Only the loop's members are reported; the 9,970 people reporting into it are not part of it.
    expect(cycles.map((finding) => finding.subject.id).sort()).toEqual(
      Array.from({ length: loop }, (_, index) => `person-${size - loop + index}`).sort(),
    );
    // A long loop is shortened in the detail, starting and ending with the reported person.
    expect(cycles.find((finding) => finding.subject.id === 'person-9985')?.detail).toMatch(
      /^person-9985 → person-9986 → (person-\d+ → ){6}person-9993 → … 21 more → person-9985\. /,
    );
  });

  it('reports stored policies and inline role documents with lint warnings', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const api = f.iam.api;
    await api.policies.create(owner, {
      tenantId,
      name: 'Office network',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['documents/*'],
            conditions: { IpAddress: { 'request.ip': '10.0.0.0/8' } },
          },
          {
            effect: 'allow',
            actions: ['documents:write'],
            resources: ['documents/*'],
            conditions: { StringEquals: { 'principal.groups': 'writers' } },
          },
        ],
      },
    });
    // Informational notes alone (a service-wide wildcard) do not make a finding.
    await api.policies.create(owner, {
      tenantId,
      name: 'Clean',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['documents/*'] }],
      },
    });
    await api.roles.create(owner, {
      tenantId,
      name: 'Inline',
      document: {
        version: 1,
        statements: [
          {
            effect: 'deny',
            actions: ['documents:write'],
            resources: ['documents/*'],
            conditions: { StringEquals: { 'resource.type': 'secret' } },
          },
        ],
      },
    });
    await api.roles.create(owner, { tenantId, name: 'Plain', permissions: ['documents:read'] });

    const lint = (await api.analysis.findings(owner, { tenantId })).findings.filter(
      (finding) => finding.kind === 'policy-lint',
    );
    expect(lint.map((finding) => `${finding.subject.type}:${finding.subject.name}`).sort()).toEqual(
      ['policy:Office network', 'role:Inline'],
    );
    expect(lint.find((finding) => finding.subject.type === 'policy')).toMatchObject({
      severity: 'low',
      title: 'Policy Office network has 2 lint warnings',
      detail: expect.stringContaining('unknown-context-key, array-key-string-operator'),
    });
    expect(lint.find((finding) => finding.subject.type === 'role')).toMatchObject({
      title: "Role Inline's inline document has 2 lint warnings",
      detail: expect.stringContaining('optional-key-deny, unknown-context-key'),
    });
  });

  it('reads stored trust flags as roles.assume enforces them (fail-closed)', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    /** A cross-tenant identity trust whose stored flags are then replaced (an `undefined` value removes one). */
    const trustWith = async (flags: Record<string, unknown>) => {
      const trust = await f.iam.api.trust.create(f.rootCredential, {
        tenantId,
        sourceTenantId: f.root.tenant.id,
        sourceIdentityId: f.root.identity.id,
        roleId: role.id,
      });
      await f.iam.store.transaction(async (tx) => {
        const next: Record<string, unknown> = { ...(await tx.get('trusts', trust.id))!, ...flags };
        for (const [key, value] of Object.entries(flags)) if (value === undefined) delete next[key];
        await tx.put('trusts', next as never);
      });
      return trust.id;
    };
    const open = await trustWith({ requireMfa: false, passSourceAttributes: true });
    const legacy = await trustWith({ requireMfa: undefined, passSourceAttributes: undefined });
    const malformed = await trustWith({ requireMfa: 'no', passSourceAttributes: 'false' });
    const falsy = await trustWith({ requireMfa: 0, passSourceAttributes: 1 });
    const findings = (await f.iam.api.analysis.findings(f.ownerCredential, { tenantId })).findings;
    const subjects = (kind: string) =>
      findings
        .filter((finding) => finding.kind === kind)
        .map((finding) => finding.subject.id)
        .sort();
    // Only the boolean false waives MFA; a missing or malformed flag requires it, so no finding.
    expect(subjects('trust-without-mfa')).toEqual([open]);
    // Legacy trusts (no field) pass attributes; a malformed value passes nothing, so no finding.
    expect(subjects('trust-passes-foreign-attributes')).toEqual([open, legacy].sort());
    expect(subjects('trust-passes-foreign-attributes')).not.toContain(malformed);
    expect(subjects('trust-without-mfa')).not.toContain(falsy);
  });
});
