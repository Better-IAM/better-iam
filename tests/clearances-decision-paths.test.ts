import { afterEach, describe, expect, it } from 'vitest';
import { classificationTemplates, type AuditEvent } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';
import { sshPublicKey } from './support/ssh.js';

afterEach(closeFixtures);

/**
 * The decision-path side of security clearances, with schemes, labels and clearances written straight to the store
 * (the clearances API is covered in clearances.test.ts): the mandatory check in authorize, simulate and effective
 * actions; root refused on labeled application resources but not on iam administration; listings, plans (root's
 * too) and access paths; the audit marker; SSH resources built outside `resolve`; and no change without the option.
 */
describe('clearances on the decision paths', () => {
  it('enforces labels in authorize, simulate, root, plans, listings, audit and context', async () => {
    const f = await organizationFixture({
      clearances: {},
      resolveContext: async () => ({
        'resource.classificationRank': -1,
        'principal.clearanceRank': 9,
      }),
      permissions: {
        resourceTypes: {
          document: { actions: ['documents:read', 'documents:write'] },
          folder: { managed: true, actions: ['folders:read'] },
        },
      },
    });
    const now = f.now();
    const alice = await f.member('alice');
    await f.database.transaction(async (tx) => {
      await tx.insert('classificationSchemes', {
        id: 'scheme-1',
        tenantId: f.tenantId,
        uniqueKey: 'scheme',
        name: 'US',
        definition: JSON.parse(JSON.stringify(classificationTemplates.us)),
        requireLabels: [],
        guestCeiling: null,
        interimAllowed: false,
        adjudication: 'within-own',
        createdAt: now,
        createdBy: f.ownerId,
        updatedAt: now,
        updatedBy: f.ownerId,
        version: 1,
      });
      for (const [type, id] of [
        ['document', 'secret'],
        ['folder', 'f-secret'],
      ] as const)
        await tx.insert('resourceLabels', {
          id: `label-${id}`,
          tenantId: f.tenantId,
          uniqueKey: `${type}/${id}`,
          type,
          resourceId: id,
          label: { level: 'S' },
          inheritToChildren: false,
          schemeTenantId: f.tenantId,
          labeledBy: f.ownerId,
          labeledAt: now,
          version: 1,
        });
    });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'f-secret',
    });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'f-open',
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Readers',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['documents:read', 'folders:read'], resources: ['*'] },
          {
            effect: 'allow',
            actions: ['documents:write'],
            resources: ['document/*'],
            conditions: { NumericLessThan: { 'principal.clearanceRank': 0 } },
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
    const { token } = await f.signIn('alice');
    const can = async (
      credential: { token: string },
      action: string,
      id: string,
      type = 'document',
    ) =>
      (
        await f.iam.authorize({
          ...credential,
          tenantId: f.tenantId,
          action,
          resource: { type, id },
        })
      ).allowed;
    const simulate = (action: string, id: string) =>
      f.iam.api.policies.simulate(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: alice.id,
        action,
        resource: { type: 'document', id },
      });
    // Uncleared: open documents yes, labeled no; principal.clearanceRank from resolveContext is stripped (-1 holds).
    expect(await can({ token }, 'documents:read', 'open')).toBe(true);
    expect(await can({ token }, 'documents:read', 'secret')).toBe(false);
    expect(await can({ token }, 'documents:write', 'open')).toBe(true);
    expect((await simulate('documents:read', 'secret')).reason).toBe('CLEARANCE_REQUIRED');
    // The denial is audited with the mandatory marker only.
    const audit = await f.database.transaction((tx) =>
      tx.find<AuditEvent>('audit', { tenantId: f.tenantId }),
    );
    const refusal = audit.find(
      (event) => event.outcome === 'deny' && event.resourceId === 'secret',
    );
    expect(refusal?.metadata).toEqual({ mandatory: 'clearance' });
    // Effective actions: iam: first, application actions still refused.
    const effective = await f.iam.api.policies.effectiveActions(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
      resource: { type: 'document', id: 'secret' },
      actions: ['documents:read', 'iam:resources:read'],
    });
    expect(effective.results.find((item) => item.action === 'documents:read')?.reason).toBe(
      'CLEARANCE_REQUIRED',
    );
    // Root: refused on the labeled application resource, iam administration unaffected.
    expect(await can(f.rootCredential, 'documents:read', 'open')).toBe(true);
    expect(await can(f.rootCredential, 'documents:read', 'secret')).toBe(false);
    expect(await can(f.rootCredential, 'iam:resources:read', f.tenantId, 'iam')).toBe(true);
    // Listing and plans.
    const listed = await f.iam.listAccessible({
      token,
      tenantId: f.tenantId,
      action: 'folders:read',
      type: 'folder',
    });
    expect(listed.resources.map((item) => item.resourceId)).toEqual(['f-open']);
    const plan = await f.iam.planResources({
      token,
      tenantId: f.tenantId,
      action: 'documents:read',
      type: 'document',
    });
    expect(plan.kind).toBe('conditional');
    expect(plan.filter).toEqual({
      kind: 'not',
      filter: { kind: 'equals', field: 'id', values: ['secret'] },
    });
    const rootPlan = await f.iam.planResources({
      ...f.rootCredential,
      tenantId: f.tenantId,
      action: 'documents:read',
      type: 'document',
    });
    expect(rootPlan.filter).toEqual(plan.filter);
    // Access paths say nothing about the label.
    const paths = await f.iam.api.accessPaths.find(
      { token },
      {
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'secret' },
      },
    );
    expect(paths).toEqual({ allowed: false, reason: 'ACCESS_DENIED', paths: [] });
    // Cleared at TS: reads it; principal.clearanceRank is the server's.
    await f.database.transaction((tx) =>
      tx.insert('clearances', {
        id: alice.id,
        tenantId: f.tenantId,
        uniqueKey: `identity:${alice.id}`,
        identityId: alice.id,
        schemeTenantId: f.tenantId,
        level: 'TS',
        citizenship: ['USA'],
        status: 'active',
        readIns: [],
        grantedAt: now,
        grantedBy: f.ownerId,
        updatedAt: now,
        updatedBy: f.ownerId,
      }),
    );
    expect(await can({ token }, 'documents:read', 'secret')).toBe(true);
    expect(await can({ token }, 'documents:write', 'open')).toBe(false);
  });

  it('labels SSH hosts and logins built outside resolve', async () => {
    const txt = new Map<string, string[][]>();
    const f = await organizationFixture({
      ssh: true,
      clearances: {},
      domains: { resolveTxt: async (name) => txt.get(name) ?? [] },
    });
    const claim = await f.iam.api.domains.add(f.ownerCredential, {
      tenantId: f.tenantId,
      domain: 'acme.test',
    });
    txt.set(claim.dnsRecord.name, [[claim.dnsRecord.value]]);
    await f.iam.api.domains.verify(f.ownerCredential, { tenantId: f.tenantId, domainId: claim.id });
    await f.iam.api.ssh.setup(f.ownerCredential, { tenantId: f.tenantId });
    const web = await f.iam.api.ssh.createHost(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'web-01',
      logins: ['deploy', 'root'],
      labels: { environment: 'staging' },
    });
    await f.iam.api.ssh.enrollHost({
      joinToken: web.joinToken,
      publicKey: sshPublicKey('ed25519', 'root@web-01'),
    });
    const alice = await f.member('alice');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Deploy',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['ssh:login'], resources: ['ssh-login/*/deploy'] },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const now = f.now();
    await f.database.transaction((tx) =>
      tx.insert('classificationSchemes', {
        id: 'scheme-1',
        tenantId: f.tenantId,
        uniqueKey: 'scheme',
        name: 'US',
        definition: JSON.parse(JSON.stringify(classificationTemplates.us)),
        requireLabels: [],
        guestCeiling: null,
        interimAllowed: false,
        adjudication: 'within-own',
        createdAt: now,
        createdBy: f.ownerId,
        updatedAt: now,
        updatedBy: f.ownerId,
        version: 1,
      }),
    );
    const aliceSession = { token: (await f.signIn('alice')).token };
    // With a scheme but no labels, SSH works as before.
    expect(
      (await f.iam.api.ssh.myAccess(aliceSession, { tenantId: f.tenantId })).hosts.map(
        (host) => host.logins,
      ),
    ).toEqual([['deploy']]);
    const issued = await f.iam.api.ssh.issueCertificate(aliceSession, {
      tenantId: f.tenantId,
      publicKey: sshPublicKey('ed25519', 'alice@laptop'),
      ttlMs: 3_600_000,
    });
    expect(issued.principals).toEqual(['deploy@web-01']);
    expect((await f.iam.api.ssh.sweep(f.ownerCredential, { tenantId: f.tenantId })).revoked).toBe(
      0,
    );
    // Labeling the login takes it away everywhere.
    await f.database.transaction((tx) =>
      tx.insert('resourceLabels', {
        id: 'label-login',
        tenantId: f.tenantId,
        uniqueKey: 'ssh-login/web-01/deploy',
        type: 'ssh-login',
        resourceId: 'web-01/deploy',
        label: { level: 'S' },
        inheritToChildren: false,
        schemeTenantId: f.tenantId,
        labeledBy: f.ownerId,
        labeledAt: now,
        version: 1,
      }),
    );
    expect((await f.iam.api.ssh.myAccess(aliceSession, { tenantId: f.tenantId })).hosts).toEqual(
      [],
    );
    expect(
      (
        await f.iam.api.ssh.whoCanLogin(f.ownerCredential, {
          tenantId: f.tenantId,
          hostId: web.host.id,
        })
      ).identities.map((item) => item.identityId),
    ).not.toContain(alice.id);
    expect((await f.iam.api.ssh.sweep(f.ownerCredential, { tenantId: f.tenantId })).revoked).toBe(
      1,
    );
  });

  it('keeps today’s behaviour without the option', async () => {
    const f = await organizationFixture({
      resolveContext: async () => ({ 'principal.clearanceRank': -1 }),
    });
    const alice = await f.member('alice');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Writers',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:write'],
            resources: ['document/*'],
            conditions: { NumericLessThan: { 'principal.clearanceRank': 0 } },
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
    const { token } = await f.signIn('alice');
    // The application's own principal.clearanceRank still reaches policies.
    expect(
      (
        await f.iam.authorize({
          token,
          tenantId: f.tenantId,
          action: 'documents:write',
          resource: { type: 'document', id: 'x' },
        })
      ).allowed,
    ).toBe(true);
  });
});
