import { afterEach, describe, expect, it } from 'vitest';
import { IamError, type IamPlugin } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization';

afterEach(closeFixtures);

describe('plugin endpoints that name a record are authorized on it', () => {
  it('applies a Deny on one record to the endpoint that acts on it', async () => {
    const endpoint = (resource?: boolean): IamPlugin['endpoints'] => [
      {
        method: 'POST',
        path: resource ? 'notes/archive' : 'notes/archive-tenant-wide',
        action: 'notes:archive',
        validate(value) {
          const input = value as { tenantId?: unknown; noteId?: unknown };
          if (typeof input.noteId !== 'string') throw new IamError('INVALID_INPUT', 'noteId');
          return { tenantId: input.tenantId, noteId: input.noteId };
        },
        ...(resource ? { resource: (input) => `note/${String(input.noteId)}` } : {}),
        handler: async (_context, input) => ({ archived: input.noteId }),
      },
    ];
    const plugin: IamPlugin = {
      id: 'notes',
      actions: ['notes:archive'],
      endpoints: [...endpoint(true)!, ...endpoint(false)!],
    };
    const f = await organizationFixture({ plugins: [plugin] });
    const { iam, tenantId, ownerCredential: owner } = f;
    const bob = await f.member('bob');
    const archivist = await iam.api.roles.create(owner, {
      tenantId,
      name: 'Archivist',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['notes:archive'], resources: ['*'] },
          { effect: 'deny', actions: ['notes:archive'], resources: ['iam/note/legal-hold'] },
        ],
      },
    });
    await iam.api.bindings.create(owner, {
      tenantId,
      roleId: archivist.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const b = { token: (await f.signIn('bob')).token };
    const call = (path: string, noteId: string) =>
      iam.callPlugin(b, { pluginId: 'notes', path, tenantId, input: { noteId } });
    expect(await call('notes/archive', 'minutes')).toEqual({ archived: 'minutes' });
    await expect(call('notes/archive', 'legal-hold')).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // Without a resource mapper the endpoint stays tenant-wide, as before.
    expect(await call('notes/archive-tenant-wide', 'legal-hold')).toEqual({
      archived: 'legal-hold',
    });
  });
});

describe('denies outlive the authority that issued them', () => {
  it('keeps a guardrail policy in force after its author’s authority is revoked', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const security = await f.member('security');
    const alice = await f.member('alice');
    const writer = await api.roles.create(owner, {
      tenantId,
      name: 'Security policy writer',
      permissions: ['iam:policies:create', 'iam:policies:read', 'iam:bindings:create'],
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: writer.id,
      subjectType: 'identity',
      subjectId: security.id,
    });
    const authority = await api.authorities.create(await f.ownerSignIn(), {
      tenantId,
      identityId: security.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['*'] }],
      },
    });
    const securityLogin = { token: (await f.signIn('security')).token };
    const guard = await api.policies.create(securityLogin, {
      tenantId,
      name: 'No writes to legal',
      document: {
        version: 1,
        statements: [
          { effect: 'deny', actions: ['documents:write'], resources: ['document/legal-*'] },
        ],
      },
    });
    const staff = await api.roles.create(owner, {
      tenantId,
      name: 'Staff',
      permissions: ['documents:read', 'documents:write'],
    });
    await api.roles.update(owner, { tenantId, roleId: staff.id, policyIds: [guard.id] });
    await api.bindings.create(owner, {
      tenantId,
      roleId: staff.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    // An allow the security engineer granted under the same authority.
    const reader = await api.roles.create(owner, {
      tenantId,
      name: 'Archive reader',
      permissions: ['documents:read'],
    });
    const bob = await f.member('bob');
    await api.bindings.create(securityLogin, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const may = async (name: string, action: string, id: string) =>
      (
        await f.iam.authorize({
          token: (await f.signIn(name)).token,
          tenantId,
          action,
          resource: { type: 'document', id },
        })
      ).allowed;
    expect(await may('alice', 'documents:write', 'legal-contract')).toBe(false);
    expect(await may('bob', 'documents:read', 'archive')).toBe(true);
    await api.authorities.revoke(await f.ownerSignIn(), { tenantId, authorityId: authority.id });
    // The deny holds; the allow granted under the revoked authority lapses; other grants keep working.
    expect(await may('alice', 'documents:write', 'legal-contract')).toBe(false);
    expect(await may('alice', 'documents:write', 'memo')).toBe(true);
    expect(await may('bob', 'documents:read', 'archive')).toBe(false);
  });

  it('keeps a deny-everything binding in force after the administrator who bound it is offboarded', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const admin = await f.member('admin');
    const suspect = await f.member('suspect');
    const staff = await api.roles.create(owner, {
      tenantId,
      name: 'Staff',
      permissions: ['documents:read'],
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: staff.id,
      subjectType: 'identity',
      subjectId: suspect.id,
    });
    const freeze = await api.roles.create(owner, {
      tenantId,
      name: 'Frozen',
      document: { version: 1, statements: [{ effect: 'deny', actions: ['*'], resources: ['*'] }] },
    });
    const adminRole = await api.roles.create(owner, {
      tenantId,
      name: 'Admin',
      permissions: ['iam:bindings:create'],
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: adminRole.id,
      subjectType: 'identity',
      subjectId: admin.id,
    });
    await api.authorities.create(await f.ownerSignIn(), {
      tenantId,
      identityId: admin.id,
      ceiling: { version: 1, statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }] },
    });
    await api.bindings.create(
      { token: (await f.signIn('admin')).token },
      { tenantId, roleId: freeze.id, subjectType: 'identity', subjectId: suspect.id },
    );
    await api.identities.offboard(await f.ownerSignIn(), {
      tenantId,
      identityId: admin.id,
      reason: 'Left the company',
    });
    expect(
      (
        await f.iam.authorize({
          token: (await f.signIn('suspect')).token,
          tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'handbook' },
        })
      ).allowed,
    ).toBe(false);
  });
});

describe('listing managed resources reads each record', () => {
  it('leaves out records a policy keeps from the caller, and refuses wildcard IDs', async () => {
    const f = await organizationFixture({
      permissions: {
        actions: ['documents:read'],
        resourceTypes: { document: { managed: true, actions: ['documents:read'] } },
      },
    } as never);
    const { iam, tenantId, ownerCredential: owner } = f;
    for (const id of ['handbook', 'payroll'])
      await iam.api.resources.register(owner, { tenantId, type: 'document', id });
    await expect(
      iam.api.resources.register(owner, { tenantId, type: 'document', id: '*' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const bob = await f.member('bob');
    const reader = await iam.api.roles.create(owner, {
      tenantId,
      name: 'Resource reader',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['iam:resources:read'], resources: ['*'] },
          { effect: 'deny', actions: ['iam:resources:read'], resources: ['iam/document/payroll'] },
        ],
      },
    });
    await iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const b = { token: (await f.signIn('bob')).token };
    await expect(
      iam.api.resources.get(b, { tenantId, type: 'document', id: 'payroll' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const listed = await iam.api.resources.list(b, { tenantId, type: 'document' });
    expect(listed.map((record) => record.resourceId)).toEqual(['handbook']);
    expect((await iam.api.resources.list(owner, { tenantId, type: 'document' })).length).toBe(2);
  });

  it('leaves out relationship tuples of resources a policy keeps from the caller', async () => {
    const f = await organizationFixture({
      permissions: {
        actions: ['documents:read'],
        resourceTypes: {
          document: { managed: true, actions: ['documents:read'], relations: ['viewer'] },
        },
      },
    } as never);
    const { iam, tenantId, ownerCredential: owner } = f;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    for (const id of ['handbook', 'payroll']) {
      await iam.api.resources.register(owner, { tenantId, type: 'document', id });
      await iam.api.relationships.create(owner, {
        tenantId,
        type: 'document',
        id,
        relation: 'viewer',
        subjectType: 'identity',
        subjectId: alice.id,
      });
    }
    const reader = await iam.api.roles.create(owner, {
      tenantId,
      name: 'Sharing reader',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['iam:relationships:read'], resources: ['*'] },
          {
            effect: 'deny',
            actions: ['iam:relationships:read'],
            resources: ['iam/document/payroll'],
          },
        ],
      },
    });
    await iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const b = { token: (await f.signIn('bob')).token };
    const listed = await iam.api.relationships.list(b, { tenantId, type: 'document' });
    expect(listed.map((tuple) => tuple.resourceId)).toEqual(['handbook']);
    expect((await iam.api.relationships.list(owner, { tenantId })).length).toBe(2);
  });
});

describe('approvers shorten activation requests, never lengthen them', () => {
  it('refuses an approval longer than requested and keeps the requested length by default', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const auditor = await api.roles.create(owner, {
      tenantId,
      name: 'Auditor',
      permissions: ['iam:audit:read'],
    });
    const member = await api.roles.create(owner, {
      tenantId,
      name: 'Member',
      permissions: ['iam:bindings:activate'],
    });
    const approver = await api.roles.create(owner, {
      tenantId,
      name: 'Approver',
      permissions: ['iam:bindings:approve'],
    });
    const approvers = await api.groups.create(owner, { tenantId, name: 'Approvers' });
    await api.groups.addMember(owner, { tenantId, groupId: approvers.id, identityId: bob.id });
    for (const [roleId, subjectType, subjectId] of [
      [member.id, 'identity', alice.id],
      [approver.id, 'group', approvers.id],
    ] as const)
      await api.bindings.create(owner, { tenantId, roleId, subjectType, subjectId });
    const eligible = await api.bindings.create(owner, {
      tenantId,
      roleId: auditor.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
      requireApproval: true,
      approverGroupId: approvers.id,
      maxActivationMs: 2 * 3_600_000,
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    const request = await api.bindings.activate(asAlice, {
      tenantId,
      bindingId: eligible.id,
      justification: 'INC-7',
      durationMs: 30 * 60_000,
    });
    await expect(
      api.bindings.approveActivation(asBob, {
        tenantId,
        activationId: request.id,
        durationMs: 2 * 3_600_000,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const approved = await api.bindings.approveActivation(asBob, {
      tenantId,
      activationId: request.id,
    });
    expect(approved.expiresAt - f.now()).toBe(30 * 60_000);
  });
});

describe('a principal of another tenant learns nothing from a decision', () => {
  it('answers a registered and an unregistered resource alike', async () => {
    const f = await organizationFixture({
      permissions: {
        actions: ['documents:read'],
        resourceTypes: { document: { managed: true, actions: ['documents:read'] } },
      },
    } as never);
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'document',
      id: 'acquisition-of-globex',
    });
    const rootTenant = f.root.tenant.id;
    await f.iam.api.identities.create(f.rootCredential, {
      tenantId: rootTenant,
      email: 'outsider@example.test',
      name: 'Outsider',
      password: 'a strong outsider password',
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: rootTenant,
      email: 'outsider@example.test',
      password: 'a strong outsider password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    const probe = (id: string, action = 'documents:read') =>
      f.iam
        .authorize({
          token: login.token,
          tenantId: f.tenantId,
          action,
          resource: { type: 'document', id },
        })
        .then(
          (decision) => `decision:${decision.reason}`,
          (error: { code?: string }) => `error:${error.code}`,
        );
    expect(await probe('acquisition-of-globex')).toBe('decision:ACCESS_DENIED');
    expect(await probe('acquisition-of-initech')).toBe('decision:ACCESS_DENIED');
    expect(await probe('acquisition-of-initech', 'reports:unknown')).toBe('decision:ACCESS_DENIED');
    // The refusals are recorded in the outsider's own tenant, never in Acme's chain (or its webhooks).
    const outsider = (await f.database.find('identities', { email: 'outsider@example.test' }))[0]!;
    const acmeEvents = await f.database.find('audit', {
      tenantId: f.tenantId,
      actorId: outsider.id,
    });
    expect(acmeEvents).toHaveLength(0);
    const ownEvents = await f.database.find('audit', {
      tenantId: rootTenant,
      actorId: outsider.id,
    });
    expect(ownEvents.filter((event) => event.outcome === 'deny')).toHaveLength(3);
    expect(ownEvents[0]).toMatchObject({ metadata: { targetTenantId: f.tenantId } });
    // Insiders still get the resolution errors they need.
    await expect(
      f.iam.authorize({
        token: f.ownerCredential.token,
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'acquisition-of-initech' },
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe('an editor cannot lift a deny another administrator relies on', () => {
  async function guardAttachedByOwner() {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const editor = await f.member('editor');
    const policyAdmin = await api.roles.create(owner, {
      tenantId,
      name: 'Policy editor',
      permissions: ['iam:policies:create', 'iam:policies:update', 'iam:policies:read'],
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: policyAdmin.id,
      subjectType: 'identity',
      subjectId: editor.id,
    });
    await api.authorities.create(await f.ownerSignIn(), {
      tenantId,
      identityId: editor.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    const editorLogin = { token: (await f.signIn('editor')).token };
    const allowRead = {
      effect: 'allow' as const,
      actions: ['documents:read'],
      resources: ['document/*'],
    };
    const denyLegal = {
      effect: 'deny' as const,
      actions: ['documents:write'],
      resources: ['document/legal-*'],
    };
    const policy = await api.policies.create(editorLogin, {
      tenantId,
      name: 'Legal guard',
      document: { version: 1, statements: [allowRead, denyLegal] },
    });
    return { f, api, tenantId, owner, editorLogin, policy, allowRead, denyLegal };
  }

  it('refuses removing the deny once a superior attached the policy', async () => {
    const { api, tenantId, owner, editorLogin, policy, allowRead, denyLegal } =
      await guardAttachedByOwner();
    const staff = await api.roles.create(owner, {
      tenantId,
      name: 'Staff',
      permissions: ['documents:read', 'documents:write'],
    });
    await api.roles.update(owner, { tenantId, roleId: staff.id, policyIds: [policy.id] });
    await expect(
      api.policies.update(editorLogin, {
        tenantId,
        policyId: policy.id,
        version: policy.version,
        document: { version: 1, statements: [allowRead] },
      }),
    ).rejects.toMatchObject({ code: 'PROTECTED_RESOURCE' });
    // Adding a deny, or changing only allows, stays possible.
    await api.policies.update(editorLogin, {
      tenantId,
      policyId: policy.id,
      version: policy.version,
      document: {
        version: 1,
        statements: [
          { ...allowRead, resources: ['document/public-*'] },
          denyLegal,
          { effect: 'deny', actions: ['documents:write'], resources: ['document/hr-*'] },
        ],
      },
    });
  });

  it('lets the editor change their policy while nobody else relies on it', async () => {
    const { api, tenantId, editorLogin, policy, allowRead } = await guardAttachedByOwner();
    await api.policies.update(editorLogin, {
      tenantId,
      policyId: policy.id,
      version: policy.version,
      document: { version: 1, statements: [allowRead] },
    });
  });
});

describe('separation of duties follows role inheritance', () => {
  async function payments() {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const alice = await f.member('alice');
    const initiate = await api.roles.create(owner, {
      tenantId,
      name: 'Initiate',
      permissions: ['documents:write'],
    });
    const approve = await api.roles.create(owner, {
      tenantId,
      name: 'Approve',
      permissions: ['documents:read'],
    });
    await api.sod.create(owner, { tenantId, name: 'Payments', roleIds: [initiate.id, approve.id] });
    const bind = (roleId: string) =>
      api.bindings.create(owner, {
        tenantId,
        roleId,
        subjectType: 'identity',
        subjectId: alice.id,
      });
    await bind(initiate.id);
    return { f, api, tenantId, owner, alice, approve, bind };
  }

  it('refuses binding a role that inherits the conflicting role', async () => {
    const { api, tenantId, owner, approve, bind } = await payments();
    const lead = await api.roles.create(owner, {
      tenantId,
      name: 'Finance lead',
      permissions: ['iam:roles:read'],
    });
    await api.roles.update(owner, { tenantId, roleId: lead.id, inherits: [approve.id] });
    await expect(bind(lead.id)).rejects.toMatchObject({ code: 'SOD_CONFLICT' });
  });

  it('refuses making a role someone holds inherit the conflicting role', async () => {
    const { api, tenantId, owner, approve, bind } = await payments();
    const helper = await api.roles.create(owner, {
      tenantId,
      name: 'Helper',
      permissions: ['iam:groups:read'],
    });
    await bind(helper.id);
    await expect(
      api.roles.update(owner, { tenantId, roleId: helper.id, inherits: [approve.id] }),
    ).rejects.toMatchObject({ code: 'SOD_CONFLICT' });
  });

  it('reports conflicts held through inheritance', async () => {
    const { f, api, tenantId, owner, alice, approve } = await payments();
    const lead = await api.roles.create(owner, {
      tenantId,
      name: 'Finance lead',
      permissions: ['iam:roles:read'],
    });
    await api.roles.update(owner, { tenantId, roleId: lead.id, inherits: [approve.id] });
    // Bound before the rule existed: a detect-only view must still see it.
    await f.database.transaction((tx) =>
      tx.insert('bindings', {
        id: 'legacy-binding',
        tenantId,
        uniqueKey: 'legacy-binding',
        subjectType: 'identity',
        subjectId: alice.id,
        roleId: lead.id,
        authorityId: 'none',
      }),
    );
    expect(await api.sod.violations(owner, { tenantId })).toMatchObject([{ identityId: alice.id }]);
  });
});

describe('a tenant-defined type answers only for its own actions', () => {
  it('keeps the application resolver in charge of application actions on a type named like it', async () => {
    const owners = new Map<string, string>();
    const f = await organizationFixture({
      permissions: { mode: 'tenant-defined', actions: ['documents:read', 'documents:write'] },
      resolveResource: async (reference) => {
        const tenantId = owners.get(`${reference.type}/${reference.id}`);
        return tenantId ? { tenantId, type: reference.type, id: reference.id } : undefined;
      },
    } as never);
    const victim = await f.iam.api.tenants.create(f.rootCredential, {
      parentId: f.root.tenant.id,
      name: 'Victim',
      type: 'organization',
      ownerEmail: 'owner@victim.test',
    });
    owners.set('document/payroll', victim.tenant.id);
    owners.set('document/handbook', f.tenantId);
    const check = (id: string) =>
      f.iam.authorize({
        token: f.ownerCredential.token,
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: { type: 'document', id },
      });
    await f.iam.api.resourceTypes.register(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'document',
      actions: ['share'],
    });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'document',
      id: 'payroll',
    });
    await expect(check('payroll')).rejects.toMatchObject({ code: 'RESOURCE_MISMATCH' });
    // The application's own records still resolve, and the tenant's type still answers for its own actions.
    expect((await check('handbook')).allowed).toBe(true);
    expect(
      (
        await f.iam.authorize({
          token: f.ownerCredential.token,
          tenantId: f.tenantId,
          action: 'document:share',
          resource: { type: 'document', id: 'payroll' },
        })
      ).allowed,
    ).toBe(true);
    await expect(
      f.iam.listAccessible({
        token: f.ownerCredential.token,
        tenantId: f.tenantId,
        action: 'documents:read',
        type: 'document',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_RESOURCE_TYPE' });
  });
});
