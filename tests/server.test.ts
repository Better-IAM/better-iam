import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { CredentialInput, HierarchyConfig, IamStore, PolicyDocument } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';
const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});
async function fixture(hierarchy?: HierarchyConfig) {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const iam = betterIam({
    database,
    secret: 'test-secret-with-at-least-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    permissions: { actions: ['documents:read', 'documents:write'], mode: 'tenant-defined' },
    onboarding: { mode: 'linked' },
    resolveResource: async (reference) => reference,
    ...(hierarchy ? { hierarchy } : {}),
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
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  const credential = { token: session.token };
  const createTenant = async (name: string, parent = root.tenant.id, type = 'organization') => {
    const created = await iam.api.tenants.create(credential, {
      parentId: parent,
      name,
      type,
      ownerEmail: `${name}@example.test`,
    });
    expect(created).not.toHaveProperty('invitationToken');
    await iam.auth.dispatchOutbox();
    const message = inbox.find(
      (m) => m.tenantId === created.tenant.id && m.template === 'owner-invitation',
    )!;
    const owner = await iam.api.tenants.acceptInvitation({
      tenantId: created.tenant.id,
      token: message.payload.token!,
      name: `${name} owner`,
      password: 'a strong tenant owner password',
    });
    if (!('token' in owner)) throw new Error('Unexpected owner MFA');
    return {
      tenant: created.tenant,
      owner,
      credential: { token: owner.token },
      invitation: message.payload.token!,
    };
  };
  return { iam, database, root, credential, inbox, createTenant };
}

describe('complete IAM workflows', () => {
  it('bootstraps root MFA, activates a tenant via delivered invitation and enforces custom role policy', async () => {
    const f = await fixture();
    const a = await f.createTenant('acme');
    await expect(
      f.iam.bootstrap({
        email: 'again@example.test',
        name: 'Again',
        password: 'a strong root test password',
      }),
    ).rejects.toMatchObject({ code: 'ALREADY_INITIALIZED' });
    await expect(
      f.iam.api.tenants.acceptInvitation({
        tenantId: a.tenant.id,
        token: a.invitation,
        name: 'Replayed',
        password: 'a strong tenant owner password',
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    const user = await f.iam.api.identities.create(a.credential, {
      tenantId: a.tenant.id,
      email: 'reader@example.test',
      name: 'Reader',
      password: 'a strong reader test password',
    });
    const policy = await f.iam.api.policies.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Document reader',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['document/*'] }],
      },
    });
    const role = await f.iam.api.roles.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Reader',
      policyIds: [policy.id],
    });
    const binding = await f.iam.api.bindings.create(a.credential, {
      tenantId: a.tenant.id,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: user.id,
    });
    const logged = await f.iam.api.auth.signIn({
      tenantId: a.tenant.id,
      email: 'reader@example.test',
      password: 'a strong reader test password',
    });
    if (!('token' in logged)) throw new Error('Unexpected MFA');
    const request = {
      token: logged.token,
      tenantId: a.tenant.id,
      action: 'documents:read',
      resource: { type: 'document', id: 'report' },
    };
    expect((await f.iam.authorize(request)).allowed).toBe(true);
    expect((await f.iam.authorize({ ...request, action: 'documents:write' })).allowed).toBe(false);
    await f.iam.api.bindings.delete(a.credential, { tenantId: a.tenant.id, bindingId: binding.id });
    expect((await f.iam.authorize(request)).allowed).toBe(false);
    await expect(
      f.iam.api.actions.register(a.credential, { tenantId: a.tenant.id, name: 'reports:export' }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    await f.iam.api.resourceTypes.register(a.credential, {
      tenantId: a.tenant.id,
      name: 'reports',
      actions: ['export'],
    });
    await f.iam.api.actions.register(a.credential, {
      tenantId: a.tenant.id,
      name: 'reports:archive',
    });
    await expect(
      f.iam.api.actions.register(a.credential, { tenantId: a.tenant.id, name: 'iam:root:grant' }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    await expect(
      f.iam.api.actions.register(a.credential, { tenantId: a.tenant.id, name: 'documents:delete' }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    expect(
      (await f.iam.api.actions.list(a.credential, { tenantId: a.tenant.id }))
        .filter((action) => action.source === 'tenant')
        .map((action) => action.name)
        .sort(),
    ).toEqual(['reports:archive', 'reports:export']);
  });

  it('validates policies against the action catalog and configured resource types', async () => {
    const f = await fixture(),
      a = await f.createTenant('catalog');
    await expect(
      f.iam.api.policies.create(a.credential, {
        tenantId: a.tenant.id,
        name: 'Typo',
        document: {
          version: 1,
          statements: [{ effect: 'allow', actions: ['documents:raed'], resources: ['*'] }],
        },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    await expect(
      f.iam.api.roles.create(a.credential, {
        tenantId: a.tenant.id,
        name: 'Typo',
        permissions: ['documents:read', 'nope:read'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    expect(
      (
        await f.iam.api.policies.create(a.credential, {
          tenantId: a.tenant.id,
          name: 'Wildcards',
          document: {
            version: 1,
            statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['anything/*'] }],
          },
        })
      ).version,
    ).toBe(1);
    const strict = betterIam({
      database: f.database,
      secret: 'test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
      authentication: { sendEmail: async () => {} },
      permissions: {
        mode: 'tenant-defined',
        resourceTypes: {
          document: {
            actions: ['documents:read', 'documents:write'],
            attributes: { classification: 'string' },
          },
        },
      },
      resolveResource: async (reference) => reference,
    });
    await expect(
      strict.api.policies.create(a.credential, {
        tenantId: a.tenant.id,
        name: 'Unknown type',
        document: {
          version: 1,
          statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['folder/*'] }],
        },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_RESOURCE_TYPE' });
    expect(
      (
        await strict.api.policies.create(a.credential, {
          tenantId: a.tenant.id,
          name: 'Known type',
          document: {
            version: 1,
            statements: [
              { effect: 'allow', actions: ['documents:read'], resources: ['document/*', 'iam/*'] },
            ],
          },
        })
      ).name,
    ).toBe('Known type');
    expect(() =>
      betterIam({
        database: f.database,
        secret: 'test-secret-with-at-least-32-characters',
        baseURL: 'http://localhost:3000',
        permissions: { resourceTypes: { iam: {} } },
      }),
    ).toThrow(/reserved/u);
    expect(() =>
      betterIam({
        database: f.database,
        secret: 'test-secret-with-at-least-32-characters',
        baseURL: 'http://localhost:3000',
        permissions: { resourceTypes: { folder: { parent: 'folder' } } },
      }),
    ).toThrow(/parent chain/u);
    expect(() =>
      betterIam({
        database: f.database,
        secret: 'test-secret-with-at-least-32-characters',
        baseURL: 'http://localhost:3000',
        permissions: {
          resourceTypes: { document: { attributes: { size: 'bigint' as 'number' } } },
        },
      }),
    ).toThrow(/string, number, or boolean/u);
  });

  it('registers managed resources with typed attributes, owners, and parents and evaluates conditions against them', async () => {
    const f = await fixture(),
      a = await f.createTenant('resources');
    const folder = await f.iam.api.resourceTypes.register(a.credential, {
      tenantId: a.tenant.id,
      name: 'folder',
      actions: ['read', 'write'],
      attributes: { confidential: 'boolean' },
    });
    expect(folder).toMatchObject({
      name: 'folder',
      source: 'tenant',
      managed: true,
      actions: ['folder:read', 'folder:write'],
    });
    const file = await f.iam.api.resourceTypes.register(a.credential, {
      tenantId: a.tenant.id,
      name: 'file',
      parent: 'folder',
      actions: ['read'],
      attributes: { size: 'number' },
    });
    expect(file.parent).toBe('folder');
    await expect(
      f.iam.api.resourceTypes.register(a.credential, { tenantId: a.tenant.id, name: 'documents' }),
    ).rejects.toMatchObject({ code: 'INVALID_RESOURCE_TYPE' });
    await expect(
      f.iam.api.resourceTypes.register(a.credential, { tenantId: a.tenant.id, name: 'iam' }),
    ).rejects.toMatchObject({ code: 'INVALID_RESOURCE_TYPE' });
    await expect(
      f.iam.api.resources.register(a.credential, {
        tenantId: a.tenant.id,
        type: 'folder',
        id: 'shared',
        attributes: { confidential: 'yes' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.resources.register(a.credential, {
        tenantId: a.tenant.id,
        type: 'folder',
        id: 'shared',
        attributes: { color: 'red' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.resources.register(a.credential, {
        tenantId: a.tenant.id,
        type: 'file',
        id: 'orphan',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.resources.register(a.credential, {
        tenantId: a.tenant.id,
        type: 'document',
        id: 'x',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_RESOURCE_TYPE' });
    const member = await f.iam.api.identities.create(a.credential, {
      tenantId: a.tenant.id,
      email: 'member@resources.test',
      name: 'Member',
      password: 'a strong member test password',
    });
    await f.iam.api.resources.register(a.credential, {
      tenantId: a.tenant.id,
      type: 'folder',
      id: 'shared',
      attributes: { confidential: false },
    });
    await f.iam.api.resources.register(a.credential, {
      tenantId: a.tenant.id,
      type: 'folder',
      id: 'secret',
      attributes: { confidential: true },
    });
    const owned = await f.iam.api.resources.register(a.credential, {
      tenantId: a.tenant.id,
      type: 'file',
      id: 'notes',
      parentId: 'shared',
      ownerId: member.id,
      attributes: { size: 12 },
    });
    expect(owned).toMatchObject({ parentType: 'folder', parentId: 'shared', ownerId: member.id });
    await expect(
      f.iam.api.resources.register(a.credential, {
        tenantId: a.tenant.id,
        type: 'file',
        id: 'notes',
        parentId: 'shared',
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await f.iam.api.resources.register(a.credential, {
      tenantId: a.tenant.id,
      type: 'file',
      id: 'plan',
      parentId: 'secret',
      attributes: { size: 1 },
    });
    const role = await f.iam.api.roles.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Folder reader',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['folder:read'],
            resources: ['folder/*'],
            conditions: { Bool: { 'resource.confidential': false } },
          },
          {
            effect: 'allow',
            actions: ['file:read'],
            resources: ['file/*'],
            conditions: { StringEquals: { 'resource.ownerId': member.id } },
          },
          {
            effect: 'allow',
            actions: ['file:read'],
            resources: ['file/*'],
            conditions: { StringEquals: { 'resource.parentId': 'shared' } },
          },
        ],
      },
    });
    await f.iam.api.bindings.create(a.credential, {
      tenantId: a.tenant.id,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: member.id,
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: a.tenant.id,
      email: 'member@resources.test',
      password: 'a strong member test password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    const check = (action: string, type: string, id: string) =>
      f.iam.authorize({
        token: login.token,
        tenantId: a.tenant.id,
        action,
        resource: { type, id },
      });
    expect((await check('folder:read', 'folder', 'shared')).allowed).toBe(true);
    expect((await check('folder:read', 'folder', 'secret')).allowed).toBe(false);
    expect((await check('folder:write', 'folder', 'shared')).allowed).toBe(false);
    expect((await check('file:read', 'file', 'notes')).allowed).toBe(true);
    expect((await check('file:read', 'file', 'plan')).allowed).toBe(false);
    await expect(check('file:read', 'file', 'missing')).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    const batch = await f.iam.authorizeMany({
      token: login.token,
      tenantId: a.tenant.id,
      checks: [
        { action: 'folder:read', resource: { type: 'folder', id: 'shared' } },
        { action: 'folder:read', resource: { type: 'folder', id: 'secret' } },
        { action: 'documents:read', resource: { type: 'document', id: 'any' } },
      ],
    });
    expect(batch.results.map((result) => result.allowed)).toEqual([true, false, false]);
    await expect(
      f.iam.authorizeMany({ token: login.token, tenantId: a.tenant.id, checks: [] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.resources.delete(a.credential, {
        tenantId: a.tenant.id,
        type: 'folder',
        id: 'shared',
      }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    await expect(
      f.iam.api.resourceTypes.delete(a.credential, { tenantId: a.tenant.id, name: 'folder' }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    await expect(
      f.iam.api.actions.unregister(a.credential, { tenantId: a.tenant.id, name: 'folder:read' }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    await expect(
      f.iam.api.resourceTypes.update(a.credential, {
        tenantId: a.tenant.id,
        name: 'folder',
        attributes: { confidential: 'string' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(
      (
        await f.iam.api.resources.list(a.credential, {
          tenantId: a.tenant.id,
          type: 'file',
          parentId: 'shared',
        })
      ).map((resource) => resource.resourceId),
    ).toEqual(['notes']);
    expect(
      (await f.iam.api.resourceTypes.list(a.credential, { tenantId: a.tenant.id }))
        .map((type) => type.name)
        .sort(),
    ).toEqual(['file', 'folder']);
    await expect(
      f.iam.api.resources.register(
        { token: login.token },
        { tenantId: a.tenant.id, type: 'folder', id: 'mine' },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('supports roles with direct permissions, inline documents, descriptions, and binding introspection', async () => {
    const f = await fixture(),
      a = await f.createTenant('roles');
    const user = await f.iam.api.identities.create(a.credential, {
      tenantId: a.tenant.id,
      email: 'editor@roles.test',
      name: 'Editor',
      password: 'a strong editor test password',
    });
    const group = await f.iam.api.groups.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Editors',
      description: 'Can edit',
    });
    await f.iam.api.groups.addMember(a.credential, {
      tenantId: a.tenant.id,
      groupId: group.id,
      identityId: user.id,
    });
    const editor = await f.iam.api.roles.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Editor',
      description: 'Reads and writes documents',
      permissions: ['documents:read', 'documents:write'],
    });
    expect(editor.document?.statements[0]).toMatchObject({
      effect: 'allow',
      actions: ['documents:read', 'documents:write'],
      resources: ['*'],
    });
    await expect(
      f.iam.api.roles.create(a.credential, {
        tenantId: a.tenant.id,
        name: 'Both',
        permissions: ['documents:read'],
        document: { version: 1, statements: [] },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const binding = await f.iam.api.bindings.create(a.credential, {
      tenantId: a.tenant.id,
      roleId: editor.id,
      subjectType: 'group',
      subjectId: group.id,
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: a.tenant.id,
      email: 'editor@roles.test',
      password: 'a strong editor test password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    const request = {
      token: login.token,
      tenantId: a.tenant.id,
      resource: { type: 'document', id: 'spec' },
    };
    expect((await f.iam.authorize({ ...request, action: 'documents:write' })).allowed).toBe(true);
    await f.iam.api.roles.update(a.credential, {
      tenantId: a.tenant.id,
      roleId: editor.id,
      permissions: ['documents:read'],
    });
    expect((await f.iam.authorize({ ...request, action: 'documents:write' })).allowed).toBe(false);
    expect((await f.iam.authorize({ ...request, action: 'documents:read' })).allowed).toBe(true);
    await f.iam.api.roles.update(a.credential, {
      tenantId: a.tenant.id,
      roleId: editor.id,
      document: null,
      name: 'Renamed',
    });
    expect(
      (await f.iam.api.roles.get(a.credential, { tenantId: a.tenant.id, roleId: editor.id })).name,
    ).toBe('Renamed');
    expect((await f.iam.authorize({ ...request, action: 'documents:read' })).allowed).toBe(false);
    const effective = await f.iam.api.identities.listBindings(a.credential, {
      tenantId: a.tenant.id,
      identityId: user.id,
    });
    expect(effective).toHaveLength(1);
    expect(effective[0]).toMatchObject({
      id: binding.id,
      via: { groupId: group.id },
      role: { id: editor.id, name: 'Renamed' },
    });
    expect(
      (
        await f.iam.api.roles.listBindings(a.credential, {
          tenantId: a.tenant.id,
          roleId: editor.id,
        })
      )[0],
    ).toMatchObject({ subjectType: 'group', subject: { id: group.id, name: 'Editors' } });
    expect(
      (
        await f.iam.api.bindings.list(a.credential, {
          tenantId: a.tenant.id,
          subjectType: 'group',
          subjectId: group.id,
        })
      ).map((b) => b.id),
    ).toEqual([binding.id]);
    expect(
      (
        await f.iam.api.groups.listMembers(a.credential, {
          tenantId: a.tenant.id,
          groupId: group.id,
        })
      ).map((member) => member.id),
    ).toEqual([user.id]);
    expect(
      (
        await f.iam.api.identities.listGroups(a.credential, {
          tenantId: a.tenant.id,
          identityId: user.id,
        })
      ).map((g) => g.name),
    ).toEqual(['Editors']);
    const policy = await f.iam.api.policies.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Reader',
      description: 'v1',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    await f.iam.api.policies.update(a.credential, {
      tenantId: a.tenant.id,
      policyId: policy.id,
      version: 1,
      description: 'v2',
    });
    const versions = await f.iam.api.policies.listVersions(a.credential, {
      tenantId: a.tenant.id,
      policyId: policy.id,
    });
    expect(versions.map((version) => [version.version, version.description])).toEqual([
      [1, 'v1'],
      [2, 'v2'],
    ]);
    expect(
      (await f.iam.api.policies.get(a.credential, { tenantId: a.tenant.id, policyId: policy.id }))
        .version,
    ).toBe(2);
  });

  it('invites members into an organization with roles applied under the inviter authority', async () => {
    const f = await fixture(),
      a = await f.createTenant('team');
    const reader = await f.iam.api.roles.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const group = await f.iam.api.groups.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Staff',
    });
    const invited = await f.iam.api.identities.invite(a.credential, {
      tenantId: a.tenant.id,
      email: 'new@team.test',
      name: 'New person',
      roleIds: [reader.id],
      groupIds: [group.id],
    });
    expect(invited).toMatchObject({
      email: 'new@team.test',
      roleIds: [reader.id],
      groupIds: [group.id],
    });
    await expect(
      f.iam.api.identities.invite(a.credential, {
        tenantId: a.tenant.id,
        email: a.owner.identity.email!,
      }),
    ).rejects.toMatchObject({ code: 'IDENTITY_EXISTS' });
    const pending = await f.iam.api.identities.listInvitations(a.credential, {
      tenantId: a.tenant.id,
    });
    expect(pending).toHaveLength(1);
    expect(pending[0]).not.toHaveProperty('tokenHash');
    await f.iam.auth.dispatchOutbox();
    const message = f.inbox.find(
      (m) => m.tenantId === a.tenant.id && m.template === 'member-invitation',
    )!;
    expect(message.to).toBe('new@team.test');
    expect(message.payload.tenantName).toBe('team');
    expect(message.payload.token).toBeTruthy();
    await expect(
      f.iam.api.identities.acceptInvitation({
        tenantId: a.tenant.id,
        token: 'wrong-token',
        password: 'a strong invited member password',
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    const outcomes = await Promise.allSettled(
      [1, 2].map(() =>
        f.iam.api.identities.acceptInvitation({
          tenantId: a.tenant.id,
          token: message.payload.token!,
          password: 'a strong invited member password',
        }),
      ),
    );
    expect(outcomes.filter((o) => o.status === 'fulfilled')).toHaveLength(1);
    const accepted = outcomes.find((o) => o.status === 'fulfilled')!;
    if (accepted.status !== 'fulfilled' || !('token' in accepted.value))
      throw new Error('Unexpected MFA');
    expect(accepted.value.identity).toMatchObject({
      email: 'new@team.test',
      name: 'New person',
      emailVerified: true,
      owner: false,
    });
    expect(
      (
        await f.iam.authorize({
          token: accepted.value.token,
          tenantId: a.tenant.id,
          action: 'documents:read',
          resource: { type: 'document', id: 'welcome' },
        })
      ).allowed,
    ).toBe(true);
    expect(
      (
        await f.iam.api.identities.listGroups(a.credential, {
          tenantId: a.tenant.id,
          identityId: accepted.value.identity.id,
        })
      ).map((g) => g.id),
    ).toEqual([group.id]);
    const login = await f.iam.api.auth.signIn({
      tenantId: a.tenant.id,
      email: 'new@team.test',
      password: 'a strong invited member password',
    });
    expect('token' in login).toBe(true);
    // A member without provisioning rights cannot invite; an inviter cannot grant roles beyond their own authority.
    await expect(
      f.iam.api.identities.invite(
        { token: accepted.value.token },
        { tenantId: a.tenant.id, email: 'friend@team.test' },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const limited = await f.iam.api.identities.create(a.credential, {
      tenantId: a.tenant.id,
      email: 'limited@team.test',
      name: 'Limited',
      password: 'a strong limited admin password',
    });
    await f.iam.api.authorities.create(a.credential, {
      tenantId: a.tenant.id,
      identityId: limited.id,
      ceiling: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['iam:identities:create', 'iam:bindings:create'],
            resources: ['*'],
          },
        ],
      },
    });
    const adminRole = await f.iam.api.roles.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Inviter',
      permissions: ['iam:identities:create', 'iam:bindings:create'],
    });
    await f.iam.api.bindings.create(a.credential, {
      tenantId: a.tenant.id,
      roleId: adminRole.id,
      subjectType: 'identity',
      subjectId: limited.id,
    });
    const limitedLogin = await f.iam.api.auth.signIn({
      tenantId: a.tenant.id,
      email: 'limited@team.test',
      password: 'a strong limited admin password',
    });
    if (!('token' in limitedLogin)) throw new Error('Unexpected MFA');
    const second = await f.iam.api.identities.invite(
      { token: limitedLogin.token },
      { tenantId: a.tenant.id, email: 'second@team.test', roleIds: [reader.id] },
    );
    await f.iam.api.authorities.revoke(a.credential, {
      tenantId: a.tenant.id,
      authorityId: (await f.database.find('memberInvitations', { id: second.invitationId }))[0]!
        .authorityId as string,
    });
    await f.iam.auth.dispatchOutbox();
    const secondMessage = f.inbox.find(
      (m) => m.tenantId === a.tenant.id && m.to === 'second@team.test',
    )!;
    await expect(
      f.iam.api.identities.acceptInvitation({
        tenantId: a.tenant.id,
        token: secondMessage.payload.token!,
        name: 'Second',
        password: 'a strong invited member password',
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    const revoked = await f.iam.api.identities.invite(a.credential, {
      tenantId: a.tenant.id,
      email: 'third@team.test',
    });
    await f.iam.api.identities.revokeInvitation(a.credential, {
      tenantId: a.tenant.id,
      invitationId: revoked.invitationId,
    });
    await f.iam.auth.dispatchOutbox();
    const thirdMessage = f.inbox.find(
      (m) => m.tenantId === a.tenant.id && m.to === 'third@team.test',
    )!;
    await expect(
      f.iam.api.identities.acceptInvitation({
        tenantId: a.tenant.id,
        token: thirdMessage.payload.token!,
        name: 'Third',
        password: 'a strong invited member password',
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
  });

  it('resolves organizations by slug for sign-in and lists linked accounts for switching', async () => {
    const f = await fixture();
    const created = await f.iam.api.tenants.create(f.credential, {
      parentId: f.root.tenant.id,
      type: 'organization',
      name: 'Acme',
      slug: 'acme',
      ownerEmail: 'owner@acme.test',
    });
    expect(created.tenant.slug).toBe('acme');
    await expect(f.iam.api.tenants.lookup({ slug: 'acme' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    await expect(
      f.iam.api.tenants.create(f.credential, {
        parentId: f.root.tenant.id,
        type: 'organization',
        name: 'Copy',
        slug: 'ACME',
        ownerEmail: 'copy@acme.test',
      }),
    ).rejects.toMatchObject({ code: 'SLUG_TAKEN' });
    await expect(
      f.iam.api.tenants.create(f.credential, {
        parentId: f.root.tenant.id,
        type: 'organization',
        name: 'Bad',
        slug: '-bad-',
        ownerEmail: 'bad@acme.test',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.auth.dispatchOutbox();
    const message = f.inbox.find(
      (m) => m.tenantId === created.tenant.id && m.template === 'owner-invitation',
    )!;
    const owner = await f.iam.api.tenants.acceptInvitation({
      tenantId: created.tenant.id,
      token: message.payload.token!,
      name: 'Owner',
      password: 'a strong tenant owner password',
    });
    if (!('token' in owner)) throw new Error('Unexpected MFA');
    expect(await f.iam.api.tenants.lookup({ slug: 'acme' })).toEqual({
      tenantId: created.tenant.id,
      name: 'Acme',
      type: 'organization',
      slug: 'acme',
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: (await f.iam.api.tenants.lookup({ slug: 'acme' })).tenantId,
      email: 'owner@acme.test',
      password: 'a strong tenant owner password',
    });
    expect('token' in login).toBe(true);
    await f.iam.api.tenants.setSlug(f.credential, {
      tenantId: created.tenant.id,
      slug: 'acme-inc',
    });
    await expect(f.iam.api.tenants.lookup({ slug: 'acme' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    expect((await f.iam.api.tenants.lookup({ slug: 'acme-inc' })).tenantId).toBe(created.tenant.id);
    await f.iam.api.tenants.setSlug(f.credential, { tenantId: created.tenant.id, slug: null });
    expect(
      (await f.iam.api.tenants.get(f.credential, { tenantId: created.tenant.id })).slug,
    ).toBeUndefined();
    const other = await f.createTenant('other');
    await f.iam.api.tenants.setSlug(f.credential, { tenantId: other.tenant.id, slug: 'acme' });
    const link = await f.iam.api.links.create(
      { token: owner.token },
      { targetCredential: other.credential },
    );
    const listed = await f.iam.api.links.list({ token: owner.token });
    expect(listed).toEqual([
      {
        id: link.id,
        identityId: other.owner.identity.id,
        email: other.owner.identity.email,
        name: other.owner.identity.name,
        status: 'active',
        tenantId: other.tenant.id,
        tenantName: 'other',
        tenantSlug: 'acme',
        tenantStatus: 'active',
      },
    ]);
    expect((await f.iam.api.links.list(other.credential))[0]!.tenantId).toBe(created.tenant.id);
    await f.iam.api.tenants.setStatus(f.credential, {
      tenantId: other.tenant.id,
      status: 'suspended',
    });
    await expect(f.iam.api.tenants.lookup({ slug: 'acme' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
  });

  it('uses the same authorization through HTTP and direct calls and rejects CSRF/private methods', async () => {
    const f = await fixture(),
      a = await f.createTenant('http');
    const call = (path: string, body: unknown, headers: Record<string, string> = {}) =>
      f.iam.handler(
        new Request(`http://localhost:3000/api/iam/${path}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-better-iam': '1',
            authorization: `Bearer ${a.credential.token}`,
            ...headers,
          },
          body: JSON.stringify(body),
        }),
      );
    expect((await call('tenants/get', { tenantId: a.tenant.id })).status).toBe(200);
    expect((await call('tenants/get', { tenantId: f.root.tenant.id })).status).toBe(403);
    expect(
      (await call('auth/createIdentity', { tenantId: a.tenant.id, email: 'forged@example.test' }))
        .status,
    ).toBe(404);
    expect((await call('auth/authenticate', {})).status).toBe(404);
    expect(
      (await call('tenants/get', { tenantId: a.tenant.id }, { origin: 'https://evil.example' }))
        .status,
    ).toBe(403);
    expect(
      (await call('tenants/get', { tenantId: a.tenant.id }, { 'x-better-iam': '0' })).status,
    ).toBe(403);
    const signed = await call('auth/signIn', {
      tenantId: a.tenant.id,
      email: 'http@example.test',
      password: 'a strong tenant owner password',
    });
    const cookie = signed.headers.get('set-cookie');
    expect(cookie).toContain('HttpOnly');
    expect(
      (
        await call(
          'tenants/get',
          { tenantId: a.tenant.id },
          { authorization: '', cookie: cookie!.split(';')[0]!, origin: 'http://localhost:3000' },
        )
      ).status,
    ).toBe(200);
    expect(
      (await call('authorize', { tenantId: a.tenant.id, action: 'documents:read', resource: null }))
        .status,
    ).toBe(400);
  });

  it('rolls back duplicate owner redemption and prevents final-owner disable', async () => {
    const f = await fixture(),
      a = await f.createTenant('owner');
    await expect(
      f.iam.api.identities.setStatus(a.credential, {
        tenantId: a.tenant.id,
        identityId: a.owner.identity.id,
        status: 'disabled',
      }),
    ).rejects.toMatchObject({ code: 'LAST_OWNER' });
    const created = await f.iam.api.tenants.create(f.credential, {
      parentId: f.root.tenant.id,
      type: 'organization',
      name: 'Concurrent',
      ownerEmail: 'concurrent@example.test',
    });
    await f.iam.auth.dispatchOutbox();
    const message = f.inbox.find((m) => m.tenantId === created.tenant.id)!;
    const input = {
      tenantId: created.tenant.id,
      token: message.payload.token!,
      name: 'Owner',
      password: 'a strong concurrent owner password',
    };
    const outcomes = await Promise.allSettled([
      f.iam.api.tenants.acceptInvitation(input),
      f.iam.api.tenants.acceptInvitation(input),
    ]);
    expect(outcomes.filter((o) => o.status === 'fulfilled')).toHaveLength(1);
    expect(
      await f.database.find('identities', { tenantId: created.tenant.id, owner: true }),
    ).toHaveLength(1);
  });

  it('isolates linked identities and revokes tenant credentials when an ancestor is suspended', async () => {
    const f = await fixture(),
      a = await f.createTenant('left'),
      b = await f.createTenant('right');
    const link = await f.iam.api.links.create(a.credential, { targetCredential: b.credential });
    const switched = await f.iam.api.links.switch(a.credential, {
      linkId: link.id,
      targetCredential: b.credential,
    });
    expect(switched.session.tenantId).toBe(b.tenant.id);
    expect(
      (
        await f.iam.authorize({
          token: switched.token,
          tenantId: a.tenant.id,
          action: 'documents:read',
          resource: { type: 'document', id: 'private' },
        })
      ).allowed,
    ).toBe(false);
    await f.iam.api.links.revoke(a.credential, { linkId: link.id });
    await expect(
      f.iam.api.links.switch(a.credential, { linkId: link.id, targetCredential: b.credential }),
    ).rejects.toMatchObject({ code: 'INVALID_LINK' });
    await expect(
      f.iam.api.links.create(f.credential, { targetCredential: b.credential }),
    ).rejects.toMatchObject({ code: 'INVALID_LINK' });
    await f.iam.api.tenants.setStatus(f.credential, { tenantId: b.tenant.id, status: 'suspended' });
    await expect(f.iam.authenticate(b.credential)).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await f.iam.api.tenants.setStatus(f.credential, { tenantId: b.tenant.id, status: 'active' });
    await expect(f.iam.authenticate(b.credential)).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
  });

  it('requires matching policy versions and applies restrictive boundaries immediately', async () => {
    const f = await fixture(),
      a = await f.createTenant('versions');
    const policy = await f.iam.api.policies.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Versioned',
      document: { version: 1, statements: [] },
    });
    const input = {
      tenantId: a.tenant.id,
      policyId: policy.id,
      version: 1,
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      } as PolicyDocument,
    };
    expect((await f.iam.api.policies.update(a.credential, input)).version).toBe(2);
    await expect(f.iam.api.policies.update(a.credential, input)).rejects.toMatchObject({
      code: 'VERSION_CONFLICT',
    });
    await f.iam.api.tenants.setBoundary(f.credential, {
      tenantId: a.tenant.id,
      boundary: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['iam:*'], resources: ['*'] }],
      },
    });
    expect(
      (
        await f.iam.authorize({
          ...a.credential,
          tenantId: a.tenant.id,
          action: 'documents:read',
          resource: { type: 'document', id: 'report' },
        })
      ).allowed,
    ).toBe(false);
  });

  it('renames and reparents tenants while enforcing hierarchy rules', async () => {
    const f = await fixture(),
      a = await f.createTenant('move-a'),
      b = await f.createTenant('move-b'),
      p = await f.createTenant('p', a.tenant.id, 'project');
    expect(
      (await f.iam.api.tenants.update(f.credential, { tenantId: a.tenant.id, name: 'Moved A' }))
        .name,
    ).toBe('Moved A');
    expect((await f.iam.api.tenants.get(f.credential, { tenantId: a.tenant.id })).name).toBe(
      'Moved A',
    );
    await expect(
      f.iam.api.tenants.update(f.credential, { tenantId: a.tenant.id, name: '  ' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(
      (
        await f.iam.api.tenants.reparent(f.credential, {
          tenantId: p.tenant.id,
          parentId: b.tenant.id,
        })
      ).parentId,
    ).toBe(b.tenant.id);
    expect(
      (await f.iam.api.tenants.listChildren(f.credential, { tenantId: b.tenant.id })).map(
        (t) => t.id,
      ),
    ).toContain(p.tenant.id);
    expect(
      (await f.iam.api.tenants.listChildren(f.credential, { tenantId: a.tenant.id })).map(
        (t) => t.id,
      ),
    ).not.toContain(p.tenant.id);
    await expect(
      f.iam.api.tenants.reparent(f.credential, { tenantId: p.tenant.id, parentId: b.tenant.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.tenants.reparent(f.credential, {
        tenantId: p.tenant.id,
        parentId: f.root.tenant.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_HIERARCHY' });
    await expect(
      f.iam.api.tenants.reparent(f.credential, {
        tenantId: f.root.tenant.id,
        parentId: b.tenant.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    const events = await f.iam.api.audit.list(f.credential, { tenantId: p.tenant.id });
    expect(
      events.some(
        (e) =>
          e.action === 'tenant:reparent' &&
          e.metadata?.from === a.tenant.id &&
          e.metadata?.to === b.tenant.id,
      ),
    ).toBe(true);
  });

  it('rejects cycles and depth violations when reparenting', async () => {
    const folders: HierarchyConfig = {
      types: {
        root: { allowedChildren: ['organization'] },
        organization: { allowedChildren: ['folder'] },
        folder: { allowedChildren: ['folder', 'project'] },
        project: { allowedChildren: [] },
      },
      maxDepth: 4,
    };
    const f = await fixture(folders),
      a = await f.createTenant('deep-a');
    const f1 = await f.createTenant('f1', a.tenant.id, 'folder'),
      f2 = await f.createTenant('f2', f1.tenant.id, 'folder'),
      g = await f.createTenant('g', a.tenant.id, 'folder');
    await expect(
      f.iam.api.tenants.reparent(f.credential, { tenantId: f1.tenant.id, parentId: f2.tenant.id }),
    ).rejects.toMatchObject({ code: 'INVALID_HIERARCHY' });
    await expect(
      f.iam.api.tenants.reparent(f.credential, { tenantId: f1.tenant.id, parentId: g.tenant.id }),
    ).rejects.toMatchObject({ code: 'MAX_DEPTH' });
    const project = await f.createTenant('project', g.tenant.id, 'project');
    await expect(
      f.iam.api.tenants.reparent(f.credential, {
        tenantId: project.tenant.id,
        parentId: a.tenant.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_HIERARCHY' });
    expect(
      (
        await f.iam.api.tenants.reparent(f.credential, {
          tenantId: f2.tenant.id,
          parentId: g.tenant.id,
        })
      ).parentId,
    ).toBe(g.tenant.id);
    expect(
      (
        await f.iam.api.tenants.reparent(f.credential, {
          tenantId: f1.tenant.id,
          parentId: g.tenant.id,
        })
      ).parentId,
    ).toBe(g.tenant.id);
    await expect(
      f.iam.api.tenants.reparent(f.credential, { tenantId: f1.tenant.id, parentId: g.tenant.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('requires update permission on the moved tenant and grant authority in the new parent', async () => {
    const f = await fixture(),
      a = await f.createTenant('authz-a'),
      b = await f.createTenant('authz-b'),
      p = await f.createTenant('proj', a.tenant.id, 'project');
    await expect(
      f.iam.api.tenants.reparent(p.credential, { tenantId: p.tenant.id, parentId: b.tenant.id }),
    ).rejects.toMatchObject({ code: 'GRANT_AUTHORITY_REQUIRED' });
    await expect(
      f.iam.api.tenants.reparent(a.credential, { tenantId: p.tenant.id, parentId: b.tenant.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.tenants.reparent(b.credential, { tenantId: p.tenant.id, parentId: b.tenant.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (
        await f.iam.api.tenants.reparent(f.credential, {
          tenantId: p.tenant.id,
          parentId: b.tenant.id,
        })
      ).parentId,
    ).toBe(b.tenant.id);
  });

  it('administers owner invitations and deletes pending tenants', async () => {
    const f = await fixture();
    const created = await f.iam.api.tenants.create(f.credential, {
      parentId: f.root.tenant.id,
      type: 'organization',
      name: 'Pendingco',
      ownerEmail: 'pending@example.test',
    });
    const listed = await f.iam.api.tenants.listInvitations(f.credential, {
      tenantId: created.tenant.id,
    });
    expect(listed).toHaveLength(1);
    expect(listed[0]).not.toHaveProperty('tokenHash');
    expect(listed[0]).not.toHaveProperty('uniqueKey');
    expect(listed[0]!.email).toBe('pending@example.test');
    expect(typeof listed[0]!.createdAt).toBe('number');
    expect(listed[0]!.revoked).toBeFalsy();
    await f.iam.api.tenants.revokeInvitation(f.credential, {
      tenantId: created.tenant.id,
      invitationId: listed[0]!.id,
    });
    await expect(
      f.iam.api.tenants.revokeInvitation(f.credential, {
        tenantId: created.tenant.id,
        invitationId: listed[0]!.id,
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await f.iam.auth.dispatchOutbox();
    const message = f.inbox.find((m) => m.tenantId === created.tenant.id)!;
    await expect(
      f.iam.api.tenants.acceptInvitation({
        tenantId: created.tenant.id,
        token: message.payload.token!,
        name: 'Owner',
        password: 'a strong pending owner password',
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    await expect(
      f.iam.api.tenants.setStatus(f.credential, { tenantId: created.tenant.id, status: 'active' }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    await expect(
      f.iam.api.tenants.setStatus(f.credential, {
        tenantId: created.tenant.id,
        status: 'suspended',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    const deleted = await f.iam.api.tenants.setStatus(f.credential, {
      tenantId: created.tenant.id,
      status: 'deleted',
    });
    expect(deleted.status).toBe('deleted');
    expect(typeof deleted.deletedAt).toBe('number');
    expect(
      (await f.iam.api.tenants.listInvitations(f.credential, { tenantId: created.tenant.id }))[0]!
        .revoked,
    ).toBe(true);
  });

  it('purges deleted tenants after the retention window and keeps audit records', async () => {
    const f = await fixture(),
      a = await f.createTenant('gone'),
      b = await f.createTenant('kept');
    const member = await f.iam.api.identities.create(a.credential, {
      tenantId: a.tenant.id,
      email: 'member@gone.test',
      name: 'Member',
      password: 'a strong member test password',
    });
    const policy = await f.iam.api.policies.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Gone policy',
      document: { version: 1, statements: [] },
    });
    const role = await f.iam.api.roles.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Gone role',
      policyIds: [policy.id],
    });
    await f.iam.api.bindings.create(a.credential, {
      tenantId: a.tenant.id,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: member.id,
    });
    await f.iam.api.identities.create(b.credential, {
      tenantId: b.tenant.id,
      email: 'member@kept.test',
      name: 'Member',
      password: 'a strong member test password',
    });
    await f.iam.api.tenants.setStatus(f.credential, { tenantId: a.tenant.id, status: 'deleted' });
    expect(await f.iam.purgeDeleted()).toEqual({
      purgedTenants: [],
      deletedRecords: 0,
      expiredBindings: 0,
      expiredRequests: 0,
      expiredIdentities: 0,
      expiredActivations: 0,
      expiredMemberships: 0,
      expiredAssignments: 0,
    });
    const purged = await f.iam.purgeDeleted({ retentionMs: 0 });
    expect(purged.purgedTenants).toEqual([a.tenant.id]);
    expect(purged.deletedRecords).toBeGreaterThan(0);
    expect(await f.database.get('tenants', a.tenant.id)).toBeUndefined();
    for (const collection of [
      'identities',
      'policies',
      'policyVersions',
      'roles',
      'bindings',
      'grantAuthorities',
      'ownerInvitations',
      'outbox',
    ])
      expect(await f.database.find(collection, { tenantId: a.tenant.id })).toHaveLength(0);
    expect(await f.database.get('tenants', b.tenant.id)).toBeDefined();
    expect(await f.database.find('identities', { tenantId: b.tenant.id })).toHaveLength(2);
    expect(
      (await f.database.find('audit', { tenantId: a.tenant.id })).some(
        (e) => e.action === 'tenants:purge',
      ),
    ).toBe(true);
    expect(await f.iam.purgeDeleted({ retentionMs: 0 })).toEqual({
      purgedTenants: [],
      deletedRecords: 0,
      expiredBindings: 0,
      expiredRequests: 0,
      expiredIdentities: 0,
      expiredActivations: 0,
      expiredMemberships: 0,
      expiredAssignments: 0,
    });
  });
});
