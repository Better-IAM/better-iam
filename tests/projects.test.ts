import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createProjectsPlugin, type Project } from '@better-iam/projects';
import type { CredentialInput, IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';
const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});
async function fixture() {
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
    onboarding: { mode: 'linked' },
    plugins: [createProjectsPlugin()],
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
    return { tenant: created.tenant, owner, credential: { token: owner.token } };
  };
  const call = async <T = unknown>(
    path: string,
    who: CredentialInput,
    tenantId: string,
    input: Record<string, unknown> = {},
  ) => iam.callPlugin(who, { pluginId: 'projects', path, tenantId, input }) as Promise<T>;
  return { iam, database, root, credential, inbox, createTenant, call };
}

describe('projects plugin', () => {
  it('manages the project lifecycle in the root tenant and organization tenants', async () => {
    const f = await fixture();
    const platform = await f.call<Project>('create', f.credential, f.root.tenant.id, {
      name: 'Platform',
      description: 'Deployment-level project',
    });
    expect(platform).toMatchObject({
      name: 'Platform',
      status: 'active',
      tenantId: f.root.tenant.id,
      createdBy: f.root.identity.id,
    });
    await expect(
      f.call('create', f.credential, f.root.tenant.id, { name: 'Platform' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      f.call('create', f.credential, f.root.tenant.id, { name: '   ' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.call('create', f.credential, f.root.tenant.id, { name: 'x'.repeat(101) }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.call('create', f.credential, f.root.tenant.id, { name: 'Fields', owner: 'forged' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const a = await f.createTenant('acme');
    await expect(
      f.call('create', a.credential, a.tenant.id, {
        tenantId: f.root.tenant.id,
        name: 'Forged scope',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The same name is available in another tenant.
    const first = await f.call<Project>('create', a.credential, a.tenant.id, { name: 'Platform' });
    expect(first).toMatchObject({
      tenantId: a.tenant.id,
      createdBy: a.owner.identity.id,
      status: 'active',
    });
    await expect(
      f.call('update', a.credential, a.tenant.id, { projectId: first.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(
      (
        await f.call<Project>('update', a.credential, a.tenant.id, {
          projectId: first.id,
          name: 'Platform Core',
        })
      ).name,
    ).toBe('Platform Core');
    expect(
      (
        await f.call<Project>('update', a.credential, a.tenant.id, {
          projectId: first.id,
          description: 'Owned by acme',
        })
      ).description,
    ).toBe('Owned by acme');
    const cleared = await f.call<Project>('update', a.credential, a.tenant.id, {
      projectId: first.id,
      description: '',
    });
    expect(cleared).not.toHaveProperty('description');
    const second = await f.call<Project>('create', a.credential, a.tenant.id, { name: 'Second' });
    await expect(
      f.call('update', a.credential, a.tenant.id, { projectId: second.id, name: 'Platform Core' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(
      (await f.call<Project>('archive', a.credential, a.tenant.id, { projectId: second.id }))
        .status,
    ).toBe('archived');
    await expect(
      f.call('archive', a.credential, a.tenant.id, { projectId: second.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    expect(
      (await f.call<Project[]>('list', a.credential, a.tenant.id, { status: 'archived' })).map(
        (project) => project.id,
      ),
    ).toEqual([second.id]);
    expect(
      (await f.call<Project[]>('list', a.credential, a.tenant.id, { status: 'active' })).map(
        (project) => project.id,
      ),
    ).toEqual([first.id]);
    expect(
      (await f.call<Project[]>('list', a.credential, a.tenant.id))
        .map((project) => project.name)
        .sort(),
    ).toEqual(['Platform Core', 'Second']);
    expect(
      (await f.call<Project>('restore', a.credential, a.tenant.id, { projectId: second.id }))
        .status,
    ).toBe('active');
    await expect(
      f.call('restore', a.credential, a.tenant.id, { projectId: second.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    expect(
      (await f.call<Project>('get', a.credential, a.tenant.id, { projectId: second.id })).name,
    ).toBe('Second');
    await expect(
      f.call('get', a.credential, a.tenant.id, { projectId: platform.id }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('isolates tenants and enforces policies for project access', async () => {
    const f = await fixture(),
      a = await f.createTenant('alpha'),
      b = await f.createTenant('beta');
    const project = await f.call<Project>('create', a.credential, a.tenant.id, {
      name: 'Alpha project',
    });
    await expect(
      f.call('create', b.credential, a.tenant.id, { name: 'Intrusion' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(f.call('list', b.credential, a.tenant.id)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(
      f.call('get', b.credential, a.tenant.id, { projectId: project.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await f.call<Project[]>('list', b.credential, b.tenant.id)).toEqual([]);
    const reader = await f.iam.api.identities.create(a.credential, {
      tenantId: a.tenant.id,
      email: 'reader@example.test',
      name: 'Reader',
      password: 'a strong reader test password',
    });
    const policy = await f.iam.api.policies.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Project reader',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['projects:read'], resources: ['iam/*'] }],
      },
    });
    const role = await f.iam.api.roles.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Reader',
      policyIds: [policy.id],
    });
    await f.iam.api.bindings.create(a.credential, {
      tenantId: a.tenant.id,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: reader.id,
    });
    const signed = await f.iam.api.auth.signIn({
      tenantId: a.tenant.id,
      email: 'reader@example.test',
      password: 'a strong reader test password',
    });
    if (!('token' in signed)) throw new Error('Unexpected MFA');
    const readerCredential = { token: signed.token };
    expect(
      (await f.call<Project>('get', readerCredential, a.tenant.id, { projectId: project.id })).name,
    ).toBe('Alpha project');
    await expect(
      f.call('create', readerCredential, a.tenant.id, { name: 'Nope' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (await f.call<Project[]>('list', f.credential, a.tenant.id)).map((project) => project.id),
    ).toEqual([project.id]);
  });

  it('applies ancestor tenant boundaries to plugin actions', async () => {
    const f = await fixture(),
      a = await f.createTenant('bounded');
    const project = await f.call<Project>('create', a.credential, a.tenant.id, {
      name: 'Bounded project',
    });
    await f.iam.api.tenants.setBoundary(f.credential, {
      tenantId: a.tenant.id,
      boundary: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['iam:*'], resources: ['*'] }],
      },
    });
    await expect(
      f.call('create', a.credential, a.tenant.id, { name: 'Blocked' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(f.call('list', a.credential, a.tenant.id)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(
      f.call('archive', a.credential, a.tenant.id, { projectId: project.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (await f.call<Project[]>('list', f.credential, a.tenant.id)).map((project) => project.id),
    ).toEqual([project.id]);
  });

  it('removes purged tenants project records through the plugin purge callback', async () => {
    const f = await fixture(),
      a = await f.createTenant('alpha'),
      b = await f.createTenant('beta');
    const inA = await f.call<Project>('create', a.credential, a.tenant.id, { name: 'Alpha one' });
    const child = await f.createTenant('alpha-web', a.tenant.id, 'project');
    const inChild = await f.call<Project>('create', child.credential, child.tenant.id, {
      name: 'Alpha web',
    });
    const inB = await f.call<Project>('create', b.credential, b.tenant.id, { name: 'Beta one' });
    await f.iam.api.tenants.setStatus(f.credential, { tenantId: a.tenant.id, status: 'deleted' });
    const purge = await f.iam.purgeDeleted({ retentionMs: 0 });
    expect(purge.purgedTenants).toEqual([a.tenant.id, child.tenant.id].sort());
    expect(await f.database.find('projects', { tenantId: a.tenant.id })).toEqual([]);
    expect(await f.database.find('projects', { tenantId: child.tenant.id })).toEqual([]);
    expect(
      (await f.database.find<Project>('projects', { tenantId: b.tenant.id })).map(
        (project) => project.id,
      ),
    ).toEqual([inB.id]);
    expect(inA.id).not.toBe(inChild.id);
    expect(
      await f.database.find('audit', { tenantId: a.tenant.id, action: 'tenants:purge' }),
    ).toHaveLength(1);
  });

  it('serves the plugin over HTTP with the same authorization boundary', async () => {
    const f = await fixture(),
      a = await f.createTenant('http');
    const call = (path: string, body: unknown, headers: Record<string, string> = {}) =>
      f.iam.handler(
        new Request(`http://localhost:3000/api/iam/plugins/projects/${path}`, {
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
    const response = await call('create', { tenantId: a.tenant.id, name: 'HTTP project' });
    expect(response.status).toBe(200);
    const created = (await response.json()).data as Project;
    expect(created).toMatchObject({
      name: 'HTTP project',
      tenantId: a.tenant.id,
      createdBy: a.owner.identity.id,
      status: 'active',
    });
    const listed = await call('list', { tenantId: a.tenant.id });
    expect(((await listed.json()).data as Project[]).map((project) => project.id)).toEqual([
      created.id,
    ]);
    expect((await call('get', { tenantId: a.tenant.id, projectId: created.id })).status).toBe(200);
    expect((await call('list', { tenantId: a.tenant.id }, { 'x-better-iam': '0' })).status).toBe(
      403,
    );
    const other = await f.createTenant('other');
    expect((await call('list', { tenantId: other.tenant.id })).status).toBe(403);
    expect((await call('destroy', { tenantId: a.tenant.id, projectId: created.id })).status).toBe(
      404,
    );
    expect(
      (await call('create', { tenantId: a.tenant.id, name: 'No owner' }, { authorization: '' }))
        .status,
    ).toBe(401);
  });
});
