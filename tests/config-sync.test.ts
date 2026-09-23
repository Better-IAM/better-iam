import { afterEach, describe, expect, it } from 'vitest';
import type { TenantConfig } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const desired: TenantConfig = {
  version: 1,
  resourceTypes: [
    {
      name: 'project',
      description: 'A project',
      actions: ['read', 'write'],
      attributes: { archived: 'boolean' },
      relations: ['viewer'],
    },
  ],
  policies: [
    {
      name: 'Readers',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['documents:read', 'project:read'], resources: ['*'] },
        ],
      },
    },
  ],
  roles: [
    { name: 'Reader', description: 'Reads', policies: ['Readers'] },
    { name: 'Editor', permissions: ['documents:write', 'project:write'] },
  ],
  groups: [{ name: 'Engineering', members: ['alice@acme.test'] }],
  bindings: [
    { group: 'Engineering', role: 'Reader' },
    {
      group: 'Engineering',
      role: 'Editor',
      eligible: true,
      maxActivationMs: 600_000,
      requireJustification: true,
    },
  ],
};

async function fixture() {
  const f = await organizationFixture({
    permissions: { mode: 'tenant-defined', actions: ['documents:read', 'documents:write'] },
  });
  await f.member('alice');
  await f.member('bob');
  return f;
}

describe('configuration sync', () => {
  it('plans, applies, exports, and converges a tenant configuration', async () => {
    const f = await fixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const plan = await f.iam.api.config.plan(owner, { tenantId, config: desired });
    expect(plan.summary).toEqual({ create: 7, update: 0, delete: 0, unchanged: 0 });
    expect(plan.changes.map((change) => `${change.action} ${change.kind} ${change.name}`)).toEqual([
      'create resourceType project',
      'create policy Readers',
      'create role Editor',
      'create role Reader',
      'create group Engineering',
      'create binding Engineering -> Editor',
      'create binding Engineering -> Reader',
    ]);
    // A plan writes nothing.
    expect((await f.iam.api.roles.list(owner, { tenantId })).map((role) => role.name)).toEqual([
      'Owner',
    ]);
    const applied = await f.iam.api.config.apply(owner, { tenantId, config: desired });
    expect(applied.applied).toBe(true);
    expect(applied.summary).toEqual(plan.summary);
    const roles = await f.iam.api.roles.list(owner, { tenantId });
    expect(roles.map((role) => role.name).sort()).toEqual(['Editor', 'Owner', 'Reader']);
    const reader = roles.find((role) => role.name === 'Reader')!;
    const readers = (await f.iam.api.policies.list(owner, { tenantId })).find(
      (policy) => policy.name === 'Readers',
    )!;
    expect(reader.policyIds).toEqual([readers.id]);
    const engineering = (await f.iam.api.groups.list(owner, { tenantId }))[0]!;
    expect(
      (await f.iam.api.groups.listMembers(owner, { tenantId, groupId: engineering.id })).map(
        (member) => member.email,
      ),
    ).toEqual(['alice@acme.test']);
    expect(await f.iam.api.bindings.list(owner, { tenantId, eligible: true })).toMatchObject([
      { subjectId: engineering.id, maxActivationMs: 600_000, requireJustification: true },
    ]);
    expect(
      (await f.iam.api.resourceTypes.get(owner, { tenantId, name: 'project' })).actions.sort(),
    ).toEqual(['project:read', 'project:write']);
    // The trail records the apply with its summary.
    const trail = await f.iam.api.audit.list(owner, { tenantId, action: 'config:apply' });
    expect(trail[0]!.metadata).toMatchObject({ create: 7, prune: false });
    // Export round-trips, and applying the export changes nothing.
    const exported = await f.iam.api.config.export(owner, { tenantId });
    expect(exported).toEqual({
      version: 1,
      resourceTypes: [
        {
          name: 'project',
          description: 'A project',
          actions: ['read', 'write'],
          attributes: { archived: 'boolean' },
          relations: ['viewer'],
        },
      ],
      policies: [{ name: 'Readers', document: desired.policies![0]!.document }],
      roles: [
        { name: 'Editor', policies: [], permissions: ['documents:write', 'project:write'] },
        { name: 'Reader', description: 'Reads', policies: ['Readers'] },
      ],
      groups: [{ name: 'Engineering', members: ['alice@acme.test'] }],
      bindings: [
        {
          group: 'Engineering',
          role: 'Editor',
          eligible: true,
          maxActivationMs: 600_000,
          requireJustification: true,
        },
        { group: 'Engineering', role: 'Reader' },
      ],
      packages: [],
    });
    expect((await f.iam.api.config.apply(owner, { tenantId, config: exported })).summary).toEqual({
      create: 0,
      update: 0,
      delete: 0,
      unchanged: 7,
    });
    // Drift: change permissions and membership, drop the Reader role; prune decides about deletions.
    const next: TenantConfig = {
      version: 1,
      roles: [
        { name: 'Editor', permissions: ['documents:read', 'documents:write', 'project:write'] },
      ],
      groups: [{ name: 'Engineering', members: ['alice@acme.test', 'bob@acme.test'] }],
      bindings: [{ group: 'Engineering', role: 'Editor' }],
    };
    const keep = await f.iam.api.config.plan(owner, { tenantId, config: next });
    expect(keep.summary).toEqual({ create: 0, update: 3, delete: 0, unchanged: 0 });
    expect(keep.changes.find((change) => change.kind === 'role')).toMatchObject({
      action: 'update',
      fields: ['document'],
    });
    expect(keep.changes.find((change) => change.kind === 'group')).toMatchObject({
      action: 'update',
      fields: ['members'],
    });
    expect(keep.changes.find((change) => change.kind === 'binding')).toMatchObject({
      action: 'update',
      fields: ['eligible', 'maxActivationMs', 'requireJustification'],
    });
    const pruned = await f.iam.api.config.plan(owner, { tenantId, config: next, prune: true });
    expect(pruned.summary).toEqual({ create: 0, update: 3, delete: 2, unchanged: 0 });
    expect(
      pruned.changes
        .filter((change) => change.action === 'delete')
        .map((change) => `${change.kind} ${change.name}`),
    ).toEqual(['role Reader', 'binding Engineering -> Reader']);
    const result = await f.iam.api.config.apply(owner, { tenantId, config: next, prune: true });
    expect(result.summary).toEqual(pruned.summary);
    expect(
      (await f.iam.api.roles.list(owner, { tenantId })).map((role) => role.name).sort(),
    ).toEqual(['Editor', 'Owner']);
    expect(
      (await f.iam.api.groups.listMembers(owner, { tenantId, groupId: engineering.id }))
        .map((member) => member.email)
        .sort(),
    ).toEqual(['alice@acme.test', 'bob@acme.test']);
    expect(await f.iam.api.bindings.list(owner, { tenantId, eligible: true })).toEqual([]);
    // Policies were not listed, so the policy survived; a later prune with policies: [] removes it.
    expect((await f.iam.api.policies.list(owner, { tenantId })).map((p) => p.name)).toContain(
      'Readers',
    );
    const cleared = await f.iam.api.config.apply(owner, {
      tenantId,
      config: { version: 1, policies: [] },
      prune: true,
    });
    expect(cleared.summary).toEqual({ create: 0, update: 0, delete: 1, unchanged: 0 });
    expect((await f.iam.api.policies.list(owner, { tenantId })).map((p) => p.name)).toEqual([
      'Owner',
    ]);
    // A resource type whose actions a role still names cannot be pruned; nothing else is touched.
    await expect(
      f.iam.api.config.apply(owner, {
        tenantId,
        config: { version: 1, resourceTypes: [], groups: [] },
        prune: true,
      }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    expect((await f.iam.api.groups.list(owner, { tenantId })).map((group) => group.name)).toEqual([
      'Engineering',
    ]);
  });

  it('rejects malformed or dangling configurations and applies atomically under authorization', async () => {
    const f = await fixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const plan = (config: unknown) => f.iam.api.config.plan(owner, { tenantId, config });
    await expect(plan({ version: 2 })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(plan({ version: 1, roles: [{ name: 'A' }, { name: 'A' }] })).rejects.toMatchObject(
      { code: 'INVALID_INPUT' },
    );
    await expect(
      plan({ version: 1, roles: [{ name: 'A', policies: ['Missing'] }] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      plan({ version: 1, groups: [{ name: 'G', members: ['nobody@acme.test'] }] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(plan({ version: 1, bindings: [{ group: 'G', role: 'R' }] })).rejects.toMatchObject(
      { code: 'INVALID_INPUT' },
    );
    await expect(
      plan({
        version: 1,
        roles: [{ name: 'A', permissions: ['x'], document: { version: 1, statements: [] } }],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Unknown actions are refused by the catalog, like a direct create.
    await expect(
      f.iam.api.config.apply(owner, {
        tenantId,
        config: { version: 1, roles: [{ name: 'A', permissions: ['nope:read'] }] },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    // Members without the config permissions are refused at the door.
    const asAlice = { token: (await f.signIn('alice')).token };
    await expect(
      f.iam.api.config.plan(asAlice, { tenantId, config: { version: 1 } }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Holding iam:config:apply is not enough: each change needs the equivalent direct permission,
    // and one refusal rolls the whole apply back.
    const operator = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Config operator',
      permissions: ['iam:config:read', 'iam:config:apply', 'iam:groups:create'],
    });
    const alice = (await f.iam.api.identities.list(owner, { tenantId, query: 'alice' }))[0]!;
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: operator.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    expect(
      (
        await f.iam.api.config.plan(asAlice, {
          tenantId,
          config: {
            version: 1,
            groups: [{ name: 'Ops' }],
            roles: [{ name: 'X', permissions: ['documents:read'] }],
          },
        })
      ).summary.create,
    ).toBe(2);
    await expect(
      f.iam.api.config.apply(asAlice, {
        tenantId,
        config: {
          version: 1,
          groups: [{ name: 'Ops' }],
          roles: [{ name: 'X', permissions: ['documents:read'] }],
        },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await f.iam.api.groups.list(owner, { tenantId })).toEqual([]);
    // The HTTP route serves the group like any other.
    const origin = 'http://localhost:3000';
    const response = await f.iam.handler(
      new Request(`${origin}/api/iam/config/plan`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          origin,
          authorization: `Bearer ${owner.token}`,
        },
        body: JSON.stringify({ tenantId, config: { version: 1, groups: [{ name: 'Ops' }] } }),
      }),
    );
    expect(response.status).toBe(200);
    expect(
      ((await response.json()) as { data: { summary: { create: number } } }).data.summary.create,
    ).toBe(1);
  });
});
