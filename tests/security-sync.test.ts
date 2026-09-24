import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

/**
 * Configuration sync: an identity provider cannot capture what configuration grants a group by creating a group of the
 * same name, and applying a document never silently drops what it cannot express (a team approver group, the dates of
 * a temporary grant).
 */

afterEach(closeFixtures);

async function setup() {
  const f = await organizationFixture();
  const owner = await f.ownerSignIn();
  const writer = await f.iam.api.roles.create(owner, {
    tenantId: f.tenantId,
    name: 'Writer',
    permissions: ['documents:write'],
  });
  return { f, owner, writer };
}

describe('configuration sync', () => {
  it('binds the administrators’ group, never a directory group that took its name', async () => {
    const { f, owner } = await setup();
    const admins = await f.iam.api.groups.create(owner, { tenantId: f.tenantId, name: 'Admins' });
    // An identity provider pushes its own "Admins" group through SCIM.
    const planted = randomUUID();
    await f.database.transaction(async (tx) => {
      await tx.insert('groups', { id: planted, tenantId: f.tenantId, name: 'Admins', createdAt: 1 });
      await tx.insert('scimGroups', {
        id: randomUUID(),
        tenantId: f.tenantId,
        connectionId: 'idp',
        groupId: planted,
        displayName: 'Admins',
        members: [],
        version: 1,
        createdAt: 1,
        updatedAt: 1,
      });
    });
    await f.iam.api.config.apply(owner, {
      tenantId: f.tenantId,
      config: {
        version: 1,
        roles: [{ name: 'Writer', permissions: ['documents:write'] }],
        groups: [{ name: 'Admins' }],
        bindings: [{ group: 'Admins', role: 'Writer' }],
      },
    });
    const bound = await f.database.find('bindings', { tenantId: f.tenantId, subjectType: 'group' });
    expect(bound.map((binding) => binding.subjectId)).toEqual([admins.id]);
  });

  it('keeps a team approver group and the dates of a temporary grant when it replaces a binding', async () => {
    const { f, owner, writer } = await setup();
    const oncall = await f.iam.api.groups.create(owner, { tenantId: f.tenantId, name: 'On-call' });
    // A team's backing group, which configuration never exports or manages.
    const teamGroup = randomUUID();
    await f.database.transaction(async (tx) => {
      await tx.insert('groups', {
        id: teamGroup,
        tenantId: f.tenantId,
        name: 'Team: Payments',
        teamId: 'team-payments',
        createdAt: 1,
      });
    });
    const expiresAt = f.now() + 30 * 86400000;
    const original = await f.iam.api.bindings.create(owner, {
      tenantId: f.tenantId,
      roleId: writer.id,
      subjectType: 'group',
      subjectId: oncall.id,
      eligible: true,
      requireApproval: true,
      approverGroupId: teamGroup,
      expiresAt,
    });
    await f.iam.api.config.apply(owner, {
      tenantId: f.tenantId,
      config: {
        version: 1,
        roles: [{ name: 'Writer', permissions: ['documents:write'] }],
        groups: [{ name: 'On-call' }],
        bindings: [
          {
            group: 'On-call',
            role: 'Writer',
            eligible: true,
            requireApproval: true,
            requireJustification: true,
          },
        ],
      },
    });
    const [replaced] = await f.database.find('bindings', {
      tenantId: f.tenantId,
      subjectType: 'group',
      subjectId: oncall.id,
    });
    expect(replaced!.id).not.toBe(original.id);
    expect(replaced).toMatchObject({
      requireJustification: true,
      approverGroupId: teamGroup,
      expiresAt,
    });
  });
});
