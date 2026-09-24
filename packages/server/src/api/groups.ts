import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Tenant,
} from '@better-iam/core';
import { releaseGroupApps } from '../applications.js';
import type { ServerContext } from '../context.js';
import type { AccessPackage, Binding, BindingActivation, Group, GroupMember } from '../models.js';
import { ruleGroupIds } from '../package-rules.js';
import {
  assertNotTeamGroup,
  syncTeamsFromGroups,
  teamChainBindings,
  teamsSyncingFrom,
} from '../teams.js';
import { id, publicIdentity, type PublicIdentity } from '../utils.js';
import { strings, text } from '../validation.js';

/**
 * Brings the teams that sync their members from the group in step (teams.ts). A synced person joins or leaves those
 * teams' backing groups and those of every team above them, so a membership change that moves a team needs the grant
 * authority behind what those groups hold, exactly as changing the team's members directly does.
 */
async function followSyncedTeams(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
  groupId: string,
): Promise<void> {
  const synced = await syncTeamsFromGroups(ctx, tx, tenantId, {
    groupId,
    actorId: principal.identity.id,
  });
  for (const binding of await teamChainBindings(tx, tenantId, synced.teams))
    await ctx.grantingAuthority(tx, principal, tenantId, binding.authorityId);
}

export interface GroupInput {
  tenantId: string;
  name: string;
  description?: string;
}

/** Creates a group within the tenant's plan limit; shared by `groups.create` and configuration sync. */
export async function createGroup(
  ctx: ServerContext,
  tx: IamStore,
  tenant: Tenant,
  input: GroupInput,
): Promise<Group> {
  await ctx.enforceLimit(
    tx,
    tenant,
    'groups',
    async () => (await tx.find('groups', { tenantId: input.tenantId })).length,
  );
  const group: Group = {
    id: id(),
    tenantId: input.tenantId,
    name: text(input.name, 'name'),
  };
  if (input.description !== undefined)
    group.description = text(input.description, 'description', 512);
  return tx.insert<Group>('groups', group);
}

/**
 * Adds an identity to a group; membership confers every group binding, so each binding's authority is required (and,
 * for teams that sync from the group, that of their backing groups' bindings). `expiresAt` makes the membership
 * temporary. Re-adding an expired member renews the membership.
 */
export async function addGroupMember(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  input: { tenantId: string; groupId: string; identityId: string; expiresAt?: number },
): Promise<GroupMember> {
  // A team's backing group takes its members from the team (teams.ts).
  assertNotTeamGroup(await ctx.scoped<Group>(tx, 'groups', input.groupId, input.tenantId));
  await ctx.activeIdentity(tx, input.identityId, input.tenantId);
  for (const binding of await tx.find<Binding>('bindings', {
    tenantId: input.tenantId,
    subjectType: 'group',
    subjectId: input.groupId,
  }))
    await ctx.grantingAuthority(tx, principal, input.tenantId, binding.authorityId);
  const expiresAt = input.expiresAt !== undefined ? ctx.bindingExpiry(input.expiresAt) : undefined;
  const existing = (
    await tx.find<GroupMember>('groupMembers', {
      tenantId: input.tenantId,
      uniqueKey: `${input.groupId}:${input.identityId}`,
    })
  )[0];
  let member: GroupMember;
  if (existing) {
    if (ctx.liveMembership(existing))
      throw new IamError('CONFLICT', 'Already a member of this group', 409);
    // A renewed membership starts fresh: it no longer belongs to the package assignment that once created it.
    const { expiresAt: _previous, packageAssignmentId: _package, ...rest } = existing;
    member = await tx.put<GroupMember>(
      'groupMembers',
      expiresAt === undefined ? rest : { ...rest, expiresAt },
    );
  } else
    member = await tx.insert<GroupMember>('groupMembers', {
      id: id(),
      tenantId: input.tenantId,
      uniqueKey: `${input.groupId}:${input.identityId}`,
      groupId: input.groupId,
      identityId: input.identityId,
      ...(expiresAt !== undefined ? { expiresAt } : {}),
    });
  // Teams that sync their members from this group follow (teams.ts).
  await followSyncedTeams(ctx, tx, principal, input.tenantId, input.groupId);
  return member;
}

/** Extends, shortens, or clears (null) a membership's expiry under the same authority rules as adding a member. */
export async function updateGroupMember(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  input: { tenantId: string; groupId: string; identityId: string; expiresAt: number | null },
): Promise<GroupMember> {
  assertNotTeamGroup(await ctx.scoped<Group>(tx, 'groups', input.groupId, input.tenantId));
  for (const binding of await tx.find<Binding>('bindings', {
    tenantId: input.tenantId,
    subjectType: 'group',
    subjectId: input.groupId,
  }))
    await ctx.grantingAuthority(tx, principal, input.tenantId, binding.authorityId);
  const member = (
    await tx.find<GroupMember>('groupMembers', {
      tenantId: input.tenantId,
      uniqueKey: `${input.groupId}:${input.identityId}`,
    })
  )[0];
  if (!member || !ctx.liveMembership(member))
    throw new IamError('NOT_FOUND', 'Not a member of this group', 404);
  // Editing a package's membership by hand takes it over: revoking the package no longer removes it.
  const { expiresAt: _previous, packageAssignmentId: _package, ...rest } = member;
  const updated = await tx.put<GroupMember>(
    'groupMembers',
    input.expiresAt === null ? rest : { ...rest, expiresAt: ctx.bindingExpiry(input.expiresAt) },
  );
  // Synced team memberships end when their source membership does (teams.ts).
  await followSyncedTeams(ctx, tx, principal, input.tenantId, input.groupId);
  return updated;
}

/** Adds up to 100 identities atomically (cohort onboarding); one failure rejects the batch. */
export async function addGroupMembers(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  input: { tenantId: string; groupId: string; identityIds: string[]; expiresAt?: number },
): Promise<GroupMember[]> {
  const identityIds = [...new Set(strings(input.identityIds, 'identityIds'))];
  if (!identityIds.length) throw new IamError('INVALID_INPUT', 'Provide 1-100 identityIds');
  const members: GroupMember[] = [];
  for (const identityId of identityIds)
    members.push(
      await addGroupMember(ctx, tx, principal, {
        tenantId: input.tenantId,
        groupId: input.groupId,
        identityId,
        ...(input.expiresAt !== undefined ? { expiresAt: input.expiresAt } : {}),
      }),
    );
  return members;
}

/** Removes an identity from a group, ending its activations of the group's eligible bindings. */
export async function removeGroupMember(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  input: { tenantId: string; groupId: string; identityId: string },
): Promise<void> {
  assertNotTeamGroup(await ctx.scoped<Group>(tx, 'groups', input.groupId, input.tenantId));
  const bindings = await tx.find<Binding>('bindings', {
    tenantId: input.tenantId,
    subjectType: 'group',
    subjectId: input.groupId,
  });
  for (const binding of bindings)
    await ctx.grantingAuthority(tx, principal, input.tenantId, binding.authorityId);
  for (const member of await tx.find<GroupMember>('groupMembers', {
    tenantId: input.tenantId,
    groupId: input.groupId,
    identityId: input.identityId,
  }))
    await tx.delete('groupMembers', member.id);
  for (const activation of await tx.find<BindingActivation>('bindingActivations', {
    tenantId: input.tenantId,
    identityId: input.identityId,
  }))
    if (bindings.some((binding) => binding.id === activation.bindingId))
      await tx.delete('bindingActivations', activation.id);
  // Teams that sync their members from this group follow (teams.ts); leaving one may lift a deny bound to it.
  await followSyncedTeams(ctx, tx, principal, input.tenantId, input.groupId);
}

/** Deletes a group with its memberships, bindings, activations, and relationships. */
export async function deleteGroup(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  group: Group,
): Promise<void> {
  const packages = await tx.find<AccessPackage>('accessPackages', { tenantId: group.tenantId });
  // A group a package grants, or one its birthright rule tests, stays until the package stops using it.
  const packaged = packages.filter(
    (pkg) => pkg.groupIds.includes(group.id) || ruleGroupIds(pkg.autoAssign).includes(group.id),
  );
  if (packaged.length)
    throw new IamError(
      'RESOURCE_IN_USE',
      `Access packages still include it or name it in a rule: ${packaged.map((pkg) => pkg.name).join(', ')}`,
      409,
    );
  // Teams that sync their members from it would silently lose them.
  const syncing = await teamsSyncingFrom(tx, group.tenantId, group.id);
  if (syncing.length)
    throw new IamError(
      'RESOURCE_IN_USE',
      `Teams sync their members from it: ${syncing.map((team) => team.name).join(', ')}; stop syncing first`,
      409,
    );
  // An approver group that disappeared would silently leave its requests to whoever else may decide.
  const approving = packages.filter((pkg) => pkg.approverGroupId === group.id);
  const approvingBindings = (
    await tx.find<Binding>('bindings', { tenantId: group.tenantId, approverGroupId: group.id })
  ).filter(
    (binding) =>
      !ctx.expiredBinding(binding) &&
      // The group's own bindings go with it.
      !(binding.subjectType === 'group' && binding.subjectId === group.id),
  );
  if (approving.length || approvingBindings.length)
    throw new IamError(
      'RESOURCE_IN_USE',
      `It approves requests for ${[
        ...approving.map((pkg) => `package ${pkg.name}`),
        ...(approvingBindings.length ? [`${approvingBindings.length} eligible binding(s)`] : []),
      ].join(', ')}; name another approver group first`,
      409,
    );
  const bindings = await tx.find<Binding>('bindings', {
    tenantId: group.tenantId,
    subjectType: 'group',
    subjectId: group.id,
  });
  for (const binding of bindings)
    await ctx.grantingAuthority(tx, principal, group.tenantId, binding.authorityId);
  for (const member of await tx.find<GroupMember>('groupMembers', {
    tenantId: group.tenantId,
    groupId: group.id,
  }))
    await tx.delete('groupMembers', member.id);
  for (const binding of bindings) {
    for (const activation of await tx.find('bindingActivations', {
      tenantId: group.tenantId,
      bindingId: binding.id,
    }))
      await tx.delete('bindingActivations', activation.id);
    await tx.delete('bindings', binding.id);
  }
  for (const tuple of await tx.find('relationships', {
    tenantId: group.tenantId,
    subjectType: 'group',
    subjectId: group.id,
  }))
    await tx.delete('relationships', tuple.id);
  // App assignments to the group go with it (applications.ts).
  await releaseGroupApps(tx, group.tenantId, group.id);
  await tx.delete('groups', group.id);
}

export function createGroupsApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  return {
    create: (credential: CredentialInput, input: GroupInput) =>
      operation(credential, input.tenantId, 'iam:groups:create', input.tenantId, ({ tx, tenant }) =>
        createGroup(ctx, tx, tenant, input),
      ),
    list: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:groups:read', input.tenantId, ({ tx }) =>
        tx.find<Group>('groups', { tenantId: input.tenantId }),
      ),
    get: (credential: CredentialInput, input: { tenantId: string; groupId: string }) =>
      operation(credential, input.tenantId, 'iam:groups:read', input.groupId, ({ tx }) =>
        ctx.scoped<Group>(tx, 'groups', input.groupId, input.tenantId),
      ),
    update: (
      credential: CredentialInput,
      input: { tenantId: string; groupId: string; name?: string; description?: string },
    ) =>
      operation(credential, input.tenantId, 'iam:groups:update', input.groupId, async ({ tx }) => {
        const group = await ctx.scoped<Group>(tx, 'groups', input.groupId, input.tenantId);
        if (input.name === undefined && input.description === undefined)
          throw new IamError('INVALID_INPUT', 'Nothing to update');
        const next: Group = { ...group };
        if (input.name !== undefined) next.name = text(input.name, 'name');
        if (input.description !== undefined)
          next.description = text(input.description, 'description', 512);
        return tx.put('groups', next);
      }),
    /** Current members (expired memberships are omitted), each with `membershipExpiresAt` when temporary. */
    listMembers: (credential: CredentialInput, input: { tenantId: string; groupId: string }) =>
      operation(credential, input.tenantId, 'iam:groups:read', input.groupId, async ({ tx }) => {
        await ctx.scoped(tx, 'groups', input.groupId, input.tenantId);
        const members: Array<PublicIdentity & { membershipExpiresAt?: number }> = [];
        for (const membership of await tx.find<GroupMember>('groupMembers', {
          tenantId: input.tenantId,
          groupId: input.groupId,
        })) {
          if (!ctx.liveMembership(membership)) continue;
          const identity = await tx.get<Identity>('identities', membership.identityId);
          if (identity && identity.tenantId === input.tenantId)
            members.push({
              ...publicIdentity(identity),
              ...(membership.expiresAt !== undefined
                ? { membershipExpiresAt: membership.expiresAt }
                : {}),
            });
        }
        return members;
      }),
    /** `expiresAt` (epoch milliseconds) makes the membership temporary; it ends by itself and the purge worker removes it. */
    addMember: (
      credential: CredentialInput,
      input: { tenantId: string; groupId: string; identityId: string; expiresAt?: number },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:groups:update',
        input.groupId,
        ({ tx, principal }) => addGroupMember(ctx, tx, principal, input),
      ),
    /** Adds up to 100 members in one transaction, optionally all with the same expiry. */
    addMembers: (
      credential: CredentialInput,
      input: { tenantId: string; groupId: string; identityIds: string[]; expiresAt?: number },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:groups:update',
        input.groupId,
        async ({ tx, principal }) => ({
          members: await addGroupMembers(ctx, tx, principal, input),
        }),
      ),
    /** Extends, shortens, or clears (null) a temporary membership. */
    updateMember: (
      credential: CredentialInput,
      input: { tenantId: string; groupId: string; identityId: string; expiresAt: number | null },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:groups:update',
        input.groupId,
        ({ tx, principal }) => updateGroupMember(ctx, tx, principal, input),
      ),
    removeMember: (
      credential: CredentialInput,
      input: { tenantId: string; groupId: string; identityId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:groups:update',
        input.groupId,
        async ({ tx, principal }) => {
          await removeGroupMember(ctx, tx, principal, input);
          return { deleted: true };
        },
      ),
    delete: (credential: CredentialInput, input: { tenantId: string; groupId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:groups:delete',
        input.groupId,
        async ({ tx, principal }) => {
          const group = await ctx.scoped<Group>(tx, 'groups', input.groupId, input.tenantId);
          // A team's backing group goes with its team (`teams.delete`).
          assertNotTeamGroup(group);
          await deleteGroup(ctx, tx, principal, group);
          return { deleted: true };
        },
      ),
  };
}
