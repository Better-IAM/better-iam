import {
  IamError,
  type AuditEvent,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type PolicyDocument,
  type Session,
} from '@better-iam/core';
import { encryptSecret } from '@better-iam/auth';
import { handOverAgents } from '../agents.js';
import { releaseAppRecordsOf } from '../applications.js';
import { attributeValues } from '../catalog.js';
import type { ServerContext } from '../context.js';
import { revokeDelegationsOf } from '../delegations.js';
import { releaseDepartments } from '../departments.js';
import { releaseDevicesOf } from '../devices.js';
import { assertNoLegalHold, releasePrivacyRecords } from '../privacy.js';
import { assertNotTeamGroup, removeFromAllTeams } from '../teams.js';
import { endContainment } from '../threats.js';
import type {
  AccessRequest,
  Binding,
  GrantAuthority,
  Group,
  GroupMember,
  IdentityLink,
  MemberInvitation,
  PackageAssignment,
  PrincipalBoundary,
  Relationship,
  ResourceRecord,
  Role,
} from '../models.js';
import { OperationDenied } from '../operations.js';
import { all, hash, id, publicIdentity, token, type PublicIdentity } from '../utils.js';
import { email, integer, object, strings, text } from '../validation.js';
import { deleteBinding } from './bindings.js';
import { removeGroupMember } from './groups.js';
import { afterIdentityChange } from './package-automation.js';
import { revokeAssignment } from './packages.js';

/**
 * Deletes an identity: every credential, factor, binding, membership, boundary, and link is removed or revoked in the same
 * transaction, and a tombstone without email or secrets remains so audit records keep a resolvable principal.
 */
export async function deleteIdentity(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  identity: Identity,
): Promise<PublicIdentity> {
  if (identity.status === 'deleted')
    throw new IamError('CONFLICT', 'Identity is already deleted', 409);
  if (identity.id === principal.identity.id)
    throw new IamError('INVALID_INPUT', 'An identity cannot delete itself');
  if (identity.rootAdmin && !(await ctx.rootPrincipal(tx, principal)))
    throw new IamError('ACCESS_DENIED', 'Root capability is protected', 403);
  await assertOwnerControl(ctx, tx, principal, identity, 'Only an owner can delete an owner');
  await ctx.protectLastOwner(tx, identity);
  // A legal hold (privacy.ts) keeps the person: no deletion path removes what litigation needs kept.
  await assertNoLegalHold(tx, identity, ctx.now());
  await ctx.revokeAll(tx, identity.id);
  await revokeInvitationsBy(tx, identity.id);
  const remove = async (collection: string, filter: Record<string, unknown>) => {
    for (const row of await tx.find(collection, filter)) await tx.delete(collection, row.id);
  };
  await remove('bindings', {
    tenantId: identity.tenantId,
    subjectType: 'identity',
    subjectId: identity.id,
  });
  await remove('groupMembers', { tenantId: identity.tenantId, identityId: identity.id });
  await remove('bindingActivations', { tenantId: identity.tenantId, identityId: identity.id });
  await remove('packageAssignments', { tenantId: identity.tenantId, identityId: identity.id });
  await remove('packageRequests', { tenantId: identity.tenantId, identityId: identity.id });
  // A tombstone is nobody's manager.
  for (const report of await tx.find<Identity>('identities', {
    tenantId: identity.tenantId,
    managerId: identity.id,
  })) {
    const { managerId: _gone, ...rest } = report;
    await tx.put<Identity>('identities', rest);
  }
  await remove('principalBoundaries', { tenantId: identity.tenantId, identityId: identity.id });
  await remove('authPasskeys', { tenantId: identity.tenantId, identityId: identity.id });
  await remove('passwordHistory', { tenantId: identity.tenantId, identityId: identity.id });
  await remove('externalIdentities', { tenantId: identity.tenantId, identityId: identity.id });
  // Onboarding progress carries the person's form answers.
  await remove('onboardingProgress', { tenantId: identity.tenantId, subjectId: identity.id });
  // Threat detection (threats.ts): the sign-in baseline (networks, user agents) and the risk record go with the
  // person; detections and incidents stay as the investigation record.
  await remove('threatBaselines', { tenantId: identity.tenantId, identityId: identity.id });
  await remove('identityRisk', { tenantId: identity.tenantId, identityId: identity.id });
  // Device posture (devices.ts): self-enrolled devices retire with their keys, managed ones lose their owner.
  await releaseDevicesOf(tx, identity, ctx.now());
  // Teams and departments (teams.ts, departments.ts): memberships end, departments they head lose their head.
  await removeFromAllTeams(tx, identity.tenantId, identity.id, ctx.now());
  await releaseDepartments(tx, identity.tenantId, identity.id, ctx.now());
  await remove('relationships', {
    tenantId: identity.tenantId,
    subjectType: 'identity',
    subjectId: identity.id,
  });
  // Delegations the person gave AI agents (or an agent held) end with the identity (delegations.ts).
  await revokeDelegationsOf(ctx, tx, identity, principal.identity.id);
  // Current consent decisions and restrictions go; their history stays as proof (privacy.ts).
  await releasePrivacyRecords(tx, identity);
  // App assignments and launch history go; apps they owned lose them as an owner (applications.ts).
  await releaseAppRecordsOf(tx, identity);
  if (await tx.get('authMfa', identity.id)) await tx.delete('authMfa', identity.id);
  for (const authority of await tx.find<GrantAuthority>('grantAuthorities', {
    tenantId: identity.tenantId,
    identityId: identity.id,
  }))
    if (!authority.revoked) await tx.put('grantAuthorities', { ...authority, revoked: true });
  const links = [
    ...(await tx.find<IdentityLink>('identityLinks', { leftId: identity.id })),
    ...(await tx.find<IdentityLink>('identityLinks', { rightId: identity.id })),
  ];
  for (const link of links)
    if (!link.revoked) await tx.put('identityLinks', { ...link, revoked: true });
  for (const request of await tx.find<AccessRequest>('accessRequests', {
    tenantId: identity.tenantId,
    requesterId: identity.id,
    status: 'pending',
  }))
    await tx.put('accessRequests', { ...request, status: 'cancelled', reviewedAt: ctx.now() });
  const {
    passwordHash: _hash,
    email: deletedEmail,
    phone: _phone,
    managerId: _manager,
    ...rest
  } = identity;
  const tombstone: Identity = {
    ...rest,
    uniqueKey: `deleted:${identity.id}`,
    status: 'deleted',
    owner: false,
    rootAdmin: false,
    emailVerified: false,
    deletedAt: ctx.now(),
  };
  if (deletedEmail !== undefined) tombstone.deletedEmail = deletedEmail;
  return publicIdentity(await tx.put('identities', tombstone));
}

/**
 * Whoever controls an account's sign-in address or triggers its password reset controls the account, so
 * iam:identities:update alone must not reach an owner or a root administrator (that would be a takeover, and it
 * would bypass the ban on impersonating them). An owner's needs another owner of the same tenant or a root
 * principal; a root administrator's needs a root principal. The refusal is audited as a denial.
 */
async function assertAccountControl(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  identity: Identity,
): Promise<void> {
  if (!identity.owner && !identity.rootAdmin) return;
  if (await ctx.rootPrincipal(tx, principal)) return;
  if (
    !identity.rootAdmin &&
    principal.identity.owner &&
    principal.identity.tenantId === identity.tenantId
  )
    return;
  throw new OperationDenied(
    identity.rootAdmin
      ? 'Only a root administrator can change a root administrator’s sign-in address or password'
      : 'Only an owner can change an owner’s sign-in address or password',
  );
}

/**
 * The caller is an owner of this tenant in person: the tenant's own owner account on an ordinary session. An
 * assumed role never counts, even when its source account owns another tenant, because a role session carries
 * only the role's grants.
 */
function ownsTenant(principal: AuthenticatedPrincipal, tenantId: string): boolean {
  return (
    principal.session.kind === 'user' &&
    principal.identity.owner &&
    principal.identity.tenantId === tenantId &&
    principal.session.tenantId === tenantId
  );
}

/**
 * Deleting, disabling, or scheduling the deactivation of an owner removes an owner as surely as `setOwner(false)` or
 * `offboard` does, so it needs the same caller: an owner of the tenant in person or a root principal, never
 * iam:identities:update or iam:identities:delete alone. The refusal is audited as a denial.
 */
export async function assertOwnerControl(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  identity: Identity,
  message: string,
): Promise<void> {
  if (!identity.owner) return;
  if (ownsTenant(principal, identity.tenantId) || (await ctx.rootPrincipal(tx, principal))) return;
  throw new OperationDenied(message);
}

/**
 * Attributes and a manager feed birthright package rules and policy conditions, so choosing them when creating an
 * identity is an update: it needs iam:identities:update on the tenant besides iam:identities:create.
 */
async function assertMaySetProfile(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
): Promise<void> {
  const decision = await ctx.decisions.decide(
    tx,
    principal,
    { tenantId, action: 'iam:identities:update', resource: { type: 'iam', id: tenantId } },
    true,
  );
  if (!decision.allowed)
    throw new OperationDenied('Setting attributes or a manager requires iam:identities:update');
}

/** Attribute maps compared by content, whatever order their keys were written in. */
function sameAttributes(a: Record<string, Json> = {}, b: Record<string, Json> = {}): boolean {
  const canonical = (value: Record<string, Json>) =>
    JSON.stringify(
      Object.keys(value)
        .sort()
        .map((key) => [key, value[key]]),
    );
  return canonical(a) === canonical(b);
}

/**
 * The member invitations an identity sent and nobody redeemed yet are revoked when it is disabled or leaves (redemption
 * refuses an inactive inviter anyway; this keeps `listInvitations` truthful and the tokens dead if it comes back).
 */
export async function revokeInvitationsBy(tx: IamStore, identityId: string): Promise<void> {
  for (const invitation of await tx.find<MemberInvitation>('memberInvitations', {
    inviterId: identityId,
  }))
    if (!invitation.consumed && !invitation.revoked)
      await tx.put('memberInvitations', { ...invitation, revoked: true });
}

/** A manager is another active identity of the tenant, never the person or one of their own reports (no cycles). */
async function managerFor(
  ctx: ServerContext,
  tx: IamStore,
  identity: Pick<Identity, 'id' | 'tenantId'>,
  managerId: unknown,
): Promise<string> {
  const manager = await ctx.activeIdentity(tx, text(managerId, 'managerId'), identity.tenantId);
  if (manager.id === identity.id)
    throw new IamError('INVALID_INPUT', 'An identity cannot be its own manager');
  if (manager.status !== 'active')
    throw new IamError('INVALID_INPUT', 'A manager must be an active identity');
  let cursor: Identity | undefined = manager;
  for (let depth = 0; cursor?.managerId && depth < 100; depth++) {
    if (cursor.managerId === identity.id)
      throw new IamError('INVALID_INPUT', 'That would make the reporting line circular');
    cursor = await tx.get<Identity>('identities', cursor.managerId);
  }
  return manager.id;
}

export function createIdentitiesApi(ctx: ServerContext) {
  const { auth, options, config, catalog } = ctx;
  const { operation } = ctx.operations;
  return {
    /**
     * `expiresAt` schedules deactivation (contractors): credentials stop working at that time and the worker disables
     * the identity. A `managerId` also needs iam:identities:update on the tenant.
     */
    create: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        email: string;
        name: string;
        password?: string;
        expiresAt?: number;
        /** The person's manager (another active identity of the tenant). */
        managerId?: string;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:create',
        input.tenantId,
        async ({ tx, principal }) => {
          const expiresAt =
            input.expiresAt !== undefined ? ctx.bindingExpiry(input.expiresAt) : undefined;
          if (input.managerId !== undefined)
            await assertMaySetProfile(ctx, tx, principal, input.tenantId);
          const identity = await auth.createIdentity(tx, {
            tenantId: input.tenantId,
            email: email(input.email),
            name: text(input.name, 'name'),
            password: input.password,
          });
          const managerId =
            input.managerId !== undefined
              ? await managerFor(ctx, tx, identity, input.managerId)
              : undefined;
          return publicIdentity(
            expiresAt === undefined && managerId === undefined
              ? identity
              : await tx.put<Identity>('identities', {
                  ...identity,
                  ...(expiresAt !== undefined ? { expiresAt } : {}),
                  ...(managerId !== undefined ? { managerId } : {}),
                }),
          );
        },
      ).then((created) => afterIdentityChange(ctx, input.tenantId, [created.id], created)),
    /**
     * Creates up to 100 identities atomically with optional attributes, roles, and groups (bulk onboarding). Roles and
     * groups are authorized once like invitations: `iam:bindings:create` on each role under the caller's grant
     * authority and `iam:groups:update` on each group; attributes need iam:identities:update on the tenant. One failure
     * rejects the whole batch.
     */
    createMany: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        identities: Array<{
          email: string;
          name: string;
          password?: string;
          attributes?: Record<string, Json>;
          roleIds?: string[];
          groupIds?: string[];
          expiresAt?: number;
        }>;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:create',
        input.tenantId,
        async ({ tx, principal, tenant: realm }) => {
          if (
            !Array.isArray(input.identities) ||
            input.identities.length === 0 ||
            input.identities.length > 100
          )
            throw new IamError('INVALID_INPUT', 'Provide 1-100 identities');
          if (realm.status !== 'active')
            throw new IamError('TENANT_INACTIVE', 'Tenant must be active');
          const items = input.identities.map((item) => {
            const value = object(item);
            return {
              email: email(value.email),
              name: text(value.name, 'name'),
              password: value.password as string | undefined,
              attributes: attributeValues(catalog.identityAttributes, value.attributes),
              roleIds: [...new Set(strings(value.roleIds ?? [], 'roleIds'))],
              groupIds: [...new Set(strings(value.groupIds ?? [], 'groupIds'))],
              expiresAt:
                value.expiresAt !== undefined ? ctx.bindingExpiry(value.expiresAt) : undefined,
            };
          });
          if (items.some((item) => Object.keys(item.attributes).length))
            await assertMaySetProfile(ctx, tx, principal, realm.id);
          const roleIds = new Set(items.flatMap((item) => item.roleIds));
          const groupIds = new Set(items.flatMap((item) => item.groupIds));
          const authority = roleIds.size
            ? await ctx.grantingAuthority(tx, principal, realm.id)
            : undefined;
          for (const roleId of roleIds) {
            const role = await ctx.scoped<Role>(tx, 'roles', roleId, realm.id);
            if (role.protected)
              throw new IamError(
                'PROTECTED_RESOURCE',
                'Use owner transfer for protected roles',
                403,
              );
            if (
              !(
                await ctx.decisions.decide(
                  tx,
                  principal,
                  {
                    tenantId: realm.id,
                    action: 'iam:bindings:create',
                    resource: { type: 'iam', id: role.id },
                  },
                  true,
                )
              ).allowed
            )
              throw new IamError('ACCESS_DENIED', 'Cannot grant this role', 403);
          }
          for (const groupId of groupIds) {
            assertNotTeamGroup(await ctx.scoped<Group>(tx, 'groups', groupId, realm.id));
            if (
              !(
                await ctx.decisions.decide(
                  tx,
                  principal,
                  {
                    tenantId: realm.id,
                    action: 'iam:groups:update',
                    resource: { type: 'iam', id: groupId },
                  },
                  true,
                )
              ).allowed
            )
              throw new IamError('ACCESS_DENIED', 'Cannot add members to this group', 403);
            for (const binding of await tx.find<Binding>('bindings', {
              tenantId: realm.id,
              subjectType: 'group',
              subjectId: groupId,
            }))
              await ctx.grantingAuthority(tx, principal, realm.id, binding.authorityId);
          }
          const created: PublicIdentity[] = [];
          for (const item of items) {
            let identity = await auth.createIdentity(tx, {
              tenantId: realm.id,
              email: item.email,
              name: item.name,
              password: item.password,
            });
            if (Object.keys(item.attributes).length || item.expiresAt !== undefined)
              identity = await tx.put('identities', {
                ...identity,
                ...(Object.keys(item.attributes).length ? { attributes: item.attributes } : {}),
                ...(item.expiresAt !== undefined ? { expiresAt: item.expiresAt } : {}),
              });
            for (const roleId of item.roleIds)
              await tx.insert<Binding>('bindings', {
                id: id(),
                tenantId: realm.id,
                uniqueKey: `identity:${identity.id}:${roleId}:${authority!.id}`,
                subjectType: 'identity',
                subjectId: identity.id,
                roleId,
                authorityId: authority!.id,
              });
            for (const groupId of item.groupIds)
              await tx.insert<GroupMember>('groupMembers', {
                id: id(),
                tenantId: realm.id,
                uniqueKey: `${groupId}:${identity.id}`,
                groupId,
                identityId: identity.id,
              });
            created.push(publicIdentity(identity));
          }
          return { identities: created };
        },
      ).then((result) =>
        afterIdentityChange(
          ctx,
          input.tenantId,
          result.identities.map((identity) => identity.id),
          result,
        ),
      ),
    /**
     * Deleted identities are omitted unless includeDeleted is set; kind and status narrow the list. `query` matches
     * the name or email case-insensitively; `expiresBefore` keeps identities scheduled to deactivate before that time
     * (expiry reports); `limit`/`offset` page through the result, ordered by name then ID.
     */
    list: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        kind?: Identity['kind'];
        status?: Identity['status'];
        includeDeleted?: boolean;
        query?: string;
        expiresBefore?: number;
        limit?: number;
        offset?: number;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:read',
        input.tenantId,
        async ({ tx }) => {
          const filter: Record<string, unknown> = { tenantId: input.tenantId };
          if (input.kind !== undefined) {
            if (!['user', 'service', 'agent'].includes(input.kind))
              throw new IamError('INVALID_INPUT', 'Invalid identity kind');
            filter.kind = input.kind;
          }
          if (input.status !== undefined) {
            if (!['active', 'disabled', 'deleted'].includes(input.status))
              throw new IamError('INVALID_INPUT', 'Invalid identity status');
            filter.status = input.status;
          }
          const query =
            input.query !== undefined ? text(input.query, 'query', 256).toLowerCase() : undefined;
          const expiresBefore =
            input.expiresBefore !== undefined
              ? integer(input.expiresBefore, 'expiresBefore', 0, Number.MAX_SAFE_INTEGER)
              : undefined;
          const limit =
            input.limit !== undefined ? integer(input.limit, 'limit', 1, 1000) : undefined;
          const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
          const matches = (await tx.find<Identity>('identities', filter))
            .filter(
              (identity) =>
                (input.includeDeleted === true ||
                  input.status === 'deleted' ||
                  identity.status !== 'deleted') &&
                (query === undefined ||
                  identity.name.toLowerCase().includes(query) ||
                  (identity.email?.toLowerCase().includes(query) ?? false)) &&
                (expiresBefore === undefined ||
                  (typeof identity.expiresAt === 'number' && identity.expiresAt <= expiresBefore)),
            )
            .sort(
              (a, b) =>
                a.name.localeCompare(b.name, 'en') || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
            )
            .map(publicIdentity);
          return limit === undefined
            ? matches.slice(offset)
            : matches.slice(offset, offset + limit);
        },
      ),
    /** Sessions of one identity for administrators (device lists, support); token hashes are never returned. */
    listSessions: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:read',
        input.identityId,
        async ({ tx }) => {
          await ctx.scoped<Identity>(tx, 'identities', input.identityId, input.tenantId);
          return (
            await tx.find<Session>('sessions', {
              tenantId: input.tenantId,
              identityId: input.identityId,
            })
          )
            .filter((session) => session.expiresAt > ctx.now())
            .sort((a, b) => b.lastSeenAt - a.lastSeenAt || (a.id < b.id ? -1 : 1))
            .map(({ tokenHash: _hash, uniqueKey: _key, ...safe }) => safe);
        },
      ),
    get: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:read',
        input.identityId,
        async ({ tx }) =>
          publicIdentity(
            await ctx.scoped<Identity>(tx, 'identities', input.identityId, input.tenantId),
          ),
      ),
    /**
     * Data-subject export: everything this tenant stores about one identity, as JSON. Requires recent authentication
     * and iam:identities:read on the identity. Audit events the identity performed are included only when the caller
     * also holds iam:audit:read (newest first, at most 5000). Secrets, hashes, and tokens are never included.
     */
    export: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:read',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const { tenantId } = input;
          const identity = await ctx.scoped<Identity>(tx, 'identities', input.identityId, tenantId);
          const groups: Group[] = [];
          for (const membership of await tx.find<GroupMember>('groupMembers', {
            tenantId,
            identityId: identity.id,
          })) {
            const group = await tx.get<Group>('groups', membership.groupId);
            if (group && group.tenantId === tenantId) groups.push(group);
          }
          const links = [
            ...(await tx.find<IdentityLink>('identityLinks', { leftId: identity.id })),
            ...(await tx.find<IdentityLink>('identityLinks', { rightId: identity.id })),
          ].map((link) => ({
            id: link.id,
            linkedIdentityId: link.leftId === identity.id ? link.rightId : link.leftId,
            revoked: link.revoked,
          }));
          const auditAllowed = (
            await ctx.decisions.decide(
              tx,
              principal,
              { tenantId, action: 'iam:audit:read', resource: { type: 'iam', id: tenantId } },
              true,
            )
          ).allowed;
          const audit = auditAllowed
            ? (await tx.find<AuditEvent>('audit', { tenantId, actorId: identity.id }))
                .sort((a, b) => b.timestamp - a.timestamp || (a.id < b.id ? -1 : 1))
                .slice(0, 5000)
            : undefined;
          await ctx.events.audit(
            tx,
            principal,
            'identity:export',
            tenantId,
            identity.id,
            'allow',
            false,
            {
              kind: identity.kind,
              auditIncluded: auditAllowed,
            },
          );
          return {
            exportedAt: ctx.now(),
            tenantId,
            identity: publicIdentity(identity),
            sessions: (
              await tx.find<Session>('sessions', { tenantId, identityId: identity.id })
            ).map(({ tokenHash: _hash, uniqueKey: _key, ...safe }) => safe),
            mfa: { enabled: Boolean((await tx.get('authMfa', identity.id))?.enabled) },
            passkeys: (await tx.find('authPasskeys', { tenantId, identityId: identity.id })).map(
              (key) => ({
                id: key.id,
                credentialId: key.credentialId,
                transports: key.transports,
              }),
            ),
            externalIdentities: (
              await tx.find('externalIdentities', { tenantId, identityId: identity.id })
            ).map((mapping) => ({
              providerId: mapping.providerId,
              issuer: mapping.issuer,
              subject: mapping.subject,
            })),
            bindings: await ctx.decisions.effectiveBindings(tx, tenantId, identity.id),
            groups,
            relationships: await tx.find<Relationship>('relationships', {
              tenantId,
              subjectType: 'identity',
              subjectId: identity.id,
            }),
            accessRequests: await tx.find<AccessRequest>('accessRequests', {
              tenantId,
              requesterId: identity.id,
            }),
            boundaries: (
              await tx.find<PrincipalBoundary>('principalBoundaries', {
                tenantId,
                identityId: identity.id,
              })
            ).map((boundary) => boundary.document),
            grantAuthorities: (
              await tx.find<GrantAuthority>('grantAuthorities', {
                tenantId,
                identityId: identity.id,
              })
            ).map(({ id, revoked, parentAuthorityId }) => ({ id, revoked, parentAuthorityId })),
            links,
            scim: (await tx.find('scimUsers', { tenantId, identityId: identity.id })).map(
              (row) => ({
                connectionId: row.connectionId,
                externalId: row.externalId,
                userName: row.userName,
                active: row.active,
              }),
            ),
            auditIncluded: auditAllowed,
            audit,
          };
        },
      ),
    /**
     * Unlocks an account: clears the sign-in, recovery, and MFA rate-limit counters for the identity's email, phone,
     * and ID. Requires recent authentication and iam:identities:update; custom limiters without `reset` report
     * `supported: false`.
     */
    unlock: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:update',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const identity = await ctx.activeIdentity(tx, input.identityId, input.tenantId);
          const result = await auth.resetRateLimits(identity);
          await ctx.events.audit(
            tx,
            principal,
            'identity:unlock',
            input.tenantId,
            identity.id,
            'allow',
            false,
            { supported: result.supported, cleared: result.cleared },
          );
          return result;
        },
      ),
    /**
     * Opens a session as a member ("view as") for support and troubleshooting. Requires recent authentication,
     * iam:identities:impersonate on the member, and the tenant's `allowImpersonation` policy. The member must be an
     * active person who is neither the caller, an owner, nor a root administrator. The session lasts at most
     * `durationMs` (one minute to eight hours, one hour by default), never outlives the caller's own session, cannot
     * perform operations that need recent authentication, assume roles, or grant OAuth consent, and every audit
     * record it produces carries `impersonatorId`. Policies see `principal.impersonated` and
     * `principal.impersonatorId`. Audited as `identity:impersonate` with the reason; the token is returned in the
     * body only, never as a cookie.
     */
    impersonate: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; reason: string; durationMs?: number },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:impersonate',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const reason = text(input.reason, 'reason', 512);
          const durationMs = integer(
            input.durationMs ?? 3_600_000,
            'durationMs',
            60_000,
            8 * 3_600_000,
          );
          const identity = await ctx.activeIdentity(tx, input.identityId, input.tenantId);
          if (identity.id === principal.identity.id)
            throw new IamError('INVALID_INPUT', 'You cannot impersonate yourself');
          if (identity.kind !== 'user')
            throw new IamError('INVALID_INPUT', 'Only people can be impersonated');
          if (identity.rootAdmin || identity.owner)
            throw new IamError(
              'ACCESS_DENIED',
              'Owners and root administrators cannot be impersonated',
              403,
            );
          const result = await auth.issueImpersonationSession(tx, principal, identity, durationMs);
          await ctx.events.audit(
            tx,
            principal,
            'identity:impersonate',
            input.tenantId,
            identity.id,
            'allow',
            false,
            { reason, sessionId: result.session.id, expiresAt: result.session.expiresAt },
          );
          const { tokenHash: _hash, uniqueKey: _key, ...session } = result.session;
          return { token: result.token, session, identity: publicIdentity(identity) };
        },
      ),
    /**
     * Queues a password-reset email for a member on an administrator's behalf (support, onboarding without a
     * password). Requires recent authentication and iam:identities:update; audited as `identity:password-reset`.
     */
    requestPasswordReset: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:update',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const identity = await ctx.activeIdentity(tx, input.identityId, input.tenantId);
          await assertAccountControl(ctx, tx, principal, identity);
          await auth.issuePasswordReset(tx, identity);
          await ctx.events.audit(
            tx,
            principal,
            'identity:password-reset',
            input.tenantId,
            identity.id,
            'allow',
          );
          return { queued: true, email: identity.email };
        },
      ),
    /**
     * Ends every session of an identity without disabling it (incident response, lost device). Requires recent
     * authentication. By default API keys are deleted too; with `keepApiKeys: true` every other credential (user,
     * role and session-token sessions, including role sessions it assumed elsewhere and session tokens minted from
     * its keys), its remembered devices and pending challenges end while the API keys stay valid. Audited as
     * `identity:revoke-sessions` with `{ revoked, keptApiKeys }`.
     */
    revokeSessions: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; keepApiKeys?: boolean },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:update',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          if (input.keepApiKeys !== undefined && typeof input.keepApiKeys !== 'boolean')
            throw new IamError('INVALID_INPUT', 'keepApiKeys must be a boolean');
          const keepApiKeys = input.keepApiKeys === true;
          const identity = await ctx.scoped<Identity>(
            tx,
            'identities',
            input.identityId,
            input.tenantId,
          );
          if (identity.rootAdmin && !(await ctx.rootPrincipal(tx, principal)))
            throw new IamError('ACCESS_DENIED', 'Root capability is protected', 403);
          let revoked: number;
          if (!keepApiKeys) {
            revoked = (await tx.find<Session>('sessions', { identityId: identity.id })).length;
            await ctx.revokeAll(tx, identity.id);
          } else {
            // As revokeAll, minus the API keys: sessions by identity (with the impersonations opened through
            // them), remembered devices, challenges, then role sessions the identity assumed in other tenants.
            revoked = 0;
            for (const session of await tx.find<Session>('sessions', { identityId: identity.id })) {
              if (session.kind === 'api-key') continue;
              await auth.endSession(tx, session.id);
              revoked++;
            }
            for (const device of await tx.find('authDevices', { identityId: identity.id }))
              await tx.delete('authDevices', device.id);
            for (const challenge of await tx.find('authChallenges', { identityId: identity.id }))
              await tx.delete('authChallenges', challenge.id);
            for (const session of await tx.find<Session>('sessions', {
              originalIdentityId: identity.id,
            }))
              if (session.kind !== 'api-key') await tx.delete('sessions', session.id);
          }
          await ctx.events.audit(
            tx,
            principal,
            'identity:revoke-sessions',
            input.tenantId,
            identity.id,
            'allow',
            false,
            { revoked, keptApiKeys: keepApiKeys },
          );
          return { revoked };
        },
      ),
    /**
     * Offboarding in one transaction: disables the identity, ends every session and key, removes its role
     * bindings (under the caller's authority, like `bindings.delete`), group memberships, activations,
     * relationships, pending access requests and member invitations, revokes the grant authorities it holds, and hands the managed
     * resources it owns to `successorId` (or reports them). Ownership is removed like `setOwner`, which needs an
     * owner or root caller; the last owner and root administrators are protected. The record stays as a disabled
     * identity for retention; `identities.delete` tombstones it later. Requires recent authentication and
     * iam:identities:update; audited as `identity:offboard` with the reason and counts.
     */
    offboard: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; reason: string; successorId?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:update',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const reason = text(input.reason, 'reason', 512);
          const identity = await ctx.activeIdentity(tx, input.identityId, input.tenantId);
          if (identity.id === principal.identity.id)
            throw new IamError('INVALID_INPUT', 'You cannot offboard yourself');
          if (identity.rootAdmin && !(await ctx.rootPrincipal(tx, principal)))
            throw new IamError('ACCESS_DENIED', 'Root capability is protected', 403);
          await ctx.protectLastOwner(tx, identity);
          const successor =
            input.successorId !== undefined
              ? await ctx.activeIdentity(tx, input.successorId, input.tenantId)
              : undefined;
          if (successor && (successor.id === identity.id || successor.status !== 'active'))
            throw new IamError('INVALID_INPUT', 'Successor must be another active identity');
          const { tenantId } = input;
          const counts = {
            sessions: (await tx.find<Session>('sessions', { identityId: identity.id })).length,
            bindings: 0,
            memberships: 0,
            activations: 0,
            packages: 0,
            relationships: 0,
            accessRequests: 0,
            authorities: 0,
            resourcesReassigned: 0,
            resourcesOwned: 0,
            reportsReassigned: 0,
          };
          // Ownership goes first: the protected Owner binding is removed like setOwner(false).
          if (identity.owner) {
            if (!ownsTenant(principal, tenantId) && !(await ctx.rootPrincipal(tx, principal)))
              throw new IamError('ACCESS_DENIED', 'Only an owner can offboard an owner', 403);
            const ownerRole = (
              await tx.find<Role>('roles', { tenantId, uniqueKey: 'system:owner' })
            )[0];
            for (const binding of await tx.find<Binding>('bindings', {
              tenantId,
              subjectType: 'identity',
              subjectId: identity.id,
              roleId: ownerRole?.id ?? '',
            })) {
              await tx.delete('bindings', binding.id);
              counts.bindings++;
            }
          }
          // Activations are counted before the bindings and memberships that would remove them.
          for (const activation of await tx.find('bindingActivations', {
            tenantId,
            identityId: identity.id,
          })) {
            await tx.delete('bindingActivations', activation.id);
            counts.activations++;
          }
          // Package assignments are revoked first, under package ownership: their bindings may come from another
          // administrator's authority, which the generic binding removal below would refuse.
          for (const assignment of await tx.find<PackageAssignment>('packageAssignments', {
            tenantId,
            identityId: identity.id,
          })) {
            const removed = await revokeAssignment(ctx, tx, assignment);
            counts.bindings += removed.bindings;
            counts.memberships += removed.memberships;
            counts.packages++;
          }
          for (const binding of await tx.find<Binding>('bindings', {
            tenantId,
            subjectType: 'identity',
            subjectId: identity.id,
          })) {
            await deleteBinding(ctx, tx, principal, binding);
            counts.bindings++;
          }
          // Teams and departments (teams.ts, departments.ts): team memberships go first, taking the team-managed
          // group memberships with them; departments they head pass to the successor. Reported only when non-zero.
          const teamsLeft = await removeFromAllTeams(tx, tenantId, identity.id, ctx.now());
          const departments = await releaseDepartments(
            tx,
            tenantId,
            identity.id,
            ctx.now(),
            successor?.id,
          );
          const orgCounts = {
            ...(teamsLeft ? { teamsLeft } : {}),
            ...(departments.headsReassigned
              ? { departmentsReassigned: departments.headsReassigned }
              : {}),
          };
          for (const membership of await tx.find<GroupMember>('groupMembers', {
            tenantId,
            identityId: identity.id,
          })) {
            await removeGroupMember(ctx, tx, principal, {
              tenantId,
              groupId: membership.groupId,
              identityId: identity.id,
            });
            counts.memberships++;
          }
          for (const tuple of await tx.find<Relationship>('relationships', {
            tenantId,
            subjectType: 'identity',
            subjectId: identity.id,
          })) {
            await tx.delete('relationships', tuple.id);
            counts.relationships++;
          }
          for (const request of await tx.find<AccessRequest>('accessRequests', {
            tenantId,
            requesterId: identity.id,
            status: 'pending',
          })) {
            await tx.put('accessRequests', {
              ...request,
              status: 'cancelled',
              reviewedAt: ctx.now(),
            });
            counts.accessRequests++;
          }
          for (const request of await tx.find('packageRequests', {
            tenantId,
            identityId: identity.id,
            status: 'pending',
          })) {
            await tx.put('packageRequests', {
              ...request,
              status: 'cancelled',
              decidedAt: ctx.now(),
            });
            counts.accessRequests++;
          }
          for (const authority of await tx.find<GrantAuthority>('grantAuthorities', {
            tenantId,
            identityId: identity.id,
          }))
            if (!authority.revoked) {
              await tx.put('grantAuthorities', { ...authority, revoked: true });
              counts.authorities++;
            }
          // Their reports move to the successor, or are left without a manager. The successor, if one of them, moves
          // up to the leaver's own manager; a report above the successor in the same line would close a cycle and is
          // left without a manager instead.
          const successorLine = new Set<string>();
          for (
            let cursor: Identity | undefined = successor, depth = 0;
            cursor?.managerId && depth < 100;
            depth++
          ) {
            successorLine.add(cursor.managerId);
            cursor = await tx.get<Identity>('identities', cursor.managerId);
          }
          for (const report of await tx.find<Identity>('identities', {
            tenantId,
            managerId: identity.id,
          })) {
            if (report.status === 'deleted') continue;
            const { managerId: _previous, ...rest } = report;
            const managerId =
              successor && report.id === successor.id
                ? identity.managerId !== undefined && identity.managerId !== report.id
                  ? identity.managerId
                  : undefined
                : successor && !successorLine.has(report.id)
                  ? successor.id
                  : undefined;
            await tx.put<Identity>(
              'identities',
              managerId !== undefined ? { ...rest, managerId } : rest,
            );
            counts.reportsReassigned++;
          }
          for (const resource of await tx.find<ResourceRecord>('resources', {
            tenantId,
            ownerId: identity.id,
          })) {
            if (successor) {
              await tx.put('resources', {
                ...resource,
                ownerId: successor.id,
                updatedAt: ctx.now(),
              });
              counts.resourcesReassigned++;
            } else counts.resourcesOwned++;
          }
          // AI agents (agents.ts): the agents they sponsor move to the successor, and every delegation they gave (or,
          // for an agent, hold) ends. Reported only when there was something to do, so other results keep their shape.
          const handover = await handOverAgents(ctx, tx, principal, identity, successor);
          const delegationsRevoked = await revokeDelegationsOf(
            ctx,
            tx,
            identity,
            principal.identity.id,
          );
          const agentCounts = {
            ...(handover.reassigned ? { agentsReassigned: handover.reassigned } : {}),
            ...(handover.unsponsored ? { agentsUnsponsored: handover.unsponsored } : {}),
            ...(delegationsRevoked ? { delegationsRevoked } : {}),
          };
          await ctx.revokeAll(tx, identity.id);
          await revokeInvitationsBy(tx, identity.id);
          const disabled = await tx.put<Identity>('identities', {
            ...identity,
            status: 'disabled',
            owner: false,
          });
          // An offboarded identity stays disabled: a threats containment of it can no longer be released.
          await endContainment(tx, identity.id, ctx.now());
          await ctx.events.audit(
            tx,
            principal,
            'identity:offboard',
            tenantId,
            identity.id,
            'allow',
            false,
            {
              reason,
              kind: identity.kind,
              ...(successor ? { successorId: successor.id } : {}),
              ...counts,
              ...agentCounts,
              ...orgCounts,
            },
          );
          return { identity: publicIdentity(disabled), ...counts, ...agentCounts, ...orgCounts };
        },
      ),
    /**
     * Renames an identity, replaces its declared attributes (validated against `permissions.identityAttributes`),
     * changes its email, or schedules/clears its deactivation (`expiresAt`, null to clear). An email change requires
     * recent authentication, marks the address unverified, revokes the identity's sessions, and is audited as
     * `identity:email-change`. Changing the expiry of an owner or root administrator needs the same protection as
     * disabling them (an owner or root caller), the last owner without an expiry cannot be given one, and shortening
     * it to the past is refused (disable the identity instead). Changing your own attributes, manager, or expiry needs
     * an owner or root caller.
     */
    update: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        identityId: string;
        name?: string;
        attributes?: Record<string, Json>;
        email?: string;
        expiresAt?: number | null;
        /** The person's manager; null clears it. */
        managerId?: string | null;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:update',
        input.identityId,
        async ({ tx, principal }) => {
          const identity = await ctx.activeIdentity(tx, input.identityId, input.tenantId);
          if (
            input.name === undefined &&
            input.attributes === undefined &&
            input.email === undefined &&
            input.expiresAt === undefined &&
            input.managerId === undefined
          )
            throw new IamError('INVALID_INPUT', 'Nothing to update');
          const next: Identity = { ...identity };
          if (input.name !== undefined) next.name = text(input.name, 'name');
          if (input.attributes !== undefined)
            next.attributes = attributeValues(catalog.identityAttributes, input.attributes);
          if (input.expiresAt !== undefined) {
            if (identity.rootAdmin && !(await ctx.rootPrincipal(tx, principal)))
              throw new IamError('ACCESS_DENIED', 'Root capability is protected', 403);
            await assertOwnerControl(
              ctx,
              tx,
              principal,
              identity,
              'Only an owner can change an owner’s expiry',
            );
            if (input.expiresAt === null) delete next.expiresAt;
            else {
              if (identity.owner) {
                await ctx.protectLastOwner(tx, identity);
                // An owner past their expiry is locked out like a disabled one: the last owner without an expiry
                // keeps none, or every owner could be scheduled away with nobody left to undo it.
                if (
                  typeof identity.expiresAt !== 'number' &&
                  !(
                    await tx.find<Identity>('identities', {
                      tenantId: identity.tenantId,
                      owner: true,
                      status: 'active',
                    })
                  ).some((other) => other.id !== identity.id && typeof other.expiresAt !== 'number')
                )
                  throw new IamError(
                    'LAST_OWNER',
                    'The last owner without an expiry cannot be given one',
                    409,
                  );
              }
              next.expiresAt = ctx.bindingExpiry(input.expiresAt);
            }
          }
          if (input.managerId === null) delete next.managerId;
          else if (input.managerId !== undefined && input.managerId !== identity.managerId)
            next.managerId = await managerFor(ctx, tx, identity, input.managerId);
          // Attributes, the reporting line and the expiry feed birthright package rules and policy conditions, so
          // changing your own would grant you access: only an owner of the tenant or root may. Re-sending the current
          // values is not a change.
          if (
            identity.id === principal.identity.id &&
            (!sameAttributes(next.attributes, identity.attributes) ||
              next.managerId !== identity.managerId ||
              next.expiresAt !== identity.expiresAt) &&
            !ownsTenant(principal, input.tenantId) &&
            !(await ctx.rootPrincipal(tx, principal))
          )
            throw new OperationDenied(
              'Your own attributes, manager and expiry are changed by another administrator',
            );
          let previousEmail: string | undefined;
          if (input.email !== undefined) {
            auth.requireRecent(principal);
            if (identity.kind !== 'user')
              throw new IamError('INVALID_INPUT', 'Service accounts have no email');
            const address = email(input.email);
            if (address !== identity.email) {
              await assertAccountControl(ctx, tx, principal, identity);
              if (
                (
                  await tx.find<Identity>('identities', {
                    tenantId: input.tenantId,
                    email: address,
                  })
                ).some((other) => other.id !== identity.id)
              )
                throw new IamError(
                  'IDENTITY_EXISTS',
                  'Email is already in use in this tenant',
                  409,
                );
              previousEmail = identity.email;
              next.email = address;
              next.uniqueKey = `email:${address}`;
              next.emailVerified = false;
            }
          }
          const updated = await tx.put('identities', next);
          if (previousEmail !== undefined || (input.email !== undefined && !identity.email)) {
            await ctx.revokeAll(tx, identity.id);
            await ctx.events.audit(
              tx,
              principal,
              'identity:email-change',
              input.tenantId,
              identity.id,
              'allow',
              false,
              { from: previousEmail ?? null, to: updated.email ?? null },
            );
          }
          return publicIdentity(updated);
        },
      ).then((updated) => afterIdentityChange(ctx, input.tenantId, [updated.id], updated)),
    /** Removes a person or service account. Requires recent authentication and iam:identities:delete; the last owner and last root administrator are protected. */
    delete: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:delete',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const identity = await ctx.scoped<Identity>(
            tx,
            'identities',
            input.identityId,
            input.tenantId,
          );
          const result = await deleteIdentity(ctx, tx, principal, identity);
          await ctx.events.audit(
            tx,
            principal,
            'identity:delete',
            input.tenantId,
            identity.id,
            'allow',
            false,
            { kind: identity.kind, ...(identity.email ? { email: identity.email } : {}) },
          );
          return result;
        },
      ),
    /** The active identities that report to this one (`managerId`), by name. Requires iam:identities:read. */
    listReports: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:read',
        input.identityId,
        async ({ tx }) => {
          await ctx.scoped(tx, 'identities', input.identityId, input.tenantId);
          return (
            await tx.find<Identity>('identities', {
              tenantId: input.tenantId,
              managerId: input.identityId,
            })
          )
            .filter((report) => report.status === 'active')
            .sort((a, b) => a.name.localeCompare(b.name, 'en') || (a.id < b.id ? -1 : 1))
            .map(publicIdentity);
        },
      ),
    /** Current groups of an identity (expired memberships omitted), each with `membershipExpiresAt` when temporary. */
    listGroups: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(credential, input.tenantId, 'iam:groups:read', input.identityId, async ({ tx }) => {
        await ctx.scoped(tx, 'identities', input.identityId, input.tenantId);
        const groups: Array<Group & { membershipExpiresAt?: number }> = [];
        for (const membership of await tx.find<GroupMember>('groupMembers', {
          tenantId: input.tenantId,
          identityId: input.identityId,
        })) {
          if (!ctx.liveMembership(membership)) continue;
          const group = await tx.get<Group>('groups', membership.groupId);
          if (group && group.tenantId === input.tenantId)
            groups.push({
              ...group,
              ...(membership.expiresAt !== undefined
                ? { membershipExpiresAt: membership.expiresAt }
                : {}),
            });
        }
        return groups;
      }),
    /** Direct and group-derived role bindings: the effective role set of an identity. */
    listBindings: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:bindings:read',
        input.identityId,
        async ({ tx }) => {
          await ctx.scoped(tx, 'identities', input.identityId, input.tenantId);
          return ctx.decisions.effectiveBindings(tx, input.tenantId, input.identityId);
        },
      ),
    /** Invites a person into an existing tenant. Roles and groups are applied when the invitation is accepted, under the inviter's authority. */
    invite: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        email: string;
        name?: string;
        roleIds?: string[];
        groupIds?: string[];
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:create',
        input.tenantId,
        async ({ tx, principal, tenant: realm }) => {
          if (!options.authentication?.sendEmail)
            throw new IamError(
              'DELIVERY_REQUIRED',
              'Member invitations require an email delivery callback',
            );
          if (realm.status !== 'active')
            throw new IamError('TENANT_INACTIVE', 'Tenant must be active');
          const to = email(input.email);
          if ((await tx.find<Identity>('identities', { tenantId: realm.id, email: to })).length)
            throw new IamError(
              'IDENTITY_EXISTS',
              'An identity with this email already exists in this tenant',
              409,
            );
          const roleIds = strings(input.roleIds ?? [], 'roleIds');
          const groupIds = strings(input.groupIds ?? [], 'groupIds');
          const authorityId =
            roleIds.length || groupIds.length
              ? (await ctx.grantingAuthority(tx, principal, realm.id)).id
              : undefined;
          for (const roleId of roleIds) {
            const role = await ctx.scoped<Role>(tx, 'roles', roleId, realm.id);
            if (role.protected)
              throw new IamError(
                'PROTECTED_RESOURCE',
                'Use owner transfer for protected roles',
                403,
              );
            if (
              !(
                await ctx.decisions.decide(
                  tx,
                  principal,
                  {
                    tenantId: realm.id,
                    action: 'iam:bindings:create',
                    resource: { type: 'iam', id: role.id },
                  },
                  true,
                )
              ).allowed
            )
              throw new IamError('ACCESS_DENIED', 'Cannot grant this role', 403);
          }
          for (const groupId of groupIds) {
            assertNotTeamGroup(await ctx.scoped<Group>(tx, 'groups', groupId, realm.id));
            if (
              !(
                await ctx.decisions.decide(
                  tx,
                  principal,
                  {
                    tenantId: realm.id,
                    action: 'iam:groups:update',
                    resource: { type: 'iam', id: groupId },
                  },
                  true,
                )
              ).allowed
            )
              throw new IamError('ACCESS_DENIED', 'Cannot add members to this group', 403);
            for (const binding of await tx.find<Binding>('bindings', {
              tenantId: realm.id,
              subjectType: 'group',
              subjectId: groupId,
            }))
              await ctx.grantingAuthority(tx, principal, realm.id, binding.authorityId);
          }
          const inviteToken = token();
          const now = Date.now();
          const invitation: MemberInvitation = {
            id: id(),
            tenantId: realm.id,
            email: to,
            tokenHash: hash(inviteToken),
            uniqueKey: hash(inviteToken),
            roleIds,
            groupIds,
            inviterId: principal.identity.id,
            createdAt: now,
            expiresAt: now + config.invitationLifetimeMs,
            consumed: false,
          };
          if (input.name !== undefined) invitation.name = text(input.name, 'name');
          if (authorityId !== undefined) invitation.authorityId = authorityId;
          await tx.insert('memberInvitations', invitation);
          const outboxId = id();
          await tx.insert('outbox', {
            id: outboxId,
            tenantId: realm.id,
            kind: 'email',
            to,
            template: 'member-invitation',
            payload: {
              sealed: encryptSecret(
                JSON.stringify({
                  token: inviteToken,
                  tenantId: realm.id,
                  tenantName: realm.name,
                  inviterName: principal.identity.name,
                }),
                options.secret,
                `outbox:${outboxId}`,
              ),
            },
            createdAt: now,
            attempts: 0,
          });
          return {
            invitationId: invitation.id,
            email: to,
            expiresAt: invitation.expiresAt,
            roleIds,
            groupIds,
          };
        },
      ),
    listInvitations: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:identities:read', input.tenantId, async ({ tx }) =>
        (await tx.find<MemberInvitation>('memberInvitations', { tenantId: input.tenantId })).map(
          ({ tokenHash: _hash, uniqueKey: _key, ...safe }) => safe,
        ),
      ),
    revokeInvitation: (
      credential: CredentialInput,
      input: { tenantId: string; invitationId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:update',
        input.invitationId,
        async ({ tx }) => {
          const invitation = await ctx.scoped<MemberInvitation>(
            tx,
            'memberInvitations',
            input.invitationId,
            input.tenantId,
          );
          if (invitation.consumed || invitation.revoked)
            throw new IamError('CONFLICT', 'Invitation is already consumed or revoked', 409);
          const {
            tokenHash: _hash,
            uniqueKey: _key,
            ...safe
          } = await tx.put('memberInvitations', { ...invitation, revoked: true });
          return safe;
        },
      ),
    /** Re-sends a member invitation with a fresh token and lifetime; the earlier token stops working. */
    resendInvitation: (
      credential: CredentialInput,
      input: { tenantId: string; invitationId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:update',
        input.invitationId,
        async ({ tx, principal, tenant: realm }) => {
          if (!options.authentication?.sendEmail)
            throw new IamError(
              'DELIVERY_REQUIRED',
              'Member invitations require an email delivery callback',
            );
          if (realm.status !== 'active')
            throw new IamError('TENANT_INACTIVE', 'Tenant must be active');
          const invitation = await ctx.scoped<MemberInvitation>(
            tx,
            'memberInvitations',
            input.invitationId,
            input.tenantId,
          );
          if (invitation.consumed || invitation.revoked)
            throw new IamError('CONFLICT', 'Invitation is already consumed or revoked', 409);
          const inviteToken = token();
          const now = Date.now();
          const renewed = await tx.put('memberInvitations', {
            ...invitation,
            tokenHash: hash(inviteToken),
            uniqueKey: hash(inviteToken),
            expiresAt: now + config.invitationLifetimeMs,
          });
          const outboxId = id();
          await tx.insert('outbox', {
            id: outboxId,
            tenantId: realm.id,
            kind: 'email',
            to: invitation.email,
            template: 'member-invitation',
            payload: {
              sealed: encryptSecret(
                JSON.stringify({
                  token: inviteToken,
                  tenantId: realm.id,
                  tenantName: realm.name,
                  inviterName: principal.identity.name,
                }),
                options.secret,
                `outbox:${outboxId}`,
              ),
            },
            createdAt: now,
            attempts: 0,
          });
          return { invitationId: renewed.id, email: renewed.email, expiresAt: renewed.expiresAt };
        },
      ),
    acceptInvitation: (input: {
      tenantId: string;
      token: string;
      name?: string;
      password: string;
    }) => ctx.flows.acceptMemberInvitation(input),
    /**
     * Disables (ending its sessions, keys and pending invitations) or re-enables an identity. Disabling an owner needs
     * an owner or root caller; agents are stopped and restarted with `agents.suspend` and `agents.resume` instead.
     */
    setStatus: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; status: 'active' | 'disabled' },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:update',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          if (!['active', 'disabled'].includes(input.status))
            throw new IamError('INVALID_INPUT', 'Invalid identity status');
          const identity = await ctx.activeIdentity(tx, input.identityId, input.tenantId);
          // An agent's status follows its own rules (agents.ts): re-enabling it here would lift a suspension that
          // only agents.resume, with its own permission and recent sign-in, may lift.
          if (identity.kind === 'agent')
            throw new IamError(
              'INVALID_INPUT',
              'Use agents.suspend and agents.resume to stop or restart an agent',
            );
          if (identity.rootAdmin && !(await ctx.rootPrincipal(tx, principal)))
            throw new IamError('ACCESS_DENIED', 'Root capability is protected', 403);
          if (input.status === 'disabled') {
            await assertOwnerControl(ctx, tx, principal, identity, 'Only an owner can disable an owner');
            await ctx.protectLastOwner(tx, identity);
          }
          if (input.status === 'active' && ctx.identityExpired(identity))
            throw new IamError(
              'INVALID_TRANSITION',
              'Extend or clear expiresAt before re-enabling an expired identity',
              409,
            );
          const updated = await tx.put('identities', { ...identity, status: input.status });
          // The status is now this call's: a threats containment is over (released here, or held by this disable).
          await endContainment(tx, identity.id, ctx.now());
          if (input.status === 'disabled') {
            await ctx.revokeAll(tx, identity.id);
            await revokeInvitationsBy(tx, identity.id);
          }
          return publicIdentity(updated);
        },
      ).then((updated) => afterIdentityChange(ctx, input.tenantId, [updated.id], updated)),
    /**
     * Ownership transfer: grants or removes the protected Owner role; the last active owner is protected. A former
     * owner's owner grant authority passes to a remaining owner, so what they granted stays and they grant no more.
     */
    setOwner: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; owner: boolean },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:update',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          if (!ownsTenant(principal, input.tenantId) && !(await ctx.rootPrincipal(tx, principal)))
            throw new IamError('ACCESS_DENIED', 'Only an owner can transfer ownership', 403);
          const identity = await ctx.activeIdentity(tx, input.identityId, input.tenantId);
          if (
            identity.kind !== 'user' ||
            identity.status !== 'active' ||
            typeof input.owner !== 'boolean'
          )
            throw new IamError('INVALID_INPUT', 'Invalid owner');
          if (!input.owner) await ctx.protectLastOwner(tx, identity);
          const ownerRole = (
            await tx.find<Role>('roles', { tenantId: input.tenantId, uniqueKey: 'system:owner' })
          )[0];
          if (!ownerRole) throw new IamError('NOT_FOUND', 'Owner role missing', 404);
          if (input.owner && !identity.owner) {
            const parent = await ctx.grantingAuthority(tx, principal, input.tenantId);
            const authority = await tx.insert<GrantAuthority>('grantAuthorities', {
              id: id(),
              tenantId: input.tenantId,
              identityId: identity.id,
              ceiling: all,
              parentAuthorityId: parent.id,
              revoked: false,
            });
            await tx.insert<Binding>('bindings', {
              id: id(),
              tenantId: input.tenantId,
              subjectType: 'identity',
              subjectId: identity.id,
              roleId: ownerRole.id,
              authorityId: authority.id,
            });
          }
          if (!input.owner) {
            // The unlimited grant authority the Owner role came with (from setOwner or the owner invitation) leaves
            // the former owner too. It passes to an owner who stays (the caller, or else the longest-standing other
            // owner) instead of being revoked: revoking it would also end every grant made under it, including the
            // authorities of owners promoted through it.
            const successorId =
              ownsTenant(principal, input.tenantId) && principal.identity.id !== identity.id
                ? principal.identity.id
                : (
                    await tx.find<Identity>('identities', {
                      tenantId: input.tenantId,
                      owner: true,
                      status: 'active',
                    })
                  )
                    .filter((other) => other.id !== identity.id)
                    .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1))[0]?.id;
            for (const binding of await tx.find<Binding>('bindings', {
              tenantId: input.tenantId,
              subjectType: 'identity',
              subjectId: identity.id,
              roleId: ownerRole.id,
            })) {
              await tx.delete('bindings', binding.id);
              const authority = await tx.get<GrantAuthority>('grantAuthorities', binding.authorityId);
              if (authority?.identityId === identity.id && successorId !== undefined)
                await tx.put('grantAuthorities', { ...authority, identityId: successorId });
            }
          }
          return publicIdentity(await tx.put('identities', { ...identity, owner: input.owner }));
        },
      ),
    setBoundary: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; document: PolicyDocument },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:boundaries:update',
        input.identityId,
        async ({ tx, principal }) => {
          await catalog.validate(tx, input.tenantId, input.document);
          await ctx.scoped(tx, 'identities', input.identityId, input.tenantId);
          if (!(await ctx.rootPrincipal(tx, principal)))
            throw new IamError('ACCESS_DENIED', 'Principal ceilings are platform controlled', 403);
          const existing = (
            await tx.find<PrincipalBoundary>('principalBoundaries', {
              tenantId: input.tenantId,
              identityId: input.identityId,
            })
          )[0];
          const record = {
            id: existing?.id ?? id(),
            tenantId: input.tenantId,
            uniqueKey: input.identityId,
            identityId: input.identityId,
            document: input.document,
          };
          return existing
            ? tx.put('principalBoundaries', record)
            : tx.insert('principalBoundaries', record);
        },
      ),
  };
}
