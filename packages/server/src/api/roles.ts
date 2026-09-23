import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Session,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type { AccessPackage, Binding, Group, OidcProvider, Role, Trust } from '../models.js';
import { nextWatermark, revokedByWatermark } from '../session-kinds.js';
import {
  deleteTemporarySessions,
  roleSessionSummary,
  type AssumeRoleInput,
  type RoleCredential,
  type RoleSessionSummary,
} from '../temporary-credentials.js';
import { id } from '../utils.js';
import { integer, strings, text } from '../validation.js';

export type BindingSubject = { id: string; name: string; email?: string; kind?: Identity['kind'] };

export interface RoleInput {
  tenantId: string;
  name: string;
  description?: string;
  policyIds?: string[];
  permissions?: string[];
  document?: PolicyDocument;
  /** Roles whose grants this role includes (at most 20, no cycles, no protected roles). */
  inherits?: string[];
}
export interface RoleUpdate {
  tenantId: string;
  roleId: string;
  name?: string;
  description?: string;
  policyIds?: string[];
  permissions?: string[];
  document?: PolicyDocument | null;
  /** Replaces the inherited roles; an empty list clears inheritance. */
  inherits?: string[];
}

/** Validates a role hierarchy edge set: existing, unprotected, distinct roles of the tenant that do not lead back to `roleId`. */
async function inheritance(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  roleId: string | undefined,
  value: unknown,
): Promise<string[]> {
  const inherits = [...new Set(strings(value, 'inherits'))];
  if (inherits.length > 20)
    throw new IamError('INVALID_INPUT', 'A role may inherit at most 20 roles');
  for (const inheritedId of inherits) {
    if (inheritedId === roleId) throw new IamError('INVALID_INPUT', 'A role cannot inherit itself');
    const inherited = await ctx.scoped<Role>(tx, 'roles', inheritedId, tenantId);
    if (inherited.protected)
      throw new IamError('PROTECTED_RESOURCE', 'Protected roles cannot be inherited', 403);
  }
  // Walk the hierarchy from the new parents; reaching this role again would close a cycle.
  if (roleId !== undefined) {
    const queue = [...inherits];
    const visited = new Set<string>();
    while (queue.length) {
      const current = queue.shift()!;
      if (current === roleId)
        throw new IamError('INVALID_INPUT', 'Role inheritance must not form a cycle');
      if (visited.has(current)) continue;
      visited.add(current);
      if (visited.size > 200) throw new IamError('INVALID_INPUT', 'Role hierarchy is too deep');
      const parent = await tx.get<Role>('roles', current);
      queue.push(...(parent?.inherits ?? []));
    }
  }
  return inherits;
}

/** A permissions list compiles to an inline allow statement over every resource; a document is used as given. */
async function roleDocument(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  input: { permissions?: string[]; document?: PolicyDocument | null },
): Promise<PolicyDocument | null | undefined> {
  if (input.permissions !== undefined && input.document !== undefined)
    throw new IamError('INVALID_INPUT', 'Provide either permissions or an inline document');
  if (input.document === null) return null;
  let document = input.document;
  if (input.permissions !== undefined) {
    const permissions = strings(input.permissions, 'permissions');
    if (!permissions.length)
      throw new IamError('INVALID_INPUT', 'permissions must name at least one action');
    document = {
      version: 1,
      statements: [
        { sid: 'RolePermissions', effect: 'allow', actions: permissions, resources: ['*'] },
      ],
    };
  }
  if (document !== undefined) await ctx.catalog.validate(tx, tenantId, document);
  return document;
}

/** Creates a role under the caller's grant authority; shared by `roles.create` and configuration sync. */
export async function createRole(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenant: Tenant,
  input: RoleInput,
): Promise<Role> {
  const authority = await ctx.grantingAuthority(tx, principal, input.tenantId);
  await ctx.enforceLimit(
    tx,
    tenant,
    'roles',
    async () => (await tx.find('roles', { tenantId: input.tenantId })).length,
  );
  const policyIds = strings(input.policyIds ?? [], 'policyIds');
  for (const policyId of policyIds) await ctx.scoped(tx, 'policies', policyId, input.tenantId);
  const document = await roleDocument(ctx, tx, input.tenantId, input);
  const role: Role = {
    id: id(),
    tenantId: input.tenantId,
    name: text(input.name, 'name'),
    policyIds,
    protected: false,
    authorityId: authority.id,
  };
  if (input.description !== undefined)
    role.description = text(input.description, 'description', 512);
  if (document) role.document = document;
  if (input.inherits !== undefined) {
    const inherits = await inheritance(ctx, tx, input.tenantId, undefined, input.inherits);
    if (inherits.length) role.inherits = inherits;
  }
  return tx.insert<Role>('roles', role);
}

/** Edits a role the caller's authority issued (or any role, for root); protected roles are refused. */
export async function updateRole(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  input: RoleUpdate,
): Promise<Role> {
  await ctx.grantingAuthority(tx, principal, input.tenantId);
  const role = await ctx.scoped<Role>(tx, 'roles', input.roleId, input.tenantId);
  if (role.protected) throw new IamError('PROTECTED_RESOURCE', 'Role is protected', 403);
  await ctx.canEditGrantResource(tx, principal, role);
  const next: Role = { ...role };
  if (input.policyIds !== undefined) {
    next.policyIds = strings(input.policyIds, 'policyIds');
    for (const policyId of next.policyIds)
      await ctx.scoped(tx, 'policies', policyId, input.tenantId);
  }
  const document = await roleDocument(ctx, tx, input.tenantId, input);
  if (document === null) delete next.document;
  else if (document) next.document = document;
  if (input.name !== undefined) next.name = text(input.name, 'name');
  if (input.description !== undefined)
    next.description = text(input.description, 'description', 512);
  if (input.inherits !== undefined) {
    const inherits = await inheritance(ctx, tx, input.tenantId, role.id, input.inherits);
    if (inherits.length) next.inherits = inherits;
    else delete next.inherits;
  }
  return tx.put('roles', next);
}

/** Roles that inherit from the given role, directly. */
export async function inheritingRoles(tx: IamStore, role: Role): Promise<Role[]> {
  return (await tx.find<Role>('roles', { tenantId: role.tenantId })).filter((other) =>
    other.inherits?.includes(role.id),
  );
}

/** Deletes a role with its bindings and activations; protected roles are refused. */
export async function deleteRole(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  role: Role,
): Promise<void> {
  if (role.protected) throw new IamError('PROTECTED_RESOURCE', 'Role is protected', 403);
  await ctx.canEditGrantResource(tx, principal, role);
  const children = await inheritingRoles(tx, role);
  if (children.length)
    throw new IamError(
      'RESOURCE_IN_USE',
      `Roles still inherit it: ${children.map((child) => child.name).join(', ')}`,
      409,
    );
  const packaged = (
    await tx.find<AccessPackage>('accessPackages', { tenantId: role.tenantId })
  ).filter((pkg) => pkg.roleIds.includes(role.id));
  if (packaged.length)
    throw new IamError(
      'RESOURCE_IN_USE',
      `Access packages still include it: ${packaged.map((pkg) => pkg.name).join(', ')}`,
      409,
    );
  for (const binding of await tx.find<Binding>('bindings', {
    tenantId: role.tenantId,
    roleId: role.id,
  }))
    await tx.delete('bindings', binding.id);
  for (const activation of await tx.find('bindingActivations', {
    tenantId: role.tenantId,
    roleId: role.id,
  }))
    await tx.delete('bindingActivations', activation.id);
  await tx.delete('roles', role.id);
}

export function createRolesApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  return {
    /** A role carries attached policies, an inline document, or a plain permissions list (an inline allow over every tenant resource). */
    create: (credential: CredentialInput, input: RoleInput) =>
      operation(
        credential,
        input.tenantId,
        'iam:roles:create',
        input.tenantId,
        ({ tx, principal, tenant }) => createRole(ctx, tx, principal, tenant, input),
      ),
    update: (credential: CredentialInput, input: RoleUpdate) =>
      operation(credential, input.tenantId, 'iam:roles:update', input.roleId, ({ tx, principal }) =>
        updateRole(ctx, tx, principal, input),
      ),
    get: (credential: CredentialInput, input: { tenantId: string; roleId: string }) =>
      operation(credential, input.tenantId, 'iam:roles:read', input.roleId, ({ tx }) =>
        ctx.scoped<Role>(tx, 'roles', input.roleId, input.tenantId),
      ),
    /** Who holds a role: live bindings with their identity or group summary. */
    listBindings: (credential: CredentialInput, input: { tenantId: string; roleId: string }) =>
      operation(credential, input.tenantId, 'iam:bindings:read', input.roleId, async ({ tx }) => {
        await ctx.scoped<Role>(tx, 'roles', input.roleId, input.tenantId);
        const result: (Binding & { subject?: BindingSubject })[] = [];
        for (const binding of (
          await tx.find<Binding>('bindings', { tenantId: input.tenantId, roleId: input.roleId })
        ).filter((binding) => !ctx.expiredBinding(binding))) {
          if (binding.subjectType === 'identity') {
            const identity = await tx.get<Identity>('identities', binding.subjectId);
            result.push({
              ...binding,
              subject:
                identity && identity.tenantId === input.tenantId
                  ? {
                      id: identity.id,
                      name: identity.name,
                      email: identity.email,
                      kind: identity.kind,
                    }
                  : undefined,
            });
          } else {
            const group = await tx.get<Group>('groups', binding.subjectId);
            result.push({
              ...binding,
              subject:
                group && group.tenantId === input.tenantId
                  ? { id: group.id, name: group.name }
                  : undefined,
            });
          }
        }
        return result;
      }),
    list: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:roles:read', input.tenantId, ({ tx }) =>
        tx.find<Role>('roles', { tenantId: input.tenantId }),
      ),
    delete: (credential: CredentialInput, input: { tenantId: string; roleId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:roles:delete',
        input.roleId,
        async ({ tx, principal }) => {
          const role = await ctx.scoped<Role>(tx, 'roles', input.roleId, input.tenantId);
          await deleteRole(ctx, tx, principal, role);
          return { deleted: true };
        },
      ),
    /**
     * AssumeRole through an identity trust: a temporary role session (`biam_rol_…`, or a session JWT with
     * `format: 'jwt'`) with an optional session name, source identity and tags the trust admits. See FlowService.
     */
    assume: (credential: CredentialInput, input: AssumeRoleInput): Promise<RoleCredential> =>
      ctx.flows.assumeRole(credential, input),
    /**
     * Revokes the role's sessions (classic and web identity) issued before `before` (default: every session so far):
     * moves the role's `sessionsRevokedBefore` watermark forward, so older sessions are refused on their next use,
     * and deletes the matching rows. Requires iam:roles:revoke-sessions on the role and recent authentication; it
     * only removes access, so it is delegable. Audited as `role:sessions-revoked`.
     */
    revokeSessions: (
      credential: CredentialInput,
      input: { tenantId: string; roleId: string; before?: number },
    ): Promise<{ roleId: string; sessionsRevokedBefore: number; revoked: number }> =>
      operation(
        credential,
        input.tenantId,
        'iam:roles:revoke-sessions',
        input.roleId,
        async ({ tx, principal }) => {
          ctx.auth.requireRecent(principal);
          const role = await ctx.scoped<Role>(tx, 'roles', input.roleId, input.tenantId);
          const sessionsRevokedBefore = nextWatermark(
            role.sessionsRevokedBefore,
            input.before,
            ctx.now(),
          );
          await tx.put<Role>('roles', { ...role, sessionsRevokedBefore });
          const revoked = await deleteTemporarySessions(tx, {
            tenantId: role.tenantId,
            roleId: role.id,
            createdBefore: sessionsRevokedBefore,
          });
          await ctx.events.audit(
            tx,
            principal,
            'role:sessions-revoked',
            input.tenantId,
            role.id,
            'allow',
            false,
            { sessionsRevokedBefore, revoked },
          );
          return { roleId: role.id, sessionsRevokedBefore, revoked };
        },
      ),
    /**
     * Live role sessions in the tenant (of one role or trust when given), newest first, as allowlist summaries that
     * never carry tokens, hashes, policies or authority ids. Expired sessions, sessions under a revoked or missing
     * trust, and sessions below a role, trust or provider watermark are left out. Requires iam:trust:read on the role
     * (or the tenant); `limit` is 1-500 (default 100).
     */
    listSessions: (
      credential: CredentialInput,
      input: { tenantId: string; roleId?: string; trustId?: string; limit?: number },
    ): Promise<RoleSessionSummary[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:trust:read',
        input.roleId ?? input.tenantId,
        async ({ tx }) => {
          const limit = integer(input.limit ?? 100, 'limit', 1, 500);
          if (input.roleId !== undefined)
            await ctx.scoped<Role>(tx, 'roles', text(input.roleId, 'roleId'), input.tenantId);
          const trustId = input.trustId === undefined ? undefined : text(input.trustId, 'trustId');
          const now = ctx.now();
          const rows =
            input.roleId !== undefined
              ? await tx.find<Session>('sessions', { roleId: input.roleId })
              : await tx.find<Session>('sessions', { tenantId: input.tenantId, kind: 'role' });
          // Each trust, role and provider is read once, however many sessions share it.
          const records = new Map<string, Promise<StoredRecord | undefined>>();
          const record = <T extends StoredRecord>(collection: string, recordId: unknown) => {
            if (typeof recordId !== 'string') return Promise.resolve(undefined);
            const key = `${collection}/${recordId}`;
            if (!records.has(key)) records.set(key, tx.get<T>(collection, recordId));
            return records.get(key) as Promise<T | undefined>;
          };
          const live: Session[] = [];
          for (const session of rows) {
            if (
              session.kind !== 'role' ||
              session.tenantId !== input.tenantId ||
              (trustId !== undefined && session.trustId !== trustId) ||
              !(session.expiresAt > now)
            )
              continue;
            const trust = await record<Trust>('trusts', session.trustId);
            const role = await record<Role>('roles', session.roleId);
            const provider = session.webIdentity
              ? await record<OidcProvider>('oidcProviders', session.webIdentity.providerId)
              : undefined;
            if (
              !trust ||
              trust.revoked ||
              trust.tenantId !== input.tenantId ||
              !role ||
              role.tenantId !== input.tenantId ||
              revokedByWatermark(
                session.createdAt,
                trust.sessionsRevokedBefore,
                role.sessionsRevokedBefore,
                provider?.sessionsRevokedBefore,
              )
            )
              continue;
            live.push(session);
          }
          return live
            .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
            .slice(0, limit)
            .map(roleSessionSummary);
        },
      ),
  };
}
