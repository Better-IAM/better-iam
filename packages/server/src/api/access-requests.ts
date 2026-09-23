import { IamError, type CredentialInput, type IamStore } from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type { AccessRequest, AccessRequestStatus, Binding, Role } from '../models.js';
import { actsInOwnRight } from '../session-kinds.js';
import { byNewest, id } from '../utils.js';
import { integer, strings, text } from '../validation.js';

const accessRequestStatuses = new Set<AccessRequestStatus>([
  'pending',
  'approved',
  'denied',
  'cancelled',
  'expired',
]);

export function createAccessRequestsApi(ctx: ServerContext) {
  const { config } = ctx;
  const { operation } = ctx.operations;
  /** A pending request past its lifetime reads as expired even before the purge worker marks it. */
  const effective = (request: AccessRequest): AccessRequest =>
    request.status === 'pending' && request.expiresAt <= ctx.now()
      ? { ...request, status: 'expired' }
      : request;
  async function pending(
    tx: IamStore,
    requestId: string,
    tenantId: string,
  ): Promise<AccessRequest> {
    const request = effective(
      await ctx.scoped<AccessRequest>(tx, 'accessRequests', requestId, tenantId),
    );
    if (request.status !== 'pending')
      throw new IamError('INVALID_TRANSITION', `Request is ${request.status}`, 409);
    return request;
  }
  function statusFilter(
    status: AccessRequestStatus | undefined,
    filter: Record<string, unknown>,
  ): void {
    if (status === undefined) return;
    if (!accessRequestStatuses.has(status)) throw new IamError('INVALID_INPUT', 'Invalid status');
    filter.status = status;
  }
  return {
    /** A member asks for roles, optionally for a limited time. Nothing is granted until a reviewer approves under their own grant authority. */
    create: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        roleIds: string[];
        justification?: string;
        durationSeconds?: number;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:access-requests:create',
        input.tenantId,
        async ({ tx, principal, tenant: realm }) => {
          if (realm.status !== 'active')
            throw new IamError('TENANT_INACTIVE', 'Tenant must be active');
          if (principal.session.tenantId !== realm.id || !actsInOwnRight(principal.session))
            throw new IamError(
              'INVALID_INPUT',
              'Requests are made from an ordinary session of the target tenant',
            );
          const roleIds = [...new Set(strings(input.roleIds, 'roleIds'))];
          if (!roleIds.length || roleIds.length > 20)
            throw new IamError('INVALID_INPUT', 'Request 1-20 roles');
          for (const roleId of roleIds) {
            const role = await ctx.scoped<Role>(tx, 'roles', roleId, realm.id);
            if (role.protected)
              throw new IamError('PROTECTED_RESOURCE', 'Owner roles cannot be requested', 403);
          }
          const open = await tx.find<AccessRequest>('accessRequests', {
            tenantId: realm.id,
            requesterId: principal.identity.id,
            status: 'pending',
          });
          if (open.length >= 20)
            throw new IamError(
              'TOO_MANY_REQUESTS',
              'Resolve pending requests before opening more',
              429,
            );
          if (
            open.some(
              (existing) =>
                existing.expiresAt > ctx.now() &&
                existing.roleIds.length === roleIds.length &&
                existing.roleIds.every((roleId) => roleIds.includes(roleId)),
            )
          )
            throw new IamError('CONFLICT', 'An identical request is already pending', 409);
          const request: AccessRequest = {
            id: id(),
            tenantId: realm.id,
            requesterId: principal.identity.id,
            roleIds,
            status: 'pending',
            createdAt: ctx.now(),
            expiresAt: ctx.now() + config.accessRequestLifetimeMs,
          };
          if (input.justification !== undefined)
            request.justification = text(input.justification, 'justification', 2048);
          if (input.durationSeconds !== undefined)
            request.durationSeconds = integer(
              input.durationSeconds,
              'durationSeconds',
              60,
              config.accessRequestMaxDurationSeconds,
            );
          return tx.insert('accessRequests', request);
        },
      ),
    list: (
      credential: CredentialInput,
      input: { tenantId: string; status?: AccessRequestStatus; requesterId?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:access-requests:read',
        input.tenantId,
        async ({ tx }) => {
          const filter: Record<string, unknown> = { tenantId: input.tenantId };
          statusFilter(input.status, filter);
          if (input.requesterId !== undefined)
            filter.requesterId = text(input.requesterId, 'requesterId');
          return (await tx.find<AccessRequest>('accessRequests', filter))
            .map(effective)
            .sort(byNewest);
        },
      ),
    /** The caller's own requests; needs only the permission to create requests. */
    listMine: (
      credential: CredentialInput,
      input: { tenantId: string; status?: AccessRequestStatus },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:access-requests:create',
        input.tenantId,
        async ({ tx, principal }) => {
          const filter: Record<string, unknown> = {
            tenantId: input.tenantId,
            requesterId: principal.identity.id,
          };
          statusFilter(input.status, filter);
          return (await tx.find<AccessRequest>('accessRequests', filter))
            .map(effective)
            .sort(byNewest);
        },
      ),
    get: (credential: CredentialInput, input: { tenantId: string; requestId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:access-requests:read',
        input.requestId,
        async ({ tx }) =>
          effective(
            await ctx.scoped<AccessRequest>(tx, 'accessRequests', input.requestId, input.tenantId),
          ),
      ),
    /**
     * Approval binds the requested roles under the reviewer's grant authority, exactly as bindings.create would, so a reviewer
     * can never grant more than they could bind directly. durationSeconds overrides the requested duration; the grant expires accordingly.
     */
    approve: (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; durationSeconds?: number; note?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:access-requests:review',
        input.requestId,
        async ({ tx, principal }) => {
          const request = await pending(tx, input.requestId, input.tenantId);
          if (request.requesterId === principal.identity.id)
            throw new IamError(
              'ACCESS_DENIED',
              'A request cannot be approved by its requester',
              403,
            );
          const requester = await ctx.activeIdentity(tx, request.requesterId, input.tenantId);
          if (requester.status !== 'active')
            throw new IamError('INVALID_IDENTITY', 'Requester is not active');
          const duration =
            input.durationSeconds !== undefined
              ? integer(
                  input.durationSeconds,
                  'durationSeconds',
                  60,
                  config.accessRequestMaxDurationSeconds,
                )
              : request.durationSeconds;
          const grantExpiresAt = duration !== undefined ? ctx.now() + duration * 1000 : undefined;
          const authority = await ctx.grantingAuthority(tx, principal, input.tenantId);
          const bindingIds: string[] = [];
          for (const roleId of request.roleIds) {
            const role = await ctx.scoped<Role>(tx, 'roles', roleId, input.tenantId);
            if (role.protected)
              throw new IamError(
                'PROTECTED_RESOURCE',
                'Owner roles cannot be granted this way',
                403,
              );
            if (
              !(
                await ctx.decisions.decide(
                  tx,
                  principal,
                  {
                    tenantId: input.tenantId,
                    action: 'iam:bindings:create',
                    resource: { type: 'iam', id: role.id },
                  },
                  true,
                )
              ).allowed
            )
              throw new IamError('ACCESS_DENIED', `Cannot grant role ${role.name}`, 403);
            const uniqueKey = `identity:${requester.id}:${role.id}:${authority.id}`;
            const existing = (
              await tx.find<Binding>('bindings', { tenantId: input.tenantId, uniqueKey })
            )[0];
            const { expiresAt: _previous, ...base } = existing ?? {
              id: id(),
              tenantId: input.tenantId,
              uniqueKey,
              subjectType: 'identity' as const,
              subjectId: requester.id,
              roleId: role.id,
              authorityId: authority.id,
            };
            const binding: Binding = { ...base, accessRequestId: request.id };
            if (grantExpiresAt !== undefined) binding.expiresAt = grantExpiresAt;
            bindingIds.push(
              (existing ? await tx.put('bindings', binding) : await tx.insert('bindings', binding))
                .id,
            );
          }
          const decided: AccessRequest = {
            ...request,
            status: 'approved',
            reviewerId: principal.identity.id,
            reviewedAt: ctx.now(),
            bindingIds,
          };
          if (grantExpiresAt !== undefined) decided.grantExpiresAt = grantExpiresAt;
          if (input.note !== undefined) decided.note = text(input.note, 'note', 2048);
          await ctx.events.audit(
            tx,
            principal,
            'access-request:approve',
            input.tenantId,
            request.id,
            'allow',
            false,
            {
              requesterId: request.requesterId,
              roleIds: request.roleIds,
              bindingIds,
              ...(grantExpiresAt !== undefined ? { grantExpiresAt } : {}),
            },
          );
          return tx.put('accessRequests', decided);
        },
      ),
    deny: (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; note?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:access-requests:review',
        input.requestId,
        async ({ tx, principal }) => {
          const request = await pending(tx, input.requestId, input.tenantId);
          const decided: AccessRequest = {
            ...request,
            status: 'denied',
            reviewerId: principal.identity.id,
            reviewedAt: ctx.now(),
          };
          if (input.note !== undefined) decided.note = text(input.note, 'note', 2048);
          await ctx.events.audit(
            tx,
            principal,
            'access-request:deny',
            input.tenantId,
            request.id,
            'allow',
            false,
            { requesterId: request.requesterId, roleIds: request.roleIds },
          );
          return tx.put('accessRequests', decided);
        },
      ),
    cancel: (credential: CredentialInput, input: { tenantId: string; requestId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:access-requests:create',
        input.requestId,
        async ({ tx, principal }) => {
          const request = await pending(tx, input.requestId, input.tenantId);
          if (request.requesterId !== principal.identity.id)
            throw new IamError('ACCESS_DENIED', 'Only the requester can cancel a request', 403);
          return tx.put('accessRequests', {
            ...request,
            status: 'cancelled',
            reviewedAt: ctx.now(),
          });
        },
      ),
  };
}
