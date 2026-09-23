import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Tenant,
} from '@better-iam/core';
import { acceptanceCurrent, type Agreement, type AgreementAcceptance } from '../agreements.js';
import type { ServerContext } from '../context.js';
import type { AccessPackage, Binding, BindingActivation, GroupMember, Role } from '../models.js';
import { actsInOwnRight } from '../session-kinds.js';
import { id } from '../utils.js';
import { object, text } from '../validation.js';

/** One way the caller could come to be allowed; each was checked by simulating it. */
export type AccessPath =
  | { kind: 'mfa' }
  | { kind: 'accept-agreements'; agreements: { id: string; name: string; version: number }[] }
  | {
      kind: 'activate';
      bindingId: string;
      role: { id: string; name: string };
      requireApproval: boolean;
      requireJustification: boolean;
      requireMfa: boolean;
      maxActivationMs?: number;
    }
  | {
      kind: 'request-package';
      package: { id: string; name: string; description?: string };
      requireJustification: boolean;
    };
export interface AccessPathsResult {
  allowed: boolean;
  /** The decision reason for the request as it stands. */
  reason: string;
  /** Empty when allowed, or when nothing the caller can do alone would help (ask an administrator). */
  paths: AccessPath[];
}

const maxCandidates = 50;

class Rollback extends Error {
  constructor(readonly result: AccessPathsResult) {
    super('rollback');
  }
}

/**
 * Self-service access paths: when a person is denied, the ways they could become allowed on their own — step up to
 * MFA, accept pending terms of use, activate one of their eligible (just-in-time) bindings, or request a
 * requestable access package — each confirmed by applying it inside a transaction that is always rolled back and
 * re-running the ordinary decision. Needs only an ordinary session of the tenant; activation and package options are
 * listed only when the caller may use them (`iam:bindings:activate`, `iam:packages:request`).
 */
export function createAccessPathsApi(ctx: ServerContext) {
  async function allowed(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    action: string,
    resource: { type: string; id: string },
  ) {
    return ctx.decisions.decide(
      tx,
      principal,
      { tenantId, action, resource },
      action.startsWith('iam:'),
    );
  }
  async function may(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    action: string,
    resourceId: string,
  ) {
    return (
      await ctx.decisions.decide(
        tx,
        principal,
        { tenantId, action, resource: { type: 'iam', id: resourceId } },
        true,
      )
    ).allowed;
  }

  async function paths(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    action: string,
    resource: { type: string; id: string },
  ): Promise<AccessPathsResult> {
    const tenantId = tenant.id;
    const identityId = principal.identity.id;
    const now = ctx.now();
    const check = async (who: AuthenticatedPrincipal = principal) =>
      (await allowed(tx, who, tenantId, action, resource)).allowed;
    const base = await allowed(tx, principal, tenantId, action, resource);
    if (base.allowed) return { allowed: true, reason: base.reason, paths: [] };
    const found: AccessPath[] = [];

    // A second factor.
    if (
      !principal.session.mfa &&
      (await check({ ...principal, session: { ...principal.session, mfa: true } }))
    )
      found.push({ kind: 'mfa' });

    // Required terms of use not yet accepted (simulated as accepted, then removed again).
    const agreements = await tx.find<Agreement>('agreements', { tenantId });
    if (agreements.length && principal.identity.kind === 'user') {
      const acceptances = new Map(
        (await tx.find<AgreementAcceptance>('agreementAcceptances', { tenantId, identityId })).map(
          (acceptance) => [acceptance.agreementId, acceptance],
        ),
      );
      const owed = agreements.filter(
        (agreement) =>
          agreement.required && !acceptanceCurrent(agreement, acceptances.get(agreement.id), now),
      );
      if (owed.length) {
        const written: { id: string; previous?: AgreementAcceptance }[] = [];
        for (const agreement of owed) {
          const acceptanceId = `${agreement.id}:${identityId}`;
          const previous = acceptances.get(agreement.id);
          const record: AgreementAcceptance = {
            id: acceptanceId,
            tenantId,
            agreementId: agreement.id,
            identityId,
            version: agreement.version,
            acceptedAt: now,
          };
          await (previous
            ? tx.put('agreementAcceptances', record)
            : tx.insert('agreementAcceptances', record));
          written.push({ id: acceptanceId, previous });
        }
        if (await check())
          found.push({
            kind: 'accept-agreements',
            agreements: owed.map((agreement) => ({
              id: agreement.id,
              name: agreement.name,
              version: agreement.version,
            })),
          });
        for (const entry of written)
          await (entry.previous
            ? tx.put('agreementAcceptances', entry.previous)
            : tx.delete('agreementAcceptances', entry.id));
      }
    }

    // Eligible bindings the caller holds directly or through a group, simulated as activated.
    const groupIds = new Set(
      (await tx.find<GroupMember>('groupMembers', { tenantId, identityId }))
        .filter((member) => ctx.liveMembership(member))
        .map((member) => member.groupId),
    );
    const eligible = (await tx.find<Binding>('bindings', { tenantId }))
      .filter(
        (binding) =>
          binding.eligible === true &&
          ctx.liveBinding(binding) &&
          (binding.subjectType === 'identity'
            ? binding.subjectId === identityId
            : groupIds.has(binding.subjectId)),
      )
      .slice(0, maxCandidates);
    const activations = new Map(
      (await tx.find<BindingActivation>('bindingActivations', { tenantId, identityId })).map(
        (activation) => [activation.bindingId, activation],
      ),
    );
    for (const binding of eligible) {
      const role = await tx.get<Role>('roles', binding.roleId);
      if (!role) continue;
      const previous = activations.get(binding.id);
      const simulated: BindingActivation = {
        id: previous?.id ?? id(),
        tenantId,
        uniqueKey: `${binding.id}:${identityId}`,
        bindingId: binding.id,
        identityId,
        roleId: binding.roleId,
        activatedAt: now,
        expiresAt: now + 3_600_000,
        sessionId: principal.session.id,
      };
      await (previous
        ? tx.put('bindingActivations', simulated)
        : tx.insert('bindingActivations', simulated));
      // `requireMfa` gates the activation itself, not the grants it brings, so the caller is evaluated as is.
      const helps = await check();
      await (previous
        ? tx.put('bindingActivations', previous)
        : tx.delete('bindingActivations', simulated.id));
      if (helps && (await may(tx, principal, tenantId, 'iam:bindings:activate', binding.roleId)))
        found.push({
          kind: 'activate',
          bindingId: binding.id,
          role: { id: role.id, name: role.name },
          requireApproval: binding.requireApproval === true,
          requireJustification: binding.requireJustification === true,
          requireMfa: binding.requireMfa === true,
          ...(binding.maxActivationMs !== undefined
            ? { maxActivationMs: binding.maxActivationMs }
            : {}),
        });
    }

    // Requestable packages, simulated as assigned (standing bindings under each role's own authority, memberships).
    const packages = (await tx.find<AccessPackage>('accessPackages', { tenantId }))
      .filter((pkg) => pkg.requestable === true)
      .slice(0, maxCandidates);
    for (const pkg of packages) {
      if (!(await may(tx, principal, tenantId, 'iam:packages:request', pkg.id))) continue;
      const created: { collection: string; id: string }[] = [];
      for (const roleId of pkg.roleIds) {
        const role = await tx.get<Role & { authorityId?: string }>('roles', roleId);
        if (!role || typeof role.authorityId !== 'string') continue;
        const bindingId = id();
        await tx.insert<Binding>('bindings', {
          id: bindingId,
          tenantId,
          uniqueKey: `simulation:${bindingId}`,
          subjectType: 'identity',
          subjectId: identityId,
          roleId,
          authorityId: role.authorityId,
        });
        created.push({ collection: 'bindings', id: bindingId });
      }
      for (const groupId of pkg.groupIds) {
        if (groupIds.has(groupId)) continue;
        const memberId = id();
        await tx.insert<GroupMember>('groupMembers', {
          id: memberId,
          tenantId,
          uniqueKey: `simulation:${memberId}`,
          groupId,
          identityId,
        });
        created.push({ collection: 'groupMembers', id: memberId });
      }
      const helps = created.length > 0 && (await check());
      for (const record of created) await tx.delete(record.collection, record.id);
      if (helps)
        found.push({
          kind: 'request-package',
          package: {
            id: pkg.id,
            name: pkg.name,
            ...(pkg.description !== undefined ? { description: pkg.description } : {}),
          },
          requireJustification: pkg.requireJustification === true,
        });
    }
    // Like `authorize`, a denial does not reveal which rule refused it.
    return { allowed: false, reason: 'ACCESS_DENIED', paths: found };
  }

  return {
    /**
     * For an `action` on a `resource` the caller is denied, lists what they could do themselves to be allowed.
     * Nothing is saved. The caller's own ordinary session only (not impersonation, assumed roles or session tokens).
     */
    find: async (
      credential: CredentialInput,
      input: { tenantId: string; action: string; resource: { type: string; id: string } },
    ): Promise<AccessPathsResult> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const action = text(input.action, 'action');
      const reference = object(input.resource);
      const resource = {
        type: text(reference.type, 'resource type'),
        id: text(reference.id, 'resource id'),
      };
      const authenticated = await ctx.principals.authenticate(credential);
      try {
        await ctx.store.transaction(async (tx) => {
          const principal = await ctx.principals.currentPrincipal(tx, authenticated);
          if (
            !actsInOwnRight(principal.session) ||
            principal.session.tenantId !== tenantId ||
            principal.identity.tenantId !== tenantId
          )
            throw new IamError(
              'ACCESS_DENIED',
              'Access paths are for an ordinary session of the tenant',
              403,
            );
          if (principal.session.impersonatorId)
            throw new IamError(
              'IMPERSONATION_RESTRICTED',
              'Access paths are not available while impersonating',
              403,
            );
          if (!(await ctx.catalog.knownAction(tx, tenantId, action)))
            throw new IamError('INVALID_ACTION', `Unknown action ${action}`);
          const tenant = await ctx.tenant(tx, tenantId);
          throw new Rollback(await paths(tx, principal, tenant, action, resource));
        });
      } catch (error) {
        if (error instanceof Rollback) return error.result;
        throw error;
      }
      throw new IamError('INTERNAL_ERROR', 'Access paths did not complete', 500);
    },
  };
}
