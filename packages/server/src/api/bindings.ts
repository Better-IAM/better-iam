import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
} from '@better-iam/core';
import { activationRules, maxActivationMs } from '../access-policy.js';
import type { ServerContext } from '../context.js';
import type {
  AccessWindow,
  Binding,
  BindingActivation,
  GrantAuthority,
  GroupMember,
  Role,
} from '../models.js';
import { actsInOwnRight } from '../session-kinds.js';
import { id } from '../utils.js';
import { integer, text } from '../validation.js';

/** Eligibility settings accepted when a binding is created or updated. */
export interface EligibilityInput {
  eligible?: boolean;
  maxActivationMs?: number;
  requireJustification?: boolean;
  requireMfa?: boolean;
  /** Activation starts as a request that an approver grants or denies. */
  requireApproval?: boolean;
  /** Group whose members approve requests (and are emailed them); null clears it. */
  approverGroupId?: string | null;
  /** The requester's manager may approve and is emailed each request. */
  managerApproval?: boolean;
}
export interface BindingInput extends EligibilityInput {
  tenantId: string;
  roleId: string;
  subjectType: 'identity' | 'group';
  subjectId: string;
  authorityId?: string;
  /** Future-dated grant: the binding grants nothing before this time. */
  startsAt?: number;
  expiresAt?: number;
  /** Business-hours access: the role applies only inside this recurring window. */
  window?: AccessWindow;
}

const maxActivation = maxActivationMs;

function boolean(value: unknown, name: string): boolean {
  if (typeof value !== 'boolean') throw new IamError('INVALID_INPUT', `${name} must be boolean`);
  return value;
}

/** Applies eligibility settings to a binding; activation options are only meaningful on eligible bindings. */
function applyEligibility(binding: Binding, input: EligibilityInput): void {
  if (input.eligible !== undefined) {
    if (boolean(input.eligible, 'eligible')) binding.eligible = true;
    else {
      delete binding.eligible;
      delete binding.maxActivationMs;
      delete binding.requireJustification;
      delete binding.requireMfa;
      delete binding.requireApproval;
      delete binding.approverGroupId;
      delete binding.managerApproval;
    }
  }
  if (input.requireJustification !== undefined)
    boolean(input.requireJustification, 'requireJustification');
  if (input.requireMfa !== undefined) boolean(input.requireMfa, 'requireMfa');
  if (input.requireApproval !== undefined) boolean(input.requireApproval, 'requireApproval');
  if (input.managerApproval !== undefined) boolean(input.managerApproval, 'managerApproval');
  // Explicit `false` flags are harmless on standing bindings (forms send every checkbox); settings are not.
  const settings =
    input.maxActivationMs !== undefined ||
    input.requireJustification === true ||
    input.requireMfa === true ||
    input.requireApproval === true ||
    input.managerApproval === true ||
    (input.approverGroupId !== undefined && input.approverGroupId !== null);
  if (settings && !binding.eligible)
    throw new IamError('INVALID_INPUT', 'Activation settings apply to eligible bindings only');
  if (!binding.eligible) return;
  if (input.requireApproval !== undefined) {
    if (input.requireApproval) binding.requireApproval = true;
    else delete binding.requireApproval;
  }
  if (input.managerApproval !== undefined) {
    if (input.managerApproval) binding.managerApproval = true;
    else delete binding.managerApproval;
  }
  if (input.maxActivationMs !== undefined)
    binding.maxActivationMs = integer(
      input.maxActivationMs,
      'maxActivationMs',
      60_000,
      maxActivation,
    );
  if (input.requireJustification !== undefined) {
    if (input.requireJustification) binding.requireJustification = true;
    else delete binding.requireJustification;
  }
  if (input.requireMfa !== undefined) {
    if (input.requireMfa) binding.requireMfa = true;
    else delete binding.requireMfa;
  }
}

/**
 * Creates a binding under the caller's grant authority; shared by `bindings.create`, invitations, access packages,
 * and configuration sync. A package assignment's bindings carry `packageAssignmentId` and a key of their own, so
 * they never collide with, replace, or depend on a binding someone granted by hand.
 */
export async function createBinding(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  input: BindingInput,
  options: { packageAssignmentId?: string } = {},
): Promise<Binding> {
  const role = await ctx.scoped<Role>(tx, 'roles', input.roleId, input.tenantId);
  if (role.protected)
    throw new IamError('PROTECTED_RESOURCE', 'Use owner transfer for protected roles', 403);
  if (!['identity', 'group'].includes(input.subjectType))
    throw new IamError('INVALID_INPUT', 'Invalid subject type');
  if (input.subjectType === 'identity')
    await ctx.activeIdentity(tx, input.subjectId, input.tenantId);
  else await ctx.scoped(tx, 'groups', input.subjectId, input.tenantId);
  const authority = await ctx.grantingAuthority(tx, principal, input.tenantId, input.authorityId);
  const binding: Binding = {
    id: id(),
    tenantId: input.tenantId,
    uniqueKey: `${input.subjectType}:${input.subjectId}:${input.roleId}:${authority.id}${options.packageAssignmentId ? `:package:${options.packageAssignmentId}` : ''}`,
    subjectType: input.subjectType,
    subjectId: input.subjectId,
    roleId: input.roleId,
    authorityId: authority.id,
    ...(options.packageAssignmentId ? { packageAssignmentId: options.packageAssignmentId } : {}),
  };
  if (input.expiresAt !== undefined) binding.expiresAt = ctx.bindingExpiry(input.expiresAt);
  if (input.startsAt !== undefined) binding.startsAt = ctx.bindingStart(input.startsAt);
  if (
    binding.startsAt !== undefined &&
    binding.expiresAt !== undefined &&
    binding.startsAt >= binding.expiresAt
  )
    throw new IamError('INVALID_INPUT', 'startsAt must be before expiresAt');
  if (input.window !== undefined) binding.window = ctx.accessWindow(input.window);
  applyEligibility(binding, input);
  await applyApprovers(ctx, tx, binding, input);
  return tx.insert<Binding>('bindings', binding);
}

/** Sets or clears the approver group of an eligible binding; the group must belong to the tenant. */
async function applyApprovers(
  ctx: ServerContext,
  tx: IamStore,
  binding: Binding,
  input: EligibilityInput,
): Promise<void> {
  if (input.approverGroupId === undefined) return;
  if (input.approverGroupId === null) {
    delete binding.approverGroupId;
    return;
  }
  if (!binding.eligible) return;
  await ctx.scoped(tx, 'groups', input.approverGroupId, binding.tenantId);
  binding.approverGroupId = input.approverGroupId;
}

/** A binding may be removed by the administrator whose authority issued it, or by root. */
export async function deleteBinding(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  binding: Binding,
): Promise<void> {
  const role = await tx.get<Role>('roles', binding.roleId);
  if (role?.protected) throw new IamError('PROTECTED_RESOURCE', 'Use owner transfer', 403);
  const authority = await tx.get<GrantAuthority>('grantAuthorities', binding.authorityId);
  if (authority?.identityId !== principal.identity.id && !(await ctx.rootPrincipal(tx, principal)))
    throw new IamError('ACCESS_DENIED', 'Cannot mutate a higher authority binding', 403);
  for (const activation of await tx.find<BindingActivation>('bindingActivations', {
    tenantId: binding.tenantId,
    bindingId: binding.id,
  }))
    await tx.delete('bindingActivations', activation.id);
  await tx.delete('bindings', binding.id);
}

/** An activation past its end (or still awaiting approval, or denied) grants nothing. */
const liveActivation = (activation: BindingActivation, now: number) =>
  activation.expiresAt > now && activation.status !== 'pending' && activation.status !== 'denied';
/** A request that still waits for a decision. */
const pendingActivation = (activation: BindingActivation, now: number) =>
  activation.status === 'pending' && activation.expiresAt > now;

export function createBindingsApi(ctx: ServerContext) {
  const { store } = ctx;
  const { operation } = ctx.operations;
  /** Whether a binding's subject is this identity, directly or through group membership. */
  async function appliesTo(tx: IamStore, binding: Binding, identityId: string): Promise<boolean> {
    if (binding.subjectType === 'identity') return binding.subjectId === identityId;
    return (
      await tx.find<GroupMember>('groupMembers', {
        tenantId: binding.tenantId,
        groupId: binding.subjectId,
        identityId,
      })
    ).some((member) => ctx.liveMembership(member));
  }
  function publicActivation(activation: BindingActivation, now: number) {
    const { uniqueKey: _key, ...rest } = activation;
    return {
      ...rest,
      status: activation.status ?? ('active' as const),
      active: liveActivation(activation, now),
    };
  }
  /** Queues an email through the host outbox when the deployment delivers email at all. */
  async function notify(
    tx: IamStore,
    tenantId: string,
    to: string | undefined,
    template: string,
    payload: Record<string, string>,
  ): Promise<void> {
    if (!to || !ctx.options.authentication?.sendEmail) return;
    await ctx.auth.enqueueDelivery(tx, { tenantId, kind: 'email', to, template, payload });
  }
  /**
   * Whether the caller may decide on an activation of this binding: anyone holding the permission when the binding
   * names no approvers; otherwise root, the requester's manager (`managerApproval`), or an approver-group member.
   */
  async function mayApprove(
    tx: IamStore,
    binding: Binding,
    principal: AuthenticatedPrincipal,
    requesterId: string,
  ): Promise<boolean> {
    if (!binding.approverGroupId && !binding.managerApproval) return true;
    if (await ctx.rootPrincipal(tx, principal)) return true;
    if (binding.managerApproval) {
      const requester = await tx.get<Identity>('identities', requesterId);
      if (requester?.managerId === principal.identity.id) return true;
    }
    if (!binding.approverGroupId) return false;
    return (
      await tx.find<GroupMember>('groupMembers', {
        tenantId: binding.tenantId,
        groupId: binding.approverGroupId,
        identityId: principal.identity.id,
      })
    ).some((member) => ctx.liveMembership(member));
  }
  /** Who is emailed an activation request: live approver-group members and, with `managerApproval`, the requester's manager. */
  async function approverIds(
    tx: IamStore,
    binding: Binding,
    requesterId: string,
  ): Promise<Set<string>> {
    const recipients = new Set<string>();
    if (binding.approverGroupId)
      for (const member of await tx.find<GroupMember>('groupMembers', {
        tenantId: binding.tenantId,
        groupId: binding.approverGroupId,
      }))
        if (ctx.liveMembership(member)) recipients.add(member.identityId);
    if (binding.managerApproval) {
      const requester = await tx.get<Identity>('identities', requesterId);
      if (requester?.managerId) recipients.add(requester.managerId);
    }
    recipients.delete(requesterId);
    return recipients;
  }
  async function decideActivation(
    credential: CredentialInput,
    input: { tenantId: string; activationId: string; note?: string; durationMs?: number },
    decision: 'approved' | 'denied',
  ) {
    const existing = await ctx.scoped<BindingActivation>(
      store,
      'bindingActivations',
      input.activationId,
      text(input.tenantId, 'tenantId'),
    );
    return operation(
      credential,
      input.tenantId,
      'iam:bindings:approve',
      existing.roleId,
      async ({ tx, principal }) => {
        const activation = await ctx.scoped<BindingActivation>(
          tx,
          'bindingActivations',
          input.activationId,
          input.tenantId,
        );
        const now = ctx.now();
        if (!pendingActivation(activation, now))
          throw new IamError('INVALID_TRANSITION', 'This request is not awaiting a decision', 409);
        if (activation.identityId === principal.identity.id)
          throw new IamError('INVALID_INPUT', 'You cannot decide on your own request');
        // Two-person control: an administrator viewing as an approver must not decide in their name.
        if (principal.session.impersonatorId)
          throw new IamError(
            'IMPERSONATION_RESTRICTED',
            'Requests cannot be decided while impersonating',
            403,
          );
        const binding = await tx.get<Binding>('bindings', activation.bindingId);
        if (!binding || !binding.eligible || !ctx.liveBinding(binding))
          throw new IamError('INVALID_TRANSITION', 'The binding is no longer eligible', 409);
        if (!(await mayApprove(tx, binding, principal, activation.identityId)))
          throw new IamError('ACCESS_DENIED', 'Only the designated approvers may decide', 403);
        const note = input.note !== undefined ? text(input.note, 'note', 2048) : undefined;
        const decided: BindingActivation = {
          ...activation,
          decidedBy: principal.identity.id,
          decidedAt: now,
          ...(note !== undefined ? { note } : {}),
        };
        if (decision === 'approved') {
          const limit = activationRules(
            binding,
            (await ctx.tenant(tx, input.tenantId)).accessPolicy,
          ).maxActivationMs;
          const durationMs = integer(
            input.durationMs ?? Math.min(activation.requestedDurationMs ?? limit, limit),
            'durationMs',
            60_000,
            limit,
          );
          decided.status = 'active';
          decided.activatedAt = now;
          decided.expiresAt = now + durationMs;
        } else {
          decided.status = 'denied';
          decided.expiresAt = now;
        }
        await tx.put('bindingActivations', decided);
        const role = await tx.get<Role>('roles', activation.roleId);
        await ctx.events.audit(
          tx,
          principal,
          `binding:activation-${decision}`,
          input.tenantId,
          activation.bindingId,
          'allow',
          false,
          {
            activationId: activation.id,
            roleId: activation.roleId,
            identityId: activation.identityId,
            ...(decision === 'approved' ? { expiresAt: decided.expiresAt } : {}),
            ...(note !== undefined ? { note } : {}),
          },
        );
        const requester = await tx.get<Identity>('identities', activation.identityId);
        await notify(tx, input.tenantId, requester?.email, 'activation-decided', {
          activationId: activation.id,
          roleId: activation.roleId,
          roleName: role?.name ?? activation.roleId,
          decision,
          deciderName: principal.identity.name,
          ...(note !== undefined ? { note } : {}),
          ...(decision === 'approved' ? { expiresAt: String(decided.expiresAt) } : {}),
        });
        return publicActivation(decided, now);
      },
    );
  }
  return {
    /**
     * expiresAt (epoch milliseconds) makes the grant temporary; it must lie in the future and within ten years.
     * `eligible` makes it a just-in-time grant: the subject holds the role only after `bindings.activate`, for at
     * most `maxActivationMs` (default one hour), optionally with a justification and an MFA-verified session.
     */
    create: (credential: CredentialInput, input: BindingInput) =>
      operation(
        credential,
        input.tenantId,
        'iam:bindings:create',
        input.roleId,
        ({ tx, principal }) => createBinding(ctx, tx, principal, input),
      ),
    /**
     * Extends, shortens, or removes (null) a binding's expiry, sets or clears (null) its access window, or changes
     * its eligibility settings. Requires iam:bindings:create on the role and the binding's own authority, like
     * delete. Turning eligibility off ends every activation of the binding.
     */
    update: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        bindingId: string;
        startsAt?: number | null;
        expiresAt?: number | null;
        window?: AccessWindow | null;
      } & EligibilityInput,
    ) => {
      const existing = await ctx.scoped<Binding>(
        store,
        'bindings',
        input.bindingId,
        text(input.tenantId, 'tenantId'),
      );
      return operation(
        credential,
        input.tenantId,
        'iam:bindings:create',
        existing.roleId,
        async ({ tx, principal }) => {
          const binding = await ctx.scoped<Binding>(
            tx,
            'bindings',
            input.bindingId,
            input.tenantId,
          );
          const role = await tx.get<Role>('roles', binding.roleId);
          if (role?.protected) throw new IamError('PROTECTED_RESOURCE', 'Use owner transfer', 403);
          const authority = await tx.get<GrantAuthority>('grantAuthorities', binding.authorityId);
          if (
            authority?.identityId !== principal.identity.id &&
            !(await ctx.rootPrincipal(tx, principal))
          )
            throw new IamError('ACCESS_DENIED', 'Cannot mutate a higher authority binding', 403);
          if (
            input.startsAt === undefined &&
            input.expiresAt === undefined &&
            input.window === undefined &&
            input.eligible === undefined &&
            input.maxActivationMs === undefined &&
            input.requireJustification === undefined &&
            input.requireMfa === undefined &&
            input.requireApproval === undefined &&
            input.approverGroupId === undefined &&
            input.managerApproval === undefined
          )
            throw new IamError('INVALID_INPUT', 'Nothing to update');
          // Editing a package's binding by hand takes it over: revoking the package no longer removes it.
          const { packageAssignmentId: _package, ...rest } = binding;
          const next: Binding = rest;
          if (input.expiresAt === null) delete next.expiresAt;
          else if (input.expiresAt !== undefined)
            next.expiresAt = ctx.bindingExpiry(input.expiresAt);
          if (input.startsAt === null) delete next.startsAt;
          else if (input.startsAt !== undefined) next.startsAt = ctx.bindingStart(input.startsAt);
          if (
            next.startsAt !== undefined &&
            next.expiresAt !== undefined &&
            next.startsAt >= next.expiresAt
          )
            throw new IamError('INVALID_INPUT', 'startsAt must be before expiresAt');
          if (input.window === null) delete next.window;
          else if (input.window !== undefined) next.window = ctx.accessWindow(input.window);
          applyEligibility(next, input);
          await applyApprovers(ctx, tx, next, input);
          if (binding.eligible && !next.eligible)
            for (const activation of await tx.find<BindingActivation>('bindingActivations', {
              tenantId: input.tenantId,
              bindingId: binding.id,
            }))
              await tx.delete('bindingActivations', activation.id);
          return tx.put<Binding>('bindings', next);
        },
      );
    },
    list: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        roleId?: string;
        subjectType?: 'identity' | 'group';
        subjectId?: string;
        includeExpired?: boolean;
        /** Keep only eligible (just-in-time) bindings, or only standing ones. */
        eligible?: boolean;
        /** Keep only temporary bindings that expire before this time (expiry reports). */
        expiresBefore?: number;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:bindings:read',
        input.roleId ?? input.subjectId ?? input.tenantId,
        async ({ tx }) => {
          const filter: Record<string, unknown> = { tenantId: input.tenantId };
          if (input.roleId !== undefined) filter.roleId = text(input.roleId, 'roleId');
          if (input.subjectType !== undefined) {
            if (!['identity', 'group'].includes(input.subjectType))
              throw new IamError('INVALID_INPUT', 'Invalid subject type');
            filter.subjectType = input.subjectType;
          }
          if (input.subjectId !== undefined) filter.subjectId = text(input.subjectId, 'subjectId');
          const eligible =
            input.eligible !== undefined ? boolean(input.eligible, 'eligible') : undefined;
          const expiresBefore =
            input.expiresBefore !== undefined
              ? integer(input.expiresBefore, 'expiresBefore', 0, Number.MAX_SAFE_INTEGER)
              : undefined;
          return (await tx.find<Binding>('bindings', filter)).filter(
            (binding) =>
              (input.includeExpired === true || !ctx.expiredBinding(binding)) &&
              (eligible === undefined || Boolean(binding.eligible) === eligible) &&
              (expiresBefore === undefined ||
                (binding.expiresAt !== undefined && binding.expiresAt <= expiresBefore)),
          );
        },
      ),
    delete: (credential: CredentialInput, input: { tenantId: string; bindingId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:bindings:delete',
        input.bindingId,
        async ({ tx, principal }) => {
          const binding = await ctx.scoped<Binding>(
            tx,
            'bindings',
            input.bindingId,
            input.tenantId,
          );
          await deleteBinding(ctx, tx, principal, binding);
          return { deleted: true };
        },
      ),
    /**
     * Just-in-time elevation: the subject of an eligible binding (directly, or through a group) activates it for
     * `durationMs` (at most the binding's `maxActivationMs`, one hour by default) with an optional justification.
     * Requires iam:bindings:activate on the role (`iam/{roleId}`) from an ordinary session of the tenant; the
     * binding may require MFA or a justification. Audited as `binding:activate` with the justification.
     */
    activate: async (
      credential: CredentialInput,
      input: { tenantId: string; bindingId: string; durationMs?: number; justification?: string },
    ) => {
      const existing = await ctx.scoped<Binding>(
        store,
        'bindings',
        input.bindingId,
        text(input.tenantId, 'tenantId'),
      );
      return operation(
        credential,
        input.tenantId,
        'iam:bindings:activate',
        existing.roleId,
        async ({ tx, principal }) => {
          const binding = await ctx.scoped<Binding>(
            tx,
            'bindings',
            input.bindingId,
            input.tenantId,
          );
          if (!binding.eligible || !ctx.liveBinding(binding))
            throw new IamError('INVALID_TRANSITION', 'This binding is not eligible for activation');
          if (!actsInOwnRight(principal.session) || principal.session.tenantId !== input.tenantId)
            throw new IamError(
              'INVALID_INPUT',
              'Activations are made from an ordinary session of the target tenant',
            );
          if (principal.session.impersonatorId)
            throw new IamError(
              'IMPERSONATION_RESTRICTED',
              'Roles cannot be activated while impersonating',
              403,
            );
          if (!(await appliesTo(tx, binding, principal.identity.id)))
            throw new IamError('ACCESS_DENIED', 'This binding does not apply to you', 403);
          const rules = activationRules(
            binding,
            (await ctx.tenant(tx, input.tenantId)).accessPolicy,
          );
          if (rules.requireMfa && !principal.session.mfa)
            throw new IamError('MFA_REQUIRED', 'Activation requires an MFA-verified session', 403);
          const justification =
            input.justification !== undefined
              ? text(input.justification, 'justification', 2048)
              : undefined;
          if (rules.requireJustification && justification === undefined)
            throw new IamError('INVALID_INPUT', 'This activation requires a justification');
          const limit = rules.maxActivationMs;
          const durationMs = integer(input.durationMs ?? limit, 'durationMs', 60_000, limit);
          const now = ctx.now();
          const uniqueKey = `${binding.id}:${principal.identity.id}`;
          const previous = (
            await tx.find<BindingActivation>('bindingActivations', {
              tenantId: input.tenantId,
              uniqueKey,
            })
          )[0];
          if (previous) {
            if (liveActivation(previous, now))
              throw new IamError('CONFLICT', 'This role is already active for you', 409);
            if (pendingActivation(previous, now))
              throw new IamError('CONFLICT', 'Your request is still awaiting a decision', 409);
            await tx.delete('bindingActivations', previous.id);
          }
          const approval = rules.requireApproval;
          // A request that names its approvers must reach at least one who can act on it.
          if (approval && (binding.approverGroupId || binding.managerApproval)) {
            let available = false;
            for (const approverId of await approverIds(tx, binding, principal.identity.id))
              if ((await tx.get<Identity>('identities', approverId))?.status === 'active') {
                available = true;
                break;
              }
            if (!available)
              throw new IamError(
                'INVALID_TRANSITION',
                'Nobody can approve this request: the approver group is empty and you have no active manager',
                409,
              );
          }
          const activation: BindingActivation = {
            id: id(),
            tenantId: input.tenantId,
            uniqueKey,
            bindingId: binding.id,
            identityId: principal.identity.id,
            roleId: binding.roleId,
            activatedAt: now,
            expiresAt: now + (approval ? rules.approvalLifetimeMs : durationMs),
            sessionId: principal.session.id,
            ...(approval ? { status: 'pending' as const, requestedDurationMs: durationMs } : {}),
          };
          if (justification !== undefined) activation.justification = justification;
          await tx.insert('bindingActivations', activation);
          await ctx.events.audit(
            tx,
            principal,
            approval ? 'binding:activation-requested' : 'binding:activate',
            input.tenantId,
            binding.id,
            'allow',
            false,
            {
              activationId: activation.id,
              roleId: binding.roleId,
              expiresAt: activation.expiresAt,
              ...(approval ? { requestedDurationMs: durationMs } : {}),
              ...(justification !== undefined ? { justification } : {}),
            },
          );
          // The designated approvers (group members, the requester's manager) learn about the request by email.
          if (approval) {
            const role = await tx.get<Role>('roles', binding.roleId);
            for (const approverId of await approverIds(tx, binding, principal.identity.id)) {
              const approver = await tx.get<Identity>('identities', approverId);
              if (approver?.status !== 'active') continue;
              await notify(tx, input.tenantId, approver.email, 'activation-request', {
                activationId: activation.id,
                roleId: binding.roleId,
                roleName: role?.name ?? binding.roleId,
                requesterId: principal.identity.id,
                requesterName: principal.identity.name,
                ...(principal.identity.email ? { requesterEmail: principal.identity.email } : {}),
                requestedDurationMs: String(durationMs),
                expiresAt: String(activation.expiresAt),
                ...(justification !== undefined ? { justification } : {}),
              });
            }
          }
          return publicActivation(activation, now);
        },
      );
    },
    /**
     * Grants a pending activation request: the role becomes live for the requested duration (or the approver's
     * shorter `durationMs`), bounded by the binding's `maxActivationMs`. Requires iam:bindings:approve on the role
     * (`iam/{roleId}`), membership of the binding's approver group when one is set, and never one's own request.
     * Audited as `binding:activation-approved`; the requester is emailed (`activation-decided`).
     */
    approveActivation: (
      credential: CredentialInput,
      input: { tenantId: string; activationId: string; note?: string; durationMs?: number },
    ) => decideActivation(credential, input, 'approved'),
    /** Refuses a pending activation request, with an optional note. Audited as `binding:activation-denied`. */
    denyActivation: (
      credential: CredentialInput,
      input: { tenantId: string; activationId: string; note?: string },
    ) => decideActivation(credential, { ...input, durationMs: undefined }, 'denied'),
    /**
     * Pending activation requests the caller may decide on: those of bindings whose approver group they belong to
     * (any binding without a group, for holders of iam:bindings:approve on the role), never their own. Requires
     * iam:bindings:approve on the tenant.
     */
    listApprovals: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:bindings:approve',
        input.tenantId,
        async ({ tx, principal }) => {
          const now = ctx.now();
          const result: Array<
            ReturnType<typeof publicActivation> & {
              role?: { id: string; name: string };
              requester?: { id: string; name: string; email?: string };
            }
          > = [];
          for (const activation of (
            await tx.find<BindingActivation>('bindingActivations', { tenantId: input.tenantId })
          ).sort((a, b) => a.activatedAt - b.activatedAt || (a.id < b.id ? -1 : 1))) {
            if (
              !pendingActivation(activation, now) ||
              activation.identityId === principal.identity.id
            )
              continue;
            const binding = await tx.get<Binding>('bindings', activation.bindingId);
            if (!binding || !(await mayApprove(tx, binding, principal, activation.identityId)))
              continue;
            if (
              !(
                await ctx.decisions.decide(
                  tx,
                  principal,
                  {
                    tenantId: input.tenantId,
                    action: 'iam:bindings:approve',
                    resource: { type: 'iam', id: activation.roleId },
                  },
                  true,
                )
              ).allowed
            )
              continue;
            const role = await tx.get<Role>('roles', activation.roleId);
            const requester = await tx.get<Identity>('identities', activation.identityId);
            result.push({
              ...publicActivation(activation, now),
              ...(role ? { role: { id: role.id, name: role.name } } : {}),
              ...(requester
                ? {
                    requester: {
                      id: requester.id,
                      name: requester.name,
                      ...(requester.email ? { email: requester.email } : {}),
                    },
                  }
                : {}),
            });
          }
          return result;
        },
      ),
    /** Ends the caller's own activation early. Audited as `binding:deactivate`. */
    deactivate: async (
      credential: CredentialInput,
      input: { tenantId: string; activationId: string },
    ) => {
      const existing = await ctx.scoped<BindingActivation>(
        store,
        'bindingActivations',
        input.activationId,
        text(input.tenantId, 'tenantId'),
      );
      return operation(
        credential,
        input.tenantId,
        'iam:bindings:activate',
        existing.roleId,
        async ({ tx, principal }) => {
          const activation = await ctx.scoped<BindingActivation>(
            tx,
            'bindingActivations',
            input.activationId,
            input.tenantId,
          );
          if (activation.identityId !== principal.identity.id)
            throw new IamError('ACCESS_DENIED', 'Only the holder can end this activation', 403);
          const cancelled = activation.status === 'pending';
          await tx.delete('bindingActivations', activation.id);
          await ctx.events.audit(
            tx,
            principal,
            'binding:deactivate',
            input.tenantId,
            activation.bindingId,
            'allow',
            false,
            {
              activationId: activation.id,
              roleId: activation.roleId,
              ...(cancelled ? { cancelled: true } : {}),
            },
          );
          return { deactivated: true };
        },
      );
    },
    /**
     * Ends someone else's activation (incident response). Requires iam:bindings:delete on the binding and the
     * binding's own authority, like deleting it. Audited as `binding:deactivate` with the holder.
     */
    revokeActivation: async (
      credential: CredentialInput,
      input: { tenantId: string; activationId: string },
    ) => {
      const existing = await ctx.scoped<BindingActivation>(
        store,
        'bindingActivations',
        input.activationId,
        text(input.tenantId, 'tenantId'),
      );
      return operation(
        credential,
        input.tenantId,
        'iam:bindings:delete',
        existing.bindingId,
        async ({ tx, principal }) => {
          const activation = await ctx.scoped<BindingActivation>(
            tx,
            'bindingActivations',
            input.activationId,
            input.tenantId,
          );
          const binding = await tx.get<Binding>('bindings', activation.bindingId);
          if (binding) {
            const authority = await tx.get<GrantAuthority>('grantAuthorities', binding.authorityId);
            if (
              authority?.identityId !== principal.identity.id &&
              !(await ctx.rootPrincipal(tx, principal))
            )
              throw new IamError('ACCESS_DENIED', 'Cannot mutate a higher authority binding', 403);
          }
          await tx.delete('bindingActivations', activation.id);
          await ctx.events.audit(
            tx,
            principal,
            'binding:deactivate',
            input.tenantId,
            activation.bindingId,
            'allow',
            false,
            {
              activationId: activation.id,
              roleId: activation.roleId,
              identityId: activation.identityId,
              revoked: true,
            },
          );
          return { deactivated: true };
        },
      );
    },
    /**
     * Activations of eligible bindings, newest first. Without `status`, live activations; `status: 'pending'`
     * lists open requests and `'denied'` refused ones; ended records are included only with includeExpired.
     */
    listActivations: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        bindingId?: string;
        identityId?: string;
        roleId?: string;
        includeExpired?: boolean;
        status?: 'pending' | 'active' | 'denied';
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:bindings:read',
        input.bindingId ?? input.identityId ?? input.roleId ?? input.tenantId,
        async ({ tx }) => {
          const filter: Record<string, unknown> = { tenantId: input.tenantId };
          if (input.bindingId !== undefined) filter.bindingId = text(input.bindingId, 'bindingId');
          if (input.identityId !== undefined)
            filter.identityId = text(input.identityId, 'identityId');
          if (input.roleId !== undefined) filter.roleId = text(input.roleId, 'roleId');
          if (input.status !== undefined && !['pending', 'active', 'denied'].includes(input.status))
            throw new IamError('INVALID_INPUT', 'status must be pending, active, or denied');
          const now = ctx.now();
          return (await tx.find<BindingActivation>('bindingActivations', filter))
            .filter((activation) =>
              input.status === undefined
                ? input.includeExpired === true || liveActivation(activation, now)
                : (activation.status ?? 'active') === input.status &&
                  (input.includeExpired === true ||
                    input.status === 'denied' ||
                    activation.expiresAt > now),
            )
            .sort((a, b) => b.activatedAt - a.activatedAt || (a.id < b.id ? -1 : 1))
            .map((activation) => publicActivation(activation, now));
        },
      ),
    /**
     * The caller's own bindings, direct and through groups, including eligible ones and their live activation.
     * Needs only iam:bindings:activate on the tenant, so members can see what they may elevate to.
     */
    listMine: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:bindings:activate',
        input.tenantId,
        async ({ tx, principal }) => {
          if (!actsInOwnRight(principal.session) || principal.session.tenantId !== input.tenantId)
            throw new IamError(
              'INVALID_INPUT',
              'Bindings are listed from an ordinary session of the target tenant',
            );
          return ctx.decisions.effectiveBindings(tx, input.tenantId, principal.identity.id);
        },
      ),
  };
}

export function createAuthoritiesApi(ctx: ServerContext) {
  const { auth, catalog } = ctx;
  const { operation } = ctx.operations;
  return {
    /** Delegates a narrower grant authority to another identity; the ceiling is validated against the catalog. */
    create: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        identityId: string;
        ceiling: import('@better-iam/core').PolicyDocument;
        parentAuthorityId?: string;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:authorities:create',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          await catalog.validate(tx, input.tenantId, input.ceiling);
          await ctx.scoped(tx, 'identities', input.identityId, input.tenantId);
          if (
            input.identityId === principal.identity.id &&
            !(await ctx.rootPrincipal(tx, principal))
          )
            throw new IamError('ACCESS_DENIED', 'Cannot issue authority to yourself', 403);
          const parent = await ctx.grantingAuthority(
            tx,
            principal,
            input.tenantId,
            input.parentAuthorityId,
          );
          return tx.insert<GrantAuthority>('grantAuthorities', {
            id: id(),
            tenantId: input.tenantId,
            identityId: input.identityId,
            ceiling: input.ceiling,
            parentAuthorityId: parent.id,
            revoked: false,
          });
        },
      ),
    revoke: (credential: CredentialInput, input: { tenantId: string; authorityId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:authorities:revoke',
        input.authorityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const authority = await ctx.scoped<GrantAuthority>(
            tx,
            'grantAuthorities',
            input.authorityId,
            input.tenantId,
          );
          const parent = authority.parentAuthorityId
            ? await tx.get<GrantAuthority>('grantAuthorities', authority.parentAuthorityId)
            : undefined;
          if (
            !(await ctx.rootPrincipal(tx, principal)) &&
            (!parent ||
              parent.identityId !== principal.identity.id ||
              authority.identityId === principal.identity.id)
          )
            throw new IamError(
              'ACCESS_DENIED',
              'Only superior authority can revoke this grant',
              403,
            );
          return tx.put('grantAuthorities', { ...authority, revoked: true });
        },
      ),
  };
}
