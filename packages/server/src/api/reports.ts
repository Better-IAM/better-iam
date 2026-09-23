import type {
  AuthenticatedPrincipal,
  CredentialInput,
  IamStore,
  Identity,
  Session,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type { Binding, BindingActivation, Group, GroupMember, Role } from '../models.js';
import { integer } from '../validation.js';
import { credentialSummary, type CredentialSummary } from './service-accounts.js';

const day = 86400_000;

export interface ExpiringIdentity {
  id: string;
  name: string;
  email?: string;
  kind: Identity['kind'];
  status: Identity['status'];
  expiresAt: number;
  /** Already past the deadline (refused, waiting for the retention worker). */
  expired: boolean;
}
export interface ExpiringBinding {
  id: string;
  roleId: string;
  roleName?: string;
  subjectType: Binding['subjectType'];
  subjectId: string;
  subjectName?: string;
  expiresAt: number;
  eligible: boolean;
}
export interface ExpiringMembership {
  groupId: string;
  groupName?: string;
  identityId: string;
  identityName?: string;
  expiresAt: number;
}
export interface LiveActivation {
  id: string;
  identityId: string;
  identityName?: string;
  roleId: string;
  roleName?: string;
  activatedAt: number;
  expiresAt: number;
  justification?: string;
}
/**
 * The access-hygiene picture of a tenant: what is about to end, what is elevated right now, and what nobody uses.
 * Sections the caller may not read are omitted and named in `omitted`.
 */
export interface AccessReport {
  generatedAt: number;
  withinMs: number;
  unusedForMs: number;
  identities: { total: number; disabled: number; expiring: ExpiringIdentity[] };
  bindings?: {
    total: number;
    eligible: number;
    windowed: number;
    expiring: ExpiringBinding[];
    /** Future-dated bindings that start within the window. */
    starting: ExpiringBinding[];
    activations: LiveActivation[];
    pendingRequests: number;
    /** Temporary group memberships ending within the window. */
    expiringMemberships: ExpiringMembership[];
  };
  credentials?: { total: number; unused: CredentialSummary[]; expiring: CredentialSummary[] };
  omitted: Array<'bindings' | 'credentials'>;
}

/** Validates the report windows: 0 to ten years, 30 days by default. */
export function reportWindows(input: { withinMs?: number; unusedForMs?: number }): {
  withinMs: number;
  unusedForMs: number;
} {
  return {
    withinMs: integer(input.withinMs ?? 30 * day, 'withinMs', 0, 10 * 365 * day),
    unusedForMs: integer(input.unusedForMs ?? 30 * day, 'unusedForMs', 0, 10 * 365 * day),
  };
}

/** Whether a report has anything worth telling someone about. */
export function reportHasFindings(report: AccessReport): boolean {
  return (
    report.identities.expiring.length > 0 ||
    (report.bindings !== undefined &&
      (report.bindings.expiring.length > 0 ||
        report.bindings.starting.length > 0 ||
        report.bindings.expiringMemberships.length > 0 ||
        report.bindings.activations.length > 0 ||
        report.bindings.pendingRequests > 0)) ||
    (report.credentials !== undefined &&
      (report.credentials.unused.length > 0 || report.credentials.expiring.length > 0))
  );
}

/**
 * Builds the access report of one tenant inside a transaction. The API decides per caller which sections to
 * include; deployment operations (the digest) include every section.
 */
export async function buildAccessReport(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  windows: { withinMs: number; unusedForMs: number },
  sections: { bindings: boolean; credentials: boolean },
): Promise<AccessReport> {
  const now = ctx.now();
  const { withinMs, unusedForMs } = windows;
  const horizon = now + withinMs;
  return assemble();
  async function assemble(): Promise<AccessReport> {
    const may = async (section: 'bindings' | 'credentials') => sections[section];
    const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name, 'en');
    const identities = (await tx.find<Identity>('identities', { tenantId })).filter(
      (identity) => identity.status !== 'deleted',
    );
    const names = new Map(identities.map((identity) => [identity.id, identity.name]));
    const report: AccessReport = {
      generatedAt: now,
      withinMs,
      unusedForMs,
      identities: {
        total: identities.length,
        disabled: identities.filter((identity) => identity.status === 'disabled').length,
        expiring: identities
          .filter(
            (identity): identity is Identity & { expiresAt: number } =>
              typeof identity.expiresAt === 'number' &&
              identity.expiresAt <= horizon &&
              // Past its deadline an identity is a finding only until the worker has disabled it.
              (identity.expiresAt > now || identity.status === 'active'),
          )
          .sort((a, b) => a.expiresAt - b.expiresAt || byName(a, b))
          .map((identity) => ({
            id: identity.id,
            name: identity.name,
            ...(identity.email ? { email: identity.email } : {}),
            kind: identity.kind,
            status: identity.status,
            expiresAt: identity.expiresAt,
            expired: identity.expiresAt <= now,
          })),
      },
      omitted: [],
    };
    if (await may('bindings')) {
      const roles = new Map(
        (await tx.find<Role>('roles', { tenantId })).map((role) => [role.id, role.name]),
      );
      const groups = new Map(
        (await tx.find<Group>('groups', { tenantId })).map((group) => [group.id, group.name]),
      );
      const bindings = (await tx.find<Binding>('bindings', { tenantId })).filter(
        (binding) => !ctx.expiredBinding(binding),
      );
      const memberships = await tx.find<GroupMember>('groupMembers', { tenantId });
      // An activation or request counts only while it could grant: its binding is still live and eligible, its
      // holder is active, and (for a group binding) still a member.
      const activeIds = new Set(
        identities
          .filter((identity) => identity.status === 'active')
          .map((identity) => identity.id),
      );
      const eligibleBindings = new Map(
        bindings
          .filter((binding) => binding.eligible && ctx.liveBinding(binding))
          .map((binding) => [binding.id, binding]),
      );
      const applies = (activation: BindingActivation) => {
        const binding = eligibleBindings.get(activation.bindingId);
        if (!binding || !activeIds.has(activation.identityId)) return false;
        return (
          binding.subjectType === 'identity' ||
          memberships.some(
            (member) =>
              member.groupId === binding.subjectId &&
              member.identityId === activation.identityId &&
              ctx.liveMembership(member),
          )
        );
      };
      const activations = (
        await tx.find<BindingActivation>('bindingActivations', { tenantId })
      ).filter(applies);
      const subjectName = (binding: Binding) =>
        binding.subjectType === 'identity'
          ? names.get(binding.subjectId)
          : groups.get(binding.subjectId);
      const summarize = (binding: Binding, at: number): ExpiringBinding => {
        const roleName = roles.get(binding.roleId);
        const subject = subjectName(binding);
        return {
          id: binding.id,
          roleId: binding.roleId,
          ...(roleName ? { roleName } : {}),
          subjectType: binding.subjectType,
          subjectId: binding.subjectId,
          ...(subject ? { subjectName: subject } : {}),
          expiresAt: at,
          eligible: binding.eligible === true,
        };
      };
      const scheduled = (await tx.find<Binding>('bindings', { tenantId })).filter(
        (binding): binding is Binding & { startsAt: number } =>
          typeof binding.startsAt === 'number' &&
          binding.startsAt > now &&
          binding.startsAt <= horizon &&
          !ctx.expiredBinding(binding),
      );
      report.bindings = {
        total: bindings.length,
        eligible: bindings.filter((binding) => binding.eligible).length,
        windowed: bindings.filter((binding) => binding.window).length,
        expiring: bindings
          .filter(
            (binding): binding is Binding & { expiresAt: number } =>
              typeof binding.expiresAt === 'number' && binding.expiresAt <= horizon,
          )
          .sort((a, b) => a.expiresAt - b.expiresAt || (a.id < b.id ? -1 : 1))
          .map((binding) => summarize(binding, binding.expiresAt)),
        starting: scheduled
          .sort((a, b) => a.startsAt - b.startsAt || (a.id < b.id ? -1 : 1))
          .map((binding) => summarize(binding, binding.startsAt)),
        expiringMemberships: memberships
          .filter(
            (member): member is GroupMember & { expiresAt: number } =>
              typeof member.expiresAt === 'number' &&
              member.expiresAt <= horizon &&
              ctx.liveMembership(member),
          )
          .sort((a, b) => a.expiresAt - b.expiresAt || (a.id < b.id ? -1 : 1))
          .map((member) => {
            const groupName = groups.get(member.groupId);
            const identityName = names.get(member.identityId);
            return {
              groupId: member.groupId,
              ...(groupName ? { groupName } : {}),
              identityId: member.identityId,
              ...(identityName ? { identityName } : {}),
              expiresAt: member.expiresAt,
            };
          }),
        activations: activations
          .filter(
            (activation) =>
              activation.expiresAt > now &&
              activation.status !== 'pending' &&
              activation.status !== 'denied',
          )
          .sort((a, b) => a.expiresAt - b.expiresAt || (a.id < b.id ? -1 : 1))
          .map((activation) => {
            const identityName = names.get(activation.identityId);
            const roleName = roles.get(activation.roleId);
            return {
              id: activation.id,
              identityId: activation.identityId,
              ...(identityName ? { identityName } : {}),
              roleId: activation.roleId,
              ...(roleName ? { roleName } : {}),
              activatedAt: activation.activatedAt,
              expiresAt: activation.expiresAt,
              ...(activation.justification ? { justification: activation.justification } : {}),
            };
          }),
        pendingRequests: activations.filter(
          (activation) => activation.status === 'pending' && activation.expiresAt > now,
        ).length,
      };
    } else report.omitted.push('bindings');
    if (await may('credentials')) {
      const keys = (await tx.find<Session>('sessions', { tenantId, kind: 'api-key' }))
        .map((session) => credentialSummary(session, now))
        .filter((key) => !key.expired);
      const unusedSince = now - unusedForMs;
      report.credentials = {
        total: keys.length,
        unused: keys
          .filter((key) => (key.lastUsedAt ?? key.createdAt) <= unusedSince)
          .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1)),
        expiring: keys
          .filter((key) => key.expiresAt <= horizon)
          .sort((a, b) => a.expiresAt - b.expiresAt || (a.id < b.id ? -1 : 1)),
      };
    } else report.omitted.push('credentials');
    return report;
  }
}

export function createReportsApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  async function may(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    action: string,
  ): Promise<boolean> {
    return (
      await ctx.decisions.decide(
        tx,
        principal,
        { tenantId, action, resource: { type: 'iam', id: tenantId } },
        true,
      )
    ).allowed;
  }
  return {
    /**
     * Identities and bindings ending within `withinMs` (30 days by default), keys unused for `unusedForMs` (30 days)
     * or ending soon, live activations, and pending activation requests. Requires iam:identities:read; the binding
     * and credential sections additionally need iam:bindings:read and iam:credentials:read and are omitted otherwise.
     */
    access: (
      credential: CredentialInput,
      input: { tenantId: string; withinMs?: number; unusedForMs?: number },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:read',
        input.tenantId,
        async ({ tx, principal }): Promise<AccessReport> =>
          buildAccessReport(ctx, tx, input.tenantId, reportWindows(input), {
            bindings: await may(tx, principal, input.tenantId, 'iam:bindings:read'),
            credentials: await may(tx, principal, input.tenantId, 'iam:credentials:read'),
          }),
      ),
  };
}
