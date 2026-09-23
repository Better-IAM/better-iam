import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type { ResolvedResource } from '../options.js';
import type { ActionDefinition, Binding, GroupMember, Policy, Role } from '../models.js';
import {
  evaluateInvariants,
  type AccessInvariant,
  type InvariantResult,
  type InvariantViolation,
} from '../invariants.js';
import { allow } from './packages.js';
import { updatePolicy } from './policies.js';
import { deleteRole, updateRole, type RoleUpdate } from './roles.js';
import { object, strings, text } from '../validation.js';

/** A candidate change: exactly one of `role` (an update as `roles.update` takes it), `policy`, or `deleteRole`. */
export interface ImpactChange {
  role?: Omit<RoleUpdate, 'tenantId'>;
  policy?: { policyId: string; document: PolicyDocument };
  deleteRole?: string;
}
export interface ImpactResourceDiff {
  /** `type/id` of the resource evaluated. */
  resource: string;
  gained: string[];
  lost: string[];
}
export interface ImpactIdentity {
  identity: { id: string; name: string };
  changes: ImpactResourceDiff[];
}
export interface ImpactPreview {
  /** Roles whose grants the change touches: the changed roles and every role inheriting them. */
  roles: { id: string; name: string }[];
  /** People and service accounts holding those roles (directly or through groups) that were evaluated. */
  evaluated: number;
  /** Holders beyond the evaluation cap (200) were skipped. */
  truncated: boolean;
  /** Holders whose allowed actions change on at least one resource. */
  identities: ImpactIdentity[];
  gainedTotal: number;
  lostTotal: number;
  /** Access invariants the change would newly break (with the new violations) or make pass again. */
  invariants: {
    broken: {
      id: string;
      name: string;
      mode: 'enforce' | 'monitor';
      violations: InvariantViolation[];
    }[];
    fixed: { id: string; name: string; mode: 'enforce' | 'monitor' }[];
  };
}

const maxHolders = 200;
const maxResources = 10;

/** Invariants whose violations grew (broken) or disappeared (fixed) between two evaluations. */
function compareInvariants(
  before: InvariantResult[],
  after: InvariantResult[],
): ImpactPreview['invariants'] {
  const previous = new Map(before.map((result) => [result.invariant.id, result]));
  const broken: ImpactPreview['invariants']['broken'] = [];
  const fixed: ImpactPreview['invariants']['fixed'] = [];
  for (const result of after) {
    const { id, name, mode } = result.invariant;
    const earlier = previous.get(id);
    const known = new Set(earlier?.violations.map((violation) => violation.identity.id));
    const added = result.violations.filter((violation) => !known.has(violation.identity.id));
    if (added.length) broken.push({ id, name, mode, violations: added });
    else if (result.passed && earlier && !earlier.passed && !earlier.error)
      fixed.push({ id, name, mode });
  }
  return { broken, fixed };
}

/** Thrown to roll back the simulation transaction while carrying its result out. */
class Rollback<T> extends Error {
  constructor(readonly result: T) {
    super('rollback');
  }
}

/**
 * Change impact preview: before editing a role or policy (or deleting a role), see who would gain or lose which
 * actions on which resources. The change is applied exactly as the real call would apply it — same validation and
 * the same edit rights — inside a transaction that is always rolled back, and every holder's decisions are compared
 * before and after, so inheritance, authority ceilings, boundaries, conditions, and eligibility all count.
 */
export function createImpactApi(ctx: ServerContext) {
  const { operation } = ctx.operations;

  /** Every role whose grants include `roleIds` (the roles themselves and their inheritors, transitively). */
  function inheritors(roles: Role[], roleIds: Set<string>): Set<string> {
    const affected = new Set(roleIds);
    let grew = true;
    while (grew) {
      grew = false;
      for (const role of roles)
        if (!affected.has(role.id) && role.inherits?.some((parent) => affected.has(parent))) {
          affected.add(role.id);
          grew = true;
        }
    }
    return affected;
  }

  async function holders(tx: IamStore, tenantId: string, roleIds: Set<string>) {
    const bindings = (await tx.find<Binding>('bindings', { tenantId })).filter(
      (binding) => roleIds.has(binding.roleId) && !ctx.expiredBinding(binding),
    );
    const ids = new Set<string>();
    const groups = new Set<string>();
    for (const binding of bindings)
      if (binding.subjectType === 'identity') ids.add(binding.subjectId);
      else groups.add(binding.subjectId);
    if (groups.size)
      for (const member of await tx.find<GroupMember>('groupMembers', { tenantId }))
        if (groups.has(member.groupId) && ctx.liveMembership(member)) ids.add(member.identityId);
    const people: Identity[] = [];
    for (const identityId of [...ids].sort()) {
      const identity = await tx.get<Identity>('identities', identityId);
      if (identity?.tenantId === tenantId && identity.status === 'active') people.push(identity);
    }
    return people;
  }

  /** The allowed actions per identity and resource, as `identityId -> resource -> Set(action)`. */
  async function allowed(
    tx: IamStore,
    tenant: Tenant,
    people: Identity[],
    resources: ResolvedResource[],
    actions: string[],
    assumeMfa: boolean,
  ) {
    const result = new Map<string, Map<string, Set<string>>>();
    for (const identity of people) {
      const principal = ctx.decisions.simulatedPrincipal(identity, assumeMfa);
      const prepared = await ctx.decisions.prepareDecision(tx, principal, tenant, actions[0]!);
      const byResource = new Map<string, Set<string>>();
      for (const resource of resources) {
        const set = new Set<string>();
        for (const action of actions) {
          const decision =
            'fixed' in prepared ? prepared.fixed : prepared.evaluate(resource, action);
          if (decision.allowed) set.add(action);
        }
        byResource.set(`${resource.type}/${resource.id}`, set);
      }
      result.set(identity.id, byResource);
    }
    return result;
  }

  async function apply(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    change: ImpactChange,
  ): Promise<void> {
    // The caller must hold the permission the real call needs, not only the edit rights the helpers check.
    if (change.role) {
      await allow(
        ctx,
        tx,
        principal,
        tenantId,
        'iam:roles:update',
        change.role.roleId,
        'update this role',
      );
      await updateRole(ctx, tx, principal, { ...change.role, tenantId });
    } else if (change.policy) {
      const policy = await ctx.scoped<Policy>(tx, 'policies', change.policy.policyId, tenantId);
      await allow(
        ctx,
        tx,
        principal,
        tenantId,
        'iam:policies:update',
        policy.id,
        'update this policy',
      );
      await updatePolicy(ctx, tx, principal, {
        tenantId,
        policyId: policy.id,
        version: policy.version,
        document: change.policy.document,
      });
    } else {
      const role = await ctx.scoped<Role>(tx, 'roles', change.deleteRole!, tenantId);
      await allow(ctx, tx, principal, tenantId, 'iam:roles:delete', role.id, 'delete this role');
      await deleteRole(ctx, tx, principal, role);
    }
  }

  return {
    /**
     * Previews a role update (`change.role`, as `roles.update` takes it), a policy document change
     * (`change.policy`), or a role deletion (`change.deleteRole`) against 1-10 `resources`. For every holder of the
     * affected roles (at most 200), reports the actions gained and lost per resource; `actions` (at most 200)
     * narrows the comparison, which otherwise covers every known action. `assumeMfa` evaluates holders as if
     * MFA-verified. Nothing is saved. Requires iam:policies:simulate, plus the rights the change itself needs.
     */
    preview: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        change: ImpactChange;
        resources: { type: string; id: string }[];
        actions?: string[];
        assumeMfa?: boolean;
      },
    ): Promise<ImpactPreview> => {
      const change = object(input.change) as ImpactChange;
      const kinds = (['role', 'policy', 'deleteRole'] as const).filter(
        (key) => change[key] !== undefined,
      );
      if (kinds.length !== 1)
        throw new IamError('INVALID_INPUT', 'Provide exactly one of role, policy, or deleteRole');
      if (change.role) text(object(change.role).roleId, 'roleId');
      if (change.policy) {
        text(object(change.policy).policyId, 'policyId');
        object(change.policy.document);
      }
      if (change.deleteRole !== undefined) text(change.deleteRole, 'deleteRole');
      if (
        !Array.isArray(input.resources) ||
        input.resources.length === 0 ||
        input.resources.length > maxResources
      )
        throw new IamError('INVALID_INPUT', `Provide 1-${maxResources} resources`);
      const references = input.resources.map((item) => {
        const reference = object(item);
        return {
          type: text(reference.type, 'resource type'),
          id: text(reference.id, 'resource id'),
        };
      });
      const requested =
        input.actions === undefined ? undefined : [...new Set(strings(input.actions, 'actions'))];
      if (requested && (requested.length === 0 || requested.length > 200))
        throw new IamError('INVALID_INPUT', 'Compare 1-200 actions');
      const assumeMfa = input.assumeMfa === true;
      const tenantId = text(input.tenantId, 'tenantId');
      // Authorize (and audit) the preview itself; the simulation runs in its own transaction below.
      const principal = await operation(
        credential,
        tenantId,
        'iam:policies:simulate',
        tenantId,
        async ({ principal }) => {
          // The change rights below are checked for the session holder alone, so "view as" cannot borrow them.
          if (principal.session.impersonatorId)
            throw new IamError(
              'IMPERSONATION_RESTRICTED',
              'Change previews are not available while impersonating',
              403,
            );
          return principal;
        },
      );
      try {
        await ctx.store.transaction(async (tx) => {
          const tenant = await ctx.tenant(tx, tenantId);
          const roles = await tx.find<Role>('roles', { tenantId });
          const changed = new Set<string>();
          if (change.role) changed.add(change.role.roleId);
          if (change.deleteRole) changed.add(change.deleteRole);
          if (change.policy)
            for (const role of roles)
              if (role.policyIds.includes(change.policy.policyId)) changed.add(role.id);
          const affected = inheritors(roles, changed);
          const everyone = await holders(tx, tenantId, affected);
          const people = everyone.slice(0, maxHolders);
          const resources: ResolvedResource[] = [];
          for (const reference of references)
            resources.push(await ctx.decisions.resolve(tx, { tenantId, ...reference }, true));
          let actions = requested;
          if (actions) {
            for (const action of actions)
              if (!(await ctx.catalog.knownAction(tx, tenantId, action)))
                throw new IamError('INVALID_ACTION', `Unknown action ${action}`);
          } else
            actions = [
              ...new Set([
                ...ctx.catalog.actions,
                ...(await tx.find<ActionDefinition>('actions', { tenantId })).map(
                  (action) => action.name,
                ),
              ]),
            ];
          actions.sort();
          const before = await allowed(tx, tenant, people, resources, actions, assumeMfa);
          const guardrails = await tx.find<AccessInvariant>('accessInvariants', { tenantId });
          const invariantsBefore = await evaluateInvariants(ctx, tx, tenant, guardrails);
          await apply(tx, principal, tenantId, change);
          const after = await allowed(tx, tenant, people, resources, actions, assumeMfa);
          const invariantsAfter = await evaluateInvariants(ctx, tx, tenant, guardrails);
          const identities: ImpactIdentity[] = [];
          let gainedTotal = 0;
          let lostTotal = 0;
          for (const identity of people) {
            const changes: ImpactResourceDiff[] = [];
            for (const resource of resources) {
              const key = `${resource.type}/${resource.id}`;
              const was = before.get(identity.id)!.get(key)!;
              const now = after.get(identity.id)!.get(key)!;
              const gained = [...now].filter((action) => !was.has(action));
              const lost = [...was].filter((action) => !now.has(action));
              if (!gained.length && !lost.length) continue;
              gainedTotal += gained.length;
              lostTotal += lost.length;
              changes.push({ resource: key, gained, lost });
            }
            if (changes.length)
              identities.push({
                identity: { id: identity.id, name: identity.email ?? identity.name },
                changes,
              });
          }
          const roleById = new Map(roles.map((role) => [role.id, role]));
          throw new Rollback<ImpactPreview>({
            roles: [...affected]
              .map((roleId) => ({ id: roleId, name: roleById.get(roleId)?.name ?? roleId }))
              .sort((a, b) => a.name.localeCompare(b.name)),
            evaluated: people.length,
            truncated: everyone.length > people.length,
            identities,
            gainedTotal,
            lostTotal,
            invariants: compareInvariants(invariantsBefore, invariantsAfter),
          });
        });
      } catch (error) {
        if (error instanceof Rollback) return error.result as ImpactPreview;
        throw error;
      }
      throw new IamError('INTERNAL_ERROR', 'Impact preview did not complete', 500);
    },
  };
}
