import { IamError, type Identity, type IamStore, type StoredRecord } from '@better-iam/core';
import type { ServerContext } from './context.js';
import type { Binding, GroupMember, Role } from './models.js';

/**
 * A separation-of-duties rule: nobody may hold two or more of these roles at once (directly, through groups, or as
 * eligible just-in-time bindings). `prevent` refuses grants that would create a conflict; `detect` only reports it.
 */
export interface SodRule extends StoredRecord {
  name: string;
  description?: string;
  roleIds: string[];
  mode: 'prevent' | 'detect';
  createdAt: number;
  createdBy: string;
}
/** An identity currently holding two or more roles of one rule. */
export interface SodViolation {
  ruleId: string;
  ruleName: string;
  mode: SodRule['mode'];
  identityId: string;
  roleIds: string[];
}

/** Operations that can grant a role to someone: only these pay for a separation-of-duties check. */
const grantingActions = new Set([
  'iam:bindings:create',
  'iam:groups:update',
  'iam:identities:create',
  'iam:access-requests:review',
  'iam:config:apply',
  // Access packages materialize bindings and memberships on assignment and on approved requests.
  'iam:packages:assign',
  'iam:packages:approve',
  // Team membership fills the team's backing group, and a team created under a parent joins its members to it.
  'iam:teams:create',
  'iam:teams:update',
]);

/** Every identity (optionally only `identityIds`) that holds two or more roles of a rule. */
export async function sodViolations(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  rules?: SodRule[],
  identityIds?: string[],
): Promise<SodViolation[]> {
  const active = rules ?? (await tx.find<SodRule>('sodRules', { tenantId }));
  if (!active.length) return [];
  // Future-dated bindings count: a prevent rule must also stop a conflict that is scheduled to start.
  const bindings = (await tx.find<Binding>('bindings', { tenantId })).filter(
    (binding) => !ctx.expiredBinding(binding),
  );
  const groupsOf = new Map<string, Set<string>>();
  for (const member of await tx.find<GroupMember>('groupMembers', { tenantId })) {
    if (!ctx.liveMembership(member)) continue;
    const set = groupsOf.get(member.identityId) ?? new Set<string>();
    set.add(member.groupId);
    groupsOf.set(member.identityId, set);
  }
  const subjects =
    identityIds ??
    (await tx.find<Identity>('identities', { tenantId }))
      .filter((identity) => identity.status !== 'deleted')
      .map((identity) => identity.id);
  const violations: SodViolation[] = [];
  for (const identityId of subjects) {
    const memberOf = groupsOf.get(identityId) ?? new Set<string>();
    const held = new Set(
      bindings
        .filter((binding) =>
          binding.subjectType === 'identity'
            ? binding.subjectId === identityId
            : memberOf.has(binding.subjectId),
        )
        .map((binding) => binding.roleId),
    );
    for (const rule of active) {
      const conflicting = rule.roleIds.filter((roleId) => held.has(roleId));
      if (conflicting.length >= 2)
        violations.push({
          ruleId: rule.id,
          ruleName: rule.name,
          mode: rule.mode,
          identityId,
          roleIds: conflicting,
        });
    }
  }
  return violations;
}

/**
 * Before a granting operation: the prevent-rule conflicts that already exist, so a rule added after the fact never
 * blocks unrelated work. Undefined when the action cannot grant or the tenant has no prevent rules.
 */
export async function sodSnapshot(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  action: string,
): Promise<{ rules: SodRule[]; existing: Set<string> } | undefined> {
  if (!grantingActions.has(action)) return undefined;
  const rules = (await tx.find<SodRule>('sodRules', { tenantId })).filter(
    (rule) => rule.mode === 'prevent',
  );
  if (!rules.length) return undefined;
  const existing = new Set(
    (await sodViolations(ctx, tx, tenantId, rules)).map((v) => `${v.ruleId}:${v.identityId}`),
  );
  return { rules, existing };
}

/** After the operation: refuses (rolling the transaction back) when it created a new prevent-rule conflict. */
export async function sodVerify(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  snapshot: { rules: SodRule[]; existing: Set<string> } | undefined,
  identityIds?: string[],
): Promise<void> {
  if (!snapshot) return;
  const created = (await sodViolations(ctx, tx, tenantId, snapshot.rules, identityIds)).find(
    (violation) => !snapshot.existing.has(`${violation.ruleId}:${violation.identityId}`),
  );
  if (!created) return;
  const names: string[] = [];
  for (const roleId of created.roleIds)
    names.push((await tx.get<Role>('roles', roleId))?.name ?? roleId);
  throw new IamError(
    'SOD_CONFLICT',
    `Separation of duties (${created.ruleName}): one person cannot hold ${names.join(' and ')}`,
    409,
  );
}

/** For flows outside the operation envelope (invitation acceptance): a newly granted identity must not conflict. */
export async function sodAssertIdentity(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  identityId: string,
): Promise<void> {
  const rules = (await tx.find<SodRule>('sodRules', { tenantId })).filter(
    (rule) => rule.mode === 'prevent',
  );
  if (rules.length)
    await sodVerify(ctx, tx, tenantId, { rules, existing: new Set() }, [identityId]);
}
