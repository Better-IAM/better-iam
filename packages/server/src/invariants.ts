import {
  IamError,
  type IamStore,
  type Identity,
  type Json,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import type { GroupMember } from './models.js';
import { id } from './utils.js';
import type { ResolvedResource } from './options.js';

/** Who an invariant is about: one identity, a group's live members, everyone with an attribute value, or everyone. */
export type InvariantSubject =
  | { identityId: string }
  | { groupId: string }
  | { attribute: { name: string; value: string | number | boolean } }
  | { everyone: true };

/**
 * An access invariant: a statement about who may (or must never) perform an action on a resource, such as "no
 * contractor may delete the payroll workspace" or "on-call engineers can always restart production". `monitor`
 * invariants are reported by `invariants.run`; `enforce` invariants also refuse any access change that would newly
 * break them. Names are unique per tenant (uniqueKey `name:{lowercase}`).
 */
export interface AccessInvariant extends StoredRecord {
  name: string;
  description?: string;
  subject: InvariantSubject;
  action: string;
  resource: { type: string; id: string };
  expect: 'allow' | 'deny';
  mode: 'enforce' | 'monitor';
  /** Evaluate subjects as MFA-verified sessions (default true: the most a person can reach). */
  assumeMfa: boolean;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
  /** The last scheduled check (`iam.checkInvariants`): whether it passed and who violated it. */
  lastCheck?: { at: number; passed: boolean; violations: string[]; error?: string };
}
export interface InvariantCheckResult {
  checked: number;
  /** Invariants that newly failed (or gained violators) since the previous check, audited as `invariant:broken`. */
  broken: { tenantId: string; invariantId: string; name: string; violations: string[] }[];
  /** Invariants that pass again, audited as `invariant:restored`. */
  restored: { tenantId: string; invariantId: string; name: string }[];
}
export interface InvariantViolation {
  identity: { id: string; name: string };
  /** The decision reason: why the action was allowed, or why it was denied. */
  reason: string;
}
export interface InvariantResult {
  invariant: Pick<AccessInvariant, 'id' | 'name' | 'mode' | 'expect' | 'action' | 'resource'>;
  passed: boolean;
  evaluated: number;
  /** Subjects beyond the evaluation cap (500) were not checked. */
  truncated: boolean;
  violations: InvariantViolation[];
  /** Set when the invariant could not be evaluated (its resource or group no longer exists, for example). */
  error?: { code: string; message: string };
}

const maxSubjects = 500;

/** Operations that can change who may do what; enforced invariants are re-checked around them. */
const accessChangingActions = new Set(
  [
    'roles:update',
    'roles:delete',
    'policies:update',
    'policies:delete',
    'bindings:create',
    'bindings:delete',
    'bindings:activate',
    'bindings:approve',
    'groups:update',
    'groups:delete',
    'identities:create',
    'identities:update',
    'packages:update',
    'packages:assign',
    'packages:approve',
    'config:apply',
    'access-requests:review',
    'relationships:create',
    'relationships:delete',
    'resources:update',
    'boundaries:update',
    'authorities:revoke',
    'resources:delete',
    'root:grant',
    // Closing a campaign removes revoked bindings.
    'certifications:manage',
    // Required agreements feed principal.pendingAgreements, which policies may deny on.
    'agreements:manage',
    // Required onboarding flows feed principal.pendingOnboarding the same way.
    'onboarding:manage',
    // roleMining.apply moves grants between bindings.
    'analysis:update',
    // Temporary credentials: issuing one, and the trusts and OIDC providers that admit role sessions. Revoking
    // sessions or trusts only removes access, and the public web-identity exchange is authorised by its trust.
    'roles:assume',
    'trust:create',
    'trust:update',
    'session-tokens:create',
    'oidc-providers:create',
    'oidc-providers:update',
    // Teams fill their backing groups (and principal.teams); departments feed principal.departments.
    'teams:create',
    'teams:update',
    'teams:delete',
    'departments:manage',
    // Packages are created with their contents (their rule-driven grants are checked where the rules apply them).
    'packages:create',
    // Feature flags feed tenant.features, and spend feeds principal.spendExceeded, both of which policies test.
    'features:manage',
    'features:override',
    'billing:manage',
  ].map((action) => `iam:${action}`),
);

async function subjects(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  subject: InvariantSubject,
): Promise<Identity[]> {
  const live = (identity: Identity | undefined): identity is Identity =>
    identity?.tenantId === tenantId &&
    identity.status === 'active' &&
    !ctx.identityExpired(identity);
  if ('identityId' in subject) {
    const identity = await tx.get<Identity>('identities', subject.identityId);
    if (!identity || identity.tenantId !== tenantId)
      throw new IamError('NOT_FOUND', 'The invariant names an identity that no longer exists', 404);
    return live(identity) ? [identity] : [];
  }
  if ('groupId' in subject) {
    const group = await tx.get('groups', subject.groupId);
    if (!group || group.tenantId !== tenantId)
      throw new IamError('NOT_FOUND', 'The invariant names a group that no longer exists', 404);
    const members = (
      await tx.find<GroupMember>('groupMembers', { tenantId, groupId: subject.groupId })
    ).filter((member) => ctx.liveMembership(member));
    const people: Identity[] = [];
    for (const member of members) {
      const identity = await tx.get<Identity>('identities', member.identityId);
      if (live(identity)) people.push(identity);
    }
    return people;
  }
  const everyone = (await tx.find<Identity>('identities', { tenantId })).filter(live);
  if ('everyone' in subject) return everyone;
  const { name, value } = subject.attribute;
  return everyone.filter(
    (identity) => (identity.attributes as Record<string, Json> | undefined)?.[name] === value,
  );
}

/** Evaluates invariants against the current state of the transaction. */
export async function evaluateInvariants(
  ctx: ServerContext,
  tx: IamStore,
  tenant: Tenant,
  invariants: AccessInvariant[],
  /** Enforcement evaluates every subject; reports stop at `maxSubjects`. */
  options: { unlimited?: boolean } = {},
): Promise<InvariantResult[]> {
  const resources = new Map<string, ResolvedResource>();
  const results: InvariantResult[] = [];
  for (const invariant of invariants) {
    const summary: InvariantResult['invariant'] = {
      id: invariant.id,
      name: invariant.name,
      mode: invariant.mode,
      expect: invariant.expect,
      action: invariant.action,
      resource: invariant.resource,
    };
    try {
      const key = `${invariant.resource.type}/${invariant.resource.id}`;
      let resource = resources.get(key);
      if (!resource) {
        resource = await ctx.decisions.resolve(
          tx,
          { tenantId: tenant.id, type: invariant.resource.type, id: invariant.resource.id },
          true,
        );
        resources.set(key, resource);
      }
      const people = (await subjects(ctx, tx, tenant.id, invariant.subject)).sort((a, b) =>
        a.id.localeCompare(b.id),
      );
      const checked = options.unlimited ? people : people.slice(0, maxSubjects);
      const violations: InvariantViolation[] = [];
      for (const identity of checked) {
        const principal = ctx.decisions.simulatedPrincipal(identity, invariant.assumeMfa);
        const prepared = await ctx.decisions.prepareDecision(
          tx,
          principal,
          tenant,
          invariant.action,
        );
        const decision =
          'fixed' in prepared ? prepared.fixed : prepared.evaluate(resource, invariant.action);
        if (decision.allowed !== (invariant.expect === 'allow'))
          violations.push({
            identity: { id: identity.id, name: identity.email ?? identity.name },
            reason: decision.reason,
          });
      }
      results.push({
        invariant: summary,
        passed: violations.length === 0,
        evaluated: checked.length,
        truncated: people.length > checked.length,
        violations,
      });
    } catch (error) {
      if (!(error instanceof IamError)) throw error;
      results.push({
        invariant: summary,
        passed: false,
        evaluated: 0,
        truncated: false,
        violations: [],
        error: { code: error.code, message: error.message },
      });
    }
  }
  return results;
}

/**
 * The scheduled invariant check: evaluates every invariant of every active tenant (or one `tenantId`), remembers the
 * outcome on the invariant, and records `invariant:broken` when an invariant starts failing or gains violators and
 * `invariant:restored` when it passes again, so monitored invariants reach webhooks and audit exports. A deployment
 * operation: no credential, one transaction per tenant.
 */
export async function checkInvariants(
  ctx: ServerContext,
  input: { tenantId?: string } = {},
): Promise<InvariantCheckResult> {
  const result: InvariantCheckResult = { checked: 0, broken: [], restored: [] };
  const tenantIds = await ctx.store.transaction(async (tx) => {
    const invariants = await tx.find<AccessInvariant>(
      'accessInvariants',
      input.tenantId ? { tenantId: input.tenantId } : {},
    );
    return [...new Set(invariants.map((invariant) => invariant.tenantId))].sort();
  });
  for (const tenantId of tenantIds)
    await ctx.store.transaction(async (tx) => {
      const tenant = await tx.get<Tenant>('tenants', tenantId);
      if (tenant?.status !== 'active') return;
      const invariants = (await tx.find<AccessInvariant>('accessInvariants', { tenantId })).sort(
        (a, b) => a.id.localeCompare(b.id),
      );
      const outcomes = await evaluateInvariants(ctx, tx, tenant, invariants);
      const now = ctx.now();
      for (const [index, invariant] of invariants.entries()) {
        const outcome = outcomes[index]!;
        result.checked++;
        const violations = outcome.violations.map((violation) => violation.identity.id).sort();
        const previous = invariant.lastCheck;
        const known = new Set(previous?.violations ?? []);
        const fresh = violations.filter((identityId) => !known.has(identityId));
        const failedNow = !outcome.passed;
        // Reported once per change: a failure after a pass (or the first check), or new people violating it.
        const newlyBroken = failedNow && (!previous || previous.passed || fresh.length > 0);
        const restored = !failedNow && previous !== undefined && !previous.passed;
        if (newlyBroken) {
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId,
            actorId: 'deployment-operator',
            action: 'invariant:broken',
            resourceId: invariant.id,
            timestamp: now,
            outcome: 'deny',
            metadata: {
              name: invariant.name,
              mode: invariant.mode,
              violations: fresh.length ? fresh : violations,
              ...(outcome.error ? { error: outcome.error.code } : {}),
            },
          });
          result.broken.push({
            tenantId,
            invariantId: invariant.id,
            name: invariant.name,
            violations,
          });
        } else if (restored) {
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId,
            actorId: 'deployment-operator',
            action: 'invariant:restored',
            resourceId: invariant.id,
            timestamp: now,
            outcome: 'allow',
            metadata: { name: invariant.name, mode: invariant.mode },
          });
          result.restored.push({ tenantId, invariantId: invariant.id, name: invariant.name });
        }
        await tx.put<AccessInvariant>('accessInvariants', {
          ...invariant,
          lastCheck: {
            at: now,
            passed: outcome.passed,
            violations,
            ...(outcome.error ? { error: outcome.error.message } : {}),
          },
        });
      }
    });
  return result;
}

const violationKeys = (results: InvariantResult[]) =>
  new Set(
    results.flatMap((result) =>
      result.violations.map((violation) => `${result.invariant.id}:${violation.identity.id}`),
    ),
  );

/** Before an access-changing operation: the enforced invariants and the violations that already exist. */
export async function invariantSnapshot(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  action: string,
): Promise<InvariantSnapshot | undefined> {
  if (!accessChangingActions.has(action)) return undefined;
  const invariants = (await tx.find<AccessInvariant>('accessInvariants', { tenantId })).filter(
    (invariant) => invariant.mode === 'enforce',
  );
  if (!invariants.length) return undefined;
  const tenant = await ctx.tenant(tx, tenantId);
  const results = await evaluateInvariants(ctx, tx, tenant, invariants, { unlimited: true });
  return {
    invariants,
    existing: violationKeys(results),
    unevaluable: new Set(
      results.filter((result) => result.error).map((result) => result.invariant.id),
    ),
  };
}
interface InvariantSnapshot {
  invariants: AccessInvariant[];
  existing: Set<string>;
  /** Invariants that already could not be evaluated before the operation. */
  unevaluable: Set<string>;
}

/** After the operation: refuses (rolling the transaction back) when it newly broke an enforced invariant. */
export async function invariantVerify(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  snapshot: InvariantSnapshot | undefined,
): Promise<void> {
  if (!snapshot) return;
  const tenant = await ctx.tenant(tx, tenantId);
  for (const result of await evaluateInvariants(ctx, tx, tenant, snapshot.invariants, {
    unlimited: true,
  })) {
    // Deleting an invariant's group or resource would otherwise switch enforcement off silently.
    if (result.error && !snapshot.unevaluable.has(result.invariant.id))
      throw new IamError(
        'INVARIANT_VIOLATION',
        `Access invariant "${result.invariant.name}" could no longer be evaluated (${result.error.message}); change or delete the invariant first`,
        409,
      );
    const broken = result.violations.find(
      (violation) => !snapshot.existing.has(`${result.invariant.id}:${violation.identity.id}`),
    );
    if (!broken) continue;
    const { name, expect, action, resource } = result.invariant;
    throw new IamError(
      'INVARIANT_VIOLATION',
      `Access invariant "${name}": ${broken.identity.name} would ${expect === 'deny' ? 'be allowed' : 'no longer be allowed'} ${action} on ${resource.type}/${resource.id}`,
      409,
    );
  }
}
