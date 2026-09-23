import { IamError, type CredentialInput, type IamStore } from '@better-iam/core';
import type { ServerContext } from '../context.js';
import {
  evaluateInvariants,
  type AccessInvariant,
  type InvariantResult,
  type InvariantSubject,
} from '../invariants.js';
import { id } from '../utils.js';
import { object, text } from '../validation.js';

export interface InvariantInput {
  name: string;
  description?: string;
  subject: InvariantSubject;
  action: string;
  resource: { type: string; id: string };
  expect: 'allow' | 'deny';
  mode?: 'enforce' | 'monitor';
  assumeMfa?: boolean;
}
export interface InvariantRunResult {
  generatedAt: number;
  summary: { passed: number; failed: number; errors: number };
  results: InvariantResult[];
}

const maxInvariants = 100;

/** The stored fields `create` and `update` derive from input (Omit over StoredRecord types loses them). */
interface InvariantFields {
  tenantId: string;
  uniqueKey: string;
  name: string;
  description?: string;
  subject: InvariantSubject;
  action: string;
  resource: { type: string; id: string };
  expect: 'allow' | 'deny';
  mode: 'enforce' | 'monitor';
  assumeMfa: boolean;
  updatedAt: number;
}

async function validSubject(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  value: unknown,
): Promise<InvariantSubject> {
  const subject = object(value);
  const keys = Object.keys(subject);
  if (keys.length !== 1)
    throw new IamError(
      'INVALID_INPUT',
      'subject must be exactly one of identityId, groupId, attribute, or everyone',
    );
  if (subject.identityId !== undefined) {
    const identityId = text(subject.identityId, 'subject.identityId');
    await ctx.scoped(tx, 'identities', identityId, tenantId);
    return { identityId };
  }
  if (subject.groupId !== undefined) {
    const groupId = text(subject.groupId, 'subject.groupId');
    await ctx.scoped(tx, 'groups', groupId, tenantId);
    return { groupId };
  }
  if (subject.everyone !== undefined) {
    if (subject.everyone !== true)
      throw new IamError('INVALID_INPUT', 'subject.everyone must be true');
    return { everyone: true };
  }
  if (subject.attribute !== undefined) {
    const attribute = object(subject.attribute);
    const name = text(attribute.name, 'subject.attribute.name');
    const type = ctx.catalog.identityAttributes[name];
    if (!type) throw new IamError('INVALID_INPUT', `Unknown identity attribute ${name}`);
    if (typeof attribute.value !== type)
      throw new IamError('INVALID_INPUT', `subject.attribute.value must be a ${type}`);
    return { attribute: { name, value: attribute.value as string | number | boolean } };
  }
  throw new IamError(
    'INVALID_INPUT',
    'subject must be exactly one of identityId, groupId, attribute, or everyone',
  );
}

/**
 * Creates (without `previous`) or updates an invariant after validating it like the API does; shared by the
 * `invariants` API and configuration apply. `actorId` is recorded as the creator.
 */
export async function saveInvariant(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  input: Partial<InvariantInput>,
  actorId: string,
  previous?: AccessInvariant,
): Promise<AccessInvariant> {
  const fields = await build(ctx, tx, tenantId, input, previous);
  const clash = (await tx.find<AccessInvariant>('accessInvariants', { tenantId })).filter(
    (invariant) => invariant.id !== previous?.id,
  );
  if (clash.some((invariant) => invariant.uniqueKey === fields.uniqueKey))
    throw new IamError('CONFLICT', 'An invariant with this name exists', 409);
  if (previous) {
    const { description: _description, ...kept } = previous;
    return tx.put<AccessInvariant>('accessInvariants', { ...kept, ...fields });
  }
  if (clash.length >= maxInvariants)
    throw new IamError('LIMIT_EXCEEDED', `At most ${maxInvariants} invariants`, 409);
  return tx.insert<AccessInvariant>('accessInvariants', {
    ...fields,
    id: id(),
    createdBy: actorId,
    createdAt: fields.updatedAt,
  });
}

async function build(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  input: Partial<InvariantInput>,
  previous?: AccessInvariant,
): Promise<InvariantFields> {
  const name = text(input.name ?? previous?.name, 'name', 100).trim();
  if (!name) throw new IamError('INVALID_INPUT', 'name is required');
  const action = text(input.action ?? previous?.action, 'action');
  if (!(await ctx.catalog.knownAction(tx, tenantId, action)))
    throw new IamError('INVALID_ACTION', `Unknown action ${action}`);
  const rawResource = object(input.resource ?? previous?.resource);
  const resource = {
    type: text(rawResource.type, 'resource type'),
    id: text(rawResource.id, 'resource id'),
  };
  // The resource must resolve now; an invariant over a resource that does not exist would never evaluate.
  await ctx.decisions.resolve(tx, { tenantId, ...resource }, true);
  const expect = input.expect ?? previous?.expect;
  if (expect !== 'allow' && expect !== 'deny')
    throw new IamError('INVALID_INPUT', 'expect must be allow or deny');
  const mode = input.mode ?? previous?.mode ?? 'monitor';
  if (mode !== 'enforce' && mode !== 'monitor')
    throw new IamError('INVALID_INPUT', 'mode must be enforce or monitor');
  const assumeMfa = input.assumeMfa ?? previous?.assumeMfa ?? true;
  if (typeof assumeMfa !== 'boolean')
    throw new IamError('INVALID_INPUT', 'assumeMfa must be a boolean');
  const description =
    input.description === undefined
      ? previous?.description
      : input.description === ''
        ? undefined
        : text(input.description, 'description', 500);
  return {
    tenantId,
    uniqueKey: `name:${name.toLowerCase()}`,
    name,
    ...(description ? { description } : {}),
    subject: await validSubject(ctx, tx, tenantId, input.subject ?? previous?.subject),
    action,
    resource,
    expect,
    mode,
    assumeMfa,
    updatedAt: ctx.now(),
  };
}

/**
 * Access invariants (guardrails): assertions about who may or must never perform an action on a resource, checked
 * by `run` and, in `enforce` mode, around every operation that changes access, so a role edit, binding, group change,
 * package assignment, or configuration apply that would newly break one is refused with `INVARIANT_VIOLATION`.
 * Invariants already broken when enforcement starts are reported but do not block unrelated changes. Reading needs
 * `iam:invariants:read`; changing them needs `iam:invariants:manage`.
 */
export function createInvariantsApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  return {
    /** Creates an invariant (default mode `monitor`) and returns it with its current result. */
    create: async (credential: CredentialInput, input: InvariantInput & { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:invariants:manage',
        input.tenantId,
        async ({ tx, tenant, principal }) => {
          const invariant = await saveInvariant(ctx, tx, tenant.id, input, principal.identity.id);
          const [result] = await evaluateInvariants(ctx, tx, tenant, [invariant]);
          return { invariant, result: result! };
        },
      ),
    /** Changes any field; switching to `enforce` is allowed even while the invariant is broken. */
    update: async (
      credential: CredentialInput,
      input: Partial<InvariantInput> & { tenantId: string; invariantId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:invariants:manage',
        text(input.invariantId, 'invariantId'),
        async ({ tx, tenant, principal }) => {
          const previous = await ctx.scoped<AccessInvariant>(
            tx,
            'accessInvariants',
            input.invariantId,
            tenant.id,
          );
          const invariant = await saveInvariant(
            ctx,
            tx,
            tenant.id,
            input,
            principal.identity.id,
            previous,
          );
          const [result] = await evaluateInvariants(ctx, tx, tenant, [invariant]);
          return { invariant, result: result! };
        },
      ),
    delete: async (credential: CredentialInput, input: { tenantId: string; invariantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:invariants:manage',
        text(input.invariantId, 'invariantId'),
        async ({ tx, tenant }) => {
          const invariant = await ctx.scoped<AccessInvariant>(
            tx,
            'accessInvariants',
            input.invariantId,
            tenant.id,
          );
          await tx.delete('accessInvariants', invariant.id);
          return { deleted: true };
        },
      ),
    list: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:invariants:read',
        input.tenantId,
        async ({ tx, tenant }) =>
          (await tx.find<AccessInvariant>('accessInvariants', { tenantId: tenant.id })).sort(
            (a, b) => a.name.localeCompare(b.name),
          ),
      ),
    /** Evaluates every invariant (or one) against the current configuration. */
    run: async (
      credential: CredentialInput,
      input: { tenantId: string; invariantId?: string },
    ): Promise<InvariantRunResult> =>
      operation(
        credential,
        input.tenantId,
        'iam:invariants:read',
        input.invariantId === undefined ? input.tenantId : text(input.invariantId, 'invariantId'),
        async ({ tx, tenant }) => {
          const invariants =
            input.invariantId === undefined
              ? (await tx.find<AccessInvariant>('accessInvariants', { tenantId: tenant.id })).sort(
                  (a, b) => a.name.localeCompare(b.name),
                )
              : [
                  await ctx.scoped<AccessInvariant>(
                    tx,
                    'accessInvariants',
                    input.invariantId,
                    tenant.id,
                  ),
                ];
          const results = await evaluateInvariants(ctx, tx, tenant, invariants);
          const summary = { passed: 0, failed: 0, errors: 0 };
          for (const result of results)
            if (result.error) summary.errors++;
            else if (result.passed) summary.passed++;
            else summary.failed++;
          return { generatedAt: ctx.now(), summary, results };
        },
      ),
  };
}
