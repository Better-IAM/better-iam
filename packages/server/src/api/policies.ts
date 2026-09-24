import {
  IamError,
  evaluatePolicy,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { documentDenyStatements } from '../decisions.js';
import { assertDeniesKept, reliedOnByOthers } from './roles.js';
import {
  enabledFeatureKeys,
  featureContextKey,
  featureState,
  mentionsFeatures,
} from '../features.js';
import type { ActionDefinition, Policy, Role } from '../models.js';
import { byId, id } from '../utils.js';
import { integer, object, strings, text } from '../validation.js';

export interface PolicyInput {
  tenantId: string;
  name: string;
  description?: string;
  document: PolicyDocument;
}
export interface PolicyUpdate {
  tenantId: string;
  policyId: string;
  version: number;
  name?: string;
  description?: string;
  document?: PolicyDocument;
}

/** Creates a policy under the caller's grant authority; shared by `policies.create` and configuration sync. */
export async function createPolicy(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenant: Tenant,
  input: PolicyInput,
): Promise<Policy> {
  await ctx.catalog.validate(tx, input.tenantId, input.document);
  const authority = await ctx.grantingAuthority(tx, principal, input.tenantId);
  await ctx.enforceLimit(
    tx,
    tenant,
    'policies',
    async () => (await tx.find('policies', { tenantId: input.tenantId })).length,
  );
  const policy: Policy = {
    id: id(),
    tenantId: input.tenantId,
    name: text(input.name, 'name'),
    document: input.document,
    version: 1,
    authorityId: authority.id,
  };
  if (input.description !== undefined)
    policy.description = text(input.description, 'description', 512);
  return tx.insert<Policy>('policies', policy);
}

/** Updates a policy as a new version (optimistic concurrency on `version`); the previous version is retained. */
export async function updatePolicy(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  input: PolicyUpdate,
): Promise<Policy> {
  if (input.document !== undefined) await ctx.catalog.validate(tx, input.tenantId, input.document);
  await ctx.grantingAuthority(tx, principal, input.tenantId);
  const policy = await ctx.scoped<Policy>(tx, 'policies', input.policyId, input.tenantId);
  await ctx.canEditGrantResource(tx, principal, policy);
  if (policy.uniqueKey === 'system:owner')
    throw new IamError('PROTECTED_RESOURCE', 'Owner policy is protected', 403);
  if (policy.version !== input.version)
    throw new IamError('VERSION_CONFLICT', 'Policy version changed', 409);
  if (input.document === undefined && input.name === undefined && input.description === undefined)
    throw new IamError('INVALID_INPUT', 'Nothing to update');
  if (input.document !== undefined)
    await assertPolicyDeniesKept(ctx, tx, principal, policy, input.document);
  await tx.insert('policyVersions', {
    ...policy,
    id: id(),
    policyId: policy.id,
    uniqueKey: `${policy.id}:${policy.version}`,
  });
  const next: Policy = {
    ...policy,
    document: input.document ?? policy.document,
    version: policy.version + 1,
  };
  if (input.name !== undefined) next.name = text(input.name, 'name');
  if (input.description !== undefined)
    next.description = text(input.description, 'description', 512);
  return tx.put('policies', next);
}

/**
 * A policy another authority attached to a role (or whose role it inherits or bound) carries denies that authority
 * relies on: its editor may not remove or change one (roles.ts assertDeniesKept).
 */
async function assertPolicyDeniesKept(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  policy: Policy,
  document: PolicyDocument,
): Promise<void> {
  await assertDeniesKept(
    ctx,
    tx,
    principal,
    documentDenyStatements(policy.document),
    documentDenyStatements(document),
    async () =>
      reliedOnByOthers(
        tx,
        policy.tenantId,
        policy.authorityId,
        (await tx.find<Role>('roles', { tenantId: policy.tenantId }))
          .filter((role) => role.policyIds.includes(policy.id))
          .map((role) => role.id),
      ),
  );
}

/** Deletes a policy that no role still attaches; the Owner policy is protected. */
export async function deletePolicy(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  policy: Policy,
): Promise<void> {
  await ctx.canEditGrantResource(tx, principal, policy);
  if (policy.uniqueKey === 'system:owner')
    throw new IamError('PROTECTED_RESOURCE', 'Owner policy is protected', 403);
  if (
    (await tx.find<Role>('roles', { tenantId: policy.tenantId })).some((role) =>
      role.policyIds.includes(policy.id),
    )
  )
    throw new IamError('RESOURCE_IN_USE', 'Detach policy before deletion', 409);
  await tx.delete('policies', policy.id);
}

export function createPoliciesApi(ctx: ServerContext) {
  const { catalog } = ctx;
  const { operation } = ctx.operations;
  return {
    create: (credential: CredentialInput, input: PolicyInput) =>
      operation(
        credential,
        input.tenantId,
        'iam:policies:create',
        input.tenantId,
        ({ tx, principal, tenant }) => createPolicy(ctx, tx, principal, tenant, input),
      ),
    /** Optimistic concurrency: the caller supplies the version it read; previous versions are retained. */
    update: (credential: CredentialInput, input: PolicyUpdate) =>
      operation(
        credential,
        input.tenantId,
        'iam:policies:update',
        input.policyId,
        ({ tx, principal }) => updatePolicy(ctx, tx, principal, input),
      ),
    /** Rolls a policy back to an earlier document as a new version; the old document is re-validated against the catalog. */
    restoreVersion: (
      credential: CredentialInput,
      input: { tenantId: string; policyId: string; version: number },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:policies:update',
        input.policyId,
        async ({ tx, principal }) => {
          const policy = await ctx.scoped<Policy>(tx, 'policies', input.policyId, input.tenantId);
          await ctx.grantingAuthority(tx, principal, input.tenantId);
          await ctx.canEditGrantResource(tx, principal, policy);
          if (policy.uniqueKey === 'system:owner')
            throw new IamError('PROTECTED_RESOURCE', 'Owner policy is protected', 403);
          const version = integer(input.version, 'version', 1, policy.version);
          if (version === policy.version)
            throw new IamError('INVALID_INPUT', 'That version is already current');
          const archived = (
            await tx.find<Policy & { policyId: string }>('policyVersions', {
              tenantId: input.tenantId,
              uniqueKey: `${policy.id}:${version}`,
            })
          )[0];
          if (!archived) throw new IamError('NOT_FOUND', 'Policy version not found', 404);
          await catalog.validate(tx, input.tenantId, archived.document);
          await assertPolicyDeniesKept(ctx, tx, principal, policy, archived.document);
          await tx.insert('policyVersions', {
            ...policy,
            id: id(),
            policyId: policy.id,
            uniqueKey: `${policy.id}:${policy.version}`,
          });
          return tx.put('policies', {
            ...policy,
            document: archived.document,
            version: policy.version + 1,
          });
        },
      ),
    /**
     * Evaluates a candidate document (not stored) against an action, a resource string, and a caller-supplied context,
     * for policy editors. Requires iam:policies:simulate. The document is validated against the catalog first.
     */
    test: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        document: PolicyDocument;
        action: string;
        resource: string;
        context?: Record<string, unknown>;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:policies:simulate',
        input.tenantId,
        async ({ tx, tenant }) => {
          await catalog.validate(tx, tenant.id, input.document);
          const context = { ...object(input.context ?? {}) };
          if (Object.keys(context).length > 200)
            throw new IamError('INVALID_INPUT', 'context may hold at most 200 keys');
          const now = new Date(ctx.now()).toISOString();
          return evaluatePolicy({
            action: text(input.action, 'action'),
            resource: text(input.resource, 'resource', 2048),
            grants: [input.document],
            // Defaults for the always-present server keys, as a synthetic session issued now would carry them;
            // the caller's context overrides any of them.
            context: {
              'resource.tenantId': tenant.id,
              'principal.tenantId': tenant.id,
              'principal.sessionId': 'simulation',
              'principal.tokenIssueTime': now,
              'principal.authTime': now,
              'principal.sessionTagKeys': [],
              'principal.delegated': false,
              // Threat detection keys as for a person nothing was detected about (threats.ts).
              'principal.riskLevel': 'none',
              'principal.riskScore': 0,
              // Device posture keys as for a request without a verified device (devices.ts).
              'request.deviceAssurance': 'none',
              'request.deviceManaged': false,
              'request.deviceCompliant': false,
              'request.time': now,
              // The tenant's feature flags as they are now, read only when the document names them.
              ...(mentionsFeatures([input.document])
                ? {
                    [featureContextKey]: enabledFeatureKeys(
                      await featureState(tx, await ctx.ancestry(tx, tenant), ctx.now()),
                    ),
                  }
                : {}),
              ...context,
            },
          });
        },
      ),
    get: (credential: CredentialInput, input: { tenantId: string; policyId: string }) =>
      operation(credential, input.tenantId, 'iam:policies:read', input.policyId, ({ tx }) =>
        ctx.scoped<Policy>(tx, 'policies', input.policyId, input.tenantId),
      ),
    listVersions: (credential: CredentialInput, input: { tenantId: string; policyId: string }) =>
      operation(credential, input.tenantId, 'iam:policies:read', input.policyId, async ({ tx }) => {
        const policy = await ctx.scoped<Policy>(tx, 'policies', input.policyId, input.tenantId);
        const versions = (
          await tx.find<Policy & { policyId: string }>('policyVersions', {
            tenantId: input.tenantId,
            policyId: policy.id,
          })
        ).map(({ uniqueKey: _key, ...version }) => version as Policy);
        return [...versions, policy].sort((a, b) => a.version - b.version);
      }),
    list: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:policies:read', input.tenantId, ({ tx }) =>
        tx.find<Policy>('policies', { tenantId: input.tenantId }),
      ),
    delete: (credential: CredentialInput, input: { tenantId: string; policyId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:policies:delete',
        input.policyId,
        async ({ tx, principal }) => {
          const policy = await ctx.scoped<Policy>(tx, 'policies', input.policyId, input.tenantId);
          await deletePolicy(ctx, tx, principal, policy);
          return { deleted: true };
        },
      ),
    /** Administrator-only explanation of a decision for any identity; it creates no session and grants nothing. `assumeMfa` simulates an MFA session. */
    simulate: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        identityId: string;
        action: string;
        resource: { type: string; id: string };
        assumeMfa?: boolean;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:policies:simulate',
        input.identityId,
        async ({ tx }) => {
          const identity = await ctx.scoped<Identity>(
            tx,
            'identities',
            input.identityId,
            input.tenantId,
          );
          return ctx.decisions.decide(
            tx,
            ctx.decisions.simulatedPrincipal(identity, input.assumeMfa === true),
            input,
          );
        },
      ),
    /**
     * Access review: every active identity of the tenant that could perform `action` on `resource`, with the reason.
     * Root administrators are not listed because their override applies everywhere. Advisory, like `simulate`.
     */
    whoCan: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        action: string;
        resource: { type: string; id: string };
        kind?: 'user' | 'service';
        assumeMfa?: boolean;
        limit?: number;
        offset?: number;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:policies:simulate',
        input.tenantId,
        async ({ tx, tenant }) => {
          const action = text(input.action, 'action');
          if (!(await catalog.knownAction(tx, tenant.id, action)))
            throw new IamError('INVALID_ACTION', `Unknown action ${action}`);
          const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
          const offset = integer(input.offset ?? 0, 'offset', 0, 1000000);
          if (input.kind !== undefined && !['user', 'service'].includes(input.kind))
            throw new IamError('INVALID_INPUT', 'kind must be user or service');
          const reference = object(input.resource);
          // Reviews accept platform resources (`iam/...`) as well as catalog resources.
          const resource = await ctx.decisions.resolve(
            tx,
            {
              tenantId: tenant.id,
              type: text(reference.type, 'resource type'),
              id: text(reference.id, 'resource id'),
            },
            true,
          );
          const filter: Record<string, unknown> = { tenantId: tenant.id, status: 'active' };
          if (input.kind !== undefined) filter.kind = input.kind;
          const identities = (await tx.find<Identity>('identities', filter)).sort(byId);
          const matches: ReviewMatch[] = [];
          for (const identity of identities) {
            const principal = ctx.decisions.simulatedPrincipal(identity, input.assumeMfa === true);
            const prepared = await ctx.decisions.prepareDecision(tx, principal, tenant, action);
            const decision = 'fixed' in prepared ? prepared.fixed : prepared.evaluate(resource);
            if (decision.allowed)
              matches.push({
                identityId: identity.id,
                name: identity.name,
                email: identity.email,
                kind: identity.kind,
                reason: decision.reason,
              });
          }
          return { identities: matches.slice(offset, offset + limit), total: matches.length };
        },
      ),
    /**
     * Access review: which catalog actions (or the given `actions`) an identity could perform on one resource.
     * Grants are loaded once and evaluated per action. Advisory, like `simulate`.
     */
    effectiveActions: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        identityId: string;
        resource: { type: string; id: string };
        actions?: string[];
        assumeMfa?: boolean;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:policies:simulate',
        input.identityId,
        async ({ tx, tenant }) => {
          const identity = await ctx.scoped<Identity>(
            tx,
            'identities',
            input.identityId,
            tenant.id,
          );
          const reference = object(input.resource);
          // Reviews accept platform resources (`iam/...`) as well as catalog resources.
          const resource = await ctx.decisions.resolve(
            tx,
            {
              tenantId: tenant.id,
              type: text(reference.type, 'resource type'),
              id: text(reference.id, 'resource id'),
            },
            true,
          );
          let candidates: string[];
          if (input.actions !== undefined) {
            candidates = [...new Set(strings(input.actions, 'actions'))];
            if (candidates.length > 200)
              throw new IamError('INVALID_INPUT', 'Review at most 200 actions at once');
            for (const action of candidates)
              if (!(await catalog.knownAction(tx, tenant.id, action)))
                throw new IamError('INVALID_ACTION', `Unknown action ${action}`);
          } else {
            const tenantActions = await tx.find<ActionDefinition>('actions', {
              tenantId: tenant.id,
            });
            candidates = [...catalog.actions, ...tenantActions.map((item) => item.name)];
          }
          candidates.sort();
          const principal = ctx.decisions.simulatedPrincipal(identity, input.assumeMfa === true);
          const prepared = await ctx.decisions.prepareDecision(
            tx,
            principal,
            tenant,
            candidates[0] ?? '*',
          );
          const results = candidates.map((action) => {
            const decision =
              'fixed' in prepared ? prepared.fixed : prepared.evaluate(resource, action);
            return { action, allowed: decision.allowed, reason: decision.reason };
          });
          return {
            allowed: results.filter((item) => item.allowed).map((item) => item.action),
            results,
          };
        },
      ),
  };
}

export interface ReviewMatch {
  identityId: string;
  name: string;
  email?: string;
  kind: Identity['kind'];
  reason: string;
}
