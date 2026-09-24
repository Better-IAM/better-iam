import {
  IamError,
  fixedPlan,
  intersectPlans,
  planResources,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type ResourcePlan,
  type Tenant,
} from '@better-iam/core';
import { internalResourceTypes, resourceTypeName } from '../catalog.js';
import type { ServerContext } from '../context.js';
import { impersonatingActor } from '../decisions.js';
import { text } from '../validation.js';

/** A plan for one principal, action and resource type. */
export interface ResourcePlanResult extends ResourcePlan {
  tenantId: string;
  action: string;
  type: string;
}

/** A plan request for the caller: the credential and which resources, as `authorize` takes them. */
export interface PlanResourcesRequest extends CredentialInput {
  tenantId: string;
  action: string;
  /** The resource type whose rows are filtered. */
  type: string;
}

function planTarget(input: { action: unknown; type: unknown }): { action: string; type: string } {
  const action = text(input.action, 'action');
  const type = text(input.type, 'type', 64);
  if (!resourceTypeName.test(type) || internalResourceTypes.has(type))
    throw new IamError('INVALID_INPUT', 'Plans cover application and managed resource types');
  // Platform administration (`iam:*`) resolves its own resources; plan application actions only.
  if (action.startsWith('iam:'))
    throw new IamError('INVALID_INPUT', 'Plans cover application actions, not iam:* administration');
  return { action, type };
}

/**
 * The plan for one principal. Mirrors `decisions.decide` for every resource of the type: a fixed decision (root
 * override, inactive tenant, another tenant's session, a revoked delegation) allows everything or nothing, an unknown
 * action nothing, and a delegation that holds the action for the person's confirmation nothing (the few resources
 * confirmed just now are left to `authorize`).
 */
async function principalPlan(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  realm: Tenant,
  action: string,
  type: string,
): Promise<ResourcePlan> {
  if (!(await ctx.catalog.knownAction(tx, realm.id, action))) return fixedPlan(false);
  const prepared = await ctx.decisions.prepareDecision(tx, principal, realm, action);
  if ('fixed' in prepared) return fixedPlan(prepared.fixed.allowed);
  const inputs = prepared.inputs;
  if (!inputs) return fixedPlan(false);
  if (inputs.confirm?.(action, type, '\u0000plan') !== undefined) return fixedPlan(false);
  return planResources({
    action,
    resourceType: type,
    tenantId: realm.id,
    context: inputs.context,
    denies: inputs.denies,
    boundaries: inputs.boundaries,
    paths: inputs.paths.map((path) => ({ grants: path.grants, boundaries: path.boundaries })),
    relations: [...inputs.held].map(([held, relations]) => {
      const slash = held.indexOf('/');
      return { type: held.slice(0, slash), id: held.slice(slash + 1), relations: [...relations] };
    }),
  });
}

/** The caller's plan; a "view as" session gets only what the administrator behind it could reach too. */
async function callerPlan(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  realm: Tenant,
  action: string,
  type: string,
): Promise<ResourcePlan> {
  const own = await principalPlan(ctx, tx, principal, realm, action, type);
  const actor = await impersonatingActor(tx, principal);
  return actor
    ? intersectPlans(own, await principalPlan(ctx, tx, actor, realm, action, type))
    : own;
}

/**
 * Data filtering: which resources of a type may a principal perform an action on, as a filter for the application's
 * own queries (compile it with `filterToSql`, `filterToPrisma`, `filterToMongo`, or test rows with `filterMatches`).
 */
export function createFiltersApi(ctx: ServerContext) {
  return {
    /**
     * The caller's plan for `action` on resources of `type`: `always`, `never`, or `conditional` with a filter over
     * `id` and the resource's attributes. Needs only a session of the tenant; not audited (the resources are still
     * decided by your own queries, and `authorize` remains the check for one resource).
     */
    plan: async (
      credential: CredentialInput,
      input: { tenantId: string; action: string; type: string },
    ): Promise<ResourcePlanResult> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const { action, type } = planTarget(input);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const realm = await ctx.tenant(tx, tenantId);
        return { tenantId: realm.id, action, type, ...(await callerPlan(ctx, tx, principal, realm, action, type)) };
      });
    },

    /**
     * An administrator's preview of another identity's plan, as `policies.simulate` does for one decision: no session
     * is created. `assumeMfa` plans as if the identity had signed in with MFA. Requires iam:policies:simulate on the
     * identity; audited as that action.
     */
    planFor: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; action: string; type: string; assumeMfa?: boolean },
    ): Promise<ResourcePlanResult> => {
      const { action, type } = planTarget(input);
      return ctx.operations.operation(
        credential,
        input.tenantId,
        'iam:policies:simulate',
        text(input.identityId, 'identityId'),
        async ({ tx, tenant: realm }) => {
          const identity = await ctx.scoped<Identity>(tx, 'identities', input.identityId, realm.id);
          if (identity.status === 'deleted') throw new IamError('NOT_FOUND', 'Identity not found', 404);
          const principal = ctx.decisions.simulatedPrincipal(identity, input.assumeMfa === true);
          return {
            tenantId: realm.id,
            action,
            type,
            ...(await principalPlan(ctx, tx, principal, realm, action, type)),
          };
        },
      );
    },
  };
}

/** `iam.planResources`: the caller's plan in process, taking the credential in the request like `iam.authorize`. */
export function createPlanRuntime(ctx: ServerContext) {
  const api = createFiltersApi(ctx);
  return (request: PlanResourcesRequest): Promise<ResourcePlanResult> => {
    const { tenantId, action, type, ...credential } = request;
    // A fixed span name: actions are caller-controlled and would otherwise mint unbounded metric series.
    return ctx.observe.span('listAccessible', 'planResources', tenantId, () =>
      api.plan(credential, { tenantId, action, type }),
    );
  };
}
