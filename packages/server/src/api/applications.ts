import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type Tenant,
} from '@better-iam/core';
import {
  appAccess,
  appHolders,
  appKey,
  appsFor,
  appUrl,
  localDeployment,
  type AppAssignment,
  type AppLaunch,
  type Application,
} from '../applications.js';
import type { ServerContext } from '../context.js';
import type { AccessPackage, Group } from '../models.js';
import { actsInOwnRight } from '../session-kinds.js';
import { id } from '../utils.js';
import { integer, strings, text } from '../validation.js';

export interface ApplicationInput {
  key: string;
  name: string;
  description?: string;
  category?: string;
  launchUrl: string;
  logoUrl?: string;
  oauthClientId?: string;
  visibility?: 'everyone' | 'assigned';
  enabled?: boolean;
  requestPackageId?: string;
  ownerIds?: string[];
}
/** An app on the person's launcher. */
export interface MyApp {
  id: string;
  key: string;
  name: string;
  description?: string;
  category?: string;
  logoUrl?: string;
  /** Why the person has it: an everyone app, assigned to them, or through a group. */
  via?: 'everyone' | 'direct' | 'group';
  lastLaunchedAt?: number;
  /** Apps the person does not have yet but may request, through this access package. */
  requestPackageId?: string;
}
export interface ApplicationUsage {
  appId: string;
  key: string;
  name: string;
  /** People who can launch it now. */
  people: number;
  launchedLast30Days: number;
  /** People assigned directly who have not launched it within `unusedDays` (or never). */
  unused: Array<{
    assignmentId: string;
    identityId: string;
    /** Only for callers who may read the directory (`iam:identities:read`). */
    name?: string;
    lastLaunchedAt?: number;
  }>;
}
/** An assignment as `listAssignments` returns it. */
export type AssignmentView = AppAssignment & {
  /** The group's name, or the person's address for callers who may read the directory. */
  subjectName?: string;
  lastLaunchedAt?: number;
};

const maxApps = 500;
const maxAssignmentsPerApp = 10_000;
const nameText = (value: unknown, name: string, max: number) => text(value, name, max).trim();

function selfSession(principal: AuthenticatedPrincipal, tenantId: string): void {
  if (
    !actsInOwnRight(principal.session) ||
    principal.session.kind !== 'user' ||
    principal.session.tenantId !== tenantId ||
    principal.identity.tenantId !== tenantId ||
    principal.identity.kind !== 'user'
  )
    throw new IamError(
      'ACCESS_DENIED',
      'The launcher is for people signed in to their organization',
      403,
    );
}

async function appFields(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  input: Partial<ApplicationInput>,
  previous?: Application,
) {
  const key = previous ? previous.key : appKey(input.key);
  if (previous && input.key !== undefined && input.key !== previous.key)
    throw new IamError('INVALID_INPUT', 'An app key cannot change');
  const allowLocal = localDeployment(ctx.options.baseURL);
  const oauthClientId =
    input.oauthClientId === undefined
      ? previous?.oauthClientId
      : input.oauthClientId === null || input.oauthClientId === ''
        ? undefined
        : text(input.oauthClientId, 'oauthClientId', 256);
  if (oauthClientId !== undefined && oauthClientId !== previous?.oauthClientId) {
    const client = (await tx.find('oauthClients', { tenantId, clientId: oauthClientId }))[0];
    if (!client || client.revoked === true)
      throw new IamError(
        'INVALID_INPUT',
        'oauthClientId must name an OAuth client of this organization',
      );
    // One app per client: two would make whether someone may sign in depend on which one is found first.
    const other = (await tx.find<Application>('applications', { tenantId })).find(
      (app) => app.oauthClientId === oauthClientId && app.id !== previous?.id,
    );
    if (other)
      throw new IamError('CONFLICT', `App ${other.key} already governs this OAuth client`, 409);
  }
  const requestPackageId =
    input.requestPackageId === undefined
      ? previous?.requestPackageId
      : input.requestPackageId === null || input.requestPackageId === ''
        ? undefined
        : text(input.requestPackageId, 'requestPackageId');
  if (requestPackageId !== undefined && requestPackageId !== previous?.requestPackageId) {
    const pkg = await ctx.scoped<AccessPackage>(tx, 'accessPackages', requestPackageId, tenantId);
    if (!pkg.requestable)
      throw new IamError(
        'INVALID_INPUT',
        'requestPackageId must name a package members may request',
      );
  }
  // Owners are checked when they are set; an owner deleted later never blocks editing (or disabling) the app.
  let ownerIds = previous?.ownerIds ?? [];
  if (input.ownerIds !== undefined) {
    ownerIds = [...new Set(strings(input.ownerIds, 'ownerIds'))];
    if (ownerIds.length > 20) throw new IamError('INVALID_INPUT', 'At most 20 owners');
    for (const ownerId of ownerIds) await ctx.activeIdentity(tx, ownerId, tenantId);
  }
  const visibility = input.visibility ?? previous?.visibility ?? 'assigned';
  if (visibility !== 'everyone' && visibility !== 'assigned')
    throw new IamError('INVALID_INPUT', "visibility must be 'everyone' or 'assigned'");
  const enabled = input.enabled ?? previous?.enabled ?? true;
  if (typeof enabled !== 'boolean')
    throw new IamError('INVALID_INPUT', 'enabled must be a boolean');
  const optional = (value: unknown, prior: string | undefined, name: string, max: number) =>
    value === undefined
      ? prior
      : value === null || value === ''
        ? undefined
        : nameText(value, name, max);
  const description = optional(input.description, previous?.description, 'description', 1000);
  const category = optional(input.category, previous?.category, 'category', 60);
  const logoUrl =
    input.logoUrl === undefined
      ? previous?.logoUrl
      : input.logoUrl === null || input.logoUrl === ''
        ? undefined
        : appUrl(input.logoUrl, 'logoUrl', allowLocal);
  const launchUrl =
    input.launchUrl === undefined && previous
      ? previous.launchUrl
      : appUrl(input.launchUrl, 'launchUrl', allowLocal);
  return {
    uniqueKey: `key:${key}`,
    key,
    name: nameText(input.name ?? previous?.name, 'name', 120),
    ...(description ? { description } : {}),
    ...(category ? { category } : {}),
    launchUrl,
    ...(logoUrl ? { logoUrl } : {}),
    kind: oauthClientId ? ('oidc' as const) : ('link' as const),
    ...(oauthClientId ? { oauthClientId } : {}),
    visibility,
    enabled,
    ...(requestPackageId ? { requestPackageId } : {}),
    ownerIds,
  };
}

/** What an audit event records about an app's state. */
const appState = (app: Application): Record<string, Json> => ({
  name: app.name,
  launchUrl: app.launchUrl,
  visibility: app.visibility,
  enabled: app.enabled,
  ...(app.oauthClientId ? { oauthClientId: app.oauthClientId } : {}),
  ...(app.requestPackageId ? { requestPackageId: app.requestPackageId } : {}),
});

/**
 * The application catalog and the "My apps" launcher. Administrators register apps (an OAuth client of this
 * deployment, or a link to any tool) and assign them to people and groups (`iam:applications:manage`,
 * `iam:applications:assign`, reading `iam:applications:read`); people see and launch their apps, and request the ones
 * they lack, without a permission. For an OpenID Connect app the OAuth provider enforces the assignment
 * (`iam.protocolHost.clientAllowed`); `check` (and `iam.applications.allowed`) answers the same question for other
 * sign-in pages. People's names and addresses appear only for callers who may read the directory.
 */
export function createApplicationsApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  /** May the caller see people's names and addresses (`iam:identities:read`)? */
  const directory = async (tx: IamStore, principal: AuthenticatedPrincipal, tenantId: string) =>
    (
      await ctx.decisions.decide(
        tx,
        principal,
        { tenantId, action: 'iam:identities:read', resource: { type: 'iam', id: tenantId } },
        true,
      )
    ).allowed;
  const audit = (
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    action: string,
    tenantId: string,
    resourceId: string,
    metadata: Record<string, Json>,
  ) => ctx.events.audit(tx, principal, action, tenantId, resourceId, 'allow', false, metadata);
  /** Governing a client stops only on purpose: without the app, everyone of the tenant may sign in to it. */
  const assertReleased = (app: Application, releaseClient: unknown) => {
    if (app.oauthClientId && releaseClient !== true)
      throw new IamError(
        'CONFLICT',
        `${app.name} decides who may sign in to OAuth client ${app.oauthClientId}; without it everyone of the organization may. Pass releaseClient: true to confirm.`,
        409,
      );
  };
  return {
    /** Registers an app. Audited as `app:create`. */
    create: async (credential: CredentialInput, input: ApplicationInput & { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:applications:manage',
        input.tenantId,
        async ({ tx, tenant, principal }) => {
          if (input.launchUrl === undefined || input.launchUrl === null || input.launchUrl === '')
            throw new IamError('INVALID_INPUT', 'launchUrl is required');
          const values = await appFields(ctx, tx, tenant.id, input);
          const existing = await tx.find<Application>('applications', { tenantId: tenant.id });
          if (existing.some((app) => app.uniqueKey === values.uniqueKey))
            throw new IamError('CONFLICT', 'An app with this key exists', 409);
          if (existing.length >= maxApps)
            throw new IamError('LIMIT_EXCEEDED', `At most ${maxApps} apps`, 409);
          const now = ctx.now();
          const app = await tx.insert<Application>('applications', {
            ...values,
            id: id(),
            tenantId: tenant.id,
            createdAt: now,
            updatedAt: now,
          });
          await audit(tx, principal, 'app:create', tenant.id, app.id, {
            key: app.key,
            ...appState(app),
          });
          return app;
        },
      ),
    /**
     * Changes an app. Clearing `oauthClientId` needs `releaseClient: true` (the client stops being governed). Audited
     * as `app:update` with the state before and after.
     */
    update: async (
      credential: CredentialInput,
      input: Partial<ApplicationInput> & {
        tenantId: string;
        appId: string;
        releaseClient?: boolean;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:applications:manage',
        text(input.appId, 'appId'),
        async ({ tx, tenant, principal }) => {
          const previous = await ctx.scoped<Application>(
            tx,
            'applications',
            input.appId,
            tenant.id,
          );
          const values = await appFields(ctx, tx, tenant.id, input, previous);
          if (previous.oauthClientId && values.oauthClientId !== previous.oauthClientId)
            assertReleased(previous, input.releaseClient);
          const {
            description: _description,
            category: _category,
            logoUrl: _logo,
            oauthClientId: _client,
            requestPackageId: _package,
            ...kept
          } = previous;
          const app = await tx.put<Application>('applications', {
            ...kept,
            ...values,
            updatedAt: ctx.now(),
          });
          await audit(tx, principal, 'app:update', tenant.id, app.id, {
            key: app.key,
            before: appState(previous),
            after: appState(app),
          });
          return app;
        },
      ),
    /**
     * Deletes an app with its assignments and launch history. An app that governs an OAuth client needs
     * `releaseClient: true`: afterwards everyone of the organization may sign in to that client (disable the app to
     * keep refusing). Audited as `app:delete`.
     */
    delete: async (
      credential: CredentialInput,
      input: { tenantId: string; appId: string; releaseClient?: boolean },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:applications:manage',
        text(input.appId, 'appId'),
        async ({ tx, tenant, principal }) => {
          const app = await ctx.scoped<Application>(tx, 'applications', input.appId, tenant.id);
          assertReleased(app, input.releaseClient);
          for (const collection of ['appAssignments', 'appLaunches'])
            for (const row of await tx.find(collection, { tenantId: tenant.id, appId: app.id }))
              await tx.delete(collection, row.id);
          await tx.delete('applications', app.id);
          await audit(tx, principal, 'app:delete', tenant.id, app.id, {
            key: app.key,
            ...appState(app),
          });
          return { deleted: true };
        },
      ),
    list: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:applications:read',
        input.tenantId,
        async ({ tx, tenant }) => {
          const now = ctx.now();
          const assignments = await tx.find<AppAssignment>('appAssignments', {
            tenantId: tenant.id,
          });
          const launches = await tx.find<AppLaunch>('appLaunches', { tenantId: tenant.id });
          return (await tx.find<Application>('applications', { tenantId: tenant.id }))
            .sort((a, b) => a.name.localeCompare(b.name))
            .map((app) => ({
              ...app,
              assignments: assignments.filter(
                (assignment) =>
                  assignment.appId === app.id &&
                  (assignment.expiresAt === undefined || assignment.expiresAt > now),
              ).length,
              launchedLast30Days: launches.filter(
                (launch) => launch.appId === app.id && launch.lastAt > now - 30 * 86_400_000,
              ).length,
            }));
        },
      ),
    /** Gives an app to a person or a group, optionally until `expiresAt`. Audited as `app:assign`. */
    assign: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        appId: string;
        subjectType: 'identity' | 'group';
        subjectId: string;
        expiresAt?: number;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:applications:assign',
        text(input.appId, 'appId'),
        async ({ tx, tenant, principal }) => {
          const app = await ctx.scoped<Application>(tx, 'applications', input.appId, tenant.id);
          if (input.subjectType !== 'identity' && input.subjectType !== 'group')
            throw new IamError('INVALID_INPUT', "subjectType must be 'identity' or 'group'");
          const subjectId = text(input.subjectId, 'subjectId');
          if (input.subjectType === 'identity') {
            const identity = await ctx.activeIdentity(tx, subjectId, tenant.id);
            if (identity.kind !== 'user')
              throw new IamError('INVALID_INPUT', 'Apps are assigned to people and groups');
          } else await ctx.scoped<Group>(tx, 'groups', subjectId, tenant.id);
          const expiresAt =
            input.expiresAt === undefined ? undefined : ctx.bindingExpiry(input.expiresAt);
          const uniqueKey = `${app.id}:${input.subjectType}:${subjectId}`;
          const existing = (
            await tx.find<AppAssignment>('appAssignments', { tenantId: tenant.id, uniqueKey })
          )[0];
          if (
            !existing &&
            (await tx.find('appAssignments', { tenantId: tenant.id, appId: app.id })).length >=
              maxAssignmentsPerApp
          )
            throw new IamError(
              'LIMIT_EXCEEDED',
              `At most ${maxAssignmentsPerApp} assignments per app; assign groups instead`,
              409,
            );
          const now = ctx.now();
          const assignment: AppAssignment = {
            id: existing?.id ?? id(),
            tenantId: tenant.id,
            uniqueKey,
            appId: app.id,
            subjectType: input.subjectType,
            subjectId,
            assignedBy: principal.identity.id,
            assignedAt: now,
            ...(expiresAt !== undefined ? { expiresAt } : {}),
          };
          await (existing
            ? tx.put('appAssignments', assignment)
            : tx.insert('appAssignments', assignment));
          await audit(tx, principal, 'app:assign', tenant.id, app.id, {
            key: app.key,
            subjectType: input.subjectType,
            subjectId,
            ...(expiresAt !== undefined ? { expiresAt } : {}),
          });
          return assignment;
        },
      ),
    /** Removes one assignment; authorized on its app, like `assign`. Audited as `app:unassign`. */
    unassign: async (
      credential: CredentialInput,
      input: { tenantId: string; assignmentId: string },
    ) => {
      const assignmentId = text(input.assignmentId, 'assignmentId');
      // Authorized on the assignment's app (per-app administrators), or on the ID itself when there is no such record.
      const found = await ctx.store.get<AppAssignment>('appAssignments', assignmentId);
      const resourceId = found?.tenantId === input.tenantId ? found.appId : assignmentId;
      return operation(
        credential,
        input.tenantId,
        'iam:applications:assign',
        resourceId,
        async ({ tx, tenant, principal }) => {
          const assignment = await ctx.scoped<AppAssignment>(
            tx,
            'appAssignments',
            assignmentId,
            tenant.id,
          );
          if (assignment.appId !== resourceId)
            throw new IamError('CONFLICT', 'The assignment changed; try again', 409);
          await tx.delete('appAssignments', assignment.id);
          await audit(tx, principal, 'app:unassign', tenant.id, assignment.appId, {
            subjectType: assignment.subjectType,
            subjectId: assignment.subjectId,
          });
          return { removed: true };
        },
      );
    },
    /** Assignments of one app, or of every app when `appId` is left out (one call for a catalog page). */
    listAssignments: async (
      credential: CredentialInput,
      input: { tenantId: string; appId?: string },
    ): Promise<AssignmentView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:applications:read',
        input.appId === undefined ? input.tenantId : text(input.appId, 'appId'),
        async ({ tx, tenant, principal }) => {
          const app =
            input.appId === undefined
              ? undefined
              : await ctx.scoped<Application>(tx, 'applications', input.appId, tenant.id);
          const filter = { tenantId: tenant.id, ...(app ? { appId: app.id } : {}) };
          const launches = new Map(
            (await tx.find<AppLaunch>('appLaunches', filter)).map((launch) => [
              `${launch.appId}:${launch.identityId}`,
              launch.lastAt,
            ]),
          );
          const names = await directory(tx, principal, tenant.id);
          const result: AssignmentView[] = [];
          for (const assignment of await tx.find<AppAssignment>('appAssignments', filter)) {
            let subjectName: string | undefined;
            if (assignment.subjectType === 'group')
              subjectName = (await tx.get<Group>('groups', assignment.subjectId))?.name;
            else if (names) {
              const identity = await tx.get<Identity>('identities', assignment.subjectId);
              subjectName = identity?.email ?? identity?.name;
            }
            const lastLaunchedAt =
              assignment.subjectType === 'identity'
                ? launches.get(`${assignment.appId}:${assignment.subjectId}`)
                : undefined;
            result.push({
              ...assignment,
              ...(subjectName ? { subjectName } : {}),
              ...(lastLaunchedAt !== undefined ? { lastLaunchedAt } : {}),
            });
          }
          return result.sort((a, b) =>
            (a.subjectName ?? a.subjectId).localeCompare(b.subjectName ?? b.subjectId),
          );
        },
      ),
    /**
     * The caller's launcher: the apps they may launch now (with when they last did), and the apps they could request
     * through an access package. Needs only a signed-in session of the organization.
     */
    mine: async (credential: CredentialInput, input: { tenantId: string }): Promise<MyApp[]> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        selfSession(principal, tenantId);
        const now = ctx.now();
        const mine = await appsFor(ctx, tx, principal.identity, now);
        const launches = new Map(
          (
            await tx.find<AppLaunch>('appLaunches', { tenantId, identityId: principal.identity.id })
          ).map((launch) => [launch.appId, launch.lastAt]),
        );
        const requestable = new Map<string, boolean>();
        const canRequest = async (packageId: string) => {
          if (!requestable.has(packageId)) {
            const pkg = await tx.get<AccessPackage>('accessPackages', packageId);
            requestable.set(
              packageId,
              Boolean(pkg && pkg.tenantId === tenantId && pkg.requestable),
            );
          }
          return requestable.get(packageId)!;
        };
        const result: MyApp[] = [];
        for (const app of (await tx.find<Application>('applications', { tenantId })).filter(
          (item) => item.enabled,
        )) {
          const entry = mine.get(app.id);
          // A package deleted (or no longer requestable) since it was named is not offered.
          if (!entry && !(app.requestPackageId && (await canRequest(app.requestPackageId))))
            continue;
          result.push({
            id: app.id,
            key: app.key,
            name: app.name,
            ...(app.description ? { description: app.description } : {}),
            ...(app.category ? { category: app.category } : {}),
            ...(app.logoUrl ? { logoUrl: app.logoUrl } : {}),
            ...(entry ? { via: entry.via } : { requestPackageId: app.requestPackageId! }),
            ...(launches.has(app.id) ? { lastLaunchedAt: launches.get(app.id)! } : {}),
          });
        }
        return result.sort(
          (a, b) =>
            Number(Boolean(a.requestPackageId)) - Number(Boolean(b.requestPackageId)) ||
            (b.lastLaunchedAt ?? 0) - (a.lastLaunchedAt ?? 0) ||
            a.name.localeCompare(b.name),
        );
      });
    },
    /**
     * Launches an app the caller has: records the launch (audited as `app:launch`) and returns where to go. Refused
     * while an administrator views as the person (`IMPERSONATION_RESTRICTED`).
     */
    launch: async (credential: CredentialInput, input: { tenantId: string; appId: string }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      const appId = text(input.appId, 'appId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        selfSession(principal, tenantId);
        if (principal.session.impersonatorId)
          throw new IamError(
            'IMPERSONATION_RESTRICTED',
            'Apps cannot be launched while viewing as someone else',
            403,
          );
        const entry = (await appsFor(ctx, tx, principal.identity, ctx.now())).get(appId);
        if (!entry) throw new IamError('ACCESS_DENIED', 'This app is not assigned to you', 403);
        const now = ctx.now();
        const uniqueKey = `${appId}:${principal.identity.id}`;
        const previous = (await tx.find<AppLaunch>('appLaunches', { tenantId, uniqueKey }))[0];
        const launch: AppLaunch = {
          id: previous?.id ?? id(),
          tenantId,
          uniqueKey,
          appId,
          identityId: principal.identity.id,
          firstAt: previous?.firstAt ?? now,
          lastAt: now,
          count: (previous?.count ?? 0) + 1,
        };
        await (previous ? tx.put('appLaunches', launch) : tx.insert('appLaunches', launch));
        await audit(tx, principal, 'app:launch', tenantId, appId, { key: entry.app.key });
        return { url: entry.app.launchUrl };
      });
    },
    /**
     * Whether a person may use an app (by `appId` or its `oauthClientId`): for a sign-in or consent page that enforces
     * assignments. An OAuth client with no app in the catalog is not governed here (`governed: false`).
     */
    check: async (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; appId?: string; oauthClientId?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:applications:read',
        input.tenantId,
        async ({ tx, tenant }) => checkAccess(ctx, tx, tenant, input),
      ),
    /**
     * Assignment hygiene: per app, how many people have it, how many launched it in 30 days, and the direct
     * assignments unused for `unusedDays` (default 90).
     */
    usage: async (
      credential: CredentialInput,
      input: { tenantId: string; unusedDays?: number },
    ): Promise<ApplicationUsage[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:applications:read',
        input.tenantId,
        async ({ tx, tenant, principal }) =>
          usageOf(
            ctx,
            tx,
            tenant.id,
            integer(input.unusedDays ?? 90, 'unusedDays', 1, 3650),
            await directory(tx, principal, tenant.id),
          ),
      ),
    /** Removes direct assignments of an app unused for `unusedDays` (group assignments stay). Audited as `app:unassign`. */
    removeUnused: async (
      credential: CredentialInput,
      input: { tenantId: string; appId: string; unusedDays: number },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:applications:assign',
        text(input.appId, 'appId'),
        async ({ tx, tenant, principal }) => {
          const app = await ctx.scoped<Application>(tx, 'applications', input.appId, tenant.id);
          const days = integer(input.unusedDays, 'unusedDays', 7, 3650);
          const unused = unusedAssignments(
            await tx.find<AppAssignment>('appAssignments', { tenantId: tenant.id, appId: app.id }),
            await tx.find<AppLaunch>('appLaunches', { tenantId: tenant.id, appId: app.id }),
            ctx.now(),
            days,
          );
          for (const assignment of unused) {
            await tx.delete('appAssignments', assignment.id);
            await audit(tx, principal, 'app:unassign', tenant.id, app.id, {
              subjectType: 'identity',
              subjectId: assignment.subjectId,
              reason: `unused ${days} days`,
            });
          }
          return { removed: unused.length };
        },
      ),
  };
}

async function checkAccess(
  ctx: ServerContext,
  tx: IamStore,
  tenant: Tenant,
  input: { identityId: string; appId?: string; oauthClientId?: string },
): Promise<{ allowed: boolean; governed: boolean; appId?: string }> {
  if ((input.appId === undefined) === (input.oauthClientId === undefined))
    throw new IamError('INVALID_INPUT', 'Name exactly one of appId or oauthClientId');
  const identityId = text(input.identityId, 'identityId');
  return appAccess(
    ctx,
    tx,
    tenant,
    identityId,
    input.appId !== undefined
      ? { appId: text(input.appId, 'appId') }
      : { oauthClientId: text(input.oauthClientId, 'oauthClientId', 256) },
  );
}

/** Direct assignments made at least `days` ago whose person has not launched the app within `days`. */
function unusedAssignments(
  assignments: AppAssignment[],
  launches: AppLaunch[],
  now: number,
  days: number,
): AppAssignment[] {
  const cutoff = now - days * 86_400_000;
  const last = new Map(
    launches.map((launch) => [`${launch.appId}:${launch.identityId}`, launch.lastAt]),
  );
  return assignments.filter(
    (assignment) =>
      assignment.subjectType === 'identity' &&
      assignment.assignedAt <= cutoff &&
      (last.get(`${assignment.appId}:${assignment.subjectId}`) ?? 0) <= cutoff,
  );
}

async function usageOf(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  unusedDays: number,
  withNames: boolean,
): Promise<ApplicationUsage[]> {
  const now = ctx.now();
  const apps = await tx.find<Application>('applications', { tenantId });
  const launches = await tx.find<AppLaunch>('appLaunches', { tenantId });
  const assignments = await tx.find<AppAssignment>('appAssignments', { tenantId });
  const holders = await appHolders(ctx, tx, tenantId, now);
  const names = new Map<string, string>();
  if (withNames)
    for (const identity of await tx.find<Identity>('identities', { tenantId }))
      names.set(identity.id, identity.email ?? identity.name);
  const lastLaunch = new Map(
    launches.map((launch) => [`${launch.appId}:${launch.identityId}`, launch.lastAt]),
  );
  return apps
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((app) => ({
      appId: app.id,
      key: app.key,
      name: app.name,
      people: holders.get(app.id) ?? 0,
      launchedLast30Days: launches.filter(
        (launch) => launch.appId === app.id && launch.lastAt > now - 30 * 86_400_000,
      ).length,
      unused: unusedAssignments(
        assignments.filter((assignment) => assignment.appId === app.id),
        launches.filter((launch) => launch.appId === app.id),
        now,
        unusedDays,
      ).map((assignment) => {
        const last = lastLaunch.get(`${app.id}:${assignment.subjectId}`);
        const name = names.get(assignment.subjectId);
        return {
          assignmentId: assignment.id,
          identityId: assignment.subjectId,
          ...(name ? { name } : {}),
          ...(last !== undefined ? { lastLaunchedAt: last } : {}),
        };
      }),
    }));
}

/** The catalog for the deployment's own code (`iam.applications`): an unaudited access check for sign-in pages. */
export function createApplicationsRuntime(ctx: ServerContext) {
  return {
    /**
     * Whether `identityId` may use the app registered for `oauthClientId` (or `appId`). The built-in OAuth provider
     * already enforces this for catalog clients; call it from other sign-in or consent pages. Ungoverned clients are
     * allowed.
     */
    allowed: (input: {
      tenantId: string;
      identityId: string;
      appId?: string;
      oauthClientId?: string;
    }) =>
      ctx.store.transaction(async (tx) =>
        checkAccess(ctx, tx, await ctx.tenant(tx, text(input.tenantId, 'tenantId')), input),
      ),
  };
}
