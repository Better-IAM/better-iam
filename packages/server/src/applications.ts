import {
  IamError,
  type IamStore,
  type Identity,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import type { GroupMember } from './models.js';
import { text } from './validation.js';

/**
 * The application catalog behind the "My apps" launcher: the tenant's applications (OpenID Connect clients of this
 * deployment, or plain links to other tools), who may see and launch each one (everyone, or assigned people and
 * groups), launch history, and the access package people request to get an app. For an OpenID Connect app the
 * assignment is enforced: the OAuth provider refuses to issue or refresh tokens for people without the app
 * (`iam.protocolHost.clientAllowed`).
 */
export interface Application extends StoredRecord {
  /** Short identifier, unique per tenant (uniqueKey `key:{key}`). */
  key: string;
  name: string;
  description?: string;
  category?: string;
  /** Where launching sends the person: the app's sign-in URL. */
  launchUrl: string;
  logoUrl?: string;
  /** `oidc`: an OAuth/OpenID Connect client of this deployment (`oauthClientId`, one app per client); `link`: any other tool. */
  kind: 'oidc' | 'link';
  oauthClientId?: string;
  /** `everyone`: every active person of the tenant sees it; `assigned`: only assigned people and group members. */
  visibility: 'everyone' | 'assigned';
  enabled: boolean;
  /** People without access see "Request access", which requests this access package (it should grant a group the app is assigned to). */
  requestPackageId?: string;
  /** People to contact about the app. */
  ownerIds: string[];
  createdAt: number;
  updatedAt: number;
}
/** An app given to a person or a group, optionally until `expiresAt` (uniqueKey `{appId}:{subjectType}:{subjectId}`). */
export interface AppAssignment extends StoredRecord {
  appId: string;
  subjectType: 'identity' | 'group';
  subjectId: string;
  assignedBy: string;
  assignedAt: number;
  expiresAt?: number;
}
/** A person's launches of an app: the last one and how many (uniqueKey `{appId}:{identityId}`). */
export interface AppLaunch extends StoredRecord {
  appId: string;
  identityId: string;
  lastAt: number;
  firstAt: number;
  count: number;
}

export const appKey = (value: unknown): string => {
  const key = text(value, 'key', 64);
  if (!/^[a-z][a-z0-9._-]{0,63}$/.test(key))
    throw new IamError(
      'INVALID_INPUT',
      'App keys use lowercase letters, digits, dots, underscores or hyphens',
    );
  return key;
};

const localHosts = ['localhost', '127.0.0.1', '[::1]'];
/** Whether the deployment itself runs on the local machine (development), where apps may use plain http locally. */
export function localDeployment(baseURL: string | undefined): boolean {
  try {
    return baseURL !== undefined && localHosts.includes(new URL(baseURL).hostname);
  } catch {
    return false;
  }
}

/** Launch and logo URLs: https, or http on the local machine when the deployment itself is local (development). */
export function appUrl(value: unknown, name: string, allowLocal: boolean): string {
  const raw = text(value, name, 2048);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new IamError('INVALID_INPUT', `${name} must be an absolute URL`);
  }
  const local = allowLocal && localHosts.includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local))
    throw new IamError('INVALID_INPUT', `${name} must use https`);
  if (url.username || url.password)
    throw new IamError('INVALID_INPUT', `${name} cannot carry credentials`);
  return url.toString();
}

const live = (expiresAt: number | undefined, now: number) =>
  expiresAt === undefined || expiresAt > now;

/** Whether an identity may hold apps at all: an active, unexpired person. */
const eligible = (ctx: ServerContext, identity: Identity) =>
  identity.kind === 'user' && identity.status === 'active' && !ctx.identityExpired(identity);

/**
 * Which enabled apps a person may launch right now: everyone apps, apps assigned to them, and apps assigned to a group
 * they belong to (memberships and assignments that have not ended). Only active, unexpired people have apps.
 */
export async function appsFor(
  ctx: ServerContext,
  tx: IamStore,
  identity: Identity,
  now: number,
): Promise<Map<string, { app: Application; via: 'everyone' | 'direct' | 'group' }>> {
  const result = new Map<string, { app: Application; via: 'everyone' | 'direct' | 'group' }>();
  if (!eligible(ctx, identity)) return result;
  const tenantId = identity.tenantId;
  const apps = new Map(
    (await tx.find<Application>('applications', { tenantId }))
      .filter((app) => app.enabled)
      .map((app) => [app.id, app]),
  );
  if (!apps.size) return result;
  for (const app of apps.values())
    if (app.visibility === 'everyone') result.set(app.id, { app, via: 'everyone' });
  const groups = [
    ...new Set(
      (await tx.find<GroupMember>('groupMembers', { tenantId, identityId: identity.id }))
        .filter((member) => live(member.expiresAt, now))
        .map((member) => member.groupId),
    ),
  ];
  // Only this person's and their groups' assignments (`subjectId` is indexed), never the whole tenant's.
  const assignments = [
    ...(await tx.find<AppAssignment>('appAssignments', {
      tenantId,
      subjectType: 'identity',
      subjectId: identity.id,
    })),
    ...(
      await Promise.all(
        groups.map((groupId) =>
          tx.find<AppAssignment>('appAssignments', {
            tenantId,
            subjectType: 'group',
            subjectId: groupId,
          }),
        ),
      )
    ).flat(),
  ];
  for (const assignment of assignments) {
    const app = apps.get(assignment.appId);
    if (!app || !live(assignment.expiresAt, now)) continue;
    const direct = assignment.subjectType === 'identity';
    const previous = result.get(app.id);
    if (!previous || previous.via === 'everyone' || (previous.via === 'group' && direct))
      result.set(app.id, { app, via: direct ? 'direct' : 'group' });
  }
  return result;
}

/**
 * How many people hold each app now, in one pass over the tenant (for usage reports): everyone apps count every
 * eligible person, assigned apps the union of direct assignees and live members of assigned groups.
 */
export async function appHolders(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  now: number,
): Promise<Map<string, number>> {
  const people = new Set(
    (await tx.find<Identity>('identities', { tenantId }))
      .filter((identity) => eligible(ctx, identity))
      .map((identity) => identity.id),
  );
  const members = new Map<string, string[]>();
  for (const member of await tx.find<GroupMember>('groupMembers', { tenantId }))
    if (live(member.expiresAt, now) && people.has(member.identityId))
      members.set(member.groupId, [...(members.get(member.groupId) ?? []), member.identityId]);
  const holders = new Map<string, Set<string>>();
  for (const assignment of await tx.find<AppAssignment>('appAssignments', { tenantId })) {
    if (!live(assignment.expiresAt, now)) continue;
    const set = holders.get(assignment.appId) ?? new Set<string>();
    if (assignment.subjectType === 'identity') {
      if (people.has(assignment.subjectId)) set.add(assignment.subjectId);
    } else for (const identityId of members.get(assignment.subjectId) ?? []) set.add(identityId);
    holders.set(assignment.appId, set);
  }
  const result = new Map<string, number>();
  for (const app of await tx.find<Application>('applications', { tenantId }))
    result.set(
      app.id,
      !app.enabled
        ? 0
        : app.visibility === 'everyone'
          ? people.size
          : (holders.get(app.id)?.size ?? 0),
    );
  return result;
}

/**
 * Whether a person may use an app, by its ID or its OAuth client: `governed: false` when no app in the catalog names
 * the client (nothing to enforce). Refuses people of another tenant, an inactive tenant, and people who are not active.
 */
export async function appAccess(
  ctx: ServerContext,
  tx: IamStore,
  tenant: Tenant,
  identityId: string,
  target: { appId: string } | { oauthClientId: string },
): Promise<{ allowed: boolean; governed: boolean; appId?: string }> {
  const apps = await tx.find<Application>('applications', { tenantId: tenant.id });
  const app =
    'appId' in target
      ? apps.find((item) => item.id === target.appId)
      : apps.find((item) => item.oauthClientId === target.oauthClientId);
  if (!app) {
    if ('appId' in target) throw new IamError('NOT_FOUND', 'App not found', 404);
    return { allowed: true, governed: false };
  }
  const identity = await tx.get<Identity>('identities', identityId);
  if (!identity || identity.tenantId !== tenant.id || tenant.status !== 'active')
    return { allowed: false, governed: true, appId: app.id };
  return {
    allowed: (await appsFor(ctx, tx, identity, ctx.now())).has(app.id),
    governed: true,
    appId: app.id,
  };
}

/** The OAuth provider's gate (`protocolHost.clientAllowed`): may this person get tokens for this client? */
export async function appClientAllowed(
  ctx: ServerContext,
  identityId: string,
  tenantId: string,
  clientId: string,
): Promise<boolean> {
  return ctx.store.transaction(async (tx) => {
    const tenant = await tx.get<Tenant>('tenants', tenantId);
    if (!tenant) return false;
    return (await appAccess(ctx, tx, tenant, identityId, { oauthClientId: clientId })).allowed;
  });
}

/** When a person is deleted: their assignments and launch history go, and they stop being an app owner. */
export async function releaseAppRecordsOf(tx: IamStore, identity: Identity): Promise<void> {
  const tenantId = identity.tenantId;
  for (const assignment of await tx.find<AppAssignment>('appAssignments', {
    tenantId,
    subjectType: 'identity',
    subjectId: identity.id,
  }))
    await tx.delete('appAssignments', assignment.id);
  for (const launch of await tx.find<AppLaunch>('appLaunches', {
    tenantId,
    identityId: identity.id,
  }))
    await tx.delete('appLaunches', launch.id);
  for (const app of await tx.find<Application>('applications', { tenantId }))
    if (app.ownerIds.includes(identity.id))
      await tx.put<Application>('applications', {
        ...app,
        ownerIds: app.ownerIds.filter((ownerId) => ownerId !== identity.id),
      });
}

/** When a group is deleted: its app assignments go with it. */
export async function releaseGroupApps(
  tx: IamStore,
  tenantId: string,
  groupId: string,
): Promise<void> {
  for (const assignment of await tx.find<AppAssignment>('appAssignments', {
    tenantId,
    subjectType: 'group',
    subjectId: groupId,
  }))
    await tx.delete('appAssignments', assignment.id);
}
