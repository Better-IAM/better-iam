/**
 * License management: products (SKUs) defined by the platform (the root tenant, visible to every tenant) or by a tenant
 * for its own subtree, capacity per consuming tenant as pools of seats, assignment to people and groups, and
 * materialized seats. The claimants of a product in a tenant (direct assignees and live members of assigned groups,
 * active and unexpired identities only) are ranked by seniority: the first `capacity` hold an active seat, the rest
 * wait. What a license unlocks is expressed with existing governance: birthright package rules on `identity.licenses`
 * (package-rules.ts, org-rules.ts), policies on `principal.licenses` (decisions.ts), and the feature keys a product
 * lists (`iam.licenses.features`).
 */
import {
  IamError,
  type AuthenticatedPrincipal,
  type IamStore,
  type Identity,
  type Json,
  type PolicyDocument,
  type Session,
  type SignInRecord,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import type { GroupMember } from './models.js';
import { id } from './utils.js';
import { text } from './validation.js';

export const licenseCollections = {
  products: 'licenseProducts',
  pools: 'licensePools',
  assignments: 'licenseAssignments',
  seats: 'licenseSeats',
  settings: 'licenseSettings',
} as const;

/** The policy key listing the product keys a person holds an active seat for in the decision's tenant. */
export const licenseContextKey = 'principal.licenses';
/** Products one tenant may define. */
export const maxLicenseProductsPerTenant = 200;
/** Feature keys one product may list. */
export const maxLicenseFeatureKeys = 50;
/** Pools (live or ended) one tenant may hold for one product; ended pools are swept 400 days after their end. */
export const maxLicensePoolsPerProduct = 100;
/** Seats one pool may carry. */
export const maxLicensePoolQuantity = 1_000_000;
/** Direct and group assignments of one product in one tenant. */
export const maxLicenseAssignmentsPerProduct = 10_000;
/** The range of `reclaimAfterDays`. */
export const licenseReclaimDays = { min: 7, max: 365 } as const;
/** How long an ended pool stays as purchase history before the retention sweep removes it. */
export const licensePoolRetentionMs = 400 * 86_400_000;

export type LicenseProductStatus = 'active' | 'retired';
export type LicenseSeatStatus = 'active' | 'waiting';
export type LicenseSubjectType = 'identity' | 'group';
export type LicensePoolSource = 'manual' | 'subscription';

/**
 * A license product (SKU). Defined on the root tenant it is a platform product every tenant sees; defined elsewhere it
 * is visible to that tenant and its subtree. Keys are unique per defining tenant (uniqueKey `key:{key}`), and a tenant
 * may not define a key an enclosing tenant already defines.
 */
export interface LicenseProduct extends StoredRecord {
  key: string;
  name: string;
  description?: string;
  /** Feature keys the product unlocks for the people holding an active seat (`iam.licenses.features`). */
  featureKeys: string[];
  /** A retired product holds no seats anywhere; its pools and assignments stay, read-only. */
  status: LicenseProductStatus;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

/**
 * Capacity of a product in the consuming tenant (`tenantId`): `quantity` seats from `startsAt` (or its creation) until
 * `endsAt` (or indefinitely). A tenant's capacity for a product is the sum over its live pools.
 */
export interface LicensePool extends StoredRecord {
  productId: string;
  quantity: number;
  startsAt?: number;
  endsAt?: number;
  note?: string;
  /** `subscription`: the capacity was bought through the billing subscription `subscriptionId` (a reference only). */
  source: LicensePoolSource;
  subscriptionId?: string;
  createdAt: number;
  createdBy: string;
  updatedAt?: number;
  updatedBy?: string;
  /** When the record itself is swept (retention.ts): 400 days after `endsAt`; ended pools stay as purchase history. */
  expiresAt?: number;
}

/** A product given to a person or a group (uniqueKey `{productId}:{subjectType}:{subjectId}`). */
export interface LicenseAssignment extends StoredRecord {
  productId: string;
  subjectType: LicenseSubjectType;
  subjectId: string;
  assignedBy: string;
  assignedAt: number;
}

/** Why a person claims a seat: a direct assignment, and the assigned groups they are a live member of. */
export interface LicenseSeatSources {
  direct?: true;
  groupIds?: string[];
}

/**
 * One person's claim on a product in a tenant (uniqueKey `{productId}:{identityId}`), materialized by reconciliation:
 * `active` holds one of the tenant's seats, `waiting` is on the waiting list. Seniority (`assignedAt`, the first time the
 * person claimed a seat) decides who keeps a seat when capacity is short; a seat that loses its last claim goes.
 */
export interface LicenseSeat extends StoredRecord {
  productId: string;
  identityId: string;
  status: LicenseSeatStatus;
  sources: LicenseSeatSources;
  assignedAt: number;
  /** When the seat last became active. */
  activatedAt?: number;
  /** The holder's latest sign-in or credential use, as the last reclaim pass saw it. */
  lastActivityAt?: number;
}

/** A tenant's license settings (id = tenant ID). */
export interface LicenseSettings extends StoredRecord {
  /** Direct assignments of people inactive this many days are removed by `iam.licenses.reclaim` (off when absent). */
  reclaimAfterDays?: number;
  /** Email people when they join a product's waiting list and when a waiting seat becomes active. */
  notifyWaiting: boolean;
  updatedAt: number;
  updatedBy: string;
}

/** One seat that reconciliation created, changed, or released. */
export interface LicenseSeatChange {
  tenantId: string;
  productId: string;
  productKey: string;
  identityId: string;
  from: LicenseSeatStatus | 'none';
  to: LicenseSeatStatus | 'none';
}

/** Who seat changes are attributed to: the acting person, or a system actor (`deployment-operator`, `directory-sync`, ...). */
export type LicenseActor = AuthenticatedPrincipal | string;

export interface ReconcileLicenseOptions {
  /** Who the seat changes are attributed to; `deployment-operator` when left out. */
  actor?: LicenseActor;
  /** Why the run happened, recorded on every seat event (`assign`, `pool-update`, `group-membership`, ...). */
  reason?: string;
}

/** An active seat that counts right now, with its product. */
export interface HeldLicense {
  product: LicenseProduct;
  seat: LicenseSeat;
}

const keyPattern = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/** Validates a product key: lowercase letters, digits, dots, underscores or hyphens, starting with a letter or digit. */
export function licenseKey(value: unknown): string {
  const key = text(value, 'key', 64);
  if (!keyPattern.test(key))
    throw new IamError(
      'INVALID_INPUT',
      'License keys are 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter or digit',
    );
  return key;
}

/** Whether a pool contributes capacity at `now`. */
export function liveLicensePool(pool: LicensePool, now: number): boolean {
  return (
    (pool.startsAt === undefined || pool.startsAt <= now) &&
    (pool.endsAt === undefined || pool.endsAt > now)
  );
}

/** The seats a set of pools provides at `now`. */
export function licenseCapacity(pools: readonly LicensePool[], now: number): number {
  return pools.reduce((sum, pool) => (liveLicensePool(pool, now) ? sum + pool.quantity : sum), 0);
}

/** The tenant and its ancestors, nearest first, tolerant of missing records (readers without a server context). */
async function chainIds(reader: IamStore, tenantId: string): Promise<string[]> {
  const ids: string[] = [];
  let current: string | null | undefined = tenantId;
  while (current && ids.length < 64 && !ids.includes(current)) {
    ids.push(current);
    current = (await reader.get<Tenant>('tenants', current))?.parentId;
  }
  return ids;
}

/** Every product visible to a tenant: its own and those of its ancestors (the root tenant's are platform products). */
export async function visibleLicenseProducts(
  reader: IamStore,
  tenantId: string,
): Promise<LicenseProduct[]> {
  const products: LicenseProduct[] = [];
  for (const definer of await chainIds(reader, tenantId))
    products.push(
      ...(await reader.find<LicenseProduct>(licenseCollections.products, { tenantId: definer })),
    );
  return products;
}

/** Of the products visible to a tenant (nearest definer first), those whose seats grant their key there, by ID. */
function grantingOf(visible: readonly LicenseProduct[]): Map<string, LicenseProduct> {
  const byKey = new Map<string, LicenseProduct>();
  // The last definition of a key is the one closest to the root: it wins.
  for (const product of visible) byKey.set(product.key, product);
  return new Map([...byKey.values()].map((product) => [product.id, product]));
}

/**
 * The products whose seats grant their key in a tenant: those visible to it, except a product whose key a tenant
 * enclosing its definer defines as well (`shadowed`). The definition closest to the root wins, so a tenant can never
 * mint seats that count as a key the platform or an enclosing tenant sells, and a product of a tenant the seat's
 * tenant is no longer below (after `tenants.reparent`) grants nothing there.
 */
export async function grantingLicenseProducts(
  reader: IamStore,
  tenantId: string,
): Promise<Map<string, LicenseProduct>> {
  return grantingOf(await visibleLicenseProducts(reader, tenantId));
}

/** The valid `identity.licenses` values of a tenant: the keys of every product visible to it, retired ones included. */
export async function licenseRuleKeys(reader: IamStore, tenantId: string): Promise<Set<string>> {
  return new Set((await visibleLicenseProducts(reader, tenantId)).map((product) => product.key));
}

/** What `identity.licenses` holds for the people of one tenant, read once (org-rules.ts). */
export interface TenantLicenseFacts {
  /** The keys of every product visible to the tenant. */
  keys: Set<string>;
  /**
   * The keys of the products a person holds an active seat for. A seat held only through groups counts while one of
   * them is in `countedGroupIds` (memberships no access package created), so a rule never feeds on what a package
   * granted.
   */
  of(identityId: string, countedGroupIds: ReadonlySet<string>): string[];
}

export async function loadLicenseFacts(
  reader: IamStore,
  tenantId: string,
): Promise<TenantLicenseFacts> {
  const visible = await visibleLicenseProducts(reader, tenantId);
  // Seats of a shadowed product (or of one the tenant no longer sees) never count.
  const products = grantingOf(visible);
  const seats = new Map<string, LicenseSeat[]>();
  for (const seat of await reader.find<LicenseSeat>(licenseCollections.seats, {
    tenantId,
    status: 'active',
  }))
    seats.set(seat.identityId, [...(seats.get(seat.identityId) ?? []), seat]);
  return {
    keys: new Set(visible.map((product) => product.key)),
    of(identityId, countedGroupIds) {
      const keys = new Set<string>();
      for (const seat of seats.get(identityId) ?? []) {
        const product = products.get(seat.productId);
        if (!product || product.status !== 'active') continue;
        if (
          seat.sources.direct !== true &&
          !(seat.sources.groupIds ?? []).some((groupId) => countedGroupIds.has(groupId))
        )
          continue;
        keys.add(product.key);
      }
      return [...keys].sort();
    },
  };
}

/**
 * The active seats of a person in a tenant that count right now: the product is active and grants its key in the
 * tenant (`grantingLicenseProducts`: not shadowed by an enclosing tenant's product, still visible), and a seat held only
 * through groups still has a live membership behind it (memberships lapse between reconciliations).
 */
export async function heldLicenses(
  tx: IamStore,
  tenantId: string,
  identityId: string,
  now: number,
): Promise<HeldLicense[]> {
  const seats = (
    await tx.find<LicenseSeat>(licenseCollections.seats, { tenantId, identityId })
  ).filter((seat) => seat.status === 'active');
  if (!seats.length) return [];
  let groups: Set<string> | undefined;
  let granting: Map<string, LicenseProduct> | undefined;
  const held: HeldLicense[] = [];
  for (const seat of seats) {
    if (seat.sources.direct !== true) {
      groups ??= new Set(
        (await tx.find<GroupMember>('groupMembers', { tenantId, identityId }))
          .filter((member) => member.expiresAt === undefined || member.expiresAt > now)
          .map((member) => member.groupId),
      );
      const live = groups;
      if (!(seat.sources.groupIds ?? []).some((groupId) => live.has(groupId))) continue;
    }
    granting ??= await grantingLicenseProducts(tx, tenantId);
    const product = granting.get(seat.productId);
    if (product?.status === 'active') held.push({ product, seat });
  }
  return held.sort((a, b) =>
    a.product.key < b.product.key ? -1 : a.product.key > b.product.key ? 1 : 0,
  );
}

/** Whether any document names `principal.licenses` (conditions, `${…}` variables, resource patterns). */
export function mentionsLicenses(documents: Iterable<PolicyDocument | undefined>): boolean {
  for (const document of documents)
    if (document && JSON.stringify(document.statements).includes(licenseContextKey)) return true;
  return false;
}

/** `principal.licenses` for a person in their own tenant: the keys of the products they hold an active seat for. */
export async function licenseContext(
  tx: IamStore,
  tenantId: string,
  identityId: string,
  now: number,
): Promise<{ 'principal.licenses': string[] }> {
  return {
    'principal.licenses': [
      ...new Set(
        (await heldLicenses(tx, tenantId, identityId, now)).map(({ product }) => product.key),
      ),
    ].sort(),
  };
}

/**
 * A person's latest activity: their last sign-in (`authSignIns`, else when the account was created) or the last use of
 * one of their own sessions or API keys ("view as" sessions of administrators excluded).
 */
export async function lastActivityOf(tx: IamStore, identity: Identity): Promise<number> {
  const ledger = await tx.get<StoredRecord & SignInRecord>('authSignIns', identity.id);
  let last = ledger?.lastAt ?? identity.createdAt;
  for (const session of await tx.find<Session>('sessions', { identityId: identity.id }))
    if (
      (session.kind === 'user' || session.kind === 'api-key') &&
      !session.impersonatorId &&
      session.lastSeenAt > last
    )
      last = session.lastSeenAt;
  return last;
}

async function auditAs(
  ctx: ServerContext,
  tx: IamStore,
  actor: LicenseActor,
  action: string,
  tenantId: string,
  resourceId: string,
  metadata: Record<string, Json>,
): Promise<void> {
  if (typeof actor === 'string')
    await ctx.events.recordAudit(tx, {
      id: id(),
      tenantId,
      actorId: actor,
      action,
      resourceId,
      timestamp: ctx.now(),
      outcome: 'allow',
      metadata,
    });
  else await ctx.events.audit(tx, actor, action, tenantId, resourceId, 'allow', false, metadata);
}

const sameGroups = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((value, index) => value === b[index]);

interface ProductRun {
  actor: LicenseActor;
  reason: string;
  identities: Map<string, Identity | undefined>;
  /** The seat tenant and its ancestors, read once per run. */
  chain?: { tenantId: string; ids: Set<string> };
}

/** Brings one product's seats in a tenant in line with its claimants and live capacity. */
async function reconcileProduct(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  productId: string,
  run: ProductRun,
): Promise<LicenseSeatChange[]> {
  const now = ctx.now();
  const product = await tx.get<LicenseProduct>(licenseCollections.products, productId);
  const seats = await tx.find<LicenseSeat>(licenseCollections.seats, { tenantId, productId });
  const claims = new Map<string, { direct: boolean; groupIds: Set<string> }>();
  const claim = (identityId: string) => {
    let entry = claims.get(identityId);
    if (!entry) {
      entry = { direct: false, groupIds: new Set() };
      claims.set(identityId, entry);
    }
    return entry;
  };
  let capacity = 0;
  if (product && run.chain?.tenantId !== tenantId)
    run.chain = { tenantId, ids: new Set(await chainIds(tx, tenantId)) };
  // A retired (or vanished) product has no claimants: every seat goes. So does one the tenant no longer sees because it
  // moved out from under the defining tenant (`tenants.reparent`); its assignments stay and count again if it returns.
  if (product?.status === 'active' && run.chain!.ids.has(product.tenantId)) {
    for (const assignment of await tx.find<LicenseAssignment>(licenseCollections.assignments, {
      tenantId,
      productId,
    })) {
      if (assignment.subjectType === 'identity') claim(assignment.subjectId).direct = true;
      else
        for (const member of await tx.find<GroupMember>('groupMembers', {
          tenantId,
          groupId: assignment.subjectId,
        }))
          if (ctx.liveMembership(member))
            claim(member.identityId).groupIds.add(assignment.subjectId);
    }
    // Only active, unexpired identities of the tenant claim a seat (any kind; guests count like anyone).
    for (const identityId of [...claims.keys()]) {
      if (!run.identities.has(identityId))
        run.identities.set(identityId, await tx.get<Identity>('identities', identityId));
      const identity = run.identities.get(identityId);
      if (
        !identity ||
        identity.tenantId !== tenantId ||
        identity.status !== 'active' ||
        ctx.identityExpired(identity)
      )
        claims.delete(identityId);
    }
    capacity = licenseCapacity(
      await tx.find<LicensePool>(licenseCollections.pools, { tenantId, productId }),
      now,
    );
  }
  const productKey = product?.key ?? productId;
  const existing = new Map(seats.map((seat) => [seat.identityId, seat]));
  // Seniority decides: the oldest claims keep their seats, new claimants queue behind every existing seat. Claims of
  // the same millisecond rank existing seats before new ones and active before waiting, so a claimant never takes a
  // seat someone already holds and repeated runs never swap two holders.
  const rank = (identityId: string) => {
    const seat = existing.get(identityId);
    return seat ? (seat.status === 'active' ? 0 : 1) : 2;
  };
  const ranked = [...claims.keys()]
    .map((identityId) => ({
      identityId,
      assignedAt: existing.get(identityId)?.assignedAt ?? now,
      rank: rank(identityId),
    }))
    .sort(
      (a, b) =>
        a.assignedAt - b.assignedAt ||
        a.rank - b.rank ||
        (a.identityId < b.identityId ? -1 : a.identityId > b.identityId ? 1 : 0),
    );
  const changes: LicenseSeatChange[] = [];
  let settings: LicenseSettings | null | undefined;
  let tenantName: string | undefined;
  const notify = async (
    identityId: string,
    template: 'license-waiting' | 'license-activated',
  ): Promise<void> => {
    if (!product || !ctx.options.authentication?.sendEmail) return;
    if (settings === undefined)
      settings = (await tx.get<LicenseSettings>(licenseCollections.settings, tenantId)) ?? null;
    if (settings?.notifyWaiting !== true) return;
    const identity =
      run.identities.get(identityId) ?? (await tx.get<Identity>('identities', identityId));
    if (!identity?.email || identity.kind !== 'user' || identity.status !== 'active') return;
    tenantName ??= (await tx.get<Tenant>('tenants', tenantId))?.name ?? '';
    await ctx.auth.enqueueDelivery(tx, {
      tenantId,
      kind: 'email',
      to: identity.email,
      template,
      payload: {
        tenantId,
        tenantName,
        productKey: product.key,
        productName: product.name,
      },
    });
  };
  const record = async (
    identityId: string,
    from: LicenseSeatChange['from'],
    to: LicenseSeatChange['to'],
  ): Promise<void> => {
    changes.push({ tenantId, productId, productKey, identityId, from, to });
    await auditAs(
      ctx,
      tx,
      run.actor,
      to === 'none'
        ? 'license:seat-release'
        : to === 'active'
          ? 'license:seat-activate'
          : 'license:seat-waiting',
      tenantId,
      identityId,
      { productId, productKey, from, to, reason: run.reason },
    );
    if (to === 'waiting') await notify(identityId, 'license-waiting');
    else if (from === 'waiting' && to === 'active') await notify(identityId, 'license-activated');
  };
  for (const seat of seats)
    if (!claims.has(seat.identityId)) {
      await tx.delete(licenseCollections.seats, seat.id);
      await record(seat.identityId, seat.status, 'none');
    }
  for (let index = 0; index < ranked.length; index++) {
    const { identityId, assignedAt } = ranked[index]!;
    const status: LicenseSeatStatus = index < capacity ? 'active' : 'waiting';
    const source = claims.get(identityId)!;
    const groupIds = [...source.groupIds].sort();
    const sources: LicenseSeatSources = {
      ...(source.direct ? { direct: true as const } : {}),
      ...(groupIds.length ? { groupIds } : {}),
    };
    const seat = existing.get(identityId);
    if (!seat) {
      await tx.insert<LicenseSeat>(licenseCollections.seats, {
        id: id(),
        tenantId,
        uniqueKey: `${productId}:${identityId}`,
        productId,
        identityId,
        status,
        sources,
        assignedAt,
        ...(status === 'active' ? { activatedAt: now } : {}),
      });
      await record(identityId, 'none', status);
      continue;
    }
    const sameSources =
      (seat.sources.direct === true) === source.direct &&
      sameGroups(seat.sources.groupIds ?? [], groupIds);
    if (seat.status === status && sameSources) continue;
    const { activatedAt: previousActivation, sources: _sources, ...rest } = seat;
    await tx.put<LicenseSeat>(licenseCollections.seats, {
      ...rest,
      status,
      sources,
      ...(status === 'active'
        ? { activatedAt: seat.status === 'active' ? (previousActivation ?? now) : now }
        : {}),
    });
    if (seat.status !== status) await record(identityId, seat.status, status);
  }
  return changes;
}

/** The products with assignments or seats in a tenant. */
async function licensedProductIds(tx: IamStore, tenantId: string): Promise<string[]> {
  const ids = new Set<string>();
  for (const assignment of await tx.find<LicenseAssignment>(licenseCollections.assignments, {
    tenantId,
  }))
    ids.add(assignment.productId);
  for (const seat of await tx.find<LicenseSeat>(licenseCollections.seats, { tenantId }))
    ids.add(seat.productId);
  return [...ids].sort();
}

/**
 * Brings the seats of one product (or of every product with assignments or seats) in a tenant in line with who claims
 * them and the capacity of the live pools. Idempotent. Seats of claimants who are gone (unassigned, left the group,
 * disabled, expired, deleted) are released; the rest are ranked by seniority, the first `capacity` active and the others
 * waiting, so capacity is never over-allocated and a capacity cut moves the newest active seats to the waiting list.
 * Changes are audited as `license:seat-activate`, `license:seat-waiting` and `license:seat-release` (resource: the
 * identity). Callers run `afterIdentityChange` post-commit for the identities in the result.
 */
export async function reconcileLicenses(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  productId?: string,
  options: ReconcileLicenseOptions = {},
): Promise<LicenseSeatChange[]> {
  const run: ProductRun = {
    actor: options.actor ?? 'deployment-operator',
    reason: options.reason ?? 'reconcile',
    identities: new Map(),
  };
  const changes: LicenseSeatChange[] = [];
  for (const each of productId !== undefined ? [productId] : await licensedProductIds(tx, tenantId))
    changes.push(...(await reconcileProduct(ctx, tx, tenantId, each, run)));
  return changes;
}

/** Per transaction: the products a batch of membership writes left to reconcile (`batchGroupLicenses`). */
const deferredGroupProducts = new WeakMap<
  IamStore,
  Map<string, { tenantId: string; productId: string; actor: LicenseActor }>
>();

/**
 * Runs a batch of group membership writes (`groups.addMembers`, offboarding, configuration sync) with the seat
 * reconciliation they cause deferred to the end of the batch, where each affected product is reconciled once instead
 * of once per membership: every run rebuilds all of the product's claimants, which made batches quadratic inside the
 * transaction. People who claim a seat in the same batch rank by identity ID among themselves. Nested batches join the
 * outermost one.
 */
export async function batchGroupLicenses<T>(
  ctx: ServerContext,
  tx: IamStore,
  run: () => Promise<T>,
): Promise<T> {
  if (deferredGroupProducts.has(tx)) return run();
  const pending = new Map<string, { tenantId: string; productId: string; actor: LicenseActor }>();
  deferredGroupProducts.set(tx, pending);
  let result: T;
  try {
    result = await run();
  } finally {
    deferredGroupProducts.delete(tx);
  }
  for (const key of [...pending.keys()].sort()) {
    const { tenantId, productId, actor } = pending.get(key)!;
    await reconcileLicenses(ctx, tx, tenantId, productId, { actor, reason: 'group-membership' });
  }
  return result;
}

/** Whether a product that still holds seats (an active one) is assigned to any of the groups. */
export async function groupsHoldLicenses(
  tx: IamStore,
  tenantId: string,
  groupIds: Iterable<string>,
): Promise<boolean> {
  for (const groupId of new Set(groupIds))
    for (const assignment of await tx.find<LicenseAssignment>(licenseCollections.assignments, {
      tenantId,
      subjectType: 'group',
      subjectId: groupId,
    }))
      if (
        (await tx.get<LicenseProduct>(licenseCollections.products, assignment.productId))
          ?.status === 'active'
      )
        return true;
  return false;
}

/**
 * The products assigned to some groups, after their membership changed (teams.ts `syncTeamsFromGroups`): each product
 * is reconciled once. Inside `batchGroupLicenses` the products are only noted, for the end of the batch.
 */
export async function reconcileGroupLicenses(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  groupIds: string | readonly string[],
  actor: LicenseActor,
): Promise<LicenseSeatChange[]> {
  const found = new Set<string>();
  for (const groupId of new Set(typeof groupIds === 'string' ? [groupIds] : groupIds))
    for (const assignment of await tx.find<LicenseAssignment>(licenseCollections.assignments, {
      tenantId,
      subjectType: 'group',
      subjectId: groupId,
    }))
      found.add(assignment.productId);
  const productIds = [...found].sort();
  const pending = deferredGroupProducts.get(tx);
  if (pending) {
    for (const productId of productIds)
      if (!pending.has(`${tenantId}:${productId}`))
        pending.set(`${tenantId}:${productId}`, { tenantId, productId, actor });
    return [];
  }
  const changes: LicenseSeatChange[] = [];
  for (const productId of productIds)
    changes.push(
      ...(await reconcileLicenses(ctx, tx, tenantId, productId, {
        actor,
        reason: 'group-membership',
      })),
    );
  return changes;
}

/** When a group is deleted: its license assignments go with it, and the seats they carried follow. */
export async function releaseGroupLicenses(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  groupId: string,
  actor: LicenseActor,
): Promise<LicenseSeatChange[]> {
  const productIds = new Set<string>();
  for (const assignment of await tx.find<LicenseAssignment>(licenseCollections.assignments, {
    tenantId,
    subjectType: 'group',
    subjectId: groupId,
  })) {
    productIds.add(assignment.productId);
    await tx.delete(licenseCollections.assignments, assignment.id);
  }
  const changes: LicenseSeatChange[] = [];
  for (const productId of [...productIds].sort())
    changes.push(
      ...(await reconcileLicenses(ctx, tx, tenantId, productId, {
        actor,
        reason: 'group-deleted',
      })),
    );
  return changes;
}

/**
 * When a person is deleted: their direct assignments go and their seats are released (their group memberships are
 * already gone), and waiting people move up.
 */
export async function releaseLicensesOf(
  ctx: ServerContext,
  tx: IamStore,
  identity: Identity,
  actor: LicenseActor,
): Promise<LicenseSeatChange[]> {
  const tenantId = identity.tenantId;
  const productIds = new Set<string>();
  for (const assignment of await tx.find<LicenseAssignment>(licenseCollections.assignments, {
    tenantId,
    subjectType: 'identity',
    subjectId: identity.id,
  })) {
    productIds.add(assignment.productId);
    await tx.delete(licenseCollections.assignments, assignment.id);
  }
  const seats = await tx.find<LicenseSeat>(licenseCollections.seats, {
    tenantId,
    identityId: identity.id,
  });
  for (const seat of seats) productIds.add(seat.productId);
  const changes: LicenseSeatChange[] = [];
  const run: ProductRun = { actor, reason: 'identity-deleted', identities: new Map() };
  // Whatever still ties the person to a product (a membership written after the cleanup) must not keep a seat.
  run.identities.set(identity.id, undefined);
  for (const productId of [...productIds].sort())
    changes.push(...(await reconcileProduct(ctx, tx, tenantId, productId, run)));
  return changes;
}

/**
 * Reconciles, inside the caller's transaction, the products that concern some identities of a tenant (their seats,
 * direct assignments, and assignments of their groups), after their status or memberships changed (SCIM provisioning
 * through `protocolHost.identityStatusChanged`, and `reconcileLicensesOf`). Returns the seat changes.
 */
export async function reconcileIdentityLicenses(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  identityIds: readonly string[],
  actor: LicenseActor = 'deployment-operator',
): Promise<LicenseSeatChange[]> {
  if (!identityIds.length) return [];
  // Tenants without licenses pay one indexed lookup.
  if (
    !(await tx.find(licenseCollections.assignments, { tenantId }, { limit: 1 })).length &&
    !(await tx.find(licenseCollections.seats, { tenantId }, { limit: 1 })).length
  )
    return [];
  const productIds = new Set<string>();
  const groups = new Map<string, string[]>();
  for (const identityId of new Set(identityIds)) {
    for (const seat of await tx.find<LicenseSeat>(licenseCollections.seats, {
      tenantId,
      identityId,
    }))
      productIds.add(seat.productId);
    for (const assignment of await tx.find<LicenseAssignment>(licenseCollections.assignments, {
      tenantId,
      subjectType: 'identity',
      subjectId: identityId,
    }))
      productIds.add(assignment.productId);
    for (const member of await tx.find<GroupMember>('groupMembers', { tenantId, identityId })) {
      if (!groups.has(member.groupId))
        groups.set(
          member.groupId,
          (
            await tx.find<LicenseAssignment>(licenseCollections.assignments, {
              tenantId,
              subjectType: 'group',
              subjectId: member.groupId,
            })
          ).map((assignment) => assignment.productId),
        );
      for (const productId of groups.get(member.groupId)!) productIds.add(productId);
    }
  }
  const run: ProductRun = { actor, reason: 'identity-change', identities: new Map() };
  const changes: LicenseSeatChange[] = [];
  for (const productId of [...productIds].sort())
    changes.push(...(await reconcileProduct(ctx, tx, tenantId, productId, run)));
  return changes;
}

/**
 * Reconciles the products that concern some identities of a tenant (`reconcileIdentityLicenses`) in one transaction,
 * after an administrator changed them (package-automation.ts `afterIdentityChange`). Returns the identities whose
 * seats changed; never throws (the scheduled reconcile catches up).
 */
export async function reconcileLicensesOf(
  ctx: ServerContext,
  tenantId: string,
  identityIds: readonly string[],
  actor: LicenseActor = 'deployment-operator',
): Promise<string[]> {
  if (!identityIds.length) return [];
  try {
    return await ctx.store.transaction(async (tx) => [
      ...new Set(
        (await reconcileIdentityLicenses(ctx, tx, tenantId, identityIds, actor)).map(
          (change) => change.identityId,
        ),
      ),
    ]);
  } catch {
    return [];
  }
}

/** A tenant's settings with defaults (reclaim off, no waiting-list email). */
export async function resolveLicenseSettings(
  reader: IamStore,
  tenantId: string,
): Promise<{
  reclaimAfterDays?: number;
  notifyWaiting: boolean;
  updatedAt?: number;
  updatedBy?: string;
}> {
  const stored = await reader.get<LicenseSettings>(licenseCollections.settings, tenantId);
  return {
    ...(stored?.reclaimAfterDays !== undefined
      ? { reclaimAfterDays: stored.reclaimAfterDays }
      : {}),
    notifyWaiting: stored?.notifyWaiting === true,
    ...(stored ? { updatedAt: stored.updatedAt, updatedBy: stored.updatedBy } : {}),
  };
}
