import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type Tenant,
} from '@better-iam/core';
import { billingCollections, type BillingSubscription } from '../billing.js';
import type { ServerContext } from '../context.js';
import { featureKey } from '../features.js';
import { invariantSnapshot, invariantVerify } from '../invariants.js';
import {
  grantingLicenseProducts,
  heldLicenses,
  lastActivityOf,
  licenseCapacity,
  licenseCollections,
  licenseKey,
  licensePoolRetentionMs,
  licenseReclaimDays,
  liveLicensePool,
  maxLicenseAssignmentsPerProduct,
  maxLicenseFeatureKeys,
  maxLicensePoolQuantity,
  maxLicensePoolsPerProduct,
  maxLicenseProductsPerTenant,
  reconcileLicenses,
  resolveLicenseSettings,
  visibleLicenseProducts,
  type LicenseAssignment,
  type LicensePool,
  type LicensePoolSource,
  type LicenseProduct,
  type LicenseProductStatus,
  type LicenseSeat,
  type LicenseSeatChange,
  type LicenseSeatStatus,
  type LicenseSettings,
  type LicenseSubjectType,
} from '../licenses.js';
import type { Group } from '../models.js';
import { OperationDenied } from '../operations.js';
import { id } from '../utils.js';
import { integer, strings, text } from '../validation.js';
import { afterIdentityChange } from './package-automation.js';

/** A product as a tenant's administrators see it (`licenses.listProducts`, `licenses.getProduct`). */
export interface LicenseProductView {
  id: string;
  key: string;
  name: string;
  description?: string;
  featureKeys: string[];
  status: LicenseProductStatus;
  /** `platform` when the root tenant defines the product. */
  scope: 'platform' | 'tenant';
  /** The defining tenant: the tenant the view was read in or one of its ancestors. */
  definedBy: string;
  /** Whether the tenant the view was read in defines the product (and so may change it). */
  definedHere: boolean;
  /**
   * An enclosing tenant defines the same key as well. Its product wins: this one's seats stay but no longer grant the key
   * or its feature keys (`principal.licenses`, `identity.licenses`, `iam.licenses`, `licenses.mine`).
   */
  shadowed: boolean;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

/** A pool of seats (`licenses.listPools`). */
export interface LicensePoolView {
  id: string;
  /** The consuming tenant. */
  tenantId: string;
  tenantName: string;
  productId: string;
  productKey: string;
  productName: string;
  quantity: number;
  startsAt?: number;
  endsAt?: number;
  note?: string;
  source: LicensePoolSource;
  subscriptionId?: string;
  /** Whether the pool contributes capacity right now (started and not ended). */
  live: boolean;
  createdAt: number;
  createdBy: string;
  updatedAt?: number;
  updatedBy?: string;
}

/** An assignment with the names of its product and subject (`licenses.listAssignments`). */
export interface LicenseAssignmentView {
  id: string;
  tenantId: string;
  productId: string;
  productKey: string;
  productName: string;
  subjectType: LicenseSubjectType;
  subjectId: string;
  /** The person's or the group's name; the ID when the subject no longer exists. */
  subjectName: string;
  subjectEmail?: string;
  assignedBy: string;
  assignedAt: number;
}

/** A seat with its product and holder (`licenses.listSeats`). */
export interface LicenseSeatView {
  id: string;
  tenantId: string;
  productId: string;
  productKey: string;
  productName: string;
  identityId: string;
  identityName: string;
  identityEmail?: string;
  identityKind?: Identity['kind'];
  status: LicenseSeatStatus;
  /** Place on the product's waiting list, from 1 (waiting seats only). */
  position?: number;
  /** Held through a direct assignment. */
  direct: boolean;
  /** The assigned groups the holder is a member of. */
  groupIds: string[];
  assignedAt: number;
  activatedAt?: number;
  lastActivityAt?: number;
}

/** One product's seats in a tenant (`licenses.usage`). */
export interface LicenseUsage {
  productId: string;
  key: string;
  name: string;
  scope: 'platform' | 'tenant';
  status: LicenseProductStatus;
  /** Seats the live pools provide. */
  capacity: number;
  active: number;
  waiting: number;
  /** Capacity not taken by an active seat. */
  available: number;
  /** Live pools. */
  pools: number;
  assignments: number;
  /** Active seats of people inactive for `reclaimAfterDays` (0 when reclaim is off). */
  reclaimable: number;
  /** The part of `reclaimable` held only through groups, which the reclaim job leaves (remove the people from the group). */
  reclaimableThroughGroups: number;
}

export interface LicenseUsageReport {
  tenantId: string;
  reclaimAfterDays?: number;
  products: LicenseUsage[];
}

/** One of the caller's own licenses (`licenses.mine`). */
export interface MyLicense {
  productId: string;
  key: string;
  name: string;
  description?: string;
  status: LicenseSeatStatus;
  /** Place on the waiting list, from 1 (waiting only). */
  position?: number;
  /** The feature keys the seat unlocks (none while waiting). */
  featureKeys: string[];
  /** Whether the platform (the root tenant) defines the product: only its feature keys are paid entitlements. */
  platform: boolean;
  /** The tenant that defines the product: the root tenant, the caller's tenant, or a tenant above it. */
  definedBy: string;
}

export interface MyLicenses {
  tenantId: string;
  identityId: string;
  licenses: MyLicense[];
  /**
   * The union of the feature keys of the caller's active seats of **platform** products: what the platform sells,
   * which no tenant can mint for itself (`iam.licenses.features` by default).
   */
  featureKeys: string[];
  /**
   * The union of the feature keys of all the caller's active seats, the products their tenant or a tenant above it
   * defines included. Any tenant can list any feature key in a product of its own, so never read these as entitlements
   * the platform sells; filter `licenses` by `definedBy` for the tenants you trust instead.
   */
  allFeatureKeys: string[];
}

export interface LicenseSettingsView {
  tenantId: string;
  reclaimAfterDays?: number;
  notifyWaiting: boolean;
  updatedAt?: number;
  updatedBy?: string;
}

export interface LicenseAssignResult {
  assignment: LicenseAssignmentView;
  /** Seats the assignment created or moved. */
  seats: LicenseSeatChange[];
}

export interface LicenseAssignManyResult {
  assigned: LicenseAssignmentView[];
  /** Identities that already held a direct assignment of the product. */
  skipped: string[];
  seats: LicenseSeatChange[];
}

export interface LicensePoolResult {
  pool: LicensePoolView;
  seats: LicenseSeatChange[];
}

export interface LicenseProductRetireResult {
  product: LicenseProductView;
  /** The seats released in every tenant that held the product. */
  seats: LicenseSeatChange[];
}

export interface LicenseReconcileResult {
  /** Tenants with licenses that were reconciled. */
  tenants: number;
  activated: number;
  waiting: number;
  released: number;
  failedTenants: Array<{ tenantId: string; code: string; message: string }>;
}

export interface LicenseReclaimResult {
  /** Tenants with reclaim turned on that were examined. */
  tenants: number;
  reclaimed: Array<{
    tenantId: string;
    productId: string;
    productKey: string;
    identityId: string;
    lastActivityAt: number;
  }>;
  failedTenants: Array<{ tenantId: string; code: string; message: string }>;
}

/** License helpers and jobs for the deployment's own server code (`iam.licenses`). */
export interface IamLicenses {
  /**
   * The feature keys of the products a person holds an active seat for in the tenant (none for inactive people), from
   * the products the trusted tenant or one of its ancestors defines only. Any tenant can define a product of its own that
   * lists any feature key, so by default only **platform** products (the root tenant's) count: pass `trustedTenantId`
   * to count the products a tenant (and the tenants above it) sells too, such as the tenant's own.
   */
  features(
    identityId: string,
    tenantId: string,
    options?: {
      /** Only products defined by this tenant or one of its ancestors count; the root tenant when left out. */
      trustedTenantId?: string;
    },
  ): Promise<string[]>;
  /** The keys of the products a person holds an active seat for in the tenant: what `principal.licenses` holds. */
  products(identityId: string, tenantId: string): Promise<string[]>;
  /**
   * A scheduler job (hourly): brings every tenant's seats in line with assignments, memberships, identity status and
   * pool terms, and re-evaluates birthright package rules for the people whose seats changed.
   */
  reconcile(input?: { tenantId?: string }): Promise<LicenseReconcileResult>;
  /**
   * A scheduler job (daily): in tenants with `reclaimAfterDays`, removes direct assignments of people with no sign-in or
   * credential use for that long (audited `license:reclaim`), then reconciles.
   */
  reclaim(input?: { tenantId?: string }): Promise<LicenseReclaimResult>;
}

const DAY = 86_400_000;
const seatStatuses = new Set<LicenseSeatStatus>(['active', 'waiting']);
const productStatuses = new Set<LicenseProductStatus>(['active', 'retired']);
const subjectTypes = new Set<LicenseSubjectType>(['identity', 'group']);
const productResource = (productId: string) => `licenses/products/${productId}`;
const poolResource = (poolId: string) => `licenses/pools/${poolId}`;
const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

function subjectType(value: unknown): LicenseSubjectType {
  if (typeof value !== 'string' || !subjectTypes.has(value as LicenseSubjectType))
    throw new IamError('INVALID_INPUT', "subjectType must be 'identity' or 'group'");
  return value as LicenseSubjectType;
}

function featureKeysOf(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > maxLicenseFeatureKeys)
    throw new IamError(
      'INVALID_INPUT',
      `featureKeys must list at most ${maxLicenseFeatureKeys} feature keys`,
    );
  return [...new Set(value.map(featureKey))].sort();
}

function optionalText(value: unknown, name: string, max: number): string | undefined {
  return value === undefined ? undefined : text(value, name, max).trim();
}

function timestamp(value: unknown, name: string): number {
  return integer(value, name, 0, Number.MAX_SAFE_INTEGER);
}

/** The views and whether each product's key is also defined further up (chain nearest-first). */
function productViews(products: LicenseProduct[], chain: readonly Tenant[], viewer: string) {
  const depth = new Map(chain.map((realm, index) => [realm.id, index]));
  const rootId = chain.at(-1)?.id;
  return products.map((product): LicenseProductView => {
    const own = depth.get(product.tenantId) ?? -1;
    return {
      id: product.id,
      key: product.key,
      name: product.name,
      ...(product.description !== undefined ? { description: product.description } : {}),
      featureKeys: product.featureKeys,
      status: product.status,
      scope: product.tenantId === rootId ? 'platform' : 'tenant',
      definedBy: product.tenantId,
      definedHere: product.tenantId === viewer,
      shadowed: products.some(
        (other) =>
          other.id !== product.id &&
          other.key === product.key &&
          (depth.get(other.tenantId) ?? -1) > own,
      ),
      createdAt: product.createdAt,
      createdBy: product.createdBy,
      updatedAt: product.updatedAt,
      updatedBy: product.updatedBy,
    };
  });
}

function productMetadata(product: LicenseProduct): Record<string, Json> {
  return {
    productId: product.id,
    key: product.key,
    name: product.name,
    description: product.description ?? null,
    featureKeys: product.featureKeys,
    status: product.status,
  };
}

function poolMetadata(pool: LicensePool, product: LicenseProduct): Record<string, Json> {
  return {
    poolId: pool.id,
    productId: product.id,
    productKey: product.key,
    quantity: pool.quantity,
    startsAt: pool.startsAt ?? null,
    endsAt: pool.endsAt ?? null,
    source: pool.source,
    subscriptionId: pool.subscriptionId ?? null,
  };
}

function poolView(
  pool: LicensePool,
  product: Pick<LicenseProduct, 'key' | 'name'>,
  tenantName: string,
  now: number,
): LicensePoolView {
  return {
    id: pool.id,
    tenantId: pool.tenantId,
    tenantName,
    productId: pool.productId,
    productKey: product.key,
    productName: product.name,
    quantity: pool.quantity,
    ...(pool.startsAt !== undefined ? { startsAt: pool.startsAt } : {}),
    ...(pool.endsAt !== undefined ? { endsAt: pool.endsAt } : {}),
    ...(pool.note !== undefined ? { note: pool.note } : {}),
    source: pool.source,
    ...(pool.subscriptionId !== undefined ? { subscriptionId: pool.subscriptionId } : {}),
    live: liveLicensePool(pool, now),
    createdAt: pool.createdAt,
    createdBy: pool.createdBy,
    ...(pool.updatedAt !== undefined ? { updatedAt: pool.updatedAt } : {}),
    ...(pool.updatedBy !== undefined ? { updatedBy: pool.updatedBy } : {}),
  };
}

/** Reads records by ID once per call. */
function cached<T>(load: (key: string) => Promise<T | undefined>) {
  const values = new Map<string, T | undefined>();
  return async (key: string): Promise<T | undefined> => {
    if (!values.has(key)) values.set(key, await load(key));
    return values.get(key);
  };
}

async function assignmentView(
  tx: IamStore,
  assignment: LicenseAssignment,
  product: Pick<LicenseProduct, 'key' | 'name'>,
): Promise<LicenseAssignmentView> {
  let subjectName = assignment.subjectId;
  let subjectEmail: string | undefined;
  if (assignment.subjectType === 'identity') {
    const identity = await tx.get<Identity>('identities', assignment.subjectId);
    if (identity) {
      subjectName = identity.name;
      subjectEmail = identity.email;
    }
  } else {
    const group = await tx.get<Group>('groups', assignment.subjectId);
    if (group) subjectName = group.name;
  }
  return {
    id: assignment.id,
    tenantId: assignment.tenantId,
    productId: assignment.productId,
    productKey: product.key,
    productName: product.name,
    subjectType: assignment.subjectType,
    subjectId: assignment.subjectId,
    subjectName,
    ...(subjectEmail !== undefined ? { subjectEmail } : {}),
    assignedBy: assignment.assignedBy,
    assignedAt: assignment.assignedAt,
  };
}

/** Waiting-list places per seat ID: per product, by seniority. */
function waitingPositions(seats: readonly LicenseSeat[]): Map<string, number> {
  const queues = new Map<string, LicenseSeat[]>();
  for (const seat of seats)
    if (seat.status === 'waiting')
      queues.set(seat.productId, [...(queues.get(seat.productId) ?? []), seat]);
  const positions = new Map<string, number>();
  for (const queue of queues.values())
    queue
      .sort((a, b) => a.assignedAt - b.assignedAt || byText(a.identityId, b.identityId))
      .forEach((seat, index) => positions.set(seat.id, index + 1));
  return positions;
}

/**
 * Package rules on `identity.licenses` re-evaluate for the people whose seats changed (post-commit, per tenant; never
 * throws).
 */
async function followSeats<T extends { seats: LicenseSeatChange[] }>(
  ctx: ServerContext,
  result: T,
): Promise<T> {
  const byTenant = new Map<string, Set<string>>();
  for (const change of result.seats)
    byTenant.set(
      change.tenantId,
      (byTenant.get(change.tenantId) ?? new Set()).add(change.identityId),
    );
  for (const [tenantId, identityIds] of byTenant)
    await afterIdentityChange(ctx, tenantId, [...identityIds], null);
  return result;
}

const failure = (tenantId: string, error: unknown) => ({
  tenantId,
  code: error instanceof IamError ? error.code : 'ERROR',
  message: error instanceof Error ? error.message : String(error),
});

async function tenantsFor(ctx: ServerContext, tenantId: string | undefined): Promise<Tenant[]> {
  return tenantId !== undefined
    ? [await ctx.tenant(ctx.store, text(tenantId, 'tenantId'))]
    : (await ctx.store.find<Tenant>('tenants', { status: 'active' })).sort((a, b) =>
        byText(a.id, b.id),
      );
}

/** The scheduler job behind `iam.licenses.reconcile`: one transaction per tenant with licenses. */
export async function reconcileAllLicenses(
  ctx: ServerContext,
  input: { tenantId?: string } = {},
): Promise<LicenseReconcileResult> {
  const result: LicenseReconcileResult = {
    tenants: 0,
    activated: 0,
    waiting: 0,
    released: 0,
    failedTenants: [],
  };
  for (const tenant of await tenantsFor(ctx, input.tenantId)) {
    if (tenant.status !== 'active') continue;
    try {
      const changes = await ctx.store.transaction(async (tx) => {
        if (
          !(await tx.find(licenseCollections.assignments, { tenantId: tenant.id }, { limit: 1 }))
            .length &&
          !(await tx.find(licenseCollections.seats, { tenantId: tenant.id }, { limit: 1 })).length
        )
          return undefined;
        return reconcileLicenses(ctx, tx, tenant.id, undefined, { reason: 'schedule' });
      });
      if (!changes) continue;
      result.tenants++;
      for (const change of changes)
        if (change.to === 'active') result.activated++;
        else if (change.to === 'waiting') result.waiting++;
        else result.released++;
      await followSeats(ctx, { seats: changes });
    } catch (error) {
      result.failedTenants.push(failure(tenant.id, error));
    }
  }
  return result;
}

/** The scheduler job behind `iam.licenses.reclaim`: one transaction per tenant with reclaim turned on. */
export async function reclaimLicenses(
  ctx: ServerContext,
  input: { tenantId?: string } = {},
): Promise<LicenseReclaimResult> {
  const result: LicenseReclaimResult = { tenants: 0, reclaimed: [], failedTenants: [] };
  const tenantIds =
    input.tenantId !== undefined
      ? [text(input.tenantId, 'tenantId')]
      : (await ctx.store.find<LicenseSettings>(licenseCollections.settings))
          .filter((settings) => settings.reclaimAfterDays !== undefined)
          .map((settings) => settings.tenantId)
          .sort(byText);
  for (const tenantId of tenantIds) {
    try {
      const outcome = await ctx.store.transaction(async (tx) => {
        const tenant = await ctx.tenant(tx, tenantId);
        const days = (await resolveLicenseSettings(tx, tenant.id)).reclaimAfterDays;
        if (tenant.status !== 'active' || days === undefined) return undefined;
        const now = ctx.now();
        const cutoff = now - days * DAY;
        const identity = cached((identityId) => tx.get<Identity>('identities', identityId));
        const activity = new Map<string, number>();
        const lastActivity = async (person: Identity) => {
          if (!activity.has(person.id)) activity.set(person.id, await lastActivityOf(tx, person));
          return activity.get(person.id)!;
        };
        // Seats remember what this pass saw, for the console and exports.
        for (const seat of await tx.find<LicenseSeat>(licenseCollections.seats, {
          tenantId: tenant.id,
        })) {
          const holder = await identity(seat.identityId);
          if (!holder) continue;
          const last = await lastActivity(holder);
          if (seat.lastActivityAt !== last)
            await tx.put<LicenseSeat>(licenseCollections.seats, { ...seat, lastActivityAt: last });
        }
        const product = cached((productId) =>
          tx.get<LicenseProduct>(licenseCollections.products, productId),
        );
        // Only a product that holds seats here has a seat to reclaim: the assignments of a retired product stay as
        // read-only history, and so do those of a product the tenant no longer sees (it moved away from the definer).
        const chain = new Set((await ctx.ancestry(tx, tenant)).map((link) => link.id));
        const reclaimed: LicenseReclaimResult['reclaimed'] = [];
        const productIds = new Set<string>();
        for (const assignment of await tx.find<LicenseAssignment>(licenseCollections.assignments, {
          tenantId: tenant.id,
          subjectType: 'identity',
        })) {
          // Someone assigned within the window has not had the chance to use it yet.
          if (assignment.assignedAt > cutoff) continue;
          const owner = await product(assignment.productId);
          if (owner?.status !== 'active' || !chain.has(owner.tenantId)) continue;
          const person = await identity(assignment.subjectId);
          const last = person && person.status !== 'deleted' ? await lastActivity(person) : 0;
          if (last > cutoff) continue;
          await tx.delete(licenseCollections.assignments, assignment.id);
          const key = owner.key;
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId: tenant.id,
            actorId: 'deployment-operator',
            action: 'license:reclaim',
            resourceId: assignment.subjectId,
            timestamp: now,
            outcome: 'allow',
            metadata: {
              productId: assignment.productId,
              productKey: key,
              assignedAt: assignment.assignedAt,
              lastActivityAt: last,
              reclaimAfterDays: days,
            },
          });
          productIds.add(assignment.productId);
          reclaimed.push({
            tenantId: tenant.id,
            productId: assignment.productId,
            productKey: key,
            identityId: assignment.subjectId,
            lastActivityAt: last,
          });
        }
        const seats: LicenseSeatChange[] = [];
        for (const productId of [...productIds].sort())
          seats.push(
            ...(await reconcileLicenses(ctx, tx, tenant.id, productId, { reason: 'reclaim' })),
          );
        return { reclaimed, seats };
      });
      if (!outcome) continue;
      result.tenants++;
      result.reclaimed.push(...outcome.reclaimed);
      await followSeats(ctx, outcome);
    } catch (error) {
      result.failedTenants.push(failure(tenantId, error));
    }
  }
  return result;
}

/** Credential-free license helpers and jobs, shared by `iam.licenses` and tests. */
export function createLicensesRuntime(ctx: ServerContext): IamLicenses {
  /**
   * The seats that count for a person of the tenant (none for inactive, expired, or other tenants' people). With
   * `trust`, only those of products defined by the trusted tenant or its ancestors: `trustedTenantId`, else the root
   * tenant alone (platform products).
   */
  const held = (
    identityId: string,
    tenantId: string,
    trust?: { trustedTenantId?: string | undefined },
  ) =>
    ctx.store.transaction(async (tx) => {
      const realm = await ctx.tenant(tx, tenantId);
      const trusted = !trust
        ? undefined
        : trust.trustedTenantId !== undefined
          ? new Set(
              (
                await ctx.ancestry(
                  tx,
                  await ctx.tenant(tx, text(trust.trustedTenantId, 'trustedTenantId')),
                )
              ).map((link) => link.id),
            )
          : new Set([(await ctx.ancestry(tx, realm)).at(-1)!.id]);
      const identity = await tx.get<Identity>('identities', text(identityId, 'identityId'));
      if (
        !identity ||
        identity.tenantId !== realm.id ||
        identity.status !== 'active' ||
        ctx.identityExpired(identity)
      )
        return [];
      const seats = await heldLicenses(tx, realm.id, identity.id, ctx.now());
      return trusted ? seats.filter(({ product }) => trusted.has(product.tenantId)) : seats;
    });
  return {
    async features(identityId, tenantId, options) {
      const trustedTenantId = (options ?? {}).trustedTenantId;
      return [
        ...new Set(
          (await held(identityId, tenantId, { trustedTenantId })).flatMap(
            ({ product }) => product.featureKeys,
          ),
        ),
      ].sort();
    },
    async products(identityId, tenantId) {
      return [
        ...new Set((await held(identityId, tenantId)).map(({ product }) => product.key)),
      ].sort();
    },
    reconcile: (input) => reconcileAllLicenses(ctx, input),
    reclaim: (input) => reclaimLicenses(ctx, input),
  };
}

/**
 * License management: products (SKUs) the platform or a tenant defines, pools of seats per consuming tenant, assignment
 * to people and groups, seats with a waiting list, and inactive-seat reclaim. What a license unlocks is expressed with
 * birthright package rules on `identity.licenses`, policies on `principal.licenses`, and product feature keys
 * (`iam.licenses.features`). Actions: iam:licenses:read, iam:licenses:manage (products, pools, settings) and
 * iam:licenses:assign, on `iam/licenses/products[/{id}]`, `iam/licenses/pools[/{id}]`, `iam/licenses/assignments`,
 * `iam/licenses/seats` and `iam/licenses/settings`.
 */
export function createLicensesApi(ctx: ServerContext) {
  const { operation } = ctx.operations;

  function writable(realm: Tenant): void {
    if (realm.status === 'deleted')
      throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot be updated', 409);
  }
  /** Platform products (the root tenant's) are defined and changed by a root administrator only. */
  async function platformGuard(
    tx: IamStore,
    realm: Tenant,
    principal: AuthenticatedPrincipal,
  ): Promise<void> {
    if (realm.parentId === null && !(await ctx.rootPrincipal(tx, principal)))
      throw new OperationDenied('Platform license products are managed by a root administrator');
  }
  async function visibleProduct(
    tx: IamStore,
    realm: Tenant,
    productId: unknown,
  ): Promise<{ product: LicenseProduct; chain: Tenant[] }> {
    const chain = await ctx.ancestry(tx, realm);
    const product = await tx.get<LicenseProduct>(
      licenseCollections.products,
      text(productId, 'productId'),
    );
    if (!product || !chain.some((link) => link.id === product.tenantId))
      throw new IamError('NOT_FOUND', 'License product not found', 404);
    return { product, chain };
  }
  async function ownProduct(
    tx: IamStore,
    realm: Tenant,
    productId: unknown,
  ): Promise<{ product: LicenseProduct; chain: Tenant[] }> {
    const found = await visibleProduct(tx, realm, productId);
    if (found.product.tenantId !== realm.id)
      throw new IamError(
        'INVALID_INPUT',
        'An enclosing tenant defines this product; change it there',
      );
    return found;
  }
  async function viewOf(
    tx: IamStore,
    realm: Tenant,
    product: LicenseProduct,
    chain: Tenant[],
  ): Promise<LicenseProductView> {
    const related = (await visibleLicenseProducts(tx, realm.id)).filter(
      (other) => other.key === product.key && other.id !== product.id,
    );
    return productViews([product, ...related], chain, realm.id)[0]!;
  }
  /**
   * Pool changes are authorized in the product's defining tenant: root for platform products (capacity bought from the
   * platform), the defining tenant's managers for their own products. Read outside the transaction to pick the tenant;
   * the operation re-reads and refuses when it changed.
   */
  async function poolAuthority(
    productId: string | undefined,
    fallback: string,
  ): Promise<{ tenantId: string; platform: boolean }> {
    const product =
      productId !== undefined
        ? await ctx.store.get<LicenseProduct>(licenseCollections.products, productId)
        : undefined;
    const definer = product ? await ctx.store.get<Tenant>('tenants', product.tenantId) : undefined;
    return definer
      ? { tenantId: definer.id, platform: definer.parentId === null }
      : { tenantId: fallback, platform: false };
  }
  /**
   * The consuming tenant and product of a pool change, checked against the authorizing (defining) tenant. With
   * `detached`, a pool of a tenant that has since moved out from under the definer passes too, so the definer can still
   * remove capacity it granted (`removePool`); nothing else changes such a pool.
   */
  async function poolTarget(
    tx: IamStore,
    definer: Tenant,
    consumerId: unknown,
    productId: string,
    detached = false,
  ): Promise<{ product: LicenseProduct; consumer: Tenant }> {
    const consumer = await ctx.tenant(tx, text(consumerId, 'tenantId'));
    const product = await tx.get<LicenseProduct>(licenseCollections.products, productId);
    if (!product) throw new IamError('NOT_FOUND', 'License product not found', 404);
    if (product.tenantId !== definer.id)
      throw new IamError('CONFLICT', 'The product changed; try again', 409);
    if (!detached && !(await ctx.ancestry(tx, consumer)).some((link) => link.id === definer.id))
      throw new IamError(
        'INVALID_INPUT',
        'tenantId must be the tenant that defines the product or a tenant below it',
      );
    writable(consumer);
    if (product.status !== 'active')
      throw new IamError(
        'INVALID_TRANSITION',
        'The product is retired; its pools are read-only',
        409,
      );
    return { product, consumer };
  }
  /**
   * Capacity granted from an enclosing tenant moves seats in the receiving tenant, whose enforced access invariants the
   * operation envelope (run in the defining tenant) does not check: they are checked around the change the same way.
   * Call before changing anything; the returned function refuses (rolling back) a change that newly breaks one.
   */
  async function consumerInvariants(
    tx: IamStore,
    definer: Tenant,
    consumer: Tenant,
  ): Promise<() => Promise<void>> {
    const snapshot =
      consumer.id !== definer.id
        ? await invariantSnapshot(ctx, tx, consumer.id, 'iam:licenses:manage')
        : undefined;
    return () => invariantVerify(ctx, tx, consumer.id, snapshot);
  }
  const audit = (
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    action: string,
    tenantId: string,
    resourceId: string,
    metadata: Record<string, Json>,
  ) => ctx.events.audit(tx, principal, action, tenantId, resourceId, 'allow', false, metadata);

  return {
    /**
     * The products the tenant can use, sorted by key: its own and its ancestors' (the root tenant's are platform
     * products), optionally one `status`. `shadowed` marks a product whose key an enclosing tenant also defines (the
     * enclosing product wins; the shadowed one's seats grant nothing). Requires iam:licenses:read on
     * `iam/licenses/products`.
     */
    listProducts: (
      credential: CredentialInput,
      input: { tenantId: string; status?: LicenseProductStatus },
    ): Promise<{ tenantId: string; products: LicenseProductView[] }> =>
      operation(
        credential,
        input.tenantId,
        'iam:licenses:read',
        'licenses/products',
        async ({ tx, tenant: realm }) => {
          if (input.status !== undefined && !productStatuses.has(input.status))
            throw new IamError('INVALID_INPUT', "status must be 'active' or 'retired'");
          const chain = await ctx.ancestry(tx, realm);
          const depth = new Map(chain.map((link, index) => [link.id, index]));
          const products = await visibleLicenseProducts(tx, realm.id);
          return {
            tenantId: realm.id,
            products: productViews(products, chain, realm.id)
              .filter((view) => input.status === undefined || view.status === input.status)
              .sort(
                (a, b) =>
                  byText(a.key, b.key) ||
                  (depth.get(b.definedBy) ?? 0) - (depth.get(a.definedBy) ?? 0),
              ),
          };
        },
      ),
    /** One product visible to the tenant. Requires iam:licenses:read on `iam/licenses/products/{id}`. */
    getProduct: async (
      credential: CredentialInput,
      input: { tenantId: string; productId: string },
    ): Promise<LicenseProductView> => {
      const productId = text(input.productId, 'productId');
      return operation(
        credential,
        input.tenantId,
        'iam:licenses:read',
        productResource(productId),
        async ({ tx, tenant: realm }) => {
          const { product, chain } = await visibleProduct(tx, realm, productId);
          return viewOf(tx, realm, product, chain);
        },
      );
    },
    /**
     * Defines a product: on the root tenant a platform product (root administrators only), elsewhere a product for the
     * tenant's subtree. Keys are unique per tenant and may not repeat a key an ancestor defines; a key a tenant below
     * already uses is taken over (that product becomes `shadowed` and grants nothing), so no tenant can claim a key
     * first. At most 200 products per tenant and 50 feature keys per product. Requires recent authentication and
     * iam:licenses:manage on `iam/licenses/products`; audited as `license:product-create`.
     */
    createProduct: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        key: string;
        name: string;
        description?: string;
        featureKeys?: string[];
      },
    ): Promise<LicenseProductView> => {
      const key = licenseKey(input.key);
      return operation(
        credential,
        input.tenantId,
        'iam:licenses:manage',
        'licenses/products',
        async ({ tx, tenant: realm, principal }) => {
          ctx.auth.requireRecent(principal);
          writable(realm);
          await platformGuard(tx, realm, principal);
          const name = text(input.name, 'name', 100).trim();
          const description = optionalText(input.description, 'description', 512);
          const featureKeys = featureKeysOf(input.featureKeys ?? []);
          const chain = await ctx.ancestry(tx, realm);
          for (const ancestor of chain.slice(1))
            if (
              (
                await tx.find(licenseCollections.products, {
                  tenantId: ancestor.id,
                  uniqueKey: `key:${key}`,
                })
              ).length
            )
              throw new IamError(
                'CONFLICT',
                ancestor.parentId === null
                  ? 'A platform license product already uses this key'
                  : 'An enclosing tenant already defines a license product with this key',
                409,
              );
          const existing = await tx.find<LicenseProduct>(licenseCollections.products, {
            tenantId: realm.id,
          });
          if (existing.some((product) => product.key === key))
            throw new IamError('CONFLICT', 'A license product with this key already exists', 409);
          if (existing.length >= maxLicenseProductsPerTenant)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant can define at most ${maxLicenseProductsPerTenant} license products`,
              409,
            );
          const now = ctx.now();
          const product = await tx.insert<LicenseProduct>(licenseCollections.products, {
            id: id(),
            tenantId: realm.id,
            uniqueKey: `key:${key}`,
            key,
            name,
            ...(description !== undefined ? { description } : {}),
            featureKeys,
            status: 'active',
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
            updatedBy: principal.identity.id,
          });
          await audit(
            tx,
            principal,
            'license:product-create',
            realm.id,
            productResource(product.id),
            productMetadata(product),
          );
          return productViews([product], chain, realm.id)[0]!;
        },
      );
    },
    /**
     * Renames a product, changes (`null` clears) its description, or replaces its feature keys; the key never changes.
     * Only the defining tenant (root administrators for platform products). Requires iam:licenses:manage on
     * `iam/licenses/products/{id}`; audited as `license:product-update` with the settings before and after.
     */
    updateProduct: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        productId: string;
        name?: string;
        description?: string | null;
        featureKeys?: string[];
      },
    ): Promise<LicenseProductView> => {
      const productId = text(input.productId, 'productId');
      return operation(
        credential,
        input.tenantId,
        'iam:licenses:manage',
        productResource(productId),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const { product, chain } = await ownProduct(tx, realm, productId);
          await platformGuard(tx, realm, principal);
          if (
            input.name === undefined &&
            input.description === undefined &&
            input.featureKeys === undefined
          )
            throw new IamError('INVALID_INPUT', 'Nothing to update');
          const { description: _description, ...rest } = product;
          const description =
            input.description === undefined
              ? product.description
              : input.description === null
                ? undefined
                : text(input.description, 'description', 512).trim();
          const next = await tx.put<LicenseProduct>(licenseCollections.products, {
            ...rest,
            ...(input.name !== undefined ? { name: text(input.name, 'name', 100).trim() } : {}),
            ...(description !== undefined ? { description } : {}),
            ...(input.featureKeys !== undefined
              ? { featureKeys: featureKeysOf(input.featureKeys) }
              : {}),
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          });
          await audit(tx, principal, 'license:product-update', realm.id, productResource(next.id), {
            before: productMetadata(product),
            after: productMetadata(next),
          });
          return viewOf(tx, realm, next, chain);
        },
      );
    },
    /**
     * Retires a product for good: every seat of it is released in every tenant, its pools and assignments stay
     * read-only, and its key stays taken. Only the defining tenant (root administrators for platform products).
     * Requires recent authentication and iam:licenses:manage on `iam/licenses/products/{id}`; audited as
     * `license:product-retire`, with a `license:seat-release` per seat.
     */
    retireProduct: async (
      credential: CredentialInput,
      input: { tenantId: string; productId: string },
    ): Promise<LicenseProductRetireResult> => {
      const productId = text(input.productId, 'productId');
      const result = await operation(
        credential,
        input.tenantId,
        'iam:licenses:manage',
        productResource(productId),
        async ({ tx, tenant: realm, principal }) => {
          ctx.auth.requireRecent(principal);
          const { product, chain } = await ownProduct(tx, realm, productId);
          await platformGuard(tx, realm, principal);
          if (product.status === 'retired')
            throw new IamError('INVALID_TRANSITION', 'The product is already retired', 409);
          const next = await tx.put<LicenseProduct>(licenseCollections.products, {
            ...product,
            status: 'retired',
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          });
          const tenantIds = [
            ...new Set(
              (await tx.find<LicenseSeat>(licenseCollections.seats, { productId: product.id })).map(
                (seat) => seat.tenantId,
              ),
            ),
          ].sort(byText);
          const seats: LicenseSeatChange[] = [];
          for (const tenantId of tenantIds)
            seats.push(
              ...(await reconcileLicenses(ctx, tx, tenantId, product.id, {
                actor: principal,
                reason: 'product-retired',
              })),
            );
          await audit(tx, principal, 'license:product-retire', realm.id, productResource(next.id), {
            productId: next.id,
            key: next.key,
            releasedSeats: seats.length,
            tenants: tenantIds.length,
          });
          return { product: await viewOf(tx, realm, next, chain), seats };
        },
      );
      return followSeats(ctx, result);
    },
    /**
     * Pools of the tenant (`tenantId` consumes them) and, for products the tenant defines, the pools it granted to
     * tenants below it; newest first. Ended pools only with `includeEnded`. Requires iam:licenses:read on
     * `iam/licenses/pools`.
     */
    listPools: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        productId?: string;
        includeEnded?: boolean;
        limit?: number;
        offset?: number;
      },
    ): Promise<{ pools: LicensePoolView[]; total: number }> =>
      operation(
        credential,
        input.tenantId,
        'iam:licenses:read',
        'licenses/pools',
        async ({ tx, tenant: realm }) => {
          const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
          const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
          const productId =
            input.productId !== undefined ? text(input.productId, 'productId') : undefined;
          if (input.includeEnded !== undefined && typeof input.includeEnded !== 'boolean')
            throw new IamError('INVALID_INPUT', 'includeEnded must be a boolean');
          const now = ctx.now();
          const rows = await tx.find<LicensePool>(licenseCollections.pools, {
            tenantId: realm.id,
            ...(productId !== undefined ? { productId } : {}),
          });
          for (const product of await tx.find<LicenseProduct>(licenseCollections.products, {
            tenantId: realm.id,
          }))
            if (productId === undefined || product.id === productId)
              for (const pool of await tx.find<LicensePool>(licenseCollections.pools, {
                productId: product.id,
              }))
                if (pool.tenantId !== realm.id) rows.push(pool);
          const shown = rows
            .filter(
              (pool) =>
                input.includeEnded === true || pool.endsAt === undefined || pool.endsAt > now,
            )
            .sort((a, b) => b.createdAt - a.createdAt || byText(a.id, b.id));
          const product = cached((key) => tx.get<LicenseProduct>(licenseCollections.products, key));
          const tenant = cached((key) => tx.get<Tenant>('tenants', key));
          const pools: LicensePoolView[] = [];
          for (const pool of shown.slice(offset, offset + limit)) {
            const owner = await product(pool.productId);
            pools.push(
              poolView(
                pool,
                owner ?? { key: pool.productId, name: pool.productId },
                (await tenant(pool.tenantId))?.name ?? pool.tenantId,
                now,
              ),
            );
          }
          return { pools, total: shown.length };
        },
      ),
    /**
     * Adds capacity to a tenant (`tenantId`): `quantity` seats of the product from `startsAt` until `endsAt`, optionally
     * referencing the billing subscription that bought them. Authorized in the product's defining tenant: root
     * administrators for platform products, the defining tenant's managers for their own products (for the tenant
     * itself or one below it). Requires iam:licenses:manage on `iam/licenses/pools`; audited as `license:pool-add` in
     * the receiving tenant. Waiting people take the new seats.
     */
    addPool: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        productId: string;
        quantity: number;
        startsAt?: number;
        endsAt?: number;
        note?: string;
        subscriptionId?: string;
      },
    ): Promise<LicensePoolResult> => {
      const productId = text(input.productId, 'productId');
      const authority = await poolAuthority(productId, input.tenantId);
      const result = await operation(
        credential,
        authority.tenantId,
        'iam:licenses:manage',
        'licenses/pools',
        async ({ tx, tenant: definer, principal }) => {
          const { product, consumer } = await poolTarget(tx, definer, input.tenantId, productId);
          const quantity = integer(input.quantity, 'quantity', 1, maxLicensePoolQuantity);
          const now = ctx.now();
          const startsAt =
            input.startsAt === undefined ? undefined : timestamp(input.startsAt, 'startsAt');
          const endsAt = input.endsAt === undefined ? undefined : timestamp(input.endsAt, 'endsAt');
          if (
            endsAt !== undefined &&
            (endsAt <= now || (startsAt !== undefined && endsAt <= startsAt))
          )
            throw new IamError('INVALID_INPUT', 'endsAt must be in the future and after startsAt');
          const note = optionalText(input.note, 'note', 512);
          let subscriptionId: string | undefined;
          if (input.subscriptionId !== undefined) {
            subscriptionId = text(input.subscriptionId, 'subscriptionId');
            const subscription = await tx.get<BillingSubscription>(
              billingCollections.subscriptions,
              subscriptionId,
            );
            // The subscription belongs to the receiving tenant's billing account: itself or an enclosing tenant.
            if (
              !subscription ||
              !(await ctx.ancestry(tx, consumer)).some((link) => link.id === subscription.tenantId)
            )
              throw new IamError('NOT_FOUND', 'Subscription not found', 404);
          }
          if (
            (
              await tx.find(licenseCollections.pools, {
                tenantId: consumer.id,
                productId: product.id,
              })
            ).length >= maxLicensePoolsPerProduct
          )
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant can hold at most ${maxLicensePoolsPerProduct} pools of one product`,
              409,
            );
          const verifyConsumer = await consumerInvariants(tx, definer, consumer);
          const pool = await tx.insert<LicensePool>(licenseCollections.pools, {
            id: id(),
            tenantId: consumer.id,
            productId: product.id,
            quantity,
            ...(startsAt !== undefined ? { startsAt } : {}),
            ...(endsAt !== undefined ? { endsAt, expiresAt: endsAt + licensePoolRetentionMs } : {}),
            ...(note !== undefined ? { note } : {}),
            source: subscriptionId !== undefined ? 'subscription' : 'manual',
            ...(subscriptionId !== undefined ? { subscriptionId } : {}),
            createdAt: now,
            createdBy: principal.identity.id,
          });
          await audit(
            tx,
            principal,
            'license:pool-add',
            consumer.id,
            poolResource(pool.id),
            poolMetadata(pool, product),
          );
          const seats = await reconcileLicenses(ctx, tx, consumer.id, product.id, {
            actor: principal,
            reason: 'pool-add',
          });
          await verifyConsumer();
          return { pool: poolView(pool, product, consumer.name, now), seats };
        },
        authority.platform,
      );
      return followSeats(ctx, result);
    },
    /**
     * Changes a pool's `quantity`, its end (`endsAt`; `null` makes it open-ended, a past time ends it now) or its note
     * (`null` clears). Reducing capacity below the active seats moves the newest active seats to the waiting list.
     * Authorized like `addPool`, on `iam/licenses/pools/{id}`; audited as `license:pool-update` with the pool before and
     * after.
     */
    updatePool: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        poolId: string;
        quantity?: number;
        endsAt?: number | null;
        note?: string | null;
      },
    ): Promise<LicensePoolResult> => {
      const poolId = text(input.poolId, 'poolId');
      const found = await ctx.store.get<LicensePool>(licenseCollections.pools, poolId);
      const authority = await poolAuthority(
        found?.tenantId === input.tenantId ? found.productId : undefined,
        input.tenantId,
      );
      const result = await operation(
        credential,
        authority.tenantId,
        'iam:licenses:manage',
        poolResource(poolId),
        async ({ tx, tenant: definer, principal }) => {
          const pool = await ctx.scoped<LicensePool>(
            tx,
            licenseCollections.pools,
            poolId,
            text(input.tenantId, 'tenantId'),
          );
          const { product, consumer } = await poolTarget(
            tx,
            definer,
            pool.tenantId,
            pool.productId,
          );
          if (
            input.quantity === undefined &&
            input.endsAt === undefined &&
            input.note === undefined
          )
            throw new IamError('INVALID_INPUT', 'Nothing to update');
          const { endsAt: _endsAt, expiresAt: _expiresAt, note: _note, ...rest } = pool;
          const endsAt =
            input.endsAt === undefined
              ? pool.endsAt
              : input.endsAt === null
                ? undefined
                : timestamp(input.endsAt, 'endsAt');
          if (endsAt !== undefined && pool.startsAt !== undefined && endsAt <= pool.startsAt)
            throw new IamError('INVALID_INPUT', 'endsAt must be after startsAt');
          const note =
            input.note === undefined
              ? pool.note
              : input.note === null
                ? undefined
                : text(input.note, 'note', 512).trim();
          const verifyConsumer = await consumerInvariants(tx, definer, consumer);
          const now = ctx.now();
          const next = await tx.put<LicensePool>(licenseCollections.pools, {
            ...rest,
            quantity:
              input.quantity === undefined
                ? pool.quantity
                : integer(input.quantity, 'quantity', 1, maxLicensePoolQuantity),
            ...(endsAt !== undefined ? { endsAt, expiresAt: endsAt + licensePoolRetentionMs } : {}),
            ...(note !== undefined ? { note } : {}),
            updatedAt: now,
            updatedBy: principal.identity.id,
          });
          await audit(tx, principal, 'license:pool-update', consumer.id, poolResource(pool.id), {
            before: poolMetadata(pool, product),
            after: poolMetadata(next, product),
          });
          const seats = await reconcileLicenses(ctx, tx, consumer.id, product.id, {
            actor: principal,
            reason: 'pool-update',
          });
          await verifyConsumer();
          return { pool: poolView(next, product, consumer.name, now), seats };
        },
        authority.platform,
      );
      return followSeats(ctx, result);
    },
    /**
     * Removes a pool; the newest active seats beyond the remaining capacity move to the waiting list. Authorized like
     * `addPool`, on `iam/licenses/pools/{id}`, including a pool of a tenant that has since moved out from under the
     * defining tenant; audited as `license:pool-remove`.
     */
    removePool: async (
      credential: CredentialInput,
      input: { tenantId: string; poolId: string },
    ): Promise<{ removed: true; seats: LicenseSeatChange[] }> => {
      const poolId = text(input.poolId, 'poolId');
      const found = await ctx.store.get<LicensePool>(licenseCollections.pools, poolId);
      const authority = await poolAuthority(
        found?.tenantId === input.tenantId ? found.productId : undefined,
        input.tenantId,
      );
      const result = await operation(
        credential,
        authority.tenantId,
        'iam:licenses:manage',
        poolResource(poolId),
        async ({ tx, tenant: definer, principal }) => {
          const pool = await ctx.scoped<LicensePool>(
            tx,
            licenseCollections.pools,
            poolId,
            text(input.tenantId, 'tenantId'),
          );
          // A tenant that moved away keeps no hold on capacity the definer granted it.
          const { product, consumer } = await poolTarget(
            tx,
            definer,
            pool.tenantId,
            pool.productId,
            true,
          );
          const verifyConsumer = await consumerInvariants(tx, definer, consumer);
          await tx.delete(licenseCollections.pools, pool.id);
          await audit(
            tx,
            principal,
            'license:pool-remove',
            consumer.id,
            poolResource(pool.id),
            poolMetadata(pool, product),
          );
          const seats = await reconcileLicenses(ctx, tx, consumer.id, product.id, {
            actor: principal,
            reason: 'pool-remove',
          });
          await verifyConsumer();
          return { removed: true as const, seats };
        },
        authority.platform,
      );
      return followSeats(ctx, result);
    },
    /**
     * Gives a product to a person (any kind; guests too) or a group of the tenant. The person, or each active member of
     * the group, claims a seat: active while capacity lasts, otherwise on the waiting list. At most 10,000 assignments
     * per product (assign groups instead). Requires iam:licenses:assign on `iam/licenses/assignments`; audited as
     * `license:assign`, with the seat changes it caused.
     */
    assign: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        productId: string;
        subjectType: LicenseSubjectType;
        subjectId: string;
      },
    ): Promise<LicenseAssignResult> => {
      const result = await operation(
        credential,
        input.tenantId,
        'iam:licenses:assign',
        'licenses/assignments',
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const { product } = await visibleProduct(tx, realm, input.productId);
          if (product.status !== 'active')
            throw new IamError('INVALID_TRANSITION', 'The product is retired', 409);
          const type = subjectType(input.subjectType);
          const subjectId = text(input.subjectId, 'subjectId');
          if (type === 'identity') await ctx.activeIdentity(tx, subjectId, realm.id);
          else await ctx.scoped<Group>(tx, 'groups', subjectId, realm.id);
          const uniqueKey = `${product.id}:${type}:${subjectId}`;
          if (
            (await tx.find(licenseCollections.assignments, { tenantId: realm.id, uniqueKey }))
              .length
          )
            throw new IamError('CONFLICT', 'The product is already assigned to this subject', 409);
          if (
            (
              await tx.find(licenseCollections.assignments, {
                tenantId: realm.id,
                productId: product.id,
              })
            ).length >= maxLicenseAssignmentsPerProduct
          )
            throw new IamError(
              'LIMIT_EXCEEDED',
              `At most ${maxLicenseAssignmentsPerProduct} assignments per product; assign groups instead`,
              409,
            );
          const assignment = await tx.insert<LicenseAssignment>(licenseCollections.assignments, {
            id: id(),
            tenantId: realm.id,
            uniqueKey,
            productId: product.id,
            subjectType: type,
            subjectId,
            assignedBy: principal.identity.id,
            assignedAt: ctx.now(),
          });
          await audit(tx, principal, 'license:assign', realm.id, subjectId, {
            assignmentId: assignment.id,
            productId: product.id,
            productKey: product.key,
            subjectType: type,
          });
          const seats = await reconcileLicenses(ctx, tx, realm.id, product.id, {
            actor: principal,
            reason: 'assign',
          });
          return { assignment: await assignmentView(tx, assignment, product), seats };
        },
      );
      return followSeats(ctx, result);
    },
    /**
     * Gives a product to up to 100 people at once (one transaction; people who already hold a direct assignment are
     * skipped). Requires iam:licenses:assign on `iam/licenses/assignments`; audited as `license:assign` per person.
     */
    assignMany: async (
      credential: CredentialInput,
      input: { tenantId: string; productId: string; identityIds: string[] },
    ): Promise<LicenseAssignManyResult> => {
      const result = await operation(
        credential,
        input.tenantId,
        'iam:licenses:assign',
        'licenses/assignments',
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const identityIds = [...new Set(strings(input.identityIds, 'identityIds'))];
          if (!identityIds.length) throw new IamError('INVALID_INPUT', 'Provide 1-100 identityIds');
          const { product } = await visibleProduct(tx, realm, input.productId);
          if (product.status !== 'active')
            throw new IamError('INVALID_TRANSITION', 'The product is retired', 409);
          const existing = await tx.find<LicenseAssignment>(licenseCollections.assignments, {
            tenantId: realm.id,
            productId: product.id,
          });
          const held = new Set(existing.map((assignment) => assignment.uniqueKey));
          const assigned: LicenseAssignmentView[] = [];
          const skipped: string[] = [];
          for (const identityId of identityIds) {
            await ctx.activeIdentity(tx, identityId, realm.id);
            const uniqueKey = `${product.id}:identity:${identityId}`;
            if (held.has(uniqueKey)) {
              skipped.push(identityId);
              continue;
            }
            if (existing.length + assigned.length >= maxLicenseAssignmentsPerProduct)
              throw new IamError(
                'LIMIT_EXCEEDED',
                `At most ${maxLicenseAssignmentsPerProduct} assignments per product; assign groups instead`,
                409,
              );
            const assignment = await tx.insert<LicenseAssignment>(licenseCollections.assignments, {
              id: id(),
              tenantId: realm.id,
              uniqueKey,
              productId: product.id,
              subjectType: 'identity',
              subjectId: identityId,
              assignedBy: principal.identity.id,
              assignedAt: ctx.now(),
            });
            held.add(uniqueKey);
            await audit(tx, principal, 'license:assign', realm.id, identityId, {
              assignmentId: assignment.id,
              productId: product.id,
              productKey: product.key,
              subjectType: 'identity',
            });
            assigned.push(await assignmentView(tx, assignment, product));
          }
          const seats = assigned.length
            ? await reconcileLicenses(ctx, tx, realm.id, product.id, {
                actor: principal,
                reason: 'assign',
              })
            : [];
          return { assigned, skipped, seats };
        },
      );
      return followSeats(ctx, result);
    },
    /**
     * Removes an assignment, by `assignmentId` or by product and subject. Seats it carried are released (unless another
     * assignment still covers the person) and waiting people move up. Requires iam:licenses:assign on
     * `iam/licenses/assignments`; audited as `license:unassign`.
     */
    unassign: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        assignmentId?: string;
        productId?: string;
        subjectType?: LicenseSubjectType;
        subjectId?: string;
      },
    ): Promise<{ removed: true; seats: LicenseSeatChange[] }> => {
      const result = await operation(
        credential,
        input.tenantId,
        'iam:licenses:assign',
        'licenses/assignments',
        async ({ tx, tenant: realm, principal }) => {
          let assignment: LicenseAssignment | undefined;
          if (input.assignmentId !== undefined)
            assignment = await ctx.scoped<LicenseAssignment>(
              tx,
              licenseCollections.assignments,
              input.assignmentId,
              realm.id,
            );
          else {
            const uniqueKey = `${text(input.productId, 'productId')}:${subjectType(input.subjectType)}:${text(input.subjectId, 'subjectId')}`;
            assignment = (
              await tx.find<LicenseAssignment>(licenseCollections.assignments, {
                tenantId: realm.id,
                uniqueKey,
              })
            )[0];
            if (!assignment) throw new IamError('NOT_FOUND', 'Assignment not found', 404);
          }
          await tx.delete(licenseCollections.assignments, assignment.id);
          const product = await tx.get<LicenseProduct>(
            licenseCollections.products,
            assignment.productId,
          );
          await audit(tx, principal, 'license:unassign', realm.id, assignment.subjectId, {
            assignmentId: assignment.id,
            productId: assignment.productId,
            productKey: product?.key ?? assignment.productId,
            subjectType: assignment.subjectType,
          });
          const seats = await reconcileLicenses(ctx, tx, realm.id, assignment.productId, {
            actor: principal,
            reason: 'unassign',
          });
          return { removed: true as const, seats };
        },
      );
      return followSeats(ctx, result);
    },
    /**
     * The tenant's assignments, newest first, optionally of one product or subject. Requires iam:licenses:read on
     * `iam/licenses/assignments`.
     */
    listAssignments: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        productId?: string;
        subjectType?: LicenseSubjectType;
        subjectId?: string;
        limit?: number;
        offset?: number;
      },
    ): Promise<{ assignments: LicenseAssignmentView[]; total: number }> =>
      operation(
        credential,
        input.tenantId,
        'iam:licenses:read',
        'licenses/assignments',
        async ({ tx, tenant: realm }) => {
          const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
          const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
          const rows = (
            await tx.find<LicenseAssignment>(licenseCollections.assignments, {
              tenantId: realm.id,
              ...(input.productId !== undefined
                ? { productId: text(input.productId, 'productId') }
                : {}),
              ...(input.subjectType !== undefined
                ? { subjectType: subjectType(input.subjectType) }
                : {}),
              ...(input.subjectId !== undefined
                ? { subjectId: text(input.subjectId, 'subjectId') }
                : {}),
            })
          ).sort((a, b) => b.assignedAt - a.assignedAt || byText(a.id, b.id));
          const product = cached((key) => tx.get<LicenseProduct>(licenseCollections.products, key));
          const assignments: LicenseAssignmentView[] = [];
          for (const assignment of rows.slice(offset, offset + limit))
            assignments.push(
              await assignmentView(
                tx,
                assignment,
                (await product(assignment.productId)) ?? {
                  key: assignment.productId,
                  name: assignment.productId,
                },
              ),
            );
          return { assignments, total: rows.length };
        },
      ),
    /**
     * The tenant's seats, optionally of one product, status or person: by product key, active before waiting, then by
     * seniority (the waiting list's order, with each waiting seat's `position`). Requires iam:licenses:read on
     * `iam/licenses/seats`.
     */
    listSeats: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        productId?: string;
        status?: LicenseSeatStatus;
        identityId?: string;
        limit?: number;
        offset?: number;
      },
    ): Promise<{ seats: LicenseSeatView[]; total: number }> =>
      operation(
        credential,
        input.tenantId,
        'iam:licenses:read',
        'licenses/seats',
        async ({ tx, tenant: realm }) => {
          const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
          const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
          if (input.status !== undefined && !seatStatuses.has(input.status))
            throw new IamError('INVALID_INPUT', "status must be 'active' or 'waiting'");
          const identityId =
            input.identityId !== undefined ? text(input.identityId, 'identityId') : undefined;
          const all = await tx.find<LicenseSeat>(licenseCollections.seats, {
            tenantId: realm.id,
            ...(input.productId !== undefined
              ? { productId: text(input.productId, 'productId') }
              : {}),
          });
          const positions = waitingPositions(all);
          const product = cached((key) => tx.get<LicenseProduct>(licenseCollections.products, key));
          const keys = new Map<string, string>();
          for (const seat of all)
            if (!keys.has(seat.productId))
              keys.set(seat.productId, (await product(seat.productId))?.key ?? seat.productId);
          const rows = all
            .filter(
              (seat) =>
                (input.status === undefined || seat.status === input.status) &&
                (identityId === undefined || seat.identityId === identityId),
            )
            .sort(
              (a, b) =>
                byText(keys.get(a.productId)!, keys.get(b.productId)!) ||
                byText(a.productId, b.productId) ||
                Number(a.status === 'waiting') - Number(b.status === 'waiting') ||
                a.assignedAt - b.assignedAt ||
                byText(a.identityId, b.identityId),
            );
          const seats: LicenseSeatView[] = [];
          for (const seat of rows.slice(offset, offset + limit)) {
            const owner = await product(seat.productId);
            const holder = await tx.get<Identity>('identities', seat.identityId);
            const position = positions.get(seat.id);
            seats.push({
              id: seat.id,
              tenantId: seat.tenantId,
              productId: seat.productId,
              productKey: owner?.key ?? seat.productId,
              productName: owner?.name ?? seat.productId,
              identityId: seat.identityId,
              identityName: holder?.name ?? seat.identityId,
              ...(holder?.email !== undefined ? { identityEmail: holder.email } : {}),
              ...(holder ? { identityKind: holder.kind } : {}),
              status: seat.status,
              ...(position !== undefined ? { position } : {}),
              direct: seat.sources.direct === true,
              groupIds: seat.sources.groupIds ?? [],
              assignedAt: seat.assignedAt,
              ...(seat.activatedAt !== undefined ? { activatedAt: seat.activatedAt } : {}),
              ...(seat.lastActivityAt !== undefined ? { lastActivityAt: seat.lastActivityAt } : {}),
            });
          }
          return { seats, total: rows.length };
        },
      ),
    /**
     * Per product the tenant uses (it has pools, seats or assignments, or defines it): capacity from the live pools,
     * active and waiting seats, what is available, and with `reclaimAfterDays` set how many active seats belong to
     * people inactive that long (`reclaimable`; `reclaimableThroughGroups` for those held only through groups).
     * Requires iam:licenses:read on `iam/licenses/seats`.
     */
    usage: (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<LicenseUsageReport> =>
      operation(
        credential,
        input.tenantId,
        'iam:licenses:read',
        'licenses/seats',
        async ({ tx, tenant: realm }) => {
          const now = ctx.now();
          const chain = await ctx.ancestry(tx, realm);
          const rootId = chain.at(-1)!.id;
          const settings = await resolveLicenseSettings(tx, realm.id);
          const cutoff =
            settings.reclaimAfterDays !== undefined
              ? now - settings.reclaimAfterDays * DAY
              : undefined;
          const pools = await tx.find<LicensePool>(licenseCollections.pools, {
            tenantId: realm.id,
          });
          const seats = await tx.find<LicenseSeat>(licenseCollections.seats, {
            tenantId: realm.id,
          });
          const assignments = await tx.find<LicenseAssignment>(licenseCollections.assignments, {
            tenantId: realm.id,
          });
          const used = new Set([
            ...pools.map((pool) => pool.productId),
            ...seats.map((seat) => seat.productId),
            ...assignments.map((assignment) => assignment.productId),
          ]);
          const activity = new Map<string, number | undefined>();
          const inactive = async (seat: LicenseSeat): Promise<boolean> => {
            if (cutoff === undefined || seat.status !== 'active' || seat.assignedAt > cutoff)
              return false;
            if (!activity.has(seat.identityId)) {
              const holder = await tx.get<Identity>('identities', seat.identityId);
              activity.set(seat.identityId, holder ? await lastActivityOf(tx, holder) : undefined);
            }
            const last = activity.get(seat.identityId);
            return last !== undefined && last <= cutoff;
          };
          const products: LicenseUsage[] = [];
          for (const product of await visibleLicenseProducts(tx, realm.id)) {
            if (!used.has(product.id) && product.tenantId !== realm.id) continue;
            const own = seats.filter((seat) => seat.productId === product.id);
            const livePools = pools.filter(
              (pool) => pool.productId === product.id && liveLicensePool(pool, now),
            );
            const capacity = licenseCapacity(livePools, now);
            const active = own.filter((seat) => seat.status === 'active').length;
            let reclaimable = 0;
            let reclaimableThroughGroups = 0;
            for (const seat of own)
              if (await inactive(seat)) {
                reclaimable++;
                if (seat.sources.direct !== true) reclaimableThroughGroups++;
              }
            products.push({
              productId: product.id,
              key: product.key,
              name: product.name,
              scope: product.tenantId === rootId ? 'platform' : 'tenant',
              status: product.status,
              capacity,
              active,
              waiting: own.length - active,
              available: Math.max(0, capacity - active),
              pools: livePools.length,
              assignments: assignments.filter((assignment) => assignment.productId === product.id)
                .length,
              reclaimable,
              reclaimableThroughGroups,
            });
          }
          return {
            tenantId: realm.id,
            ...(settings.reclaimAfterDays !== undefined
              ? { reclaimAfterDays: settings.reclaimAfterDays }
              : {}),
            products: products.sort(
              (a, b) => byText(a.key, b.key) || byText(a.productId, b.productId),
            ),
          };
        },
      ),
    /**
     * The caller's own licenses in the tenant (active seats and waiting-list places, each with whether the platform
     * defines its product and which tenant does) and the feature keys their active seats unlock: `featureKeys` from
     * platform products only, `allFeatureKeys` from every product (tenant-defined ones are not paid entitlements). Needs
     * only a session of the tenant; assumed roles and other tenants' people hold none here. Not audited.
     */
    mine: async (credential: CredentialInput, input: { tenantId: string }): Promise<MyLicenses> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const realm = await ctx.tenant(tx, tenantId);
        if (principal.session.tenantId !== realm.id && !(await ctx.rootPrincipal(tx, principal)))
          throw new IamError(
            'ACCESS_DENIED',
            'Licenses are read from a session of their tenant',
            403,
          );
        const identity = principal.identity;
        const empty: MyLicenses = {
          tenantId: realm.id,
          identityId: identity.id,
          licenses: [],
          featureKeys: [],
          allFeatureKeys: [],
        };
        if (principal.session.kind === 'role' || identity.tenantId !== realm.id) return empty;
        const now = ctx.now();
        const rootId = (await ctx.ancestry(tx, realm)).at(-1)!.id;
        const counted = new Set(
          (await heldLicenses(tx, realm.id, identity.id, now)).map(({ seat }) => seat.id),
        );
        const licenses: MyLicense[] = [];
        // A shadowed product, or one the tenant no longer sees, grants nothing: neither its seats nor its waiting list.
        const granting = await grantingLicenseProducts(tx, realm.id);
        for (const seat of await tx.find<LicenseSeat>(licenseCollections.seats, {
          tenantId: realm.id,
          identityId: identity.id,
        })) {
          const product = granting.get(seat.productId);
          if (!product || product.status !== 'active') continue;
          if (seat.status === 'active' && !counted.has(seat.id)) continue;
          const position =
            seat.status === 'waiting'
              ? waitingPositions(
                  await tx.find<LicenseSeat>(licenseCollections.seats, {
                    tenantId: realm.id,
                    productId: seat.productId,
                    status: 'waiting',
                  }),
                ).get(seat.id)
              : undefined;
          licenses.push({
            productId: product.id,
            key: product.key,
            name: product.name,
            ...(product.description !== undefined ? { description: product.description } : {}),
            status: seat.status,
            ...(position !== undefined ? { position } : {}),
            featureKeys: seat.status === 'active' ? product.featureKeys : [],
            platform: product.tenantId === rootId,
            definedBy: product.tenantId,
          });
        }
        licenses.sort((a, b) => byText(a.key, b.key) || byText(a.productId, b.productId));
        const union = (list: MyLicense[]) =>
          [...new Set(list.flatMap((license) => license.featureKeys))].sort();
        return {
          ...empty,
          licenses,
          // Only the platform's products are paid entitlements no tenant can mint for itself.
          featureKeys: union(licenses.filter((license) => license.platform)),
          allFeatureKeys: union(licenses),
        };
      });
    },
    /** The tenant's license settings (defaults when never configured). Requires iam:licenses:read on `iam/licenses/settings`. */
    getSettings: (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<LicenseSettingsView> =>
      operation(
        credential,
        input.tenantId,
        'iam:licenses:read',
        'licenses/settings',
        async ({ tx, tenant: realm }) => ({
          tenantId: realm.id,
          ...(await resolveLicenseSettings(tx, realm.id)),
        }),
      ),
    /**
     * Turns inactive-seat reclaim on (`reclaimAfterDays`, 7-365) or off (`null`), and waiting-list email on or off
     * (`notifyWaiting`). Requires iam:licenses:manage on `iam/licenses/settings`; audited as `license:settings`.
     */
    configure: (
      credential: CredentialInput,
      input: { tenantId: string; reclaimAfterDays?: number | null; notifyWaiting?: boolean },
    ): Promise<LicenseSettingsView> =>
      operation(
        credential,
        input.tenantId,
        'iam:licenses:manage',
        'licenses/settings',
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          if (input.reclaimAfterDays === undefined && input.notifyWaiting === undefined)
            throw new IamError('INVALID_INPUT', 'Nothing to update');
          if (input.notifyWaiting !== undefined && typeof input.notifyWaiting !== 'boolean')
            throw new IamError('INVALID_INPUT', 'notifyWaiting must be a boolean');
          const stored = await tx.get<LicenseSettings>(licenseCollections.settings, realm.id);
          const reclaimAfterDays =
            input.reclaimAfterDays === undefined
              ? stored?.reclaimAfterDays
              : input.reclaimAfterDays === null
                ? undefined
                : integer(
                    input.reclaimAfterDays,
                    'reclaimAfterDays',
                    licenseReclaimDays.min,
                    licenseReclaimDays.max,
                  );
          const next: LicenseSettings = {
            id: realm.id,
            tenantId: realm.id,
            ...(reclaimAfterDays !== undefined ? { reclaimAfterDays } : {}),
            notifyWaiting: input.notifyWaiting ?? stored?.notifyWaiting === true,
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          };
          await (stored
            ? tx.put<LicenseSettings>(licenseCollections.settings, next)
            : tx.insert<LicenseSettings>(licenseCollections.settings, next));
          await audit(tx, principal, 'license:settings', realm.id, 'licenses/settings', {
            reclaimAfterDays: next.reclaimAfterDays ?? null,
            notifyWaiting: next.notifyWaiting,
            previousReclaimAfterDays: stored?.reclaimAfterDays ?? null,
            previousNotifyWaiting: stored?.notifyWaiting === true,
          });
          return { tenantId: realm.id, ...(await resolveLicenseSettings(tx, realm.id)) };
        },
      ),
  };
}
