import {
  IamError,
  dominates,
  falseFilter,
  isValidClassificationLabel,
  joinLabels,
  labelRank,
  notFilter,
  trueFilter,
  validateLabel,
  type AuthenticatedPrincipal,
  type ClassificationLabel,
  type ClassificationLevel,
  type ClassificationSchemeDefinition,
  type ClearanceParty,
  type Decision,
  type DominanceFailure,
  type IamStore,
  type Identity,
  type ResourceFilter,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import type { AgentDecisionScope } from './agents.js';
import { acceptanceCurrent, type Agreement, type AgreementAcceptance } from './agreements.js';
import { internalResourceTypes, managedResource, resolvedManaged } from './catalog.js';
import type { ServerContext } from './context.js';
import type { ResourceRecord } from './models.js';
import type { ResolvedResource } from './options.js';
import { hash } from './utils.js';

/**
 * Security clearances and mandatory access control (the `clearances` option). A tenant (normally an organization)
 * defines a classification scheme: ranked levels, compartments and dissemination controls (core classification.ts).
 * The scheme in force for a tenant is the one defined closest to the root of its ancestry, so a child can neither
 * redefine nor re-rank what its ancestors classify. Officers adjudicate one clearance per identity (level, adjudicated
 * citizenship, read-ins to compartments backed by NDAs) and label resources; the label is IAM-held (`resourceLabels`),
 * inherited down managed parents, and can only be raised by the application's resolver. At decision time every party of
 * the session must dominate the resource's label (Bell-LaPadula simple security property: no read up), whatever roles,
 * policies and relationships say; `iam:*` administration is never subject. Status, expiry, the guest ceiling and NDA
 * acceptance are evaluated at decision time, never by a worker.
 */

/** The collections of the clearance module (tenant scoped; tenant purge sweeps them). */
export const clearanceCollections = {
  schemes: 'classificationSchemes',
  clearances: 'clearances',
  labels: 'resourceLabels',
} as const;

/** Limits of the clearance module. */
export const clearanceLimits = {
  /** Resource types a scheme may require labels on. */
  maxRequiredTypes: 100,
  /** Countries on one clearance record. */
  maxCitizenship: 10,
  /** Extra addresses `sendReminders` emails besides the scheme tenant's owners. */
  maxNotifyEmails: 20,
  /** How far up managed parents a label is inherited from. */
  maxInheritanceDepth: 16,
  /** Default window of `sendReminders`, in days. */
  reminderDays: 60,
} as const;

const dayMs = 86_400_000;
const schemeKey = 'scheme';

/** Resource types the built-in modules resolve themselves; `requireLabels: ['*']` (all application types) skips them. */
const moduleResourceTypes: ReadonlySet<string> = new Set([
  'model',
  'ssh-login',
  'ssh-host',
  'credential-type',
]);

/** How officers may adjudicate: only within their own clearance, or any level the scheme defines. */
export type AdjudicationMode = 'within-own' | 'unrestricted';

/** A tenant's classification scheme; `tenantId` is the defining tenant (its whole subtree uses it). */
export interface ClassificationScheme extends StoredRecord {
  uniqueKey: string;
  name: string;
  definition: ClassificationSchemeDefinition;
  /** Resource types that must carry a label (`*`: every application type); unlabeled ones are refused. */
  requireLabels: string[];
  /** Applied to unlabeled resources of the required types instead of refusing them. */
  defaultLabel?: ClassificationLabel;
  /** The highest level a guest's clearance counts as; null: guests hold no clearance. */
  guestCeiling: string | null;
  /** Whether interim clearances count at decision time. */
  interimAllowed: boolean;
  adjudication: AdjudicationMode;
  /** Extra recipients of `iam.clearances.sendReminders` besides the defining tenant's owners. */
  notify?: { emails: string[] };
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
  version: number;
}

export type ClearanceStatus = 'interim' | 'active' | 'suspended' | 'revoked' | 'terminated';
/**
 * What a clearance counts as at decision time: `active` or `interim` when it applies, otherwise why not (`none`: no
 * record, another scheme, an unknown level, an interim the scheme does not allow, a guest without a ceiling, or an
 * inactive identity; `expired`; or the record's own `suspended` / `revoked` / `terminated`).
 */
export type EffectiveClearanceStatus =
  | 'active'
  | 'interim'
  | 'none'
  | 'expired'
  | 'suspended'
  | 'revoked'
  | 'terminated';

/** One compartment a person is read into; with `agreementId` it counts only while their NDA acceptance is current. */
export interface ClearanceReadIn {
  compartmentId: string;
  readInAt: number;
  readInBy: string;
  agreementId?: string;
  /** When the person had accepted the NDA as of the read-in (evidence; decisions check the live acceptance). */
  acceptedAt?: number;
}

/** One identity's adjudicated clearance, in the identity's tenant (the record id is the identity id). */
export interface Clearance extends StoredRecord {
  uniqueKey: string;
  identityId: string;
  /** The tenant whose scheme it was issued under; it counts only while that scheme is the one in force. */
  schemeTenantId: string;
  level: string;
  /** Adjudicated citizenship (ISO 3166-1 alpha-3), the only source of NOFORN and REL TO decisions. */
  citizenship: string[];
  status: ClearanceStatus;
  investigation?: { kind: string; completedAt: number };
  reinvestigationDue?: number;
  expiresAt?: number;
  readIns: ClearanceReadIn[];
  grantedAt: number;
  grantedBy: string;
  updatedAt: number;
  updatedBy: string;
  suspended?: {
    by: string;
    at: number;
    reason: string;
    incidentId?: string;
    /** The status a reinstatement returns to. */
    previousStatus: 'active' | 'interim';
  };
  revoked?: { by: string; at: number; reason: string };
  terminated?: { by: string; at: number; reason: string };
}

/** An IAM-held classification label of one resource; it outlives the resource, so deleting cannot declassify. */
export interface ResourceLabel extends StoredRecord {
  /** `{type}/{resourceId}`, or `sha256:{hex}` of it when longer than 512 bytes (`labelKey`). */
  uniqueKey: string;
  type: string;
  resourceId: string;
  label: ClassificationLabel;
  /** Whether the label also applies to every managed descendant of the resource. */
  inheritToChildren: boolean;
  /** The defining tenant of the scheme the label was written under. */
  schemeTenantId: string;
  labeledBy: string;
  labeledAt: number;
  version: number;
}

/**
 * What decisions enforce for one session in one tenant (decisions.ts): the policy keys and the mandatory check. Built
 * once per prepared decision by `clearanceScope`.
 */
export interface MandatoryAccess {
  /** `principal.clearance*` keys: the lowest rank of the parties, the shared compartments and citizenship. */
  keys: Record<string, unknown>;
  /**
   * The label `check` applies to a resource whose label `resolve` attached (the scheme's `defaultLabel` for an
   * unlabeled resource of a required type), or undefined when it carries none.
   */
  label(resource: ResolvedResource): ClassificationLabel | undefined;
  /** The rank of a label's level in the scheme (`resource.classificationRank`); undefined for an unknown level. */
  rank(label: ClassificationLabel): number | undefined;
  /**
   * `{ allowed: false, reason: 'CLEARANCE_REQUIRED' }` unless every party dominates the resource's label; undefined
   * when the check passes. `iam:*` actions are never subject. Fails closed on a resource whose label was never looked
   * up (`classification` absent), a missing label on a required type, and a label invalid for the scheme.
   */
  check(resource: ResolvedResource, action: string): Decision | undefined;
  /**
   * For query planning (`planResources`): the resources of `type` every party may read, by id. Throws
   * UNSUPPORTED_FILTER for an application (unmanaged) type the scheme requires labels on, and for any application type
   * while a label in the tenant passes down to children (reported parents are invisible to a filter). Always passes
   * `iam:*` actions.
   */
  filter(type: string, action?: string): Promise<ResourceFilter> | ResourceFilter;
}

/** A label that is valid for no scheme (level ids start with a letter or digit): it refuses every party. */
const invalidLabel: ClassificationLabel = Object.freeze({
  level: '!invalid',
}) as ClassificationLabel;

/** Refuses with FEATURE_DISABLED (403) unless the deployment enables clearances. */
export function assertClearances(ctx: ServerContext): void {
  if (!ctx.options.clearances)
    throw new IamError(
      'FEATURE_DISABLED',
      'Security clearances are not enabled on this deployment',
      403,
    );
}

/** The natural key of a resource's label: `{type}/{id}`, hashed when it would exceed 512 UTF-8 bytes. */
export function labelKey(type: string, resourceId: string): string {
  const key = `${type}/${resourceId}`;
  return Buffer.byteLength(key, 'utf8') <= 512 ? key : `sha256:${hash(key)}`;
}

/** The scheme a tenant defines itself, if it does. */
export async function definedScheme(
  tx: IamStore,
  tenantId: string,
): Promise<ClassificationScheme | undefined> {
  const found = (
    await tx.find<ClassificationScheme>(clearanceCollections.schemes, {
      tenantId,
      uniqueKey: schemeKey,
    })
  )[0];
  return found?.tenantId === tenantId ? found : undefined;
}

/**
 * The scheme in force for a tenant, given its ancestry (`[tenant, parent, ..., root]`): the one defined closest to the
 * root. Undefined when no tenant of the chain defines one.
 */
export async function effectiveScheme(
  tx: IamStore,
  chain: readonly Pick<Tenant, 'id'>[],
): Promise<ClassificationScheme | undefined> {
  for (let index = chain.length - 1; index >= 0; index--) {
    const scheme = await definedScheme(tx, chain[index]!.id);
    if (scheme) return scheme;
  }
  return undefined;
}

/** A tenant's ancestor ids from itself to the root, read through the store alone; fails closed on a broken chain. */
async function tenantChain(tx: IamStore, tenantId: string): Promise<{ id: string }[]> {
  const chain: { id: string }[] = [];
  const seen = new Set<string>();
  let current: string | null | undefined = tenantId;
  while (current) {
    if (seen.has(current) || chain.length > 100)
      throw new IamError('INVALID_HIERARCHY', 'Invalid tenant hierarchy', 500);
    seen.add(current);
    const realm: Tenant | undefined = await tx.get<Tenant>('tenants', current);
    if (!realm) throw new IamError('NOT_FOUND', 'Tenant not found', 404);
    chain.push({ id: realm.id });
    current = realm.parentId;
  }
  return chain;
}

/** The scheme in force for a tenant, reading its ancestry from the store. */
export async function schemeForTenant(
  tx: IamStore,
  tenantId: string,
): Promise<ClassificationScheme | undefined> {
  return effectiveScheme(tx, await tenantChain(tx, tenantId));
}

/** A level of the scheme by id. */
export function schemeLevel(
  scheme: Pick<ClassificationScheme, 'definition'>,
  levelId: string | null | undefined,
): ClassificationLevel | undefined {
  return typeof levelId === 'string'
    ? scheme.definition.levels.find((level) => level.id === levelId)
    : undefined;
}

/** Whether the scheme requires a label on resources of `type` (`*` covers application types, not built-in ones). */
export function labelRequired(
  scheme: Pick<ClassificationScheme, 'requireLabels'>,
  type: string,
): boolean {
  if (internalResourceTypes.has(type)) return false;
  return (
    scheme.requireLabels.includes(type) ||
    (scheme.requireLabels.includes('*') && !moduleResourceTypes.has(type))
  );
}

/** The stored IAM label of a resource, if it has one. */
export async function storedLabel(
  tx: IamStore,
  tenantId: string,
  type: string,
  resourceId: string,
): Promise<ResourceLabel | undefined> {
  const found = (
    await tx.find<ResourceLabel>(clearanceCollections.labels, {
      tenantId,
      uniqueKey: labelKey(type, resourceId),
    })
  )[0];
  return found && found.type === type && found.resourceId === resourceId ? found : undefined;
}

/** A stored or asserted label as the scheme reads it: normalized when valid, otherwise the invalid label. */
function schemeLabel(
  label: unknown,
  definition: ClassificationSchemeDefinition,
): ClassificationLabel {
  return isValidClassificationLabel(label, definition)
    ? validateLabel(label, definition)
    : invalidLabel;
}

/**
 * Whether a stored IAM label is valid under the scheme in force: written under that scheme (not one a tenant used before
 * it was moved below an ancestor defining its own) and valid for its definition.
 */
export function storedLabelValid(
  stored: Pick<ResourceLabel, 'label' | 'schemeTenantId'>,
  scheme: Pick<ClassificationScheme, 'tenantId' | 'definition'>,
): boolean {
  return (
    stored.schemeTenantId === scheme.tenantId &&
    isValidClassificationLabel(stored.label, scheme.definition)
  );
}

/** A stored IAM label as the scheme in force reads it; one `storedLabelValid` rejects refuses every party. */
function storedSchemeLabel(
  stored: Pick<ResourceLabel, 'label' | 'schemeTenantId'>,
  scheme: Pick<ClassificationScheme, 'tenantId' | 'definition'>,
): ClassificationLabel {
  return storedLabelValid(stored, scheme)
    ? validateLabel(stored.label, scheme.definition)
    : invalidLabel;
}

type Reference = { type: string; id: string };
const refKey = (ref: Reference) => `${ref.type}/${ref.id}`;

/** The managed parent of a registered resource, when it has one. */
function parentOf(record: ResourceRecord | undefined): Reference | undefined {
  return record && typeof record.parentType === 'string' && typeof record.parentId === 'string'
    ? { type: record.parentType, id: record.parentId }
    : undefined;
}

/**
 * Every parent a resource inherits labels from: its registration's managed parent, and the parent its attributes
 * report (`parentType` / `parentId`: an application resolver's, or what `resolvedManaged` presents for a registration).
 * Both count when they differ, since labels only ever rise: a type only a tenant registered answers the application's
 * actions from the application's resolver, so a registration of the tenant's must not stand in for the parent the
 * application reports (that would declassify through registering a record).
 */
function parentsOf(
  record: ResourceRecord | undefined,
  attributes: Record<string, unknown> | undefined,
): Reference[] {
  const parents: Reference[] = [];
  const linked = parentOf(record);
  if (linked) parents.push(linked);
  if (typeof attributes?.parentType === 'string' && typeof attributes.parentId === 'string') {
    const reported = { type: attributes.parentType, id: attributes.parentId };
    if (!linked || refKey(linked) !== refKey(reported)) parents.push(reported);
  }
  return parents;
}

/** What a managed resource passes down: the join of its and its ancestors' inherited labels, and its chain's height. */
interface InheritedChain {
  label: ClassificationLabel | undefined;
  /** The resource and the ancestors above it; Infinity for a cyclic or runaway chain. */
  height: number;
}
/** How far a walk up managed parents goes at all before it fails closed (inheritance itself stops at 16). */
const maxParentWalk = 256;

/**
 * The chain above (and including) one managed resource. Depends only on the resource, never on where a walk started,
 * so `memo` can share it between the resources of one batch. A cycle (which registration never creates) or a runaway
 * chain yields the invalid label.
 */
async function chainFrom(
  tx: IamStore,
  tenantId: string,
  scheme: ClassificationScheme,
  node: Reference,
  visiting: Set<string>,
  memo: Map<string, InheritedChain>,
): Promise<InheritedChain> {
  const key = refKey(node);
  const known = memo.get(key);
  if (known) return known;
  if (visiting.has(key) || visiting.size >= maxParentWalk)
    return { label: invalidLabel, height: Infinity };
  visiting.add(key);
  const stored = await storedLabel(tx, tenantId, node.type, node.id);
  const above = parentOf(await managedResource(tx, tenantId, node.type, node.id));
  const upper: InheritedChain = above
    ? await chainFrom(tx, tenantId, scheme, above, visiting, memo)
    : { label: undefined, height: 0 };
  visiting.delete(key);
  const here = stored?.inheritToChildren ? storedSchemeLabel(stored, scheme) : undefined;
  const chain = {
    label: joinLabels(here, upper.label, scheme.definition),
    height: upper.height + 1,
  };
  memo.set(key, chain);
  return chain;
}

/**
 * The labels a resource (`self`, a `{type}/{id}` key) inherits from `parent` and the managed ancestors above it: the
 * join of every one of their labels marked `inheritToChildren`. More than `maxInheritanceDepth` ancestors, or a cyclic
 * chain, inherits the invalid label (fail closed). `memo` shares results between the resources of one batch.
 */
async function inheritedAt(
  tx: IamStore,
  tenantId: string,
  scheme: ClassificationScheme,
  parent: Reference,
  self: string,
  memo: Map<string, InheritedChain>,
): Promise<ClassificationLabel | undefined> {
  const chain = await chainFrom(tx, tenantId, scheme, parent, new Set([self]), memo);
  return chain.height > clearanceLimits.maxInheritanceDepth ? invalidLabel : chain.label;
}

/**
 * The effective IAM-held label of one resource under `scheme`: its own label joined with what it inherits from its
 * managed parents and from the parent its attributes report (`attributes.parentType` / `attributes.parentId`, see
 * `parentsOf`). Undefined when unlabeled.
 */
async function iamLabel(
  tx: IamStore,
  tenantId: string,
  scheme: ClassificationScheme,
  resource: { type: string; id: string; attributes?: Record<string, unknown> },
): Promise<ClassificationLabel | undefined> {
  const { definition } = scheme;
  const own = await storedLabel(tx, tenantId, resource.type, resource.id);
  const record = await managedResource(tx, tenantId, resource.type, resource.id);
  const memo = new Map<string, InheritedChain>();
  let label = own ? storedSchemeLabel(own, scheme) : undefined;
  for (const parent of parentsOf(record, resource.attributes))
    label = joinLabels(
      label,
      await inheritedAt(tx, tenantId, scheme, parent, refKey(resource), memo),
      definition,
    );
  return label;
}

/**
 * Attaches a resource's effective classification label as the server-owned `classification` field (never an
 * attribute): its IAM label, joined with the labels inherited from managed parents (at most 16 levels) and with the
 * `classification` the application's resolver returned, which can therefore only raise it. An asserted label that is
 * not valid for the scheme makes the result invalid, so every party is refused. `null` means looked up and unlabeled.
 * Without a scheme in force the resource is returned unchanged. Platform-internal resources carry a label only as
 * `iam/{type}/{id}`, labeled as the resource it names. Pass `known.scheme` when the caller already resolved the scheme
 * (`null` for none) to save the ancestry reads.
 */
export async function attachLabel(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  resource: ResolvedResource,
  known?: { scheme: ClassificationScheme | null },
): Promise<ResolvedResource> {
  const scheme =
    known !== undefined ? (known.scheme ?? undefined) : await schemeForTenant(tx, tenantId);
  if (!scheme) return resource;
  // `iam/{type}/{id}` is labeled as the resource it names, with what was resolved for this name (the parent its
  // attributes report, a resolver's own label) joined in like for the resource itself, so the alias never reads lower.
  let labeled: { type: string; id: string; attributes?: Record<string, unknown> } = resource;
  if (internalResourceTypes.has(resource.type)) {
    const slash = resource.type === 'iam' ? resource.id.indexOf('/') : -1;
    if (slash <= 0) return resource;
    labeled = {
      type: resource.id.slice(0, slash),
      id: resource.id.slice(slash + 1),
      ...(resource.attributes ? { attributes: resource.attributes } : {}),
    };
    if (!labeled.id || internalResourceTypes.has(labeled.type)) return resource;
  }
  const asserted = resource.classification;
  let label = await iamLabel(tx, tenantId, scheme, labeled);
  if (asserted !== undefined && asserted !== null)
    label = joinLabels(label, schemeLabel(asserted, scheme.definition), scheme.definition);
  return { ...resource, classification: label ?? null };
}

/**
 * What a registered resource inherits from its managed ancestors under `scheme` (the join of their labels marked
 * `inheritToChildren`, through the parents `parentsOf` names for the registration), without its own label; undefined
 * when it inherits nothing.
 */
export async function inheritedLabel(
  tx: IamStore,
  tenantId: string,
  scheme: ClassificationScheme,
  type: string,
  resourceId: string,
): Promise<ClassificationLabel | undefined> {
  const record = await managedResource(tx, tenantId, type, resourceId);
  const memo = new Map<string, InheritedChain>();
  let label: ClassificationLabel | undefined;
  for (const parent of parentsOf(record, record ? resolvedManaged(record).attributes : undefined))
    label = joinLabels(
      label,
      await inheritedAt(tx, tenantId, scheme, parent, refKey({ type, id: resourceId }), memo),
      scheme.definition,
    );
  return label;
}

/** `labelsForType` under a scheme already known. */
async function typeLabels(
  tx: IamStore,
  tenantId: string,
  scheme: ClassificationScheme,
  type: string,
): Promise<Map<string, ClassificationLabel>> {
  const { definition } = scheme;
  const result = new Map<string, ClassificationLabel>();
  for (const stored of await tx.find<ResourceLabel>(clearanceCollections.labels, {
    tenantId,
    type,
  }))
    if (stored.tenantId === tenantId && stored.type === type)
      result.set(stored.resourceId, storedSchemeLabel(stored, scheme));
  const memo = new Map<string, InheritedChain>();
  for (const record of await tx.find<ResourceRecord>('resources', { tenantId, type })) {
    if (record.type !== type) continue;
    // The same parents `resolve` follows for the registration (see `parentsOf`).
    let joined = result.get(record.resourceId);
    for (const parent of parentsOf(record, resolvedManaged(record).attributes))
      joined = joinLabels(
        joined,
        await inheritedAt(
          tx,
          tenantId,
          scheme,
          parent,
          refKey({ type, id: record.resourceId }),
          memo,
        ),
        definition,
      );
    if (joined) result.set(record.resourceId, joined);
  }
  return result;
}

/**
 * The effective IAM-held labels of every labeled resource of one type in a tenant, by resource id, for listings: own
 * labels joined with what registered resources inherit from their managed parents. Labels an application resolver
 * asserts are not included (decisions still apply them). Empty when no scheme is in force.
 */
export async function labelsForType(
  tx: IamStore,
  tenantId: string,
  type: string,
): Promise<Map<string, ClassificationLabel>> {
  const scheme = await schemeForTenant(tx, tenantId);
  return scheme ? typeLabels(tx, tenantId, scheme, type) : new Map();
}

// --- parties ---------------------------------------------------------------------------------------

/** A party's clearance as it stands at decision time. */
export interface PartyState {
  party: ClearanceParty;
  status: EffectiveClearanceStatus;
  /** The level the party counts at (capped for guests); absent without a clearance. */
  level?: ClassificationLevel;
  record?: Clearance;
}

const unclearedParty = (identityId: string): ClearanceParty => ({
  identityId,
  rank: -1,
  compartments: new Set<string>(),
  citizenship: new Set<string>(),
});

/** An identity's clearance record (in the identity's own tenant), if any. */
export async function readClearance(
  tx: IamStore,
  identity: Pick<Identity, 'id' | 'tenantId'>,
): Promise<Clearance | undefined> {
  const record = await tx.get<Clearance>(clearanceCollections.clearances, identity.id);
  return record && record.tenantId === identity.tenantId && record.identityId === identity.id
    ? record
    : undefined;
}

/** The compartments a record's read-ins hold right now: known to the scheme, NDA (when named) currently accepted. */
async function liveCompartments(
  tx: IamStore,
  scheme: ClassificationScheme,
  record: Clearance,
  now: number,
): Promise<Set<string>> {
  const known = new Set(scheme.definition.compartments.map((compartment) => compartment.id));
  const held = new Set<string>();
  for (const readIn of record.readIns ?? []) {
    if (!known.has(readIn.compartmentId)) continue;
    if (readIn.agreementId !== undefined) {
      const agreement = await tx.get<Agreement>('agreements', readIn.agreementId);
      const acceptance = await tx.get<AgreementAcceptance>(
        'agreementAcceptances',
        `${readIn.agreementId}:${record.identityId}`,
      );
      if (
        !agreement ||
        agreement.tenantId !== record.tenantId ||
        !acceptance ||
        acceptance.tenantId !== record.tenantId ||
        acceptance.identityId !== record.identityId ||
        acceptance.agreementId !== agreement.id ||
        !acceptanceCurrent(agreement, acceptance, now)
      )
        continue;
    }
    held.add(readIn.compartmentId);
  }
  return held;
}

/**
 * One identity's clearance at decision time under `scheme`: the identity must be active and unexpired (and, unless
 * `tenantId` is undefined, of that tenant), the record issued under this scheme, active (or interim where the scheme
 * allows it) and unexpired, its level known; guests count at most at the scheme's guest ceiling and never hold
 * compartments; compartments count only while their NDA acceptance is current. Anything else is no clearance.
 */
export async function partyState(
  tx: IamStore,
  scheme: ClassificationScheme,
  identity: Identity | undefined,
  identityId: string,
  tenantId: string | undefined,
  now: number,
): Promise<PartyState> {
  const none = (status: EffectiveClearanceStatus = 'none', record?: Clearance): PartyState => ({
    party: unclearedParty(identityId),
    status,
    ...(record ? { record } : {}),
  });
  if (
    !identity ||
    identity.id !== identityId ||
    (tenantId !== undefined && identity.tenantId !== tenantId)
  )
    return none();
  const active =
    identity.status === 'active' &&
    !(typeof identity.expiresAt === 'number' && identity.expiresAt <= now);
  // An inactive account never counts; its record is read only to report a suspended or ended clearance as such.
  const record = await readClearance(tx, identity);
  if (!record) return none();
  if (record.schemeTenantId !== scheme.tenantId) return none('none', record);
  if (record.status !== 'active' && record.status !== 'interim') return none(record.status, record);
  if (!active) return none('none', record);
  if (record.status === 'interim' && !scheme.interimAllowed) return none('none', record);
  if (typeof record.expiresAt === 'number' && record.expiresAt <= now)
    return none('expired', record);
  let level = schemeLevel(scheme, record.level);
  if (!level) return none('none', record);
  let compartments = new Set<string>();
  if (identity.guest !== undefined) {
    const ceiling = schemeLevel(scheme, scheme.guestCeiling);
    if (!ceiling) return none('none', record);
    if (level.rank > ceiling.rank) level = ceiling;
  } else compartments = await liveCompartments(tx, scheme, record, now);
  return {
    party: {
      identityId,
      rank: level.rank,
      compartments,
      citizenship: new Set(Array.isArray(record.citizenship) ? record.citizenship : []),
    },
    status: record.status,
    level,
    record,
  };
}

/** The agents of a delegated session: the acting agent and every agent that handed the work on to it. */
function delegatedAgents(
  principal: AuthenticatedPrincipal,
  agentScope: AgentDecisionScope | undefined,
): string[] {
  const ids: string[] = [];
  const add = (value: unknown) => {
    if (typeof value === 'string' && value && !ids.includes(value)) ids.push(value);
  };
  const listed = (agentScope as { agentIds?: unknown } | undefined)?.agentIds;
  const chain = agentScope?.keys['principal.delegationChain'];
  for (const value of Array.isArray(listed) ? listed : Array.isArray(chain) ? chain : [])
    add(value);
  add(agentScope?.keys['principal.agentId']);
  add(principal.session.agentId);
  return ids;
}

/**
 * The parties of a session in `target`, each with its clearance: a person in their own tenant (an impersonation
 * session: the member; the administrator is decided separately); a service account's key: the account; an agent's key
 * (or a session token from it): the agent and its sponsor; a session token: its source identity; a delegated session:
 * the person, the acting agent and every agent above it in the hand-off chain; a role session: nobody cleared; root:
 * the root administrator's record when issued under the target's scheme. Unknown session kinds are uncleared.
 */
export async function sessionParties(
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  target: Pick<Tenant, 'id'>,
  agentScope: AgentDecisionScope | undefined,
  scheme: ClassificationScheme,
  now: number,
  root: boolean,
): Promise<PartyState[]> {
  const { identity, session } = principal;
  const uncleared = (identityId: string): PartyState => ({
    party: unclearedParty(identityId),
    status: 'none',
  });
  if (root) return [await partyState(tx, scheme, identity, identity.id, undefined, now)];
  if (session.tenantId !== target.id || identity.tenantId !== target.id)
    return [uncleared(identity.id)];
  const local = (candidate: Identity | undefined, identityId: string) =>
    partyState(tx, scheme, candidate, identityId, target.id, now);
  const load = (identityId: string) => tx.get<Identity>('identities', identityId);
  switch (session.kind) {
    case 'user':
      return [await local(identity, identity.id)];
    case 'api-key':
    case 'session-token': {
      const own = await local(identity, identity.id);
      if (identity.kind !== 'agent') return [own];
      const sponsorId = identity.agent?.sponsorId;
      if (typeof sponsorId !== 'string' || !sponsorId)
        return [own, uncleared(`${identity.id}#sponsor`)];
      const sponsor = await load(sponsorId);
      return [own, await local(sponsor?.kind === 'user' ? sponsor : undefined, sponsorId)];
    }
    case 'delegated': {
      const states = [await local(identity, identity.id)];
      const agentIds = delegatedAgents(principal, agentScope);
      if (!agentIds.length) return [...states, uncleared(`${identity.id}#agent`)];
      for (const agentId of agentIds) {
        const agent = await load(agentId);
        states.push(await local(agent?.kind === 'agent' ? agent : undefined, agentId));
      }
      return states;
    }
    default:
      return [uncleared(identity.id)];
  }
}

/** Sorted members of every set (the empty list for no sets). */
function intersection(sets: ReadonlySet<string>[]): string[] {
  if (!sets.length) return [];
  return [...sets[0]!].filter((value) => sets.every((set) => set.has(value))).sort();
}

/** The status the parties hold together: the first that does not count, otherwise interim when any is interim. */
function combinedStatus(states: PartyState[]): EffectiveClearanceStatus {
  const lacking = states.find((state) => state.status !== 'active' && state.status !== 'interim');
  if (lacking) return lacking.status;
  return states.some((state) => state.status === 'interim') ? 'interim' : 'active';
}

/** The `principal.clearance*` policy keys of a set of parties. */
export function clearanceKeys(states: PartyState[]): Record<string, unknown> {
  const rank = states.length ? Math.min(...states.map((state) => state.party.rank)) : -1;
  const weakest = states.find((state) => state.party.rank === rank);
  return {
    'principal.clearanceRank': rank,
    ...(rank >= 0 && weakest?.level ? { 'principal.clearanceLevel': weakest.level.id } : {}),
    'principal.clearanceStatus': states.length ? combinedStatus(states) : 'none',
    'principal.clearanceCompartments': intersection(
      states.map((state) => state.party.compartments),
    ),
    'principal.clearanceCitizenship': intersection(states.map((state) => state.party.citizenship)),
  };
}

const refused = (): Decision => ({ allowed: false, reason: 'CLEARANCE_REQUIRED', matched: [] });

/**
 * The label the scheme applies to a resource, `undefined` when it carries none, or `false` when it must be refused
 * whoever asks: its label was never looked up, or it lacks the label its type requires and the scheme sets no default.
 */
export function applicableLabel(
  scheme: Pick<ClassificationScheme, 'requireLabels' | 'defaultLabel'>,
  resource: ResolvedResource,
): ClassificationLabel | undefined | false {
  const classification: unknown = resource.classification;
  // Platform-internal resources are not labeled, except `iam/{type}/{id}` naming a labeled resource (or, once its
  // label was looked up, an unlabeled one of a type that requires a label: refused like the resource itself).
  if (internalResourceTypes.has(resource.type)) {
    if (classification !== null && typeof classification === 'object')
      return classification as ClassificationLabel;
    const slash = resource.type === 'iam' ? resource.id.indexOf('/') : -1;
    return classification === null &&
      slash > 0 &&
      labelRequired(scheme, resource.id.slice(0, slash))
      ? (scheme.defaultLabel ?? false)
      : undefined;
  }
  if (classification === undefined) return false;
  if (classification === null)
    return labelRequired(scheme, resource.type) ? (scheme.defaultLabel ?? false) : undefined;
  if (typeof classification !== 'object' || Array.isArray(classification)) return false;
  return classification as ClassificationLabel;
}

/** Whether every party dominates the label; undefined when they do, else the first failure. */
export function partiesFail(
  parties: readonly ClearanceParty[],
  label: ClassificationLabel,
  definition: ClassificationSchemeDefinition,
): DominanceFailure | undefined {
  if (!parties.length) return 'level';
  for (const party of parties) {
    const failure = dominates(party, label, definition);
    if (failure) return failure;
  }
  return undefined;
}

/**
 * The mandatory part of a decision for one session in `target`: undefined when no scheme is in force there (nothing to
 * enforce) or the principal is a root administrator and `clearances.appliesToRoot` is false. Otherwise the session's
 * parties (see `sessionParties`) with their clearances at `now`, their policy keys, and the check every party must pass
 * on labeled resources. Called by `prepareDecision` after the tenant checks and the agent scope; `chain` is the
 * target's ancestry from itself to the root.
 */
export async function clearanceScope(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  target: Tenant,
  chain: Tenant[],
  agentScope: AgentDecisionScope | undefined,
  now: number,
): Promise<MandatoryAccess | undefined> {
  if (!ctx.options.clearances) return undefined;
  const scheme = await effectiveScheme(tx, chain.length ? chain : [target]);
  if (!scheme) return undefined;
  const root = await ctx.rootPrincipal(tx, principal);
  if (root && ctx.options.clearances.appliesToRoot === false) return undefined;
  const states = await sessionParties(tx, principal, target, agentScope, scheme, now, root);
  const parties = states.map((state) => state.party);
  const { definition } = scheme;
  const passes = (label: ClassificationLabel) =>
    partiesFail(parties, label, definition) === undefined;
  return {
    keys: clearanceKeys(states),
    label(resource) {
      const label = applicableLabel(scheme, resource);
      return label === false ? undefined : label;
    },
    rank: (label) => labelRank(label, definition),
    check(resource, action) {
      if (typeof action === 'string' && action.startsWith('iam:')) return undefined;
      const label = applicableLabel(scheme, resource);
      if (label === undefined) return undefined;
      return label !== false && passes(label) ? undefined : refused();
    },
    async filter(type, action) {
      if (
        (typeof action === 'string' && action.startsWith('iam:')) ||
        internalResourceTypes.has(type)
      )
        return trueFilter;
      const required = labelRequired(scheme, type);
      const definitionOfType = await ctx.catalog.resourceTypeDefinition(tx, target.id, type);
      // Registered resources answer for the action unless the type is one only a tenant registered and the action is
      // the application's: `resolve` then asks the application's resolver (decisions.ts shadowsApplicationType, which
      // this module cannot import), so the type is planned as an application type.
      const managed =
        definitionOfType?.managed === true &&
        !(
          !!ctx.options.resolveResource &&
          definitionOfType.source === 'tenant' &&
          (typeof action !== 'string' || !action.startsWith(`${type}:`))
        );
      if (required && !managed)
        throw new IamError(
          'UNSUPPORTED_FILTER',
          'Resources of this type must carry a classification label, which a filter cannot check for application resources; check them with authorize',
        );
      // An application resource also inherits the labels of the parent its resolver reports, which no filter can see:
      // while any label in the tenant passes down to children, application types are not planned (fail closed).
      if (
        !managed &&
        (
          await tx.find<ResourceLabel>(
            clearanceCollections.labels,
            { tenantId: target.id, inheritToChildren: true },
            { limit: 1 },
          )
        ).length
      )
        throw new IamError(
          'UNSUPPORTED_FILTER',
          'Classification labels pass down to application resources through the parents their resolver reports, which a filter cannot check; check them with authorize',
        );
      const labels = await typeLabels(tx, target.id, scheme, type);
      if (required) {
        const allowed = new Set<string>();
        for (const record of await tx.find<ResourceRecord>('resources', {
          tenantId: target.id,
          type,
        })) {
          const label = labels.get(record.resourceId) ?? scheme.defaultLabel;
          if (label && passes(label)) allowed.add(record.resourceId);
        }
        return allowed.size
          ? { kind: 'equals', field: 'id', values: [...allowed].sort() }
          : falseFilter;
      }
      const denied = [...labels]
        .filter(([, label]) => !passes(label))
        .map(([resourceId]) => resourceId)
        .sort();
      return denied.length
        ? notFilter({ kind: 'equals', field: 'id', values: denied })
        : trueFilter;
    },
  };
}

// --- lifecycle -------------------------------------------------------------------------------------

/** Whether a clearance already ended: revoked for cause or terminated. Such a record keeps why it ended. */
const ended = (record: Pick<Clearance, 'status'>) =>
  record.status === 'terminated' || record.status === 'revoked';

/**
 * Offboarding (`identities.offboard`): ends the leaver's clearance as `terminated`, debriefing every compartment
 * (audited as `clearance:debrief` and `clearance:terminate` with the identity as the resource). The record stays as
 * history; one that already ended (revoked for cause, or terminated) is left as it is, so a revocation is never
 * rewritten as an ordinary departure. Returns 1 when a clearance was terminated, else 0. Lifecycle cleanup inside the
 * offboarding operation, so it needs no clearance permission. Does nothing (and reads nothing) without the
 * `clearances` option.
 */
export async function terminateClearancesOf(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  identity: Identity,
  reason: string,
): Promise<number> {
  if (!ctx.options.clearances) return 0;
  const record = await readClearance(tx, identity);
  if (!record || ended(record)) return 0;
  const now = ctx.now();
  for (const readIn of record.readIns ?? [])
    await ctx.events.audit(
      tx,
      principal,
      'clearance:debrief',
      identity.tenantId,
      identity.id,
      'allow',
      false,
      { compartmentId: readIn.compartmentId, reason: 'terminated' },
    );
  const { suspended: _suspended, ...rest } = record;
  await tx.put<Clearance>(clearanceCollections.clearances, {
    ...rest,
    status: 'terminated',
    readIns: [],
    terminated: { by: principal.identity.id, at: now, reason: reason.slice(0, 512) },
    updatedAt: now,
    updatedBy: principal.identity.id,
  });
  await ctx.events.audit(
    tx,
    principal,
    'clearance:terminate',
    identity.tenantId,
    identity.id,
    'allow',
    false,
    { level: record.level, previousStatus: record.status, reason: reason.slice(0, 512) },
  );
  return 1;
}

/**
 * Identity deletion (`deleteIdentity`): marks the clearance `terminated` and releases its read-ins, keeping the record
 * as history. One that already ended keeps its status (a revocation for cause stays a revocation) and only loses any
 * read-ins left. Call only with the `clearances` option.
 */
export async function releaseClearancesOf(
  tx: IamStore,
  identity: Identity,
  now: number = Date.now(),
  by = 'identity-deleted',
): Promise<void> {
  const record = await readClearance(tx, identity);
  if (!record || (ended(record) && !(record.readIns ?? []).length)) return;
  const { suspended: _suspended, ...rest } = record;
  await tx.put<Clearance>(clearanceCollections.clearances, {
    ...rest,
    status: ended(record) ? record.status : 'terminated',
    readIns: [],
    ...(ended(record) ? {} : { terminated: { by, at: now, reason: 'identity deleted' } }),
    updatedAt: now,
    updatedBy: by,
  });
}

/** What `suspendClearance` did: suspended, or why it did nothing. */
export type ClearanceSuspension = 'suspended' | 'no-clearance' | 'already-applied';

/**
 * Suspends an identity's active or interim clearance (`suspended` with who, when, why and the incident), for the
 * clearances API and automatic responses. It records nothing in the audit trail and sends nothing: callers do. A
 * suspension is lifted only by `clearances.reinstate`.
 */
export async function suspendClearance(
  tx: IamStore,
  identity: Pick<Identity, 'id' | 'tenantId'>,
  input: { by: string; at: number; reason: string; incidentId?: string },
): Promise<{ outcome: ClearanceSuspension; record?: Clearance }> {
  const record = await readClearance(tx, identity);
  if (!record || record.status === 'revoked' || record.status === 'terminated')
    return { outcome: 'no-clearance' };
  if (record.status === 'suspended') return { outcome: 'already-applied', record };
  const next = await tx.put<Clearance>(clearanceCollections.clearances, {
    ...record,
    status: 'suspended',
    suspended: {
      by: input.by,
      at: input.at,
      reason: input.reason.slice(0, 512),
      ...(input.incidentId !== undefined ? { incidentId: input.incidentId } : {}),
      previousStatus: record.status,
    },
    updatedAt: input.at,
    updatedBy: input.by,
  });
  return { outcome: 'suspended', record: next };
}

/**
 * Emails the person (template `clearance-status`) that their clearance was suspended, revoked or reinstated, naming the
 * level only. Sent only to people with an address, and only when the deployment delivers email.
 */
export async function notifyClearanceStatus(
  ctx: ServerContext,
  tx: IamStore,
  identity: Identity,
  scheme: ClassificationScheme | undefined,
  record: Pick<Clearance, 'level'>,
  status: 'suspended' | 'revoked' | 'reinstated',
): Promise<void> {
  if (!ctx.options.authentication?.sendEmail || identity.kind !== 'user' || !identity.email) return;
  const tenant = await tx.get<Tenant>('tenants', identity.tenantId);
  const level = scheme ? schemeLevel(scheme, record.level) : undefined;
  await ctx.auth.enqueueDelivery(tx, {
    tenantId: identity.tenantId,
    kind: 'email',
    to: identity.email,
    template: 'clearance-status',
    payload: {
      tenantId: identity.tenantId,
      ...(tenant ? { tenantName: tenant.name } : {}),
      status,
      ...(level ? { levelName: level.name } : {}),
    },
  });
}
