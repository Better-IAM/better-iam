import { createHash } from 'node:crypto';
import {
  auditEventHash,
  auditGenesis,
  findOrdered,
  type AuditChainHead,
  type AuditEvent,
  type IamStore,
  type Identity,
  type Json,
  type Tenant,
} from '@better-iam/core';
import { unrestrictedAdmin } from './api/analysis.js';
import type { ServerContext } from './context.js';
import type { Binding, GroupMember, Policy, Role } from './models.js';
import {
  afterThreatResponses,
  applyResponse,
  threatAudit,
  type PlaybookBrake,
} from './threat-response.js';
import {
  baselineIdentityIds,
  considered,
  evaluateThreatRules,
  ruleWindowMs,
  type DetectionCandidate,
  type RuleFacts,
  type RuleState,
} from './threat-rules.js';
import {
  defaultThreatSettings,
  effectiveRisk,
  maxSeverity,
  resolveThreatSettings,
  responseActionKinds,
  riskPoints,
  severityAtLeast,
  threatActor,
  threatCollections,
  type IdentityRisk,
  type ResolvedThreatSettings,
  type RiskContribution,
  type ThreatBaseline,
  type ThreatCursor,
  type ThreatDetection,
  type ThreatDetectionRun,
  type ThreatIncident,
  type ThreatPlaybook,
  type ThreatResponse,
  type ThreatSettings,
  type ThreatSeverity,
} from './threats.js';
import { byId, id } from './utils.js';
import { integer, text } from './validation.js';

/**
 * The detection engine of the threats module (`threats.ts`): a scheduled job (`iam.detectThreats()`) that reads each
 * tenant's audit chain from a cursor, verifies the chain as it goes, evaluates the detection rules
 * (`threat-rules.ts`) over the unread events and their lookback window, records detections grouped into incidents,
 * keeps identity risk, and runs the tenant's playbooks for new detections. It reads the trail rather than hooking
 * the recorders, so it also sees what the protocol packages write without fan-out and never slows a sign-in.
 */

const hour = 3_600_000;
const day = 24 * hour;
/** Default and largest number of unread events one run reads per tenant. */
const defaultMaxEvents = 2000;
const maxEventsLimit = 20_000;
/** Most lookback events one run loads per tenant for the window rules (the newest are kept). */
const maxHistory = 20_000;
/**
 * Most people whose sign-in baselines one run writes. Those writes happen in the run's transaction, which holds the
 * store's write lock, so a run reaching this many stops at that event and the next run continues from there.
 */
const maxBaselinesPerRun = 500;
/** Detections an incident lists by id (newest last); older ones stay findable through `incidentId`. */
const maxIncidentDetections = 200;
/** Risk contributions kept per identity (newest last); older ones have decayed to almost nothing. */
const maxContributions = 50;
/** Contributions older than this many half-lives (under 0.1% of their points) are pruned. */
const contributionHalfLives = 10;
/** Longest `uniqueKey` the store accepts, in UTF-8 bytes; a longer key is stored as its hash. */
const maxKeyBytes = 512;

type ChainBreakReason =
  | 'sequence-gap'
  | 'sequence-repeated'
  | 'previous-hash-mismatch'
  | 'hash-mismatch'
  | 'head-rolled-back'
  | 'head-mismatch';
interface ChainBreak {
  reason: ChainBreakReason;
  sequence: number;
  /** The event at which verification failed; absent when the chain head itself moved. */
  event?: AuditEvent;
}
const chainBreakText: Record<ChainBreakReason, string> = {
  'sequence-gap': 'events before it are missing',
  'sequence-repeated': 'its position in the chain is taken twice',
  'previous-hash-mismatch': 'it does not follow the event before it',
  'hash-mismatch': 'its content no longer matches its hash',
  'head-rolled-back': 'the chain head moved back behind events already read',
  'head-mismatch': 'the latest event was replaced',
};

/** What one tenant contributed to a run. */
interface TenantOutcome {
  eventsScanned: number;
  detections: number;
  incidentsOpened: number;
  responses: number;
  braked: number;
  chainBroken: boolean;
  pending: boolean;
}

/**
 * Runs detection for every active tenant (or only `tenantId`, NOT_FOUND when it does not exist): reads up to
 * `maxEvents` (default 2000, at most 20000) unread audit events per tenant (fewer when they hold the sign-ins of more
 * than 500 people, whose baselines the run writes; the rest stays pending), verifies their hash chain (a break raises
 * `audit-tampering` and detection continues), evaluates the rules, records detections and incidents, updates risk
 * and sign-in baselines, advances the tenant's cursor, and runs matching playbooks for new detections (automatic
 * containments braked at `maxAutomaticContainments` per tenant and run). A tenant whose evaluation fails, or whose
 * detection settings changed while it was evaluated, records nothing and keeps its cursor, so the next run reads the
 * same events again; the other tenants are unaffected. A
 * deployment operation for schedulers: no credential. The first run of a tenant starts one day back.
 */
export async function detectThreats(
  ctx: ServerContext,
  input: { tenantId?: string; maxEvents?: number } = {},
): Promise<ThreatDetectionRun> {
  const maxEvents = integer(input.maxEvents ?? defaultMaxEvents, 'maxEvents', 1, maxEventsLimit);
  const tenants =
    input.tenantId !== undefined
      ? [await ctx.tenant(ctx.store, text(input.tenantId, 'tenantId'))]
      : (await ctx.store.find<Tenant>('tenants', { status: 'active' })).sort(byId);
  const run: ThreatDetectionRun = {
    tenants: 0,
    eventsScanned: 0,
    detections: 0,
    incidentsOpened: 0,
    responses: 0,
    braked: 0,
    chainBreaks: 0,
    pending: 0,
  };
  for (const tenant of tenants) {
    // A tombstoned tenant only waits for the purge worker.
    if (tenant.status === 'deleted') continue;
    run.tenants++;
    let outcome: TenantOutcome;
    try {
      outcome = await ctx.observe.span('operation', 'threats:detect', tenant.id, () =>
        detectTenant(ctx, tenant, maxEvents),
      );
    } catch {
      // Nothing was recorded and the cursor stayed put, so the next run retries these events; the span reports it.
      continue;
    }
    run.eventsScanned += outcome.eventsScanned;
    run.detections += outcome.detections;
    run.incidentsOpened += outcome.incidentsOpened;
    run.responses += outcome.responses;
    run.braked += outcome.braked;
    if (outcome.chainBroken) run.chainBreaks++;
    if (outcome.pending) run.pending++;
  }
  return run;
}

async function detectTenant(
  ctx: ServerContext,
  tenant: Tenant,
  maxEvents: number,
): Promise<TenantOutcome> {
  const { store } = ctx;
  const tenantId = tenant.id;
  const now = ctx.now();
  // Everything up to the rule results is read outside a transaction: hashing and evaluating thousands of events
  // would otherwise hold the store's write lock. The write transaction re-checks the cursor, so overlapping runs
  // never record the same events twice.
  const cursor = await store.get<ThreatCursor>(threatCollections.cursors, tenantId);
  // Kept as read, so the write transaction can tell when threats.configure changed them meanwhile.
  const storedSettings = await store.get<ThreatSettings>(threatCollections.settings, tenantId);
  const settings = resolveThreatSettings(storedSettings);
  const head = await store.get<AuditChainHead>('auditChains', tenantId);
  const breaks: ChainBreak[] = [];
  // The last verified chain position; undefined until known (the first run starts mid-chain).
  let sequence: number | undefined;
  let hash: string | undefined;
  if (cursor) {
    const headSequence = head?.sequence ?? 0;
    const rolledBack = cursor.sequence > headSequence;
    const replaced =
      !rolledBack &&
      head !== undefined &&
      cursor.sequence === head.sequence &&
      cursor.hash !== undefined &&
      cursor.hash !== head.hash;
    if (rolledBack || replaced) {
      breaks.push({
        reason: rolledBack ? 'head-rolled-back' : 'head-mismatch',
        sequence: cursor.sequence,
      });
      // Continue from the head as it is now, so events appended after the rollback are still read.
      sequence = headSequence;
      hash = head?.hash;
    } else {
      sequence = cursor.sequence;
      hash = cursor.hash;
    }
  }
  let events: AuditEvent[] = [];
  if (sequence !== undefined)
    events = await findOrdered<AuditEvent>(
      store,
      'audit',
      { tenantId },
      { field: 'sequence', from: sequence + 1, limit: maxEvents + 1 },
    );
  else {
    // First run: start one day back instead of replaying the whole trail (both clocks, since server and
    // authentication events are stamped by different ones); the chain is verified from that event on.
    const first = await firstEventSince(
      store,
      tenantId,
      Math.min(now, Date.now()) - day,
      head?.sequence ?? 0,
    );
    if (first)
      events = await findOrdered<AuditEvent>(
        store,
        'audit',
        { tenantId },
        { field: 'sequence', from: first.sequence!, limit: maxEvents + 1 },
      );
    else {
      sequence = head?.sequence ?? 0;
      hash = head?.hash;
    }
  }
  let pending = events.length > maxEvents;
  if (pending) events = events.slice(0, maxEvents);
  const within = withinBaselineBudget(events);
  if (within < events.length) {
    events = events.slice(0, within);
    pending = true;
  }

  // Chain verification, every event including the module's own.
  let prunes: AuditEvent[] | undefined;
  /** A gap left by `pruneAudit` while the cursor was behind: a checkpoint names the event just before this one. */
  const prunedBefore = async (event: AuditEvent) => {
    prunes ??= await store.find<AuditEvent>('audit', { tenantId, action: 'audit:prune' });
    return prunes.some(
      (prune) =>
        prune.metadata?.prunedThroughSequence === event.sequence! - 1 &&
        prune.metadata?.prunedThroughHash === event.previousHash,
    );
  };
  for (const event of events) {
    const position = event.sequence!;
    const previous = hash ?? (sequence === 0 ? auditGenesis : undefined);
    let reason: ChainBreakReason | undefined;
    if (sequence !== undefined && position !== sequence + 1) {
      if (position <= sequence) reason = 'sequence-repeated';
      else if (!(await prunedBefore(event))) reason = 'sequence-gap';
    } else if (previous !== undefined && event.previousHash !== previous)
      reason = 'previous-hash-mismatch';
    if (!reason && event.hash !== (await auditEventHash(event))) reason = 'hash-mismatch';
    if (reason) breaks.push({ reason, sequence: position, event });
    // Detection continues from the event as stored, so one break is reported once.
    sequence = position;
    hash = event.hash;
  }
  const position = { sequence: sequence ?? 0, hash };

  const candidates: DetectionCandidate[] = [];
  const tampering = settings.rules['audit-tampering'];
  if (tampering.enabled)
    for (const found of breaks)
      candidates.push(tamperingCandidate(tenant, found, tampering.severity, now));

  // The module's own events never feed the rules, nor do malformed ones (the chain check above reports an edited
  // event; its fields are not trusted here).
  const ruleEvents = events.filter(considered);
  const baselines = new Map<string, ThreatBaseline>();
  /** Baselines stored for this tenant when read (overwritten in place), and ids another tenant's baseline holds. */
  const storedBaselines = new Set<string>();
  const foreignBaselines = new Set<string>();
  const state: RuleState = cursor?.authPolicy ? { authPolicy: cursor.authPolicy } : {};
  let touched = new Set<string>();
  if (ruleEvents.length) {
    let first = Number.POSITIVE_INFINITY;
    let last = Number.NEGATIVE_INFINITY;
    for (const event of ruleEvents) {
      first = Math.min(first, event.timestamp);
      last = Math.max(last, event.timestamp);
    }
    // Newest first, so a crowded window keeps the events closest to the ones being judged. One more than the cap
    // tells whether older events were left out.
    const newest = await findOrdered<AuditEvent>(
      store,
      'audit',
      { tenantId },
      {
        field: 'timestamp',
        direction: 'desc',
        from: first - ruleWindowMs(settings),
        to: last,
        limit: maxHistory + 1,
        where: considered,
      },
    );
    const history = newest.slice(0, maxHistory).reverse();
    const historyFrom = newest.length > maxHistory ? history[0]?.timestamp : undefined;
    // Sign-ins compare against and update baselines; own sign-in method changes read the risky sign-in on them.
    for (const identityId of baselineIdentityIds(ruleEvents)) {
      const baseline = await store.get<ThreatBaseline>(threatCollections.baselines, identityId);
      if (baseline?.tenantId === tenantId) {
        baselines.set(identityId, baseline);
        storedBaselines.add(identityId);
      } else if (baseline) foreignBaselines.add(identityId);
    }
    const evaluated = await evaluateThreatRules({
      tenantId,
      events: ruleEvents,
      history,
      ...(historyFrom !== undefined ? { historyFrom } : {}),
      settings,
      baselines,
      state,
      facts: ruleFacts(ctx, tenantId),
      now,
    });
    candidates.push(...evaluated.candidates);
    touched = new Set(evaluated.touchedBaselines);
  }
  // With no sign-in policy seen yet (a first run, or none changed so far), the policy in force before this run's
  // events is the tenant's as read before them, so guardrail-weakened judges the first change after this run too.
  // Not while more events wait than one run reads: a later one may already be reflected in that read.
  if (state.authPolicy === undefined && !pending)
    state.authPolicy = tenant.authPolicy
      ? (JSON.parse(JSON.stringify(tenant.authPolicy)) as Record<string, Json>)
      : {};

  const brake: PlaybookBrake = { contained: 0 };
  const written = await store.transaction(async (tx) => {
    const current = await tx.get<ThreatCursor>(threatCollections.cursors, tenantId);
    // Another run advanced the cursor since it was read: it recorded these events.
    if (
      current?.sequence !== cursor?.sequence ||
      current?.hash !== cursor?.hash ||
      current?.updatedAt !== cursor?.updatedAt
    )
      return undefined;
    // The settings changed since this run read them (threats.configure): the events were judged under the old ones, and
    // playbooks would run with the old brake, trusted networks and recipients. Nothing is recorded; the next run reads
    // the same events under the new settings.
    const settingsNow = await tx.get<ThreatSettings>(threatCollections.settings, tenantId);
    if (JSON.stringify(settingsNow ?? null) !== JSON.stringify(storedSettings ?? null))
      return undefined;
    let detections = 0;
    let incidentsOpened = 0;
    const created: { detection: ThreatDetection; incident: ThreatIncident }[] = [];
    for (const candidate of candidates) {
      const recorded = await recordDetection(ctx, tx, tenantId, candidate, settings, now);
      if (!recorded.created) continue;
      detections++;
      if (recorded.incidentOpened) incidentsOpened++;
      created.push({ detection: recorded.detection, incident: recorded.incident });
      if (candidate.riskySignIn && candidate.identityId !== undefined) {
        const baseline = await baselineFor(
          tx,
          tenantId,
          candidate.identityId,
          baselines,
          storedBaselines,
          now,
        );
        if (
          baseline &&
          (!baseline.riskySignIn || baseline.riskySignIn.at <= candidate.occurredAt)
        ) {
          baseline.riskySignIn = {
            at: candidate.occurredAt,
            detectionId: recorded.detection.id,
            ruleId: candidate.ruleId,
          };
          touched.add(candidate.identityId);
        }
      }
    }
    // Two round trips per person under the write lock, and at most `maxBaselinesPerRun` people per run.
    for (const identityId of touched) {
      const baseline = baselines.get(identityId);
      if (!baseline || foreignBaselines.has(identityId)) continue;
      const record: ThreatBaseline = {
        ...baseline,
        id: identityId,
        tenantId,
        identityId,
        updatedAt: now,
      };
      // A baseline read from this tenant is overwritten; if identity deletion removed it meanwhile, the write fails
      // and so does the run, and the next run skips the deleted person.
      if (storedBaselines.has(identityId)) await tx.put(threatCollections.baselines, record);
      else {
        // A deleted identity's baseline went with it (identity deletion); a late sign-in event does not bring it back.
        const identity = await tx.get<Identity>('identities', identityId);
        if (identity?.tenantId !== tenantId || identity.status === 'deleted') continue;
        await tx.insert(threatCollections.baselines, record);
      }
    }
    const next: ThreatCursor = {
      id: tenantId,
      tenantId,
      sequence: position.sequence,
      ...(position.hash !== undefined ? { hash: position.hash } : {}),
      ...(state.authPolicy !== undefined ? { authPolicy: state.authPolicy } : {}),
      updatedAt: now,
    };
    if (current) await tx.put(threatCollections.cursors, next);
    else await tx.insert(threatCollections.cursors, next);
    const responses: ThreatResponse[] = [];
    for (const { detection, incident } of created)
      responses.push(
        ...(await runPlaybooks(ctx, tx, tenantId, detection, incident, settings, brake)),
      );
    return { detections, incidentsOpened, responses };
  });
  if (!written)
    return {
      eventsScanned: 0,
      detections: 0,
      incidentsOpened: 0,
      responses: 0,
      braked: 0,
      chainBroken: false,
      pending: false,
    };
  await afterThreatResponses(ctx, tenantId, written.responses);
  return {
    eventsScanned: events.length,
    detections: written.detections,
    incidentsOpened: written.incidentsOpened,
    responses: written.responses.filter((response) => response.outcome === 'applied').length,
    braked: brake.braked ?? 0,
    chainBroken: breaks.length > 0,
    pending,
  };
}

/**
 * The earliest event of the tenant's chain stamped at or after `cutoff`, found by bisecting sequences (timestamps rise
 * along the chain, so this takes a few indexed reads however long the trail is; skew between the service and
 * authentication clocks only moves the start by as much). Pruned sequences are skipped. Undefined when every event
 * is older.
 */
async function firstEventSince(
  store: IamStore,
  tenantId: string,
  cutoff: number,
  headSequence: number,
): Promise<AuditEvent | undefined> {
  /** The first event at or after a sequence. */
  const from = async (sequence: number) =>
    (
      await findOrdered<AuditEvent>(
        store,
        'audit',
        { tenantId },
        { field: 'sequence', from: sequence, limit: 1 },
      )
    )[0];
  let low = 1;
  let high = headSequence + 1;
  let found: AuditEvent | undefined;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    const event = await from(middle);
    if (event && event.timestamp < cutoff) low = event.sequence! + 1;
    else {
      if (event) found = event;
      high = middle;
    }
  }
  return found;
}

/**
 * The baseline a risky sign-in is marked on: preloaded, stored (noted in `storedBaselines`), or new; undefined when
 * another tenant holds the id.
 */
async function baselineFor(
  tx: IamStore,
  tenantId: string,
  identityId: string,
  baselines: Map<string, ThreatBaseline>,
  storedBaselines: Set<string>,
  now: number,
): Promise<ThreatBaseline | undefined> {
  const loaded = baselines.get(identityId);
  if (loaded) return loaded;
  const stored = await tx.get<ThreatBaseline>(threatCollections.baselines, identityId);
  if (stored && stored.tenantId !== tenantId) return undefined;
  if (stored) storedBaselines.add(identityId);
  const baseline: ThreatBaseline = stored ?? {
    id: identityId,
    tenantId,
    identityId,
    networks: [],
    userAgents: [],
    firstSeenAt: now,
    updatedAt: now,
  };
  baselines.set(identityId, baseline);
  return baseline;
}

/**
 * How many of a run's events it takes so that it learns sign-ins (or reads risky sign-ins) of at most
 * `maxBaselinesPerRun` people; every event when fewer people are involved.
 */
function withinBaselineBudget(events: readonly AuditEvent[]): number {
  const people = new Set<string>();
  for (let index = 0; index < events.length; index++) {
    const event = events[index]!;
    if (!considered(event)) continue;
    for (const identityId of baselineIdentityIds([event])) {
      if (people.has(identityId)) continue;
      if (people.size >= maxBaselinesPerRun) return index;
      people.add(identityId);
    }
  }
  return events.length;
}

function tamperingCandidate(
  tenant: Tenant,
  found: ChainBreak,
  severity: ThreatSeverity,
  now: number,
): DetectionCandidate {
  // The event failed verification: none of its fields is trusted to have the right type.
  const stamped = found.event?.timestamp;
  const at = typeof stamped === 'number' && Number.isFinite(stamped) ? stamped : now;
  const action = typeof found.event?.action === 'string' ? found.event.action : undefined;
  const eventId = typeof found.event?.id === 'string' ? found.event.id : undefined;
  return {
    ruleId: 'audit-tampering',
    severity,
    title: 'Audit trail tampering',
    summary: `The audit trail of ${tenant.name} no longer verifies at event ${found.sequence}: ${chainBreakText[found.reason]}.`,
    subject: { type: 'tenant', id: tenant.id, name: tenant.name },
    dedupeKey: `${tenant.id}:${found.sequence}`,
    occurredAt: at,
    evidence: {
      eventIds: eventId !== undefined ? [eventId] : [],
      count: 1,
      firstAt: at,
      lastAt: at,
      ...(action !== undefined ? { actions: [action] } : {}),
    },
    metadata: { reason: found.reason, sequence: found.sequence },
  };
}

/**
 * The facts rules may ask about a tenant, read from the store and cached for the run. Privileged means owner, root
 * administrator, or holder of a live standing binding (direct or through a live group membership) of a role whose
 * inline document, attached policies, or inherited roles grant `*` or `iam:*` on `*` without conditions.
 */
function ruleFacts(ctx: ServerContext, tenantId: string): RuleFacts {
  const { store } = ctx;
  const identities = new Map<string, Identity | undefined>();
  const adminRoles = new Map<string, boolean>();
  const heldRoles = new Map<string, Set<string>>();
  const privileged = new Map<string, boolean>();
  const incidents = new Map<string, ThreatIncident | undefined>();
  async function identity(identityId: string): Promise<Identity | undefined> {
    if (!identities.has(identityId)) {
      const found = await store.get<Identity>('identities', identityId);
      identities.set(identityId, found?.tenantId === tenantId ? found : undefined);
    }
    return identities.get(identityId);
  }
  async function grantsAdmin(roleId: string, seen: Set<string>): Promise<boolean> {
    if (seen.has(roleId) || seen.size >= 64) return false;
    seen.add(roleId);
    const role = await store.get<Role>('roles', roleId);
    if (!role || role.tenantId !== tenantId) return false;
    if (unrestrictedAdmin(role.document)) return true;
    for (const policyId of role.policyIds) {
      const policy = await store.get<Policy>('policies', policyId);
      if (policy?.tenantId === tenantId && unrestrictedAdmin(policy.document)) return true;
    }
    for (const inherited of role.inherits ?? [])
      if (await grantsAdmin(inherited, seen)) return true;
    return false;
  }
  async function isAdminRole(roleId: string): Promise<boolean> {
    let admin = adminRoles.get(roleId);
    if (admin === undefined) {
      admin = await grantsAdmin(roleId, new Set());
      adminRoles.set(roleId, admin);
    }
    return admin;
  }
  async function held(identityId: string): Promise<Set<string>> {
    const cached = heldRoles.get(identityId);
    if (cached) return cached;
    const roles = new Set<string>();
    const standing = (binding: Binding) => !binding.eligible && ctx.liveBinding(binding);
    for (const binding of await store.find<Binding>('bindings', {
      tenantId,
      subjectType: 'identity',
      subjectId: identityId,
    }))
      if (standing(binding)) roles.add(binding.roleId);
    for (const member of await store.find<GroupMember>('groupMembers', { tenantId, identityId })) {
      if (!ctx.liveMembership(member)) continue;
      for (const binding of await store.find<Binding>('bindings', {
        tenantId,
        subjectType: 'group',
        subjectId: member.groupId,
      }))
        if (standing(binding)) roles.add(binding.roleId);
    }
    heldRoles.set(identityId, roles);
    return roles;
  }
  return {
    identity,
    isAdminRole,
    holdsRole: async (identityId, roleId) => (await held(identityId)).has(roleId),
    detectionStands: (detectionId) => stillCounts(store, tenantId, detectionId, incidents),
    async isPrivileged(identityId) {
      const cached = privileged.get(identityId);
      if (cached !== undefined) return cached;
      const found = await identity(identityId);
      let result = false;
      if (found && found.status !== 'deleted') {
        if (found.owner || found.rootAdmin) result = true;
        else
          for (const roleId of await held(identityId))
            if (await isAdminRole(roleId)) {
              result = true;
              break;
            }
      }
      privileged.set(identityId, result);
      return result;
    },
  };
}

/** A `uniqueKey` the store accepts: the value itself, or its prefix and hash when too long or not printable. */
function storageKey(value: string): string {
  let printable = true;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) {
      printable = false;
      break;
    }
  }
  if (printable && Buffer.byteLength(value, 'utf8') <= maxKeyBytes) return value;
  const prefix = value.slice(0, value.indexOf(':') + 1) || 'key:';
  return `${prefix}sha256:${createHash('sha256').update(value).digest('hex')}`;
}

/** A readable name for a subject in titles. */
const subjectLabel = (subject: ThreatDetection['subject']) => subject.name ?? subject.id;

/**
 * Adds a detection to the subject's open (or investigating) incident, or opens one (uniqueKey
 * `open:{subject.type}:{subject.id}`). An incident spanning several rules is retitled "N detections for X".
 */
async function joinIncident(
  tx: IamStore,
  tenantId: string,
  detection: ThreatDetection,
  now: number,
): Promise<{ incident: ThreatIncident; opened: boolean }> {
  const uniqueKey = storageKey(`open:${detection.subject.type}:${detection.subject.id}`);
  const [open] = await tx.find<ThreatIncident>(threatCollections.incidents, {
    tenantId,
    uniqueKey,
  });
  if (open) {
    const ruleIds = open.ruleIds.includes(detection.ruleId)
      ? open.ruleIds
      : [...open.ruleIds, detection.ruleId];
    const detectionCount = open.detectionCount + 1;
    // An incident about the tenant (or a network, a connection) gathers detections of whoever acted: once two name
    // different identities it names none, so a response to it never acts on whoever happened to come first.
    const several =
      open.severalIdentities === true ||
      (open.subject.type !== 'identity' &&
        open.identityId !== undefined &&
        detection.identityId !== undefined &&
        detection.identityId !== open.identityId);
    const { identityId: _identityId, ...rest } = open;
    const identityId = several ? undefined : (open.identityId ?? detection.identityId);
    const incident: ThreatIncident = {
      ...rest,
      detectionIds: [...open.detectionIds, detection.id].slice(-maxIncidentDetections),
      detectionCount,
      ruleIds,
      severity: maxSeverity(open.severity, detection.severity),
      title:
        ruleIds.length > 1
          ? `${detectionCount} detections for ${subjectLabel(open.subject)}`
          : open.title,
      lastDetectedAt: now,
      updatedAt: now,
      ...(identityId !== undefined ? { identityId } : {}),
      ...(several ? { severalIdentities: true as const } : {}),
      ...(open.network === undefined && detection.network !== undefined
        ? { network: detection.network }
        : {}),
    };
    await tx.put(threatCollections.incidents, incident);
    return { incident, opened: false };
  }
  const incident: ThreatIncident = {
    id: id(),
    tenantId,
    uniqueKey,
    subject: detection.subject,
    ...(detection.identityId !== undefined ? { identityId: detection.identityId } : {}),
    ...(detection.network !== undefined ? { network: detection.network } : {}),
    severity: detection.severity,
    title: detection.title,
    status: 'open',
    detectionIds: [detection.id],
    detectionCount: 1,
    ruleIds: [detection.ruleId],
    firstDetectedAt: now,
    lastDetectedAt: now,
    createdAt: now,
    updatedAt: now,
  };
  await tx.insert(threatCollections.incidents, incident);
  return { incident, opened: true };
}

/**
 * Records a candidate once: its `uniqueKey` is `{ruleId}:{dedupeKey}`, so a candidate raised again (the same burst or
 * triggering event) returns the existing detection with `created: false`. A new detection is `open`, joins its
 * subject's open incident or opens one, is audited as `threat:detection` (and `threat:incident-open`) under the
 * `threat-detection` actor, and adds `riskPoints[severity]` to its identity's risk (`recomputeRisk`).
 */
export async function recordDetection(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  candidate: DetectionCandidate,
  settings: ResolvedThreatSettings,
  now: number,
): Promise<{
  detection: ThreatDetection;
  incident: ThreatIncident;
  incidentOpened: boolean;
  created: boolean;
}> {
  const uniqueKey = storageKey(`${candidate.ruleId}:${candidate.dedupeKey}`);
  const [existing] = await tx.find<ThreatDetection>(threatCollections.detections, {
    tenantId,
    uniqueKey,
  });
  if (existing) {
    const linked =
      existing.incidentId !== undefined
        ? await tx.get<ThreatIncident>(threatCollections.incidents, existing.incidentId)
        : undefined;
    if (linked?.tenantId === tenantId)
      return { detection: existing, incident: linked, incidentOpened: false, created: false };
    // Its incident is gone: attach it to the subject's current one rather than leave it orphaned.
    const { incident, opened } = await joinIncident(tx, tenantId, existing, now);
    const detection: ThreatDetection = { ...existing, incidentId: incident.id };
    await tx.put(threatCollections.detections, detection);
    return { detection, incident, incidentOpened: opened, created: false };
  }
  const detection: ThreatDetection = {
    id: id(),
    tenantId,
    uniqueKey,
    ruleId: candidate.ruleId,
    severity: candidate.severity,
    title: candidate.title,
    summary: candidate.summary,
    subject: candidate.subject,
    ...(candidate.identityId !== undefined ? { identityId: candidate.identityId } : {}),
    ...(candidate.network !== undefined ? { network: candidate.network } : {}),
    evidence: candidate.evidence,
    ...(candidate.metadata !== undefined ? { metadata: candidate.metadata } : {}),
    status: 'open',
    occurredAt: candidate.occurredAt,
    detectedAt: now,
  };
  const { incident, opened } = await joinIncident(tx, tenantId, detection, now);
  detection.incidentId = incident.id;
  await tx.insert(threatCollections.detections, detection);
  const automatic = { automatic: true } as const;
  await threatAudit(
    ctx,
    tx,
    tenantId,
    automatic,
    'threat:detection',
    `threats/detections/${detection.id}`,
    {
      ruleId: detection.ruleId,
      severity: detection.severity,
      subjectType: detection.subject.type,
      subjectId: detection.subject.id,
      ...(detection.identityId !== undefined ? { identityId: detection.identityId } : {}),
      ...(detection.network !== undefined ? { network: detection.network } : {}),
      incidentId: incident.id,
    },
  );
  if (opened)
    await threatAudit(
      ctx,
      tx,
      tenantId,
      automatic,
      'threat:incident-open',
      `threats/incidents/${incident.id}`,
      {
        ruleId: detection.ruleId,
        severity: incident.severity,
        subjectType: incident.subject.type,
        subjectId: incident.subject.id,
        ...(incident.identityId !== undefined ? { identityId: incident.identityId } : {}),
      },
    );
  if (detection.identityId !== undefined)
    await recomputeRisk(ctx, tx, tenantId, detection.identityId, settings, now, undefined, {
      add: {
        detectionId: detection.id,
        ruleId: detection.ruleId,
        severity: detection.severity,
        points: riskPoints[detection.severity],
        at: now,
      },
    });
  return { detection, incident, incidentOpened: opened, created: true };
}

/**
 * Whether a contribution's detection still counts: not dismissed, and not resolved in an incident closed as a false
 * positive or benign. A detection that no longer exists does not count.
 */
async function stillCounts(
  tx: IamStore,
  tenantId: string,
  detectionId: string,
  incidents: Map<string, ThreatIncident | undefined>,
): Promise<boolean> {
  const detection = await tx.get<ThreatDetection>(threatCollections.detections, detectionId);
  if (!detection || detection.tenantId !== tenantId || detection.status === 'dismissed')
    return false;
  if (detection.status !== 'resolved' || detection.incidentId === undefined) return true;
  if (!incidents.has(detection.incidentId))
    incidents.set(
      detection.incidentId,
      await tx.get<ThreatIncident>(threatCollections.incidents, detection.incidentId),
    );
  const resolution = incidents.get(detection.incidentId)?.resolution;
  return resolution !== 'false-positive' && resolution !== 'benign';
}

/**
 * Recomputes an identity's risk record (`identityRisk`, id = identity id) in this tenant: adds `options.add`, drops
 * `options.drop` and, when nothing is added, every contribution whose detection was dismissed or resolved as a false
 * positive or benign; prunes contributions older than ten half-lives (ten days at least), keeps the newest 50, drops
 * a lapsed override, and stores the effective score and level. A level change is audited as `threat:risk-change`
 * (`{from, to, score}`, by `actorId` or the `threat-detection` actor). Undefined for identities outside the tenant or
 * deleted, and when there is no record and nothing to add.
 */
export async function recomputeRisk(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  identityId: string,
  settings: ResolvedThreatSettings,
  now: number,
  actorId?: string,
  options: { add?: RiskContribution; drop?: readonly string[] } = {},
): Promise<IdentityRisk | undefined> {
  const identity = await tx.get<Identity>('identities', identityId);
  if (!identity || identity.tenantId !== tenantId || identity.status === 'deleted')
    return undefined;
  const stored = await tx.get<IdentityRisk>(threatCollections.risk, identityId);
  if (stored && stored.tenantId !== tenantId) return undefined;
  if (!stored && !options.add) return undefined;
  // Never sooner than ten default half-lives: a half-life shortened for a while (threats.configure) decays scores at
  // once, but restoring it brings them back rather than finding the contributions gone.
  const cutoff =
    now -
    contributionHalfLives *
      Math.max(defaultThreatSettings.riskHalfLifeHours, settings.riskHalfLifeHours) *
      hour;
  const drop = new Set(options.drop ?? []);
  const incidents = new Map<string, ThreatIncident | undefined>();
  const kept: RiskContribution[] = [];
  const seen = new Set<string>();
  for (const contribution of stored?.contributions ?? []) {
    if (drop.has(contribution.detectionId) || seen.has(contribution.detectionId)) continue;
    if (contribution.at < cutoff) continue;
    // A new detection cannot have changed older ones; dismissals and resolutions recompute without adding.
    if (!options.add && !(await stillCounts(tx, tenantId, contribution.detectionId, incidents)))
      continue;
    seen.add(contribution.detectionId);
    kept.push(contribution);
  }
  if (options.add && !seen.has(options.add.detectionId) && !drop.has(options.add.detectionId))
    kept.push(options.add);
  const contributions = kept.sort((a, b) => a.at - b.at).slice(-maxContributions);
  const next: IdentityRisk = stored
    ? { ...stored, contributions, updatedAt: now }
    : {
        id: identityId,
        tenantId,
        identityId,
        contributions,
        score: 0,
        level: 'none',
        updatedAt: now,
      };
  if (next.override?.expiresAt !== undefined && next.override.expiresAt <= now)
    delete next.override;
  const effective = effectiveRisk(next, now, settings.riskHalfLifeHours);
  const previous = stored?.level ?? 'none';
  next.score = effective.score;
  next.level = effective.level;
  if (stored) await tx.put(threatCollections.risk, next);
  else await tx.insert(threatCollections.risk, next);
  if (next.level !== previous)
    await ctx.events.recordAudit(tx, {
      id: id(),
      tenantId,
      actorId: actorId ?? threatActor,
      action: 'threat:risk-change',
      resourceId: identityId,
      timestamp: ctx.now(),
      outcome: 'allow',
      metadata: { from: previous, to: next.level, score: next.score },
    });
  return next;
}

/** A playbook fires for a detection when every trigger clause it sets matches (unset or empty clauses match all). */
function playbookMatches(playbook: ThreatPlaybook, detection: ThreatDetection): boolean {
  const { ruleIds, minSeverity, subjectTypes } = playbook.trigger ?? {};
  return (
    (!ruleIds?.length || ruleIds.includes(detection.ruleId)) &&
    (!minSeverity || severityAtLeast(detection.severity, minSeverity)) &&
    (!subjectTypes?.length || subjectTypes.includes(detection.subject.type))
  );
}

/**
 * Runs the tenant's enabled playbooks whose trigger matches a new detection, oldest playbook first, each action in
 * order through `applyResponse` under the automatic actor, and counts the run on the playbook (`runs`,
 * `lastRunAt`). Containments share `brake` (one per tenant and run). Returns every response recorded, applied or
 * skipped; after the transaction commits the caller runs `afterThreatResponses`.
 */
export async function runPlaybooks(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  detection: ThreatDetection,
  incident: ThreatIncident,
  settings: ResolvedThreatSettings,
  brake: PlaybookBrake,
): Promise<ThreatResponse[]> {
  const playbooks = (
    await tx.find<ThreatPlaybook>(threatCollections.playbooks, { tenantId, enabled: true })
  )
    .filter((playbook) => playbookMatches(playbook, detection))
    .sort((a, b) => a.createdAt - b.createdAt || byId(a, b));
  const responses: ThreatResponse[] = [];
  for (const playbook of playbooks) {
    for (const action of playbook.actions) {
      if (!responseActionKinds.includes(action.kind)) continue;
      responses.push(
        await applyResponse(
          ctx,
          tx,
          tenantId,
          {
            action,
            subject: detection.subject,
            ...(detection.identityId !== undefined ? { identityId: detection.identityId } : {}),
            ...(detection.network !== undefined ? { network: detection.network } : {}),
            incidentId: incident.id,
            detectionId: detection.id,
            playbookId: playbook.id,
            reason: `Playbook ${playbook.name}: ${detection.title}`,
            actor: { automatic: true },
          },
          settings,
          brake,
        ),
      );
    }
    await tx.put<ThreatPlaybook>(threatCollections.playbooks, {
      ...playbook,
      runs: (playbook.runs ?? 0) + 1,
      lastRunAt: ctx.now(),
    });
  }
  return responses;
}
