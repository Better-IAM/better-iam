import {
  ipCounterKey,
  ipMatches,
  type AuditEvent,
  type Identity,
  type Json,
} from '@better-iam/core';
import {
  maxSeverity,
  threatActor,
  threatRule,
  threatRuleIds,
  type ResolvedThreatSettings,
  type ThreatBaseline,
  type ThreatEvidence,
  type ThreatRuleId,
  type ThreatSeverity,
  type ThreatSubject,
} from './threats.js';

/**
 * The detection rules of the threats module (`threatRules` in threats.ts) as pure evaluation: given one run's unread
 * audit events of a tenant, the events before them that the rules' windows reach back to, the tenant's settings, and
 * read-only facts about identities and roles, it returns the detections to record. Nothing is written here. The
 * engine (threat-engine.ts) records the candidates (deduplicated by `{ruleId}:{dedupeKey}`), persists the sign-in
 * baselines the rules updated, and keeps `state` on its cursor.
 *
 * Per-event rules run in chain order, so a risky sign-in earlier in the run opens the account-takeover window for a
 * change later in it. Counting rules slide a window over history and new events together and fire only for windows
 * that end at a new event, so every event is judged once, and a burst keeps one dedupe key however many runs see it
 * (`burstAnchor`).
 */

export interface RuleFacts {
  /** Identity by id in this tenant (undefined when unknown/deleted). */
  identity(id: string): Promise<Identity | undefined>;
  /**
   * Owner, rootAdmin, or holds (directly or via a group; live standing binding) a role whose policies grant
   * unconditional `*` or `iam:*` on `*` (analysis.ts unrestrictedAdmin logic).
   */
  isPrivileged(identityId: string): Promise<boolean>;
  /** Role grants unconditional `*`/`iam:*` on `*`. */
  isAdminRole(roleId: string): Promise<boolean>;
  /** Identity holds a live standing binding of the role, directly or through a group membership. */
  holdsRole(identityId: string, roleId: string): Promise<boolean>;
  /**
   * Whether a stored detection still stands: not dismissed, and not resolved in an incident closed as a false positive
   * or benign. Absent: every stored detection stands.
   */
  detectionStands?(detectionId: string): Promise<boolean>;
}

export interface RuleState {
  /** Tenant sign-in policy as last seen (cursor.authPolicy); rules update it when they read tenant:auth-policy. */
  authPolicy?: Record<string, Json>;
}

export interface RuleInput {
  tenantId: string;
  /**
   * Unread events of this run, ascending by sequence (the engine already dropped `threat:*` actions and actor
   * `threat-detection`).
   */
  events: AuditEvent[];
  /**
   * Events in the lookback window before/overlapping `events` (timestamp >= min(event ts) - `ruleWindowMs`), ascending
   * by timestamp; may include ids also in `events` (deduplicated by id). Same filtering as events.
   */
  history: AuditEvent[];
  /**
   * Set when the lookback was cut short (the engine keeps only the newest events up to a cap): the timestamp of the
   * oldest event loaded. A burst whose events reach back to within a window of it may have begun earlier, so its
   * anchor is the start of its UTC day, which every later run computes alike (`findBursts`).
   */
  historyFrom?: number;
  settings: ResolvedThreatSettings;
  /**
   * Baselines by identity id for the identities the engine preloaded (`baselineIdentityIds(events)`); rules mutate
   * them in place and create missing ones for people who sign in.
   */
  baselines: Map<string, ThreatBaseline>;
  state: RuleState;
  facts: RuleFacts;
  now: number;
}

export interface DetectionCandidate {
  ruleId: ThreatRuleId;
  severity: ThreatSeverity;
  title: string;
  summary: string;
  subject: ThreatSubject;
  identityId?: string;
  network?: string;
  /** Stable per burst / per triggering event; uniqueKey = `${ruleId}:${dedupeKey}` (≤ 400 chars, no control chars). */
  dedupeKey: string;
  occurredAt: number;
  evidence: ThreatEvidence;
  metadata?: Record<string, Json>;
  /** For sign-in rules: marks the baseline's riskySignIn after the engine stores the detection. */
  riskySignIn?: boolean;
}

const minute = 60_000;
const hour = 60 * minute;
const day = 24 * hour;
/** Evidence lists (event ids, networks, identities, actions) keep at most this many entries. */
const evidenceLimit = 20;
/** Longest `uniqueKey` (`{ruleId}:{dedupeKey}`) a detection may have. */
const uniqueKeyLimit = 400;
const baselineNetworkLimit = 25;
const baselineUserAgentLimit = 10;
/** The auth service caps recorded user agents at this length; stored baselines never hold longer ones. */
const userAgentLength = 512;

/** Actors that stand for the deployment, a protocol, or the application rather than an identity. */
const systemActors = new Set([
  'deployment-operator',
  threatActor,
  'directory-sync',
  'dynamic-registration',
  'access-package',
  'public-intake',
  'application',
]);

/**
 * Allowed actions mass-deletion counts. Domain events stand in for their operation envelopes where they exist:
 * `identity:delete` is written by identity, service-account, and agent deletion (whose envelopes are
 * `iam:identities:delete` and `iam:agents:delete`, so those are not counted twice), and `identity:offboard` rides on
 * `iam:identities:update`.
 */
const deletionActions = new Set([
  'identity:delete',
  'identity:offboard',
  'iam:roles:delete',
  'iam:policies:delete',
  'iam:groups:delete',
  'iam:bindings:delete',
  'iam:credentials:revoke',
  'iam:trust:revoke',
  'iam:webhooks:delete',
  'iam:resource-types:delete',
]);

/**
 * Refusals recorded for callers nobody authenticated, under the identity they tried to act as. A web identity token
 * refused by `assumeRoleWithWebIdentity` is recorded as a denial of the trust's service account, but trust ids are
 * public (they sit in CI workflow files) and anyone may post tokens for one, so these never count as that account's
 * denials (denial-burst). token-replay still reads the replays among them, which only a verified token can cause.
 */
const unauthenticatedRefusals: ReadonlySet<string> = new Set(['role:assumed-with-web-identity']);

/** Changes to a person's own sign-in methods that keep an intruder in after a takeover, as summaries word them. */
const persistenceChanges = new Map<string, string>([
  ['auth:mfa:disable', 'turned off their second factor'],
  // An intruder's own authenticator on an account that had none locks the account holder out of their next sign-in.
  ['auth:mfa:enable', 'enrolled an authenticator app'],
  ['auth:passkey:create', 'added a passkey'],
  ['auth:mfa:recovery-codes', 'generated new recovery codes'],
  ['auth:device:trust', 'remembered a device'],
  ['auth:email:change', 'changed their email address'],
  ['auth:password:change', 'changed their password'],
  ['iam:credentials:create', 'created an API key'],
]);

const droppedFlag = (name: string) => (before: Record<string, Json>, after: Record<string, Json>) =>
  before[name] === true && after[name] !== true;
const nonEmptyList = (value: Json | undefined) => Array.isArray(value) && value.length > 0;
/** Protections of the tenant sign-in policy whose removal guardrail-weakened reports. */
const policyProtections: {
  name: string;
  label: string;
  weakened(before: Record<string, Json>, after: Record<string, Json>): boolean;
}[] = [
  { name: 'requireMfa', label: 'the MFA requirement', weakened: droppedFlag('requireMfa') },
  {
    name: 'requireMfaForOwners',
    label: 'the MFA requirement for owners',
    weakened: droppedFlag('requireMfaForOwners'),
  },
  {
    name: 'bindSessionsToIp',
    label: 'binding sessions to their network',
    weakened: droppedFlag('bindSessionsToIp'),
  },
  {
    name: 'allowedIpRanges',
    label: 'the IP allowlist',
    weakened: (before, after) =>
      nonEmptyList(before.allowedIpRanges) && !nonEmptyList(after.allowedIpRanges),
  },
  {
    name: 'notifyNewSignIn',
    label: 'new sign-in notices',
    weakened: droppedFlag('notifyNewSignIn'),
  },
];

/** Rules that count events per key in a sliding window (`findBursts`). */
const countingRules: readonly ThreatRuleId[] = [
  'password-spray',
  'brute-force',
  'mfa-bombardment',
  'mass-deletion',
  'directory-mass-change',
  'impersonation-burst',
  'denial-burst',
  'recon-burst',
];

type RuleSetting = ResolvedThreatSettings['rules'][ThreatRuleId];

/** An enabled rule's severity, threshold, and window, with the definition's defaults behind the tenant's values. */
interface Tuned {
  setting: RuleSetting;
  severity: ThreatSeverity;
  threshold: number;
  windowMs: number;
}

function positive(value: number | undefined, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : fallback;
}

/** The rule's tuning when the tenant has it enabled. */
function tuned(settings: ResolvedThreatSettings, ruleId: ThreatRuleId): Tuned | undefined {
  const setting: RuleSetting | undefined = settings.rules[ruleId];
  if (!setting?.enabled) return undefined;
  const definition = threatRule(ruleId);
  return {
    setting,
    severity: setting.severity,
    threshold: positive(setting.threshold, definition.threshold ?? 1),
    windowMs: positive(setting.windowMs, definition.windowMs ?? hour),
  };
}

/**
 * The dedupe anchor of a qualifying window ending at `at`: the first event of its cluster (events of one key no more
 * than a window apart), but never before the start of the UTC day of `at`, so activity that never pauses raises at
 * most one detection a day. Every run that sees the window computes the same anchor as long as its history reaches
 * `burstReach` back. Windows of a day or longer use window-sized buckets instead.
 */
function burstAnchor(clusterStart: number, at: number, windowMs: number): number {
  if (windowMs >= day) return Math.floor(at / windowMs) * windowMs;
  return Math.max(clusterStart, Math.floor(at / day) * day);
}

/** History a counting rule needs for stable anchors: the anchor's day (or bucket) plus one window before it. */
function burstReach(windowMs: number): number {
  return windowMs >= day ? windowMs : day + windowMs;
}

/**
 * How far before a run's earliest event the engine loads history: the longest reach of an enabled rule, at least one
 * day. A counting rule reaches back one window plus the UTC day its burst anchor may lie in (`burstAnchor`), so an
 * ongoing burst keeps its dedupe key from run to run; brute-force-success reaches back its window. With the default
 * settings this is one day and fifteen minutes.
 */
export function ruleWindowMs(settings: ResolvedThreatSettings): number {
  let reach = day;
  for (const ruleId of countingRules) {
    const rule = tuned(settings, ruleId);
    if (rule) reach = Math.max(reach, burstReach(rule.windowMs));
  }
  const success = tuned(settings, 'brute-force-success');
  if (success) reach = Math.max(reach, success.windowMs);
  return reach;
}

/**
 * Identities whose stored baselines the rules read for these events: people who signed in (not through
 * impersonation), whose baselines the sign-in rules compare and update, and people who changed their own sign-in
 * methods, for whom account-takeover-persistence reads the risky sign-in an earlier run marked. The engine preloads
 * these into `RuleInput.baselines`.
 */
export function baselineIdentityIds(events: readonly AuditEvent[]): string[] {
  const ids = new Set<string>();
  for (const event of events)
    if (
      (event.action === 'auth:session:create' && !event.impersonatorId) ||
      (persistenceChanges.has(event.action) && event.resourceId === event.actorId)
    )
      ids.add(event.actorId);
  return [...ids];
}

/** A sign-in a rule flagged, opening the account-takeover-persistence window. */
interface RiskySignIn {
  at: number;
  ruleId: ThreatRuleId;
  /** The sign-in event, when it was judged in this run. */
  eventId?: string;
  /** The stored detection, when an earlier run recorded it (the baseline's riskySignIn). */
  detectionId?: string;
  /** The candidate's unique key, when it was raised in this run. */
  uniqueKey?: string;
}

/** One evaluation: its input, memoized reads, and the candidates found so far (merged by unique key). */
interface Run {
  input: RuleInput;
  identity(identityId: string): Promise<Identity | undefined>;
  /** True when the address lies in one of the tenant's trusted networks, which detections never report. */
  trusted(ip: string): boolean;
  add(candidate: DetectionCandidate): void;
}

/**
 * Evaluates every enabled rule over one run's events. Returns the detections to record, oldest first, and the
 * identities whose baselines changed (created, or updated by a sign-in); the engine persists those.
 */
export async function evaluateThreatRules(
  input: RuleInput,
): Promise<{ candidates: DetectionCandidate[]; touchedBaselines: Set<string> }> {
  const identities = new Map<string, Promise<Identity | undefined>>();
  const trustedAddresses = new Map<string, boolean>();
  const found = new Map<string, DetectionCandidate>();
  const run: Run = {
    input,
    identity(identityId) {
      let identity = identities.get(identityId);
      if (!identity) {
        identity = input.facts.identity(identityId);
        identities.set(identityId, identity);
      }
      return identity;
    },
    trusted(ip) {
      let trusted = trustedAddresses.get(ip);
      if (trusted === undefined) {
        trusted = input.settings.trustedNetworks.some((network) => ipMatches(ip, network));
        trustedAddresses.set(ip, trusted);
      }
      return trusted;
    },
    add(candidate) {
      const uniqueKey = `${candidate.ruleId}:${candidate.dedupeKey}`;
      const existing = found.get(uniqueKey);
      if (existing) merge(existing, candidate);
      else found.set(uniqueKey, candidate);
    },
  };
  const ordered = chronological([...input.history, ...input.events]);
  const fresh = new Set<string>();
  const events: AuditEvent[] = [];
  for (const event of input.events)
    if (considered(event) && !fresh.has(event.id)) {
      fresh.add(event.id);
      events.push(event);
    }
  const context: EventContext = {
    signIns: indexSignIns(ordered),
    risky: new Map(),
    touched: new Set(),
  };
  for (const event of events) await evaluateEvent(run, event, context);
  await evaluateCounting(run, ordered, fresh);
  return {
    candidates: [...found.values()].sort((a, b) => a.occurredAt - b.occurredAt),
    touchedBaselines: context.touched,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Event shapes

/**
 * Events the rules read: well formed, and not the threats module's own. The engine filters with it too, so a stored
 * event with a missing or mistyped field (one an intruder edited, say) is reported by the chain check and otherwise
 * skipped, never stopping detection for its tenant.
 */
export function considered(event: AuditEvent): boolean {
  return (
    typeof event.id === 'string' &&
    typeof event.action === 'string' &&
    typeof event.actorId === 'string' &&
    typeof event.resourceId === 'string' &&
    Number.isFinite(event.timestamp) &&
    event.actorId !== threatActor &&
    !event.action.startsWith('threat:')
  );
}

/** History and new events together, each once, oldest first. */
function chronological(events: readonly AuditEvent[]): AuditEvent[] {
  const byId = new Map<string, AuditEvent>();
  for (const event of events) if (considered(event)) byId.set(event.id, event);
  return [...byId.values()].sort(
    (a, b) =>
      a.timestamp - b.timestamp ||
      (a.sequence ?? 0) - (b.sequence ?? 0) ||
      (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  );
}

/**
 * Written by the service that owns the action, not an application `authorize()` call: those record only denials and
 * root overrides, under any action name the application passes and without metadata.
 */
function recorded(event: AuditEvent): boolean {
  return event.rootOverride !== true;
}

/** Actors that are identities (people, service accounts, agents), not the deployment or a SCIM connection. */
function identityActor(actorId: string): boolean {
  return (
    !systemActors.has(actorId) && !actorId.startsWith('scim:') && !actorId.startsWith('signal:')
  );
}

/**
 * Who is behind an event: the administrator of a "view as" session (`impersonatorId`) rather than the member it
 * shows as, so what support staff do while viewing as someone never counts against, or raises the risk of, that
 * person.
 */
function responsibleActor(event: AuditEvent): string {
  return typeof event.impersonatorId === 'string' && event.impersonatorId
    ? event.impersonatorId
    : event.actorId;
}

/** Members a burst's events were performed as, through "view as" sessions of its actor. */
function viewedAs(events: readonly AuditEvent[]): string[] {
  return limited(
    events.map((event) => (responsibleActor(event) !== event.actorId ? event.actorId : undefined)),
  );
}

/** How a summary notes a burst performed (partly) through "view as" sessions, with `viewedAs` metadata. */
function viewing(events: readonly AuditEvent[]): {
  clause: string;
  metadata: Record<string, Json>;
} {
  const members = viewedAs(events);
  if (!members.length) return { clause: '', metadata: {} };
  const all = events.every((event) => responsibleActor(event) !== event.actorId);
  const whom = members.length === 1 ? 'someone else' : `${members.length} other people`;
  return {
    clause: `, ${all ? 'all' : 'some'} while viewing as ${whom}`,
    metadata: { viewedAs: members },
  };
}

/** A failed sign-in the auth service recorded (`auth:signin:fail`), optionally of one reason. */
function signInFailure(event: AuditEvent, reason?: string): boolean {
  const recordedReason = event.metadata?.reason;
  return (
    event.action === 'auth:signin:fail' &&
    event.outcome === 'allow' &&
    recorded(event) &&
    typeof recordedReason === 'string' &&
    (reason === undefined || recordedReason === reason)
  );
}

/** A sign-in session the person started themselves (`auth:session:create` without an impersonating administrator). */
function ownSignIn(event: AuditEvent): boolean {
  return (
    event.action === 'auth:session:create' &&
    event.outcome === 'allow' &&
    !event.impersonatorId &&
    recorded(event)
  );
}

interface ClientNetwork {
  ip: string;
  /** `ipCounterKey` form: an IPv4 address, or an IPv6 /64. */
  key: string;
}

function clientNetwork(value: Json | undefined): ClientNetwork | undefined {
  if (typeof value !== 'string') return undefined;
  const key = ipCounterKey(value);
  return key === undefined ? undefined : { ip: value, key };
}

/** The network's key, unless it is trusted (trusted networks never appear in a detection). */
function reportableKey(run: Run, network: ClientNetwork | undefined): string | undefined {
  return network && !run.trusted(network.ip) ? network.key : undefined;
}

/** Distinct reportable networks the events came from. */
function reportableNetworks(run: Run, events: readonly AuditEvent[]): string[] {
  return distinctValues(
    events.map((event) => reportableKey(run, clientNetwork(event.metadata?.ip))),
  );
}

function jsonObject(value: Json | undefined): value is { [key: string]: Json } {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// ---------------------------------------------------------------------------------------------------------------
// Per-event rules

/** Sign-in events per person, oldest first: failures of any reason, and sign-ins not made through impersonation. */
interface SignInIndex {
  failures: Map<string, AuditEvent[]>;
  signIns: Map<string, AuditEvent[]>;
  /** Position of each sign-in in its person's list. */
  positions: Map<string, number>;
  /** Position of each indexed failure and sign-in in the run's chronological order (timestamp, then chain sequence). */
  order: Map<string, number>;
}

interface EventContext {
  signIns: SignInIndex;
  /** The latest risky sign-in flagged in this run, per identity. */
  risky: Map<string, RiskySignIn>;
  /** Identities whose baselines changed. */
  touched: Set<string>;
}

function append(lists: Map<string, AuditEvent[]>, key: string, event: AuditEvent): AuditEvent[] {
  let list = lists.get(key);
  if (!list) {
    list = [];
    lists.set(key, list);
  }
  list.push(event);
  return list;
}

function indexSignIns(ordered: readonly AuditEvent[]): SignInIndex {
  const index: SignInIndex = {
    failures: new Map(),
    signIns: new Map(),
    positions: new Map(),
    order: new Map(),
  };
  for (let position = 0; position < ordered.length; position++) {
    const event = ordered[position]!;
    if (signInFailure(event)) append(index.failures, event.actorId, event);
    else if (ownSignIn(event))
      index.positions.set(event.id, append(index.signIns, event.actorId, event).length - 1);
    else continue;
    index.order.set(event.id, position);
  }
  return index;
}

/** The first index of a time-ordered list whose event passes a test that, once passed, stays passed. */
function firstIndex(list: readonly AuditEvent[], test: (event: AuditEvent) => boolean): number {
  let low = 0;
  let high = list.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (test(list[middle]!)) high = middle;
    else low = middle + 1;
  }
  return low;
}

/**
 * The person's failed sign-ins in the `windowMs` before a sign-in and after their previous one: the streak the
 * sign-in ended, as the auth service's sign-in ledger counts it. A failure belongs to the streak when it comes after
 * the previous sign-in in chronological order (so an attempt stamped in the same millisecond as that sign-in but
 * recorded after it, as the ledger restarted from it, still counts) and was refused no later than this sign-in: its
 * timestamp is the refusal time, while its record is written after the refusal was answered and may land behind the
 * sign-in in the chain.
 */
function failuresBefore(index: SignInIndex, event: AuditEvent, windowMs: number): AuditEvent[] {
  const failures = index.failures.get(event.actorId);
  if (!failures) return [];
  const position = index.positions.get(event.id);
  const previous = position ? index.signIns.get(event.actorId)?.[position - 1] : undefined;
  const after = previous ? (index.order.get(previous.id) ?? -1) : -1;
  const from = event.timestamp - windowMs;
  const start = firstIndex(
    failures,
    (failure) => failure.timestamp >= from && index.order.get(failure.id)! > after,
  );
  const end = firstIndex(failures, (failure) => failure.timestamp > event.timestamp);
  return failures.slice(start, end);
}

async function evaluateEvent(run: Run, event: AuditEvent, context: EventContext): Promise<void> {
  switch (event.action) {
    case 'auth:session:create':
      return signedIn(run, event, context);
    case 'auth:session:mismatch':
      return sessionMismatch(run, event);
    case 'iam:bindings:create':
      return bindingCreated(run, event);
    case 'iam:root:grant':
      return rootGranted(run, event);
    case 'tenant:auth-policy':
      return authPolicyChanged(run, event);
    case 'security:network-unblock':
      return networkUnblocked(run, event);
    case 'role:assumed-with-web-identity':
      return tokenReplayed(run, event);
    case 'invariant:broken':
      return invariantBroken(run, event);
    case 'signal:received':
      return upstreamSignal(run, event);
    default:
      if (persistenceChanges.has(event.action))
        return persistenceChanged(run, event, context.risky);
  }
}

/**
 * brute-force-success, dormant-reactivated, and new-network judge a sign-in against what came before it; then the
 * sign-in is learned into the person's baseline whether or not those rules are enabled.
 */
async function signedIn(run: Run, event: AuditEvent, context: EventContext): Promise<void> {
  if (!ownSignIn(event)) return;
  const { settings } = run.input;
  const identityId = event.actorId;
  const network = clientNetwork(event.metadata?.ip);
  const baseline = run.input.baselines.get(identityId);
  const flag = (candidate: DetectionCandidate) => {
    run.add(candidate);
    context.risky.set(identityId, {
      at: candidate.occurredAt,
      ruleId: candidate.ruleId,
      eventId: event.id,
      uniqueKey: `${candidate.ruleId}:${candidate.dedupeKey}`,
    });
  };

  const success = tuned(settings, 'brute-force-success');
  const failures = success ? failuresBefore(context.signIns, event, success.windowMs) : [];
  if (success && failures.length >= success.threshold) {
    const failing = new Set(failures.map((failure) => clientNetwork(failure.metadata?.ip)?.key));
    const fromFailing = network !== undefined && failing.has(network.key);
    const who = await identitySubject(run, identityId);
    flag({
      ruleId: 'brute-force-success',
      severity: fromFailing ? success.severity : lowerSeverity[success.severity],
      title: titled('brute-force-success', who.label),
      summary: `${who.label} signed in after ${plural(failures.length, 'failed attempt')} in the preceding ${inWords(success.windowMs)}${fromFailing ? ', from a network that was failing' : ''}.`,
      ...who.target,
      ...reportedNetwork(run, network),
      dedupeKey: dedupeKey('brute-force-success', event.id),
      occurredAt: event.timestamp,
      evidence: evidenceOf(run, [...failures, event]),
      metadata: {
        failures: failures.length,
        threshold: success.threshold,
        windowMs: success.windowMs,
        fromFailingNetwork: fromFailing,
      },
      riskySignIn: true,
    });
  }

  const dormant = tuned(settings, 'dormant-reactivated');
  const lastSignInAt = baseline?.lastSignInAt;
  const dormantDays = Math.max(1, settings.dormantDays);
  if (
    dormant &&
    lastSignInAt !== undefined &&
    event.timestamp - lastSignInAt >= dormantDays * day
  ) {
    const idleDays = Math.floor((event.timestamp - lastSignInAt) / day);
    const who = await identitySubject(run, identityId);
    flag({
      ruleId: 'dormant-reactivated',
      severity: dormant.severity,
      title: titled('dormant-reactivated', who.label),
      summary: `${who.label} signed in after ${plural(idleDays, 'day')} without a sign-in (accounts count as dormant after ${plural(dormantDays, 'day')}).`,
      ...who.target,
      ...reportedNetwork(run, network),
      dedupeKey: dedupeKey('dormant-reactivated', event.id),
      occurredAt: event.timestamp,
      evidence: evidenceOf(run, [event]),
      metadata: { lastSignInAt, idleDays, dormantDays },
      riskySignIn: true,
    });
  }

  const unfamiliar = tuned(settings, 'new-network');
  if (
    unfamiliar &&
    network &&
    baseline?.networks.length &&
    !baseline.networks.some((known) => known.key === network.key) &&
    !run.trusted(network.ip)
  ) {
    const privileged = await run.input.facts.isPrivileged(identityId);
    if (privileged || unfamiliar.setting.everyone === true) {
      const who = await identitySubject(run, identityId);
      flag({
        ruleId: 'new-network',
        severity: privileged ? unfamiliar.severity : 'low',
        title: titled('new-network', who.label),
        summary: `${who.label}${privileged ? ', a privileged account,' : ''} signed in from ${network.key}, a network not seen for them before.`,
        ...who.target,
        network: network.key,
        dedupeKey: dedupeKey('new-network', event.id),
        occurredAt: event.timestamp,
        evidence: evidenceOf(run, [event]),
        metadata: { privileged, knownNetworks: baseline.networks.length },
        riskySignIn: true,
      });
    }
  }

  learnSignIn(run.input, event, network, context.touched);
}

/** Records a sign-in on the person's baseline (created on first sight): its network, user agent, and time. */
function learnSignIn(
  input: RuleInput,
  event: AuditEvent,
  network: ClientNetwork | undefined,
  touched: Set<string>,
): void {
  const identityId = event.actorId;
  let baseline = input.baselines.get(identityId);
  if (!baseline) {
    baseline = {
      id: identityId,
      tenantId: input.tenantId,
      identityId,
      networks: [],
      userAgents: [],
      firstSeenAt: event.timestamp,
      updatedAt: input.now,
    };
    input.baselines.set(identityId, baseline);
  }
  if (network)
    baseline.networks = [
      ...baseline.networks.filter((known) => known.key !== network.key),
      { key: network.key, lastAt: event.timestamp },
    ].slice(-baselineNetworkLimit);
  const recordedAgent = event.metadata?.userAgent;
  const userAgent =
    typeof recordedAgent === 'string' ? clean(recordedAgent).slice(0, userAgentLength) : '';
  if (userAgent)
    baseline.userAgents = [
      ...baseline.userAgents.filter((known) => known.value !== userAgent),
      { value: userAgent, lastAt: event.timestamp },
    ].slice(-baselineUserAgentLimit);
  baseline.lastSignInAt = Math.max(baseline.lastSignInAt ?? event.timestamp, event.timestamp);
  baseline.updatedAt = input.now;
  touched.add(identityId);
}

/** session-hijack: a session bound to one network was presented from another (one detection per session). */
async function sessionMismatch(run: Run, event: AuditEvent): Promise<void> {
  const rule = tuned(run.input.settings, 'session-hijack');
  if (!rule || event.outcome !== 'allow' || !recorded(event)) return;
  const metadata = event.metadata ?? {};
  const sessionId =
    typeof metadata.sessionId === 'string' && metadata.sessionId ? metadata.sessionId : undefined;
  const sessionIp = typeof metadata.sessionIp === 'string' ? metadata.sessionIp : '';
  const ip = typeof metadata.ip === 'string' ? metadata.ip : undefined;
  const presented = clientNetwork(ip);
  const who = await identitySubject(run, event.actorId);
  run.add({
    ruleId: 'session-hijack',
    severity: rule.severity,
    title: titled('session-hijack', who.label),
    summary: `A session of ${who.label} bound to ${sessionIp ? clean(sessionIp) : 'one network'} was presented from ${ip ? clean(ip) : 'another network'}.`,
    ...who.target,
    ...reportedNetwork(run, presented),
    dedupeKey: dedupeKey('session-hijack', sessionId ?? event.id),
    occurredAt: event.timestamp,
    evidence: evidenceOf(run, [event], {
      networks: [reportableKey(run, clientNetwork(sessionIp))],
    }),
    metadata: { ...(sessionId ? { sessionId } : {}), sessionIp, ...(ip ? { ip } : {}) },
  });
}

/**
 * account-takeover-persistence: a person changed their own sign-in methods within the window after a risky sign-in,
 * flagged earlier in this run or by an earlier run (the baseline's riskySignIn). The chain already orders the two,
 * so timestamps from different writers' clocks may disagree by up to a window.
 */
async function persistenceChanged(
  run: Run,
  event: AuditEvent,
  risky: Map<string, RiskySignIn>,
): Promise<void> {
  const rule = tuned(run.input.settings, 'account-takeover-persistence');
  const change = persistenceChanges.get(event.action);
  if (!rule || !change || event.outcome !== 'allow' || event.resourceId !== event.actorId) return;
  if (event.action.startsWith('auth:') && !recorded(event)) return;
  const sources: RiskySignIn[] = [];
  const stored = run.input.baselines.get(event.actorId)?.riskySignIn;
  // A risky sign-in an administrator has since judged harmless (dismissed, or closed as a false positive or benign)
  // opens no window.
  if (stored && (await run.input.facts.detectionStands?.(stored.detectionId)) !== false)
    sources.push({ at: stored.at, ruleId: stored.ruleId, detectionId: stored.detectionId });
  const current = risky.get(event.actorId);
  if (current) sources.push(current);
  let source: RiskySignIn | undefined;
  for (const candidate of sources)
    if (
      Math.abs(event.timestamp - candidate.at) <= rule.windowMs &&
      (!source || candidate.at > source.at)
    )
      source = candidate;
  if (!source) return;
  const who = await identitySubject(run, event.actorId);
  const elapsed = Math.max(0, event.timestamp - source.at);
  const riskyTitle = threatRuleIds.has(source.ruleId)
    ? threatRule(source.ruleId).title.toLowerCase()
    : clean(source.ruleId);
  run.add({
    ruleId: 'account-takeover-persistence',
    severity: rule.severity,
    title: titled('account-takeover-persistence', who.label),
    summary: `${who.label} ${change} ${elapsed < minute ? 'less than a minute' : about(elapsed)} after a risky sign-in (${riskyTitle}).`,
    ...who.target,
    dedupeKey: dedupeKey('account-takeover-persistence', event.id),
    occurredAt: event.timestamp,
    evidence: {
      eventIds: [...(source.eventId ? [source.eventId] : []), event.id],
      count: source.eventId ? 2 : 1,
      firstAt: Math.min(source.at, event.timestamp),
      lastAt: Math.max(source.at, event.timestamp),
      actions: source.eventId ? ['auth:session:create', event.action] : [event.action],
    },
    metadata: {
      changedAction: event.action,
      riskySignInRuleId: source.ruleId,
      riskySignInAt: source.at,
      ...(source.detectionId ? { riskySignInDetectionId: source.detectionId } : {}),
      ...(source.uniqueKey ? { riskySignInKey: source.uniqueKey } : {}),
    },
  });
}

/**
 * privilege-escalation: an administrator role was granted by someone who now holds it. The operation event names
 * only the role, so a holder granting the role to a colleague matches too; firings are kept to one per actor, role,
 * and UTC day (later grants add evidence), and root administrators and owners, who hold full access already, are not
 * judged.
 */
async function bindingCreated(run: Run, event: AuditEvent): Promise<void> {
  const rule = tuned(run.input.settings, 'privilege-escalation');
  if (!rule || event.outcome !== 'allow' || !identityActor(event.actorId)) return;
  const actor = await run.identity(event.actorId);
  if (!actor || actor.rootAdmin || actor.owner) return;
  const roleId = event.resourceId;
  if (!(await run.input.facts.isAdminRole(roleId))) return;
  if (!(await run.input.facts.holdsRole(actor.id, roleId))) return;
  const label = identityLabel(actor, actor.id);
  run.add({
    ruleId: 'privilege-escalation',
    severity: rule.severity,
    title: titled('privilege-escalation', label),
    summary: `${label} granted the administrator role ${clean(roleId)} and now holds it.`,
    subject: { type: 'identity', id: actor.id, name: label },
    identityId: actor.id,
    dedupeKey: dedupeKey('privilege-escalation', actor.id, roleId, startOfDay(event.timestamp)),
    occurredAt: event.timestamp,
    evidence: evidenceOf(run, [event], { actions: true }),
    metadata: { roleId },
  });
}

/** root-admin-granted: `iam:root:grant` left its target a root administrator (the same event also removes it). */
async function rootGranted(run: Run, event: AuditEvent): Promise<void> {
  const rule = tuned(run.input.settings, 'root-admin-granted');
  if (!rule || event.outcome !== 'allow') return;
  const target = await run.identity(event.resourceId);
  if (!target?.rootAdmin) return;
  const label = identityLabel(target, target.id);
  const grantedBy = identityLabel(await run.identity(event.actorId), event.actorId);
  run.add({
    ruleId: 'root-admin-granted',
    severity: rule.severity,
    title: titled('root-admin-granted', label),
    summary: `${grantedBy} made ${label} a root administrator of the deployment.`,
    subject: { type: 'identity', id: target.id, name: label },
    identityId: target.id,
    dedupeKey: dedupeKey('root-admin-granted', event.id),
    occurredAt: event.timestamp,
    evidence: evidenceOf(run, [event], { identityIds: [target.id], actions: true }),
    metadata: { grantedBy: event.actorId },
  });
}

/**
 * guardrail-weakened (sign-in policy): compares the tenant's new sign-in policy with the one last seen, then
 * remembers the new one. Without a previous policy the rule only learns.
 */
async function authPolicyChanged(run: Run, event: AuditEvent): Promise<void> {
  const { input } = run;
  if (event.outcome !== 'allow' || !recorded(event) || event.resourceId !== input.tenantId) return;
  const metadata = event.metadata;
  if (!metadata || !Object.hasOwn(metadata, 'authPolicy')) return;
  const policy = metadata.authPolicy;
  if (policy !== null && !jsonObject(policy)) return;
  const after: Record<string, Json> = policy ?? {};
  const before = input.state.authPolicy;
  input.state.authPolicy = after;
  const rule = tuned(input.settings, 'guardrail-weakened');
  if (!rule || !before) return;
  const dropped = policyProtections.filter((protection) => protection.weakened(before, after));
  if (!dropped.length) return;
  const actor = await actorOf(run, event.actorId);
  run.add({
    ruleId: 'guardrail-weakened',
    severity: rule.severity,
    title: titled('guardrail-weakened', 'sign-in policy'),
    summary: `${actor.label} removed ${series(dropped.map((protection) => protection.label))} from the tenant sign-in policy.`,
    subject: { type: 'tenant', id: input.tenantId },
    ...(actor.identityId ? { identityId: actor.identityId } : {}),
    dedupeKey: dedupeKey('guardrail-weakened', event.id),
    occurredAt: event.timestamp,
    evidence: evidenceOf(run, [event], { actions: true }),
    metadata: { change: 'auth-policy', weakened: dropped.map((protection) => protection.name) },
  });
}

/** guardrail-weakened (network block lifted): every `security:network-unblock`. */
async function networkUnblocked(run: Run, event: AuditEvent): Promise<void> {
  const rule = tuned(run.input.settings, 'guardrail-weakened');
  const network = event.metadata?.network;
  if (!rule || event.outcome !== 'allow' || !recorded(event) || typeof network !== 'string') return;
  const platform = event.metadata?.platform === true;
  const actor = await actorOf(run, event.actorId);
  run.add({
    ruleId: 'guardrail-weakened',
    severity: rule.severity,
    title: titled('guardrail-weakened', 'network block lifted'),
    summary: `${actor.label} lifted the ${platform ? 'platform-wide ' : ''}block on ${clean(network)}.`,
    subject: { type: 'tenant', id: run.input.tenantId },
    ...(actor.identityId ? { identityId: actor.identityId } : {}),
    dedupeKey: dedupeKey('guardrail-weakened', event.id),
    occurredAt: event.timestamp,
    evidence: evidenceOf(run, [event], { actions: true }),
    metadata: { change: 'network-unblock', network, platform, blockId: event.resourceId },
  });
}

/** token-replay: a web identity token refused as already used (`role:assumed-with-web-identity`, reason `replay`). */
async function tokenReplayed(run: Run, event: AuditEvent): Promise<void> {
  const rule = tuned(run.input.settings, 'token-replay');
  const metadata = event.metadata ?? {};
  if (!rule || event.outcome !== 'deny' || metadata.reason !== 'replay') return;
  const who = await identitySubject(run, event.actorId);
  const details: Record<string, Json> = { roleId: event.resourceId };
  for (const name of ['trustId', 'providerId', 'issuer', 'subject']) {
    const value = metadata[name];
    if (typeof value === 'string') details[name] = value;
  }
  const external = typeof metadata.subject === 'string' ? clean(metadata.subject) : '';
  run.add({
    ruleId: 'token-replay',
    severity: rule.severity,
    title: titled('token-replay', who.label),
    summary: `A web identity token was presented a second time to assume role ${clean(event.resourceId)} as ${who.label}${external ? ` (token subject ${external})` : ''}.`,
    ...who.target,
    dedupeKey: dedupeKey('token-replay', event.id),
    occurredAt: event.timestamp,
    evidence: evidenceOf(run, [event]),
    metadata: details,
  });
}

/** invariant-broken: the invariant checker reported a newly broken invariant; enforced ones are at least high. */
async function invariantBroken(run: Run, event: AuditEvent): Promise<void> {
  const rule = tuned(run.input.settings, 'invariant-broken');
  const metadata = event.metadata ?? {};
  const name = metadata.name;
  if (!rule || event.actorId !== 'deployment-operator' || typeof name !== 'string') return;
  const mode = metadata.mode === 'enforce' ? 'enforce' : 'monitor';
  const violations = Array.isArray(metadata.violations)
    ? metadata.violations.filter((value): value is string => typeof value === 'string')
    : [];
  const error = typeof metadata.error === 'string' ? metadata.error : undefined;
  const detail = violations.length
    ? ` for ${plural(violations.length, 'identity', 'identities')}`
    : error
      ? ` (${clean(error)})`
      : '';
  run.add({
    ruleId: 'invariant-broken',
    severity: mode === 'enforce' ? maxSeverity('high', rule.severity) : rule.severity,
    title: titled('invariant-broken', clean(name)),
    summary: `The ${mode === 'enforce' ? 'enforced' : 'monitored'} access invariant "${clean(name)}" stopped holding${detail}.`,
    subject: { type: 'tenant', id: run.input.tenantId },
    dedupeKey: dedupeKey('invariant-broken', event.id),
    occurredAt: event.timestamp,
    evidence: evidenceOf(run, [event], { identityIds: violations }),
    metadata: {
      name,
      mode,
      invariantId: event.resourceId,
      violations: violations.slice(0, evidenceLimit),
      ...(error ? { error } : {}),
    },
  });
}

/** Severity of an upstream Shared Signals event about a person; undefined for events that raise nothing. */
function upstreamSeverity(eventType: string, currentLevel: unknown): ThreatSeverity | undefined {
  switch (eventType) {
    case 'credential-compromise':
      return 'high';
    case 'account-disabled':
    case 'account-purged':
    case 'account-credential-change-required':
      return 'medium';
    case 'credential-change':
      return 'low';
    case 'risk-level-change':
      return currentLevel === 'HIGH' ? 'high' : currentLevel === 'MEDIUM' ? 'medium' : undefined;
    default:
      return undefined;
  }
}

/**
 * upstream-signal: the Shared Signals receiver (signal-receiver.ts) matched an upstream provider's event to a person of
 * this tenant (`signal:received`, actor `signal:{sourceId}`). Session revocations and low risk raise nothing; what the
 * event reports sets the severity.
 */
async function upstreamSignal(run: Run, event: AuditEvent): Promise<void> {
  const rule = tuned(run.input.settings, 'upstream-signal');
  const metadata = event.metadata ?? {};
  const { sourceId, eventType, identityId, jti } = metadata;
  if (
    !rule ||
    event.outcome !== 'allow' ||
    !recorded(event) ||
    typeof sourceId !== 'string' ||
    event.actorId !== `signal:${sourceId}` ||
    typeof eventType !== 'string' ||
    typeof identityId !== 'string'
  )
    return;
  const severity = upstreamSeverity(eventType, metadata.currentLevel);
  if (!severity) return;
  const who = await identitySubject(run, identityId);
  const reason = typeof metadata.reasonAdmin === 'string' ? clean(metadata.reasonAdmin) : '';
  const details: Record<string, Json> = { sourceId, eventType };
  if (typeof jti === 'string') details.jti = jti;
  for (const name of ['currentLevel', 'credentialType'] as const) {
    const value = metadata[name];
    if (typeof value === 'string') details[name] = value;
  }
  run.add({
    ruleId: 'upstream-signal',
    severity,
    title: titled('upstream-signal', who.label),
    summary: `An upstream identity provider reported ${eventType.replace(/-/g, ' ')} for ${who.label}${reason ? `: ${reason}` : ''}.`,
    ...who.target,
    dedupeKey: dedupeKey('upstream-signal', event.id),
    occurredAt: event.timestamp,
    evidence: evidenceOf(run, [event]),
    metadata: details,
  });
}

// ---------------------------------------------------------------------------------------------------------------
// Counting rules

/** What a counting rule counts: the key it counts per and, for distinct counts, the value that must differ. */
interface Counter {
  key(event: AuditEvent): string | undefined;
  /** Count distinct values (password spray: accounts) instead of events. */
  distinct?(event: AuditEvent): string | undefined;
}

/** A qualifying burst of one key that this run's events are part of. */
interface Burst {
  key: string;
  /** The burst's dedupe anchor (`burstAnchor`). */
  anchor: number;
  /** Events from the start of the first qualifying window to the last qualifying new event, oldest first. */
  events: AuditEvent[];
  /** The highest count (or distinct count) one window reached. */
  peak: number;
  lastAt: number;
}

/**
 * Slides each key's window over history and new events (two pointers over the key's time-ordered events, so linear
 * after the one sort) and reports the windows that end at a new event and reach the threshold, grouped by anchor.
 */
function findBursts(
  ordered: readonly AuditEvent[],
  fresh: ReadonlySet<string>,
  historyFrom: number | undefined,
  window: { threshold: number; windowMs: number },
  counter: Counter,
): Burst[] {
  const byKey = new Map<string, AuditEvent[]>();
  for (const event of ordered) {
    const key = counter.key(event);
    if (key !== undefined) append(byKey, key, event);
  }
  const bursts: Burst[] = [];
  const distinct = counter.distinct;
  for (const [key, list] of byKey) {
    if (!list.some((event) => fresh.has(event.id))) continue;
    const values = new Map<string, number>();
    const count = (event: AuditEvent, delta: number) => {
      const value = distinct?.(event);
      if (value === undefined) return;
      const next = (values.get(value) ?? 0) + delta;
      if (next > 0) values.set(value, next);
      else values.delete(value);
    };
    const qualifying = new Map<number, { from: number; to: number; peak: number }>();
    let start = 0;
    let clusterStart = 0;
    for (let index = 0; index < list.length; index++) {
      const event = list[index]!;
      if (index > 0 && event.timestamp - list[index - 1]!.timestamp > window.windowMs)
        clusterStart = index;
      count(event, 1);
      while (list[start]!.timestamp < event.timestamp - window.windowMs) count(list[start++]!, -1);
      if (!fresh.has(event.id)) continue;
      const size = distinct ? values.size : index - start + 1;
      if (size < window.threshold) continue;
      // With the lookback cut short, a cluster whose first loaded event lies within a window of the cut may have begun
      // before it: its start is unknown, and the start of the day stands in, as it will for every later run.
      const cut =
        clusterStart === 0 &&
        historyFrom !== undefined &&
        list[0]!.timestamp - historyFrom <= window.windowMs;
      const anchor = burstAnchor(
        cut ? Number.NEGATIVE_INFINITY : list[clusterStart]!.timestamp,
        event.timestamp,
        window.windowMs,
      );
      const burst = qualifying.get(anchor);
      if (burst) {
        burst.to = index;
        burst.peak = Math.max(burst.peak, size);
      } else qualifying.set(anchor, { from: start, to: index, peak: size });
    }
    for (const [anchor, burst] of qualifying)
      bursts.push({
        key,
        anchor,
        events: list.slice(burst.from, burst.to + 1),
        peak: burst.peak,
        lastAt: list[burst.to]!.timestamp,
      });
  }
  return bursts;
}

function burstMetadata(
  window: { threshold: number; windowMs: number },
  burst: Burst,
  extra: Record<string, Json> = {},
): Record<string, Json> {
  return { peak: burst.peak, threshold: window.threshold, windowMs: window.windowMs, ...extra };
}

async function evaluateCounting(
  run: Run,
  ordered: readonly AuditEvent[],
  fresh: ReadonlySet<string>,
): Promise<void> {
  const { settings, historyFrom } = run.input;

  const spray = tuned(settings, 'password-spray');
  if (spray)
    for (const burst of findBursts(ordered, fresh, historyFrom, spray, {
      key: (event) =>
        signInFailure(event, 'password')
          ? reportableKey(run, clientNetwork(event.metadata?.ip))
          : undefined,
      distinct: (event) => event.actorId,
    })) {
      const accounts = distinctValues(burst.events.map((event) => event.actorId));
      run.add({
        ruleId: 'password-spray',
        severity: spray.severity,
        title: `Password spray from ${burst.key}`,
        summary: `${plural(burst.peak, 'account')} failed password sign-in from ${burst.key} within ${inWords(spray.windowMs)} (${plural(burst.events.length, 'attempt')} in all).`,
        subject: { type: 'network', id: burst.key },
        network: burst.key,
        dedupeKey: dedupeKey('password-spray', burst.key, burst.anchor),
        occurredAt: burst.lastAt,
        evidence: evidenceOf(run, burst.events, { identityIds: accounts }),
        metadata: burstMetadata(spray, burst, { accounts: accounts.length }),
      });
    }

  for (const [ruleId, reason] of [
    ['brute-force', 'password'],
    ['mfa-bombardment', 'mfa'],
  ] as const) {
    const rule = tuned(settings, ruleId);
    if (!rule) continue;
    for (const burst of findBursts(ordered, fresh, historyFrom, rule, {
      key: (event) => (signInFailure(event, reason) ? event.actorId : undefined),
    })) {
      const who = await identitySubject(run, burst.key);
      const networks = reportableNetworks(run, burst.events);
      const where =
        networks.length === 1
          ? ` from ${networks[0]}`
          : networks.length > 1
            ? ` from ${plural(networks.length, 'network')}`
            : '';
      run.add({
        ruleId,
        severity: rule.severity,
        title: titled(ruleId, who.label),
        summary:
          ruleId === 'brute-force'
            ? `${who.label} had ${plural(burst.peak, 'failed password sign-in')} within ${inWords(rule.windowMs)}${where}.`
            : `${who.label} had ${plural(burst.peak, 'wrong second-factor code')} entered within ${inWords(rule.windowMs)}${where}, so someone else likely knows the password.`,
        ...who.target,
        ...(networks.length === 1 ? { network: networks[0] } : {}),
        dedupeKey: dedupeKey(ruleId, burst.key, burst.anchor),
        occurredAt: burst.lastAt,
        evidence: evidenceOf(run, burst.events),
        metadata: burstMetadata(rule, burst, { networks: networks.length }),
      });
    }
  }

  const deletion = tuned(settings, 'mass-deletion');
  if (deletion)
    for (const burst of findBursts(ordered, fresh, historyFrom, deletion, {
      key: (event) =>
        deletionActions.has(event.action) &&
        event.outcome === 'allow' &&
        identityActor(responsibleActor(event)) &&
        (event.action.startsWith('iam:') || recorded(event))
          ? responsibleActor(event)
          : undefined,
    })) {
      const who = await identitySubject(run, burst.key);
      const identities = distinctValues(
        burst.events
          .filter((event) => event.action.startsWith('identity:'))
          .map((event) => event.resourceId),
      );
      const viewed = viewing(burst.events);
      run.add({
        ruleId: 'mass-deletion',
        severity: deletion.severity,
        title: titled('mass-deletion', who.label),
        summary: `${who.label} deleted or revoked ${plural(burst.peak, 'item')} within ${inWords(deletion.windowMs)}${viewed.clause}.`,
        ...who.target,
        dedupeKey: dedupeKey('mass-deletion', burst.key, burst.anchor),
        occurredAt: burst.lastAt,
        evidence: evidenceOf(run, burst.events, { identityIds: identities, actions: true }),
        metadata: burstMetadata(deletion, burst, {
          identities: identities.length,
          ...viewed.metadata,
        }),
      });
    }

  const directory = tuned(settings, 'directory-mass-change');
  if (directory)
    for (const burst of findBursts(ordered, fresh, historyFrom, directory, {
      key: (event) =>
        (event.action === 'iam:scim:UpdateUser' || event.action === 'iam:scim:DeleteUser') &&
        event.outcome === 'allow' &&
        event.actorId.startsWith('scim:')
          ? event.actorId
          : undefined,
    })) {
      const deletions = burst.events.filter(
        (event) => event.action === 'iam:scim:DeleteUser',
      ).length;
      const connection = clean(burst.key);
      run.add({
        ruleId: 'directory-mass-change',
        severity: directory.severity,
        title: titled('directory-mass-change', connection),
        summary: `SCIM connection ${connection.slice('scim:'.length)} updated or deleted people ${plural(burst.peak, 'time')} within ${inWords(directory.windowMs)}${deletions ? ` (${plural(deletions, 'deletion')} in all)` : ''}.`,
        subject: { type: 'connection', id: burst.key },
        dedupeKey: dedupeKey('directory-mass-change', burst.key, burst.anchor),
        occurredAt: burst.lastAt,
        evidence: evidenceOf(run, burst.events, { actions: true }),
        metadata: burstMetadata(directory, burst, { deletions }),
      });
    }

  const impersonation = tuned(settings, 'impersonation-burst');
  if (impersonation)
    for (const burst of findBursts(ordered, fresh, historyFrom, impersonation, {
      key: (event) =>
        event.action === 'identity:impersonate' &&
        event.outcome === 'allow' &&
        recorded(event) &&
        identityActor(event.actorId)
          ? event.actorId
          : undefined,
    })) {
      const who = await identitySubject(run, burst.key);
      const targets = distinctValues(burst.events.map((event) => event.resourceId));
      run.add({
        ruleId: 'impersonation-burst',
        severity: impersonation.severity,
        title: titled('impersonation-burst', who.label),
        summary: `${who.label} started ${plural(burst.peak, '"view as" session')} within ${inWords(impersonation.windowMs)}, as ${plural(targets.length, 'person', 'people')}.`,
        ...who.target,
        dedupeKey: dedupeKey('impersonation-burst', burst.key, burst.anchor),
        occurredAt: burst.lastAt,
        evidence: evidenceOf(run, burst.events, { identityIds: targets }),
        metadata: burstMetadata(impersonation, burst, { targets: targets.length }),
      });
    }

  const denial = tuned(settings, 'denial-burst');
  if (denial)
    for (const burst of findBursts(ordered, fresh, historyFrom, denial, {
      key: (event) =>
        event.outcome === 'deny' &&
        !unauthenticatedRefusals.has(event.action) &&
        identityActor(responsibleActor(event))
          ? responsibleActor(event)
          : undefined,
    })) {
      const who = await identitySubject(run, burst.key);
      const actions = distinctValues(burst.events.map((event) => event.action));
      const agentId = burst.events.find((event) => event.sessionContext?.agentId)?.sessionContext
        ?.agentId;
      const agent = who.identity?.kind === 'agent' || agentId !== undefined;
      const through =
        who.identity?.kind === 'agent'
          ? ' (an AI agent)'
          : agentId !== undefined
            ? ', acting through an AI agent,'
            : '';
      const viewed = viewing(burst.events);
      run.add({
        ruleId: 'denial-burst',
        severity: denial.severity,
        title: titled('denial-burst', who.label),
        summary: `${who.label}${through} was denied ${plural(burst.peak, 'time')} within ${inWords(denial.windowMs)}, across ${plural(actions.length, 'action')}${viewed.clause}.`,
        ...who.target,
        dedupeKey: dedupeKey('denial-burst', burst.key, burst.anchor),
        occurredAt: burst.lastAt,
        evidence: evidenceOf(run, burst.events, { actions: true }),
        metadata: burstMetadata(denial, burst, {
          agent,
          ...(agentId !== undefined ? { agentId } : {}),
          ...viewed.metadata,
        }),
      });
    }

  const recon = tuned(settings, 'recon-burst');
  if (recon) {
    const reads = findBursts(ordered, fresh, historyFrom, recon, {
      key: (event) =>
        event.outcome === 'allow' &&
        event.action.startsWith('iam:') &&
        event.action.endsWith(':read') &&
        event.action !== 'iam:threats:read' &&
        identityActor(responsibleActor(event))
          ? responsibleActor(event)
          : undefined,
    });
    for (const burst of reads) {
      const who = await identitySubject(run, burst.key);
      const viewed = viewing(burst.events);
      run.add({
        ruleId: 'recon-burst',
        severity: recon.severity,
        title: titled('recon-burst', who.label),
        summary: `${who.label} made ${plural(burst.peak, 'administrative read')} within ${inWords(recon.windowMs)}${viewed.clause}.`,
        ...who.target,
        dedupeKey: dedupeKey('recon-burst', burst.key, 'reads', burst.anchor),
        occurredAt: burst.lastAt,
        evidence: evidenceOf(run, burst.events, { actions: true }),
        metadata: burstMetadata(recon, burst, { kind: 'reads', ...viewed.metadata }),
      });
    }
    const exportWindow = {
      threshold: Math.max(3, Math.floor(recon.threshold / 50)),
      windowMs: recon.windowMs,
    };
    const exports = findBursts(ordered, fresh, historyFrom, exportWindow, {
      key: (event) =>
        event.action === 'identity:export' &&
        event.outcome === 'allow' &&
        recorded(event) &&
        identityActor(responsibleActor(event))
          ? responsibleActor(event)
          : undefined,
    });
    for (const burst of exports) {
      const who = await identitySubject(run, burst.key);
      const exported = distinctValues(burst.events.map((event) => event.resourceId));
      const viewed = viewing(burst.events);
      run.add({
        ruleId: 'recon-burst',
        severity: recon.severity,
        title: titled('recon-burst', who.label),
        summary: `${who.label} exported ${plural(burst.peak, 'identity', 'identities')} within ${inWords(recon.windowMs)}${viewed.clause}.`,
        ...who.target,
        dedupeKey: dedupeKey('recon-burst', burst.key, 'exports', burst.anchor),
        occurredAt: burst.lastAt,
        evidence: evidenceOf(run, burst.events, { identityIds: exported, actions: true }),
        metadata: burstMetadata(exportWindow, burst, {
          kind: 'exports',
          exported: exported.length,
          ...viewed.metadata,
        }),
      });
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Candidates

interface Named {
  identity: Identity | undefined;
  label: string;
  /** The subject and, for an identity of this tenant, the identity whose risk the detection raises. */
  target: { subject: ThreatSubject; identityId?: string };
}

/**
 * An identity as a detection subject. Only identities of this tenant carry `identityId` (risk is kept in the
 * identity's own tenant); an actor from another tenant or one since deleted is still the subject.
 */
async function identitySubject(run: Run, identityId: string): Promise<Named> {
  const identity = await run.identity(identityId);
  const label = identityLabel(identity, identityId);
  return {
    identity,
    label,
    target: identity
      ? { subject: { type: 'identity', id: identityId, name: label }, identityId }
      : { subject: { type: 'identity', id: identityId } },
  };
}

/** The actor of a tenant-level change: its name, and `identityId` when it is an identity of this tenant. */
async function actorOf(run: Run, actorId: string): Promise<{ label: string; identityId?: string }> {
  const identity = identityActor(actorId) ? await run.identity(actorId) : undefined;
  return identity
    ? { label: identityLabel(identity, actorId), identityId: identity.id }
    : { label: clean(actorId) };
}

/** How summaries name an identity: name and email where it has both; its id when it is unknown. */
function identityLabel(identity: Identity | undefined, identityId: string): string {
  if (!identity) return clean(identityId);
  const name = clean(identity.name ?? '').trim();
  const email = identity.email ? clean(identity.email) : '';
  if (name && email && name !== email) return `${name} (${email})`;
  return email || name || clean(identity.id);
}

/** `{ network }` for a reportable (untrusted) client network, otherwise nothing. */
function reportedNetwork(run: Run, network: ClientNetwork | undefined): { network?: string } {
  const key = reportableKey(run, network);
  return key === undefined ? {} : { network: key };
}

/** Evidence for the events (oldest first): the last 20 ids, counts, span, and the networks the events came from. */
function evidenceOf(
  run: Run,
  events: readonly AuditEvent[],
  extra: {
    identityIds?: readonly string[];
    networks?: readonly (string | undefined)[];
    actions?: boolean;
  } = {},
): ThreatEvidence {
  let firstAt = Number.POSITIVE_INFINITY;
  let lastAt = Number.NEGATIVE_INFINITY;
  for (const event of events) {
    firstAt = Math.min(firstAt, event.timestamp);
    lastAt = Math.max(lastAt, event.timestamp);
  }
  const networks = limited([...reportableNetworks(run, events), ...(extra.networks ?? [])]);
  const identityIds = limited(extra.identityIds ?? []);
  const actions = extra.actions ? limited(events.map((event) => event.action)) : [];
  return {
    eventIds: events.slice(-evidenceLimit).map((event) => event.id),
    count: events.length,
    firstAt,
    lastAt,
    ...(networks.length ? { networks } : {}),
    ...(identityIds.length ? { identityIds } : {}),
    ...(actions.length ? { actions } : {}),
  };
}

/** Folds another firing of a unique key already found in this run into the first one. */
function merge(into: DetectionCandidate, other: DetectionCandidate): void {
  const a = into.evidence;
  const b = other.evidence;
  const networks = limited([...(a.networks ?? []), ...(b.networks ?? [])]);
  const identityIds = limited([...(a.identityIds ?? []), ...(b.identityIds ?? [])]);
  const actions = limited([...(a.actions ?? []), ...(b.actions ?? [])]);
  into.evidence = {
    eventIds: [...new Set([...a.eventIds, ...b.eventIds])].slice(-evidenceLimit),
    count: a.count + b.count,
    firstAt: Math.min(a.firstAt, b.firstAt),
    lastAt: Math.max(a.lastAt, b.lastAt),
    ...(networks.length ? { networks } : {}),
    ...(identityIds.length ? { identityIds } : {}),
    ...(actions.length ? { actions } : {}),
  };
  into.occurredAt = Math.max(into.occurredAt, other.occurredAt);
}

/** Distinct defined values in first-seen order. */
function distinctValues(values: Iterable<string | undefined>): string[] {
  const result = new Set<string>();
  for (const value of values) if (value !== undefined) result.add(value);
  return [...result];
}

/** Distinct defined values in first-seen order, at most `evidenceLimit`. */
function limited(values: Iterable<string | undefined>): string[] {
  const result = new Set<string>();
  for (const value of values) {
    if (value === undefined) continue;
    result.add(value);
    if (result.size === evidenceLimit) break;
  }
  return [...result];
}

/** `{part}:{part}...` without control characters, short enough for `{ruleId}:{dedupeKey}` to fit a unique key. */
function dedupeKey(ruleId: ThreatRuleId, ...parts: (string | number)[]): string {
  return clean(parts.join(':')).slice(0, uniqueKeyLimit - ruleId.length - 1);
}

/** Drops control characters (C0, DEL, C1) from text that reaches keys and summaries. */
function clean(value: string): string {
  let result = '';
  for (const char of value) {
    const code = char.codePointAt(0)!;
    if (code >= 32 && (code < 127 || code > 159)) result += char;
  }
  return result;
}

const lowerSeverity: Record<ThreatSeverity, ThreatSeverity> = {
  critical: 'high',
  high: 'medium',
  medium: 'low',
  low: 'low',
};

function startOfDay(at: number): number {
  return Math.floor(at / day) * day;
}

/** A rule's title, followed by what the detection is about when that has a name. */
function titled(ruleId: ThreatRuleId, name?: string): string {
  const title = threatRule(ruleId).title;
  return name ? `${title}: ${name}` : title;
}

function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

/** "a", "a and b", "a, b and c". */
function series(items: readonly string[]): string {
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

/** A window length in words, in the largest whole unit that divides it: "15 minutes", "1 hour", "7 days". */
function inWords(ms: number): string {
  if (ms % day === 0) return plural(ms / day, 'day');
  if (ms % hour === 0) return plural(ms / hour, 'hour');
  if (ms % minute === 0) return plural(ms / minute, 'minute');
  return about(ms);
}

/** An elapsed time in words, rounded to the largest unit it reaches. */
function about(ms: number): string {
  if (ms >= day) return plural(Math.round(ms / day), 'day');
  if (ms >= hour) return plural(Math.round(ms / hour), 'hour');
  return plural(Math.max(1, Math.round(ms / minute)), 'minute');
}
