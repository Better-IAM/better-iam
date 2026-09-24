import type {
  AuthenticatedPrincipal,
  IamStore,
  Json,
  PolicyDocument,
  StoredRecord,
} from '@better-iam/core';

/**
 * Identity threat detection and response (ITDR): detection rules read the audit trail each tenant already keeps
 * (sign-ins, failures, session mismatches, administrative changes, directory pushes), raise detections, group them
 * into incidents per subject, keep a decaying risk score per identity (exposed to policies as principal.riskLevel /
 * principal.riskScore), and run response playbooks. The engine (`threat-engine.ts`) is a scheduled job,
 * `iam.detectThreats()`, that reads each tenant's audit chain from a cursor, so it also sees events the protocol
 * packages write without fan-out, verifies the chain as it goes, and never slows a sign-in.
 */

/** Storage collections of the threats module; every one is tenant-scoped (lifecycle.ts tenantCollections). */
export const threatCollections = {
  detections: 'threatDetections',
  incidents: 'threatIncidents',
  notes: 'threatNotes',
  risk: 'identityRisk',
  baselines: 'threatBaselines',
  cursors: 'threatCursors',
  settings: 'threatSettings',
  playbooks: 'threatPlaybooks',
  responses: 'threatResponses',
} as const;

/** The actor recorded on audit events the detection engine and automatic playbooks write. */
export const threatActor = 'threat-detection';

export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';
export const threatSeverities: readonly ThreatSeverity[] = ['low', 'medium', 'high', 'critical'];
/** A risk level derived from an identity's score; `none` below the `low` threshold. */
export type RiskLevel = 'none' | 'low' | 'medium' | 'high';
export const riskLevels: readonly RiskLevel[] = ['none', 'low', 'medium', 'high'];

export type ThreatRuleId =
  | 'password-spray'
  | 'brute-force'
  | 'brute-force-success'
  | 'mfa-bombardment'
  | 'session-hijack'
  | 'new-network'
  | 'dormant-reactivated'
  | 'account-takeover-persistence'
  | 'privilege-escalation'
  | 'root-admin-granted'
  | 'mass-deletion'
  | 'directory-mass-change'
  | 'impersonation-burst'
  | 'denial-burst'
  | 'recon-burst'
  | 'guardrail-weakened'
  | 'token-replay'
  | 'audit-tampering'
  | 'invariant-broken'
  | 'user-reported'
  | 'upstream-signal';

/** What a detection is about: a person or machine identity, a client network, the tenant itself, or a directory connection. */
export type ThreatSubjectType = 'identity' | 'network' | 'tenant' | 'connection';
export interface ThreatSubject {
  type: ThreatSubjectType;
  /** Identity id, network key (`ipCounterKey` form: an IPv4 address or an IPv6 /64), tenant id, or `scim:{connectionId}`. */
  id: string;
  name?: string;
}

export type ThreatRuleCategory = 'sign-in' | 'account' | 'privilege' | 'activity' | 'integrity';

/** A built-in detection rule; tenants tune it with `threats.configure` (`ThreatRuleSetting`). */
export interface ThreatRuleDefinition {
  id: ThreatRuleId;
  title: string;
  description: string;
  category: ThreatRuleCategory;
  severity: ThreatSeverity;
  subject: ThreatSubjectType;
  /** Default count that trips the rule, when the rule counts. */
  threshold?: number;
  /** Default sliding window, when the rule counts or correlates over time. */
  windowMs?: number;
  /** Bounds `threats.configure` enforces on a tenant's `threshold` / `windowMs`. */
  tunable?: { threshold?: [min: number, max: number]; windowMs?: [min: number, max: number] };
  enabledByDefault: boolean;
  /** MITRE ATT&CK technique the rule maps to. */
  technique: string;
}

const minute = 60_000;
const hour = 60 * minute;
const day = 24 * hour;

/** The rule catalog, in display order. */
export const threatRules: readonly ThreatRuleDefinition[] = [
  {
    id: 'password-spray',
    title: 'Password spray',
    description:
      'One network fails password sign-ins for many different people in a short window: someone is trying common passwords across accounts.',
    category: 'sign-in',
    severity: 'high',
    subject: 'network',
    threshold: 10,
    windowMs: 15 * minute,
    tunable: { threshold: [3, 1000], windowMs: [minute, day] },
    enabledByDefault: true,
    technique: 'T1110.003',
  },
  {
    id: 'brute-force',
    title: 'Password guessing',
    description: 'Many failed password sign-ins for one person in a short window.',
    category: 'sign-in',
    severity: 'medium',
    subject: 'identity',
    threshold: 10,
    windowMs: 15 * minute,
    tunable: { threshold: [3, 1000], windowMs: [minute, day] },
    enabledByDefault: true,
    technique: 'T1110.001',
  },
  {
    id: 'brute-force-success',
    title: 'Sign-in after repeated failures',
    description:
      'A person signed in right after a run of failed attempts; high when the success came from a network that was failing.',
    category: 'sign-in',
    severity: 'high',
    subject: 'identity',
    threshold: 5,
    windowMs: 30 * minute,
    tunable: { threshold: [2, 1000], windowMs: [minute, day] },
    enabledByDefault: true,
    technique: 'T1110',
  },
  {
    id: 'mfa-bombardment',
    title: 'Second-factor guessing',
    description:
      'Repeated wrong second-factor codes for one person: the password was right, so someone else probably knows it.',
    category: 'sign-in',
    severity: 'high',
    subject: 'identity',
    threshold: 5,
    windowMs: 15 * minute,
    tunable: { threshold: [2, 1000], windowMs: [minute, day] },
    enabledByDefault: true,
    technique: 'T1621',
  },
  {
    id: 'session-hijack',
    title: 'Session used from another network',
    description:
      'A session bound to one network was presented from another (tenant policy bindSessionsToIp): a stolen cookie or token.',
    category: 'sign-in',
    severity: 'high',
    subject: 'identity',
    enabledByDefault: true,
    technique: 'T1550.004',
  },
  {
    id: 'new-network',
    title: 'Sign-in from a new network',
    description:
      'A privileged person (owner, root administrator, or holder of an administrator role) signed in from a network not seen for them before.',
    category: 'sign-in',
    severity: 'medium',
    subject: 'identity',
    enabledByDefault: true,
    technique: 'T1078',
  },
  {
    id: 'dormant-reactivated',
    title: 'Dormant account signed in',
    description:
      'Someone signed in to an account that had not been used for longer than the dormancy period.',
    category: 'account',
    severity: 'medium',
    subject: 'identity',
    enabledByDefault: true,
    technique: 'T1078',
  },
  {
    id: 'account-takeover-persistence',
    title: 'Account changes after a risky sign-in',
    description:
      'Shortly after a risky sign-in the account changed its sign-in methods (second factor removed, passkey or trusted device added, email or password changed, API key created).',
    category: 'account',
    severity: 'high',
    subject: 'identity',
    windowMs: hour,
    tunable: { windowMs: [5 * minute, 7 * day] },
    enabledByDefault: true,
    technique: 'T1098',
  },
  {
    id: 'privilege-escalation',
    title: 'Self-granted administrator role',
    description: 'Someone granted an administrator role and now holds it themselves.',
    category: 'privilege',
    severity: 'high',
    subject: 'identity',
    enabledByDefault: true,
    technique: 'T1098.003',
  },
  {
    id: 'root-admin-granted',
    title: 'Root administrator granted',
    description: 'A person was made a root administrator of the deployment.',
    category: 'privilege',
    severity: 'high',
    subject: 'identity',
    enabledByDefault: true,
    technique: 'T1098',
  },
  {
    id: 'mass-deletion',
    title: 'Mass deletion',
    description:
      'One actor deleted or revoked many identities, roles, policies, groups, bindings, keys, or trusts in a short window.',
    category: 'activity',
    severity: 'high',
    subject: 'identity',
    threshold: 20,
    windowMs: 10 * minute,
    tunable: { threshold: [3, 10_000], windowMs: [minute, day] },
    enabledByDefault: true,
    technique: 'T1531',
  },
  {
    id: 'directory-mass-change',
    title: 'Directory mass change',
    description: 'A SCIM connection updated or deleted many people in a short window.',
    category: 'activity',
    severity: 'medium',
    subject: 'connection',
    threshold: 25,
    windowMs: 10 * minute,
    tunable: { threshold: [3, 100_000], windowMs: [minute, day] },
    enabledByDefault: true,
    technique: 'T1531',
  },
  {
    id: 'impersonation-burst',
    title: 'Repeated impersonation',
    description: 'One administrator started many "view as" sessions in a day.',
    category: 'activity',
    severity: 'medium',
    subject: 'identity',
    threshold: 5,
    windowMs: day,
    tunable: { threshold: [2, 1000], windowMs: [hour, 7 * day] },
    enabledByDefault: true,
    technique: 'T1078',
  },
  {
    id: 'denial-burst',
    title: 'Burst of denied requests',
    description:
      'One actor was denied many times in a few minutes: probing for access it does not have (agents included).',
    category: 'activity',
    severity: 'medium',
    subject: 'identity',
    threshold: 30,
    windowMs: 10 * minute,
    tunable: { threshold: [5, 100_000], windowMs: [minute, day] },
    enabledByDefault: true,
    technique: 'T1069',
  },
  {
    id: 'recon-burst',
    title: 'Directory enumeration',
    description:
      'One actor read identities, bindings, credentials, or the audit trail far more than usual in a short window, or exported many people.',
    category: 'activity',
    severity: 'low',
    subject: 'identity',
    threshold: 300,
    windowMs: 10 * minute,
    tunable: { threshold: [20, 1_000_000], windowMs: [minute, day] },
    enabledByDefault: true,
    technique: 'T1087',
  },
  {
    id: 'guardrail-weakened',
    title: 'Security settings weakened',
    description:
      'The tenant sign-in policy dropped a protection (MFA requirement, IP allowlist, session binding), a network block was lifted, or threat detection was turned off or weakened (a rule, the risk half-life, trusted networks, the containment brake).',
    category: 'integrity',
    severity: 'medium',
    subject: 'tenant',
    enabledByDefault: true,
    technique: 'T1562',
  },
  {
    id: 'token-replay',
    title: 'Token replay',
    description: 'A web identity token was presented a second time to assume a role.',
    category: 'sign-in',
    severity: 'high',
    subject: 'identity',
    enabledByDefault: true,
    technique: 'T1550',
  },
  {
    id: 'audit-tampering',
    title: 'Audit trail tampering',
    description:
      'The tenant audit hash chain no longer verifies: an event was changed, removed, or inserted outside the recorder.',
    category: 'integrity',
    severity: 'critical',
    subject: 'tenant',
    enabledByDefault: true,
    technique: 'T1070',
  },
  {
    id: 'invariant-broken',
    title: 'Access invariant broken',
    description: 'A monitored access invariant stopped holding (invariant:broken).',
    category: 'integrity',
    severity: 'medium',
    subject: 'tenant',
    enabledByDefault: true,
    technique: 'T1098',
  },
  {
    id: 'user-reported',
    title: 'Reported by the account holder',
    description:
      'The person said a sign-in or change on their account was not them (threats.reportSuspicious).',
    category: 'account',
    severity: 'high',
    subject: 'identity',
    enabledByDefault: true,
    technique: 'T1078',
  },
  {
    id: 'upstream-signal',
    title: 'Reported by an upstream identity provider',
    description:
      'An upstream identity provider reported a compromised credential, a disabled or purged account, a required credential change, or medium or high risk for a person (Shared Signals). The severity follows the event: high for credential compromise and high risk, medium for disabled accounts and medium risk, low for credential changes.',
    category: 'account',
    severity: 'high',
    subject: 'identity',
    enabledByDefault: true,
    technique: 'T1078',
  },
];

export const threatRuleIds: ReadonlySet<ThreatRuleId> = new Set(threatRules.map((rule) => rule.id));
export function threatRule(id: ThreatRuleId): ThreatRuleDefinition {
  const rule = threatRules.find((candidate) => candidate.id === id);
  if (!rule) throw new Error(`Unknown threat rule ${id}`);
  return rule;
}

/** A tenant's adjustment of one rule; unset fields keep the rule's defaults. */
export interface ThreatRuleSetting {
  enabled?: boolean;
  threshold?: number;
  windowMs?: number;
  severity?: ThreatSeverity;
  /** `new-network` only: report non-privileged people too (at low severity). */
  everyone?: boolean;
}

/** Per-tenant settings, one record per tenant (`id` = tenant id), written by `threats.configure`. */
export interface ThreatSettings extends StoredRecord {
  rules: Partial<Record<ThreatRuleId, ThreatRuleSetting>>;
  /** Networks (IP or CIDR) that network rules never report and responses never block: offices, VPN egress. */
  trustedNetworks: string[];
  /** Days without a sign-in after which an account counts as dormant (`dormant-reactivated`); default 90. */
  dormantDays: number;
  /** Risk contributions halve every this many hours; default 24. */
  riskHalfLifeHours: number;
  /** Who is emailed when a playbook's `notify` action runs: active owners and/or listed addresses. */
  notify: { owners: boolean; emails: string[] };
  /** Largest number of identities automatic playbooks may contain in one run before braking (default 3). */
  maxAutomaticContainments: number;
  updatedAt: number;
  updatedBy: string;
}

/** Settings with every default applied, as the engine and the API use them. */
export interface ResolvedThreatSettings {
  rules: Record<
    ThreatRuleId,
    Required<Pick<ThreatRuleSetting, 'enabled' | 'severity'>> & ThreatRuleSetting
  >;
  trustedNetworks: string[];
  dormantDays: number;
  riskHalfLifeHours: number;
  notify: { owners: boolean; emails: string[] };
  maxAutomaticContainments: number;
}

export const defaultThreatSettings = {
  dormantDays: 90,
  riskHalfLifeHours: 24,
  maxAutomaticContainments: 3,
} as const;

/** Applies rule defaults and deployment defaults to a tenant's stored settings (absent when never configured). */
export function resolveThreatSettings(stored?: ThreatSettings): ResolvedThreatSettings {
  const rules = {} as ResolvedThreatSettings['rules'];
  for (const rule of threatRules) {
    const own = stored?.rules[rule.id] ?? {};
    rules[rule.id] = {
      ...own,
      enabled: own.enabled ?? rule.enabledByDefault,
      severity: own.severity ?? rule.severity,
      ...(rule.threshold !== undefined ? { threshold: own.threshold ?? rule.threshold } : {}),
      ...(rule.windowMs !== undefined ? { windowMs: own.windowMs ?? rule.windowMs } : {}),
    };
  }
  return {
    rules,
    trustedNetworks: stored?.trustedNetworks ?? [],
    dormantDays: stored?.dormantDays ?? defaultThreatSettings.dormantDays,
    riskHalfLifeHours: stored?.riskHalfLifeHours ?? defaultThreatSettings.riskHalfLifeHours,
    notify: stored?.notify ?? { owners: false, emails: [] },
    maxAutomaticContainments:
      stored?.maxAutomaticContainments ?? defaultThreatSettings.maxAutomaticContainments,
  };
}

/** What a detection points at: up to 20 audit event ids plus counts, so a reviewer can open the underlying trail. */
export interface ThreatEvidence {
  eventIds: string[];
  count: number;
  firstAt: number;
  lastAt: number;
  /** Network keys involved (`ipCounterKey` form), at most 20. */
  networks?: string[];
  /** Identities involved (targets of a spray, subjects of a mass deletion), at most 20. */
  identityIds?: string[];
  /** Distinct audit actions involved, at most 20. */
  actions?: string[];
}

export type DetectionStatus = 'open' | 'dismissed' | 'resolved';

/**
 * One rule firing. `uniqueKey` is `{ruleId}:{dedupeKey}`, so re-reading the same events never raises a second
 * detection; rules choose a dedupe key per burst (window bucket) or per triggering event.
 */
export interface ThreatDetection extends StoredRecord {
  ruleId: ThreatRuleId;
  severity: ThreatSeverity;
  title: string;
  /** One sentence for lists and emails. */
  summary: string;
  subject: ThreatSubject;
  /** The identity whose risk this detection raises, when there is one (the subject, or the actor behind it). */
  identityId?: string;
  /** Network key (`ipCounterKey` form) the activity came from, when known. */
  network?: string;
  evidence: ThreatEvidence;
  metadata?: Record<string, Json>;
  status: DetectionStatus;
  incidentId?: string;
  /** When the triggering activity happened (the latest event's timestamp). */
  occurredAt: number;
  /** When the engine (or a report) recorded it. */
  detectedAt: number;
  dismissedBy?: string;
  dismissedAt?: number;
  dismissReason?: string;
}

export type IncidentStatus = 'open' | 'investigating' | 'resolved';
export type IncidentResolution = 'true-positive' | 'false-positive' | 'benign';

/**
 * Detections about one subject grouped for investigation. While open it holds `uniqueKey`
 * `open:{subject.type}:{subject.id}` (so one open incident per subject); resolving drops the key.
 */
export interface ThreatIncident extends StoredRecord {
  subject: ThreatSubject;
  /**
   * The identity the incident concerns, which responses to the incident act on. An incident about anything but an
   * identity (the tenant, a network, a connection) names one only while all its detections that name an identity name
   * the same one; once they differ it names none and `severalIdentities` is set.
   */
  identityId?: string;
  severalIdentities?: true;
  network?: string;
  severity: ThreatSeverity;
  title: string;
  status: IncidentStatus;
  /** Newest last, at most 200 (older ids stay findable through `threatDetections.incidentId`). */
  detectionIds: string[];
  detectionCount: number;
  ruleIds: ThreatRuleId[];
  firstDetectedAt: number;
  lastDetectedAt: number;
  createdAt: number;
  updatedAt: number;
  assigneeId?: string;
  resolution?: IncidentResolution;
  resolvedBy?: string;
  resolvedAt?: number;
}

/** A free-text investigation note on an incident (`threats.addNote`). */
export interface ThreatNote extends StoredRecord {
  incidentId: string;
  authorId: string;
  body: string;
  createdAt: number;
}

/** Points one detection adds to an identity's risk, decaying with the tenant's half-life. */
export interface RiskContribution {
  detectionId: string;
  ruleId: ThreatRuleId;
  severity: ThreatSeverity;
  points: number;
  at: number;
}

/** Risk points per detection severity. */
export const riskPoints: Record<ThreatSeverity, number> = {
  low: 10,
  medium: 25,
  high: 50,
  critical: 80,
};
/** Lowest score of each level. */
export const riskThresholds = { low: 10, medium: 40, high: 70 } as const;

/**
 * An identity's risk (`id` = identity id, stored in the identity's tenant). The score is recomputed from live
 * contributions whenever it is read, so it decays without a writer; `score`/`level` are the values as of `updatedAt`.
 */
export interface IdentityRisk extends StoredRecord {
  identityId: string;
  /** At most 50, newest last. */
  contributions: RiskContribution[];
  score: number;
  level: RiskLevel;
  /** An administrator's floor ("confirmed compromised"): the effective level is never below it until it expires. */
  override?: {
    level: Exclude<RiskLevel, 'none'>;
    reason: string;
    by: string;
    at: number;
    expiresAt?: number;
  };
  /** Set while the identity is contained by the threats module (`contain` response): who, when, why. */
  contained?: { at: number; by: string; reason: string; incidentId?: string };
  updatedAt: number;
}

/** Decayed score of the contributions at `now` (0-100). */
export function riskScore(
  contributions: readonly RiskContribution[],
  now: number,
  halfLifeHours: number,
): number {
  const halfLifeMs = Math.max(1, halfLifeHours) * hour;
  let total = 0;
  for (const contribution of contributions) {
    const age = Math.max(0, now - contribution.at);
    total += contribution.points * Math.pow(0.5, age / halfLifeMs);
  }
  return Math.min(100, Math.round(total));
}

export function riskLevelFor(score: number): RiskLevel {
  if (score >= riskThresholds.high) return 'high';
  if (score >= riskThresholds.medium) return 'medium';
  if (score >= riskThresholds.low) return 'low';
  return 'none';
}

const levelRank: Record<RiskLevel, number> = { none: 0, low: 1, medium: 2, high: 3 };
export function maxRiskLevel(a: RiskLevel, b: RiskLevel): RiskLevel {
  return levelRank[a] >= levelRank[b] ? a : b;
}
export function riskLevelAtLeast(level: RiskLevel, floor: RiskLevel): boolean {
  return levelRank[level] >= levelRank[floor];
}
const severityRank: Record<ThreatSeverity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
export function severityAtLeast(severity: ThreatSeverity, floor: ThreatSeverity): boolean {
  return severityRank[severity] >= severityRank[floor];
}
export function maxSeverity(a: ThreatSeverity, b: ThreatSeverity): ThreatSeverity {
  return severityRank[a] >= severityRank[b] ? a : b;
}

/** The score and level in force at `now`: decayed contributions, raised to an unexpired override's level. */
export function effectiveRisk(
  record: IdentityRisk | undefined,
  now: number,
  halfLifeHours: number,
): { score: number; level: RiskLevel } {
  if (!record) return { score: 0, level: 'none' };
  const score = riskScore(record.contributions, now, halfLifeHours);
  let level = riskLevelFor(score);
  const override = record.override;
  if (override && (override.expiresAt === undefined || override.expiresAt > now))
    level = maxRiskLevel(level, override.level);
  const floor = level === 'none' ? 0 : level === 'low' ? riskThresholds.low : riskThresholds[level];
  return { score: Math.max(score, floor), level };
}

/** Learned sign-in habits of one identity (`id` = identity id), used by the new-network and dormancy rules. */
export interface ThreatBaseline extends StoredRecord {
  identityId: string;
  /** Networks seen at successful sign-ins, most recent last, at most 25. */
  networks: { key: string; lastAt: number }[];
  /** User agents seen at successful sign-ins, most recent last, at most 10. */
  userAgents: { value: string; lastAt: number }[];
  lastSignInAt?: number;
  /** The last sign-in a sign-in rule flagged, opening the account-takeover-persistence window. */
  riskySignIn?: { at: number; detectionId: string; ruleId: ThreatRuleId };
  firstSeenAt: number;
  updatedAt: number;
}

/**
 * How far the engine has read a tenant's audit chain (`id` = tenant id): the last verified event's sequence and hash,
 * plus small state some rules compare against (the previous tenant sign-in policy).
 */
export interface ThreatCursor extends StoredRecord {
  sequence: number;
  hash?: string;
  /** The tenant sign-in policy as of the last `tenant:auth-policy` event read (for `guardrail-weakened`). */
  authPolicy?: Record<string, Json>;
  updatedAt: number;
}

/**
 * Response actions. `revoke-sessions` ends the identity's sessions (API keys kept unless `keepApiKeys: false`);
 * `forget-devices` removes remembered devices so the next sign-in needs the second factor again; `contain` disables
 * the identity (credentials kept but refused) until `threats.release`; `block-network` blocks the detection's
 * network for `durationMs` (default one day); `notify` emails the tenant's configured recipients.
 */
export type ResponseActionKind =
  | 'revoke-sessions'
  | 'forget-devices'
  | 'contain'
  | 'block-network'
  | 'notify';
export const responseActionKinds: readonly ResponseActionKind[] = [
  'revoke-sessions',
  'forget-devices',
  'contain',
  'block-network',
  'notify',
];
export interface ResponseAction {
  kind: ResponseActionKind;
  /** `block-network`: block length (one minute to 30 days; default one day). */
  durationMs?: number;
  /** `revoke-sessions`: keep API keys (default true). */
  keepApiKeys?: boolean;
}

/** An automatic response: when a new detection matches `trigger`, the actions run under the threat-detection actor. */
export interface ThreatPlaybook extends StoredRecord {
  name: string;
  description?: string;
  enabled: boolean;
  trigger: {
    ruleIds?: ThreatRuleId[];
    minSeverity?: ThreatSeverity;
    subjectTypes?: ThreatSubjectType[];
  };
  actions: ResponseAction[];
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
  lastRunAt?: number;
  runs: number;
}

/** One response action taken (automatically or by a person), kept for the incident timeline. */
export interface ThreatResponse extends StoredRecord {
  action: ResponseActionKind | 'release';
  subject: ThreatSubject;
  outcome: 'applied' | 'skipped';
  /** Why a response was skipped: `protected`, `no-network`, `trusted-network`, `already-applied`, `braked`, `no-recipients`, `not-identity`, ... */
  reason?: string;
  incidentId?: string;
  detectionId?: string;
  playbookId?: string;
  /** Identity id of the person who responded, or `threat-detection` for playbooks. */
  actorId: string;
  details?: Record<string, Json>;
  createdAt: number;
}

/** What one `iam.detectThreats()` run did. */
export interface ThreatDetectionRun {
  tenants: number;
  eventsScanned: number;
  detections: number;
  incidentsOpened: number;
  responses: number;
  /** Automatic containments held back by `maxAutomaticContainments`. */
  braked: number;
  /** Tenants whose audit chain failed verification in this run. */
  chainBreaks: number;
  /** Tenants with more unread events than one run reads (`maxEvents`); the next run continues. */
  pending: number;
}

/** The policy context keys this module fills (decisions.ts reads them lazily when a document mentions them). */
export const riskContextKeys = ['principal.riskLevel', 'principal.riskScore'] as const;

/** True when any statement of the documents refers to principal.riskLevel / principal.riskScore (conditions or variables). */
export function mentionsRisk(documents: readonly (PolicyDocument | undefined)[]): boolean {
  return documents.some(
    (document) =>
      document !== undefined && JSON.stringify(document.statements).includes('principal.risk'),
  );
}

/**
 * The risk keys for a decision. Simulated principals (invariants, impact previews, policy simulation, birthright
 * automation) always get `none`/0 so an incident never flips an invariant or stalls automation; a delegated session
 * takes the higher of the person's and the agent's risk.
 */
export async function riskContext(
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  now: number,
): Promise<{ 'principal.riskLevel': RiskLevel; 'principal.riskScore': number }> {
  if (principal.session.id === 'simulation')
    return { 'principal.riskLevel': 'none', 'principal.riskScore': 0 };
  const ids = [
    principal.identity.id,
    ...(principal.session.agentId ? [principal.session.agentId] : []),
  ];
  let level: RiskLevel = 'none';
  let score = 0;
  for (const identityId of ids) {
    const record = await tx.get<IdentityRisk>(threatCollections.risk, identityId);
    if (!record) continue;
    const settings = await tx.get<ThreatSettings>(threatCollections.settings, record.tenantId);
    const risk = effectiveRisk(
      record,
      now,
      settings?.riskHalfLifeHours ?? defaultThreatSettings.riskHalfLifeHours,
    );
    level = maxRiskLevel(level, risk.level);
    score = Math.max(score, risk.score);
  }
  return { 'principal.riskLevel': level, 'principal.riskScore': score };
}

/**
 * Ends the threats module's hold on an identity whose status another path changed (identities.setStatus and offboard,
 * service accounts, agents.suspend and resume, lifecycle workflows): the containment mark goes, so `threats.release`
 * never re-activates what that path disabled, and a later disable is not taken for a containment. The risk score
 * stays. Nothing happens for an identity that is not contained.
 */
export async function endContainment(tx: IamStore, identityId: string, now: number): Promise<void> {
  const record = await tx.get<IdentityRisk>(threatCollections.risk, identityId);
  if (!record?.contained) return;
  const { contained: _ended, ...rest } = record;
  await tx.put<IdentityRisk>(threatCollections.risk, { ...rest, updatedAt: now });
}
