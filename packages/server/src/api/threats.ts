import {
  IamError,
  findOrdered,
  ipCounterKey,
  isIpRange,
  type AuditEvent,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type Session,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { OperationDenied } from '../operations.js';
import { actsInOwnRight } from '../session-kinds.js';
import { detectThreats, recomputeRisk, recordDetection, runPlaybooks } from '../threat-engine.js';
import {
  afterThreatResponses,
  applyResponse,
  releaseIdentity,
  type ResponseRequest,
} from '../threat-response.js';
import type { DetectionCandidate } from '../threat-rules.js';
import {
  effectiveRisk,
  resolveThreatSettings,
  responseActionKinds,
  riskLevelAtLeast,
  riskLevels,
  riskScore,
  severityAtLeast,
  threatCollections,
  threatRule,
  threatRuleIds,
  threatRules,
  threatSeverities,
  type DetectionStatus,
  type IdentityRisk,
  type IncidentResolution,
  type IncidentStatus,
  type ResolvedThreatSettings,
  type ResponseAction,
  type ResponseActionKind,
  type RiskContribution,
  type RiskLevel,
  type ThreatCursor,
  type ThreatDetection,
  type ThreatDetectionRun,
  type ThreatIncident,
  type ThreatNote,
  type ThreatPlaybook,
  type ThreatResponse,
  type ThreatRuleCategory,
  type ThreatRuleDefinition,
  type ThreatRuleId,
  type ThreatRuleSetting,
  type ThreatSettings,
  type ThreatSeverity,
  type ThreatSubject,
  type ThreatSubjectType,
} from '../threats.js';
import { byNewest, id } from '../utils.js';
import { email, integer, object, text } from '../validation.js';

/** A detection rule with the setting in force for the tenant (`threats.rules`). */
export interface ThreatRuleView {
  id: ThreatRuleId;
  title: string;
  description: string;
  category: ThreatRuleCategory;
  /** What the rule's detections are about. */
  subject: ThreatSubjectType;
  /** MITRE ATT&CK technique the rule maps to. */
  technique: string;
  /** The rule's built-in settings. */
  defaults: { enabled: boolean; severity: ThreatSeverity; threshold?: number; windowMs?: number };
  /** Bounds `threats.configure` accepts for `threshold` and `windowMs`; absent when neither can be tuned. */
  tunable?: { threshold?: [min: number, max: number]; windowMs?: [min: number, max: number] };
  enabled: boolean;
  severity: ThreatSeverity;
  threshold?: number;
  windowMs?: number;
  /** `new-network` only: whether non-privileged people are reported too (at low severity). */
  everyone?: boolean;
  /** Whether the tenant changed any of the rule's settings. */
  customized: boolean;
}

/** A tenant's detection settings with every default applied (`threats.getSettings`, `threats.configure`). */
export interface ThreatSettingsView extends ResolvedThreatSettings {
  tenantId: string;
  /** False while the tenant has never saved settings (everything is at its default). */
  configured: boolean;
  updatedAt?: number;
  updatedBy?: string;
}

/** A tenant's adjustment of one rule in `threats.configure`; `null` puts a field back to the rule's default. */
export interface ThreatRuleSettingInput {
  enabled?: boolean | null;
  threshold?: number | null;
  windowMs?: number | null;
  severity?: ThreatSeverity | null;
  /** `new-network` only. */
  everyone?: boolean | null;
}

/** What `threats.configure` changes; fields left out keep their value. */
export interface ThreatSettingsInput {
  /** Per-rule changes, merged into the tenant's settings; `null` for a rule drops every adjustment of it. */
  rules?: Partial<Record<ThreatRuleId, ThreatRuleSettingInput | null>>;
  /** Replaces the trusted networks: at most 50 addresses or CIDR blocks (no wider than /8 for IPv4, /32 for IPv6). */
  trustedNetworks?: string[];
  /** 7 to 3650. */
  dormantDays?: number;
  /** 1 to 720. */
  riskHalfLifeHours?: number;
  /** Who the `notify` response emails: active owners and/or up to 20 addresses. */
  notify?: { owners?: boolean; emails?: string[] };
  /** 0 to 100. */
  maxAutomaticContainments?: number;
}

/** One contribution to an identity's risk with the points it still adds after decay. */
export interface RiskContributionView extends RiskContribution {
  /** Points this detection adds at the time of the read (decayed with the tenant's half-life). */
  current: number;
}

/** An identity's risk as administrators see it (`threats.getRisk`, `threats.listRisk`). */
export interface IdentityRiskView {
  identityId: string;
  name?: string;
  email?: string;
  kind: Identity['kind'];
  status: Identity['status'];
  /** Effective score at the time of the read: decayed contributions, raised to an active override's floor. */
  score: number;
  level: RiskLevel;
  /** An administrator's floor (`threats.setRisk`); `active` is false once it has expired. */
  override?: {
    level: Exclude<RiskLevel, 'none'>;
    reason: string;
    by: string;
    at: number;
    expiresAt?: number;
    active: boolean;
  };
  /** Set while the threats module holds the identity contained (`threats.release` lifts it). */
  contained?: { at: number; by: string; reason: string; incidentId?: string };
  /** Newest first. */
  contributions: RiskContributionView[];
  /** When the stored risk was last recomputed; absent for identities that never had a detection. */
  updatedAt?: number;
}

/** One page of detections, newest first (`threats.listDetections`). */
export interface DetectionPage {
  detections: ThreatDetection[];
  total: number;
}

/** One page of incidents, most recently active first (`threats.listIncidents`). */
export interface IncidentPage {
  incidents: ThreatIncident[];
  total: number;
}

/** One page of risky identities, highest score first (`threats.listRisk`). */
export interface RiskPage {
  identities: IdentityRiskView[];
  total: number;
}

/** An incident with everything an investigator needs (`threats.getIncident`). */
export interface IncidentDetail {
  incident: ThreatIncident;
  /** At most 200, newest first. */
  detections: ThreatDetection[];
  /** Oldest first. */
  notes: ThreatNote[];
  /** Newest first. */
  responses: ThreatResponse[];
  /** The risk of the identity the incident is about, when there is one. */
  risk?: IdentityRiskView;
}

/** The tenant's threat posture at a glance (`threats.summary`). */
export interface ThreatSummary {
  /** Open (not yet investigating) incidents by severity. */
  openIncidents: Record<ThreatSeverity, number>;
  investigating: number;
  /** Identities at each effective risk level. */
  riskyIdentities: Record<Exclude<RiskLevel, 'none'>, number>;
  /** Identities currently contained. */
  contained: number;
  /** Detections recorded in the last 24 hours, in total and per rule. */
  detections24h: number;
  byRule24h: Partial<Record<ThreatRuleId, number>>;
  /** When the detection engine last read the tenant's audit trail. */
  lastRunAt?: number;
}

/** The trigger and actions of a playbook (`threats.createPlaybook`). */
export interface ThreatPlaybookInput {
  name: string;
  description?: string;
  /** Default true. */
  enabled?: boolean;
  /** Which new detections run the playbook; every field left out matches everything. */
  trigger: {
    ruleIds?: ThreatRuleId[];
    minSeverity?: ThreatSeverity;
    subjectTypes?: ThreatSubjectType[];
  };
  /** One to five actions, each kind at most once, run in order. */
  actions: ResponseAction[];
}

/** What `threats.reportSuspicious` did. */
export interface SuspiciousActivityReport {
  detectionId: string;
  incidentId: string;
  /** Other sessions of the account that were ended (the reporting session is kept, API keys too). */
  sessionsEnded: number;
  /** Remembered devices forgotten, so the next sign-in asks for the second factor again. */
  devicesForgotten: number;
}

const minute = 60_000;
const hour = 60 * minute;
const day = 24 * hour;
/** Playbooks a tenant may define. */
const maxPlaybooks = 50;
/** Notes one incident may hold. */
const maxNotesPerIncident = 500;
/** Reports one person may file in 24 hours. */
const maxReportsPerDay = 5;
const incidentStatuses: readonly Exclude<IncidentStatus, 'resolved'>[] = ['open', 'investigating'];
const detectionStatuses: readonly DetectionStatus[] = ['open', 'dismissed', 'resolved'];
const allIncidentStatuses: readonly IncidentStatus[] = ['open', 'investigating', 'resolved'];
const resolutions: readonly IncidentResolution[] = ['true-positive', 'false-positive', 'benign'];
const raisedLevels: readonly Exclude<RiskLevel, 'none'>[] = ['low', 'medium', 'high'];
const subjectTypes: readonly ThreatSubjectType[] = ['identity', 'network', 'tenant', 'connection'];

const detectionResource = (detectionId: string) => `threats/detections/${detectionId}`;
const incidentResource = (incidentId: string) => `threats/incidents/${incidentId}`;
const riskResource = (identityId: string) => `threats/risk/${identityId}`;
const playbookResource = (playbookId: string) => `threats/playbooks/${playbookId}`;
/** How detections and responses name a person: their name, else their email (as the response module does). */
const personLabel = (identity: Identity) => identity.name || identity.email || identity.id;

function oneOf<T extends string>(value: unknown, allowed: readonly T[], name: string): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value))
    throw new IamError('INVALID_INPUT', `${name} must be one of ${allowed.join(', ')}`);
  return value as T;
}

function ruleIdOf(value: unknown, name: string): ThreatRuleId {
  if (typeof value !== 'string' || !threatRuleIds.has(value as ThreatRuleId))
    throw new IamError('INVALID_INPUT', `${name} names an unknown detection rule`);
  return value as ThreatRuleId;
}

function flag(value: unknown, name: string): boolean {
  if (typeof value !== 'boolean') throw new IamError('INVALID_INPUT', `${name} must be a boolean`);
  return value;
}

/** JSON with object keys sorted, to compare settings regardless of the order their keys were written in. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) =>
    item && typeof item === 'object' && !Array.isArray(item)
      ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : item,
  );
}

/** The effective values of a resolved rule setting, for telling whether a change altered what the rule does. */
function ruleSignature(setting: ResolvedThreatSettings['rules'][ThreatRuleId]): string {
  return JSON.stringify([
    setting.enabled,
    setting.severity,
    setting.threshold ?? null,
    setting.windowMs ?? null,
    setting.everyone === true,
  ]);
}

/** One way a settings change weakens detection or response (`threats.configure` reports it as guardrail-weakened). */
interface Weakening {
  /** The setting as audit metadata names it: `rules.brute-force.threshold`, `riskHalfLifeHours`, ... */
  key: string;
  /** What the caller did, for the detection's summary. */
  words: string;
}

/** A few items in words: "a", "a and b", "a, b and 3 more". */
function listed(items: readonly string[], limit = 3): string {
  const shown = items.slice(0, limit);
  const rest = items.length - shown.length;
  if (rest > 0) return `${shown.join(', ')} and ${rest} more`;
  if (shown.length <= 1) return shown.join('');
  return `${shown.slice(0, -1).join(', ')} and ${shown.at(-1)}`;
}

/**
 * What a settings change weakens besides turning rules off (reported on its own): a rule that stays on made less
 * sensitive (a higher threshold, a shorter window, a lower severity, new-network no longer reporting everyone), a
 * shorter risk half-life (every score decays at once), a longer dormancy period, newly trusted networks (never reported,
 * never blocked), a lower automatic containment brake, and fewer people emailed about incidents.
 */
function weakenings(before: ResolvedThreatSettings, after: ResolvedThreatSettings): Weakening[] {
  const found: Weakening[] = [];
  for (const rule of threatRules) {
    const was = before.rules[rule.id];
    const is = after.rules[rule.id];
    if (!was.enabled || !is.enabled) continue;
    const key = `rules.${rule.id}`;
    const name = `"${rule.title}"`;
    if (was.threshold !== undefined && is.threshold !== undefined && is.threshold > was.threshold)
      found.push({
        key: `${key}.threshold`,
        words: `raised the threshold of ${name} from ${was.threshold} to ${is.threshold}`,
      });
    if (was.windowMs !== undefined && is.windowMs !== undefined && is.windowMs < was.windowMs)
      found.push({
        key: `${key}.windowMs`,
        words: `shortened the window of ${name} from ${Math.round(was.windowMs / minute)} to ${Math.round(is.windowMs / minute)} minutes`,
      });
    if (!severityAtLeast(is.severity, was.severity))
      found.push({
        key: `${key}.severity`,
        words: `lowered the severity of ${name} from ${was.severity} to ${is.severity}`,
      });
    if (was.everyone === true && is.everyone !== true)
      found.push({ key: `${key}.everyone`, words: `stopped ${name} reporting everyone` });
  }
  if (after.riskHalfLifeHours < before.riskHalfLifeHours)
    found.push({
      key: 'riskHalfLifeHours',
      words: `shortened the risk half-life from ${before.riskHalfLifeHours} to ${after.riskHalfLifeHours} hours`,
    });
  if (after.dormantDays > before.dormantDays)
    found.push({
      key: 'dormantDays',
      words: `lengthened the dormancy period from ${before.dormantDays} to ${after.dormantDays} days`,
    });
  const trusted = after.trustedNetworks.filter(
    (network) => !before.trustedNetworks.includes(network),
  );
  if (trusted.length) found.push({ key: 'trustedNetworks', words: `trusted ${listed(trusted)}` });
  if (after.maxAutomaticContainments < before.maxAutomaticContainments)
    found.push({
      key: 'maxAutomaticContainments',
      words: `lowered the automatic containment limit from ${before.maxAutomaticContainments} to ${after.maxAutomaticContainments}`,
    });
  const removed = before.notify.emails.filter(
    (address) => !after.notify.emails.includes(address),
  ).length;
  if ((before.notify.owners && !after.notify.owners) || removed)
    found.push({
      key: 'notify',
      words:
        before.notify.owners && !after.notify.owners
          ? 'stopped emailing owners about incidents'
          : `removed ${removed} incident email recipient${removed === 1 ? '' : 's'}`,
    });
  return found;
}

function paging(input: { limit?: unknown; offset?: unknown }): { limit: number; offset: number } {
  return {
    limit: integer(input.limit ?? 100, 'limit', 1, 1000),
    offset: integer(input.offset ?? 0, 'offset', 0, 1_000_000),
  };
}

/**
 * Free text over several lines (notes, reports): line breaks are normalized to `\n`, tabs kept, every other control
 * character dropped; 1 to `max` characters after trimming.
 */
function multiline(value: unknown, name: string, max: number): string {
  if (typeof value !== 'string' || value.length > max * 4)
    throw new IamError('INVALID_INPUT', `Invalid ${name}`);
  let cleaned = '';
  let previous = 0;
  for (const character of value) {
    const code = character.codePointAt(0)!;
    if (code === 13) cleaned += '\n';
    else if (code === 10) {
      if (previous !== 13) cleaned += '\n';
    } else if (code === 9 || (code >= 32 && code < 127) || code >= 160) cleaned += character;
    previous = code;
  }
  cleaned = cleaned.trim();
  if (!cleaned || cleaned.length > max)
    throw new IamError('INVALID_INPUT', `${name} must be 1-${max} characters`);
  return cleaned;
}

/**
 * True for a CIDR block wider than /8 (IPv4, including IPv4-mapped IPv6 blocks) or /32 (IPv6): trusting it would
 * switch the network rules off, and exempt it from network blocks, for a large part of the internet.
 */
function tooWide(network: string): boolean {
  const slash = network.indexOf('/');
  if (slash < 0) return false;
  const address = network.slice(0, slash);
  const prefix = Number(network.slice(slash + 1));
  // ipCounterKey folds IPv4-mapped IPv6 addresses to their IPv4 form, so only real IPv6 keys keep a colon.
  const ipv6 = ipCounterKey(address)?.includes(':') ?? true;
  const mapped = !ipv6 && address.includes(':');
  return prefix < (ipv6 ? 32 : mapped ? 104 : 8);
}

function trustedNetworksOf(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 50)
    throw new IamError('INVALID_INPUT', 'trustedNetworks must list at most 50 networks');
  const networks = new Set<string>();
  for (const entry of value) {
    const network = text(entry, 'trustedNetworks', 64).trim();
    if (!isIpRange(network))
      throw new IamError(
        'INVALID_INPUT',
        'trustedNetworks entries must be IPv4/IPv6 addresses or CIDR blocks',
      );
    if (tooWide(network))
      throw new IamError(
        'INVALID_INPUT',
        'Trusted networks may be at most /8 (IPv4) or /32 (IPv6) wide',
      );
    networks.add(network);
  }
  return [...networks];
}

function notifyOf(value: unknown, current: ThreatSettings['notify']): ThreatSettings['notify'] {
  const input = object(value);
  for (const key of Object.keys(input))
    if (key !== 'owners' && key !== 'emails')
      throw new IamError('INVALID_INPUT', `Unknown notify setting ${key.slice(0, 64)}`);
  const next = { owners: current.owners, emails: [...current.emails] };
  if (input.owners !== undefined) next.owners = flag(input.owners, 'notify.owners');
  if (input.emails !== undefined) {
    if (!Array.isArray(input.emails) || input.emails.length > 20)
      throw new IamError('INVALID_INPUT', 'notify.emails must list at most 20 addresses');
    next.emails = [...new Set(input.emails.map((entry) => email(entry)))];
  }
  return next;
}

/** Merges per-rule changes into a tenant's rule settings; a rule left without adjustments is dropped. */
function mergeRules(current: ThreatSettings['rules'], value: unknown): ThreatSettings['rules'] {
  const next: ThreatSettings['rules'] = { ...current };
  for (const [key, change] of Object.entries(object(value))) {
    const rule = threatRule(ruleIdOf(key, 'rules'));
    if (change === null) {
      delete next[rule.id];
      continue;
    }
    const setting: ThreatRuleSetting = { ...next[rule.id] };
    for (const [field, raw] of Object.entries(object(change))) {
      const name = `rules.${rule.id}.${field}`;
      switch (field) {
        case 'enabled':
          if (raw === null) delete setting.enabled;
          else setting.enabled = flag(raw, name);
          break;
        case 'severity':
          if (raw === null) delete setting.severity;
          else setting.severity = oneOf(raw, threatSeverities, name);
          break;
        case 'threshold':
        case 'windowMs': {
          const bounds = rule.tunable?.[field];
          if (raw === null) delete setting[field];
          else if (!bounds)
            throw new IamError('INVALID_INPUT', `The ${rule.id} rule has no adjustable ${field}`);
          else setting[field] = integer(raw, name, bounds[0], bounds[1]);
          break;
        }
        case 'everyone':
          if (rule.id !== 'new-network')
            throw new IamError('INVALID_INPUT', 'everyone applies to the new-network rule only');
          if (raw === null) delete setting.everyone;
          else setting.everyone = flag(raw, name);
          break;
        default:
          throw new IamError(
            'INVALID_INPUT',
            `Unknown setting ${field.slice(0, 64)} for ${rule.id}`,
          );
      }
    }
    if (Object.keys(setting).length) next[rule.id] = setting;
    else delete next[rule.id];
  }
  return next;
}

function ruleView(
  rule: ThreatRuleDefinition,
  settings: ResolvedThreatSettings,
  stored: ThreatSettings | undefined,
): ThreatRuleView {
  const effective = settings.rules[rule.id];
  const own = stored?.rules[rule.id];
  return {
    id: rule.id,
    title: rule.title,
    description: rule.description,
    category: rule.category,
    subject: rule.subject,
    technique: rule.technique,
    defaults: {
      enabled: rule.enabledByDefault,
      severity: rule.severity,
      ...(rule.threshold !== undefined ? { threshold: rule.threshold } : {}),
      ...(rule.windowMs !== undefined ? { windowMs: rule.windowMs } : {}),
    },
    ...(rule.tunable ? { tunable: rule.tunable } : {}),
    enabled: effective.enabled,
    severity: effective.severity,
    ...(effective.threshold !== undefined ? { threshold: effective.threshold } : {}),
    ...(effective.windowMs !== undefined ? { windowMs: effective.windowMs } : {}),
    ...(rule.id === 'new-network' ? { everyone: effective.everyone === true } : {}),
    customized: own !== undefined && Object.keys(own).length > 0,
  };
}

function settingsView(tenantId: string, stored: ThreatSettings | undefined): ThreatSettingsView {
  return {
    tenantId,
    configured: stored !== undefined,
    ...resolveThreatSettings(stored),
    ...(stored ? { updatedAt: stored.updatedAt, updatedBy: stored.updatedBy } : {}),
  };
}

/** The tenant's stored settings (absent until `threats.configure` first saves them). */
async function storedSettings(tx: IamStore, tenantId: string): Promise<ThreatSettings | undefined> {
  const stored = await tx.get<ThreatSettings>(threatCollections.settings, tenantId);
  return stored?.tenantId === tenantId ? stored : undefined;
}

async function riskRecord(
  tx: IamStore,
  tenantId: string,
  identityId: string,
): Promise<IdentityRisk | undefined> {
  const record = await tx.get<IdentityRisk>(threatCollections.risk, identityId);
  return record?.tenantId === tenantId ? record : undefined;
}

/**
 * The containment in force: the risk record's mark while the identity is still disabled. An identity re-enabled
 * outside the threats module (identities.setStatus, agents.resume) is no longer contained, whatever the mark says.
 */
function containment(
  identity: Identity,
  record: IdentityRisk | undefined,
): IdentityRisk['contained'] | undefined {
  return identity.status === 'disabled' ? record?.contained : undefined;
}

function riskView(
  identity: Identity,
  record: IdentityRisk | undefined,
  settings: ResolvedThreatSettings,
  now: number,
): IdentityRiskView {
  const risk = effectiveRisk(record, now, settings.riskHalfLifeHours);
  const override = record?.override;
  const contained = containment(identity, record);
  return {
    identityId: identity.id,
    ...(identity.name ? { name: identity.name } : {}),
    ...(identity.email ? { email: identity.email } : {}),
    kind: identity.kind,
    status: identity.status,
    score: risk.score,
    level: risk.level,
    ...(override
      ? {
          override: {
            level: override.level,
            reason: override.reason,
            by: override.by,
            at: override.at,
            ...(override.expiresAt !== undefined ? { expiresAt: override.expiresAt } : {}),
            active: override.expiresAt === undefined || override.expiresAt > now,
          },
        }
      : {}),
    ...(contained ? { contained } : {}),
    contributions: (record?.contributions ?? [])
      .map((contribution) => ({
        ...contribution,
        current: riskScore([contribution], now, settings.riskHalfLifeHours),
      }))
      .sort((a, b) => b.at - a.at),
    ...(record ? { updatedAt: record.updatedAt } : {}),
  };
}

/**
 * Takes the contributions of `detectionIds` out of an identity's risk and recomputes it, auditing a level change
 * under the caller; nothing happens when none of them contributes.
 */
async function dropContributions(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  identityId: string,
  detectionIds: ReadonlySet<string>,
  settings: ResolvedThreatSettings,
  now: number,
  actorId: string,
): Promise<void> {
  const record = await riskRecord(tx, tenantId, identityId);
  if (!record?.contributions.some((contribution) => detectionIds.has(contribution.detectionId)))
    return;
  await recomputeRisk(ctx, tx, tenantId, identityId, settings, now, actorId, {
    drop: [...detectionIds],
  });
}

function responseActionsOf(value: unknown, name: string): ResponseAction[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 5)
    throw new IamError('INVALID_INPUT', `${name} must list 1-5 response actions`);
  const seen = new Set<ResponseActionKind>();
  return value.map((entry) => {
    const input = object(entry);
    for (const key of Object.keys(input))
      if (key !== 'kind' && key !== 'durationMs' && key !== 'keepApiKeys')
        throw new IamError('INVALID_INPUT', `Unknown response action field ${key.slice(0, 64)}`);
    const kind = oneOf(input.kind, responseActionKinds, `${name} kind`);
    if (seen.has(kind))
      throw new IamError('INVALID_INPUT', `${name} may list each kind of action once`);
    seen.add(kind);
    const action: ResponseAction = { kind };
    if (input.durationMs !== undefined) {
      if (kind !== 'block-network')
        throw new IamError('INVALID_INPUT', 'durationMs applies to block-network only');
      action.durationMs = integer(input.durationMs, 'durationMs', minute, 30 * day);
    }
    if (input.keepApiKeys !== undefined) {
      if (kind !== 'revoke-sessions')
        throw new IamError('INVALID_INPUT', 'keepApiKeys applies to revoke-sessions only');
      action.keepApiKeys = flag(input.keepApiKeys, 'keepApiKeys');
    }
    return action;
  });
}

function playbookName(value: unknown): string {
  const name = text(value, 'name', 100).trim();
  if (!name) throw new IamError('INVALID_INPUT', 'name is required');
  return name;
}

function playbookTrigger(value: unknown): ThreatPlaybook['trigger'] {
  if (value === undefined)
    throw new IamError('INVALID_INPUT', 'trigger is required ({} matches every detection)');
  const input = object(value);
  const trigger: ThreatPlaybook['trigger'] = {};
  for (const key of Object.keys(input))
    if (key !== 'ruleIds' && key !== 'minSeverity' && key !== 'subjectTypes')
      throw new IamError('INVALID_INPUT', `Unknown trigger field ${key.slice(0, 64)}`);
  if (input.ruleIds !== undefined && input.ruleIds !== null) {
    if (
      !Array.isArray(input.ruleIds) ||
      input.ruleIds.length === 0 ||
      input.ruleIds.length > threatRules.length
    )
      throw new IamError(
        'INVALID_INPUT',
        `trigger.ruleIds must list 1-${threatRules.length} detection rules`,
      );
    trigger.ruleIds = [
      ...new Set(input.ruleIds.map((ruleId) => ruleIdOf(ruleId, 'trigger.ruleIds'))),
    ];
  }
  if (input.minSeverity !== undefined && input.minSeverity !== null)
    trigger.minSeverity = oneOf(input.minSeverity, threatSeverities, 'trigger.minSeverity');
  if (input.subjectTypes !== undefined && input.subjectTypes !== null) {
    if (
      !Array.isArray(input.subjectTypes) ||
      input.subjectTypes.length === 0 ||
      input.subjectTypes.length > subjectTypes.length
    )
      throw new IamError(
        'INVALID_INPUT',
        `trigger.subjectTypes must list 1-${subjectTypes.length} subject types`,
      );
    trigger.subjectTypes = [
      ...new Set(
        input.subjectTypes.map((type) => oneOf(type, subjectTypes, 'trigger.subjectTypes')),
      ),
    ];
  }
  return trigger;
}

/** Audit metadata describing a playbook's settings. */
function playbookMetadata(playbook: ThreatPlaybook): Record<string, Json> {
  const { trigger } = playbook;
  return {
    name: playbook.name,
    enabled: playbook.enabled,
    trigger: {
      ...(trigger.ruleIds ? { ruleIds: trigger.ruleIds } : {}),
      ...(trigger.minSeverity ? { minSeverity: trigger.minSeverity } : {}),
      ...(trigger.subjectTypes ? { subjectTypes: trigger.subjectTypes } : {}),
    },
    actions: playbook.actions.map((action) => ({
      kind: action.kind,
      ...(action.durationMs !== undefined ? { durationMs: action.durationMs } : {}),
      ...(action.keepApiKeys !== undefined ? { keepApiKeys: action.keepApiKeys } : {}),
    })),
  };
}

/** Runs the tenant's playbooks for a detection the API itself recorded; nothing runs for a detection seen before. */
async function playbooksFor(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  recorded: Awaited<ReturnType<typeof recordDetection>>,
  settings: ResolvedThreatSettings,
): Promise<ThreatResponse[]> {
  if (!recorded.created) return [];
  return runPlaybooks(ctx, tx, tenantId, recorded.detection, recorded.incident, settings, {
    contained: 0,
  });
}

/**
 * True when one of `identityIds` is the caller's own identity and the caller is not a root administrator: nobody else
 * clears risk raised against themselves, so a compromised administrator account cannot erase its own signal.
 */
async function clearsOwnRisk(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  identityIds: Iterable<string | undefined>,
): Promise<boolean> {
  for (const identityId of identityIds)
    if (identityId === principal.identity.id) return !(await ctx.rootPrincipal(tx, principal));
  return false;
}

/**
 * Identity threat detection and response. Detection rules (sign-in attacks, session theft, account takeover,
 * privilege escalation, mass changes, weakened guardrails, audit tampering) read each tenant's audit trail through
 * the `iam.detectThreats()` job, group detections into incidents per subject, and raise a decaying risk score per
 * identity that policies read as `principal.riskLevel` / `principal.riskScore`. Administrators tune the rules,
 * investigate and resolve incidents, respond by hand (end sessions, forget devices, contain an identity, block a
 * network, notify), and define playbooks that respond automatically. Reading needs `iam:threats:read`, tuning and
 * triage `iam:threats:manage`, and acting on identities and networks `iam:threats:respond`, all on `iam/threats/...`;
 * people report suspicious activity on their own account without a permission.
 */
export function createThreatsApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  return {
    /**
     * Every detection rule with its defaults and the setting in force for the tenant. Requires iam:threats:read on
     * iam/threats/rules.
     */
    rules: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<ThreatRuleView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:threats:read',
        'threats/rules',
        async ({ tx, tenant }) => {
          const stored = await storedSettings(tx, tenant.id);
          const settings = resolveThreatSettings(stored);
          return threatRules.map((rule) => ruleView(rule, settings, stored));
        },
      ),
    /** The tenant's detection settings with defaults applied. Requires iam:threats:read on iam/threats/settings. */
    getSettings: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<ThreatSettingsView> =>
      operation(
        credential,
        input.tenantId,
        'iam:threats:read',
        'threats/settings',
        async ({ tx, tenant }) => settingsView(tenant.id, await storedSettings(tx, tenant.id)),
      ),
    /**
     * Tunes detection: per-rule `enabled`, `severity`, `threshold` and `windowMs` (within the rule's `tunable` bounds;
     * `null` restores a default, a rule set to `null` drops all its adjustments), `everyone` for new-network, trusted
     * networks, the dormancy period, the risk half-life, notification recipients and the automatic containment
     * brake. Turning a rule off, or weakening detection or response otherwise (a rule made less sensitive, a shorter
     * risk half-life, a longer dormancy period, newly trusted networks, a lower containment brake, fewer incident
     * recipients), also records a `guardrail-weakened` detection against the caller, since the engine never reads the
     * module's own events. Nobody shortens the half-life while detections raise their own risk (root administrators
     * excepted). Requires iam:threats:manage on iam/threats/settings and recent authentication; audited as
     * `threat:settings` with the changed keys, the rules turned off, and the weakened settings.
     */
    configure: async (
      credential: CredentialInput,
      input: ThreatSettingsInput & { tenantId: string },
    ): Promise<ThreatSettingsView> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const { value, responses } = await operation(
        credential,
        tenantId,
        'iam:threats:manage',
        'threats/settings',
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const stored = await storedSettings(tx, tenant.id);
          const before = resolveThreatSettings(stored);
          const now = ctx.now();
          const next: ThreatSettings = {
            id: tenant.id,
            tenantId: tenant.id,
            rules:
              input.rules === undefined
                ? { ...stored?.rules }
                : mergeRules(stored?.rules ?? {}, input.rules),
            trustedNetworks:
              input.trustedNetworks === undefined
                ? before.trustedNetworks
                : trustedNetworksOf(input.trustedNetworks),
            dormantDays:
              input.dormantDays === undefined
                ? before.dormantDays
                : integer(input.dormantDays, 'dormantDays', 7, 3650),
            riskHalfLifeHours:
              input.riskHalfLifeHours === undefined
                ? before.riskHalfLifeHours
                : integer(input.riskHalfLifeHours, 'riskHalfLifeHours', 1, 720),
            notify:
              input.notify === undefined ? before.notify : notifyOf(input.notify, before.notify),
            maxAutomaticContainments:
              input.maxAutomaticContainments === undefined
                ? before.maxAutomaticContainments
                : integer(input.maxAutomaticContainments, 'maxAutomaticContainments', 0, 100),
            updatedAt: now,
            updatedBy: principal.identity.id,
          };
          // A shorter half-life decays every score at once, the caller's too: as with dismissals, nobody clears risk
          // raised against themselves.
          if (
            next.riskHalfLifeHours < before.riskHalfLifeHours &&
            riskScore(
              (await riskRecord(tx, tenant.id, principal.identity.id))?.contributions ?? [],
              now,
              before.riskHalfLifeHours,
            ) > 0 &&
            (await clearsOwnRisk(ctx, tx, principal, [principal.identity.id]))
          )
            throw new OperationDenied(
              'While detections raise your own risk, another administrator shortens the risk half-life',
            );
          await (stored
            ? tx.put(threatCollections.settings, next)
            : tx.insert(threatCollections.settings, next));
          const after = resolveThreatSettings(next);
          const changedRules = threatRules
            .filter(
              (rule) =>
                ruleSignature(before.rules[rule.id]) !== ruleSignature(after.rules[rule.id]),
            )
            .map((rule) => rule.id);
          const changed = [
            ...(changedRules.length ? ['rules'] : []),
            ...(
              [
                'trustedNetworks',
                'dormantDays',
                'riskHalfLifeHours',
                'notify',
                'maxAutomaticContainments',
              ] as const
            ).filter((key) => canonical(before[key]) !== canonical(after[key])),
          ];
          const disabledRules = threatRules
            .filter((rule) => before.rules[rule.id].enabled && !after.rules[rule.id].enabled)
            .map((rule) => rule.id);
          const weakened = weakenings(before, after);
          await ctx.events.audit(
            tx,
            principal,
            'threat:settings',
            tenant.id,
            'threats/settings',
            'allow',
            false,
            { changed, changedRules, disabledRules, weakened: weakened.map((item) => item.key) },
          );
          let responses: ThreatResponse[] = [];
          // Judged by the guardrail rule as it stood before the change, so turning that rule off (or down) in the
          // same call is reported too; a tenant that had already turned it off is not.
          const guardrail = before.rules['guardrail-weakened'];
          if ((disabledRules.length || weakened.length) && guardrail.enabled) {
            const reporting: ResolvedThreatSettings = {
              ...after,
              rules: { ...after.rules, 'guardrail-weakened': guardrail },
            };
            const titles = disabledRules.map((ruleId) => threatRule(ruleId).title).join(', ');
            const count = `${disabledRules.length} detection rule${disabledRules.length === 1 ? '' : 's'}`;
            const changes = [
              ...(disabledRules.length ? [`turned off ${count}: ${titles}`] : []),
              ...weakened.map((item) => item.words),
            ];
            const candidate: DetectionCandidate = {
              ruleId: 'guardrail-weakened',
              severity: guardrail.severity,
              title: weakened.length ? 'Threat detection weakened' : 'Detection rules turned off',
              summary: `${personLabel(principal.identity)} ${listed(changes, 6)}.`,
              subject: { type: 'tenant', id: tenant.id, name: tenant.name },
              identityId: principal.identity.id,
              dedupeKey: `settings:${id()}`,
              occurredAt: now,
              evidence: {
                eventIds: [],
                count: disabledRules.length + weakened.length,
                firstAt: now,
                lastAt: now,
                identityIds: [principal.identity.id],
                actions: ['threat:settings'],
              },
              metadata: {
                disabledRules,
                weakened: weakened.map((item) => item.key),
                changedBy: principal.identity.id,
              },
            };
            const recorded = await recordDetection(ctx, tx, tenant.id, candidate, reporting, now);
            responses = await playbooksFor(ctx, tx, tenant.id, recorded, reporting);
          }
          return { value: settingsView(tenant.id, next), responses };
        },
      );
      await afterThreatResponses(ctx, tenantId, responses);
      return value;
    },
    /**
     * The tenant's detections, newest first, optionally narrowed by status, rule, severity, identity, incident and a
     * `since` time (epoch milliseconds, by detection time). Requires iam:threats:read on iam/threats/detections.
     */
    listDetections: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        status?: DetectionStatus;
        ruleId?: ThreatRuleId;
        severity?: ThreatSeverity;
        identityId?: string;
        incidentId?: string;
        since?: number;
        limit?: number;
        offset?: number;
      },
    ): Promise<DetectionPage> => {
      const { limit, offset } = paging(input);
      const filter: Record<string, unknown> = {
        ...(input.status !== undefined
          ? { status: oneOf(input.status, detectionStatuses, 'status') }
          : {}),
        ...(input.ruleId !== undefined ? { ruleId: ruleIdOf(input.ruleId, 'ruleId') } : {}),
        ...(input.severity !== undefined
          ? { severity: oneOf(input.severity, threatSeverities, 'severity') }
          : {}),
        ...(input.identityId !== undefined
          ? { identityId: text(input.identityId, 'identityId') }
          : {}),
        ...(input.incidentId !== undefined
          ? { incidentId: text(input.incidentId, 'incidentId') }
          : {}),
      };
      const since =
        input.since === undefined
          ? undefined
          : integer(input.since, 'since', 0, Number.MAX_SAFE_INTEGER);
      return operation(
        credential,
        input.tenantId,
        'iam:threats:read',
        'threats/detections',
        async ({ tx, tenant }) => {
          const detections = await findOrdered<ThreatDetection>(
            tx,
            threatCollections.detections,
            { ...filter, tenantId: tenant.id },
            {
              field: 'detectedAt',
              direction: 'desc',
              ...(since !== undefined ? { from: since } : {}),
            },
          );
          return { detections: detections.slice(offset, offset + limit), total: detections.length };
        },
      );
    },
    /** One detection with its evidence. Requires iam:threats:read on iam/threats/detections/{id}. */
    getDetection: async (
      credential: CredentialInput,
      input: { tenantId: string; detectionId: string },
    ): Promise<ThreatDetection> => {
      const detectionId = text(input.detectionId, 'detectionId');
      return operation(
        credential,
        input.tenantId,
        'iam:threats:read',
        detectionResource(detectionId),
        async ({ tx, tenant }) =>
          ctx.scoped<ThreatDetection>(tx, threatCollections.detections, detectionId, tenant.id),
      );
    },
    /**
     * Marks an open detection as a false alarm and takes its points out of the identity's risk; the incident stays
     * open for a person to resolve. Detections about the caller are dismissed by someone else (root administrators
     * excepted). Requires iam:threats:manage on iam/threats/detections/{id} and recent authentication; audited as
     * `threat:detection-dismiss`.
     */
    dismissDetection: async (
      credential: CredentialInput,
      input: { tenantId: string; detectionId: string; reason: string },
    ): Promise<ThreatDetection> => {
      const detectionId = text(input.detectionId, 'detectionId');
      return operation(
        credential,
        input.tenantId,
        'iam:threats:manage',
        detectionResource(detectionId),
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const reason = text(input.reason, 'reason', 512).trim();
          const detection = await ctx.scoped<ThreatDetection>(
            tx,
            threatCollections.detections,
            detectionId,
            tenant.id,
          );
          if (detection.status !== 'open')
            throw new IamError('INVALID_TRANSITION', 'Only open detections can be dismissed', 409);
          if (await clearsOwnRisk(ctx, tx, principal, [detection.identityId]))
            throw new OperationDenied(
              'Detections about yourself are dismissed by another administrator',
            );
          const now = ctx.now();
          const next = await tx.put<ThreatDetection>(threatCollections.detections, {
            ...detection,
            status: 'dismissed',
            dismissedBy: principal.identity.id,
            dismissedAt: now,
            dismissReason: reason,
          });
          if (detection.identityId)
            await dropContributions(
              ctx,
              tx,
              tenant.id,
              detection.identityId,
              new Set([detection.id]),
              resolveThreatSettings(await storedSettings(tx, tenant.id)),
              now,
              principal.identity.id,
            );
          await ctx.events.audit(
            tx,
            principal,
            'threat:detection-dismiss',
            tenant.id,
            detectionResource(detection.id),
            'allow',
            false,
            {
              ruleId: detection.ruleId,
              severity: detection.severity,
              reason,
              ...(detection.identityId ? { identityId: detection.identityId } : {}),
              ...(detection.incidentId ? { incidentId: detection.incidentId } : {}),
            },
          );
          return next;
        },
      );
    },
    /**
     * The tenant's incidents, most recently active first, optionally narrowed by status, severity, assignee and
     * identity. Requires iam:threats:read on iam/threats/incidents.
     */
    listIncidents: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        status?: IncidentStatus;
        severity?: ThreatSeverity;
        assigneeId?: string;
        identityId?: string;
        limit?: number;
        offset?: number;
      },
    ): Promise<IncidentPage> => {
      const { limit, offset } = paging(input);
      const filter: Record<string, unknown> = {
        ...(input.status !== undefined
          ? { status: oneOf(input.status, allIncidentStatuses, 'status') }
          : {}),
        ...(input.severity !== undefined
          ? { severity: oneOf(input.severity, threatSeverities, 'severity') }
          : {}),
        ...(input.assigneeId !== undefined
          ? { assigneeId: text(input.assigneeId, 'assigneeId') }
          : {}),
        ...(input.identityId !== undefined
          ? { identityId: text(input.identityId, 'identityId') }
          : {}),
      };
      return operation(
        credential,
        input.tenantId,
        'iam:threats:read',
        'threats/incidents',
        async ({ tx, tenant }) => {
          const incidents = await findOrdered<ThreatIncident>(
            tx,
            threatCollections.incidents,
            { ...filter, tenantId: tenant.id },
            { field: 'lastDetectedAt', direction: 'desc' },
          );
          return { incidents: incidents.slice(offset, offset + limit), total: incidents.length };
        },
      );
    },
    /**
     * An incident with its detections (up to 200, newest first), notes (oldest first), responses (newest first) and
     * the risk of the identity it concerns. Requires iam:threats:read on iam/threats/incidents/{id}.
     */
    getIncident: async (
      credential: CredentialInput,
      input: { tenantId: string; incidentId: string },
    ): Promise<IncidentDetail> => {
      const incidentId = text(input.incidentId, 'incidentId');
      return operation(
        credential,
        input.tenantId,
        'iam:threats:read',
        incidentResource(incidentId),
        async ({ tx, tenant }) => {
          const incident = await ctx.scoped<ThreatIncident>(
            tx,
            threatCollections.incidents,
            incidentId,
            tenant.id,
          );
          const detections = await findOrdered<ThreatDetection>(
            tx,
            threatCollections.detections,
            { tenantId: tenant.id, incidentId: incident.id },
            { field: 'detectedAt', direction: 'desc', limit: 200 },
          );
          const notes = (
            await tx.find<ThreatNote>(threatCollections.notes, {
              tenantId: tenant.id,
              incidentId: incident.id,
            })
          ).sort((a, b) => byNewest(b, a));
          const responses = (
            await tx.find<ThreatResponse>(threatCollections.responses, {
              tenantId: tenant.id,
              incidentId: incident.id,
            })
          ).sort(byNewest);
          const detail: IncidentDetail = { incident, detections, notes, responses };
          if (incident.identityId) {
            const identity = await tx.get<Identity>('identities', incident.identityId);
            if (identity?.tenantId === tenant.id)
              detail.risk = riskView(
                identity,
                await riskRecord(tx, tenant.id, identity.id),
                resolveThreatSettings(await storedSettings(tx, tenant.id)),
                ctx.now(),
              );
          }
          return detail;
        },
      );
    },
    /**
     * Triage: moves an incident between `open` and `investigating`, assigns it to an active identity of the tenant
     * (`null` unassigns), or changes its severity. Resolved incidents are closed to changes. Requires
     * iam:threats:manage on iam/threats/incidents/{id}; audited as `threat:incident-update`.
     */
    updateIncident: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        incidentId: string;
        status?: Exclude<IncidentStatus, 'resolved'>;
        assigneeId?: string | null;
        severity?: ThreatSeverity;
      },
    ): Promise<ThreatIncident> => {
      const incidentId = text(input.incidentId, 'incidentId');
      return operation(
        credential,
        input.tenantId,
        'iam:threats:manage',
        incidentResource(incidentId),
        async ({ tx, tenant, principal }) => {
          const incident = await ctx.scoped<ThreatIncident>(
            tx,
            threatCollections.incidents,
            incidentId,
            tenant.id,
          );
          if (incident.status === 'resolved')
            throw new IamError('INVALID_TRANSITION', 'Resolved incidents cannot be changed', 409);
          const status =
            input.status === undefined
              ? incident.status
              : oneOf(input.status, incidentStatuses, 'status');
          const severity =
            input.severity === undefined
              ? incident.severity
              : oneOf(input.severity, threatSeverities, 'severity');
          const { assigneeId: previousAssignee, ...rest } = incident;
          let assigneeId = previousAssignee;
          if (input.assigneeId === null) assigneeId = undefined;
          else if (input.assigneeId !== undefined) {
            const assignee = await ctx.activeIdentity(
              tx,
              text(input.assigneeId, 'assigneeId'),
              tenant.id,
            );
            if (assignee.status !== 'active')
              throw new IamError('INVALID_INPUT', 'Incidents are assigned to active identities');
            assigneeId = assignee.id;
          }
          const changes = [
            ...(status !== incident.status ? ['status'] : []),
            ...(severity !== incident.severity ? ['severity'] : []),
            ...(assigneeId !== previousAssignee ? ['assigneeId'] : []),
          ];
          const next = await tx.put<ThreatIncident>(threatCollections.incidents, {
            ...rest,
            status,
            severity,
            ...(assigneeId !== undefined ? { assigneeId } : {}),
            updatedAt: ctx.now(),
          });
          await ctx.events.audit(
            tx,
            principal,
            'threat:incident-update',
            tenant.id,
            incidentResource(incident.id),
            'allow',
            false,
            { changes, status, severity, assigneeId: assigneeId ?? null },
          );
          return next;
        },
      );
    },
    /**
     * Adds an investigation note (1-4000 characters over several lines) to an incident, resolved ones included; at
     * most 500 per incident. Requires iam:threats:manage on iam/threats/incidents/{id}; audited as `threat:note`
     * (without the text).
     */
    addNote: async (
      credential: CredentialInput,
      input: { tenantId: string; incidentId: string; body: string },
    ): Promise<ThreatNote> => {
      const incidentId = text(input.incidentId, 'incidentId');
      const body = multiline(input.body, 'body', 4000);
      return operation(
        credential,
        input.tenantId,
        'iam:threats:manage',
        incidentResource(incidentId),
        async ({ tx, tenant, principal }) => {
          const incident = await ctx.scoped<ThreatIncident>(
            tx,
            threatCollections.incidents,
            incidentId,
            tenant.id,
          );
          const existing = await tx.find(threatCollections.notes, {
            tenantId: tenant.id,
            incidentId: incident.id,
          });
          if (existing.length >= maxNotesPerIncident)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `An incident holds at most ${maxNotesPerIncident} notes`,
              409,
            );
          const note = await tx.insert<ThreatNote>(threatCollections.notes, {
            id: id(),
            tenantId: tenant.id,
            incidentId: incident.id,
            authorId: principal.identity.id,
            body,
            createdAt: ctx.now(),
          });
          await ctx.events.audit(
            tx,
            principal,
            'threat:note',
            tenant.id,
            incidentResource(incident.id),
            'allow',
            false,
            { noteId: note.id, length: body.length },
          );
          return note;
        },
      );
    },
    /**
     * Closes an incident as `true-positive`, `false-positive` or `benign`, optionally with a closing note. Its open
     * detections become resolved; a false positive or benign finding also takes their points out of the identities'
     * risk (not for risk raised against the caller, unless a root administrator resolves). A new detection about the
     * same subject opens a new incident. Requires iam:threats:manage on iam/threats/incidents/{id} and recent
     * authentication; audited as `threat:incident-resolve`.
     */
    resolveIncident: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        incidentId: string;
        resolution: IncidentResolution;
        note?: string;
      },
    ): Promise<ThreatIncident> => {
      const incidentId = text(input.incidentId, 'incidentId');
      const resolution = oneOf(input.resolution, resolutions, 'resolution');
      const note = input.note === undefined ? undefined : multiline(input.note, 'note', 4000);
      return operation(
        credential,
        input.tenantId,
        'iam:threats:manage',
        incidentResource(incidentId),
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const incident = await ctx.scoped<ThreatIncident>(
            tx,
            threatCollections.incidents,
            incidentId,
            tenant.id,
          );
          if (incident.status === 'resolved')
            throw new IamError('INVALID_TRANSITION', 'The incident is already resolved', 409);
          const detections = await tx.find<ThreatDetection>(threatCollections.detections, {
            tenantId: tenant.id,
            incidentId: incident.id,
          });
          const clears = resolution !== 'true-positive';
          if (
            clears &&
            (await clearsOwnRisk(
              ctx,
              tx,
              principal,
              detections.map((detection) => detection.identityId),
            ))
          )
            throw new OperationDenied(
              'Incidents that raised your own risk are closed as false positives by another administrator',
            );
          const now = ctx.now();
          const { uniqueKey: _openKey, ...rest } = incident;
          const next = await tx.put<ThreatIncident>(threatCollections.incidents, {
            ...rest,
            status: 'resolved',
            resolution,
            resolvedBy: principal.identity.id,
            resolvedAt: now,
            updatedAt: now,
          });
          let resolved = 0;
          for (const detection of detections)
            if (detection.status === 'open') {
              await tx.put<ThreatDetection>(threatCollections.detections, {
                ...detection,
                status: 'resolved',
              });
              resolved++;
            }
          if (clears) {
            const byIdentity = new Map<string, Set<string>>();
            for (const detection of detections)
              if (detection.identityId)
                byIdentity.set(
                  detection.identityId,
                  (byIdentity.get(detection.identityId) ?? new Set<string>()).add(detection.id),
                );
            const settings = resolveThreatSettings(await storedSettings(tx, tenant.id));
            for (const [identityId, detectionIds] of byIdentity)
              await dropContributions(
                ctx,
                tx,
                tenant.id,
                identityId,
                detectionIds,
                settings,
                now,
                principal.identity.id,
              );
          }
          if (note !== undefined)
            await tx.insert<ThreatNote>(threatCollections.notes, {
              id: id(),
              tenantId: tenant.id,
              incidentId: incident.id,
              authorId: principal.identity.id,
              body: note,
              createdAt: now,
            });
          await ctx.events.audit(
            tx,
            principal,
            'threat:incident-resolve',
            tenant.id,
            incidentResource(incident.id),
            'allow',
            false,
            {
              resolution,
              severity: incident.severity,
              subjectType: incident.subject.type,
              subjectId: incident.subject.id,
              detectionsResolved: resolved,
              ...(incident.identityId ? { identityId: incident.identityId } : {}),
            },
          );
          return next;
        },
      );
    },
    /**
     * Responds by hand to an incident (its subject), an identity or a network: exactly one target, one to five
     * actions (`revoke-sessions`, `forget-devices`, `contain`, `block-network` with `durationMs`, `notify`) run in
     * order. A response to an identity or network with an open incident is filed under it. Actions that do not apply
     * to the target, or that protections refuse, come back `skipped` with a reason. Requires iam:threats:respond on
     * iam/threats/incidents/{id} (iam/threats/responses without an incident) and recent authentication; each action
     * is audited as `threat:{action}`.
     */
    respond: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        incidentId?: string;
        identityId?: string;
        network?: string;
        actions: ResponseAction[];
        reason: string;
      },
    ): Promise<ThreatResponse[]> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const incidentId =
        input.incidentId === undefined ? undefined : text(input.incidentId, 'incidentId');
      const identityId =
        input.identityId === undefined ? undefined : text(input.identityId, 'identityId');
      const network =
        input.network === undefined ? undefined : text(input.network, 'network', 64).trim();
      if ([incidentId, identityId, network].filter((target) => target !== undefined).length !== 1)
        throw new IamError(
          'INVALID_INPUT',
          'Respond to exactly one of incidentId, identityId or network',
        );
      if (network !== undefined && !isIpRange(network))
        throw new IamError('INVALID_INPUT', 'network must be an IPv4/IPv6 address or CIDR block');
      const actions = responseActionsOf(input.actions, 'actions');
      const responses = await operation(
        credential,
        tenantId,
        'iam:threats:respond',
        incidentId ? incidentResource(incidentId) : 'threats/responses',
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const reason = text(input.reason, 'reason', 512).trim();
          const settings = resolveThreatSettings(await storedSettings(tx, tenant.id));
          const openIncident = async (subject: ThreatSubject) =>
            (
              await tx.find<ThreatIncident>(threatCollections.incidents, {
                tenantId: tenant.id,
                uniqueKey: `open:${subject.type}:${subject.id}`,
              })
            )[0];
          let target: Pick<ResponseRequest, 'subject' | 'identityId' | 'network' | 'incidentId'>;
          if (incidentId !== undefined) {
            const incident = await ctx.scoped<ThreatIncident>(
              tx,
              threatCollections.incidents,
              incidentId,
              tenant.id,
            );
            target = {
              subject: incident.subject,
              incidentId: incident.id,
              ...(incident.identityId ? { identityId: incident.identityId } : {}),
              ...(incident.network ? { network: incident.network } : {}),
            };
          } else if (identityId !== undefined) {
            const identity = await ctx.activeIdentity(tx, identityId, tenant.id);
            const subject: ThreatSubject = {
              type: 'identity',
              id: identity.id,
              name: personLabel(identity),
            };
            const incident = await openIncident(subject);
            target = {
              subject,
              identityId: identity.id,
              ...(incident ? { incidentId: incident.id } : {}),
            };
          } else {
            const subject: ThreatSubject = { type: 'network', id: network! };
            const incident = await openIncident(subject);
            target = {
              subject,
              network: network!,
              ...(incident ? { incidentId: incident.id } : {}),
            };
          }
          const taken: ThreatResponse[] = [];
          for (const action of actions)
            taken.push(
              await applyResponse(
                ctx,
                tx,
                tenant.id,
                { action, ...target, reason, actor: { principal } },
                settings,
              ),
            );
          return taken;
        },
      );
      await afterThreatResponses(ctx, tenantId, responses);
      return responses;
    },
    /**
     * Lifts a containment: the identity becomes active again and signs in as usual (its sessions stay ended, its API
     * keys work again); its risk score is kept. Only an identity the threats module contained and that is still
     * disabled can be released (INVALID_TRANSITION otherwise), a root administrator only by root. Requires
     * iam:threats:respond on iam/threats/responses and recent authentication; audited as `threat:release`.
     */
    release: async (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; note?: string },
    ): Promise<ThreatResponse> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const identityId = text(input.identityId, 'identityId');
      const note = input.note === undefined ? undefined : text(input.note, 'note', 512).trim();
      const response = await operation(
        credential,
        tenantId,
        'iam:threats:respond',
        'threats/responses',
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          return releaseIdentity(ctx, tx, tenant.id, identityId, { principal }, note);
        },
      );
      await afterThreatResponses(ctx, tenantId, [response]);
      return response;
    },
    /**
     * Identities whose effective risk is at least `minLevel` (default `low`), or that are contained, highest score
     * first. Requires iam:threats:read on iam/threats/risk.
     */
    listRisk: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        minLevel?: Exclude<RiskLevel, 'none'>;
        limit?: number;
        offset?: number;
      },
    ): Promise<RiskPage> => {
      const { limit, offset } = paging(input);
      const floor =
        input.minLevel === undefined ? 'low' : oneOf(input.minLevel, raisedLevels, 'minLevel');
      return operation(
        credential,
        input.tenantId,
        'iam:threats:read',
        'threats/risk',
        async ({ tx, tenant }) => {
          const settings = resolveThreatSettings(await storedSettings(tx, tenant.id));
          const now = ctx.now();
          const identities: IdentityRiskView[] = [];
          for (const record of await tx.find<IdentityRisk>(threatCollections.risk, {
            tenantId: tenant.id,
          })) {
            const risk = effectiveRisk(record, now, settings.riskHalfLifeHours);
            if (!riskLevelAtLeast(risk.level, floor) && !record.contained) continue;
            const identity = await tx.get<Identity>('identities', record.identityId);
            if (identity?.tenantId !== tenant.id || identity.status === 'deleted') continue;
            if (riskLevelAtLeast(risk.level, floor) || containment(identity, record))
              identities.push(riskView(identity, record, settings, now));
          }
          identities.sort(
            (a, b) => b.score - a.score || (a.identityId < b.identityId ? -1 : 1),
          );
          return { identities: identities.slice(offset, offset + limit), total: identities.length };
        },
      );
    },
    /**
     * One identity's risk (level `none` when nothing was ever detected). Requires iam:threats:read on
     * iam/threats/risk/{id}.
     */
    getRisk: async (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string },
    ): Promise<IdentityRiskView> => {
      const identityId = text(input.identityId, 'identityId');
      return operation(
        credential,
        input.tenantId,
        'iam:threats:read',
        riskResource(identityId),
        async ({ tx, tenant }) => {
          const identity = await ctx.scoped<Identity>(tx, 'identities', identityId, tenant.id);
          return riskView(
            identity,
            await riskRecord(tx, tenant.id, identity.id),
            resolveThreatSettings(await storedSettings(tx, tenant.id)),
            ctx.now(),
          );
        },
      );
    },
    /**
     * Sets an identity's risk by hand: `low`, `medium` or `high` sets a floor ("confirmed compromised") that holds
     * until `expiresInMs` (one hour to 90 days) or indefinitely; `none` clears the override and every detection's
     * contribution. Nobody sets their own risk. Requires iam:threats:respond on iam/threats/risk/{id} and recent
     * authentication; audited as `threat:risk-override`, plus `threat:risk-change` when the effective level moves.
     */
    setRisk: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        identityId: string;
        level: RiskLevel;
        reason: string;
        expiresInMs?: number;
      },
    ): Promise<IdentityRiskView> => {
      const identityId = text(input.identityId, 'identityId');
      const level = oneOf(input.level, riskLevels, 'level');
      const expiresInMs =
        input.expiresInMs === undefined
          ? undefined
          : integer(input.expiresInMs, 'expiresInMs', hour, 90 * day);
      if (level === 'none' && expiresInMs !== undefined)
        throw new IamError('INVALID_INPUT', 'expiresInMs applies to a raised level only');
      return operation(
        credential,
        input.tenantId,
        'iam:threats:respond',
        riskResource(identityId),
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const reason = text(input.reason, 'reason', 512).trim();
          const identity = await ctx.scoped<Identity>(tx, 'identities', identityId, tenant.id);
          if (identity.id === principal.identity.id)
            throw new OperationDenied('Your own risk level is set by another administrator');
          const settings = resolveThreatSettings(await storedSettings(tx, tenant.id));
          const now = ctx.now();
          const record = await riskRecord(tx, tenant.id, identity.id);
          let cleared = 0;
          let expiresAt: number | undefined;
          if (level === 'none') {
            if (record) {
              cleared = record.contributions.length;
              const { override: _override, ...rest } = record;
              await tx.put<IdentityRisk>(threatCollections.risk, { ...rest, contributions: [] });
            }
          } else {
            expiresAt = expiresInMs === undefined ? undefined : now + expiresInMs;
            const override: NonNullable<IdentityRisk['override']> = {
              level,
              reason,
              by: principal.identity.id,
              at: now,
              ...(expiresAt !== undefined ? { expiresAt } : {}),
            };
            await (record
              ? tx.put<IdentityRisk>(threatCollections.risk, { ...record, override })
              : tx.insert<IdentityRisk>(threatCollections.risk, {
                  id: identity.id,
                  tenantId: tenant.id,
                  identityId: identity.id,
                  contributions: [],
                  score: 0,
                  level: 'none',
                  override,
                  updatedAt: now,
                }));
          }
          await ctx.events.audit(
            tx,
            principal,
            'threat:risk-override',
            tenant.id,
            identity.id,
            'allow',
            false,
            {
              level,
              reason,
              ...(expiresAt !== undefined ? { expiresAt } : {}),
              ...(level === 'none' ? { clearedContributions: cleared } : {}),
            },
          );
          await recomputeRisk(
            ctx,
            tx,
            tenant.id,
            identity.id,
            settings,
            now,
            principal.identity.id,
          );
          return riskView(identity, await riskRecord(tx, tenant.id, identity.id), settings, now);
        },
      );
    },
    /**
     * The identity's recent audit trail, newest first: events it performed and events about it, from `since`
     * (default seven days ago), at most `limit` (default 200, up to 500). Requires iam:threats:read on
     * iam/threats/risk/{id}.
     */
    timeline: async (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; since?: number; limit?: number },
    ): Promise<AuditEvent[]> => {
      const identityId = text(input.identityId, 'identityId');
      const limit = integer(input.limit ?? 200, 'limit', 1, 500);
      const since =
        input.since === undefined
          ? undefined
          : integer(input.since, 'since', 0, Number.MAX_SAFE_INTEGER);
      return operation(
        credential,
        input.tenantId,
        'iam:threats:read',
        riskResource(identityId),
        async ({ tx, tenant }) => {
          const identity = await ctx.scoped<Identity>(tx, 'identities', identityId, tenant.id);
          return findOrdered<AuditEvent>(
            tx,
            'audit',
            { tenantId: tenant.id },
            {
              field: 'timestamp',
              direction: 'desc',
              from: since ?? ctx.now() - 7 * day,
              limit,
              where: (event) =>
                event.actorId === identity.id ||
                event.resourceId === identity.id ||
                event.originalActorId === identity.id,
            },
          );
        },
      );
    },
    /** The tenant's playbooks by name. Requires iam:threats:read on iam/threats/playbooks. */
    listPlaybooks: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<ThreatPlaybook[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:threats:read',
        'threats/playbooks',
        async ({ tx, tenant }) =>
          (
            await tx.find<ThreatPlaybook>(threatCollections.playbooks, { tenantId: tenant.id })
          ).sort((a, b) => a.name.localeCompare(b.name)),
      ),
    /**
     * Defines an automatic response: when a new detection matches `trigger` (rules, minimum severity, subject types;
     * fields left out match everything), `actions` run in order as the threat-detection actor. Automatic actions
     * never contain owners or root administrators, and at most `maxAutomaticContainments` identities are contained
     * per run. Names are unique per tenant; at most 50 playbooks. Requires iam:threats:manage on
     * iam/threats/playbooks and recent authentication; audited as `threat:playbook-create`.
     */
    createPlaybook: async (
      credential: CredentialInput,
      input: ThreatPlaybookInput & { tenantId: string },
    ): Promise<ThreatPlaybook> =>
      operation(
        credential,
        input.tenantId,
        'iam:threats:manage',
        'threats/playbooks',
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const name = playbookName(input.name);
          const description =
            input.description === undefined
              ? undefined
              : text(input.description, 'description', 512).trim();
          const enabled = input.enabled === undefined ? true : flag(input.enabled, 'enabled');
          const trigger = playbookTrigger(input.trigger);
          const actions = responseActionsOf(input.actions, 'actions');
          const uniqueKey = `name:${name.toLowerCase()}`;
          const existing = await tx.find<ThreatPlaybook>(threatCollections.playbooks, {
            tenantId: tenant.id,
          });
          if (existing.some((playbook) => playbook.uniqueKey === uniqueKey))
            throw new IamError('CONFLICT', 'A playbook with this name exists', 409);
          if (existing.length >= maxPlaybooks)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant can define at most ${maxPlaybooks} playbooks`,
              409,
            );
          const now = ctx.now();
          const playbook = await tx.insert<ThreatPlaybook>(threatCollections.playbooks, {
            id: id(),
            tenantId: tenant.id,
            uniqueKey,
            name,
            ...(description ? { description } : {}),
            enabled,
            trigger,
            actions,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
            updatedBy: principal.identity.id,
            runs: 0,
          });
          await ctx.events.audit(
            tx,
            principal,
            'threat:playbook-create',
            tenant.id,
            playbookResource(playbook.id),
            'allow',
            false,
            playbookMetadata(playbook),
          );
          return playbook;
        },
      ),
    /**
     * Changes a playbook; fields left out keep their value and `description: null` clears the description.
     * Requires iam:threats:manage on iam/threats/playbooks/{id} and recent authentication; audited as
     * `threat:playbook-update` with the settings before and after.
     */
    updatePlaybook: async (
      credential: CredentialInput,
      input: Partial<Omit<ThreatPlaybookInput, 'description'>> & {
        tenantId: string;
        playbookId: string;
        description?: string | null;
      },
    ): Promise<ThreatPlaybook> => {
      const playbookId = text(input.playbookId, 'playbookId');
      return operation(
        credential,
        input.tenantId,
        'iam:threats:manage',
        playbookResource(playbookId),
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const playbook = await ctx.scoped<ThreatPlaybook>(
            tx,
            threatCollections.playbooks,
            playbookId,
            tenant.id,
          );
          const name = input.name === undefined ? playbook.name : playbookName(input.name);
          const uniqueKey = `name:${name.toLowerCase()}`;
          if (
            (
              await tx.find<ThreatPlaybook>(threatCollections.playbooks, {
                tenantId: tenant.id,
                uniqueKey,
              })
            ).some((other) => other.id !== playbook.id)
          )
            throw new IamError('CONFLICT', 'A playbook with this name exists', 409);
          const description =
            input.description === undefined
              ? playbook.description
              : input.description === null
                ? undefined
                : text(input.description, 'description', 512).trim();
          const { description: _description, ...rest } = playbook;
          const next = await tx.put<ThreatPlaybook>(threatCollections.playbooks, {
            ...rest,
            uniqueKey,
            name,
            ...(description ? { description } : {}),
            enabled:
              input.enabled === undefined ? playbook.enabled : flag(input.enabled, 'enabled'),
            trigger:
              input.trigger === undefined ? playbook.trigger : playbookTrigger(input.trigger),
            actions:
              input.actions === undefined
                ? playbook.actions
                : responseActionsOf(input.actions, 'actions'),
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          });
          await ctx.events.audit(
            tx,
            principal,
            'threat:playbook-update',
            tenant.id,
            playbookResource(playbook.id),
            'allow',
            false,
            { before: playbookMetadata(playbook), after: playbookMetadata(next) },
          );
          return next;
        },
      );
    },
    /**
     * Deletes a playbook; responses it already took stay on their incidents. Requires iam:threats:manage on
     * iam/threats/playbooks/{id} and recent authentication; audited as `threat:playbook-delete`.
     */
    deletePlaybook: async (
      credential: CredentialInput,
      input: { tenantId: string; playbookId: string },
    ): Promise<{ deleted: true }> => {
      const playbookId = text(input.playbookId, 'playbookId');
      return operation(
        credential,
        input.tenantId,
        'iam:threats:manage',
        playbookResource(playbookId),
        async ({ tx, tenant, principal }) => {
          ctx.auth.requireRecent(principal);
          const playbook = await ctx.scoped<ThreatPlaybook>(
            tx,
            threatCollections.playbooks,
            playbookId,
            tenant.id,
          );
          await tx.delete(threatCollections.playbooks, playbook.id);
          await ctx.events.audit(
            tx,
            principal,
            'threat:playbook-delete',
            tenant.id,
            playbookResource(playbook.id),
            'allow',
            false,
            { name: playbook.name },
          );
          return { deleted: true as const };
        },
      );
    },
    /**
     * Runs detection for the tenant now instead of waiting for the scheduled `iam.detectThreats()` job, and returns
     * what the run did. Requires iam:threats:manage on iam/threats/detections.
     */
    detect: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<ThreatDetectionRun> => {
      // The engine opens its own transactions, so it runs once the permission check has committed.
      const tenantId = await operation(
        credential,
        input.tenantId,
        'iam:threats:manage',
        'threats/detections',
        async ({ tenant }) => tenant.id,
      );
      return detectThreats(ctx, { tenantId });
    },
    /**
     * Counts for a dashboard: open incidents by severity, incidents under investigation, identities by risk level,
     * contained identities, detections in the last 24 hours by rule, and when detection last ran. Requires
     * iam:threats:read on iam/threats/incidents.
     */
    summary: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<ThreatSummary> =>
      operation(
        credential,
        input.tenantId,
        'iam:threats:read',
        'threats/incidents',
        async ({ tx, tenant }) => {
          const now = ctx.now();
          const settings = resolveThreatSettings(await storedSettings(tx, tenant.id));
          const summary: ThreatSummary = {
            openIncidents: { low: 0, medium: 0, high: 0, critical: 0 },
            investigating: 0,
            riskyIdentities: { low: 0, medium: 0, high: 0 },
            contained: 0,
            detections24h: 0,
            byRule24h: {},
          };
          for (const incident of await tx.find<ThreatIncident>(threatCollections.incidents, {
            tenantId: tenant.id,
            status: 'open',
          }))
            summary.openIncidents[incident.severity]++;
          summary.investigating = (
            await tx.find(threatCollections.incidents, {
              tenantId: tenant.id,
              status: 'investigating',
            })
          ).length;
          for (const record of await tx.find<IdentityRisk>(threatCollections.risk, {
            tenantId: tenant.id,
          })) {
            const { level } = effectiveRisk(record, now, settings.riskHalfLifeHours);
            if (level === 'none' && !record.contained) continue;
            const identity = await tx.get<Identity>('identities', record.identityId);
            if (identity?.tenantId !== tenant.id || identity.status === 'deleted') continue;
            if (level !== 'none') summary.riskyIdentities[level]++;
            if (containment(identity, record)) summary.contained++;
          }
          for (const detection of await findOrdered<ThreatDetection>(
            tx,
            threatCollections.detections,
            { tenantId: tenant.id },
            { field: 'detectedAt', from: now - day },
          )) {
            summary.detections24h++;
            summary.byRule24h[detection.ruleId] = (summary.byRule24h[detection.ruleId] ?? 0) + 1;
          }
          const cursor = await tx.get<ThreatCursor>(threatCollections.cursors, tenant.id);
          if (cursor?.tenantId === tenant.id) summary.lastRunAt = cursor.updatedAt;
          return summary;
        },
      ),
    /**
     * "This wasn't me": the signed-in person reports suspicious activity on their own account, optionally with a
     * note (up to 1000 characters) and the id of the session they do not recognize. Records a `user-reported`
     * detection (raising their risk and opening an incident administrators see), ends every other session of the
     * account except API keys (the reporting session stays) and its pending sign-in challenges, forgets remembered
     * devices, and runs the tenant's playbooks. Needs only an ordinary sign-in session of the tenant (not an
     * impersonation); at most five reports a day; refused with FEATURE_DISABLED when the tenant turned the rule off.
     * Audited as `threat:user-report`, with the two responses as `threat:revoke-sessions` and `threat:forget-devices`.
     */
    reportSuspicious: async (
      credential: CredentialInput,
      input: { tenantId: string; note?: string; sessionId?: string },
    ): Promise<SuspiciousActivityReport> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const note = input.note === undefined ? undefined : multiline(input.note, 'note', 1000);
      const sessionId =
        input.sessionId === undefined ? undefined : text(input.sessionId, 'sessionId');
      const authenticated = await ctx.principals.authenticate(credential);
      const { report, responses } = await ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        if (principal.session.impersonatorId)
          throw new IamError(
            'IMPERSONATION_RESTRICTED',
            'Suspicious activity cannot be reported while impersonating',
            403,
          );
        const { identity, session } = principal;
        if (
          session.kind !== 'user' ||
          !actsInOwnRight(session) ||
          session.tenantId !== tenantId ||
          identity.tenantId !== tenantId
        )
          throw new IamError(
            'ACCESS_DENIED',
            'Suspicious activity is reported from a sign-in session of the account’s own tenant',
            403,
          );
        const realm = await ctx.tenant(tx, tenantId);
        const settings = resolveThreatSettings(await storedSettings(tx, tenantId));
        const rule = settings.rules['user-reported'];
        if (!rule.enabled)
          throw new IamError(
            'FEATURE_DISABLED',
            'This organization does not take reports of suspicious activity',
            403,
          );
        const now = ctx.now();
        const recent = await findOrdered<ThreatDetection>(
          tx,
          threatCollections.detections,
          { tenantId, ruleId: 'user-reported', identityId: identity.id },
          { field: 'detectedAt', from: now - day },
        );
        if (recent.length >= maxReportsPerDay)
          throw new IamError(
            'LIMIT_EXCEEDED',
            `At most ${maxReportsPerDay} reports a day; administrators already have the earlier ones`,
            409,
          );
        if (sessionId !== undefined) {
          const reported = await tx.get<Session>('sessions', sessionId);
          if (reported && (reported.identityId !== identity.id || reported.tenantId !== tenantId))
            throw new IamError('NOT_FOUND', 'Session not found', 404);
        }
        const subject: ThreatSubject = {
          type: 'identity',
          id: identity.id,
          name: personLabel(identity),
        };
        const candidate: DetectionCandidate = {
          ruleId: 'user-reported',
          severity: rule.severity,
          title: threatRule('user-reported').title,
          summary: `${personLabel(identity)} reported activity on their account that was not them.`,
          subject,
          identityId: identity.id,
          dedupeKey: id(),
          occurredAt: now,
          evidence: {
            eventIds: [],
            count: 1,
            firstAt: now,
            lastAt: now,
            identityIds: [identity.id],
            actions: ['threat:user-report'],
          },
          metadata: {
            ...(note !== undefined ? { note } : {}),
            ...(sessionId !== undefined ? { sessionId } : {}),
          },
        };
        const recorded = await recordDetection(ctx, tx, tenantId, candidate, settings, now);
        // The person's own responses, filed under the new incident: every other credential of the account ends
        // (API keys and the reporting session stay, pending sign-in challenges go), then remembered devices.
        const own = {
          subject,
          identityId: identity.id,
          incidentId: recorded.incident.id,
          detectionId: recorded.detection.id,
          reason: 'Reported by the account holder',
          actor: { principal },
        };
        const revoked = await applyResponse(
          ctx,
          tx,
          tenantId,
          { ...own, action: { kind: 'revoke-sessions', keepApiKeys: true } },
          settings,
        );
        const forgotten = await applyResponse(
          ctx,
          tx,
          tenantId,
          { ...own, action: { kind: 'forget-devices' } },
          settings,
        );
        const count = (response: ThreatResponse, key: string) => {
          const value = response.details?.[key];
          return typeof value === 'number' ? value : 0;
        };
        const report: SuspiciousActivityReport = {
          detectionId: recorded.detection.id,
          incidentId: recorded.incident.id,
          sessionsEnded: count(revoked, 'revoked'),
          devicesForgotten: count(forgotten, 'removed'),
        };
        await ctx.events.audit(
          tx,
          principal,
          'threat:user-report',
          realm.id,
          identity.id,
          'allow',
          false,
          {
            detectionId: report.detectionId,
            incidentId: report.incidentId,
            sessionsEnded: report.sessionsEnded,
            devicesForgotten: report.devicesForgotten,
            withNote: note !== undefined,
            ...(sessionId !== undefined ? { sessionId } : {}),
          },
        );
        return { report, responses: await playbooksFor(ctx, tx, tenantId, recorded, settings) };
      });
      await afterThreatResponses(ctx, tenantId, responses);
      return report;
    },
  };
}
