// Pure helpers behind the Threats pages (cloud/[org]/threats): labels, badge tones, and the request bodies the threat
// forms send. Type-only imports, so tests can load this file by relative path.
import type {
  DetectionStatus,
  IncidentResolution,
  IncidentStatus,
  ResponseAction,
  ResponseActionKind,
  RiskLevel,
  ThreatPlaybook,
  ThreatPlaybookInput,
  ThreatRuleId,
  ThreatRuleSettingInput,
  ThreatRuleView,
  ThreatSeverity,
  ThreatSubject,
  ThreatSubjectType,
} from 'better-iam/server';
import type { Tone } from '@/components/ui';

const minute = 60_000;
const hour = 60 * minute;
const day = 24 * hour;

export const severities: readonly ThreatSeverity[] = ['low', 'medium', 'high', 'critical'];
export const subjectTypes: readonly ThreatSubjectType[] = [
  'identity',
  'network',
  'tenant',
  'connection',
];
/** Response actions in the order the forms list them (and send them). */
export const responseKinds: readonly ResponseActionKind[] = [
  'revoke-sessions',
  'forget-devices',
  'contain',
  'block-network',
  'notify',
];

export function severityTone(severity: ThreatSeverity): Tone {
  return severity === 'critical' || severity === 'high'
    ? 'danger'
    : severity === 'medium'
      ? 'warning'
      : 'neutral';
}

export function riskTone(level: RiskLevel): Tone {
  return level === 'high'
    ? 'danger'
    : level === 'medium'
      ? 'warning'
      : level === 'low'
        ? 'accent'
        : 'neutral';
}

export function incidentStatusTone(status: IncidentStatus): Tone {
  return status === 'open' ? 'warning' : status === 'investigating' ? 'accent' : 'success';
}

export function detectionStatusTone(status: DetectionStatus): Tone {
  return status === 'open' ? 'warning' : status === 'resolved' ? 'success' : 'neutral';
}

export const subjectTypeLabels: Record<ThreatSubjectType, string> = {
  identity: 'Identity',
  network: 'Network',
  tenant: 'Organization',
  connection: 'Directory connection',
};

export const resolutionLabels: Record<IncidentResolution, string> = {
  'true-positive': 'Confirmed threat',
  'false-positive': 'False alarm',
  benign: 'Expected activity',
};

export const responseLabels: Record<ResponseActionKind | 'release', string> = {
  'revoke-sessions': 'End sessions',
  'forget-devices': 'Forget devices',
  contain: 'Contain',
  'block-network': 'Block network',
  notify: 'Notify',
  release: 'Release',
};

export const responseHelp: Record<ResponseActionKind, string> = {
  'revoke-sessions':
    'Signs the identity out everywhere; API keys keep working unless you say otherwise.',
  'forget-devices':
    'Removes remembered devices, so the next sign-in asks for the second factor again.',
  contain:
    'Disables the identity and ends its sessions until someone releases it; owners and root administrators are protected.',
  'block-network': 'Refuses sign-ins and requests from the network for a while.',
  notify: 'Emails the recipients set on the detection settings page.',
};

/** Why a response was skipped, in words. */
const skipReasons: Record<string, string> = {
  protected: 'protected identity',
  'no-network': 'no network to block',
  'invalid-network': 'not a blockable network',
  'trusted-network': 'trusted network',
  'already-applied': 'already in place',
  braked: 'automatic containment limit reached',
  'no-recipients': 'no recipients configured',
  'no-transport': 'email is not configured',
  'not-identity': 'not about an identity',
  'not-found': 'identity not found',
  inactive: 'identity is not active',
  'no-incident': 'no incident to report',
};

export function skipReason(reason: string | undefined): string {
  return reason ? (skipReasons[reason] ?? reason) : 'skipped';
}

/** A duration such as a rule window or a block length, in the largest whole unit. */
export function durationLabel(ms: number): string {
  if (ms % day === 0) return `${ms / day} day${ms === day ? '' : 's'}`;
  if (ms % hour === 0) return `${ms / hour} h`;
  if (ms % minute === 0) return `${ms / minute} min`;
  return `${Math.round(ms / 1000)} s`;
}

/** Where a detection's or incident's subject is managed in the console, when it has a page. */
export function subjectHref(
  base: string,
  subject: ThreatSubject,
  kind?: string,
): string | undefined {
  if (subject.type === 'identity') return identityHref(base, subject.id, kind);
  if (subject.type === 'connection') return `${base}/directory`;
  return undefined;
}

export function identityHref(base: string, identityId: string, kind?: string): string {
  return kind === 'agent'
    ? `${base}/agents/${encodeURIComponent(identityId)}`
    : `${base}/members/${encodeURIComponent(identityId)}`;
}

export function subjectLabel(subject: ThreatSubject): string {
  if (subject.type === 'tenant') return subject.name ?? 'This organization';
  return subject.name ?? subject.id;
}

/** Splits a list typed one per line or comma-separated. */
export function splitList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

/** Response actions for the kinds ticked on a form, in the canonical order, with their options. */
export function responseActions(
  kinds: readonly ResponseActionKind[],
  options: { blockHours?: number; keepApiKeys?: boolean } = {},
): ResponseAction[] {
  return responseKinds
    .filter((kind) => kinds.includes(kind))
    .map((kind): ResponseAction => {
      if (kind === 'block-network' && options.blockHours !== undefined)
        return { kind, durationMs: Math.round(options.blockHours * hour) };
      if (kind === 'revoke-sessions' && options.keepApiKeys === false)
        return { kind, keepApiKeys: false };
      return { kind };
    });
}

export function actionsSummary(actions: readonly ResponseAction[]): string {
  return actions
    .map((action) => {
      const label = responseLabels[action.kind];
      if (action.kind === 'block-network')
        return `${label} for ${durationLabel(action.durationMs ?? day)}`;
      if (action.kind === 'revoke-sessions' && action.keepApiKeys === false)
        return `${label} and API keys`;
      return label;
    })
    .join(', ');
}

export function triggerSummary(
  trigger: ThreatPlaybook['trigger'],
  ruleTitle: (ruleId: string) => string,
): string {
  const parts = [
    trigger.ruleIds?.length ? trigger.ruleIds.map(ruleTitle).join(', ') : 'any rule',
    ...(trigger.minSeverity ? [`${trigger.minSeverity} severity or higher`] : []),
    ...(trigger.subjectTypes?.length
      ? [
          `about ${trigger.subjectTypes.map((type) => subjectTypeLabels[type].toLowerCase()).join(' or ')}`,
        ]
      : []),
  ];
  return parts.join(' · ');
}

/** What a rule row on the settings page holds while it is being edited. */
export interface RuleDraft {
  enabled: boolean;
  severity: ThreatSeverity;
  /** As typed; empty keeps the default. */
  threshold: string;
  /** Minutes as typed; empty keeps the default. */
  windowMinutes: string;
  everyone: boolean;
}

export function ruleDraft(rule: ThreatRuleView): RuleDraft {
  return {
    enabled: rule.enabled,
    severity: rule.severity,
    threshold: rule.threshold === undefined ? '' : String(rule.threshold),
    windowMinutes: rule.windowMs === undefined ? '' : String(rule.windowMs / minute),
    everyone: rule.everyone === true,
  };
}

/**
 * The `threats.configure` change for one rule: every field that matches the rule's built-in default is sent as `null`
 * (so the rule stops counting as customized), everything else as its value. Fields the rule cannot tune are left out.
 */
export function ruleSettingChange(rule: ThreatRuleView, draft: RuleDraft): ThreatRuleSettingInput {
  const change: ThreatRuleSettingInput = {
    enabled: draft.enabled === rule.defaults.enabled ? null : draft.enabled,
    severity: draft.severity === rule.defaults.severity ? null : draft.severity,
  };
  if (rule.tunable?.threshold) {
    const threshold = draft.threshold.trim() === '' ? undefined : Number(draft.threshold);
    change.threshold =
      threshold === undefined || threshold === rule.defaults.threshold ? null : threshold;
  }
  if (rule.tunable?.windowMs) {
    const windowMs =
      draft.windowMinutes.trim() === ''
        ? undefined
        : Math.round(Number(draft.windowMinutes) * minute);
    change.windowMs =
      windowMs === undefined || windowMs === rule.defaults.windowMs ? null : windowMs;
  }
  if (rule.id === 'new-network') change.everyone = draft.everyone ? true : null;
  return change;
}

/** Whether a rule row differs from the setting in force (an emptied number stands for the rule's default). */
export function ruleDraftChanged(rule: ThreatRuleView, draft: RuleDraft): boolean {
  const typed = (value: string) => (value.trim() === '' ? undefined : Number(value));
  const minutes = typed(draft.windowMinutes);
  const threshold = typed(draft.threshold) ?? rule.defaults.threshold;
  const windowMs = minutes === undefined ? rule.defaults.windowMs : Math.round(minutes * minute);
  return (
    draft.enabled !== rule.enabled ||
    draft.severity !== rule.severity ||
    (rule.tunable?.threshold !== undefined && threshold !== rule.threshold) ||
    (rule.tunable?.windowMs !== undefined && windowMs !== rule.windowMs) ||
    (rule.id === 'new-network' && draft.everyone !== (rule.everyone === true))
  );
}

/** What the playbook form holds. */
export interface PlaybookDraft {
  name: string;
  description: string;
  enabled: boolean;
  ruleIds: string[];
  /** Empty matches every severity. */
  minSeverity: string;
  subjectTypes: string[];
  actions: ResponseActionKind[];
  blockHours: string;
  keepApiKeys: boolean;
}

export function playbookDraft(playbook?: ThreatPlaybook): PlaybookDraft {
  const block = playbook?.actions.find((action) => action.kind === 'block-network');
  const revoke = playbook?.actions.find((action) => action.kind === 'revoke-sessions');
  return {
    name: playbook?.name ?? '',
    description: playbook?.description ?? '',
    enabled: playbook?.enabled ?? true,
    ruleIds: playbook?.trigger.ruleIds ?? [],
    minSeverity: playbook?.trigger.minSeverity ?? '',
    subjectTypes: playbook?.trigger.subjectTypes ?? [],
    actions: playbook?.actions.map((action) => action.kind) ?? [],
    blockHours: String((block?.durationMs ?? day) / hour),
    keepApiKeys: revoke?.keepApiKeys !== false,
  };
}

/**
 * The body of `threats.createPlaybook` (or `updatePlaybook`, which replaces the trigger and actions as a whole and
 * clears an emptied description, but leaves `enabled` to the list's own switch so an open edit form never reverts
 * it). Trigger fields left empty match every detection.
 */
export function playbookBody(
  draft: PlaybookDraft,
  update: boolean,
): Omit<ThreatPlaybookInput, 'description'> & { description?: string | null } {
  const description = draft.description.trim();
  const blockHours = Number(draft.blockHours);
  return {
    name: draft.name.trim(),
    ...(description ? { description } : update ? { description: null } : {}),
    ...(update ? {} : { enabled: draft.enabled }),
    trigger: {
      ...(draft.ruleIds.length ? { ruleIds: draft.ruleIds as ThreatRuleId[] } : {}),
      ...(draft.minSeverity ? { minSeverity: draft.minSeverity as ThreatSeverity } : {}),
      ...(draft.subjectTypes.length
        ? { subjectTypes: draft.subjectTypes as ThreatSubjectType[] }
        : {}),
    },
    actions: responseActions(draft.actions, {
      ...(draft.blockHours.trim() && Number.isFinite(blockHours) ? { blockHours } : {}),
      keepApiKeys: draft.keepApiKeys,
    }),
  };
}
