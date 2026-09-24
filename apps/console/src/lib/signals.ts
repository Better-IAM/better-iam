// Pure helpers behind the Shared Signals pages (cloud/[org]/signals): labels, badge tones, subject summaries, and the
// request bodies the source forms send. Type-only imports, so tests can load this file by relative path.
import type {
  SignalAction,
  SignalActionableEvent,
  SignalAlgorithm,
  SignalDelivery,
  SignalEventType,
  SignalSourceCreateInput,
  SignalSourceUpdateInput,
  SignalSourceView,
  SignalStatus,
  SignalSubjectMapping,
} from 'better-iam/server';
import type { Tone } from '@/components/ui';

export const signalStatuses: readonly SignalStatus[] = [
  'applied',
  'recorded',
  'unmatched',
  'ignored',
  'failed',
];

/** Every algorithm a source may allow, strongest families first; HMAC and `none` are never accepted. */
export const signalAlgorithms: readonly SignalAlgorithm[] = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'EdDSA',
];
/** What the server allows when a source names no algorithms. */
export const defaultSignalAlgorithms: readonly SignalAlgorithm[] = [
  'RS256',
  'ES256',
  'PS256',
  'EdDSA',
];

export function signalStatusTone(status: SignalStatus): Tone {
  return status === 'applied'
    ? 'success'
    : status === 'recorded'
      ? 'accent'
      : status === 'unmatched'
        ? 'warning'
        : status === 'failed'
          ? 'danger'
          : 'neutral';
}

export const signalStatusHelp: Record<SignalStatus, string> = {
  applied: 'Matched a person, and the configured action ran.',
  recorded: 'Kept for the record and for threat detection; nothing else to do.',
  unmatched: 'No person of this organization matched the subject.',
  ignored: 'An unsupported event, or an action refused for a protected person.',
  failed: 'Processing failed; reprocess it once the cause is fixed.',
};

export const eventTypeLabels: Record<SignalEventType, string> = {
  'session-revoked': 'Session revoked',
  'credential-change': 'Credential changed',
  'token-claims-change': 'Token claims changed',
  'assurance-level-change': 'Assurance level changed',
  'device-compliance-change': 'Device compliance changed',
  'risk-level-change': 'Risk level changed',
  'account-disabled': 'Account disabled',
  'account-enabled': 'Account enabled',
  'account-purged': 'Account deleted',
  'account-credential-change-required': 'Credential change required',
  'credential-compromise': 'Credential compromised',
  'identifier-changed': 'Identifier changed',
  'identifier-recycled': 'Identifier recycled',
  'sessions-revoked': 'Sessions revoked (legacy)',
  verification: 'Stream verification',
  'stream-updated': 'Stream status changed',
  unknown: 'Unsupported event',
};

/**
 * The event types a source can configure an action for, in the order the forms list them, with what each one means.
 * A `Record` so a new event type fails the typecheck until it is described here.
 */
export const actionableEventHelp: Record<SignalActionableEvent, string> = {
  'session-revoked': "The provider ended one of the person's sessions (CAEP).",
  'sessions-revoked': "The provider ended all of the person's sessions (RISC, deprecated).",
  'credential-compromise': 'A password or other credential of the person is known to be stolen.',
  'account-disabled': "The provider disabled the person's account.",
  'account-purged': "The provider deleted the person's account.",
  'account-credential-change-required': 'The provider requires the person to change a credential.',
  'credential-change': 'The person added, changed or removed a credential.',
  'risk-level-change': "The provider's risk assessment of the person changed.",
  'token-claims-change': "Claims in the person's tokens changed, such as group memberships.",
  'assurance-level-change': 'The authentication assurance level of a session changed.',
  'device-compliance-change': 'A device of the person became compliant or non-compliant.',
  'account-enabled': "The provider enabled the person's account again.",
  'identifier-changed': "The person's email address or phone number changed.",
  'identifier-recycled': 'An identifier now belongs to someone else.',
};
export const actionableEventTypes = Object.keys(actionableEventHelp) as SignalActionableEvent[];

/** Why an event was not applied, in words. */
const reasons: Record<string, string> = {
  'no-match': 'no person matched the subject',
  'no-subject': 'the event named no subject',
  protected: 'root administrators are protected',
  'unsupported-event': 'unsupported event type',
};

export function signalReason(reason: string | undefined): string | undefined {
  return reason === undefined ? undefined : (reasons[reason] ?? reason);
}

const text = (value: unknown): string | undefined =>
  typeof value === 'string' && value ? value : undefined;
const record = (value: unknown): Record<string, unknown> | undefined =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;

/** A stored subject (RFC 9493 form) in one line: `sub at issuer`, an email address, an opaque id, and so on. */
export function subjectSummary(subject: unknown): string {
  const value = record(subject);
  if (!value) return '—';
  if (value._truncated === true) return `${text(value.format) ?? 'subject'} (too large to keep)`;
  switch (value.format) {
    case 'iss_sub':
      return `${text(value.sub) ?? '?'} at ${text(value.iss) ?? '?'}`;
    case 'email':
      return text(value.email) ?? '—';
    case 'opaque':
      return `id ${text(value.id) ?? '?'}`;
    case 'account':
    case 'uri':
      return text(value.uri) ?? '—';
    case 'phone_number':
      return text(value.phone_number) ?? '—';
    case 'did':
      return text(value.url) ?? '—';
    case 'aliases': {
      const identifiers = Array.isArray(value.identifiers) ? value.identifiers : [];
      return identifiers.map(subjectSummary).join(' / ') || '—';
    }
    case 'complex': {
      const parts = (
        ['user', 'session', 'device', 'tenant', 'group', 'application', 'org_unit'] as const
      )
        .filter((member) => record(value[member]))
        .map((member) =>
          member === 'user'
            ? subjectSummary(value[member])
            : `${member.replace('_', ' ')} ${subjectSummary(value[member])}`,
        );
      return parts.join(' · ') || '—';
    }
    default:
      return text(value.format) ?? '—';
  }
}

/** A localized claim (CAEP `reason_admin` is a language map; some transmitters send a plain string). */
function localized(value: unknown): string | undefined {
  if (typeof value === 'string') return value || undefined;
  const map = record(value);
  if (!map) return undefined;
  return (
    text(map.en) ?? Object.values(map).find((entry): entry is string => typeof entry === 'string')
  );
}

/** The claims worth showing next to an event (risk level, credential type, the transmitter's reason), in one line. */
export function claimsSummary(eventType: SignalEventType, claims: unknown): string | undefined {
  const value = record(claims);
  if (!value) return undefined;
  const parts: string[] = [];
  if (eventType === 'risk-level-change') {
    const current = text(value.current_level);
    const previous = text(value.previous_level);
    if (current) parts.push(previous ? `${previous} → ${current}` : `now ${current}`);
  }
  if (eventType === 'device-compliance-change') {
    const current = text(value.current_status);
    if (current) parts.push(current);
  }
  if (eventType === 'stream-updated') {
    const status = text(value.status);
    if (status) parts.push(`stream ${status}`);
  }
  const credential = text(value.credential_type);
  if (credential) parts.push([credential, text(value.change_type)].filter(Boolean).join(' '));
  const reason = localized(value.reason_admin) ?? localized(value.reason);
  if (reason) parts.push(reason.length > 160 ? `${reason.slice(0, 159)}…` : reason);
  return parts.length ? parts.join(' · ') : undefined;
}

/** Splits a list typed one per line or comma-separated, dropping blanks and repeats. */
export function splitEntries(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ];
}

/** Where a source's verification keys come from. */
export type KeySourceMode = 'discover' | 'jwksUri' | 'jwks';

/** What the source settings form holds, as typed. */
export interface SourceDraft {
  name: string;
  issuer: string;
  /** One per line. */
  issuerAliases: string;
  /** One per line. */
  audiences: string;
  keys: KeySourceMode;
  jwksUri: string;
  /** A JSON key set, `{ "keys": [...] }`. */
  jwks: string;
  algorithms: SignalAlgorithm[];
  requireTyp: boolean;
  delivery: SignalDelivery;
  /** Push sources being created: generate a bearer token the transmitter must send. */
  pushToken: boolean;
  pollEndpoint: string;
  /** Empty on an existing source: the stored token is never shown, and a new one replaces it. */
  pollToken: string;
  pollMaxEvents: string;
}

export function sourceDraft(source?: SignalSourceView): SourceDraft {
  return {
    name: source?.name ?? '',
    issuer: source?.issuer ?? '',
    issuerAliases: source?.issuerAliases.join('\n') ?? '',
    audiences: source?.audiences.join('\n') ?? '',
    keys: source?.jwks ? 'jwks' : source?.jwksUri ? 'jwksUri' : 'discover',
    jwksUri: source?.jwksUri ?? '',
    jwks: source?.jwks ? JSON.stringify(source.jwks, null, 2) : '',
    algorithms: source ? [...source.algorithms] : [...defaultSignalAlgorithms],
    requireTyp: source?.requireTyp ?? true,
    delivery: source?.delivery ?? 'push',
    pushToken: true,
    pollEndpoint: source?.poll?.endpoint ?? '',
    pollToken: '',
    pollMaxEvents: String(source?.poll?.maxEvents ?? 25),
  };
}

/** The static key set typed on the form, checked for shape only (the server checks the keys themselves). */
function parsedKeys(value: string): NonNullable<SignalSourceCreateInput['jwks']> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('Static keys must be valid JSON');
  }
  const keys = record(parsed)?.keys;
  if (!Array.isArray(keys) || !keys.length)
    throw new Error('Static keys must be a key set: { "keys": [ … ] }');
  return parsed as NonNullable<SignalSourceCreateInput['jwks']>;
}

function maxEvents(value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 100)
    throw new Error('Events per request must be a whole number from 1 to 100');
  return parsed;
}

/** What the subject mapping form holds. */
export interface MappingDraft {
  /** Sign-in connection ids, one per line. */
  connectionIds: string;
  scimConnectionIds: string[];
  matchEmail: boolean;
}

export function mappingDraft(mapping?: SignalSubjectMapping): MappingDraft {
  return {
    connectionIds: mapping?.connectionIds.join('\n') ?? '',
    scimConnectionIds: mapping ? [...mapping.scimConnectionIds] : [],
    matchEmail: mapping?.matchEmail ?? false,
  };
}

export function mappingBody(draft: MappingDraft): SignalSubjectMapping {
  return {
    connectionIds: splitEntries(draft.connectionIds),
    scimConnectionIds: [...new Set(draft.scimConnectionIds)],
    matchEmail: draft.matchEmail,
  };
}

/** The mapping as stored, for comparing with a draft. */
function sameMapping(a: SignalSubjectMapping, b: SignalSubjectMapping): boolean {
  const sorted = (list: string[]) => JSON.stringify([...list].sort());
  return (
    a.matchEmail === b.matchEmail &&
    sorted(a.connectionIds) === sorted(b.connectionIds) &&
    sorted(a.scimConnectionIds) === sorted(b.scimConnectionIds)
  );
}

/** The action map as sent: only the event types that do more than record (unlisted types are recorded). */
export function actionsBody(
  actions: Partial<Record<SignalActionableEvent, SignalAction>>,
): Partial<Record<SignalActionableEvent, SignalAction>> {
  return Object.fromEntries(
    actionableEventTypes
      .filter((type) => actions[type] === 'revoke-sessions')
      .map((type) => [type, 'revoke-sessions' as const]),
  );
}

function sameActions(
  a: Partial<Record<SignalActionableEvent, SignalAction>>,
  b: Partial<Record<SignalActionableEvent, SignalAction>>,
): boolean {
  return JSON.stringify(actionsBody(a)) === JSON.stringify(actionsBody(b));
}

/** The `signals.createSource` body for the create form. Throws an `Error` with a message for input it can tell is wrong. */
export function createSourceBody(
  tenantId: string,
  draft: SourceDraft,
  mapping: MappingDraft,
  actions: Partial<Record<SignalActionableEvent, SignalAction>>,
): SignalSourceCreateInput {
  const issuerAliases = splitEntries(draft.issuerAliases);
  if (!draft.algorithms.length) throw new Error('Allow at least one signature algorithm');
  return {
    tenantId,
    name: draft.name.trim(),
    issuer: draft.issuer.trim(),
    ...(issuerAliases.length ? { issuerAliases } : {}),
    audiences: splitEntries(draft.audiences),
    ...(draft.keys === 'jwksUri' ? { jwksUri: draft.jwksUri.trim() } : {}),
    ...(draft.keys === 'jwks' ? { jwks: parsedKeys(draft.jwks) } : {}),
    algorithms: [...draft.algorithms],
    delivery: draft.delivery,
    ...(draft.delivery === 'push'
      ? { pushToken: draft.pushToken }
      : {
          poll: {
            endpoint: draft.pollEndpoint.trim(),
            token: draft.pollToken.trim(),
            maxEvents: maxEvents(draft.pollMaxEvents),
          },
        }),
    subjects: mappingBody(mapping),
    actions: actionsBody(actions),
    requireTyp: draft.requireTyp,
  };
}

type SourceChanges = Omit<SignalSourceUpdateInput, 'tenantId' | 'sourceId'>;

/**
 * The `signals.updateSource` change for the settings form: only the fields that differ from the source (an empty
 * result means nothing changed). Switching where keys come from clears the other setting; a new poll endpoint needs
 * the token again, which the server enforces.
 */
export function sourceSettingsChange(source: SignalSourceView, draft: SourceDraft): SourceChanges {
  const change: SourceChanges = {};
  const name = draft.name.trim();
  if (name !== source.name) change.name = name;
  const aliases = splitEntries(draft.issuerAliases);
  if (JSON.stringify(aliases) !== JSON.stringify(source.issuerAliases))
    change.issuerAliases = aliases;
  const audiences = splitEntries(draft.audiences);
  if (JSON.stringify(audiences) !== JSON.stringify(source.audiences)) change.audiences = audiences;
  if (draft.keys === 'jwksUri') {
    const jwksUri = draft.jwksUri.trim();
    if (jwksUri !== source.jwksUri) change.jwksUri = jwksUri;
  } else if (source.jwksUri !== undefined) change.jwksUri = null;
  if (draft.keys === 'jwks') {
    const jwks = parsedKeys(draft.jwks);
    if (JSON.stringify(jwks) !== JSON.stringify(source.jwks)) change.jwks = jwks;
  } else if (source.jwks !== undefined) change.jwks = null;
  if (!draft.algorithms.length) throw new Error('Allow at least one signature algorithm');
  if (
    JSON.stringify([...draft.algorithms].sort()) !== JSON.stringify([...source.algorithms].sort())
  )
    change.algorithms = [...draft.algorithms];
  if (draft.requireTyp !== source.requireTyp) change.requireTyp = draft.requireTyp;
  if (source.delivery === 'poll' && source.poll) {
    const poll: NonNullable<SourceChanges['poll']> = {};
    const endpoint = draft.pollEndpoint.trim();
    if (endpoint !== source.poll.endpoint) poll.endpoint = endpoint;
    const token = draft.pollToken.trim();
    if (token) poll.token = token;
    const events = maxEvents(draft.pollMaxEvents);
    if (events !== source.poll.maxEvents) poll.maxEvents = events;
    if (Object.keys(poll).length) change.poll = poll;
  }
  return change;
}

/** The `signals.updateSource` change for the mapping form, or undefined when it matches the source. */
export function mappingChange(
  source: SignalSourceView,
  draft: MappingDraft,
): SignalSubjectMapping | undefined {
  const next = mappingBody(draft);
  return sameMapping(next, source.subjects) ? undefined : next;
}

/** The `signals.updateSource` action map for the actions form, or undefined when it matches the source. */
export function actionsChange(
  source: SignalSourceView,
  actions: Partial<Record<SignalActionableEvent, SignalAction>>,
): Partial<Record<SignalActionableEvent, SignalAction>> | undefined {
  return sameActions(actions, source.actions) ? undefined : actionsBody(actions);
}

/** A poll run in one sentence. */
export function pollSummary(result: {
  received: number;
  acknowledged: number;
  errors: number;
}): string {
  const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`;
  return [
    `${plural(result.received, 'new event')}, ${result.acknowledged} acknowledged`,
    ...(result.errors ? [`${plural(result.errors, 'error')} (see the source\'s last error)`] : []),
  ].join(', ');
}
