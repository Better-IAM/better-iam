/**
 * Shared Signals (OpenID SSF 1.0 with CAEP and RISC): the pure pieces of receiving security events from an upstream
 * identity provider. Event-type URIs, subject identifiers (RFC 9493, the SSF `complex` format and the legacy RISC
 * `subject`), and a reader for the claims of a Security Event Token (RFC 8417) whose signature, issuer, audience and
 * `typ` the caller has already verified. No cryptography and no I/O: the server's signal receiver builds on it.
 */
import { canonicalizeJson } from './jcs.js';

const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
const RISC = 'https://schemas.openid.net/secevent/risc/event-type/';
const SSF = 'https://schemas.openid.net/secevent/ssf/event-type/';
/** The interim "Shared Signals and Events" drafts, before the framework was renamed SSF. */
const SSE = 'https://schemas.openid.net/secevent/sse/event-type/';

/**
 * The security events a receiver understands: CAEP (`session-revoked` through `risk-level-change`), RISC
 * (`account-disabled` through `sessions-revoked`, which RISC deprecated in favour of CAEP `session-revoked`) and the
 * SSF control events `verification` and `stream-updated`. Every other event type reads as `unknown`.
 */
export type SignalEventType =
  | 'session-revoked'
  | 'credential-change'
  | 'token-claims-change'
  | 'assurance-level-change'
  | 'device-compliance-change'
  | 'risk-level-change'
  | 'account-disabled'
  | 'account-enabled'
  | 'account-purged'
  | 'account-credential-change-required'
  | 'credential-compromise'
  | 'identifier-changed'
  | 'identifier-recycled'
  | 'sessions-revoked'
  | 'verification'
  | 'stream-updated'
  | 'unknown';

/** The event-type URI of each known security event, as SSF 1.0, CAEP 1.0 and RISC 1.0 name them. */
export const signalEventUris: Readonly<Record<Exclude<SignalEventType, 'unknown'>, string>> =
  Object.freeze({
    'session-revoked': `${CAEP}session-revoked`,
    'credential-change': `${CAEP}credential-change`,
    'token-claims-change': `${CAEP}token-claims-change`,
    'assurance-level-change': `${CAEP}assurance-level-change`,
    'device-compliance-change': `${CAEP}device-compliance-change`,
    'risk-level-change': `${CAEP}risk-level-change`,
    'account-disabled': `${RISC}account-disabled`,
    'account-enabled': `${RISC}account-enabled`,
    'account-purged': `${RISC}account-purged`,
    'account-credential-change-required': `${RISC}account-credential-change-required`,
    'credential-compromise': `${RISC}credential-compromise`,
    'identifier-changed': `${RISC}identifier-changed`,
    'identifier-recycled': `${RISC}identifier-recycled`,
    'sessions-revoked': `${RISC}sessions-revoked`,
    verification: `${SSF}verification`,
    'stream-updated': `${SSF}stream-updated`,
  });

const eventTypes = new Map<string, SignalEventType>([
  ...Object.entries(signalEventUris).map(([type, uri]) => [uri, type as SignalEventType] as const),
  // Before SSF 1.0 the control events lived under the RISC namespace (Google still sends them there) and, briefly,
  // under the SSE drafts' namespace.
  [`${RISC}verification`, 'verification'],
  [`${RISC}stream-updated`, 'stream-updated'],
  [`${SSE}verification`, 'verification'],
  [`${SSE}stream-updated`, 'stream-updated'],
]);

/** The event type an event-type URI names (exact match), or `unknown`. */
export function signalEventType(uri: string): SignalEventType {
  return (typeof uri === 'string' && eventTypes.get(uri)) || 'unknown';
}

/**
 * A subject identifier (RFC 9493 section 3, plus the SSF 1.0 `complex` format): who or what a security event is
 * about. `aliases` lists several identifiers of one subject; `complex` names a subject by its parts (the person, their
 * session, device, organization and so on), each an identifier of its own.
 */
export type SubjectIdentifier =
  | { format: 'iss_sub'; iss: string; sub: string }
  | { format: 'email'; email: string }
  | { format: 'opaque'; id: string }
  | { format: 'account'; uri: string }
  | { format: 'phone_number'; phone_number: string }
  | { format: 'did'; url: string }
  | { format: 'uri'; uri: string }
  | { format: 'aliases'; identifiers: SubjectIdentifier[] }
  | {
      format: 'complex';
      user?: SubjectIdentifier;
      session?: SubjectIdentifier;
      device?: SubjectIdentifier;
      tenant?: SubjectIdentifier;
      group?: SubjectIdentifier;
      application?: SubjectIdentifier;
      org_unit?: SubjectIdentifier;
    };

type ComplexSubject = Extract<SubjectIdentifier, { format: 'complex' }>;
type ComplexMember = Exclude<keyof ComplexSubject, 'format'>;
const complexMembers: readonly ComplexMember[] = [
  'user',
  'session',
  'device',
  'tenant',
  'group',
  'application',
  'org_unit',
];

/** The longest string a subject identifier or a SET claim this module reads may carry (UTF-16 code units). */
const MAX_STRING = 512;
/** Identifiers an `aliases` subject may list. */
const MAX_ALIASES = 10;
/** Levels of subject identifiers: a `complex` or `aliases` subject counts as one level, the identifiers inside as the next. */
const MAX_SUBJECT_DEPTH = 3;
/** Audiences a SET may name. */
const MAX_AUDIENCES = 20;
/** Levels of objects and arrays inside the event's own claims (the event object is level 1). */
const MAX_EVENT_DEPTH = 10;
/** NumericDate claims beyond this (about the year 5100) are treated as malformed, not as a far future. */
const MAX_SECONDS = 1e11;

const plainObject = (value: unknown): Record<string, unknown> | undefined =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
/** A member of the object itself, never one it inherits (`toString`, `constructor`). */
const own = (value: Record<string, unknown>, key: string): unknown =>
  Object.hasOwn(value, key) ? value[key] : undefined;

/** A string of 1 to 512 characters with no control characters (C0, DEL or C1). */
function text(value: unknown): value is string {
  if (typeof value !== 'string' || !value.length || value.length > MAX_STRING) return false;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) return false;
  }
  return true;
}

/** An address with a local part and a domain around its last `@`, and no whitespace. */
function emailAddress(value: unknown): value is string {
  if (!text(value) || /\s/.test(value)) return false;
  const at = value.lastIndexOf('@');
  return at > 0 && at < value.length - 1;
}

const accountUri = (value: unknown): value is string =>
  text(value) && /^acct:/i.test(value) && emailAddress(value.slice(5));
const didUrl = (value: unknown): value is string =>
  text(value) && /^did:[a-z0-9]+:\S+$/.test(value);
const genericUri = (value: unknown): value is string =>
  text(value) && /^[A-Za-z][A-Za-z0-9+.-]*:\S+$/.test(value);

interface SubjectScope {
  depth: number;
  inAliases: boolean;
  inComplex: boolean;
}

function readSubject(value: unknown, scope: SubjectScope): SubjectIdentifier | undefined {
  if (scope.depth > MAX_SUBJECT_DEPTH) return undefined;
  const subject = plainObject(value);
  if (!subject) return undefined;
  switch (own(subject, 'format')) {
    case 'iss_sub': {
      const iss = own(subject, 'iss');
      const sub = own(subject, 'sub');
      return text(iss) && text(sub) ? { format: 'iss_sub', iss, sub } : undefined;
    }
    case 'email': {
      const email = own(subject, 'email');
      return emailAddress(email) ? { format: 'email', email } : undefined;
    }
    case 'opaque': {
      const id = own(subject, 'id');
      return text(id) ? { format: 'opaque', id } : undefined;
    }
    case 'account': {
      const uri = own(subject, 'uri');
      return accountUri(uri) ? { format: 'account', uri } : undefined;
    }
    case 'phone_number': {
      const phone = own(subject, 'phone_number');
      return text(phone) ? { format: 'phone_number', phone_number: phone } : undefined;
    }
    case 'did': {
      const url = own(subject, 'url');
      return didUrl(url) ? { format: 'did', url } : undefined;
    }
    case 'uri': {
      const uri = own(subject, 'uri');
      return genericUri(uri) ? { format: 'uri', uri } : undefined;
    }
    case 'aliases': {
      // RFC 9493 section 3.2.8: an alias list never nests another, directly or through a complex subject.
      if (scope.inAliases) return undefined;
      const listed = own(subject, 'identifiers');
      if (!Array.isArray(listed) || !listed.length || listed.length > MAX_ALIASES) return undefined;
      const identifiers: SubjectIdentifier[] = [];
      for (const entry of listed) {
        const identifier = readSubject(entry, {
          ...scope,
          depth: scope.depth + 1,
          inAliases: true,
        });
        if (!identifier) return undefined;
        identifiers.push(identifier);
      }
      return { format: 'aliases', identifiers };
    }
    case 'complex': {
      // Each member names one part of the subject (a person, a session); a complex part is not one.
      if (scope.inComplex) return undefined;
      const complex: ComplexSubject = { format: 'complex' };
      let members = 0;
      for (const member of complexMembers) {
        const entry = own(subject, member);
        if (entry === undefined) continue;
        const identifier = readSubject(entry, {
          ...scope,
          depth: scope.depth + 1,
          inComplex: true,
        });
        if (!identifier) return undefined;
        complex[member] = identifier;
        members++;
      }
      return members ? complex : undefined;
    }
    default:
      return undefined;
  }
}

/**
 * Reads an RFC 9493 subject identifier (or an SSF `complex` one) strictly: known formats only, every string 1 to 512
 * characters without control characters, email, `acct:`, DID and URI values well formed, at most 10 aliases and no
 * alias list inside another, no complex subject inside another, and at most three levels of nesting. Members a format
 * does not define are left out of the result. Returns `undefined` for anything else.
 */
export function parseSubjectIdentifier(value: unknown): SubjectIdentifier | undefined {
  return readSubject(value, { depth: 1, inAliases: false, inComplex: false });
}

/**
 * Reads the subject of a legacy RISC event (Google's RISC, and SSF drafts before RFC 9493): `events[type].subject`
 * with a hyphenated `subject_type` instead of `format`. `iss-sub` (also spelled `iss_sub`), `email` and `phone` map to
 * their RFC 9493 formats; `id_token_claims` maps to whichever of `iss`+`sub`, `email` and `phone` it carries, as an
 * alias list when there are several. Returns `undefined` for other types and malformed values.
 */
export function legacyRiscSubject(value: unknown): SubjectIdentifier | undefined {
  const subject = plainObject(value);
  if (!subject) return undefined;
  const iss = own(subject, 'iss');
  const sub = own(subject, 'sub');
  const email = own(subject, 'email');
  const phone = own(subject, 'phone');
  switch (own(subject, 'subject_type')) {
    case 'iss-sub':
    case 'iss_sub':
      return text(iss) && text(sub) ? { format: 'iss_sub', iss, sub } : undefined;
    case 'email':
      return emailAddress(email) ? { format: 'email', email } : undefined;
    case 'phone':
      return text(phone) ? { format: 'phone_number', phone_number: phone } : undefined;
    case 'id_token_claims':
    case 'id-token-claims': {
      const identifiers: SubjectIdentifier[] = [];
      if (iss !== undefined || sub !== undefined) {
        if (!text(iss) || !text(sub)) return undefined;
        identifiers.push({ format: 'iss_sub', iss, sub });
      }
      if (email !== undefined) {
        if (!emailAddress(email)) return undefined;
        identifiers.push({ format: 'email', email });
      }
      if (phone !== undefined) {
        if (!text(phone)) return undefined;
        identifiers.push({ format: 'phone_number', phone_number: phone });
      }
      if (identifiers.length < 2) return identifiers[0];
      return { format: 'aliases', identifiers };
    }
    default:
      return undefined;
  }
}

/** Why a SET's claims were refused: the receiver answers the transmitter with `invalid_request` for each. */
export class SignalFormatError extends Error {
  constructor(
    public readonly reason: 'events' | 'subject' | 'nonce' | 'claims' | 'size',
    message: string,
  ) {
    super(message);
    this.name = 'SignalFormatError';
  }
}

/** The claims of a verified Security Event Token, normalized. */
export interface SecurityEventClaims {
  iss: string;
  /** The audiences it names (a single `aud` string becomes a one-entry list), without repeats. */
  aud: string[];
  /** Issued-at, in seconds as the SET carries it. */
  iat: number;
  /** The transmitter's unique id of this SET; receivers deduplicate on issuer and jti. */
  jti: string;
  /** Transaction id tying SETs about the same change together (RFC 8417 section 2.2). */
  txn?: string;
  /** The event-type URI, the single member of `events`. */
  eventUri: string;
  eventType: SignalEventType;
  /** The event's own claims (`reason_admin`, `current_level`, `credential_type`...), without a legacy `subject`. */
  event: Record<string, unknown>;
  /** The subject: top-level `sub_id` (RFC 9493 section 4.1) or the legacy `events[type].subject`. */
  subject?: SubjectIdentifier;
  /** When the event happened (CAEP `event_timestamp`, or the RFC 8417 `toe` claim), in epoch milliseconds. */
  eventTimestamp?: number;
}

function stringClaim(
  claims: Record<string, unknown>,
  name: string,
  required: boolean,
): string | undefined {
  const value = own(claims, name);
  if (value === undefined) {
    if (required)
      throw new SignalFormatError('claims', `The security event token has no ${name} claim`);
    return undefined;
  }
  if (typeof value !== 'string' || !value)
    throw new SignalFormatError('claims', `The security event token's ${name} claim is invalid`);
  if (value.length > MAX_STRING)
    throw new SignalFormatError('size', `The security event token's ${name} claim is too long`);
  if (!text(value))
    throw new SignalFormatError('claims', `The security event token's ${name} claim is invalid`);
  return value;
}

/** A NumericDate (seconds), or undefined when absent; throws for anything but a positive finite number. */
function numericDate(value: unknown, name: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value > MAX_SECONDS)
    throw new SignalFormatError('claims', `The security event token's ${name} is invalid`);
  return value;
}

function audiences(value: unknown): string[] {
  if (value === undefined)
    throw new SignalFormatError('claims', 'The security event token has no aud claim');
  const listed = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(listed) || !listed.length)
    throw new SignalFormatError('claims', "The security event token's aud claim is invalid");
  if (listed.length > MAX_AUDIENCES)
    throw new SignalFormatError('size', 'The security event token names too many audiences');
  for (const audience of listed) {
    if (typeof audience === 'string' && audience.length > MAX_STRING)
      throw new SignalFormatError('size', 'An audience of the security event token is too long');
    if (!text(audience))
      throw new SignalFormatError('claims', "The security event token's aud claim is invalid");
  }
  return [...new Set(listed as string[])];
}

/** True when objects and arrays inside `value` go deeper than `MAX_EVENT_DEPTH` levels (`value` is level `depth`). */
function nestedTooDeep(value: unknown, depth: number): boolean {
  if (value === null || typeof value !== 'object') return false;
  if (depth > MAX_EVENT_DEPTH) return true;
  const entries = Array.isArray(value) ? value : Object.values(value);
  return entries.some((entry) => nestedTooDeep(entry, depth + 1));
}

const withoutTrailingSlash = (issuer: string) => issuer.replace(/\/+$/, '');

/**
 * Reads the claims of a Security Event Token after its signature, issuer, audience and `typ` were verified (and before
 * it is acted on). The SET must carry `iss`, `aud` (a string or a list), `iat` and `jti`; `events` must hold exactly
 * one event, an object; a `nonce` claim (which only ID tokens carry) is refused so an ID token can never pass for a
 * SET. The subject is the top-level `sub_id` or the legacy `events[type].subject` (RFC 9493 or RISC `subject_type`
 * form); when both are present they must name the same subject, and a top-level `sub` must not contradict an
 * `iss_sub` subject of the same issuer. `event_timestamp` (or `toe`) seconds become milliseconds. Throws
 * `SignalFormatError` otherwise.
 */
export function readSecurityEvent(payload: Record<string, unknown>): SecurityEventClaims {
  const claims = plainObject(payload);
  if (!claims) throw new SignalFormatError('claims', 'The security event token has no claims');
  if (own(claims, 'nonce') !== undefined)
    throw new SignalFormatError('nonce', 'A security event token must not carry a nonce');
  const iss = stringClaim(claims, 'iss', true)!;
  const jti = stringClaim(claims, 'jti', true)!;
  const txn = stringClaim(claims, 'txn', false);
  const iat = numericDate(own(claims, 'iat'), 'iat claim');
  if (iat === undefined)
    throw new SignalFormatError('claims', 'The security event token has no iat claim');
  const aud = audiences(own(claims, 'aud'));

  const events = plainObject(own(claims, 'events'));
  if (!events)
    throw new SignalFormatError('events', 'The security event token has no events claim');
  const uris = Object.keys(events);
  if (uris.length !== 1)
    throw new SignalFormatError(
      'events',
      `A security event token carries exactly one event, not ${uris.length}`,
    );
  const eventUri = uris[0]!;
  if (eventUri.length > MAX_STRING)
    throw new SignalFormatError('size', 'The event type of the security event token is too long');
  if (!text(eventUri))
    throw new SignalFormatError('events', 'The event type of the security event token is invalid');
  const payloadEvent = plainObject(events[eventUri]);
  if (!payloadEvent)
    throw new SignalFormatError('events', 'The event of the security event token is not an object');
  if (nestedTooDeep(payloadEvent, 1))
    throw new SignalFormatError(
      'size',
      'The event of the security event token is nested too deeply',
    );
  const { subject: legacySubject, ...event } = payloadEvent;

  let subject: SubjectIdentifier | undefined;
  const subId = own(claims, 'sub_id');
  if (subId !== undefined) {
    subject = parseSubjectIdentifier(subId);
    if (!subject)
      throw new SignalFormatError('subject', 'The sub_id claim is not a valid subject identifier');
  }
  if (Object.hasOwn(payloadEvent, 'subject')) {
    const legacy = plainObject(legacySubject);
    const parsed =
      legacy && Object.hasOwn(legacy, 'format')
        ? parseSubjectIdentifier(legacy)
        : legacyRiscSubject(legacy);
    if (!parsed)
      throw new SignalFormatError(
        'subject',
        'The subject of the event is not a valid subject identifier',
      );
    if (subject && canonicalizeJson(subject) !== canonicalizeJson(parsed))
      throw new SignalFormatError(
        'subject',
        'The sub_id claim and the event name different subjects',
      );
    subject ??= parsed;
  }
  const sub = own(claims, 'sub');
  if (sub !== undefined) {
    if (typeof sub === 'string' && sub.length > MAX_STRING)
      throw new SignalFormatError('size', "The security event token's sub claim is too long");
    if (!text(sub))
      throw new SignalFormatError('claims', "The security event token's sub claim is invalid");
    const issuer = withoutTrailingSlash(iss);
    const contradicts = userSubjects(subject).some(
      (identifier) =>
        identifier.format === 'iss_sub' &&
        withoutTrailingSlash(identifier.iss) === issuer &&
        identifier.sub !== sub,
    );
    if (contradicts)
      throw new SignalFormatError('subject', 'The sub and sub_id claims name different subjects');
  }

  const eventSeconds = numericDate(own(event, 'event_timestamp'), 'event_timestamp');
  const toe = numericDate(own(claims, 'toe'), 'toe claim');
  const seconds = eventSeconds ?? toe;
  return {
    iss,
    aud,
    iat,
    jti,
    ...(txn === undefined ? {} : { txn }),
    eventUri,
    eventType: signalEventType(eventUri),
    event,
    ...(subject ? { subject } : {}),
    ...(seconds === undefined ? {} : { eventTimestamp: Math.round(seconds * 1000) }),
  };
}

/**
 * The identifiers in a subject that may name a person, without repeats: the subject itself when it is an `iss_sub`,
 * `email`, `opaque`, `account` or `phone_number` identifier, the `user` member of a complex subject, and each entry of
 * an alias list (expanded the same way). Session, device, organization, group and application parts, DIDs and plain
 * URIs name no person and are left out.
 */
export function userSubjects(subject: SubjectIdentifier | undefined): SubjectIdentifier[] {
  const found: SubjectIdentifier[] = [];
  const seen = new Set<string>();
  const visit = (identifier: SubjectIdentifier | undefined): void => {
    if (!identifier) return;
    switch (identifier.format) {
      case 'aliases':
        for (const entry of identifier.identifiers) visit(entry);
        return;
      case 'complex':
        visit(identifier.user);
        return;
      case 'iss_sub':
      case 'email':
      case 'opaque':
      case 'account':
      case 'phone_number': {
        const key = canonicalizeJson(identifier);
        if (seen.has(key)) return;
        seen.add(key);
        found.push(identifier);
        return;
      }
      default:
        return;
    }
  };
  visit(subject);
  return found;
}
