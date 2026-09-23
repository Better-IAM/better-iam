import {
  IamError,
  type AuditSessionContext,
  type AuthMethod,
  type AuthenticatedPrincipal,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Session,
} from '@better-iam/core';
import { newCredentialToken } from '@better-iam/auth';
import type { ServerContext } from './context.js';
import { tagKeyPattern } from './context-keys.js';
import type { Trust } from './models.js';
import { MAX_SESSION_TOKEN_LENGTH, type SessionTokenClaims } from './session-tokens.js';
import { hash } from './utils.js';

/**
 * Issuance core of temporary credentials (STS): role sessions (`roles.assume`, web identity) and session tokens
 * (`sts.getSessionToken`). The flows validate their inputs with the helpers below, build a draft session row, and
 * hand it to `mintCredential`, which issues either a typed opaque token (`biam_rol_…`, `biam_sts_…`) or an IAM-signed
 * session JWT and stores the row. The projections at the end (`temporaryCredential`, `callerIdentity`,
 * `roleSessionSummary`, `auditSessionContext`) are allowlists: they never carry hashes, policies, authority ids or
 * the source session id.
 */

/** How a temporary credential is delivered: a typed opaque token (default) or an IAM-signed session JWT. */
export type CredentialFormat = 'opaque' | 'jwt';

/** The session a temporary credential opens, as its issuer returns it. */
export interface TemporaryCredentialSession {
  id: string;
  tenantId: string;
  kind: Session['kind'];
  identityId: string;
  expiresAt: number;
  mfa: boolean;
  roleId?: string;
  trustId?: string;
  sessionName?: string;
  sourceIdentity?: string;
}

/** What every temporary-credential issuer returns. The token appears once, in the response body only. */
export interface TemporaryCredential {
  token: string;
  tokenType: 'Bearer';
  format: CredentialFormat;
  /** Epoch milliseconds; never later than the source credential's expiry. */
  expiresAt: number;
  /** Seconds from issuance to `expiresAt`. */
  expiresIn: number;
  /** Session JWTs: the audiences the token names. */
  audience?: string[];
  session: TemporaryCredentialSession;
}

/** `roles.assume`: a temporary credential whose session always names the role and the trust. */
export interface RoleCredential extends TemporaryCredential {
  session: TemporaryCredentialSession & { roleId: string; trustId: string };
}

/** `roles.assume` input (AWS AssumeRole). */
export interface AssumeRoleInput {
  /** The tenant of the role (the trust's tenant). */
  tenantId: string;
  trustId: string;
  /** Required when the trust was created with an external ID. */
  externalId?: string;
  /** 60 up to the trust's maximum (default 900, or less when the maximum is lower). */
  durationSeconds?: number;
  /** A scope-down policy: the session may do only what both the role and this policy allow. */
  policy?: PolicyDocument;
  /** A label for the session (/^[\w+=,.@-]{2,64}$/), exposed as principal.sessionName and in audit events. */
  sessionName?: string;
  /** The person or workload behind the call, when the trust's sourceIdentityMode permits or requires it. */
  sourceIdentity?: string;
  /** Session tags (principal.sessionTags.{key}); every key must be admitted by the trust's allowedTagKeys. */
  tags?: Record<string, string>;
  format?: CredentialFormat;
  /** Session JWTs only: 1 to 5 audiences from `sts.jwt.audiences` (default: the IAM issuer). */
  audience?: string[];
}

/** `sts.getSessionToken` input (AWS GetSessionToken). */
export interface GetSessionTokenInput {
  durationSeconds?: number;
  policy?: PolicyDocument;
  sessionName?: string;
  /** A current TOTP code: the token then carries a fresh MFA time (user sources with TOTP only). */
  mfaCode?: string;
  format?: CredentialFormat;
  audience?: string[];
}

/** `sts.getCallerIdentity`: who the presented credential acts as, for every session kind. */
export interface CallerIdentity {
  identityId: string;
  identityTenantId: string;
  identityKind: Identity['kind'];
  /** The tenant the session acts in (the role's tenant for role sessions). */
  tenantId: string;
  sessionId: string;
  sessionKind: Session['kind'];
  format: CredentialFormat;
  mfa: boolean;
  authenticatedAt: number;
  issuedAt: number;
  expiresAt: number;
  method?: AuthMethod;
  roleId?: string;
  trustId?: string;
  sourceTenantId?: string;
  sessionName?: string;
  sourceIdentity?: string;
  sessionTags?: Record<string, string>;
  audience?: string[];
  webIdentity?: { providerId: string; issuer: string; subject: string };
  impersonatorId?: string;
  /** Delegated sessions: the agent acting for the identity, and the delegation it acts under. */
  agentId?: string;
  delegationId?: string;
}

/** A live role session as `roles.listSessions` shows it to the target tenant. */
export interface RoleSessionSummary {
  id: string;
  roleId: string;
  trustId: string;
  identityId: string;
  sourceTenantId?: string;
  sessionName?: string;
  sourceIdentity?: string;
  webIdentity?: { providerId: string; subject: string };
  mfa: boolean;
  format: CredentialFormat;
  createdAt: number;
  expiresAt: number;
  clientIp?: string;
}

/** Duration bounds of a temporary credential, in seconds. */
export interface DurationBounds {
  min: number;
  max: number;
  /** Used when the caller asks for no duration. */
  fallback: number;
}

/** Session names and source identities: 2 to 64 characters of letters, digits and `+=,.@_-` (as in AWS STS). */
export const sessionNamePattern = /^[\w+=,.@-]{2,64}$/;
/** Session tag values: at most 256 letters, digits, whitespace and `_.:/=+-@`. */
const tagValuePattern = /^[\p{L}\p{N}\s_.:/=+\-@]*$/u;
/** Session JWT audiences, as for assertions: URL-safe identifiers of at most 256 characters. */
const audiencePattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const maxTags = 50;
const maxPackedTagBytes = 2048;
const maxAudiences = 5;

function invalid(message: string): never {
  throw new IamError('INVALID_INPUT', message);
}

/** A session name, or undefined when none was given. */
export function sessionNameValue(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !sessionNamePattern.test(value))
    invalid('sessionName must be 2-64 letters, digits or +=,.@_- characters');
  return value;
}

/** A caller-stated source identity, or undefined when none was given. */
export function sourceIdentityValue(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || !sessionNamePattern.test(value))
    invalid('sourceIdentity must be 2-64 letters, digits or +=,.@_- characters');
  return value;
}

/**
 * Session tags: at most 50, keys matching /^[A-Za-z][A-Za-z0-9_]{0,63}$/ and unique case-insensitively, values of at
 * most 256 characters from the tag value charset, and at most 2048 bytes as packed JSON. Undefined (or no tags) gives
 * undefined.
 */
export function sessionTagsValue(value: unknown): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value))
    invalid('tags must be an object of tag keys to string values');
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > maxTags) invalid(`tags may contain at most ${maxTags} entries`);
  const seen = new Set<string>();
  const tags: Record<string, string> = {};
  for (const [key, tag] of entries) {
    if (!tagKeyPattern.test(key))
      invalid(
        'Tag keys must start with a letter and use at most 64 letters, digits or underscores',
      );
    const folded = key.toLowerCase();
    if (seen.has(folded)) invalid(`Tag key ${key} is repeated (tag keys are case-insensitive)`);
    seen.add(folded);
    if (typeof tag !== 'string' || tag.length > 256 || !tagValuePattern.test(tag))
      invalid(`Tag ${key} must be a string of at most 256 letters, digits, spaces or _.:/=+-@`);
    tags[key] = tag;
  }
  if (!entries.length) return undefined;
  if (new TextEncoder().encode(JSON.stringify(tags)).length > maxPackedTagBytes)
    invalid(`tags must pack into at most ${maxPackedTagBytes} bytes`);
  return tags;
}

/** A trust's admitted session tag keys: at most 50 distinct tag keys, or exactly ['*'] for any key. */
export function allowedTagKeysValue(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > maxTags)
    invalid(`allowedTagKeys must be a list of at most ${maxTags} tag keys, or ['*']`);
  if (value.length === 1 && value[0] === '*') return ['*'];
  const seen = new Set<string>();
  for (const key of value) {
    if (typeof key !== 'string' || !tagKeyPattern.test(key))
      invalid(`allowedTagKeys must be a list of at most ${maxTags} tag keys, or ['*']`);
    const folded = key.toLowerCase();
    if (seen.has(folded)) invalid(`Tag key ${key} is repeated (tag keys are case-insensitive)`);
    seen.add(folded);
  }
  return [...(value as string[])];
}

/** The requested credential format; 'opaque' by default. */
export function credentialFormat(value: unknown): CredentialFormat {
  if (value === undefined) return 'opaque';
  if (value !== 'opaque' && value !== 'jwt') invalid("format must be 'opaque' or 'jwt'");
  return value;
}

/**
 * Requested JWT audiences: 1 to 5 URL-safe identifiers, deduplicated, and only with `format: 'jwt'`. Whether each is
 * on the deployment's allowlist and permitted to the caller is checked at issuance (`mintCredential`).
 */
export function audienceValue(value: unknown, format: CredentialFormat): string[] | undefined {
  if (value === undefined) return undefined;
  if (format !== 'jwt') invalid("audience requires format 'jwt'");
  if (!Array.isArray(value) || value.length < 1 || value.length > maxAudiences)
    invalid(`audience must list 1 to ${maxAudiences} audiences`);
  for (const audience of value)
    if (typeof audience !== 'string' || !audiencePattern.test(audience))
      invalid('audience entries must be URL-safe identifiers of at most 256 characters');
  return [...new Set(value as string[])];
}

/** The JWT lifetime cap, or no cap for opaque tokens (and deployments without `sts.jwt`, which refuse JWTs anyway). */
function formatCap(ctx: ServerContext, format: CredentialFormat): number {
  return format === 'jwt' && ctx.sessionTokens
    ? secondsOr(ctx.sessionTokens.maxLifetimeSeconds, defaultTrustMaxSessionSeconds)
    : Number.POSITIVE_INFINITY;
}

/** A trust's default maximum role session, used when it stores none (or none that is usable). */
const defaultTrustMaxSessionSeconds = 3600;

/**
 * A stored or configured duration limit in seconds, or `fallback` when it is not a positive safe integer. Limits
 * read from storage may be malformed (a string, NaN, a negative number), and `Math.min` over such a value yields NaN,
 * which every range check would accept; this fails closed to the default instead, which the other levels then clamp.
 */
function secondsOr(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

/**
 * Role session durations: the least of the deployment ceiling (`sts.maxRoleSessionSeconds`), the trust's
 * `maxSessionSeconds` (3600 when absent or not a positive integer) and, for JWTs, `sts.jwt.maxLifetimeSeconds`; 900 by
 * default or the maximum when that is lower. A lower level can only reduce the level above it.
 */
export function roleDurationBounds(
  ctx: ServerContext,
  trust: Pick<Trust, 'maxSessionSeconds'>,
  format: CredentialFormat,
): DurationBounds {
  const max = Math.min(
    secondsOr(ctx.config.sts.maxRoleSessionSeconds, defaultTrustMaxSessionSeconds),
    secondsOr(trust.maxSessionSeconds, defaultTrustMaxSessionSeconds),
    formatCap(ctx, format),
  );
  return { min: 60, max, fallback: Math.min(900, max) };
}

/**
 * Session token durations: the least of `sts.maxSessionTokenSeconds` and, for JWTs, `sts.jwt.maxLifetimeSeconds`;
 * 3600 by default or the maximum when that is lower. A limit that is not a positive integer counts as 3600.
 */
export function sessionTokenDurationBounds(
  ctx: ServerContext,
  format: CredentialFormat,
): DurationBounds {
  const max = Math.min(
    secondsOr(ctx.config.sts.maxSessionTokenSeconds, defaultTrustMaxSessionSeconds),
    formatCap(ctx, format),
  );
  return { min: 60, max, fallback: Math.min(3600, max) };
}

/** A requested duration within the bounds (the fallback when absent); anything outside is INVALID_INPUT, never clamped. */
export function durationWithin(value: unknown, bounds: DurationBounds): number {
  const seconds = value ?? bounds.fallback;
  if (
    typeof seconds !== 'number' ||
    !Number.isSafeInteger(seconds) ||
    seconds < bounds.min ||
    seconds > bounds.max
  )
    invalid(`durationSeconds must be an integer from ${bounds.min} to ${bounds.max}`);
  return seconds;
}

/**
 * Issues a temporary credential for a draft session row and stores the row. The draft carries every field except
 * the token material (`tokenHash` and `uniqueKey` are replaced; `format` and `audience` are set here).
 *
 * Opaque tokens are typed and checksummed (`biam_rol_…` for role sessions, `biam_sts_…` for session tokens). Session
 * JWTs need `sts.jwt` (FEATURE_DISABLED otherwise): every audience must be on the deployment's allowlist
 * (INVALID_INPUT), and each one other than the IAM issuer must be allowed as `iam:assertions:create` on `iam/{aud}`
 * for the drafted session (ACCESS_DENIED). The token is signed, bounded to 4096 characters, and its SHA-256 stored
 * like an opaque token's, so IAM re-validates the row on every use.
 */
export async function mintCredential(
  ctx: ServerContext,
  tx: IamStore,
  input: {
    identity: Identity;
    draft: Session;
    format: CredentialFormat;
    audience?: string[];
  },
): Promise<{ token: string; session: Session }> {
  const { identity, draft, format } = input;
  if (draft.kind !== 'role' && draft.kind !== 'session-token')
    throw new Error('mintCredential issues role sessions and session tokens only');
  const row: Session = { ...draft };
  delete row.format;
  delete row.audience;
  if (format === 'opaque') {
    if (input.audience !== undefined) invalid("audience requires format 'jwt'");
    const token = newCredentialToken(draft.kind === 'role' ? 'rol' : 'sts');
    row.tokenHash = hash(token);
    row.uniqueKey = row.tokenHash;
    return { token, session: await tx.insert<Session>('sessions', row) };
  }
  if (format !== 'jwt') invalid("format must be 'opaque' or 'jwt'");
  const signer = ctx.sessionTokens;
  if (!signer)
    throw new IamError(
      'FEATURE_DISABLED',
      'Session JWTs are not enabled on this deployment (sts.jwt)',
      403,
    );
  const audience = input.audience ?? [signer.issuer];
  if (audience.length < 1 || audience.length > maxAudiences)
    invalid(`audience must list 1 to ${maxAudiences} audiences`);
  for (const entry of audience)
    if (!signer.audiences.includes(entry))
      invalid(`audience ${entry} is not an allowed session token audience`);
  for (const entry of audience) {
    if (entry === signer.issuer) continue;
    const decision = await ctx.decisions.decide(
      tx,
      { identity, session: draft },
      {
        tenantId: draft.tenantId,
        action: 'iam:assertions:create',
        resource: { type: 'iam', id: entry },
      },
      true,
    );
    if (!decision.allowed)
      throw new IamError(
        'ACCESS_DENIED',
        `This credential may not obtain tokens for audience ${entry}`,
        403,
      );
  }
  const issuedAt = Math.floor(draft.createdAt / 1000);
  const expiresAt = Math.floor(draft.expiresAt / 1000);
  if (expiresAt - issuedAt > signer.maxLifetimeSeconds)
    invalid(`durationSeconds exceeds the session JWT lifetime of ${signer.maxLifetimeSeconds}`);
  const claims: SessionTokenClaims = {
    iss: signer.issuer,
    aud: audience.length === 1 ? audience[0]! : [...audience],
    sub: draft.identityId,
    tid: draft.tenantId,
    sid: draft.id,
    jti: draft.id,
    iat: issuedAt,
    nbf: issuedAt,
    exp: expiresAt,
    auth_time: Math.floor(draft.authenticatedAt / 1000),
    kind: draft.kind,
    mfa: draft.mfa,
  };
  if (typeof draft.roleId === 'string') claims.role = draft.roleId;
  if (typeof draft.trustId === 'string') claims.trust = draft.trustId;
  if (typeof draft.sourceTenantId === 'string') claims.src_tid = draft.sourceTenantId;
  if (typeof draft.sessionName === 'string') claims.session_name = draft.sessionName;
  if (typeof draft.sourceIdentity === 'string') claims.source_identity = draft.sourceIdentity;
  if (draft.webIdentity) {
    claims.idp = draft.webIdentity.providerId;
    claims.idp_sub = draft.webIdentity.subject;
  }
  const token = await signer.sign(claims);
  if (token.length > MAX_SESSION_TOKEN_LENGTH)
    invalid(`The session token would exceed ${MAX_SESSION_TOKEN_LENGTH} characters`);
  row.tokenHash = hash(token);
  row.uniqueKey = row.tokenHash;
  row.format = 'jwt';
  row.audience = [...audience];
  return { token, session: await tx.insert<Session>('sessions', row) };
}

function credentialFormatOf(session: Session): CredentialFormat {
  return session.format === 'jwt' ? 'jwt' : 'opaque';
}

/** The issuer response for a stored temporary session (an allowlist projection; the token is the only secret). */
export function temporaryCredential(
  token: string,
  session: Session,
  now: number,
): TemporaryCredential {
  const summary: TemporaryCredentialSession = {
    id: session.id,
    tenantId: session.tenantId,
    kind: session.kind,
    identityId: session.identityId,
    expiresAt: session.expiresAt,
    mfa: session.mfa,
  };
  if (typeof session.roleId === 'string') summary.roleId = session.roleId;
  if (typeof session.trustId === 'string') summary.trustId = session.trustId;
  if (typeof session.sessionName === 'string') summary.sessionName = session.sessionName;
  if (typeof session.sourceIdentity === 'string') summary.sourceIdentity = session.sourceIdentity;
  const credential: TemporaryCredential = {
    token,
    tokenType: 'Bearer',
    format: credentialFormatOf(session),
    expiresAt: session.expiresAt,
    expiresIn: Math.max(0, Math.floor((session.expiresAt - now) / 1000)),
    session: summary,
  };
  if (Array.isArray(session.audience)) credential.audience = [...session.audience];
  return credential;
}

/** `sts.getCallerIdentity`: an allowlist projection of a verified principal. */
export function callerIdentity(principal: AuthenticatedPrincipal): CallerIdentity {
  const { identity, session } = principal;
  const caller: CallerIdentity = {
    identityId: identity.id,
    identityTenantId: identity.tenantId,
    identityKind: identity.kind,
    tenantId: session.tenantId,
    sessionId: session.id,
    sessionKind: session.kind,
    format: credentialFormatOf(session),
    mfa: session.mfa,
    authenticatedAt: session.authenticatedAt,
    issuedAt: session.createdAt,
    expiresAt: session.expiresAt,
  };
  if (session.method !== undefined) caller.method = session.method;
  if (typeof session.roleId === 'string') caller.roleId = session.roleId;
  if (typeof session.trustId === 'string') caller.trustId = session.trustId;
  if (typeof session.sourceTenantId === 'string') caller.sourceTenantId = session.sourceTenantId;
  if (typeof session.sessionName === 'string') caller.sessionName = session.sessionName;
  if (typeof session.sourceIdentity === 'string') caller.sourceIdentity = session.sourceIdentity;
  if (session.sessionTags && Object.keys(session.sessionTags).length)
    caller.sessionTags = { ...session.sessionTags };
  if (Array.isArray(session.audience)) caller.audience = [...session.audience];
  if (session.webIdentity)
    caller.webIdentity = {
      providerId: session.webIdentity.providerId,
      issuer: session.webIdentity.issuer,
      subject: session.webIdentity.subject,
    };
  if (typeof session.impersonatorId === 'string') caller.impersonatorId = session.impersonatorId;
  if (typeof session.agentId === 'string') caller.agentId = session.agentId;
  if (typeof session.delegationId === 'string') caller.delegationId = session.delegationId;
  return caller;
}

/** `roles.listSessions`: an allowlist projection of a role session row. */
export function roleSessionSummary(session: Session): RoleSessionSummary {
  const summary: RoleSessionSummary = {
    id: session.id,
    roleId: session.roleId!,
    trustId: session.trustId!,
    identityId: session.identityId,
    mfa: session.mfa,
    format: credentialFormatOf(session),
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
  };
  if (typeof session.sourceTenantId === 'string') summary.sourceTenantId = session.sourceTenantId;
  if (typeof session.sessionName === 'string') summary.sessionName = session.sessionName;
  if (typeof session.sourceIdentity === 'string') summary.sourceIdentity = session.sourceIdentity;
  if (session.webIdentity)
    summary.webIdentity = {
      providerId: session.webIdentity.providerId,
      subject: session.webIdentity.subject,
    };
  // A cross-tenant role session was issued to a person of another tenant: their address is not the target tenant's
  // to see (its readers hold iam:trust:read, not access to the source tenant's sign-in records).
  const crossTenant =
    typeof session.sourceTenantId === 'string' && session.sourceTenantId !== session.tenantId;
  if (typeof session.client?.ip === 'string' && !crossTenant) summary.clientIp = session.client.ip;
  return summary;
}

/**
 * The session context recorded on an audit event (and its webhook body): which credential acted, and for temporary
 * credentials the role, trust, source tenant, session name, source identity and web identity behind it. Undefined for
 * simulated principals. Session ids are identifiers, not credentials; hashes, policies, tag values and authority ids
 * are never included.
 */
export function auditSessionContext(session: Session | undefined): AuditSessionContext | undefined {
  if (!session || typeof session.id !== 'string' || session.id === 'simulation') return undefined;
  const context: AuditSessionContext = { sessionId: session.id, kind: session.kind };
  if (typeof session.roleId === 'string') context.roleId = session.roleId;
  if (typeof session.trustId === 'string') context.trustId = session.trustId;
  if (typeof session.sourceTenantId === 'string') context.sourceTenantId = session.sourceTenantId;
  if (typeof session.sessionName === 'string') context.sessionName = session.sessionName;
  if (typeof session.sourceIdentity === 'string') context.sourceIdentity = session.sourceIdentity;
  if (session.webIdentity) {
    context.webIdentityProviderId = session.webIdentity.providerId;
    context.webIdentitySubject = session.webIdentity.subject.slice(0, 256);
  }
  if (session.format === 'jwt') context.format = 'jwt';
  // Delegated sessions: the agent that acted for the person, under which delegation.
  if (typeof session.agentId === 'string') context.agentId = session.agentId;
  if (typeof session.delegationId === 'string') context.delegationId = session.delegationId;
  return context;
}

/**
 * Deletes live role sessions of a role in a tenant created before `createdBefore` (eager revocation alongside a
 * watermark), optionally only those of one trust or one OIDC provider. Reads through the indexed roleId and returns
 * the number of rows deleted.
 */
export async function deleteTemporarySessions(
  tx: IamStore,
  filter: {
    tenantId: string;
    roleId: string;
    trustId?: string;
    providerId?: string;
    createdBefore: number;
  },
): Promise<number> {
  let deleted = 0;
  for (const session of await tx.find<Session>('sessions', { roleId: filter.roleId })) {
    if (
      session.kind !== 'role' ||
      session.tenantId !== filter.tenantId ||
      (filter.trustId !== undefined && session.trustId !== filter.trustId) ||
      (filter.providerId !== undefined && session.webIdentity?.providerId !== filter.providerId) ||
      !(session.createdAt < filter.createdBefore)
    )
      continue;
    await tx.delete('sessions', session.id);
    deleted++;
  }
  return deleted;
}
