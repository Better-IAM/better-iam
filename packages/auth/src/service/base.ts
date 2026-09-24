import { AsyncLocalStorage } from 'node:async_hooks';
import { createHmac } from 'node:crypto';
import argon2 from 'argon2';
import {
  IamError,
  appendAuditEvent,
  ipCounterKey,
  ipMatches,
  isIpRange,
  type AuditEvent,
  type AuthMethod,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type OutboxMessage,
  type Session,
  type SessionClientInfo,
  type SignInRecord,
  type Tenant,
} from '@better-iam/core';
import { hashToken, newCredentialToken, newId, newToken, parseCredentialToken } from '../crypto.js';
import {
  dispatchOutbox,
  enqueueDelivery,
  type DispatchResult,
  type OutboxContext,
} from '../outbox.js';
import { resolveRateLimits, type ResolvedRateLimits } from '../rate-limit.js';
import type {
  AuthOptions,
  Challenge,
  DeliveryMessage,
  MfaRecord,
  NetworkBlock,
  PasswordHistoryRecord,
  SessionResult,
  SignInFailureReason,
  SignInLedger,
  SignInResult,
  TrustedDevice,
} from '../types.js';
import { displayName, email, password, publicSession, text } from '../validation.js';
import { assertPasswordRules } from '../password-policy.js';

/** Previous password hashes kept per identity; `passwordHistory` policies may use up to this many. */
const PASSWORD_HISTORY_LIMIT = 24;
/** How long a tenant's network block list is reused before storage is read again. */
const BLOCK_CACHE_MS = 5_000;

/** A bound session presented from another network; `authenticate` records it after the refusal rolled back. */
class SessionNetworkMismatch extends IamError {
  constructor(
    readonly session: Session,
    readonly presentedIp: string,
  ) {
    super(
      'SESSION_NETWORK_MISMATCH',
      'This session can only be used from the network it was signed in from',
      401,
    );
  }
}

/**
 * The address a request arrived on, as the HTTP layer resolved it: `origin` is the request's trusted `Origin` (an
 * organization's own address counts), and `tenantId` the organization that address belongs to, if any.
 */
export interface RequestHost {
  origin?: string;
  tenantId?: string;
}

/** The public part of a sign-in ledger, as stamped on a new session. */
function signInSummary(ledger: SignInLedger): SignInRecord {
  const summary: SignInRecord = { failedAttempts: ledger.failedAttempts };
  if (ledger.lastAt !== undefined) summary.lastAt = ledger.lastAt;
  if (ledger.lastClient) summary.lastClient = ledger.lastClient;
  if (ledger.lastFailedAt !== undefined) summary.lastFailedAt = ledger.lastFailedAt;
  if (ledger.lastFailedClient) summary.lastFailedClient = ledger.lastFailedClient;
  return summary;
}

/**
 * Configuration, storage primitives, and the session core shared by every authentication feature.
 * Feature classes extend this in a chain (sessions, account, passwordless, MFA, passkeys) so each concern
 * lives in its own module while `this` keeps the whole service available.
 */
export class AuthBase {
  protected readonly now: () => number;
  protected readonly origins: string[];
  protected readonly sessionLifetime: number;
  protected readonly idleLifetime: number;
  protected readonly cookieName: string;
  protected readonly recentLifetime: number;
  /** Deployment ceiling for "remember this device"; 0 disables it everywhere. */
  protected readonly deviceLifetime: number;
  /** Failed attempts since the last sign-in at which one `sign-in-failures` email goes out; 0 disables it. */
  protected readonly failedAlertThreshold: number;
  protected readonly appName: string;
  protected readonly requireEmailVerification: boolean;
  protected readonly dummyPasswordHash: Promise<string>;
  protected readonly limits: ResolvedRateLimits;
  protected readonly outbox: OutboxContext;
  /** Client details for sessions issued inside `withClient`; the HTTP layer sets them per request. */
  protected readonly clientScope = new AsyncLocalStorage<SessionClientInfo>();
  /** The address of the current request (set by `withRequestHost`); organization addresses pin their requests. */
  protected readonly hostScope = new AsyncLocalStorage<RequestHost>();
  /** Network block lists per tenant (own plus platform-wide), reused for a few seconds; management clears it. */
  private readonly blockCache = new Map<string, { at: number; blocks: NetworkBlock[] }>();
  /** Failed-attempt bookkeeping still being written after its refusal was answered; see `settleBookkeeping`. */
  private readonly bookkeeping = new Set<Promise<void>>();

  /** The current secret first, then the ones being rotated out (`previousSecrets`). */
  readonly secrets: readonly string[];

  constructor(readonly options: AuthOptions) {
    if (!options.secret || options.secret.length < 32)
      throw new IamError('INVALID_CONFIG', 'secret must have at least 32 characters');
    const previous = options.previousSecrets ?? [];
    if (
      !Array.isArray(previous) ||
      previous.length > 5 ||
      previous.some(
        (value) => typeof value !== 'string' || value.length < 32 || value === options.secret,
      ) ||
      new Set(previous).size !== previous.length
    )
      throw new IamError(
        'INVALID_CONFIG',
        'previousSecrets must list at most 5 distinct secrets of at least 32 characters, other than secret',
      );
    this.secrets = Object.freeze([options.secret, ...previous]);
    this.limits = resolveRateLimits(options.rateLimits, options.store);
    const maxAttempts = options.maxDeliveryAttempts ?? 25;
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 1_000)
      throw new IamError(
        'INVALID_CONFIG',
        'maxDeliveryAttempts must be an integer between 1 and 1000',
      );
    const url = new URL(options.baseURL);
    this.cookieName =
      url.protocol === 'https:' ? '__Host-better-iam.session' : 'better-iam.session';
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      (url.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))
    )
      throw new IamError('INVALID_CONFIG', 'baseURL must use HTTPS, except loopback development');
    this.requireEmailVerification =
      options.requireEmailVerification ?? Boolean(options.signUpEnabled);
    if ((this.requireEmailVerification || options.passwordlessEmail) && !options.sendEmail)
      throw new IamError('INVALID_CONFIG', 'Enabled email features require sendEmail');
    if (options.passwordlessSms && !options.sendSms)
      throw new IamError('INVALID_CONFIG', 'Enabled SMS features require sendSms');
    this.origins = [
      ...new Set([
        url.origin,
        ...(options.trustedOrigins ?? []).map((origin) => {
          if (new URL(origin).origin !== origin)
            throw new IamError('INVALID_CONFIG', 'Trusted origins must be exact origins');
          return origin;
        }),
      ]),
    ];
    this.now = options.now ?? Date.now;
    this.sessionLifetime = options.sessionLifetimeMs ?? 7 * 24 * 60 * 60_000;
    this.idleLifetime =
      options.sessionIdleTimeoutMs ?? Math.min(this.sessionLifetime, 24 * 60 * 60_000);
    this.recentLifetime = options.recentAuthenticationMs ?? 5 * 60_000;
    if (
      !Number.isSafeInteger(this.sessionLifetime) ||
      this.sessionLifetime < 60_000 ||
      this.sessionLifetime > 30 * 24 * 60 * 60_000
    )
      throw new IamError(
        'INVALID_CONFIG',
        'Session lifetime must be between one minute and thirty days',
      );
    if (
      !Number.isSafeInteger(this.idleLifetime) ||
      this.idleLifetime < 60_000 ||
      this.idleLifetime > this.sessionLifetime
    )
      throw new IamError(
        'INVALID_CONFIG',
        'Session idle timeout must be between one minute and the absolute session lifetime',
      );
    if (
      !Number.isSafeInteger(this.recentLifetime) ||
      this.recentLifetime < 1_000 ||
      this.recentLifetime > 15 * 60_000
    )
      throw new IamError(
        'INVALID_CONFIG',
        'Recent authentication lifetime must be between one second and fifteen minutes',
      );
    this.deviceLifetime = options.trustedDeviceLifetimeMs ?? 30 * 24 * 60 * 60_000;
    if (
      !Number.isSafeInteger(this.deviceLifetime) ||
      this.deviceLifetime < 0 ||
      (this.deviceLifetime > 0 && this.deviceLifetime < 60_000) ||
      this.deviceLifetime > 365 * 24 * 60 * 60_000
    )
      throw new IamError(
        'INVALID_CONFIG',
        'Trusted device lifetime must be 0 (disabled) or between one minute and one year',
      );
    this.failedAlertThreshold = options.failedSignInAlerts ?? 0;
    if (
      !Number.isSafeInteger(this.failedAlertThreshold) ||
      this.failedAlertThreshold < 0 ||
      this.failedAlertThreshold > 1_000
    )
      throw new IamError(
        'INVALID_CONFIG',
        'failedSignInAlerts must be 0 (disabled) or an integer between 1 and 1000',
      );
    if (this.failedAlertThreshold > 0 && !options.sendEmail)
      throw new IamError('INVALID_CONFIG', 'failedSignInAlerts requires sendEmail');
    this.appName = options.appName ?? 'Better IAM';
    if (
      options.passkeys &&
      (!options.passkeys.rpID ||
        !this.origins.every((origin) => {
          const hostname = new URL(origin).hostname;
          return (
            hostname === options.passkeys!.rpID || hostname.endsWith(`.${options.passkeys!.rpID}`)
          );
        }))
    )
      throw new IamError('INVALID_CONFIG', 'Passkey RP ID must match each trusted origin');
    this.dummyPasswordHash = argon2.hash(newToken(), { type: argon2.argon2id });
    this.outbox = {
      store: options.store,
      secret: options.secret,
      secrets: this.secrets,
      now: () => this.now(),
      maxAttempts,
      deliverer: (kind) => this.deliverer(kind),
    };
  }

  /** Runs `fn` so that every session it issues records `client` (IP, user agent, label); values are trimmed and bounded. */
  withClient<T>(client: SessionClientInfo | undefined, fn: () => Promise<T>): Promise<T> {
    if (!client) return fn();
    const clean = (value: unknown, max: number) =>
      typeof value === 'string' && value.trim()
        ? value
            .replace(/[\u0000-\u001f\u007f]/g, '')
            .trim()
            .slice(0, max)
        : undefined;
    const info: SessionClientInfo = {};
    const ip = clean(client.ip, 64);
    const userAgent = clean(client.userAgent, 512);
    const label = clean(client.label, 128);
    if (ip) info.ip = ip;
    if (userAgent) info.userAgent = userAgent;
    if (label) info.label = label;
    return Object.keys(info).length ? this.clientScope.run(info, fn) : fn();
  }

  /** The client details of the current request (set by `withClient`), if any; used for checks on the presenting address. */
  currentClient(): SessionClientInfo | undefined {
    return this.clientScope.getStore();
  }

  /**
   * Runs `fn` for a request that arrived on `host`: credentials of another organization are refused on an
   * organization's own address (`HOST_MISMATCH`), and passkey ceremonies accept that address's origin.
   */
  withRequestHost<T>(host: RequestHost | undefined, fn: () => Promise<T>): Promise<T> {
    if (!host || (!host.origin && !host.tenantId)) return fn();
    return this.hostScope.run({ ...host }, fn);
  }

  /** The address of the current request (set by `withRequestHost`), if any. */
  requestHost(): RequestHost | undefined {
    return this.hostScope.getStore();
  }

  /** Refuses a credential of another organization on an organization's own address. */
  assertRequestHost(tenantId: string): void {
    const pinned = this.hostScope.getStore()?.tenantId;
    if (pinned && pinned !== tenantId)
      throw new IamError('HOST_MISMATCH', 'This address belongs to another organization', 403);
  }

  /** Origins a WebAuthn response may come from: the deployment's, plus the current request's organization address. */
  protected expectedOrigins(): string[] {
    const origin = this.hostScope.getStore()?.origin;
    return origin && !this.origins.includes(origin) ? [...this.origins, origin] : this.origins;
  }

  /** Serializably validates every ancestor; tenant identifiers are never inferred from email. */
  async assertTenantActive(tx: IamStore, tenantId: string): Promise<void> {
    let current: string | null = text(tenantId, 'tenantId');
    const seen = new Set<string>();
    while (current) {
      if (seen.has(current))
        throw new IamError('INVALID_TENANT_TREE', 'Invalid tenant hierarchy', 403);
      seen.add(current);
      const tenant: Tenant | undefined = await tx.get<Tenant>('tenants', current);
      if (!tenant || tenant.status !== 'active')
        throw new IamError('TENANT_UNAVAILABLE', 'Tenant is not active', 403);
      current = tenant.parentId;
    }
  }

  /**
   * Counts an attempt against the configured limiter before any credential is examined: first against the client
   * IP when one is recorded and `rateLimits.ipAttempts` is set (every flow of the tenant shares that counter, so
   * spraying many accounts from one address runs out as fast as hammering one), then against the subject.
   */
  protected async rate(
    tenantId: string,
    subject: string,
    tier: 'default' | 'sensitive' | 'generous' = 'default',
  ): Promise<void> {
    await this.rateClient(tenantId);
    await this.rateSubject(tenantId, subject, tier);
  }

  /**
   * Counts an attempt for a server flow outside the sign-in paths (MFA step-ups, web-identity exchanges). Without
   * `limit` it is exactly `rate(tenantId, subject, tier)`. With `limit` it applies the same network blocks and per-IP
   * counter, then a dedicated per-subject budget of `limit` attempts per window that ignores the tenant's
   * `maxAttempts`, so a busy automation budget never loosens or tightens human sign-in limits. Call it outside any
   * transaction: a counter consumed inside one would roll back with the refusal. Throws RATE_LIMITED (429, with
   * `retryAfterMs`) or the network refusals.
   */
  async limitAttempt(
    tenantId: string,
    subject: string,
    options: {
      tier?: 'default' | 'sensitive' | 'generous';
      limit?: number;
      /** With `limit`: false skips the network steps (blocks, per-IP counter) when the same attempt already ran them. */
      countClient?: boolean;
    } = {},
  ): Promise<void> {
    if (options.limit === undefined) {
      await this.rate(tenantId, subject, options.tier ?? 'default');
      return;
    }
    if (!Number.isSafeInteger(options.limit) || options.limit < 1)
      throw new IamError('INVALID_INPUT', 'limit must be a positive integer');
    if (options.countClient !== false) await this.rateClient(tenantId);
    await this.consume(hashToken(`${tenantId}:${subject}`), tenantId, options.limit);
  }

  /** The network steps `rate` performs before a subject's counter: network blocks, then the per-IP counter. */
  private async rateClient(tenantId: string): Promise<void> {
    const ip = this.clientScope.getStore()?.ip;
    // A blocked network is refused before any credential is examined or any counter moves.
    await this.assertNetworkNotBlocked(this.options.store, tenantId, ip);
    if (this.limits.ipAttempts > 0 && ip) {
      // IPv6 clients are counted per /64 (one subscriber can rotate through all of it) and an IPv4-mapped address as
      // its IPv4 form, so neither rotation nor spelling earns a fresh counter; a value that is not an IP counts as is.
      const network = ipCounterKey(ip) ?? ip;
      await this.consume(hashToken(`${tenantId}:ip:${network}`), tenantId, this.limits.ipAttempts);
    }
  }

  /**
   * Counts a second-factor attempt against the person a challenge names (subject `${subject}:${identityId}`), on top
   * of the flow's per-challenge counter: every correct password mints a fresh login challenge, and with it a fresh
   * per-challenge budget, so without this whoever holds the password would get `attempts` x `sensitiveAttempts`
   * code guesses per window. The challenge is read outside any transaction and the counter consumed before the
   * flow's own transaction starts, because a counter consumed inside it would join that transaction and roll back
   * with the refusal. An unknown or expired challenge counts nothing more here; the flow refuses it.
   */
  protected async rateChallengeIdentity(
    tenantId: string,
    token: string,
    purpose: string,
    subject: string,
  ): Promise<void> {
    let identityId: string | undefined;
    try {
      identityId = (await this.readChallenge(this.options.store, tenantId, token, purpose))
        .identityId;
    } catch {
      /* The flow itself refuses a missing or expired challenge. */
    }
    if (identityId) await this.rateSubject(tenantId, `${subject}:${identityId}`, 'sensitive');
  }

  /** One subject's counter, without the network checks `rate` performs first. */
  private async rateSubject(
    tenantId: string,
    subject: string,
    tier: 'default' | 'sensitive' | 'generous',
  ): Promise<void> {
    const key = hashToken(`${tenantId}:${subject}`);
    // `generous` covers anonymous, credential-free starts (passkey discovery): ten times the ordinary allowance.
    let limit =
      tier === 'sensitive'
        ? this.limits.sensitiveAttempts
        : tier === 'generous'
          ? this.limits.attempts * 10
          : this.limits.attempts;
    // A tenant policy can only tighten the deployment's limit; an unknown tenant keeps the default.
    try {
      const cap = (await this.options.store.get<Tenant>('tenants', tenantId))?.authPolicy
        ?.maxAttempts;
      if (cap !== undefined) limit = Math.min(limit, cap);
    } catch {
      /* Invalid identifiers are rejected by the flow itself. */
    }
    await this.consume(key, tenantId, limit);
  }

  private async consume(key: string, tenantId: string, limit: number): Promise<void> {
    const permitted = await this.limits.limiter.consume({
      key,
      tenantId,
      limit,
      windowMs: this.limits.windowMs,
      now: this.now(),
    });
    if (!permitted) {
      // Clients and the HTTP layer read `retryAfterMs` (the window length: the counter resets at most that far away).
      const error = new IamError('RATE_LIMITED', 'Too many attempts; try again later', 429);
      Object.assign(error, { retryAfterMs: this.limits.windowMs });
      throw error;
    }
  }

  /**
   * Validates and sets `identity.passwordHash` (the caller persists the identity): the deployment minimum (12), the
   * tenant's password rules, the deployment screen (common, breached, custom), and — for an existing password — the
   * tenant's `passwordHistory`. The replaced hash joins the identity's history.
   */
  protected async setPassword(
    tx: IamStore,
    tenant: Tenant | undefined,
    identity: Identity,
    value: unknown,
  ): Promise<void> {
    const plain = password(value);
    const policy = tenant?.authPolicy;
    const screening = this.options.passwordPolicy;
    assertPasswordRules(plain, policy, screening, identity);
    const custom = await screening?.check?.(plain, {
      tenantId: identity.tenantId,
      identity: { id: identity.id, email: identity.email, name: identity.name },
    });
    if (custom) throw new IamError('WEAK_PASSWORD', custom);
    if (screening?.isBreached && (await screening.isBreached(plain)))
      throw new IamError(
        'BREACHED_PASSWORD',
        'This password appears in a known data breach; choose a different one',
      );
    const history = identity.passwordHash
      ? (await tx.find<PasswordHistoryRecord>('passwordHistory', { identityId: identity.id })).sort(
          (a, b) => b.createdAt - a.createdAt,
        )
      : [];
    const depth = policy?.passwordHistory ?? 0;
    if (identity.passwordHash && depth > 0) {
      const recent = [identity.passwordHash, ...history.slice(0, depth - 1).map((row) => row.hash)];
      for (const hash of recent)
        if (await argon2.verify(hash, plain))
          throw new IamError(
            'PASSWORD_REUSED',
            `Password must differ from your last ${depth} password${depth === 1 ? '' : 's'}`,
          );
    }
    const now = this.now();
    if (identity.passwordHash) {
      await tx.insert<PasswordHistoryRecord>('passwordHistory', {
        id: newId('pwh'),
        tenantId: identity.tenantId,
        identityId: identity.id,
        hash: identity.passwordHash,
        // Strictly increasing per identity, so history order survives changes within one clock tick.
        createdAt: Math.max(now, (history[0]?.createdAt ?? 0) + 1),
      });
      for (const stale of history.slice(PASSWORD_HISTORY_LIMIT - 1))
        await tx.delete('passwordHistory', stale.id);
    }
    identity.passwordHash = await argon2.hash(plain, { type: argon2.argon2id });
    identity.passwordChangedAt = now;
  }

  /** When the identity's password expires under its tenant's `passwordMaxAgeDays`, if it does. */
  passwordExpiresAt(tenant: Tenant | undefined, identity: Identity): number | undefined {
    const days = tenant?.authPolicy?.passwordMaxAgeDays;
    if (!days || !identity.passwordHash) return undefined;
    return (identity.passwordChangedAt ?? identity.createdAt) + days * 24 * 60 * 60_000;
  }

  /** Refuses a correct but expired password; the person recovers through password reset. */
  protected async assertPasswordCurrent(tx: IamStore, identity: Identity): Promise<void> {
    const expiresAt = this.passwordExpiresAt(
      await tx.get<Tenant>('tenants', identity.tenantId),
      identity,
    );
    if (expiresAt !== undefined && expiresAt <= this.now())
      throw new IamError(
        'PASSWORD_EXPIRED',
        'Your password has expired; reset it to continue',
        403,
      );
  }

  /**
   * Clears the rate-limit counters an identity's sign-in and recovery flows use, so an administrator can unlock an
   * account after a burst of failures. Returns false when the configured limiter cannot reset counters.
   */
  async resetRateLimits(identity: Identity): Promise<{ supported: boolean; cleared: number }> {
    const { limiter } = this.limits;
    if (!limiter.reset) return { supported: false, cleared: 0 };
    const subjects = [
      `mfa-enroll:${identity.id}`,
      `password-change:${identity.id}`,
      `reauth:${identity.id}`,
      `email-change:${identity.id}`,
      `phone-verify:${identity.id}`,
      `phone-code:${identity.id}`,
      // Per-person second-factor counters (see `rateChallengeIdentity`).
      `mfa-verify:${identity.id}`,
      `mfa-recovery:${identity.id}`,
      `mfa-code-send:${identity.id}`,
      `passkey-mfa-begin:${identity.id}`,
      `passkey-mfa-verify:${identity.id}`,
    ];
    for (const destination of [identity.email, identity.phone])
      if (destination)
        subjects.push(
          `signup:${destination}`,
          `signin:${destination}`,
          `verify-email:${destination}`,
          `password-reset:${destination}`,
          `passwordless-start:${destination}`,
          `passwordless-finish:${destination}`,
          `passkey:${destination}`,
        );
    for (const subject of subjects)
      await limiter.reset({
        key: hashToken(`${identity.tenantId}:${subject}`),
        tenantId: identity.tenantId,
      });
    return { supported: true, cleared: subjects.length };
  }

  /** True once an identity's `expiresAt` has passed: it is refused everywhere, before the purge worker disables it. */
  protected identityExpired(identity: Identity): boolean {
    return typeof identity.expiresAt === 'number' && identity.expiresAt <= this.now();
  }

  /** An active, unexpired human identity in an active tenant tree. */
  protected async user(tx: IamStore, identityId: string, tenantId?: string): Promise<Identity> {
    const identity = await tx.get<Identity>('identities', identityId);
    if (
      !identity ||
      identity.kind !== 'user' ||
      identity.status !== 'active' ||
      this.identityExpired(identity) ||
      (tenantId && identity.tenantId !== tenantId)
    )
      throw new IamError('UNAUTHENTICATED', 'Invalid authentication', 401);
    await this.assertTenantActive(tx, identity.tenantId);
    return identity;
  }

  /** Root administrators, enrolled people, and members of tenants that require MFA (by callback or tenant policy). */
  async mfaRequired(tx: IamStore, identity: Identity): Promise<boolean> {
    const mfa = await tx.get<MfaRecord>('authMfa', identity.id);
    const tenant = await tx.get<Tenant>('tenants', identity.tenantId);
    return (
      identity.rootAdmin ||
      Boolean(mfa?.enabled) ||
      Boolean(tenant && (await this.tenantRequiresMfa(tenant, identity)))
    );
  }

  /** The tenant-level MFA requirement alone: the configured callback or the tenant's own policy. */
  async tenantRequiresMfa(tenant: Tenant, identity: Identity): Promise<boolean> {
    return (
      tenant.authPolicy?.requireMfa === true ||
      (tenant.authPolicy?.requireMfaForOwners === true && identity.owner) ||
      Boolean(await this.options.requireMfa?.(tenant, identity))
    );
  }

  /** Session limits for a tenant: its policy can shorten, never extend, the deployment's lifetimes. */
  sessionLimits(tenant?: Tenant): { lifetimeMs: number; idleTimeoutMs: number } {
    const policy = tenant?.authPolicy;
    const lifetimeMs = Math.min(this.sessionLifetime, policy?.sessionLifetimeMs ?? Infinity);
    const idleTimeoutMs = Math.min(
      lifetimeMs,
      this.idleLifetime,
      policy?.sessionIdleTimeoutMs ?? Infinity,
    );
    return { lifetimeMs, idleTimeoutMs };
  }

  /** Rejects a sign-in method the tenant's policy excludes; called before any credential is examined so failures never reveal validity. */
  protected async methodAllowed(tx: IamStore, tenantId: string, method: AuthMethod): Promise<void> {
    const tenant = await tx.get<Tenant>('tenants', tenantId);
    const allowed = tenant?.authPolicy?.allowedMethods;
    if (allowed && !allowed.includes(method))
      throw new IamError(
        'METHOD_NOT_ALLOWED',
        'This sign-in method is not permitted for this organization',
        403,
      );
  }

  /**
   * Records an authentication event; when `session` is an impersonation session the administrator is attributed.
   * `metadata` carries small facts about the event (never secrets), such as the client behind a sign-in.
   */
  protected async audit(
    tx: IamStore,
    identity: Identity,
    action: string,
    session?: Session,
    metadata?: Record<string, Json>,
  ): Promise<void> {
    const event: AuditEvent = {
      id: newId('audit'),
      tenantId: identity.tenantId,
      actorId: identity.id,
      action,
      resourceId: identity.id,
      timestamp: this.now(),
      outcome: 'allow',
    };
    if (session?.impersonatorId) event.impersonatorId = session.impersonatorId;
    if (metadata && Object.keys(metadata).length > 0) event.metadata = metadata;
    await this.options.onAudit?.(tx, await appendAuditEvent(tx, event));
  }

  /** The recorded client of the current request as audit metadata (IP and user agent only). */
  protected clientMetadata(): Record<string, string> {
    const client = this.clientScope.getStore();
    return {
      ...(client?.ip ? { ip: client.ip } : {}),
      ...(client?.userAgent ? { userAgent: client.userAgent } : {}),
    };
  }

  protected digestChallenge(tenantId: string, token: string, secret = this.options.secret): string {
    return createHmac('sha256', secret).update(`${tenantId}:${token}`).digest('hex');
  }

  /** Stores a single-use, purpose-bound challenge and returns the plaintext token to deliver. */
  protected async challenge(
    tx: IamStore,
    identity: Identity,
    purpose: string,
    payload: Record<string, string>,
    lifetimeMs = 10 * 60_000,
    token = newToken(),
    sessionId?: string,
  ): Promise<string> {
    const tokenHash = this.digestChallenge(identity.tenantId, token);
    await tx.insert<Challenge>('authChallenges', {
      id: newId('ch'),
      tenantId: identity.tenantId,
      identityId: identity.id,
      purpose,
      tokenHash,
      payload,
      expiresAt: this.now() + lifetimeMs,
      sessionId,
    });
    return token;
  }

  protected async readChallenge(
    tx: IamStore,
    tenantId: string,
    token: string,
    purpose: string,
    match: { identityId?: string; destination?: string } = {},
  ): Promise<Challenge> {
    text(tenantId, 'tenantId');
    text(token, 'token', 512);
    let item: Challenge | undefined;
    // Links issued before a secret rotation carry digests under a previous secret.
    for (const secret of this.secrets) {
      item = (
        await tx.find<Challenge>('authChallenges', {
          tenantId,
          tokenHash: this.digestChallenge(tenantId, token, secret),
          purpose,
        })
      ).find(
        (entry) =>
          (!match.identityId || entry.identityId === match.identityId) &&
          (!match.destination || entry.payload.destination === match.destination),
      );
      if (item) break;
    }
    if (!item || item.expiresAt <= this.now())
      throw new IamError('INVALID_CHALLENGE', 'Challenge is invalid or expired', 401);
    return item;
  }

  protected async enqueue(
    tx: IamStore,
    identity: Identity,
    kind: 'email' | 'sms',
    to: string,
    template: string,
    payload: Record<string, string>,
  ): Promise<void> {
    await this.enqueueDelivery(tx, { tenantId: identity.tenantId, kind, to, template, payload });
  }

  protected deliverer(
    kind: OutboxMessage['kind'],
  ): ((message: DeliveryMessage) => Promise<void>) | undefined {
    return kind === 'email'
      ? this.options.sendEmail
      : kind === 'sms'
        ? this.options.sendSms
        : this.options.deliverWebhook;
  }

  /** Internal server integrations enqueue callbacks in the same transaction as provisioning. Returns the message ID. */
  enqueueDelivery(
    tx: IamStore,
    input: {
      tenantId: string;
      kind: OutboxMessage['kind'];
      to: string;
      template: string;
      payload: Record<string, string>;
      reference?: string;
    },
  ): Promise<string> {
    return enqueueDelivery(this.outbox, tx, input);
  }

  /** At-least-once delivery with backoff; see the outbox module. */
  dispatchOutbox(limit = 100): Promise<DispatchResult> {
    return dispatchOutbox(this.outbox, limit);
  }

  /** Internal provisioning primitive. It does not grant application permissions. */
  async createIdentity(
    tx: IamStore,
    input: {
      tenantId: string;
      email: string;
      name: string;
      password?: string;
      owner?: boolean;
      rootAdmin?: boolean;
      emailVerified?: boolean;
    },
  ): Promise<Identity> {
    const tenantId = text(input.tenantId, 'tenantId');
    const normalized = email(input.email);
    const tenant = await tx.get<Tenant>('tenants', tenantId);
    if (!tenant) throw new IamError('TENANT_NOT_FOUND', 'Tenant does not exist', 404);
    if ((await tx.find<Identity>('identities', { tenantId, email: normalized })).length)
      throw new IamError(
        'IDENTITY_EXISTS',
        'An identity with this email already exists in this tenant',
        409,
      );
    // Every path that creates a person (administration, invitations, self-registration, federation, SCIM) ends here.
    const limit = tenant.limits?.identities;
    if (
      limit !== undefined &&
      (await tx.find<Identity>('identities', { tenantId, kind: 'user' })).filter(
        (item) => item.status !== 'deleted',
      ).length >= limit
    )
      throw new IamError(
        'LIMIT_EXCEEDED',
        `This tenant has reached its member limit (${limit})`,
        409,
      );
    const identity: Identity = {
      id: newId('usr'),
      tenantId,
      uniqueKey: `email:${normalized}`,
      kind: 'user',
      email: normalized,
      name: displayName(input.name, 256),
      status: 'active',
      emailVerified: input.emailVerified ?? false,
      rootAdmin: input.rootAdmin ?? false,
      owner: input.owner ?? false,
      createdAt: this.now(),
    };
    if (input.password !== undefined) await this.setPassword(tx, tenant, identity, input.password);
    await tx.insert('identities', identity);
    await this.audit(tx, identity, 'auth:identity:create');
    return identity;
  }

  /** How long this tenant remembers a device: the deployment ceiling, shortened by policy; 0 when either disables it. */
  deviceLifetimeFor(tenant?: Tenant): number {
    const days = tenant?.authPolicy?.trustedDeviceDays;
    if (this.deviceLifetime === 0 || days === 0) return 0;
    return Math.min(this.deviceLifetime, days === undefined ? Infinity : days * 24 * 60 * 60_000);
  }

  /**
   * Internal: remembers the current client for an identity that just completed MFA. Returns the device token to hand
   * to the client, or nothing when the deployment, the tenant, or the identity (root administrators) rules it out.
   */
  async rememberDevice(
    tx: IamStore,
    identity: Identity,
  ): Promise<{ deviceToken: string; deviceExpiresAt: number } | undefined> {
    if (identity.rootAdmin) return undefined;
    const lifetime = this.deviceLifetimeFor(await tx.get<Tenant>('tenants', identity.tenantId));
    if (lifetime === 0) return undefined;
    const now = this.now();
    const token = newToken();
    const device: TrustedDevice = {
      id: newId('dev'),
      tenantId: identity.tenantId,
      identityId: identity.id,
      tokenHash: hashToken(token),
      uniqueKey: hashToken(token),
      createdAt: now,
      expiresAt: now + lifetime,
      lastUsedAt: now,
    };
    const client = this.clientScope.getStore();
    if (client) device.client = client;
    await tx.insert('authDevices', device);
    await this.audit(tx, identity, 'auth:device:trust');
    return { deviceToken: token, deviceExpiresAt: device.expiresAt };
  }

  /** Internal: the live trusted device behind a token for this identity, touched on use; undefined when it cannot vouch. */
  protected async trustedDevice(
    tx: IamStore,
    identity: Identity,
    deviceToken: string,
  ): Promise<TrustedDevice | undefined> {
    if (identity.rootAdmin || !/^[A-Za-z0-9_-]{32,512}$/.test(deviceToken)) return undefined;
    const lifetime = this.deviceLifetimeFor(await tx.get<Tenant>('tenants', identity.tenantId));
    if (lifetime === 0) return undefined;
    const device = (
      await tx.find<TrustedDevice>('authDevices', { tokenHash: hashToken(deviceToken) })
    )[0];
    // The current policy also bounds devices remembered under a longer one (trustedDeviceDays lowered later).
    if (
      !device ||
      device.identityId !== identity.id ||
      device.tenantId !== identity.tenantId ||
      device.expiresAt <= this.now() ||
      this.now() - device.createdAt >= lifetime
    )
      return undefined;
    device.lastUsedAt = this.now();
    await tx.put('authDevices', device);
    return device;
  }

  /** Internal: caller must already have verified the authentication ceremony. */
  async issueSession(
    tx: IamStore,
    identity: Identity,
    options: {
      mfa?: boolean;
      authenticatedAt?: number;
      method?: AuthMethod;
      trustedDeviceId?: string;
      /**
       * When the second factor behind `mfa` was verified, for sessions that carry an earlier ceremony forward (such as
       * a linked-identity switch). Without it, a first-hand MFA session (`mfa`, no remembered device, no carried
       * `authenticatedAt`) records the issue time.
       */
      mfaAuthenticatedAt?: number;
    } = {},
  ): Promise<SessionResult> {
    const active = await this.user(tx, identity.id, identity.tenantId);
    if (this.requireEmailVerification && !active.emailVerified)
      throw new IamError('EMAIL_UNVERIFIED', 'Verify your email before signing in', 403);
    if ((await this.mfaRequired(tx, active)) && !options.mfa)
      throw new IamError('MFA_REQUIRED', 'Multi-factor authentication is required', 403);
    const tenant = await tx.get<Tenant>('tenants', active.tenantId);
    this.assertIpAllowed(tenant, this.clientScope.getStore()?.ip);
    await this.assertNetworkNotBlocked(tx, active.tenantId, this.clientScope.getStore()?.ip);
    const now = this.now();
    const token = newCredentialToken('ses');
    const session: Session = {
      id: newId('ses'),
      tenantId: active.tenantId,
      identityId: active.id,
      kind: 'user',
      tokenHash: hashToken(token),
      uniqueKey: hashToken(token),
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + this.sessionLimits(tenant).lifetimeMs,
      authenticatedAt: options.authenticatedAt ?? now,
      mfa: options.mfa ?? false,
    };
    if (options.method) session.method = options.method;
    if (options.trustedDeviceId) session.trustedDeviceId = options.trustedDeviceId;
    // principal.mfaTime: only a first-hand factor counts, never a remembered device.
    if (session.mfa && !options.trustedDeviceId) {
      const mfaAuthenticatedAt =
        options.mfaAuthenticatedAt ?? (options.authenticatedAt === undefined ? now : undefined);
      if (mfaAuthenticatedAt !== undefined) session.mfaAuthenticatedAt = mfaAuthenticatedAt;
    }
    const client = this.clientScope.getStore();
    if (client) session.client = client;
    // The previous sign-in, and the attempts that failed since, travel on the session for a "last sign-in" notice;
    // the ledger then restarts from this session.
    const ledger = await tx.get<SignInLedger>('authSignIns', active.id);
    if (ledger) session.previousSignIn = signInSummary(ledger);
    await tx.insert('sessions', session);
    const next: SignInLedger = {
      id: active.id,
      tenantId: active.tenantId,
      identityId: active.id,
      lastAt: now,
      failedAttempts: 0,
    };
    if (client && (client.ip || client.userAgent || client.label)) next.lastClient = client;
    if (ledger) await tx.put('authSignIns', next);
    else await tx.insert('authSignIns', next);
    // A tenant may cap concurrent sessions per person; the oldest live sessions make room for the new one.
    const maxSessions = tenant?.authPolicy?.maxSessions;
    if (maxSessions !== undefined) {
      const live = (
        await tx.find<Session>('sessions', {
          tenantId: active.tenantId,
          identityId: active.id,
          kind: 'user',
        })
      )
        .filter((item) => item.expiresAt > now && !item.impersonatorId)
        .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1));
      for (const stale of live.slice(0, Math.max(0, live.length - maxSessions)))
        await this.endSession(tx, stale.id);
    }
    await this.audit(tx, active, 'auth:session:create', undefined, {
      ...(options.method ? { method: options.method } : {}),
      ...this.clientMetadata(),
    });
    if (!options.trustedDeviceId) await this.notifyNewSignIn(tx, active, tenant, session);
    return { token, session: publicSession(session) };
  }

  /**
   * Internal: counts an attempt that named a known, active person with a wrong password, factor, or recovery code.
   * The refused flow rolled back, so this runs in its own transaction, and it never throws: the credential error
   * is what the caller reports. The next session carries the count (`previousSignIn`) and the person's trail
   * shows the `auth:signin:fail` event with the client that tried. `at` is when the attempt was refused.
   */
  async recordSignInFailure(
    identity: Identity,
    reason: SignInFailureReason,
    at: number = this.now(),
  ): Promise<void> {
    if (identity.kind !== 'user' || identity.status !== 'active') return;
    try {
      await this.options.store.transaction(async (tx) => {
        const now = at;
        const client = this.clientScope.getStore();
        const existing = await tx.get<SignInLedger>('authSignIns', identity.id);
        const ledger: SignInLedger = {
          id: identity.id,
          tenantId: identity.tenantId,
          identityId: identity.id,
          failedAttempts: (existing?.failedAttempts ?? 0) + 1,
          lastFailedAt: now,
        };
        if (existing?.lastAt !== undefined) ledger.lastAt = existing.lastAt;
        if (existing?.lastClient) ledger.lastClient = existing.lastClient;
        if (client && (client.ip || client.userAgent || client.label))
          ledger.lastFailedClient = client;
        if (existing) await tx.put('authSignIns', ledger);
        else await tx.insert('authSignIns', ledger);
        await this.audit(tx, identity, 'auth:signin:fail', undefined, {
          reason,
          ...this.clientMetadata(),
        });
        // One alert per streak: exactly when the threshold is reached, and the streak ends with a sign-in.
        if (
          this.failedAlertThreshold > 0 &&
          ledger.failedAttempts === this.failedAlertThreshold &&
          identity.email &&
          identity.emailVerified &&
          this.options.sendEmail
        )
          await this.enqueue(tx, identity, 'email', identity.email, 'sign-in-failures', {
            attempts: String(ledger.failedAttempts),
            time: new Date(now).toISOString(),
            ...this.clientMetadata(),
          });
      });
    } catch {
      /* Bookkeeping never masks the credential refusal. */
    }
  }

  /**
   * Internal: records a refused attempt (`recordSignInFailure`) without delaying the refusal. Awaiting that ledger and
   * audit transaction would make a wrong password for a real account measurably slower than one for an unknown
   * address, whose refusal writes nothing: a response-time oracle for which accounts exist. The write starts once
   * the refusal's own continuations have run, so the caller is answered first; `settleBookkeeping` awaits it.
   */
  protected deferSignInFailure(identity: Identity, reason: SignInFailureReason): void {
    const at = this.now();
    const pending = new Promise<void>((resolve) => setImmediate(resolve))
      .then(() => this.recordSignInFailure(identity, reason, at))
      .catch(() => {
        /* recordSignInFailure never throws; nothing may escape as an unhandled rejection either. */
      });
    this.bookkeeping.add(pending);
    void pending.finally(() => this.bookkeeping.delete(pending));
  }

  /**
   * Resolves once the failed-attempt bookkeeping of refusals already answered has been written. Tests that read the
   * sign-in ledger or trail right after a refusal await this first; a graceful shutdown (or a serverless platform's
   * `waitUntil`) can await it so those records are not lost.
   */
  async settleBookkeeping(): Promise<void> {
    while (this.bookkeeping.size) await Promise.all([...this.bookkeeping]);
  }

  /** Emails the person about a session from a client that no live session or remembered device of theirs has used. */
  protected async notifyNewSignIn(
    tx: IamStore,
    identity: Identity,
    tenant: Tenant | undefined,
    session: Session,
  ): Promise<void> {
    const enabled =
      tenant?.authPolicy?.notifyNewSignIn ?? this.options.signInNotifications ?? false;
    if (!enabled || !identity.email || !this.options.sendEmail) return;
    const fingerprint = (client?: SessionClientInfo) =>
      client && (client.userAgent || client.ip)
        ? `${client.userAgent ?? ''}|${client.ip ?? ''}`
        : undefined;
    const current = fingerprint(session.client);
    if (!current) return;
    const now = this.now();
    const scope = { identityId: identity.id, tenantId: identity.tenantId };
    const knownSession = (await tx.find<Session>('sessions', { ...scope, kind: 'user' })).some(
      (other) =>
        other.id !== session.id && other.expiresAt > now && fingerprint(other.client) === current,
    );
    const knownDevice =
      !knownSession &&
      (await tx.find<TrustedDevice>('authDevices', scope)).some(
        (device) => device.expiresAt > now && fingerprint(device.client) === current,
      );
    if (knownSession || knownDevice) return;
    const payload: Record<string, string> = {
      sessionId: session.id,
      time: new Date(now).toISOString(),
      method: session.method ?? 'unknown',
    };
    if (session.client?.userAgent) payload.userAgent = session.client.userAgent;
    if (session.client?.ip) payload.ip = session.client.ip;
    if (session.client?.label) payload.label = session.client.label;
    await this.enqueue(tx, identity, 'email', identity.email, 'new-sign-in', payload);
  }

  /**
   * Internal: opens a session as `target` on behalf of `actor` ("view as"). The server authorizes and audits the
   * request; here the tenant must allow impersonation, the actor must hold an ordinary session of their own, and the
   * new session inherits the actor's MFA state, expires with the actor's session, and is marked so that policies,
   * audit records, and the member can see who is really acting.
   */
  async issueImpersonationSession(
    tx: IamStore,
    actor: AuthenticatedPrincipal,
    target: Identity,
    durationMs: number,
  ): Promise<SessionResult> {
    if (actor.session.kind !== 'user' || actor.session.impersonatorId)
      throw new IamError(
        'IMPERSONATION_RESTRICTED',
        'Only a person acting through their own session can impersonate',
        403,
      );
    const active = await this.user(tx, target.id, target.tenantId);
    const tenant = await tx.get<Tenant>('tenants', active.tenantId);
    this.assertIpAllowed(tenant, this.clientScope.getStore()?.ip);
    await this.assertNetworkNotBlocked(tx, active.tenantId, this.clientScope.getStore()?.ip);
    if (!tenant?.authPolicy?.allowImpersonation)
      throw new IamError(
        'FEATURE_DISABLED',
        'Impersonation is not enabled for this organization',
        403,
      );
    if ((await this.mfaRequired(tx, active)) && !actor.session.mfa)
      throw new IamError(
        'MFA_REQUIRED',
        'Complete multi-factor authentication before impersonating a member who requires it',
        403,
      );
    const now = this.now();
    // Impersonation inherits the actor's MFA flag but never a first-hand factor time (no principal.mfaTime).
    const token = newCredentialToken('ses');
    const session: Session = {
      id: newId('ses'),
      tenantId: active.tenantId,
      identityId: active.id,
      kind: 'user',
      tokenHash: hashToken(token),
      uniqueKey: hashToken(token),
      createdAt: now,
      lastSeenAt: now,
      expiresAt: Math.min(actor.session.expiresAt, now + durationMs),
      authenticatedAt: now,
      mfa: actor.session.mfa,
      method: 'impersonation',
      impersonatorId: actor.identity.id,
      impersonatorSessionId: actor.session.id,
    };
    const client = this.clientScope.getStore();
    if (client) session.client = client;
    await tx.insert('sessions', session);
    await this.audit(tx, active, 'auth:session:create', session);
    return { token, session: publicSession(session) };
  }

  /** Removes a session together with any impersonation sessions an administrator opened through it. */
  async endSession(tx: IamStore, sessionId: string): Promise<void> {
    await tx.delete('sessions', sessionId);
    for (const dependent of await tx.find<Session>('sessions', {
      impersonatorSessionId: sessionId,
    }))
      await tx.delete('sessions', dependent.id);
  }

  /**
   * An impersonation session lives only while the administrator's own session and identity do, while the member's
   * tenant still allows impersonation, and while the member is still someone who may be impersonated (not an owner or
   * root administrator); otherwise it is refused (and removed on sight). The administrator's tenant idle timeout also
   * applies: the view-as ends once neither session has been used for that long.
   */
  async assertImpersonationSource(tx: IamStore, session: Session): Promise<void> {
    if (!session.impersonatorId) return;
    const source = session.impersonatorSessionId
      ? await tx.get<Session>('sessions', session.impersonatorSessionId)
      : undefined;
    const actor = await tx.get<Identity>('identities', session.impersonatorId);
    const member = await tx.get<Identity>('identities', session.identityId);
    const memberTenant = await tx.get<Tenant>('tenants', session.tenantId);
    const sourceTenant = source ? await tx.get<Tenant>('tenants', source.tenantId) : undefined;
    const lastActive = Math.max(source?.lastSeenAt ?? 0, session.lastSeenAt);
    if (
      !source ||
      source.kind !== 'user' ||
      source.identityId !== session.impersonatorId ||
      source.expiresAt <= this.now() ||
      this.now() - lastActive >= this.sessionLimits(sourceTenant).idleTimeoutMs ||
      !actor ||
      actor.status !== 'active' ||
      this.identityExpired(actor) ||
      !memberTenant?.authPolicy?.allowImpersonation ||
      !member ||
      member.owner ||
      member.rootAdmin
    ) {
      await tx.delete('sessions', session.id);
      throw new IamError('UNAUTHENTICATED', 'Impersonation has ended', 401);
    }
  }

  /** Whether the person has a registered passkey that can serve as their second factor on this deployment. */
  protected async passkeyFactor(tx: IamStore, identity: Identity): Promise<boolean> {
    return (
      Boolean(this.options.passkeys) &&
      (await tx.find('authPasskeys', { tenantId: identity.tenantId, identityId: identity.id }))
        .length > 0
    );
  }

  /**
   * Internal: callers have verified the first factor (or a federated assertion). `method` is recorded on the session,
   * carried through the MFA challenge, and checked against the tenant's allowed methods. A valid `deviceToken` from
   * "remember this device" satisfies the MFA requirement; an invalid one simply leads to the normal challenge.
   */
  async completeAuthentication(
    tx: IamStore,
    identity: Identity,
    method?: AuthMethod,
    deviceToken?: string,
  ): Promise<SignInResult> {
    const active = await this.user(tx, identity.id, identity.tenantId);
    if (method) await this.methodAllowed(tx, active.tenantId, method);
    if (await this.mfaRequired(tx, active)) {
      const device = deviceToken ? await this.trustedDevice(tx, active, deviceToken) : undefined;
      if (device)
        return this.issueSession(tx, active, { mfa: true, method, trustedDeviceId: device.id });
      const mfa = await tx.get<MfaRecord>('authMfa', active.id);
      // Emailed one-time codes stand in for an authenticator only when nothing is enrolled and policy allows it.
      const tenant = await tx.get<Tenant>('tenants', active.tenantId);
      const emailCodes =
        !mfa?.enabled &&
        !active.rootAdmin &&
        Boolean(active.email && active.emailVerified) &&
        Boolean(this.options.sendEmail) &&
        (tenant?.authPolicy?.mfaEmailCodes ?? this.options.mfaEmailCodes ?? false);
      const passkeys = await this.passkeyFactor(tx, active);
      const challenge = await this.challenge(
        tx,
        active,
        'mfa-login',
        { ...(method ? { method } : {}), ...(emailCodes ? { emailCodes: '1' } : {}) },
        5 * 60_000,
      );
      return {
        mfaRequired: true,
        challenge,
        // A registered passkey is a second factor: the login challenge cannot enroll an authenticator over it.
        enrollmentRequired: !mfa?.enabled && !passkeys,
        authenticatorEnrolled: Boolean(mfa?.enabled),
        ...(emailCodes ? { emailCodeAvailable: true } : {}),
        ...(passkeys ? { passkeyAvailable: true } : {}),
      };
    }
    return this.issueSession(tx, active, { method });
  }

  /** Resolves a bearer token or session cookie to its verified identity and session. */
  async authenticate(input: CredentialInput): Promise<AuthenticatedPrincipal> {
    let token = input?.token;
    if (token === undefined) {
      const headers = new Headers(input?.headers);
      const authorization = headers.get('authorization');
      if (authorization) {
        if (!/^Bearer [A-Za-z0-9_-]+$/i.test(authorization))
          throw new IamError('UNAUTHENTICATED', 'Invalid credentials', 401);
        token = authorization.slice(7);
      } else
        token = headers
          .get('cookie')
          ?.split(';')
          .map((part) => part.trim())
          .find((part) => part.startsWith(`${this.cookieName}=`))
          ?.slice(this.cookieName.length + 1);
    }
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{32,512}$/.test(token))
      throw new IamError('UNAUTHENTICATED', 'Invalid or missing credentials', 401);
    // A prefixed token with a bad shape or checksum is refused before any storage read (bearer and cookie alike).
    if (token.startsWith('biam_') && !parseCredentialToken(token))
      throw new IamError('UNAUTHENTICATED', 'Invalid or missing credentials', 401);
    let principal: AuthenticatedPrincipal;
    try {
      principal = await this.options.store.transaction(async (tx) => {
        const sessions = await tx.find<Session>('sessions', { tokenHash: hashToken(token!) });
        return await this.validateStoredSession(tx, sessions[0]);
      });
    } catch (error) {
      if (error instanceof SessionNetworkMismatch) await this.recordSessionMismatch(error);
      throw error;
    }
    this.assertRequestHost(principal.session.tenantId);
    return principal;
  }

  /**
   * Internal: notes in the person's trail that their bound session was presented from another network
   * (`auth:session:mismatch`, with both addresses), in its own transaction; never throws.
   */
  protected async recordSessionMismatch(mismatch: SessionNetworkMismatch): Promise<void> {
    try {
      await this.options.store.transaction(async (tx) => {
        const identity = await tx.get<Identity>('identities', mismatch.session.identityId);
        if (!identity) return;
        await this.audit(tx, identity, 'auth:session:mismatch', undefined, {
          sessionId: mismatch.session.id,
          sessionIp: mismatch.session.client?.ip ?? '',
          ...this.clientMetadata(),
        });
      });
    } catch {
      /* Bookkeeping never masks the refusal. */
    }
  }

  protected async validateStoredSession(
    tx: IamStore,
    session: Session | undefined,
  ): Promise<AuthenticatedPrincipal> {
    if (!session || session.kind !== 'user' || session.expiresAt <= this.now())
      throw new IamError('UNAUTHENTICATED', 'Invalid or expired credentials', 401);
    const tenant = await tx.get<Tenant>('tenants', session.tenantId);
    const { lifetimeMs, idleTimeoutMs } = this.sessionLimits(tenant);
    // Both limits are judged against the tenant's current policy, so shortening the lifetime (after an incident, say)
    // also ends sessions issued under the longer one.
    if (
      this.now() - session.lastSeenAt >= idleTimeoutMs ||
      this.now() - session.createdAt >= lifetimeMs
    )
      throw new IamError('UNAUTHENTICATED', 'Invalid or expired credentials', 401);
    const identity = await this.user(tx, session.identityId, session.tenantId);
    if (this.requireEmailVerification && !identity.emailVerified)
      throw new IamError('EMAIL_UNVERIFIED', 'Verify your email before signing in', 403);
    if ((await this.mfaRequired(tx, identity)) && !session.mfa)
      throw new IamError('MFA_REQUIRED', 'Multi-factor authentication is required', 403);
    await this.assertImpersonationSource(tx, session);
    // A session issued from a network the tenant no longer allows, or has since blocked, stops working at its next use.
    this.assertIpAllowed(tenant, session.client?.ip);
    await this.assertNetworkNotBlocked(tx, session.tenantId, session.client?.ip);
    // The address presenting the cookie now is judged against network blocks too, so a stolen session is useless
    // from a blocked network (as API keys and temporary credentials already are).
    const presentedIp = this.clientScope.getStore()?.ip;
    if (presentedIp && presentedIp !== session.client?.ip)
      await this.assertNetworkNotBlocked(tx, session.tenantId, presentedIp);
    // Opt-in per tenant: the session works only from the network it was issued from, so a stolen cookie is
    // useless elsewhere; unknown addresses on either side are not judged.
    if (tenant?.authPolicy?.bindSessionsToIp) {
      const presented = this.clientScope.getStore()?.ip;
      if (session.client?.ip && presented && presented !== session.client.ip)
        throw new SessionNetworkMismatch(session, presented);
    }
    // Touching the session on every request would make each authenticated call a durable write. A touch
    // at most every tenth of the idle window (at most once a minute) keeps idle expiry within that
    // margin, and only ever earlier than configured, never later.
    if (this.now() - session.lastSeenAt >= Math.min(60_000, Math.floor(idleTimeoutMs / 10))) {
      session.lastSeenAt = this.now();
      await tx.put('sessions', session);
    }
    return { identity, session };
  }

  /** The blocks that apply to a tenant, its own and the platform-wide ones, read through `reader` and cached briefly. */
  protected async networkBlocks(reader: IamStore, tenantId: string): Promise<NetworkBlock[]> {
    const now = this.now();
    const cached = this.blockCache.get(tenantId);
    if (cached && now >= cached.at && now - cached.at < BLOCK_CACHE_MS) return cached.blocks;
    const [own, platform] = await Promise.all([
      reader.find<NetworkBlock>('authBlocks', { tenantId }),
      reader.find<NetworkBlock>('authBlocks', { platform: true }),
    ]);
    const blocks = [...own, ...platform.filter((block) => block.tenantId !== tenantId)];
    if (this.blockCache.size >= 10_000) this.blockCache.clear();
    this.blockCache.set(tenantId, { at: now, blocks });
    return blocks;
  }

  /** Forgets the cached block lists so a change applies at once in this process (other processes follow within seconds). */
  invalidateNetworkBlocks(): void {
    this.blockCache.clear();
  }

  /** The live block covering an IP for a tenant, if any; unknown IPs are never blocked. */
  async blockedNetwork(
    reader: IamStore,
    tenantId: string,
    ip: string | undefined,
  ): Promise<NetworkBlock | undefined> {
    if (!ip) return undefined;
    const now = this.now();
    return (await this.networkBlocks(reader, tenantId)).find(
      (block) =>
        (block.expiresAt === undefined || block.expiresAt > now) &&
        isIpRange(block.network) &&
        ipMatches(ip, block.network),
    );
  }

  /** Refuses a recorded client IP that a live block of the tenant or the platform covers (`IP_BLOCKED`). */
  async assertNetworkNotBlocked(
    reader: IamStore,
    tenantId: string,
    ip: string | undefined,
  ): Promise<void> {
    if (await this.blockedNetwork(reader, tenantId, ip))
      throw new IamError('IP_BLOCKED', 'Sign-in from this network is blocked', 403);
  }

  /** Refuses a recorded client IP outside the tenant's `allowedIpRanges`; unknown IPs are not judged. */
  assertIpAllowed(tenant: Tenant | undefined, ip: string | undefined): void {
    const ranges = tenant?.authPolicy?.allowedIpRanges;
    if (!ranges?.length || !ip) return;
    if (!ranges.some((range) => ipMatches(ip, range)))
      throw new IamError(
        'IP_NOT_ALLOWED',
        'Sign-in from this network is not permitted for this organization',
        403,
      );
  }

  /** Internal protocol integrations only: revalidate the IAM session attached to a stored OAuth grant. */
  async validateSessionId(sessionId: string): Promise<AuthenticatedPrincipal> {
    text(sessionId, 'sessionId');
    return this.options.store.transaction(async (tx) =>
      this.validateStoredSession(tx, await tx.get<Session>('sessions', sessionId)),
    );
  }

  /**
   * Sensitive operations need a fresh authentication; an impersonated session never qualifies, whatever its age, and
   * neither does a temporary credential (a role session, a session token, any derived session, or a kind this
   * service does not know), which carries its source's authentication time forward.
   */
  requireRecent(principal: AuthenticatedPrincipal): void {
    if (principal.session.impersonatorId)
      throw new IamError(
        'IMPERSONATION_RESTRICTED',
        'This operation is unavailable while impersonating a member',
        403,
      );
    if (
      (principal.session.kind !== 'user' && principal.session.kind !== 'api-key') ||
      principal.session.sourceSessionId !== undefined
    )
      throw new IamError(
        'RECENT_AUTH_REQUIRED',
        'Temporary credentials cannot perform this operation; use a signed-in session',
        403,
      );
    if (
      this.now() - principal.session.authenticatedAt > this.recentLifetime ||
      principal.session.authenticatedAt > this.now()
    )
      throw new IamError('RECENT_AUTH_REQUIRED', 'Reauthenticate to perform this operation', 403);
  }

  /** Revokes every session, pending challenge, and remembered device of an identity. */
  async revokeIdentity(tx: IamStore, identityId: string): Promise<void> {
    for (const session of await tx.find<Session>('sessions', { identityId }))
      await this.endSession(tx, session.id);
    for (const device of await tx.find<TrustedDevice>('authDevices', { identityId }))
      await tx.delete('authDevices', device.id);
    for (const challenge of await tx.find<Challenge>('authChallenges', { identityId }))
      await tx.delete('authChallenges', challenge.id);
  }
}
