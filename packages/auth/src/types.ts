import type {
  AuditEvent,
  CredentialInput,
  IamStore,
  Identity,
  Session,
  SessionClientInfo,
  SignInRecord,
  StoredRecord,
  Tenant,
} from '@better-iam/core';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';
import type { PasswordPolicyOptions } from './password-policy.js';

export interface DeliveryMessage {
  id: string;
  tenantId: string;
  to: string;
  template: string;
  payload: Record<string, string>;
  /**
   * The organization's sign-in URL (its own subdomain, custom hostname, or regional address), added by the server
   * when organization addresses or regions are configured, so the links in the message can point there.
   */
  signInUrl?: string;
}
/** A durable attempt counter. The default limiter stores counters in the IAM database; supply one backed by Redis or similar for multi-instance deployments. */
export interface RateLimiter {
  /** Returns true when the attempt is permitted. Implementations must count the attempt even when the caller later fails. */
  consume(input: {
    key: string;
    tenantId: string;
    limit: number;
    windowMs: number;
    now: number;
  }): Promise<boolean>;
  /** Clears one counter so an administrator can unlock an account; optional for custom limiters. */
  reset?(input: { key: string; tenantId: string }): Promise<void>;
}
export interface RateLimitOptions {
  /** Attempts per window for ordinary flows such as password sign-in (default 10). */
  attempts?: number;
  /** Attempts per window for sensitive flows such as MFA, recovery, and delivery requests (default 5). */
  sensitiveAttempts?: number;
  /** Rolling window length (default 15 minutes). */
  windowMs?: number;
  /**
   * Attempts per window from one client IP across every authentication flow of a tenant, on top of the per-account
   * limits, against credential stuffing and password spraying (0, the default, disables it). Needs a recorded IP
   * (`http.clientInfo` or `withClient`), so it never judges direct API calls; size it for the offices behind one NAT.
   */
  ipAttempts?: number;
  limiter?: RateLimiter;
}
export interface AuthOptions {
  store: IamStore;
  secret: string;
  /**
   * Secrets being rotated out: values sealed with them (authenticator secrets, pending deliveries)
   * and challenge links issued under them keep working until re-sealed or expired. New values
   * always use `secret`.
   */
  previousSecrets?: string[];
  baseURL: string;
  trustedOrigins?: string[];
  appName?: string;
  signUpEnabled?: boolean;
  requireEmailVerification?: boolean;
  emailPassword?: boolean;
  passwordlessEmail?: boolean;
  passwordlessSms?: boolean;
  sendEmail?: (message: DeliveryMessage) => Promise<void>;
  sendSms?: (message: DeliveryMessage) => Promise<void>;
  /** Delivers webhook outbox messages; `to` is the webhook ID and the payload carries `url` and the JSON `body`. */
  deliverWebhook?: (message: DeliveryMessage) => Promise<void>;
  /** Outbox messages are abandoned after this many failed attempts (default 25). */
  maxDeliveryAttempts?: number;
  sessionLifetimeMs?: number;
  sessionIdleTimeoutMs?: number;
  recentAuthenticationMs?: number;
  /** How long "remember this device" lets a browser skip MFA (default 30 days, at most 365; 0 disables the feature). */
  trustedDeviceLifetimeMs?: number;
  /**
   * Queue a `new-sign-in` email when a session starts from a client (user agent + IP) that none of the person's live
   * sessions or remembered devices has used. Off by default; tenants override it with `notifyNewSignIn`. Only sessions
   * that carry client details (the HTTP handler, or `withClient`) can be judged, so direct API sign-ins never notify.
   */
  signInNotifications?: boolean;
  /**
   * Let people who have no authenticator enrolled satisfy an MFA requirement with a one-time code emailed to their
   * verified address (`requestMfaCode` + `verifyMfa`). Off by default; tenants override it with `mfaEmailCodes`.
   * Never applies to root administrators or to people with an authenticator, who use it or their recovery codes.
   */
  mfaEmailCodes?: boolean;
  /**
   * Email a `sign-in-failures` alert to a person's verified address the moment this many attempts have failed since
   * their last sign-in (wrong password, factor, or recovery code); once per streak, since a successful sign-in
   * restarts the count. 0 (the default) disables it; at most 1000. Needs `sendEmail`.
   */
  failedSignInAlerts?: number;
  rateLimits?: RateLimitOptions;
  requireMfa?: (tenant: Tenant, identity: Identity) => boolean | Promise<boolean>;
  passkeys?: { rpID: string; rpName?: string };
  /** Runs inside the transaction that records an authentication audit event, so hosts can fan events out atomically. */
  onAudit?: (tx: IamStore, event: AuditEvent) => Promise<void>;
  /** Inject time for deterministic integration tests. */
  now?: () => number;
  /** Deployment-wide password screening (built-in common-password screen, breach corpus, custom rule). */
  passwordPolicy?: PasswordPolicyOptions;
}
export interface SessionResult {
  /** The bearer token, returned once; only its hash is stored. */
  token: string;
  /** The new session without its secret-derived fields (`tokenHash`, `uniqueKey`). */
  session: SafeSession;
}
export interface MfaRequired {
  mfaRequired: true;
  challenge: string;
  /**
   * No second factor is set up: enroll an authenticator (`beginMfa` / `confirmMfa`) or, when offered, use an emailed
   * code. False when an authenticator is enrolled or a registered passkey can satisfy the challenge.
   */
  enrollmentRequired: boolean;
  /** Whether an authenticator app is enabled, so an authenticator or recovery code can satisfy the challenge. */
  authenticatorEnrolled?: boolean;
  /** `requestMfaCode` may email a one-time code for this challenge instead of enrolling an authenticator. */
  emailCodeAvailable?: boolean;
  /** A registered passkey may satisfy this challenge (`beginPasskeyMfa` / `finishPasskeyMfa`). */
  passkeyAvailable?: boolean;
}
export type SignInResult = SessionResult | MfaRequired;
// Mapped types rather than Omit: Omit over a record with an index signature would erase every known key.
export type SafeIdentity = { [K in keyof Identity as Exclude<K, 'passwordHash'>]: Identity[K] };
export type SafeSession = {
  [K in keyof Session as Exclude<K, 'tokenHash' | 'uniqueKey'>]: Session[K];
};
export type MfaCredential = CredentialInput | { tenantId: string; challenge: string };
/** A remembered browser that may satisfy the MFA requirement until it expires or is revoked. */
export interface TrustedDevice extends StoredRecord {
  identityId: string;
  tokenHash: string;
  createdAt: number;
  expiresAt: number;
  lastUsedAt: number;
  client?: SessionClientInfo;
}
export type SafeTrustedDevice = {
  [K in keyof TrustedDevice as Exclude<K, 'tokenHash' | 'uniqueKey'>]: TrustedDevice[K];
};
/** A session plus, when the caller asked to remember the device and the policy allows it, the device token. */
export type MfaSessionResult = SessionResult & { deviceToken?: string; deviceExpiresAt?: number };
/** Per-person sign-in bookkeeping (`authSignIns`, one record per identity, `id` = identity ID); see `SignInRecord`. */
export interface SignInLedger extends StoredRecord, SignInRecord {
  identityId: string;
}
/** What a failed attempt presented wrongly; recorded on `auth:signin:fail` events. */
export type SignInFailureReason = 'password' | 'mfa' | 'recovery-code';
/**
 * A network (IPv4/IPv6 address or CIDR block) refused across a tenant's sign-in flows and live sessions
 * (`authBlocks`); a `platform` block, set by root administrators on the root tenant, applies to every tenant.
 */
export interface NetworkBlock extends StoredRecord {
  network: string;
  reason: string;
  createdAt: number;
  createdBy: string;
  expiresAt?: number;
  platform?: boolean;
}

/** Records private to the authentication service. */
export interface Challenge extends StoredRecord {
  purpose: string;
  tokenHash: string;
  identityId: string;
  expiresAt: number;
  payload: Record<string, string>;
  sessionId?: string;
}
export interface MfaRecord extends StoredRecord {
  identityId: string;
  encryptedSecret: string;
  recoveryHashes: string[];
  enabled: boolean;
  lastUsedStep: number;
}
export interface PasskeyRecord extends StoredRecord {
  identityId: string;
  credentialId: string;
  publicKey: string;
  counter: number;
  transports?: AuthenticatorTransportFuture[];
  /** A label the person chose or the default derived from the authenticator's transports. */
  name?: string;
  createdAt?: number;
  /** Last successful sign-in or MFA assertion with this passkey. */
  lastUsedAt?: number;
  /** Whether the credential is bound to one authenticator or synced across devices (from the registration). */
  deviceType?: 'singleDevice' | 'multiDevice';
  backedUp?: boolean;
  aaguid?: string;
}
/** What `listPasskeys` returns: everything but the key material. */
export type SafePasskey = {
  [K in keyof PasskeyRecord as Exclude<K, 'publicKey' | 'counter' | 'uniqueKey'>]: PasskeyRecord[K];
};
export interface RateRecord extends StoredRecord {
  count: number;
  resetAt: number;
}
/** A previous password hash, kept (newest 24 per identity) so `passwordHistory` can refuse reuse. */
export interface PasswordHistoryRecord extends StoredRecord {
  identityId: string;
  hash: string;
  createdAt: number;
}
