import { isIP } from 'node:net';
import { decryptSecret, encryptSecret } from '@better-iam/auth';
import {
  IamError,
  findOrdered,
  matchPattern,
  type AuthenticatedPrincipal,
  type IamPlugin,
  type IamStore,
  type Identity,
  type Session,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import { withDeviceKey } from './devices.js';
import { grantDeadline as sharedGrantDeadline } from './grant-deadline.js';
import type { ResolvedResource } from './options.js';
import {
  buildSshKrl,
  generateSshAuthorityKey,
  parseSshPublicKey,
  sshFingerprint,
  sshKeyLine,
  sshLoginPrincipal,
  sshSigningKey,
  type SshPublicKey,
  type SshSigningKey,
} from './ssh-ca.js';
import { id } from './utils.js';

/**
 * SSH certificate authority: people and machines get short-lived OpenSSH user certificates for exactly the hosts and
 * logins policies allow, hosts get certificates their clients trust, and hosts refuse revoked certificates through a
 * key revocation list. Each tenant has a user authority and a host authority (Ed25519, sealed with the deployment
 * secret). Access is an ordinary policy decision: `ssh:login` on `ssh-login/{host}/{login}` (attributes: the host's
 * labels plus `host` and `login`), and `ssh:port-forward` / `ssh:agent-forward` / `ssh:x11-forward` on
 * `ssh-host/{host}`. A certificate names each host it opens as the principal `{login}@{host}`, and every enrolled
 * host accepts, for each local login, only its own principal, so one certificate never opens a host it was not
 * issued for. A certificate lives only as long as the session that requested it and the grants that allowed it.
 */

export interface SshOptions {
  /** The longest user certificate any tenant may allow, in milliseconds (default 24 hours, 5 minutes to 7 days). */
  maxUserCertificateMs?: number;
  /** Host certificate lifetime (default 90 days, 1 day to 1 year); hosts renew with their renewal token. */
  hostCertificateMs?: number;
  /** How far `valid after` is backdated against clock skew (default 5 minutes, at most 1 hour). */
  clockSkewMs?: number;
  /** The most hosts one user certificate may name (default 64, 1 to 256). */
  maxHostsPerCertificate?: number;
  /** How long certificate records stay after they expire, for audits (default 90 days, 1 to 3650). */
  recordRetentionDays?: number;
  /** How long a host join token stays valid (default 24 hours, 5 minutes to 30 days). */
  joinTokenMs?: number;
  /** Certificates one identity may request per rate-limit window (default 60). */
  issuanceLimit?: number;
}

export const sshLoginResourceType = 'ssh-login';
export const sshHostResourceType = 'ssh-host';
export const sshLoginAction = 'ssh:login';
/** Forwarding a certificate allows only when every host it names allows it (certificate extensions are global). */
export const sshForwardingActions = {
  'ssh:port-forward': 'permit-port-forwarding',
  'ssh:agent-forward': 'permit-agent-forwarding',
  'ssh:x11-forward': 'permit-X11-forwarding',
} as const;
export type SshForwardingAction = keyof typeof sshForwardingActions;

const HOUR = 3_600_000;
const DAY = 86_400_000;
/** Certificates for agents acting for people (delegated sessions) are short: their confirmations are. */
export const DELEGATED_CERTIFICATE_MS = 10 * 60_000;

export interface ResolvedSshOptions {
  maxUserCertificateMs: number;
  hostCertificateMs: number;
  clockSkewMs: number;
  maxHostsPerCertificate: number;
  recordRetentionMs: number;
  joinTokenMs: number;
  issuanceLimit: number;
}

function bounded(value: unknown, fallback: number, min: number, max: number, name: string) {
  const resolved = value ?? fallback;
  if (typeof resolved !== 'number' || !Number.isSafeInteger(resolved) || resolved < min || resolved > max)
    throw new IamError('INVALID_CONFIG', `ssh.${name} must be an integer between ${min} and ${max}`);
  return resolved;
}

/** Validates the `ssh` option; undefined when the module is off. */
export function resolveSshOptions(value: unknown): ResolvedSshOptions | undefined {
  if (value === undefined || value === false) return undefined;
  if (value !== true && (typeof value !== 'object' || value === null || Array.isArray(value)))
    throw new IamError('INVALID_CONFIG', 'ssh must be true or an options object');
  const options = (value === true ? {} : value) as SshOptions;
  return {
    maxUserCertificateMs: bounded(options.maxUserCertificateMs, DAY, 5 * 60_000, 7 * DAY, 'maxUserCertificateMs'),
    hostCertificateMs: bounded(options.hostCertificateMs, 90 * DAY, DAY, 365 * DAY, 'hostCertificateMs'),
    clockSkewMs: bounded(options.clockSkewMs, 5 * 60_000, 0, HOUR, 'clockSkewMs'),
    maxHostsPerCertificate: bounded(options.maxHostsPerCertificate, 64, 1, 256, 'maxHostsPerCertificate'),
    recordRetentionMs: bounded(options.recordRetentionDays, 90, 1, 3650, 'recordRetentionDays') * DAY,
    joinTokenMs: bounded(options.joinTokenMs, DAY, 5 * 60_000, 30 * DAY, 'joinTokenMs'),
    issuanceLimit: bounded(options.issuanceLimit, 60, 1, 100_000, 'issuanceLimit'),
  };
}

const resolvedOptions = new WeakMap<object, ResolvedSshOptions | undefined>();
/** The deployment's SSH settings, or undefined when `ssh` is off. */
export function sshOptions(ctx: ServerContext): ResolvedSshOptions | undefined {
  if (!resolvedOptions.has(ctx.options)) resolvedOptions.set(ctx.options, resolveSshOptions(ctx.options.ssh));
  return resolvedOptions.get(ctx.options);
}
export function assertSsh(ctx: ServerContext): ResolvedSshOptions {
  const options = sshOptions(ctx);
  if (!options)
    throw new IamError('FEATURE_DISABLED', 'The SSH certificate authority is not enabled on this deployment', 403);
  return options;
}

/** The catalog entries the module contributes when enabled: the `ssh-login` and `ssh-host` types and their actions. */
export function sshPlugins(options: { ssh?: unknown }): IamPlugin[] {
  if (!resolveSshOptions(options.ssh)) return [];
  return [
    {
      id: 'better-iam:ssh',
      resourceTypes: {
        [sshLoginResourceType]: {
          description: 'Logging in to an enrolled SSH host as one local account: ssh-login/{host}/{login}',
          actions: [sshLoginAction],
          attributes: { host: 'string', login: 'string' },
        },
        [sshHostResourceType]: {
          description: 'An enrolled SSH host, for the forwarding a certificate may allow: ssh-host/{host}',
          actions: Object.keys(sshForwardingActions),
          attributes: { host: 'string' },
        },
      },
    },
  ];
}

/** A tenant's SSH settings (collection `sshSettings`, one record per tenant, id = tenant ID). */
export interface SshSettings extends StoredRecord {
  /** People must hold an MFA session to get a certificate (service accounts and agents are unaffected). */
  requireMfa: boolean;
  /** Only FIDO security keys (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`) are certified. */
  requireSecurityKey: boolean;
  /** Security-key certificates carry `verify-required`: the key must check its PIN or biometric at each login. */
  requireUserVerification: boolean;
  /** Certificates carry `source-address` with the caller's IP, so they only work from where they were issued. */
  bindSourceAddress: boolean;
  /** The lifetime when a request names none. */
  defaultCertificateMs: number;
  /** The longest lifetime a request may ask for (never above the deployment's `maxUserCertificateMs`). */
  maxCertificateMs: number;
  /**
   * known_hosts patterns (`*.corp.example.com`, `10.20.*`, `!bastion.corp.example.com`) the host authority is trusted
   * for; every host name and address must match them. Empty (the default): host names must be single labels, private
   * addresses, or names under the organization's verified domains, and members' clients trust the authority for
   * exactly the enrolled names.
   */
  hostPatterns: string[];
  /** Increases with every revocation; the revocation lists' version. */
  revocationVersion: number;
  updatedAt?: number;
  updatedBy?: string;
}

export type SshAuthorityKind = 'user' | 'host';
/**
 * An authority key. `active` signs; `pending` is published (trusted) ahead of a rotation so hosts and clients pick it
 * up before it signs; `previous` stays trusted after a rotation until its certificates have expired; `retired` is
 * trusted nowhere.
 */
export type SshAuthorityStatus = 'pending' | 'active' | 'previous' | 'retired';
export interface SshAuthority extends StoredRecord {
  kind: SshAuthorityKind;
  status: SshAuthorityStatus;
  algorithm: 'ssh-ed25519';
  /** The public key as an authorized_keys-style line. */
  publicKey: string;
  fingerprint: string;
  keySealed: string;
  createdAt: number;
  createdBy: string;
  activatedAt?: number;
  rotatedAt?: number;
  retiredAt?: number;
}

export type SshHostStatus = 'pending' | 'enrolled' | 'disabled';
/** A server people SSH into. Its `name` is unique in the tenant and never changes; it is part of every principal. */
export interface SshHost extends StoredRecord {
  name: string;
  description?: string;
  /** DNS names and addresses clients connect with; the host certificate names them (and `name`). Unique per tenant. */
  addresses: string[];
  /** The local accounts people may be granted (`ssh-login/{name}/{login}`). */
  logins: string[];
  /** Free-form attributes for policies (`resource.environment`, ...). */
  labels: Record<string, string>;
  status: SshHostStatus;
  joinTokenHash?: string;
  joinTokenExpiresAt?: number;
  renewalTokenHash?: string;
  /** The renewal token handed out before the current one, accepted until the host uses the new one. */
  previousRenewalTokenHash?: string;
  /** The host's own public key once enrolled. */
  hostKey?: string;
  hostKeyFingerprint?: string;
  certificateId?: string;
  certificateExpiresAt?: number;
  enrolledAt?: number;
  renewedAt?: number;
  /** Last enrollment or sync with this host's token. */
  lastSeenAt?: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}

export type SshRevocationReason =
  | 'revoked'
  | 'identity-revoked'
  | 'identity-inactive'
  | 'access-changed'
  | 'session-ended'
  | 'host-disabled'
  | 'host-deleted'
  | 'addresses-changed'
  | 'superseded'
  | 'authority-retired'
  | 'tenant-revoked';

/** An issued certificate (collection `sshCertificates`); kept `recordRetentionDays` past its expiry. */
export interface SshCertificateRecord extends StoredRecord {
  kind: 'user' | 'host';
  /** Decimal uint64. */
  serial: string;
  keyId: string;
  authorityId: string;
  /** User certificates: who it was issued to, the session it came from, and that session's MFA state. */
  identityId?: string;
  sessionId?: string;
  sessionKind?: string;
  mfa?: boolean;
  /**
   * User certificates: the registered device key the issuing request proved (devices.ts), so the sweep judges device
   * conditions by that device as it stands now; absent when the request proved none.
   */
  deviceKeyId?: string;
  /** Host certificates: the host. */
  hostId?: string;
  principals: string[];
  /** User certificates: the hosts and logins it opens. */
  access?: { host: string; logins: string[] }[];
  extensions: string[];
  sourceAddress?: string;
  keyType: string;
  publicKeyFingerprint: string;
  /** Host certificates: the certified key, published as `@revoked` once the certificate is revoked. */
  publicKey?: string;
  validAfter: number;
  validBefore: number;
  issuedAt: number;
  reason?: string;
  revokedAt?: number;
  revokedBy?: string;
  revocationReason?: SshRevocationReason;
  /** Host certificates: the certificate line, handed out again at each `syncHost`. */
  certificate?: string;
  /** When the record itself is swept (retention.ts): `validBefore` plus the record retention. */
  expiresAt: number;
}

export const sshCollections = ['sshSettings', 'sshAuthorities', 'sshHosts', 'sshCertificates'] as const;

export function defaultSshSettings(tenantId: string, options: ResolvedSshOptions): SshSettings {
  return {
    id: tenantId,
    tenantId,
    requireMfa: false,
    requireSecurityKey: false,
    requireUserVerification: false,
    bindSourceAddress: false,
    defaultCertificateMs: Math.min(8 * HOUR, options.maxUserCertificateMs),
    maxCertificateMs: Math.min(16 * HOUR, options.maxUserCertificateMs),
    hostPatterns: [],
    revocationVersion: 0,
  };
}

/** known_hosts pattern-list semantics (case-insensitive): some pattern matches and no negated (`!`) one does. */
export function knownHostsMatch(patterns: string[], name: string): boolean {
  const value = name.toLowerCase();
  let matched = false;
  for (const raw of patterns) {
    const pattern = raw.toLowerCase();
    const negated = pattern.startsWith('!');
    if (!matchPattern(negated ? pattern.slice(1) : pattern, value)) continue;
    if (negated) return false;
    matched = true;
  }
  return matched;
}

/** The tenant's verified email/DNS domains (domains API), which bound the host names it may vouch for. */
export async function verifiedDomains(tx: IamStore, tenantId: string): Promise<string[]> {
  return (
    await tx.find<{ id: string; tenantId: string; domain: string; status: string }>('tenantDomains', {
      tenantId,
      status: 'verified',
    })
  ).map((record) => record.domain.toLowerCase());
}

const underDomain = (name: string, domains: string[]) =>
  domains.some((domain) => name === domain || name.endsWith(`.${domain}`));

/** Private, loopback, link-local and shared address space: never another organization's public address. */
export function privateAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    const [a, b] = address.split('.').map(Number) as [number, number];
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  if (family === 6) {
    const first = address.toLowerCase().split(':')[0] ?? '';
    return address === '::1' || /^f[cd][0-9a-f]{0,2}$/.test(first) || /^fe[89ab][0-9a-f]?$/.test(first);
  }
  return false;
}

/**
 * Validates `hostPatterns`: every positive pattern must pin a literal suffix the organization owns (a verified domain
 * such as `*.corp.example.com`) or a literal address prefix (`10.20.*`, `fd00:1:*`); `*` alone is refused.
 */
export function hostPatternList(value: unknown, domains: string[]): string[] {
  if (!Array.isArray(value) || value.length > 16)
    throw new IamError('INVALID_INPUT', 'hostPatterns must list at most 16 known_hosts patterns');
  const patterns = [
    ...new Set(
      value.map((item) => {
        if (typeof item !== 'string' || !/^!?[a-zA-Z0-9.*?:_-]{1,253}$/.test(item))
          throw new IamError('INVALID_INPUT', 'hostPatterns hold known_hosts patterns such as *.corp.example.com');
        return item.toLowerCase();
      }),
    ),
  ];
  const positive = patterns.filter((pattern) => !pattern.startsWith('!'));
  if (patterns.length && !positive.length)
    throw new IamError('INVALID_INPUT', 'hostPatterns needs at least one pattern that is not negated');
  for (const pattern of positive) {
    const wildcard = Math.max(pattern.lastIndexOf('*'), pattern.lastIndexOf('?'));
    const ipv4 = /^\d{1,3}\.\d{1,3}\.[0-9.*?]*$/.test(pattern);
    const ipv6 = /^[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f:*?]*$/.test(pattern);
    const suffix = wildcard < 0 ? pattern : pattern.slice(wildcard + 1);
    const dns = (wildcard < 0 || suffix.startsWith('.')) && underDomain(suffix.replace(/^\./, ''), domains);
    const literalPrivate = wildcard < 0 && isIP(pattern) > 0 && privateAddress(pattern);
    // Short (single-label) names such as `web-*` mean nothing outside the organization's network; `*` alone is refused.
    const shortName = /^[a-z0-9*?-]+$/.test(pattern) && /[a-z0-9]/.test(pattern) && pattern !== 'localhost';
    if (!ipv4 && !ipv6 && !dns && !literalPrivate && !shortName)
      throw new IamError(
        'HOST_OUTSIDE_PATTERNS',
        `Pattern ${pattern.slice(0, 64)} must end in a verified domain of this organization or fix an address prefix`,
        400,
      );
  }
  return patterns;
}

/**
 * Refuses host names or addresses the organization cannot vouch for: outside its `hostPatterns` when it has any;
 * otherwise anything but single labels, private addresses, and names under its verified domains.
 */
export function assertVouchable(settings: SshSettings, domains: string[], names: string[]): void {
  const patterns = settings.hostPatterns;
  // Patterns only narrow: `*` crosses dots, so a pattern alone never makes a foreign name vouchable.
  const ipPattern = (name: string) =>
    patterns.some(
      (pattern) =>
        !pattern.startsWith('!') &&
        (/^\d{1,3}\.\d{1,3}\.[0-9.*?]*$/.test(pattern) || /^[0-9a-f]{1,4}:[0-9a-f]{1,4}:/.test(pattern)) &&
        matchPattern(pattern, name),
    );
  const outside = names.filter((name) => {
    if (patterns.length && !knownHostsMatch(patterns, name)) return true;
    if (isIP(name)) return !privateAddress(name) && !ipPattern(name);
    if (!name.includes('.')) return name === 'localhost';
    return !underDomain(name, domains);
  });
  if (outside.length)
    throw new IamError(
      'HOST_OUTSIDE_PATTERNS',
      `${outside.slice(0, 5).join(', ')} is outside the names this organization can vouch for (verify its domain or set hostPatterns)`,
      400,
    );
}

/** Refuses names or addresses another host of the tenant already uses (any status). */
export async function assertNamesFree(
  tx: IamStore,
  tenantId: string,
  names: string[],
  hostId?: string,
): Promise<void> {
  const wanted = new Set(names);
  for (const host of await tx.find<SshHost>('sshHosts', { tenantId })) {
    if (host.id === hostId) continue;
    const taken = [host.name, ...host.addresses].find((name) => wanted.has(name));
    if (taken) throw new IamError('HOST_NAME_TAKEN', `Host ${host.name} already uses ${taken}`, 409);
  }
}

/** Refuses a host key that is a tenant authority key or another host's key (a revocation of it would hit them). */
export async function assertHostKeyFree(
  tx: IamStore,
  tenantId: string,
  hostId: string,
  key: SshPublicKey,
): Promise<void> {
  if (key.securityKey) throw new IamError('INVALID_INPUT', 'Host keys cannot be security keys');
  if ((await tenantAuthorities(tx, tenantId)).some((authority) => authority.fingerprint === key.fingerprint))
    throw new IamError('INVALID_INPUT', 'An authority key cannot be a host key');
  const other = (await tx.find<SshHost>('sshHosts', { tenantId })).find(
    (host) => host.id !== hostId && host.hostKeyFingerprint === key.fingerprint,
  );
  if (other) throw new IamError('HOST_KEY_IN_USE', `Host ${other.name} already uses this key`, 409);
}

export async function loadSshSettings(ctx: ServerContext, tx: IamStore, tenantId: string): Promise<SshSettings> {
  const options = assertSsh(ctx);
  const stored = await tx.get<SshSettings>('sshSettings', tenantId);
  const defaults = defaultSshSettings(tenantId, options);
  if (!stored || stored.tenantId !== tenantId) return defaults;
  // A deployment that lowered its maximum caps what tenants stored earlier.
  return {
    ...defaults,
    ...stored,
    maxCertificateMs: Math.min(stored.maxCertificateMs, options.maxUserCertificateMs),
    defaultCertificateMs: Math.min(
      stored.defaultCertificateMs,
      stored.maxCertificateMs,
      options.maxUserCertificateMs,
    ),
  };
}

/** Stores a tenant's settings (the record exists once anything was changed or revoked). */
export async function saveSshSettings(tx: IamStore, settings: SshSettings): Promise<SshSettings> {
  return (await tx.get<SshSettings>('sshSettings', settings.id))
    ? tx.put<SshSettings>('sshSettings', settings)
    : tx.insert<SshSettings>('sshSettings', settings);
}

/** Bumps the revocation list version after a revocation. */
export async function bumpRevocationVersion(ctx: ServerContext, tx: IamStore, tenantId: string): Promise<void> {
  const settings = await loadSshSettings(ctx, tx, tenantId);
  await saveSshSettings(tx, { ...settings, revocationVersion: settings.revocationVersion + 1 });
}

const authorityContext = (authority: { id: string }) => `ssh-authority:${authority.id}`;

export async function tenantAuthorities(
  tx: IamStore,
  tenantId: string,
  kind?: SshAuthorityKind,
): Promise<SshAuthority[]> {
  const found = await tx.find<SshAuthority>('sshAuthorities', {
    tenantId,
    ...(kind ? { kind } : {}),
  });
  // User authorities first, then oldest first.
  return found.sort(
    (a, b) =>
      (a.kind === b.kind ? 0 : a.kind === 'user' ? -1 : 1) ||
      a.createdAt - b.createdAt ||
      (a.id < b.id ? -1 : 1),
  );
}

/** Creates an authority key, sealed under the deployment secret. */
export async function createAuthority(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  kind: SshAuthorityKind,
  status: 'active' | 'pending',
  actorId: string,
): Promise<SshAuthority> {
  const key = generateSshAuthorityKey();
  const record: SshAuthority = {
    id: id(),
    tenantId,
    kind,
    status,
    algorithm: 'ssh-ed25519',
    publicKey: sshKeyLine(key.publicBlob, `better-iam-${kind}-ca`),
    fingerprint: sshFingerprint(key.publicBlob),
    keySealed: '',
    createdAt: ctx.now(),
    createdBy: actorId,
    ...(status === 'active' ? { activatedAt: ctx.now() } : {}),
  };
  record.keySealed = encryptSecret(key.privatePkcs8, ctx.options.secret, authorityContext(record));
  return tx.insert<SshAuthority>('sshAuthorities', record);
}

/** Creates the tenant's user and host authorities when missing; returns the active ones. */
export async function ensureAuthorities(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  actorId: string,
): Promise<{ user: SshAuthority; host: SshAuthority; created: SshAuthorityKind[] }> {
  const created: SshAuthorityKind[] = [];
  const active = async (kind: SshAuthorityKind) => {
    const existing = (await tenantAuthorities(tx, tenantId, kind)).find((item) => item.status === 'active');
    if (existing) return existing;
    created.push(kind);
    return createAuthority(ctx, tx, tenantId, kind, 'active', actorId);
  };
  return { user: await active('user'), host: await active('host'), created };
}

/** The active authority of a kind, or SSH_NOT_CONFIGURED. */
export async function activeAuthority(
  tx: IamStore,
  tenantId: string,
  kind: SshAuthorityKind,
): Promise<SshAuthority> {
  const found = (await tenantAuthorities(tx, tenantId, kind)).find((item) => item.status === 'active');
  if (!found)
    throw new IamError('SSH_NOT_CONFIGURED', 'Set up the SSH certificate authority first (ssh.setup)', 409);
  return found;
}

export function publicBlobOf(authority: { publicKey: string }): Buffer {
  return Buffer.from(authority.publicKey.split(' ')[1]!, 'base64');
}

/** Opens an authority's signing key. */
export function openAuthority(ctx: ServerContext, authority: SshAuthority): SshSigningKey {
  const secrets = [ctx.options.secret, ...(ctx.options.previousSecrets ?? [])];
  return sshSigningKey(
    publicBlobOf(authority),
    decryptSecret(authority.keySealed, secrets, authorityContext(authority)),
  );
}

/** Keys hosts and clients trust: pending (ahead of a rotation), active, and previous (until retired). */
export const trustedStatuses: ReadonlySet<SshAuthorityStatus> = new Set(['pending', 'active', 'previous']);

/** Host names: lowercase letters, digits, dots and hyphens (no `/`, `@` or wildcards, so they can sit in principals). */
export function sshHostName(value: unknown): string {
  if (typeof value !== 'string') throw new IamError('INVALID_INPUT', 'Invalid host name');
  const name = value.trim().toLowerCase();
  if (
    !/^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$/.test(name) ||
    name.includes('..') ||
    // A dotted name ending in digits would read as an address (`127.1`).
    (name.includes('.') && /^\d+$/.test(name.split('.').at(-1)!))
  )
    throw new IamError('INVALID_INPUT', 'Host names use 1-128 lowercase letters, digits, "." or "-"');
  return name;
}

const reservedLabels = new Set([
  'host',
  'login',
  'tenantId',
  'name',
  'status',
  'id',
  'type',
  'ownerId',
  'parentId',
  'parentType',
]);
/** Host labels: at most 32 `name: value` pairs; the names policies read as `resource.{name}`. */
export function sshLabels(value: unknown): Record<string, string> {
  if (value === undefined) return {};
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new IamError('INVALID_INPUT', 'labels must be an object of strings');
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > 32) throw new IamError('INVALID_INPUT', 'A host has at most 32 labels');
  const labels: Record<string, string> = {};
  for (const [key, item] of entries) {
    if (!/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(key) || reservedLabels.has(key))
      throw new IamError('INVALID_INPUT', `Invalid or reserved label name ${key.slice(0, 64)}`);
    if (typeof item !== 'string' || item.length > 256 || /[\u0000-\u001f]/.test(item))
      throw new IamError('INVALID_INPUT', `Label ${key} must be a string of at most 256 characters`);
    labels[key] = item;
  }
  return labels;
}

export async function hostByName(tx: IamStore, tenantId: string, name: string): Promise<SshHost | undefined> {
  return (await tx.find<SshHost>('sshHosts', { tenantId, uniqueKey: name }))[0];
}

/** What policies see for `ssh-login/{host}/{login}`. */
export function loginResource(host: SshHost, login: string): ResolvedResource {
  return {
    tenantId: host.tenantId,
    type: sshLoginResourceType,
    id: `${host.name}/${login}`,
    attributes: { ...host.labels, host: host.name, login },
  };
}
/** What policies see for `ssh-host/{host}`. */
export function hostResource(host: SshHost): ResolvedResource {
  return {
    tenantId: host.tenantId,
    type: sshHostResourceType,
    id: host.name,
    attributes: { ...host.labels, host: host.name },
  };
}

/**
 * Resolves `ssh-login/{host}/{login}` and `ssh-host/{host}` for the decision engine (so `authorize`, `whoCan` and
 * `simulate` work on them); undefined for other types. Unknown hosts and logins are NOT_FOUND.
 */
export async function resolveSshResource(
  ctx: ServerContext,
  tx: IamStore,
  reference: { tenantId: string; type: string; id: string },
): Promise<ResolvedResource | undefined> {
  if (reference.type !== sshLoginResourceType && reference.type !== sshHostResourceType) return undefined;
  if (!sshOptions(ctx)) return undefined;
  const slash = reference.id.indexOf('/');
  const name =
    reference.type === sshHostResourceType ? reference.id : slash > 0 ? reference.id.slice(0, slash) : '';
  const host = name ? await hostByName(tx, reference.tenantId, name) : undefined;
  if (!host) throw new IamError('NOT_FOUND', 'Unknown SSH host', 404);
  if (reference.type === sshHostResourceType) return hostResource(host);
  const login = slash > 0 ? reference.id.slice(slash + 1) : '';
  if (!host.logins.includes(login)) throw new IamError('NOT_FOUND', 'Unknown login on this host', 404);
  return loginResource(host, login);
}

/** The per-host principals file lines: one file per login holding `{login}@{host}`. */
export function principalFiles(host: SshHost): Record<string, string> {
  return Object.fromEntries(host.logins.map((login) => [login, `${sshLoginPrincipal(login, host.name)}\n`]));
}

/** Whether the tenant and every ancestor are active. */
export async function tenantActive(ctx: ServerContext, reader: IamStore, tenant: Tenant): Promise<boolean> {
  return (await ctx.ancestry(reader, tenant)).every((item) => item.status === 'active');
}

/**
 * Host keys clients must refuse: the current key of disabled hosts and the keys of unexpired revoked host
 * certificates that no enrolled host uses any more (a rebuilt or deleted host's old key). Never an authority key.
 */
async function revokedHostKeys(ctx: ServerContext, reader: IamStore, tenantId: string): Promise<string[]> {
  const now = ctx.now();
  const hosts = await reader.find<SshHost>('sshHosts', { tenantId });
  const inUse = new Set(
    hosts.filter((host) => host.status === 'enrolled' && host.hostKeyFingerprint).map((host) => host.hostKeyFingerprint),
  );
  const authorities = new Set((await tenantAuthorities(reader, tenantId)).map((item) => item.fingerprint));
  const lines = new Map<string, string>();
  for (const host of hosts)
    if (host.status === 'disabled' && host.hostKey && host.hostKeyFingerprint)
      lines.set(host.hostKeyFingerprint, host.hostKey);
  for (const record of await liveRecords(ctx, reader, tenantId))
    if (
      record.kind === 'host' &&
      record.revokedAt !== undefined &&
      record.publicKey &&
      record.validBefore > now &&
      !inUse.has(record.publicKeyFingerprint)
    )
      lines.set(record.publicKeyFingerprint, record.publicKey);
  for (const fingerprint of authorities) lines.delete(fingerprint);
  return [...lines.values()].map((line) => line.split(' ').slice(0, 2).join(' '));
}

/**
 * Trust material. `public` (anyone with the tenant ID): the authority keys, and a known_hosts line only for configured
 * `hostPatterns`. `member` (members and hosts): the known_hosts line for the enrolled names as well, and `@revoked`
 * lines for host keys clients must refuse.
 */
export async function trustBundle(
  ctx: ServerContext,
  reader: IamStore,
  tenant: Tenant,
  audience: 'public' | 'member',
) {
  const settings = await loadSshSettings(ctx, reader, tenant.id);
  const authorities = await tenantAuthorities(reader, tenant.id);
  const trusted = (kind: SshAuthorityKind) =>
    authorities.filter((item) => item.kind === kind && trustedStatuses.has(item.status));
  const userAuthorities = trusted('user');
  const hostAuthorities = trusted('host');
  let patterns = settings.hostPatterns;
  if (!patterns.length && audience === 'member')
    patterns = [
      ...new Set(
        (await reader.find<SshHost>('sshHosts', { tenantId: tenant.id, status: 'enrolled' })).flatMap((host) => [
          host.name,
          ...host.addresses,
        ]),
      ),
    ].sort();
  const comment = `better-iam:${tenant.id}`;
  const knownHosts = [
    ...(patterns.length ? hostAuthorities : []).map(
      (authority) =>
        `@cert-authority ${patterns.join(',')} ${authority.publicKey.split(' ').slice(0, 2).join(' ')} ${comment}`,
    ),
    ...(audience === 'member'
      ? (await revokedHostKeys(ctx, reader, tenant.id)).map((key) => `@revoked * ${key} better-iam:revoked`)
      : []),
  ];
  const view = (item: SshAuthority) => ({
    id: item.id,
    status: item.status,
    publicKey: item.publicKey,
    fingerprint: item.fingerprint,
  });
  return {
    tenantId: tenant.id,
    /** For hosts: sshd `TrustedUserCAKeys`. */
    userAuthorities: userAuthorities.map(view),
    /** For clients: known_hosts `@cert-authority` lines. */
    hostAuthorities: hostAuthorities.map(view),
    hostPatterns: settings.hostPatterns,
    trustedUserCaKeys: userAuthorities.map((item) => `${item.publicKey}\n`).join(''),
    knownHosts: knownHosts.map((line) => `${line}\n`).join(''),
  };
}

/**
 * Unexpired certificate records of a tenant (plus some recently expired ones), read through the expiry index:
 * `expiresAt` is `validBefore` plus a retention of at least a day, so a record still valid has `expiresAt` over a day
 * ahead.
 */
export async function liveRecords(
  ctx: ServerContext,
  reader: IamStore,
  tenantId: string,
): Promise<SshCertificateRecord[]> {
  const now = ctx.now();
  return (
    await findOrdered<SshCertificateRecord>(reader, 'sshCertificates', { tenantId }, {
      field: 'expiresAt',
      from: now + DAY,
    })
  ).filter((record) => record.validBefore > now);
}

/** Certificate records that are still valid and not revoked. */
export async function liveCertificates(
  ctx: ServerContext,
  tx: IamStore,
  filter: Record<string, unknown> & { tenantId: string },
): Promise<SshCertificateRecord[]> {
  const now = ctx.now();
  return (await tx.find<SshCertificateRecord>('sshCertificates', { ...filter, revokedAt: undefined })).filter(
    (record) => record.validBefore > now,
  );
}

/** Marks one certificate revoked (idempotent); the caller bumps the revocation version. */
export async function markRevoked(
  ctx: ServerContext,
  tx: IamStore,
  record: SshCertificateRecord,
  reason: SshRevocationReason,
  actorId: string,
): Promise<SshCertificateRecord> {
  if (record.revokedAt !== undefined) return record;
  return tx.put<SshCertificateRecord>('sshCertificates', {
    ...record,
    revokedAt: ctx.now(),
    revokedBy: actorId,
    revocationReason: reason,
  });
}

const activeIdentity = (ctx: ServerContext, identity: Identity | undefined) =>
  Boolean(identity && identity.status === 'active' && !ctx.identityExpired(identity));

/**
 * A tenant's binary key revocation list.
 * - `user` (sshd `RevokedKeys`): the serials of unexpired user certificates that were revoked, whose holder is no
 *   longer active or whose session is gone (even before the sweep marks them), or all of them while the tenant or an
 *   ancestor is suspended.
 * - `host` (ssh `RevokedHostKeys` on clients): revoked host certificate serials and host keys clients must refuse.
 */
export async function revocationList(
  ctx: ServerContext,
  reader: IamStore,
  tenant: Tenant,
  kind: 'user' | 'host' = 'user',
) {
  const settings = await loadSshSettings(ctx, reader, tenant.id);
  const now = ctx.now();
  const active = await tenantActive(ctx, reader, tenant);
  const records = (await liveRecords(ctx, reader, tenant.id)).filter((record) => record.kind === kind);
  const identities = new Map<string, boolean>();
  const bySerial = new Map<string, bigint[]>();
  let revoked = 0;
  for (const record of records) {
    let dead = record.revokedAt !== undefined || (kind === 'user' && !active);
    if (!dead && record.identityId) {
      if (!identities.has(record.identityId))
        identities.set(
          record.identityId,
          activeIdentity(ctx, await reader.get<Identity>('identities', record.identityId)),
        );
      dead = !identities.get(record.identityId);
    }
    if (!dead && record.sessionId) {
      const session = await reader.get<Session>('sessions', record.sessionId);
      dead = !session || session.expiresAt <= now || session.identityId !== record.identityId;
    }
    if (!dead) continue;
    revoked++;
    bySerial.set(record.authorityId, [...(bySerial.get(record.authorityId) ?? []), BigInt(record.serial)]);
  }
  const authorities = new Map((await tenantAuthorities(reader, tenant.id)).map((item) => [item.id, item]));
  const keys =
    kind === 'host'
      ? (await revokedHostKeys(ctx, reader, tenant.id)).map((line) => Buffer.from(line.split(' ')[1]!, 'base64'))
      : [];
  const krl = buildSshKrl({
    version: BigInt(settings.revocationVersion),
    generatedAt: now,
    comment: `better-iam:${tenant.id}:${kind}`,
    authorities: [...bySerial].flatMap(([authorityId, serials]) => {
      const authority = authorities.get(authorityId);
      return authority ? [{ authority: publicBlobOf(authority), serials }] : [];
    }),
    keys,
  });
  return {
    tenantId: tenant.id,
    kind,
    version: settings.revocationVersion,
    generatedAt: now,
    tenantActive: active,
    revokedCertificates: revoked,
    revokedHostKeys: keys.length,
    /** The KRL, base64: write it (decoded) to the file sshd's `RevokedKeys` (or ssh's `RevokedHostKeys`) names. */
    krl: krl.toString('base64'),
  };
}

/** The latest a certificate may be valid until given the caller's time-limited grants of `ssh:login` (grant-deadline.ts). */
export const grantDeadline = (
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
  horizon: number,
) => sharedGrantDeadline(ctx, tx, principal, tenantId, horizon, sshLoginAction);

export interface SshSweepResult {
  examined: number;
  revoked: number;
  byReason: Partial<Record<SshRevocationReason, number>>;
}

/**
 * Continuous authorization for certificates already issued: revokes live user certificates whose holder is no longer
 * active, whose issuing session (user session, API key, role session, session token or delegated session) was revoked,
 * ended or no longer validates, or whose hosts, logins and forwarding policies no longer allow as decided for that very
 * session. A scheduler job (`iam.ssh.sweep`); hosts pick the result up with their next revocation list.
 */
export async function sweepSshCertificates(
  ctx: ServerContext,
  input: { tenantId?: string } = {},
): Promise<SshSweepResult> {
  assertSsh(ctx);
  const result: SshSweepResult = { examined: 0, revoked: 0, byReason: {} };
  const tenantIds = input.tenantId
    ? [input.tenantId]
    : [
        ...new Set(
          (await ctx.store.find<SshCertificateRecord>('sshCertificates', { kind: 'user', revokedAt: undefined }))
            .filter((record) => record.validBefore > ctx.now())
            .map((record) => record.tenantId),
        ),
      ];
  for (const tenantId of tenantIds) {
    await ctx.store.transaction(async (tx) => {
      const tenant = await tx.get<Tenant>('tenants', tenantId);
      if (!tenant) return;
      const records = await liveCertificates(ctx, tx, { tenantId, kind: 'user' });
      const hosts = new Map((await tx.find<SshHost>('sshHosts', { tenantId })).map((host) => [host.name, host]));
      type Prepared = Awaited<ReturnType<typeof ctx.decisions.prepareDecision>>;
      // Per issuing session: its decision, `ended` when it no longer validates, `skip` while its tenant is suspended.
      const decisions = new Map<string, Prepared | 'ended' | 'skip'>();
      let changed = false;
      for (const record of records) {
        result.examined++;
        const identity = record.identityId ? await tx.get<Identity>('identities', record.identityId) : undefined;
        let reason: SshRevocationReason | undefined;
        if (!activeIdentity(ctx, identity)) reason = 'identity-inactive';
        else {
          const key = `${record.sessionId ?? ''} ${record.deviceKeyId ?? ''}`;
          if (!decisions.has(key)) {
            const session = record.sessionId ? await tx.get<Session>('sessions', record.sessionId) : undefined;
            let state: Prepared | 'ended' | 'skip' = 'ended';
            if (session && session.identityId === identity!.id)
              try {
                // The same validation every request gets: revocations, expiry and idle limits, authority chains,
                // delegations and their confirmations, network rules.
                const current = await ctx.principals.currentPrincipal(tx, { identity: identity!, session });
                // With no request to carry a proof, device conditions judge the device the issuing request proved.
                const principal = record.deviceKeyId ? withDeviceKey(current, record.deviceKeyId) : current;
                state = await ctx.decisions.prepareDecision(tx, principal, tenant, sshLoginAction);
                if (
                  'fixed' in state &&
                  state.fixed.reason === 'ROOT_OVERRIDE' &&
                  principal.identity.tenantId !== tenantId
                )
                  state = { fixed: { allowed: false, reason: 'ROOT_SSH_RESTRICTED', matched: [] } };
              } catch (error) {
                // A suspended tenant is refused by the revocation list itself; its certificates return with it.
                state = (error as IamError).code === 'TENANT_INACTIVE' ? 'skip' : 'ended';
              }
            decisions.set(key, state);
          }
          const prepared = decisions.get(key)!;
          if (prepared === 'skip') continue;
          if (prepared === 'ended') reason = 'session-ended';
          else {
            const decide = (resource: ResolvedResource, action: string) =>
              ('fixed' in prepared ? prepared.fixed : prepared.evaluate(resource, action)).allowed;
            const named = (record.access ?? []).flatMap(({ host: name }) => {
              const host = hosts.get(name);
              return host ? [host] : [];
            });
            const loginLost = (record.access ?? []).some(({ host: name, logins }) => {
              const host = hosts.get(name);
              // A deleted host takes nothing away; its principals open nothing any more.
              if (!host) return false;
              return logins.some(
                (login) => !host.logins.includes(login) || !decide(loginResource(host, login), sshLoginAction),
              );
            });
            const forwardingLost = Object.entries(sshForwardingActions).some(
              ([action, extension]) =>
                record.extensions.includes(extension) && named.some((host) => !decide(hostResource(host), action)),
            );
            if (loginLost || forwardingLost) reason = 'access-changed';
          }
        }
        if (!reason) continue;
        await markRevoked(ctx, tx, record, reason, 'deployment-operator');
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: 'deployment-operator',
          action: 'ssh:certificate:revoke',
          resourceId: `ssh/certificates/${record.id}`,
          outcome: 'allow',
          timestamp: ctx.now(),
          metadata: { reason, serial: record.serial, identityId: record.identityId ?? null },
        });
        result.revoked++;
        result.byReason[reason] = (result.byReason[reason] ?? 0) + 1;
        changed = true;
      }
      if (changed) await bumpRevocationVersion(ctx, tx, tenantId);
    });
  }
  return result;
}

/** A key ID for sshd logs: who (and the agent acting for them), printable ASCII only. */
export function certificateKeyId(principal: AuthenticatedPrincipal): string {
  const who = principal.identity.email ?? principal.identity.name ?? principal.identity.id;
  const agent = (principal.session as { agentId?: unknown }).agentId;
  const via = typeof agent === 'string' ? ` via agent ${agent}` : principal.session.originalIdentityId ? ` via ${principal.session.originalIdentityId}` : '';
  return `${who} (${principal.identity.id})${via}`.replace(/[^\x20-\x7e]|"/g, '_').slice(0, 256);
}

/** Parses a stored host key line (enrolled keys were validated when they arrived). */
export const storedHostKey = (host: SshHost) => parseSshPublicKey(host.hostKey);
