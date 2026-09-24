import { isIP } from 'node:net';
import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { presentedDevice } from '../devices.js';
import { OperationDenied } from '../operations.js';
import type { ResolvedResource } from '../options.js';
import {
  SSH_CERT_HOST,
  SSH_CERT_USER,
  parseSshPublicKey,
  signSshCertificate,
  sshHostAddress,
  sshKeyLine,
  sshLogin,
  sshLoginPrincipal,
  sshSerial,
  type SshPublicKey,
} from '../ssh-ca.js';
import {
  DELEGATED_CERTIFICATE_MS,
  activeAuthority,
  assertHostKeyFree,
  assertNamesFree,
  assertSsh,
  assertVouchable,
  bumpRevocationVersion,
  certificateKeyId,
  createAuthority,
  ensureAuthorities,
  grantDeadline,
  hostByName,
  hostPatternList,
  hostResource,
  liveCertificates,
  loadSshSettings,
  loginResource,
  markRevoked,
  openAuthority,
  principalFiles,
  revocationList,
  saveSshSettings,
  sshForwardingActions,
  sshHostName,
  sshLabels,
  sshLoginAction,
  storedHostKey,
  sweepSshCertificates,
  tenantActive,
  tenantAuthorities,
  trustBundle,
  verifiedDomains,
  type ResolvedSshOptions,
  type SshAuthority,
  type SshAuthorityKind,
  type SshCertificateRecord,
  type SshHost,
  type SshRevocationReason,
  type SshSettings,
  type SshSweepResult,
} from '../ssh.js';
import { byId, hash, id, sameHash, token } from '../utils.js';
import { integer, text } from '../validation.js';

/** An authority as administrators see it: never the sealed key. */
export interface SshAuthorityView {
  id: string;
  tenantId: string;
  kind: SshAuthorityKind;
  status: SshAuthority['status'];
  algorithm: 'ssh-ed25519';
  publicKey: string;
  fingerprint: string;
  createdAt: number;
  createdBy: string;
  activatedAt?: number;
  rotatedAt?: number;
  retiredAt?: number;
}
/** A host as administrators see it: never its token hashes. */
export interface SshHostView {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  addresses: string[];
  logins: string[];
  labels: Record<string, string>;
  status: SshHost['status'];
  hostKey?: string;
  hostKeyFingerprint?: string;
  certificateId?: string;
  certificateExpiresAt?: number;
  joinTokenExpiresAt?: number;
  enrolledAt?: number;
  renewedAt?: number;
  lastSeenAt?: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}
type SshCertificateRecordFields = Pick<
  SshCertificateRecord,
  | 'kind'
  | 'serial'
  | 'keyId'
  | 'authorityId'
  | 'identityId'
  | 'sessionKind'
  | 'mfa'
  | 'hostId'
  | 'principals'
  | 'access'
  | 'extensions'
  | 'sourceAddress'
  | 'keyType'
  | 'publicKeyFingerprint'
  | 'validAfter'
  | 'validBefore'
  | 'issuedAt'
  | 'reason'
  | 'revokedAt'
  | 'revokedBy'
  | 'revocationReason'
>;
export type SshCertificateView = SshCertificateRecordFields & {
  id: string;
  tenantId: string;
  status: 'active' | 'revoked' | 'expired';
};

export interface SshSettingsView {
  tenantId: string;
  requireMfa: boolean;
  requireSecurityKey: boolean;
  requireUserVerification: boolean;
  bindSourceAddress: boolean;
  defaultCertificateMs: number;
  maxCertificateMs: number;
  hostPatterns: string[];
  revocationVersion: number;
  /** The deployment's ceiling for `maxCertificateMs`. */
  deploymentMaxCertificateMs: number;
  updatedAt?: number;
  updatedBy?: string;
}

export interface SshCertificateRequest {
  tenantId: string;
  /** The OpenSSH public key to certify (`ssh-ed25519 AAAA... comment`). */
  publicKey: string;
  /** Host names to open (default: every enrolled host the caller may log in to, up to the deployment's limit). */
  hosts?: string[];
  /** Only these logins (default: every login policies allow on those hosts). */
  logins?: string[];
  /** Requested lifetime (default and maximum from the tenant's settings). */
  ttlMs?: number;
  /** Why the certificate is needed; recorded in the audit log. */
  reason?: string;
}

export interface SshIssuedCertificate {
  id: string;
  /** The `*-cert.pub` line: save it next to the private key (`id_ed25519-cert.pub`). */
  certificate: string;
  serial: string;
  keyId: string;
  principals: string[];
  validAfter: number;
  validBefore: number;
  extensions: string[];
  sourceAddress?: string;
  hosts: { name: string; addresses: string[]; logins: string[] }[];
  /** known_hosts lines trusting the tenant's host authority for its hosts, and refusing revoked host keys. */
  knownHosts: string;
  /** The host revocation list (base64 KRL) for ssh's `RevokedHostKeys`. */
  revokedHostKeys: string;
}

export interface SshAccessEntry {
  name: string;
  description?: string;
  addresses: string[];
  labels: Record<string, string>;
  logins: string[];
  forwarding: { port: boolean; agent: boolean; x11: boolean };
}

/** What an enrolled host installs; `syncHost` returns it again whenever the host checks in. */
export interface SshHostSetup {
  host: SshHostView;
  /** The host certificate line (sshd `HostCertificate`). */
  certificate: string;
  certificateExpiresAt: number;
  /** A new certificate was issued by this call. */
  certificateRenewed: boolean;
  /**
   * The host's credential for `syncHost`: at enrollment, and a new one with every renewed certificate (the one it
   * replaces keeps working until the new one is used). Store it root-only.
   */
  renewalToken?: string;
  /** sshd `TrustedUserCAKeys` contents. */
  trustedUserCaKeys: string;
  /** One principals file per login (sshd `AuthorizedPrincipalsFile .../%u`). */
  principals: Record<string, string>;
  /** The user key revocation list (sshd `RevokedKeys`), base64. */
  revocationList: string;
  revocationVersion: number;
  /** Suggested files with their paths and modes (`encoding: 'base64'` for the binary revocation list). */
  files: { path: string; content: string; mode: string; encoding?: 'base64' }[];
  /** Directories whose files this setup manages completely: remove the ones it does not list. */
  managedDirectories: string[];
  /** An sshd_config drop-in naming those files. */
  sshdConfig: string;
}

export interface SshHostInput {
  tenantId: string;
  name: string;
  description?: string;
  addresses?: string[];
  logins: string[];
  labels?: Record<string, string>;
}
export interface SshHostUpdate {
  tenantId: string;
  hostId: string;
  /** null clears it. */
  description?: string | null;
  addresses?: string[];
  logins?: string[];
  labels?: Record<string, string>;
}

const hostKeyFile: Record<string, string> = {
  'ssh-ed25519': 'ssh_host_ed25519_key',
  'ecdsa-sha2-nistp256': 'ssh_host_ecdsa_key',
  'ecdsa-sha2-nistp384': 'ssh_host_ecdsa_key',
  'ecdsa-sha2-nistp521': 'ssh_host_ecdsa_key',
  'ssh-rsa': 'ssh_host_rsa_key',
};
const principalsDirectory = '/etc/ssh/better-iam/principals';
/** A forced renewal (`renew: true`) is honoured at most this often. */
const FORCED_RENEWAL_MS = 3_600_000;

function publicAuthority(authority: SshAuthority): SshAuthorityView {
  return {
    id: authority.id,
    tenantId: authority.tenantId,
    kind: authority.kind,
    status: authority.status,
    algorithm: authority.algorithm,
    publicKey: authority.publicKey,
    fingerprint: authority.fingerprint,
    createdAt: authority.createdAt,
    createdBy: authority.createdBy,
    ...(authority.activatedAt !== undefined ? { activatedAt: authority.activatedAt } : {}),
    ...(authority.rotatedAt !== undefined ? { rotatedAt: authority.rotatedAt } : {}),
    ...(authority.retiredAt !== undefined ? { retiredAt: authority.retiredAt } : {}),
  };
}

function publicHost(host: SshHost): SshHostView {
  const {
    joinTokenHash: _join,
    renewalTokenHash: _renewal,
    previousRenewalTokenHash: _previous,
    uniqueKey: _key,
    ...view
  } = host;
  return view as SshHostView;
}

function settingsView(settings: SshSettings, options: ResolvedSshOptions): SshSettingsView {
  return {
    tenantId: settings.tenantId,
    requireMfa: settings.requireMfa,
    requireSecurityKey: settings.requireSecurityKey,
    requireUserVerification: settings.requireUserVerification,
    bindSourceAddress: settings.bindSourceAddress,
    defaultCertificateMs: settings.defaultCertificateMs,
    maxCertificateMs: settings.maxCertificateMs,
    hostPatterns: settings.hostPatterns,
    revocationVersion: settings.revocationVersion,
    deploymentMaxCertificateMs: options.maxUserCertificateMs,
    ...(settings.updatedAt !== undefined ? { updatedAt: settings.updatedAt } : {}),
    ...(settings.updatedBy !== undefined ? { updatedBy: settings.updatedBy } : {}),
  };
}

function listOf<T>(value: unknown, name: string, max: number, each: (item: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length > max)
    throw new IamError('INVALID_INPUT', `${name} must be a list of at most ${max} items`);
  return [...new Set(value.map(each))];
}

const hostLogins = (value: unknown) => {
  const logins = listOf(value, 'logins', 64, sshLogin);
  if (!logins.length) throw new IamError('INVALID_INPUT', 'A host needs at least one login');
  return logins;
};
const hostAddresses = (value: unknown) =>
  value === undefined ? [] : listOf(value, 'addresses', 32, sshHostAddress);

/** Join and renewal tokens name their host: `biam_sshj.{hostId}.{secret}` / `biam_sshr.{hostId}.{secret}`. */
function tokenHost(value: unknown, prefix: 'biam_sshj' | 'biam_sshr'): string {
  const parts = typeof value === 'string' && value.length <= 256 ? value.split('.') : [];
  if (parts.length !== 3 || parts[0] !== prefix || !parts[1] || !parts[2])
    throw new IamError('INVALID_TOKEN', 'Invalid or expired host token', 401);
  return parts[1];
}

function certificateView(record: SshCertificateRecord, now: number): SshCertificateView {
  const {
    expiresAt: _expires,
    uniqueKey: _key,
    certificate: _line,
    publicKey: _publicKey,
    sessionId: _session,
    ...view
  } = record;
  return {
    ...(view as SshCertificateRecordFields & { id: string; tenantId: string }),
    status: record.revokedAt !== undefined ? 'revoked' : record.validBefore <= now ? 'expired' : 'active',
  };
}

/** Codes a host-management refusal is audited with (a denied `iam:ssh:manage`). */
const auditedRefusals = new Set(['HOST_OUTSIDE_PATTERNS', 'HOST_NAME_TAKEN', 'HOST_KEY_IN_USE']);

/**
 * The `ssh` API group: the tenant's SSH certificate authority. Administrators (`iam:ssh:manage`, `iam:ssh:read`) set it
 * up, enroll hosts and review and revoke certificates; members get certificates for what policies allow them
 * (`ssh:login` on `ssh-login/{host}/{login}`); hosts enroll with a one-time join token and then check in with their
 * renewal token (`syncHost`), which also renews their certificate and hands them the current trust and revocation list.
 */
export function createSshApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const manage = 'iam:ssh:manage';
  const read = 'iam:ssh:read';
  const tenantOf = (value: unknown) => text(value, 'tenantId');

  async function activeTenant(tx: IamStore, tenantId: string): Promise<Tenant> {
    const tenant = await ctx.tenant(tx, tenantId);
    if (!(await tenantActive(ctx, tx, tenant)))
      throw new IamError('TENANT_INACTIVE', 'This organization is not active', 403);
    return tenant;
  }

  async function scopedHost(tx: IamStore, tenantId: string, hostId: unknown): Promise<SshHost> {
    return ctx.scoped<SshHost>(tx, 'sshHosts', text(hostId, 'hostId'), tenantId);
  }

  async function hostRecordName(tenantId: string, hostId: unknown): Promise<string> {
    return (await scopedHost(ctx.store, tenantId, hostId)).name;
  }

  const joinToken = (host: { id: string }) => `biam_sshj.${host.id}.${token()}`;
  const renewalToken = (host: { id: string }) => `biam_sshr.${host.id}.${token()}`;

  /** Records a refused host call (bad token, key swap) in its own transaction, then throws. */
  async function refuseHost(
    host: { id: string; tenantId: string; name: string } | undefined,
    action: string,
    error: IamError,
    metadata: Record<string, Json> = {},
  ): Promise<never> {
    if (host)
      try {
        await ctx.store.transaction((tx) =>
          ctx.events.recordAudit(tx, {
            id: id(),
            tenantId: host.tenantId,
            actorId: `ssh-host:${host.id}`,
            action,
            resourceId: `ssh/hosts/${host.name}`,
            outcome: 'deny',
            timestamp: ctx.now(),
            metadata: { reason: error.code, ...metadata },
          }),
        );
      } catch {
        /* Bookkeeping never masks the refusal. */
      }
    throw error;
  }

  /** An administrative host operation whose policy-shaped refusals (names outside patterns, taken) are audited. */
  async function audited<T>(
    credential: CredentialInput,
    tenantId: string,
    resourceId: string,
    run: () => Promise<T>,
  ): Promise<T> {
    try {
      return await run();
    } catch (error) {
      if (error instanceof IamError && auditedRefusals.has(error.code))
        try {
          const principal = await ctx.principals.authenticate(credential);
          await ctx.store.transaction((tx) =>
            ctx.events.audit(tx, principal, manage, tenantId, resourceId, 'deny', false, {
              reason: error.code,
              message: error.message.slice(0, 256),
            }),
          );
        } catch {
          /* Bookkeeping never masks the refusal. */
        }
      throw error;
    }
  }

  /**
   * Every name a host certificate would carry must be one the organization can vouch for, used by no other host, and
   * within the caller's own `iam:ssh:manage` scope (`iam/ssh/hosts/{name}` for each address), so an administrator of
   * some hosts cannot claim another host's name.
   */
  async function assertNamesAllowed(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    names: string[],
    hostId?: string,
  ): Promise<void> {
    assertVouchable(await loadSshSettings(ctx, tx, tenantId), await verifiedDomains(tx, tenantId), names);
    await assertNamesFree(tx, tenantId, names, hostId);
    for (const name of names.slice(1)) {
      const decision = await ctx.operations.recordedDecision(tx, principal, {
        tenantId,
        action: manage,
        resource: { type: 'iam', id: `ssh/hosts/${name}` },
      });
      if (!decision.allowed) throw new OperationDenied(`You may not manage the host name ${name}`);
    }
  }

  /** Issues a host certificate for the host's name and addresses and supersedes every earlier one. */
  async function certifyHost(
    tx: IamStore,
    host: SshHost,
    key: SshPublicKey,
    options: ResolvedSshOptions,
  ): Promise<{ record: SshCertificateRecord; line: string }> {
    const authority = await activeAuthority(tx, host.tenantId, 'host');
    const now = ctx.now();
    const serial = sshSerial();
    const principals = [...new Set([host.name, ...host.addresses])];
    // Never vouch for a name outside the organization's reach, whatever the host record says.
    assertVouchable(
      await loadSshSettings(ctx, tx, host.tenantId),
      await verifiedDomains(tx, host.tenantId),
      principals,
    );
    const previous = await liveCertificates(ctx, tx, { tenantId: host.tenantId, hostId: host.id });
    const validBefore = now + options.hostCertificateMs;
    const signed = signSshCertificate(
      openAuthority(ctx, authority),
      {
        key,
        serial,
        kind: SSH_CERT_HOST,
        keyId: `host:${host.name}`,
        principals,
        validAfter: Math.floor((now - options.clockSkewMs) / 1000),
        validBefore: Math.floor(validBefore / 1000),
      },
      host.name,
    );
    const record = await tx.insert<SshCertificateRecord>('sshCertificates', {
      id: id(),
      tenantId: host.tenantId,
      uniqueKey: `${authority.id}:${serial}`,
      kind: 'host',
      serial: serial.toString(),
      keyId: `host:${host.name}`,
      authorityId: authority.id,
      hostId: host.id,
      principals,
      extensions: [],
      keyType: key.type,
      publicKeyFingerprint: key.fingerprint,
      publicKey: sshKeyLine(key.blob),
      validAfter: now - options.clockSkewMs,
      validBefore,
      issuedAt: now,
      certificate: signed.line,
      expiresAt: validBefore + options.recordRetentionMs,
    });
    // One live certificate per host: earlier ones (another key, other names, another authority) end here.
    await revokeAll(tx, host.tenantId, previous, 'superseded', `ssh-host:${host.id}`);
    return { record, line: signed.line };
  }

  async function hostSetup(
    tx: IamStore,
    tenant: Tenant,
    host: SshHost,
    certificate: { line: string; expiresAt: number; renewed: boolean },
    renewal?: string,
  ): Promise<SshHostSetup> {
    const bundle = await trustBundle(ctx, tx, tenant, 'member');
    const krl = await revocationList(ctx, tx, tenant, 'user');
    const principals = principalFiles(host);
    const keyType = host.hostKey?.split(' ')[0] ?? 'ssh-ed25519';
    const certificatePath = `/etc/ssh/${hostKeyFile[keyType] ?? 'ssh_host_ed25519_key'}-cert.pub`;
    const sshdConfig = [
      `# Managed by better-iam: host ${host.name} of tenant ${tenant.id}`,
      '# The first value sshd reads wins, so this drop-in sorts first (check with sshd -T).',
      'TrustedUserCAKeys /etc/ssh/better-iam/user-ca.pub',
      `AuthorizedPrincipalsFile ${principalsDirectory}/%u`,
      'RevokedKeys /etc/ssh/better-iam/revoked.krl',
      `HostCertificate ${certificatePath}`,
      '',
    ].join('\n');
    return {
      host: publicHost(host),
      certificate: certificate.line,
      certificateExpiresAt: certificate.expiresAt,
      certificateRenewed: certificate.renewed,
      ...(renewal ? { renewalToken: renewal } : {}),
      trustedUserCaKeys: bundle.trustedUserCaKeys,
      principals,
      revocationList: krl.krl,
      revocationVersion: krl.version,
      files: [
        { path: certificatePath, content: `${certificate.line}\n`, mode: '0644' },
        { path: '/etc/ssh/better-iam/user-ca.pub', content: bundle.trustedUserCaKeys, mode: '0644' },
        ...Object.entries(principals).map(([login, content]) => ({
          path: `${principalsDirectory}/${login}`,
          content,
          mode: '0644',
        })),
        { path: '/etc/ssh/better-iam/revoked.krl', content: krl.krl, mode: '0644', encoding: 'base64' as const },
        { path: '/etc/ssh/sshd_config.d/00-better-iam.conf', content: sshdConfig, mode: '0644' },
      ],
      managedDirectories: [principalsDirectory],
      sshdConfig,
    };
  }

  async function hostAudit(tx: IamStore, host: SshHost, action: string, metadata: Record<string, Json>) {
    await ctx.events.recordAudit(tx, {
      id: id(),
      tenantId: host.tenantId,
      actorId: `ssh-host:${host.id}`,
      action,
      resourceId: `ssh/hosts/${host.name}`,
      outcome: 'allow',
      timestamp: ctx.now(),
      metadata,
    });
  }

  /** Revokes the certificates in `records` and bumps the revocation version once. */
  async function revokeAll(
    tx: IamStore,
    tenantId: string,
    records: SshCertificateRecord[],
    reason: SshRevocationReason,
    actorId: string,
  ): Promise<number> {
    let count = 0;
    for (const record of records) {
      if (record.revokedAt !== undefined) continue;
      await markRevoked(ctx, tx, record, reason, actorId);
      count++;
    }
    if (count) await bumpRevocationVersion(ctx, tx, tenantId);
    return count;
  }

  type Prepared = Awaited<ReturnType<typeof ctx.decisions.prepareDecision>>;
  const decideWith = (prepared: Prepared) => (resource: ResolvedResource, action: string) =>
    'fixed' in prepared ? prepared.fixed : prepared.evaluate(resource, action);
  /** A root override from outside the tenant (the platform's administrators acting in an organization). */
  const crossTenantRoot = (prepared: Prepared, principal: AuthenticatedPrincipal, tenantId: string) =>
    'fixed' in prepared && prepared.fixed.reason === 'ROOT_OVERRIDE' && principal.identity.tenantId !== tenantId;

  /** The hosts and logins a principal may open, and what forwarding each host allows. */
  function accessOf(
    prepared: Prepared,
    hosts: SshHost[],
    logins?: Set<string>,
  ): { host: SshHost; logins: string[]; forwarding: Record<string, boolean> }[] {
    const decide = decideWith(prepared);
    const result = [];
    for (const host of [...hosts].sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const allowed = host.logins.filter(
        (login) => (!logins || logins.has(login)) && decide(loginResource(host, login), sshLoginAction).allowed,
      );
      if (!allowed.length) continue;
      const forwarding: Record<string, boolean> = {};
      for (const action of Object.keys(sshForwardingActions))
        forwarding[action] = decide(hostResource(host), action).allowed;
      result.push({ host, logins: allowed, forwarding });
    }
    return result;
  }

  // The public revocation list is read by every host every few minutes: cached per tenant, kind and version and read
  // outside any transaction (a revocation bumps the version, so it is never served stale; holders or sessions that
  // ended meanwhile show within seconds).
  const revocationCache = new Map<string, { at: number; version: number; value: Awaited<ReturnType<typeof revocationList>> }>();
  const REVOCATION_CACHE_MS = 10_000;

  return {
    /**
     * Creates the tenant's user and host authorities (idempotent) and returns the trust to distribute. Requires
     * iam:ssh:manage.
     */
    setup: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, tenantOf(input.tenantId), manage, 'ssh/authorities', async ({ tx, principal, tenant }) => {
        assertSsh(ctx);
        const { created } = await ensureAuthorities(ctx, tx, tenant.id, principal.identity.id);
        return {
          created,
          authorities: (await tenantAuthorities(tx, tenant.id)).map(publicAuthority),
          trust: await trustBundle(ctx, tx, tenant, 'member'),
        };
      }),

    /** Configuration and counts at a glance. Requires iam:ssh:read. */
    status: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, tenantOf(input.tenantId), read, 'ssh/settings', async ({ tx, tenant }) => {
        const options = assertSsh(ctx);
        const authorities = await tenantAuthorities(tx, tenant.id);
        const hosts = await tx.find<SshHost>('sshHosts', { tenantId: tenant.id });
        const now = ctx.now();
        const certificates = (await tx.find<SshCertificateRecord>('sshCertificates', { tenantId: tenant.id })).filter(
          (record) => record.validBefore > now,
        );
        const count = (status: SshHost['status']) => hosts.filter((host) => host.status === status).length;
        return {
          configured: authorities.some((item) => item.kind === 'user' && item.status === 'active'),
          settings: settingsView(await loadSshSettings(ctx, tx, tenant.id), options),
          authorities: authorities.filter((item) => item.status !== 'retired').map(publicAuthority),
          hosts: { pending: count('pending'), enrolled: count('enrolled'), disabled: count('disabled') },
          certificates: {
            activeUser: certificates.filter((record) => record.kind === 'user' && record.revokedAt === undefined).length,
            activeHost: certificates.filter((record) => record.kind === 'host' && record.revokedAt === undefined).length,
            revoked: certificates.filter((record) => record.revokedAt !== undefined).length,
          },
          hostsExpiringSoon: hosts.filter(
            (host) => host.status === 'enrolled' && (host.certificateExpiresAt ?? 0) < now + 14 * 86_400_000,
          ).length,
        };
      }),

    /** The tenant's SSH settings. Requires iam:ssh:read. */
    getSettings: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, tenantOf(input.tenantId), read, 'ssh/settings', async ({ tx, tenant }) =>
        settingsView(await loadSshSettings(ctx, tx, tenant.id), assertSsh(ctx)),
      ),

    /**
     * Changes the tenant's SSH settings (fields left out keep their values). `hostPatterns` must pin a verified domain
     * of the organization or an address prefix, and cover every host already enrolled. Requires iam:ssh:manage.
     */
    updateSettings: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        requireMfa?: boolean;
        requireSecurityKey?: boolean;
        requireUserVerification?: boolean;
        bindSourceAddress?: boolean;
        defaultCertificateMs?: number;
        maxCertificateMs?: number;
        hostPatterns?: string[];
      },
    ) => {
      const tenantId = tenantOf(input.tenantId);
      return audited(credential, tenantId, 'ssh/settings', () =>
        operation(credential, tenantId, manage, 'ssh/settings', async ({ tx, tenant, principal }) => {
          const options = assertSsh(ctx);
          const current = await loadSshSettings(ctx, tx, tenant.id);
          const next: SshSettings = { ...current };
          for (const key of ['requireMfa', 'requireSecurityKey', 'requireUserVerification', 'bindSourceAddress'] as const) {
            if (input[key] === undefined) continue;
            if (typeof input[key] !== 'boolean') throw new IamError('INVALID_INPUT', `${key} must be a boolean`);
            next[key] = input[key];
          }
          if (input.maxCertificateMs !== undefined)
            next.maxCertificateMs = integer(input.maxCertificateMs, 'maxCertificateMs', 60_000, options.maxUserCertificateMs);
          if (input.defaultCertificateMs !== undefined)
            next.defaultCertificateMs = integer(input.defaultCertificateMs, 'defaultCertificateMs', 60_000, options.maxUserCertificateMs);
          if (next.defaultCertificateMs > next.maxCertificateMs)
            throw new IamError('INVALID_INPUT', 'defaultCertificateMs cannot exceed maxCertificateMs');
          if (input.hostPatterns !== undefined) {
            const domains = await verifiedDomains(tx, tenant.id);
            next.hostPatterns = hostPatternList(input.hostPatterns, domains);
            // Every host the authority already vouches for must stay inside the new patterns.
            for (const host of await tx.find<SshHost>('sshHosts', { tenantId: tenant.id }))
              if (host.status !== 'disabled') assertVouchable(next, domains, [host.name, ...host.addresses]);
          }
          next.updatedAt = ctx.now();
          next.updatedBy = principal.identity.id;
          await saveSshSettings(tx, next);
          return settingsView(next, options);
        }),
      );
    },

    /** Every authority key of the tenant, newest last (retired ones included). Requires iam:ssh:read. */
    listAuthorities: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, tenantOf(input.tenantId), read, 'ssh/authorities', async ({ tx, tenant }) => {
        assertSsh(ctx);
        return (await tenantAuthorities(tx, tenant.id)).map(publicAuthority);
      }),

    /**
     * Starts rotating an authority: a new key is published as `pending`, trusted by hosts and clients from their next
     * sync, and signs from `activateAuthority`. `activate: true` switches at once (a compromised key; certificates
     * then only work on hosts that already synced). Requires iam:ssh:manage.
     */
    rotateAuthority: (
      credential: CredentialInput,
      input: { tenantId: string; kind: SshAuthorityKind; activate?: boolean },
    ) => {
      if (input.kind !== 'user' && input.kind !== 'host')
        throw new IamError('INVALID_INPUT', "kind must be 'user' or 'host'");
      return operation(
        credential,
        tenantOf(input.tenantId),
        manage,
        `ssh/authorities/${input.kind}`,
        async ({ tx, tenant, principal }) => {
          assertSsh(ctx);
          const existing = await tenantAuthorities(tx, tenant.id, input.kind);
          if (existing.some((item) => item.status === 'pending'))
            throw new IamError('CONFLICT', 'A rotation is already pending; activate or retire it first', 409);
          const pending = await createAuthority(ctx, tx, tenant.id, input.kind, 'pending', principal.identity.id);
          if (input.activate !== true) return publicAuthority(pending);
          return publicAuthority(await activate(tx, pending));
        },
      );
    },

    /** Makes a pending authority the signing key; the one it replaces stays trusted as `previous`. Requires iam:ssh:manage. */
    activateAuthority: async (credential: CredentialInput, input: { tenantId: string; authorityId: string }) => {
      const tenantId = tenantOf(input.tenantId);
      const found = await ctx.scoped<SshAuthority>(ctx.store, 'sshAuthorities', text(input.authorityId, 'authorityId'), tenantId);
      return operation(credential, tenantId, manage, `ssh/authorities/${found.kind}`, async ({ tx }) => {
        assertSsh(ctx);
        const authority = await ctx.scoped<SshAuthority>(tx, 'sshAuthorities', found.id, tenantId);
        if (authority.status !== 'pending')
          throw new IamError('INVALID_TRANSITION', 'Only a pending authority can be activated', 409);
        return publicAuthority(await activate(tx, authority));
      });
    },

    /**
     * Stops trusting a previous authority. Refused while certificates it signed are still valid, unless `force` (they
     * are revoked). Requires iam:ssh:manage.
     */
    retireAuthority: async (
      credential: CredentialInput,
      input: { tenantId: string; authorityId: string; force?: boolean },
    ) => {
      const tenantId = tenantOf(input.tenantId);
      const found = await ctx.scoped<SshAuthority>(ctx.store, 'sshAuthorities', text(input.authorityId, 'authorityId'), tenantId);
      return operation(credential, tenantId, manage, `ssh/authorities/${found.kind}`, async ({ tx, principal }) => {
        assertSsh(ctx);
        const authority = await ctx.scoped<SshAuthority>(tx, 'sshAuthorities', found.id, tenantId);
        if (authority.status !== 'previous' && authority.status !== 'pending')
          throw new IamError('INVALID_TRANSITION', 'Only a previous or pending authority can be retired', 409);
        const live = await liveCertificates(ctx, tx, { tenantId, authorityId: authority.id });
        if (live.length && input.force !== true)
          throw new IamError('RESOURCE_IN_USE', `${live.length} certificates signed by this authority are still valid`, 409);
        await revokeAll(tx, tenantId, live, 'authority-retired', principal.identity.id);
        return publicAuthority(
          await tx.put<SshAuthority>('sshAuthorities', { ...authority, status: 'retired', retiredAt: ctx.now() }),
        );
      });
    },

    /**
     * Registers a host and returns its one-time join token (shown once; valid for `joinTokenMs`). Its name and every
     * address must be unused, within the caller's `iam:ssh:manage` scope, and names the organization can vouch for.
     * Needs the authorities (`setup`). Requires iam:ssh:manage.
     */
    createHost: (credential: CredentialInput, input: SshHostInput) => {
      const name = sshHostName(input.name);
      const logins = hostLogins(input.logins);
      const addresses = hostAddresses(input.addresses).filter((address) => address !== name);
      const labels = sshLabels(input.labels);
      const description = input.description === undefined ? undefined : text(input.description, 'description', 512);
      const tenantId = tenantOf(input.tenantId);
      return audited(credential, tenantId, `ssh/hosts/${name}`, () =>
        operation(credential, tenantId, manage, `ssh/hosts/${name}`, async ({ tx, tenant, principal }) => {
          const options = assertSsh(ctx);
          if (await hostByName(tx, tenant.id, name))
            throw new IamError('CONFLICT', 'A host with this name already exists', 409);
          // Creating the authorities is `setup`, a decision of its own.
          await activeAuthority(tx, tenant.id, 'host');
          await assertNamesAllowed(tx, principal, tenant.id, [name, ...addresses]);
          const hostId = id();
          const secret = joinToken({ id: hostId });
          const now = ctx.now();
          const host = await tx.insert<SshHost>('sshHosts', {
            id: hostId,
            tenantId: tenant.id,
            uniqueKey: name,
            name,
            ...(description ? { description } : {}),
            addresses,
            logins,
            labels,
            status: 'pending',
            joinTokenHash: hash(secret),
            joinTokenExpiresAt: now + options.joinTokenMs,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
          });
          return { host: publicHost(host), joinToken: secret, joinTokenExpiresAt: host.joinTokenExpiresAt! };
        }),
      );
    },

    /**
     * Changes a host's addresses, logins, labels or description. New addresses follow the `createHost` rules; a removed
     * address revokes the host's certificate at once (the host gets a new one at its next `syncHost`), and new logins
     * reach the principals files then too. Requires iam:ssh:manage.
     */
    updateHost: async (credential: CredentialInput, input: SshHostUpdate) => {
      const tenantId = tenantOf(input.tenantId);
      const name = await hostRecordName(tenantId, input.hostId);
      const changes: Partial<SshHost> = {};
      if (input.logins !== undefined) changes.logins = hostLogins(input.logins);
      if (input.addresses !== undefined)
        changes.addresses = hostAddresses(input.addresses).filter((address) => address !== name);
      if (input.labels !== undefined) changes.labels = sshLabels(input.labels);
      return audited(credential, tenantId, `ssh/hosts/${name}`, () =>
        operation(credential, tenantId, manage, `ssh/hosts/${name}`, async ({ tx, principal }) => {
          assertSsh(ctx);
          const host = await scopedHost(tx, tenantId, input.hostId);
          const next: SshHost = { ...host, ...changes, updatedAt: ctx.now() };
          if (input.description === null) delete next.description;
          else if (input.description !== undefined) next.description = text(input.description, 'description', 512);
          const added = next.addresses.filter((address) => !host.addresses.includes(address));
          const removed = host.addresses.filter((address) => !next.addresses.includes(address));
          if (added.length) await assertNamesAllowed(tx, principal, tenantId, [host.name, ...added], host.id);
          // A name the host gives up could be claimed by another host: its certificate must stop vouching for it.
          if (removed.length)
            await revokeAll(
              tx,
              tenantId,
              await liveCertificates(ctx, tx, { tenantId, hostId: host.id }),
              'addresses-changed',
              principal.identity.id,
            );
          const saved = await tx.put<SshHost>('sshHosts', next);
          return {
            host: publicHost(saved),
            syncRequired:
              JSON.stringify(host.logins) !== JSON.stringify(saved.logins) || added.length > 0 || removed.length > 0,
          };
        }),
      );
    },

    /** One host. Requires iam:ssh:read. */
    getHost: async (credential: CredentialInput, input: { tenantId: string; hostId: string }) => {
      const tenantId = tenantOf(input.tenantId);
      const name = await hostRecordName(tenantId, input.hostId);
      return operation(credential, tenantId, read, `ssh/hosts/${name}`, async ({ tx }) =>
        publicHost(await scopedHost(tx, tenantId, input.hostId)),
      );
    },

    /** The tenant's hosts by name, optionally by status or matching labels. Requires iam:ssh:read. */
    listHosts: (
      credential: CredentialInput,
      input: { tenantId: string; status?: SshHost['status']; labels?: Record<string, string>; query?: string },
    ) =>
      operation(credential, tenantOf(input.tenantId), read, 'ssh/hosts', async ({ tx, tenant }) => {
        assertSsh(ctx);
        const labels = input.labels === undefined ? {} : sshLabels(input.labels);
        const query = input.query === undefined ? undefined : text(input.query, 'query', 128).toLowerCase();
        return (await tx.find<SshHost>('sshHosts', { tenantId: tenant.id, ...(input.status ? { status: input.status } : {}) }))
          .filter((host) => Object.entries(labels).every(([key, value]) => host.labels[key] === value))
          .filter(
            (host) =>
              !query ||
              host.name.includes(query) ||
              host.addresses.some((address) => address.includes(query)) ||
              (host.description ?? '').toLowerCase().includes(query),
          )
          .sort((a, b) => (a.name < b.name ? -1 : 1))
          .map(publicHost);
      }),

    /**
     * Takes a host out of service: its certificate is revoked, its key is published as revoked to clients, it can no
     * longer sync, and no user certificate names it. Requires iam:ssh:manage.
     */
    disableHost: async (credential: CredentialInput, input: { tenantId: string; hostId: string }) => {
      const tenantId = tenantOf(input.tenantId);
      const name = await hostRecordName(tenantId, input.hostId);
      return operation(credential, tenantId, manage, `ssh/hosts/${name}`, async ({ tx, principal }) => {
        assertSsh(ctx);
        const host = await scopedHost(tx, tenantId, input.hostId);
        if (host.status === 'disabled') return publicHost(host);
        await revokeAll(tx, tenantId, await liveCertificates(ctx, tx, { tenantId, hostId: host.id }), 'host-disabled', principal.identity.id);
        const {
          joinTokenHash: _join,
          joinTokenExpiresAt: _expires,
          renewalTokenHash: _renewal,
          previousRenewalTokenHash: _previous,
          ...rest
        } = host;
        const saved = await tx.put<SshHost>('sshHosts', { ...rest, status: 'disabled', updatedAt: ctx.now() });
        await bumpRevocationVersion(ctx, tx, tenantId);
        return publicHost(saved);
      });
    },

    /**
     * Puts a disabled host back into enrollment (or re-enrolls a rebuilt one): returns a fresh one-time join token; the
     * host's renewal tokens stop working. Requires iam:ssh:manage.
     */
    resetJoinToken: async (credential: CredentialInput, input: { tenantId: string; hostId: string }) => {
      const tenantId = tenantOf(input.tenantId);
      const name = await hostRecordName(tenantId, input.hostId);
      return operation(credential, tenantId, manage, `ssh/hosts/${name}`, async ({ tx }) => {
        const options = assertSsh(ctx);
        const host = await scopedHost(tx, tenantId, input.hostId);
        const secret = joinToken(host);
        const { renewalTokenHash: _renewal, previousRenewalTokenHash: _previous, ...rest } = host;
        const saved = await tx.put<SshHost>('sshHosts', {
          ...rest,
          status: host.status === 'disabled' ? 'pending' : host.status,
          joinTokenHash: hash(secret),
          joinTokenExpiresAt: ctx.now() + options.joinTokenMs,
          updatedAt: ctx.now(),
        });
        return { host: publicHost(saved), joinToken: secret, joinTokenExpiresAt: saved.joinTokenExpiresAt! };
      });
    },

    /** Deletes a host; its certificate is revoked and its key published as revoked. Requires iam:ssh:manage. */
    deleteHost: async (credential: CredentialInput, input: { tenantId: string; hostId: string }) => {
      const tenantId = tenantOf(input.tenantId);
      const name = await hostRecordName(tenantId, input.hostId);
      return operation(credential, tenantId, manage, `ssh/hosts/${name}`, async ({ tx, principal }) => {
        assertSsh(ctx);
        const host = await scopedHost(tx, tenantId, input.hostId);
        await revokeAll(tx, tenantId, await liveCertificates(ctx, tx, { tenantId, hostId: host.id }), 'host-deleted', principal.identity.id);
        await tx.delete('sshHosts', host.id);
        return { deleted: true };
      });
    },

    /**
     * Enrolls a host with its one-time join token and its public host key: returns the host certificate, the trust
     * and principals files sshd needs, the revocation list, and the renewal token for `syncHost`. Public: the join
     * token is the credential. Refusals of a real host's token are audited.
     */
    enrollHost: async (input: { joinToken: string; publicKey: string }): Promise<SshHostSetup> => {
      const options = assertSsh(ctx);
      const hostId = tokenHost(input.joinToken, 'biam_sshj');
      const known = await ctx.store.get<SshHost>('sshHosts', hostId);
      if (known) await ctx.auth.limitAttempt(known.tenantId, `ssh:enroll:${hostId}`, { limit: 10 });
      const key = parseSshPublicKey(input.publicKey);
      const outcome = await ctx.store.transaction(
        async (tx): Promise<{ error: IamError; host?: SshHost } | { value: SshHostSetup }> => {
          const host = await tx.get<SshHost>('sshHosts', hostId);
          if (
            !host ||
            host.status === 'disabled' ||
            !host.joinTokenHash ||
            !sameHash(host.joinTokenHash, hash(input.joinToken)) ||
            (host.joinTokenExpiresAt ?? 0) <= ctx.now()
          )
            return { error: new IamError('INVALID_TOKEN', 'Invalid or expired host token', 401), host };
          const tenant = await activeTenant(tx, host.tenantId);
          await assertHostKeyFree(tx, host.tenantId, host.id, key);
          const issued = await certifyHost(tx, host, key, options);
          const renewal = renewalToken(host);
          const now = ctx.now();
          const { joinTokenHash: _join, joinTokenExpiresAt: _expires, previousRenewalTokenHash: _previous, ...rest } = host;
          const saved = await tx.put<SshHost>('sshHosts', {
            ...rest,
            status: 'enrolled',
            hostKey: sshKeyLine(key.blob),
            hostKeyFingerprint: key.fingerprint,
            certificateId: issued.record.id,
            certificateExpiresAt: issued.record.validBefore,
            renewalTokenHash: hash(renewal),
            enrolledAt: now,
            renewedAt: now,
            lastSeenAt: now,
            updatedAt: now,
          });
          await hostAudit(tx, saved, 'ssh:host:enroll', {
            serial: issued.record.serial,
            fingerprint: key.fingerprint,
            keyType: key.type,
          });
          return {
            value: await hostSetup(
              tx,
              tenant,
              saved,
              { line: issued.line, expiresAt: issued.record.validBefore, renewed: true },
              renewal,
            ),
          };
        },
      );
      if ('error' in outcome) return refuseHost(outcome.host, 'ssh:host:enroll', outcome.error);
      return outcome.value;
    },

    /**
     * A host's periodic check-in with its renewal token: returns the current trust, principals files and revocation
     * list, and a new host certificate (with a new renewal token) when its addresses or the host authority changed or
     * the current one is past two thirds of its lifetime; `renew: true` forces one at most hourly. `publicKey`, when
     * sent, must be the enrolled key (`HOST_KEY_CHANGED` otherwise: re-enroll). Public: the renewal token is the
     * credential. While the organization is suspended a host still syncs (its revocation list then revokes every
     * user certificate) but gets no new certificate.
     */
    syncHost: async (input: { renewalToken: string; publicKey?: string; renew?: boolean }): Promise<SshHostSetup> => {
      const options = assertSsh(ctx);
      const hostId = tokenHost(input.renewalToken, 'biam_sshr');
      const known = await ctx.store.get<SshHost>('sshHosts', hostId);
      if (known) await ctx.auth.limitAttempt(known.tenantId, `ssh:sync:${hostId}`, { limit: 120 });
      const offered = input.publicKey === undefined ? undefined : parseSshPublicKey(input.publicKey);
      const outcome = await ctx.store.transaction(
        async (tx): Promise<{ error: IamError; host?: SshHost; metadata?: Record<string, Json> } | { value: SshHostSetup }> => {
          const host = await tx.get<SshHost>('sshHosts', hostId);
          const presented = hash(input.renewalToken);
          const current = Boolean(host?.renewalTokenHash && sameHash(host.renewalTokenHash, presented));
          const previous = Boolean(host?.previousRenewalTokenHash && sameHash(host.previousRenewalTokenHash, presented));
          if (!host || host.status !== 'enrolled' || (!current && !previous))
            return { error: new IamError('INVALID_TOKEN', 'Invalid or expired host token', 401), host };
          const tenant = await ctx.tenant(tx, host.tenantId);
          const active = await tenantActive(ctx, tx, tenant);
          const key = storedHostKey(host);
          // The renewal token never moves the host's identity to another key: a stolen token must not yield a host
          // certificate for an attacker's key. A rebuilt host re-enrolls with a new join token.
          if (offered && offered.fingerprint !== key.fingerprint)
            return {
              error: new IamError(
                'HOST_KEY_CHANGED',
                'This host key differs from the enrolled one; re-enroll the host with a new join token',
                409,
              ),
              host,
              metadata: { offered: offered.fingerprint },
            };
          const certificate = host.certificateId
            ? await tx.get<SshCertificateRecord>('sshCertificates', host.certificateId)
            : undefined;
          const now = ctx.now();
          const principals = [...new Set([host.name, ...host.addresses])];
          const hostAuthority = active ? await activeAuthority(tx, host.tenantId, 'host') : undefined;
          const stale =
            !certificate ||
            certificate.revokedAt !== undefined ||
            certificate.publicKeyFingerprint !== key.fingerprint ||
            (hostAuthority !== undefined && certificate.authorityId !== hostAuthority.id) ||
            JSON.stringify(certificate.principals) !== JSON.stringify(principals) ||
            now >= certificate.validAfter + ((certificate.validBefore - certificate.validAfter) * 2) / 3;
          const forced = input.renew === true && (!certificate || now - certificate.issuedAt >= FORCED_RENEWAL_MS);
          let line = typeof certificate?.certificate === 'string' ? certificate.certificate : '';
          let issued = certificate;
          const renewed = active && (forced || stale || !line);
          let renewal: string | undefined;
          if (renewed) {
            const next = await certifyHost(tx, host, key, options);
            line = next.line;
            issued = next.record;
            renewal = renewalToken(host);
          }
          const saved = await tx.put<SshHost>('sshHosts', {
            ...host,
            certificateId: issued!.id,
            certificateExpiresAt: issued!.validBefore,
            // A new token rotates in; the one presented stays valid until the new one is used. Using the new one retires
            // the old for good.
            ...(renewal
              ? {
                  renewalTokenHash: hash(renewal),
                  previousRenewalTokenHash: current ? host.renewalTokenHash! : host.previousRenewalTokenHash!,
                }
              : current && host.previousRenewalTokenHash
                ? { previousRenewalTokenHash: undefined }
                : {}),
            ...(renewed ? { renewedAt: now } : {}),
            lastSeenAt: now,
            updatedAt: renewed ? now : host.updatedAt,
          });
          if (renewed) await hostAudit(tx, saved, 'ssh:host:renew', { serial: issued!.serial, fingerprint: key.fingerprint });
          return {
            value: await hostSetup(tx, tenant, saved, { line, expiresAt: issued!.validBefore, renewed }, renewal),
          };
        },
      );
      if ('error' in outcome) return refuseHost(outcome.host, 'ssh:host:sync', outcome.error, outcome.metadata);
      return outcome.value;
    },

    /**
     * The tenant's public trust: user authority keys for hosts (`trustedUserCaKeys` for `TrustedUserCAKeys`) and, when
     * the organization set `hostPatterns`, the `@cert-authority` line for clients. Public: public keys and patterns only;
     * members get the line for the enrolled names from `clientTrust`.
     */
    trust: async (input: { tenantId: string }) => {
      assertSsh(ctx);
      const tenantId = tenantOf(input.tenantId);
      return trustBundle(ctx, ctx.store, await ctx.tenant(ctx.store, tenantId), 'public');
    },

    /**
     * What a member's SSH client needs: known_hosts lines for the organization's hosts (and `@revoked` ones for keys
     * to refuse), and the host revocation list for `RevokedHostKeys`.
     */
    clientTrust: async (credential: CredentialInput, input: { tenantId: string }) => {
      assertSsh(ctx);
      const tenantId = tenantOf(input.tenantId);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        if (principal.session.tenantId !== tenantId)
          throw new IamError('ACCESS_DENIED', 'Access denied', 403);
        const tenant = await ctx.tenant(tx, tenantId);
        const bundle = await trustBundle(ctx, tx, tenant, 'member');
        const hosts = await revocationList(ctx, tx, tenant, 'host');
        return { knownHosts: bundle.knownHosts, revokedHostKeys: hosts.krl, hostPatterns: bundle.hostPatterns };
      });
    },

    /**
     * The tenant's key revocation list: `user` (default, for sshd `RevokedKeys`) or `host` (for ssh `RevokedHostKeys`),
     * base64. Public, like a certificate revocation list: serials and public keys only. Served for suspended
     * organizations too (every user certificate is then revoked).
     */
    revocationList: async (input: { tenantId: string; kind?: 'user' | 'host' }) => {
      assertSsh(ctx);
      const tenantId = tenantOf(input.tenantId);
      const kind = input.kind ?? 'user';
      if (kind !== 'user' && kind !== 'host') throw new IamError('INVALID_INPUT', "kind must be 'user' or 'host'");
      const settings = await loadSshSettings(ctx, ctx.store, tenantId);
      const cacheKey = `${tenantId}:${kind}`;
      const cached = revocationCache.get(cacheKey);
      const now = ctx.now();
      if (cached && cached.version === settings.revocationVersion && now - cached.at < REVOCATION_CACHE_MS && now >= cached.at)
        return cached.value;
      const value = await revocationList(ctx, ctx.store, await ctx.tenant(ctx.store, tenantId), kind);
      if (revocationCache.size >= 1000) revocationCache.delete(revocationCache.keys().next().value!);
      revocationCache.set(cacheKey, { at: now, version: settings.revocationVersion, value });
      return value;
    },

    /**
     * Issues a user certificate for the caller's public key, naming every requested host and login that policies
     * allow (`ssh:login` on `ssh-login/{host}/{login}`), with forwarding extensions only where every named host
     * allows them. The lifetime never outlives the caller's session or account, nor a time-limited grant that allows
     * `ssh:login` (a just-in-time activation, an expiring binding or membership, an access window); certificates for
     * agents acting for people last ten minutes. Rate limited per identity (`ssh.issuanceLimit`). Audited as
     * `ssh:certificate:issue`; a refusal is audited as a denied `ssh:login`.
     */
    issueCertificate: async (credential: CredentialInput, input: SshCertificateRequest): Promise<SshIssuedCertificate> => {
      const options = assertSsh(ctx);
      const tenantId = tenantOf(input.tenantId);
      const key = parseSshPublicKey(input.publicKey);
      const requestedHosts = input.hosts === undefined ? undefined : listOf(input.hosts, 'hosts', 256, sshHostName);
      const requestedLogins =
        input.logins === undefined ? undefined : new Set(listOf(input.logins, 'logins', 64, sshLogin));
      const ttl =
        input.ttlMs === undefined ? undefined : integer(input.ttlMs, 'ttlMs', 60_000, options.maxUserCertificateMs);
      const reason = input.reason === undefined ? undefined : text(input.reason, 'reason', 512);
      const authenticated = await ctx.principals.authenticate(credential);
      await ctx.auth.limitAttempt(tenantId, `ssh:issue:${authenticated.identity.id}`, { limit: options.issuanceLimit });
      const outcome = await ctx.observe.span('operation', 'ssh:certificate:issue', tenantId, () =>
        ctx.store.transaction(async (tx): Promise<{ error: IamError } | { value: SshIssuedCertificate; usage: boolean }> => {
          const principal = await ctx.principals.currentPrincipal(tx, authenticated);
          const tenant = await ctx.tenant(tx, tenantId);
          const target = requestedHosts?.length ? `ssh-login/${requestedHosts.join(',')}`.slice(0, 256) : 'ssh-login/*';
          const refuse = async (code: string, message: string, status: number) => {
            await ctx.events.audit(tx, principal, sshLoginAction, tenantId, target, 'deny', false, {
              reason: code,
              fingerprint: key.fingerprint,
            });
            return { error: new IamError(code, message, status) };
          };
          if (principal.session.impersonatorId)
            return refuse('IMPERSONATION_RESTRICTED', 'SSH certificates cannot be issued while viewing as someone', 403);
          // Decided first, so a principal of another tenant learns nothing about this one's hosts or settings.
          const prepared = await ctx.decisions.prepareDecision(tx, principal, tenant, sshLoginAction);
          if ('fixed' in prepared && !prepared.fixed.allowed) return refuse('ACCESS_DENIED', 'Access denied', 403);
          // The platform's root override never opens an organization's servers: a root administrator needs a role
          // in that organization like anyone else (only the root tenant's own hosts are theirs).
          if (crossTenantRoot(prepared, principal, tenantId))
            return refuse('ROOT_SSH_RESTRICTED', 'Platform administrators need a role in this organization to open its hosts', 403);
          const settings = await loadSshSettings(ctx, tx, tenantId);
          if (settings.requireMfa && principal.identity.kind === 'user' && !principal.session.mfa)
            return refuse('MFA_REQUIRED', 'Sign in with multi-factor authentication to get an SSH certificate', 403);
          if (settings.requireSecurityKey && !key.securityKey)
            return refuse(
              'SECURITY_KEY_REQUIRED',
              'This organization certifies only hardware security keys (ed25519-sk or ecdsa-sk)',
              403,
            );
          const authority = await activeAuthority(tx, tenantId, 'user');
          const authorities = await tenantAuthorities(tx, tenantId);
          if (authorities.some((item) => item.fingerprint === key.fingerprint))
            return { error: new IamError('INVALID_INPUT', 'An authority key cannot be certified') };
          let hosts: SshHost[];
          if (requestedHosts) {
            hosts = [];
            for (const name of requestedHosts) {
              const host = await hostByName(tx, tenantId, name);
              if (!host || host.status !== 'enrolled')
                return { error: new IamError('NOT_FOUND', `No enrolled host is named ${name}`, 404) };
              hosts.push(host);
            }
          } else hosts = await tx.find<SshHost>('sshHosts', { tenantId, status: 'enrolled' });
          const access = accessOf(prepared, hosts, requestedLogins);
          if (!access.length) return refuse('ACCESS_DENIED', 'Access denied', 403);
          if (access.length > options.maxHostsPerCertificate)
            return {
              error: new IamError(
                'TOO_MANY_HOSTS',
                `The certificate would name ${access.length} hosts; name at most ${options.maxHostsPerCertificate} with hosts`,
                400,
              ),
            };
          const principals = access.flatMap(({ host, logins }) =>
            logins.map((login) => sshLoginPrincipal(login, host.name)),
          );
          if (principals.length > 256)
            return { error: new IamError('TOO_MANY_HOSTS', 'Name fewer hosts or logins (at most 256 principals)', 400) };
          const extensions = ['permit-pty', 'permit-user-rc'];
          for (const [action, extension] of Object.entries(sshForwardingActions))
            if (access.every((entry) => entry.forwarding[action])) extensions.push(extension);
          const now = ctx.now();
          let validBefore = now + Math.min(ttl ?? settings.defaultCertificateMs, settings.maxCertificateMs);
          validBefore = Math.min(validBefore, principal.session.expiresAt);
          if (typeof principal.identity.expiresAt === 'number')
            validBefore = Math.min(validBefore, principal.identity.expiresAt);
          if (principal.session.kind === 'delegated') validBefore = Math.min(validBefore, now + DELEGATED_CERTIFICATE_MS);
          if (!('fixed' in prepared)) validBefore = await grantDeadline(ctx, tx, principal, tenantId, validBefore);
          if (validBefore < now + 60_000)
            return {
              error: new IamError(
                'SESSION_EXPIRING',
                'This session or the access that allows it ends within a minute; renew it first',
                401,
              ),
            };
          const criticalOptions: Record<string, string> = {};
          let sourceAddress: string | undefined;
          if (settings.bindSourceAddress) {
            const ip = ctx.auth.currentClient()?.ip;
            const family = ip ? isIP(ip) : 0;
            if (!family)
              return {
                error: new IamError(
                  'SOURCE_ADDRESS_UNKNOWN',
                  'This organization binds certificates to your address, which could not be determined',
                  400,
                ),
              };
            sourceAddress = `${ip}/${family === 6 ? 128 : 32}`;
            criticalOptions['source-address'] = sourceAddress;
          }
          if (key.securityKey && settings.requireUserVerification) criticalOptions['verify-required'] = '';
          const serial = sshSerial();
          const keyId = certificateKeyId(principal);
          const signed = signSshCertificate(
            openAuthority(ctx, authority),
            {
              key,
              serial,
              kind: SSH_CERT_USER,
              keyId,
              principals,
              validAfter: Math.floor((now - options.clockSkewMs) / 1000),
              validBefore: Math.floor(validBefore / 1000),
              criticalOptions,
              extensions,
            },
            key.comment?.replace(/[^\x20-\x7e]/g, '_'),
          );
          const rootOverride = 'fixed' in prepared && prepared.fixed.reason === 'ROOT_OVERRIDE';
          // The device this request proved, which the sweep judges device conditions by (devices.ts).
          const device = await presentedDevice(tx, principal, now);
          const record = await tx.insert<SshCertificateRecord>('sshCertificates', {
            id: id(),
            tenantId,
            uniqueKey: `${authority.id}:${serial}`,
            kind: 'user',
            serial: serial.toString(),
            keyId,
            authorityId: authority.id,
            identityId: principal.identity.id,
            sessionId: principal.session.id,
            sessionKind: principal.session.kind,
            mfa: principal.session.mfa,
            ...(device ? { deviceKeyId: device.key.id } : {}),
            principals,
            access: access.map(({ host, logins }) => ({ host: host.name, logins })),
            extensions: [...extensions].sort(),
            ...(sourceAddress ? { sourceAddress } : {}),
            keyType: key.type,
            publicKeyFingerprint: key.fingerprint,
            validAfter: now - options.clockSkewMs,
            validBefore,
            issuedAt: now,
            ...(reason ? { reason } : {}),
            expiresAt: validBefore + options.recordRetentionMs,
          });
          await ctx.events.audit(
            tx,
            principal,
            'ssh:certificate:issue',
            tenantId,
            `ssh/certificates/${record.id}`,
            'allow',
            rootOverride,
            {
              serial: record.serial,
              keyId,
              hosts: access.map(({ host }) => host.name),
              principals: principals.length,
              validBefore,
              fingerprint: key.fingerprint,
              keyType: key.type,
              ...(reason ? { reason } : {}),
            },
          );
          const bundle = await trustBundle(ctx, tx, tenant, 'member');
          const hostList = await revocationList(ctx, tx, tenant, 'host');
          return {
            usage: !rootOverride,
            value: {
              id: record.id,
              certificate: signed.line,
              serial: record.serial,
              keyId,
              principals,
              validAfter: record.validAfter,
              validBefore,
              extensions: record.extensions,
              ...(sourceAddress ? { sourceAddress } : {}),
              hosts: access.map(({ host, logins }) => ({ name: host.name, addresses: host.addresses, logins })),
              knownHosts: bundle.knownHosts,
              revokedHostKeys: hostList.krl,
            },
          };
        }),
      );
      if ('error' in outcome) throw outcome.error;
      // Using SSH access is using `ssh:login` (not a root override), for role mining and right-sizing.
      if (outcome.usage) ctx.usage.record(tenantId, authenticated.identity.id, sshLoginAction);
      return outcome.value;
    },

    /** The enrolled hosts the caller may open, with the logins and forwarding policies allow. No permission needed. */
    myAccess: async (credential: CredentialInput, input: { tenantId: string }) => {
      assertSsh(ctx);
      const tenantId = tenantOf(input.tenantId);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const tenant = await ctx.tenant(tx, tenantId);
        const prepared = await ctx.decisions.prepareDecision(tx, principal, tenant, sshLoginAction);
        const refused =
          ('fixed' in prepared && !prepared.fixed.allowed) || crossTenantRoot(prepared, principal, tenantId);
        const settings = await loadSshSettings(ctx, tx, tenantId);
        const hosts = refused ? [] : await tx.find<SshHost>('sshHosts', { tenantId, status: 'enrolled' });
        const hostsView: SshAccessEntry[] = accessOf(prepared, hosts).map(({ host, logins, forwarding }) => ({
          name: host.name,
          ...(host.description ? { description: host.description } : {}),
          addresses: host.addresses,
          labels: host.labels,
          logins,
          forwarding: {
            port: forwarding['ssh:port-forward']!,
            agent: forwarding['ssh:agent-forward']!,
            x11: forwarding['ssh:x11-forward']!,
          },
        }));
        return {
          hosts: hostsView,
          requireMfa: settings.requireMfa,
          requireSecurityKey: settings.requireSecurityKey,
          defaultCertificateMs: settings.defaultCertificateMs,
          maxCertificateMs: settings.maxCertificateMs,
        };
      });
    },

    /** The caller's own certificates in the tenant, newest first (the last 100). */
    myCertificates: async (credential: CredentialInput, input: { tenantId: string }) => {
      assertSsh(ctx);
      const tenantId = tenantOf(input.tenantId);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const now = ctx.now();
        // An agent acting for the person sees only the certificates its own session obtained.
        const delegated = principal.session.kind === 'delegated';
        return (await tx.find<SshCertificateRecord>('sshCertificates', { tenantId, identityId: principal.identity.id }))
          .filter((record) => !delegated || record.sessionId === principal.session.id)
          .sort((a, b) => b.issuedAt - a.issuedAt || (a.id < b.id ? -1 : 1))
          .slice(0, 100)
          .map((record) => certificateView(record, now));
      });
    },

    /** Issued certificates, newest first, with filters. Requires iam:ssh:read. */
    listCertificates: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        kind?: 'user' | 'host';
        identityId?: string;
        hostId?: string;
        status?: 'active' | 'revoked' | 'expired';
        limit?: number;
        offset?: number;
      },
    ) =>
      operation(credential, tenantOf(input.tenantId), read, 'ssh/certificates', async ({ tx, tenant }) => {
        assertSsh(ctx);
        const limit = integer(input.limit ?? 100, 'limit', 1, 500);
        const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
        const filter: Record<string, unknown> = { tenantId: tenant.id };
        if (input.kind !== undefined) filter.kind = input.kind;
        if (input.identityId !== undefined) filter.identityId = text(input.identityId, 'identityId');
        if (input.hostId !== undefined) filter.hostId = text(input.hostId, 'hostId');
        const now = ctx.now();
        const views = (await tx.find<SshCertificateRecord>('sshCertificates', filter))
          .map((record) => certificateView(record, now))
          .filter((view) => input.status === undefined || view.status === input.status)
          .sort((a, b) => b.issuedAt - a.issuedAt || (a.id < b.id ? -1 : 1));
        return { certificates: views.slice(offset, offset + limit), total: views.length };
      }),

    /** One certificate record. Requires iam:ssh:read. */
    getCertificate: (credential: CredentialInput, input: { tenantId: string; certificateId: string }) =>
      operation(
        credential,
        tenantOf(input.tenantId),
        read,
        `ssh/certificates/${text(input.certificateId, 'certificateId')}`,
        async ({ tx, tenant }) =>
          certificateView(
            await ctx.scoped<SshCertificateRecord>(tx, 'sshCertificates', input.certificateId, tenant.id),
            ctx.now(),
          ),
      ),

    /**
     * Revokes one certificate: the caller's own without any permission (not while viewing as someone nor with a scoped
     * credential; an agent only those of its own session), anyone's with iam:ssh:manage. Hosts refuse it from their next revocation list.
     */
    revokeCertificate: async (credential: CredentialInput, input: { tenantId: string; certificateId: string }) => {
      assertSsh(ctx);
      const tenantId = tenantOf(input.tenantId);
      const certificateId = text(input.certificateId, 'certificateId');
      const authenticated = await ctx.principals.authenticate(credential);
      const found = await ctx.scoped<SshCertificateRecord>(ctx.store, 'sshCertificates', certificateId, tenantId);
      const revoke = async (tx: IamStore, principal: AuthenticatedPrincipal) => {
        const record = await ctx.scoped<SshCertificateRecord>(tx, 'sshCertificates', certificateId, tenantId);
        await revokeAll(tx, tenantId, [record], 'revoked', principal.identity.id);
        return certificateView(await ctx.scoped<SshCertificateRecord>(tx, 'sshCertificates', certificateId, tenantId), ctx.now());
      };
      // The own path skips the permission, so only a session acting in its own unrestricted right takes it (not "view
      // as", not a key or token narrowed by a session policy); an agent acting for the person only for certificates
      // its own session obtained.
      if (
        found.identityId === authenticated.identity.id &&
        found.kind === 'user' &&
        !authenticated.session.impersonatorId &&
        !authenticated.session.policy &&
        !authenticated.session.sourcePolicy &&
        (authenticated.session.kind !== 'delegated' || found.sessionId === authenticated.session.id)
      )
        return ctx.store.transaction(async (tx) => {
          const principal = await ctx.principals.currentPrincipal(tx, authenticated);
          const result = await revoke(tx, principal);
          await ctx.events.audit(tx, principal, 'ssh:certificate:revoke', tenantId, `ssh/certificates/${certificateId}`, 'allow', false, {
            reason: 'revoked',
            serial: found.serial,
            own: true,
          });
          return result;
        });
      return operation(credential, tenantId, manage, `ssh/certificates/${certificateId}`, ({ tx, principal }) =>
        revoke(tx, principal),
      );
    },

    /** Revokes every live certificate of one identity (incident response). Requires iam:ssh:manage. */
    revokeIdentity: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(
        credential,
        tenantOf(input.tenantId),
        manage,
        `ssh/identities/${text(input.identityId, 'identityId')}`,
        async ({ tx, tenant, principal }) => {
          assertSsh(ctx);
          const records = await liveCertificates(ctx, tx, { tenantId: tenant.id, identityId: input.identityId, kind: 'user' });
          return { revoked: await revokeAll(tx, tenant.id, records, 'identity-revoked', principal.identity.id) };
        },
      ),

    /** Revokes every live user certificate of the tenant (a suspected compromise). Requires iam:ssh:manage. */
    revokeAllCertificates: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, tenantOf(input.tenantId), manage, 'ssh/certificates', async ({ tx, tenant, principal }) => {
        assertSsh(ctx);
        const records = await liveCertificates(ctx, tx, { tenantId: tenant.id, kind: 'user' });
        return { revoked: await revokeAll(tx, tenant.id, records, 'tenant-revoked', principal.identity.id) };
      }),

    /**
     * Access review: which active identities may log in to a host, and as which logins (each identity decided in a
     * synthetic session, with MFA when `assumeMfa`). Requires iam:ssh:read.
     */
    whoCanLogin: async (
      credential: CredentialInput,
      input: { tenantId: string; hostId: string; login?: string; assumeMfa?: boolean; kind?: 'user' | 'service' | 'agent' },
    ) => {
      const tenantId = tenantOf(input.tenantId);
      const name = await hostRecordName(tenantId, input.hostId);
      const only = input.login === undefined ? undefined : sshLogin(input.login);
      return operation(credential, tenantId, read, `ssh/hosts/${name}`, async ({ tx, tenant }) => {
        assertSsh(ctx);
        const host = await scopedHost(tx, tenantId, input.hostId);
        const logins = only ? host.logins.filter((login) => login === only) : host.logins;
        const filter: Record<string, unknown> = { tenantId, status: 'active' };
        if (input.kind !== undefined) filter.kind = input.kind;
        const identities = (await tx.find<Identity>('identities', filter)).sort(byId);
        const result: { identityId: string; name?: string; email?: string; kind: string; logins: string[] }[] = [];
        for (const identity of identities) {
          if (ctx.identityExpired(identity)) continue;
          const prepared = await ctx.decisions.prepareDecision(
            tx,
            ctx.decisions.simulatedPrincipal(identity, input.assumeMfa === true),
            tenant,
            sshLoginAction,
          );
          const decide = decideWith(prepared);
          const allowed = logins.filter((login) => decide(loginResource(host, login), sshLoginAction).allowed);
          if (allowed.length)
            result.push({
              identityId: identity.id,
              ...(identity.name ? { name: identity.name } : {}),
              ...(identity.email ? { email: identity.email } : {}),
              kind: identity.kind,
              logins: allowed,
            });
        }
        return { host: host.name, identities: result };
      });
    },

    /** Runs the continuous-authorization sweep for this tenant now (the scheduler job covers every tenant). Requires iam:ssh:manage. */
    sweep: async (credential: CredentialInput, input: { tenantId: string }): Promise<SshSweepResult> => {
      const tenantId = tenantOf(input.tenantId);
      // Authorized (and audited) first; the sweep then runs in its own short transactions.
      await operation(credential, tenantId, manage, 'ssh/certificates', async () => assertSsh(ctx));
      return sweepSshCertificates(ctx, { tenantId });
    },
  };

  /** Switches the signing key: the current active authority becomes `previous`. */
  async function activate(tx: IamStore, pending: SshAuthority): Promise<SshAuthority> {
    const now = ctx.now();
    for (const current of await tenantAuthorities(tx, pending.tenantId, pending.kind))
      if (current.status === 'active')
        await tx.put<SshAuthority>('sshAuthorities', { ...current, status: 'previous', rotatedAt: now });
    return tx.put<SshAuthority>('sshAuthorities', { ...pending, status: 'active', activatedAt: now });
  }
}

/** `iam.ssh`: the deployment-side jobs and public reads (no credential), for schedulers and custom routes. */
export function createSshRuntime(ctx: ServerContext) {
  return {
    /** Whether the `ssh` option is on. */
    get enabled() {
      try {
        assertSsh(ctx);
        return true;
      } catch {
        return false;
      }
    },
    /** Continuous authorization: revokes live certificates whose holder, session or access went away (run every few minutes). */
    sweep: (input?: { tenantId?: string }) => sweepSshCertificates(ctx, input),
    /** A tenant's KRL as bytes, for serving it from a custom route (`application/octet-stream`). */
    revocationList: async (tenantId: string, kind: 'user' | 'host' = 'user') => {
      assertSsh(ctx);
      const list = await revocationList(ctx, ctx.store, await ctx.tenant(ctx.store, tenantId), kind);
      return { ...list, bytes: Buffer.from(list.krl, 'base64') };
    },
  };
}
