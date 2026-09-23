import { randomBytes } from 'node:crypto';
import { resolveTxt } from 'node:dns/promises';
import { IamError, type CredentialInput } from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type { HostnameOwner, TenantHostname } from '../hosts.js';
import { byNewest, id } from '../utils.js';
import { text } from '../validation.js';
import { domainName } from './domains.js';

/** The most hostnames one organization may claim. */
const MAX_HOSTNAMES = 20;

/** A claimed hostname as the API returns it, with the DNS records that verify and route it. */
export interface PublicHostname {
  id: string;
  tenantId: string;
  hostname: string;
  status: 'pending' | 'verified';
  primary: boolean;
  /** The sign-in URL at this hostname. */
  url: string;
  createdAt: number;
  createdBy: string;
  verifiedAt?: number;
  lastCheckedAt?: number;
  dnsRecords: {
    /** Proves the organization controls the hostname; publish it, then call `verify`. */
    verification: { type: 'TXT'; name: string; value: string };
    /** Sends the hostname's traffic to the deployment (when `hosts.cnameTarget` is configured). */
    routing?: { type: 'CNAME'; name: string; value: string };
  };
}

/**
 * Custom sign-in hostnames. An organization claims a hostname it controls (`login.acme.com`), publishes the TXT
 * record it is given, points the hostname at the deployment with a CNAME, and verifies it. From then on the hostname
 * resolves to the organization like its subdomain does: requests there are pinned to it, its origin is trusted,
 * and a primary hostname becomes the address in its sign-in URLs and email links. Needs `hosts.customHostnames`.
 */
export function createHostnamesApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const { hosts, baseURL } = ctx.config;
  const settings = ctx.options.domains ?? {};
  const recordName = settings.recordName ?? '_better-iam-challenge';
  const lookup = settings.resolveTxt ?? resolveTxt;
  const enabled = () => {
    if (!hosts.customHostnames)
      throw new IamError(
        'FEATURE_DISABLED',
        'Custom hostnames are not enabled on this deployment (hosts.customHostnames)',
      );
  };
  const present = (record: TenantHostname): PublicHostname => ({
    id: record.id,
    tenantId: record.tenantId,
    hostname: record.hostname,
    status: record.status,
    primary: record.primary === true,
    url: `${baseURL.protocol}//${record.hostname}${hosts.signInPath}`,
    createdAt: record.createdAt,
    createdBy: record.createdBy,
    ...(record.verifiedAt !== undefined ? { verifiedAt: record.verifiedAt } : {}),
    ...(record.lastCheckedAt !== undefined ? { lastCheckedAt: record.lastCheckedAt } : {}),
    dnsRecords: {
      verification: {
        type: 'TXT',
        name: `${recordName}.${record.hostname}`,
        value: `better-iam-hostname=${record.verificationToken}`,
      },
      ...(hosts.cnameTarget
        ? { routing: { type: 'CNAME' as const, name: record.hostname, value: hosts.cnameTarget } }
        : {}),
    },
  });
  const claimed = (tenantId: string, hostnameId: unknown) =>
    ctx.scoped<TenantHostname>(
      ctx.store,
      'tenantHostnames',
      text(hostnameId, 'hostnameId'),
      tenantId,
    );

  return {
    /**
     * Claims a hostname for the organization and returns the DNS records to publish. Requires
     * iam:hostnames:create. Hostnames the deployment uses itself (its base URL and its subdomain space) are refused.
     */
    add: async (credential: CredentialInput, input: { tenantId: string; hostname: string }) => {
      enabled();
      const hostname = domainName(input.hostname);
      ctx.hosts.assertClaimable(hostname);
      return operation(
        credential,
        input.tenantId,
        'iam:hostnames:create',
        `hostnames/${hostname}`,
        async ({ tx, principal }) => {
          const existing = await tx.find<TenantHostname>('tenantHostnames', {
            tenantId: input.tenantId,
          });
          if (existing.some((record) => record.hostname === hostname))
            throw new IamError('CONFLICT', 'This organization already claimed the hostname', 409);
          if (existing.length >= MAX_HOSTNAMES)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `An organization can claim at most ${MAX_HOSTNAMES} hostnames`,
              409,
            );
          const owner = await tx.get<HostnameOwner>('hostnameOwners', hostname);
          if (owner && owner.tenantId !== input.tenantId)
            throw new IamError(
              'HOSTNAME_TAKEN',
              'Another organization verified this hostname',
              409,
            );
          const record = await tx.insert<TenantHostname>('tenantHostnames', {
            id: id(),
            tenantId: input.tenantId,
            uniqueKey: hostname,
            hostname,
            status: 'pending',
            verificationToken: randomBytes(18).toString('base64url'),
            createdAt: ctx.now(),
            createdBy: principal.identity.id,
          });
          return present(record);
        },
      );
    },
    /** The organization's claimed hostnames with their DNS records, newest first. Requires iam:hostnames:read. */
    list: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:hostnames:read', 'hostnames/*', async ({ tx }) =>
        (await tx.find<TenantHostname>('tenantHostnames', { tenantId: input.tenantId }))
          .sort(byNewest)
          .map(present),
      ),
    /**
     * Looks up the TXT record and, when it matches, marks the hostname verified so it starts resolving to the
     * organization. DNS is queried before the transaction opens; `verified: false` means the record is not visible
     * yet. Requires iam:hostnames:update.
     */
    verify: async (
      credential: CredentialInput,
      input: { tenantId: string; hostnameId: string },
    ) => {
      enabled();
      const tenantId = text(input.tenantId, 'tenantId');
      await ctx.principals.authenticate(credential);
      const record = await claimed(tenantId, input.hostnameId);
      const expected = present(record).dnsRecords.verification;
      let found = false;
      if (record.status !== 'verified') {
        ctx.hosts.assertClaimable(record.hostname);
        try {
          const answers = await lookup(expected.name);
          found = answers.some((chunks) => chunks.join('').trim() === expected.value);
        } catch {
          found = false;
        }
      }
      return operation(
        credential,
        tenantId,
        'iam:hostnames:update',
        `hostnames/${record.hostname}`,
        async ({ tx }) => {
          const current = await ctx.scoped<TenantHostname>(
            tx,
            'tenantHostnames',
            record.id,
            tenantId,
          );
          if (current.status === 'verified') return { verified: true, hostname: present(current) };
          const now = ctx.now();
          if (!found) {
            const checked = await tx.put('tenantHostnames', { ...current, lastCheckedAt: now });
            return { verified: false, hostname: present(checked) };
          }
          const owner = await tx.get<HostnameOwner>('hostnameOwners', current.hostname);
          if (owner && owner.tenantId !== tenantId)
            throw new IamError(
              'HOSTNAME_TAKEN',
              'Another organization verified this hostname',
              409,
            );
          if (!owner)
            await tx.insert<HostnameOwner>('hostnameOwners', {
              id: current.hostname,
              tenantId,
              hostnameId: current.id,
              verifiedAt: now,
            });
          const verified = await tx.put<TenantHostname>('tenantHostnames', {
            ...current,
            status: 'verified',
            verifiedAt: now,
            lastCheckedAt: now,
          });
          return { verified: true, hostname: present(verified) };
        },
      );
    },
    /**
     * Makes a verified hostname the organization's canonical address (sign-in URLs and email links use it), or with
     * `hostnameId: null` goes back to the subdomain. Requires iam:hostnames:update.
     */
    setPrimary: async (
      credential: CredentialInput,
      input: { tenantId: string; hostnameId: string | null },
    ) => {
      enabled();
      const tenantId = text(input.tenantId, 'tenantId');
      const target =
        input.hostnameId === null ? undefined : await claimed(tenantId, input.hostnameId);
      return operation(
        credential,
        tenantId,
        'iam:hostnames:update',
        target ? `hostnames/${target.hostname}` : 'hostnames/*',
        async ({ tx }) => {
          if (target) {
            const current = await ctx.scoped<TenantHostname>(
              tx,
              'tenantHostnames',
              target.id,
              tenantId,
            );
            if (current.status !== 'verified')
              throw new IamError('INVALID_INPUT', 'Verify the hostname before making it primary');
          }
          const records = await tx.find<TenantHostname>('tenantHostnames', { tenantId });
          for (const record of records) {
            const primary = record.id === target?.id;
            if ((record.primary === true) === primary) continue;
            const { primary: _previous, ...rest } = record;
            await tx.put<TenantHostname>('tenantHostnames', primary ? { ...rest, primary } : rest);
          }
          return {
            primary: target ? present({ ...target, primary: true, status: 'verified' }) : null,
            signInUrl: (await ctx.hosts.signInUrl(tenantId, tx)) ?? null,
          };
        },
      );
    },
    /** Releases a hostname; a verified one stops resolving to the organization at once. Requires iam:hostnames:delete. */
    delete: async (
      credential: CredentialInput,
      input: { tenantId: string; hostnameId: string },
    ) => {
      const tenantId = text(input.tenantId, 'tenantId');
      const record = await claimed(tenantId, input.hostnameId);
      return operation(
        credential,
        tenantId,
        'iam:hostnames:delete',
        `hostnames/${record.hostname}`,
        async ({ tx }) => {
          const current = await ctx.scoped<TenantHostname>(
            tx,
            'tenantHostnames',
            record.id,
            tenantId,
          );
          const owner = await tx.get<HostnameOwner>('hostnameOwners', current.hostname);
          if (owner?.tenantId === tenantId) await tx.delete('hostnameOwners', current.hostname);
          await tx.delete('tenantHostnames', current.id);
          return { deleted: true };
        },
      );
    },
  };
}
