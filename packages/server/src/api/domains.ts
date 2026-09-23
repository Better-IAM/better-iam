import { randomBytes } from 'node:crypto';
import { resolveTxt } from 'node:dns/promises';
import {
  IamError,
  type AuthMethod,
  type CredentialInput,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { byNewest, id } from '../utils.js';
import { text } from '../validation.js';

/** DNS verification settings for organization email domains. */
export interface DomainOptions {
  /** TXT lookup (defaults to `node:dns/promises` `resolveTxt`); inject for tests or a DNS-over-HTTPS resolver. */
  resolveTxt?: (hostname: string) => Promise<string[][]>;
  /** Label under the domain that holds the TXT record (default `_better-iam-challenge`). */
  recordName?: string;
  /** Domains no tenant may claim; defaults to widely used consumer mailbox providers. Compared exactly. */
  blockedDomains?: string[];
}

/** A domain an organization claims; it becomes discoverable once a DNS TXT record proves control. */
export interface TenantDomain extends StoredRecord {
  domain: string;
  status: 'pending' | 'verified';
  verificationToken: string;
  createdAt: number;
  createdBy: string;
  verifiedAt?: number;
  lastCheckedAt?: number;
}
/** Global ownership record (id = the domain), so one domain is verified by at most one tenant. */
interface DomainOwner extends StoredRecord {
  domainId: string;
  verifiedAt: number;
}
/** What a sign-in screen needs after the person types an email address. */
export interface DomainDiscovery {
  domain: string;
  tenantId: string;
  name: string;
  type: string;
  slug?: string;
  /** Accepted sign-in methods; null means every method the deployment enables. */
  allowedMethods: AuthMethod[] | null;
  requireMfa: boolean;
  /** The organization's home region, in a multi-region deployment. */
  region?: string;
  /** The organization's canonical sign-in URL, when organization addresses or regions are configured. */
  signInUrl?: string;
}

const consumerDomains = [
  'gmail.com',
  'googlemail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'yahoo.com',
  'ymail.com',
  'aol.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'proton.me',
  'protonmail.com',
  'pm.me',
  'gmx.com',
  'gmx.net',
  'mail.com',
  'yandex.com',
  'yandex.ru',
  'zoho.com',
  'fastmail.com',
  'hey.com',
  'qq.com',
  '163.com',
];
const label = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/** Normalizes and validates a registrable-looking DNS name: lowercase, no trailing dot, alphabetic TLD. */
export function domainName(value: unknown): string {
  const domain = text(value, 'domain', 253).trim().toLowerCase().replace(/\.$/, '');
  const labels = domain.split('.');
  if (
    labels.length < 2 ||
    domain.length > 253 ||
    !labels.every((part) => label.test(part)) ||
    !/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(labels.at(-1)!)
  )
    throw new IamError('INVALID_INPUT', 'Enter a domain such as example.com');
  return domain;
}

/**
 * Verified email domains and home-realm discovery. An organization claims a domain, publishes the TXT record it is
 * given, and verifies it; a verified domain is owned by exactly one tenant, and `discover` maps an email address to
 * that tenant (and its sign-in requirements) so login screens need neither a tenant ID nor a slug.
 */
export function createDomainsApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const settings = ctx.options.domains ?? {};
  const recordName = settings.recordName ?? '_better-iam-challenge';
  if (!/^[a-z0-9_-]{1,63}$/i.test(recordName))
    throw new IamError('INVALID_CONFIG', 'domains.recordName must be a single DNS label');
  const blocked = new Set((settings.blockedDomains ?? consumerDomains).map((d) => d.toLowerCase()));
  const lookup = settings.resolveTxt ?? resolveTxt;
  const instructions = (record: TenantDomain) => ({
    type: 'TXT' as const,
    name: `${recordName}.${record.domain}`,
    value: `better-iam-verification=${record.verificationToken}`,
  });
  const present = (record: TenantDomain) => ({
    id: record.id,
    tenantId: record.tenantId,
    domain: record.domain,
    status: record.status,
    createdAt: record.createdAt,
    createdBy: record.createdBy,
    verifiedAt: record.verifiedAt,
    lastCheckedAt: record.lastCheckedAt,
    dnsRecord: instructions(record),
  });

  return {
    /** Claims a domain for the tenant and returns the TXT record to publish. Requires iam:domains:create. */
    add: async (credential: CredentialInput, input: { tenantId: string; domain: string }) => {
      const domain = domainName(input.domain);
      return operation(
        credential,
        input.tenantId,
        'iam:domains:create',
        `domains/${domain}`,
        async ({ tx, principal }) => {
          if (blocked.has(domain))
            throw new IamError(
              'DOMAIN_NOT_ALLOWED',
              'Shared mailbox providers cannot be claimed by an organization',
            );
          if ((await tx.find('tenantDomains', { tenantId: input.tenantId, domain })).length)
            throw new IamError('CONFLICT', 'This organization already claimed the domain', 409);
          const owner = await tx.get<DomainOwner>('domainOwners', domain);
          if (owner && owner.tenantId !== input.tenantId)
            throw new IamError('DOMAIN_TAKEN', 'Another organization verified this domain', 409);
          const record = await tx.insert<TenantDomain>('tenantDomains', {
            id: id(),
            tenantId: input.tenantId,
            uniqueKey: domain,
            domain,
            status: 'pending',
            verificationToken: randomBytes(18).toString('base64url'),
            createdAt: ctx.now(),
            createdBy: principal.identity.id,
          });
          return present(record);
        },
      );
    },
    /** The tenant's claimed domains with their verification records. */
    list: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:domains:read', 'domains/*', async ({ tx }) =>
        (await tx.find<TenantDomain>('tenantDomains', { tenantId: input.tenantId }))
          .sort(byNewest)
          .map(present),
      ),
    /**
     * Looks up the TXT record and, when it matches, marks the domain verified. DNS is queried before the
     * transaction opens; the result reports `verified: false` (and the expected record) while it is not yet visible.
     */
    verify: async (credential: CredentialInput, input: { tenantId: string; domainId: string }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      await ctx.principals.authenticate(credential);
      const claimed = await ctx.scoped<TenantDomain>(
        ctx.store,
        'tenantDomains',
        text(input.domainId, 'domainId'),
        tenantId,
      );
      const expected = instructions(claimed);
      let found = false;
      if (claimed.status !== 'verified') {
        try {
          const records = await lookup(expected.name);
          found = records.some((chunks) => chunks.join('').trim() === expected.value);
        } catch {
          found = false;
        }
      }
      return operation(
        credential,
        tenantId,
        'iam:domains:update',
        `domains/${claimed.domain}`,
        async ({ tx }) => {
          const record = await ctx.scoped<TenantDomain>(tx, 'tenantDomains', claimed.id, tenantId);
          if (record.status === 'verified') return { verified: true, domain: present(record) };
          const now = ctx.now();
          if (!found) {
            const checked = await tx.put('tenantDomains', { ...record, lastCheckedAt: now });
            return { verified: false, domain: present(checked) };
          }
          const owner = await tx.get<DomainOwner>('domainOwners', record.domain);
          if (owner && owner.tenantId !== tenantId)
            throw new IamError('DOMAIN_TAKEN', 'Another organization verified this domain', 409);
          if (!owner)
            await tx.insert<DomainOwner>('domainOwners', {
              id: record.domain,
              tenantId,
              domainId: record.id,
              verifiedAt: now,
            });
          const verified = await tx.put<TenantDomain>('tenantDomains', {
            ...record,
            status: 'verified',
            verifiedAt: now,
            lastCheckedAt: now,
          });
          return { verified: true, domain: present(verified) };
        },
      );
    },
    /** Releases a claim; a verified domain stops resolving to the tenant immediately. Requires iam:domains:delete. */
    delete: async (credential: CredentialInput, input: { tenantId: string; domainId: string }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      const claimed = await ctx.scoped<TenantDomain>(
        ctx.store,
        'tenantDomains',
        text(input.domainId, 'domainId'),
        tenantId,
      );
      return operation(
        credential,
        tenantId,
        'iam:domains:delete',
        `domains/${claimed.domain}`,
        async ({ tx }) => {
          const record = await ctx.scoped<TenantDomain>(tx, 'tenantDomains', claimed.id, tenantId);
          const owner = await tx.get<DomainOwner>('domainOwners', record.domain);
          if (owner?.tenantId === tenantId) await tx.delete('domainOwners', record.domain);
          await tx.delete('tenantDomains', record.id);
          return { deleted: true };
        },
      );
    },
    /**
     * Public home-realm discovery: the active tenant that verified the email's domain, with its sign-in
     * requirements. Unknown, unverified, and inactive domains are indistinguishable (404).
     */
    discover: async (input: { email?: string; domain?: string }): Promise<DomainDiscovery> => {
      const raw =
        input.email !== undefined
          ? text(input.email, 'email', 320).trim().split('@').at(-1)
          : input.domain;
      if (input.email !== undefined && !input.email.includes('@'))
        throw new IamError('INVALID_INPUT', 'Enter an email address');
      const domain = domainName(raw);
      return ctx.store.transaction(async (tx) => {
        const owner = await tx.get<DomainOwner>('domainOwners', domain);
        const realm = owner ? await tx.get<Tenant>('tenants', owner.tenantId) : undefined;
        if (
          !realm ||
          realm.status !== 'active' ||
          (await ctx.ancestry(tx, realm)).some((item) => item.status !== 'active')
        )
          throw new IamError('NOT_FOUND', 'No organization uses this domain', 404);
        // In a multi-region deployment, people of an organization homed elsewhere are sent to its region.
        await ctx.hosts.assertServedHere(tx, realm);
        const region = await ctx.hosts.regionOf(tx, realm);
        const signInUrl = await ctx.hosts.signInUrl(realm, tx);
        return {
          domain,
          tenantId: realm.id,
          name: realm.name,
          type: realm.type,
          ...(realm.slug ? { slug: realm.slug } : {}),
          allowedMethods: realm.authPolicy?.allowedMethods ?? null,
          requireMfa: realm.authPolicy?.requireMfa === true,
          ...(region ? { region } : {}),
          ...(signInUrl ? { signInUrl } : {}),
        };
      });
    },
  };
}
