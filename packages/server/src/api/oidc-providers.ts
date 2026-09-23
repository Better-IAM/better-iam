import { IamError, type CredentialInput, type IamStore } from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type {
  OidcProvider,
  PublicJwk,
  PublicOidcProvider,
  Trust,
  WebIdentityAlgorithm,
} from '../models.js';
import { nextWatermark } from '../session-kinds.js';
import { deleteTemporarySessions } from '../temporary-credentials.js';
import { hash, id } from '../utils.js';
import { integer, text } from '../validation.js';
import {
  webIdentityAlgorithms,
  webIdentityAudiences,
  webIdentityIssuer,
  webIdentityJwksUri,
  webIdentityKeys,
} from '../web-identity.js';

/** `oidcProviders.create` input. */
export interface OidcProviderCreateInput {
  tenantId: string;
  /** A label for administrators, at most 128 characters. */
  name: string;
  /** The exact `iss` of the provider's tokens: https, no credentials, query or fragment, at most 512 characters. */
  issuer: string;
  /** Accepted `aud` values (1 to 10 of at most 256 characters); a token must name one of them. */
  audiences: string[];
  /** Where the keys live (https on port 443). Without it and without `jwks`, OIDC discovery on the issuer. */
  jwksUri?: string;
  /** Static public keys (1 to 20), used instead of fetching. */
  jwks?: { keys: PublicJwk[] };
  /** Accepted signature algorithms (default ['RS256', 'ES256']). */
  algorithms?: WebIdentityAlgorithm[];
  /** Longest accepted token lifetime and age, 60..86400 seconds (default 3600). */
  maxTokenLifetimeSeconds?: number;
  /** Clock skew tolerated on the time claims, 0..120 seconds (default 30). */
  clockToleranceSeconds?: number;
  /** 'single-use' (default) redeems each token once; 'off' suits tokens SDKs reuse until they rotate. */
  replayProtection?: 'single-use' | 'off';
  /** Default true. */
  enabled?: boolean;
}

/** `oidcProviders.update` input. The issuer cannot change; `null` clears `jwksUri` or `jwks`. */
export interface OidcProviderUpdateInput {
  tenantId: string;
  providerId: string;
  name?: string;
  audiences?: string[];
  jwksUri?: string | null;
  jwks?: { keys: PublicJwk[] } | null;
  algorithms?: WebIdentityAlgorithm[];
  maxTokenLifetimeSeconds?: number;
  clockToleranceSeconds?: number;
  replayProtection?: 'single-use' | 'off';
  enabled?: boolean;
}

/** `oidcProviders.revokeSessions` input: `before` defaults to now + 1 (everything issued so far). */
export interface OidcProviderRevokeSessionsInput {
  tenantId: string;
  providerId: string;
  /** Epoch milliseconds, no later than now + 1. */
  before?: number;
}

const featureDisabled = () =>
  new IamError('FEATURE_DISABLED', 'Web identity federation is not enabled', 403);
const updatableFields = [
  'name',
  'audiences',
  'jwksUri',
  'jwks',
  'algorithms',
  'maxTokenLifetimeSeconds',
  'clockToleranceSeconds',
  'replayProtection',
  'enabled',
] as const;
/**
 * The settings a token's acceptance depends on (keys, algorithms, audiences, lifetime and skew). An update that
 * changes any of them ends the sessions issued under the old ones, as `trust.update` does when a trust tightens.
 */
const verificationFields = [
  'audiences',
  'jwksUri',
  'jwks',
  'algorithms',
  'maxTokenLifetimeSeconds',
  'clockToleranceSeconds',
] as const;

function invalid(message: string): never {
  throw new IamError('INVALID_INPUT', message);
}

/**
 * The provider's natural key within its tenant, `issuer:{issuer}`. Stored keys are limited to 512 bytes, so an issuer
 * too long for that is keyed by its SHA-256 instead; both forms are deterministic, so duplicates still collide.
 */
function issuerKey(issuer: string): string {
  const key = `issuer:${issuer}`;
  return new TextEncoder().encode(key).byteLength <= 512 ? key : `issuer#sha256:${hash(issuer)}`;
}

/**
 * An OIDC provider as the API returns it: an explicit allowlist projection (static keys are public members only,
 * as validated when they were stored).
 */
export function publicOidcProvider(provider: OidcProvider): PublicOidcProvider {
  const result: PublicOidcProvider = {
    id: provider.id,
    tenantId: provider.tenantId,
    name: provider.name,
    issuer: provider.issuer,
    audiences: [...provider.audiences],
    algorithms: [...provider.algorithms],
    maxTokenLifetimeSeconds: provider.maxTokenLifetimeSeconds,
    clockToleranceSeconds: provider.clockToleranceSeconds,
    replayProtection: provider.replayProtection === 'off' ? 'off' : 'single-use',
    enabled: provider.enabled === true,
    authorityId: provider.authorityId,
    createdAt: provider.createdAt,
    createdBy: provider.createdBy,
    updatedAt: provider.updatedAt,
  };
  if (provider.jwksUri !== undefined) result.jwksUri = provider.jwksUri;
  if (provider.jwks !== undefined) result.jwks = structuredClone(provider.jwks);
  if (provider.sessionsRevokedBefore !== undefined)
    result.sessionsRevokedBefore = provider.sessionsRevokedBefore;
  return result;
}

function replayProtectionValue(value: unknown): 'single-use' | 'off' {
  if (value !== 'single-use' && value !== 'off')
    invalid("replayProtection must be 'single-use' or 'off'");
  return value;
}

function enabledValue(value: unknown): boolean {
  if (typeof value !== 'boolean') invalid('enabled must be a boolean');
  return value;
}

/** Deletes the provider's web-identity sessions created before `createdBefore`, across every trust that uses it. */
async function deleteProviderSessions(
  tx: IamStore,
  provider: OidcProvider,
  createdBefore: number,
): Promise<number> {
  let revoked = 0;
  for (const trust of await tx.find<Trust>('trusts', {
    tenantId: provider.tenantId,
    providerId: provider.id,
  }))
    if (trust.providerId === provider.id && typeof trust.roleId === 'string')
      revoked += await deleteTemporarySessions(tx, {
        tenantId: provider.tenantId,
        roleId: trust.roleId,
        trustId: trust.id,
        providerId: provider.id,
        createdBefore,
      });
  return revoked;
}

/**
 * The `oidcProviders` group: tenant-managed OIDC identity providers whose tokens web-identity trusts admit. Every
 * provider records its creator's grant authority, which bounds each web-identity session through it; it is edited
 * only under that authority (or by root). Creating and changing providers needs `sts.webIdentity.enabled`, except an
 * update that only disables one; reading, deleting and revoking sessions keep working when the feature is off.
 */
export function createOidcProvidersApi(ctx: ServerContext) {
  const { auth } = ctx;
  const { operation } = ctx.operations;
  const settings = ctx.config.sts.webIdentity;
  const defaultIssuer = `${ctx.config.baseURL.origin}${ctx.config.basePath}`;

  /** The issuer rules: https (loopback http in development), not IAM's own issuer, and on the deployment's pin list. */
  function issuerValue(value: unknown): string {
    for (const selfIssuer of new Set([ctx.sessionTokens?.issuer ?? defaultIssuer, defaultIssuer]))
      webIdentityIssuer(value, {
        allowInsecureLocalhost: settings.allowInsecureLocalhost,
        selfIssuer,
        ...(settings.allowedIssuers ? { allowedIssuers: settings.allowedIssuers } : {}),
      });
    return value as string;
  }

  const jwksUriValue = (value: unknown) =>
    webIdentityJwksUri(value, {
      allowInsecureLocalhost: settings.allowInsecureLocalhost,
      allowPrivateNetworks: settings.allowPrivateNetworks,
    });
  const lifetimeValue = (value: unknown) => integer(value, 'maxTokenLifetimeSeconds', 60, 86400);
  const toleranceValue = (value: unknown) => integer(value, 'clockToleranceSeconds', 0, 120);

  /** Forgets cached keys once a change is committed, so the next token is checked against the new settings. */
  const forget = (providerId: string) => ctx.webIdentity?.forget(providerId);

  return {
    /**
     * Registers an OIDC provider (iam:oidc-providers:create on the tenant, recent authentication, web identity
     * enabled). The issuer must be https, not IAM's own, and on `sts.webIdentity.allowedIssuers` when that is set;
     * static keys must be public signature keys. One provider per issuer and tenant (CONFLICT otherwise). Nothing is
     * fetched now: keys are fetched (or discovered) when a token first needs them.
     */
    create: async (
      credential: CredentialInput,
      input: OidcProviderCreateInput,
    ): Promise<PublicOidcProvider> => {
      if (!settings.enabled) throw featureDisabled();
      const name = text(input.name, 'name', 128);
      const issuer = issuerValue(input.issuer);
      const audiences = webIdentityAudiences(input.audiences);
      const jwksUri = input.jwksUri === undefined ? undefined : jwksUriValue(input.jwksUri);
      const jwks = input.jwks === undefined ? undefined : webIdentityKeys(input.jwks);
      if (jwksUri !== undefined && jwks !== undefined) invalid('Give jwks or jwksUri, not both');
      const algorithms = webIdentityAlgorithms(input.algorithms);
      const maxTokenLifetimeSeconds =
        input.maxTokenLifetimeSeconds === undefined
          ? 3600
          : lifetimeValue(input.maxTokenLifetimeSeconds);
      const clockToleranceSeconds =
        input.clockToleranceSeconds === undefined
          ? 30
          : toleranceValue(input.clockToleranceSeconds);
      const replayProtection =
        input.replayProtection === undefined
          ? 'single-use'
          : replayProtectionValue(input.replayProtection);
      const enabled = input.enabled === undefined ? true : enabledValue(input.enabled);
      return operation(
        credential,
        input.tenantId,
        'iam:oidc-providers:create',
        input.tenantId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const uniqueKey = issuerKey(issuer);
          if (
            (
              await tx.find<OidcProvider>('oidcProviders', { tenantId: input.tenantId, uniqueKey })
            )[0]
          )
            throw new IamError('CONFLICT', 'A provider for this issuer already exists', 409);
          const authority = await ctx.grantingAuthority(tx, principal, input.tenantId);
          const now = ctx.now();
          const provider: OidcProvider = {
            id: id(),
            tenantId: input.tenantId,
            uniqueKey,
            name,
            issuer,
            audiences,
            algorithms: algorithms as WebIdentityAlgorithm[],
            maxTokenLifetimeSeconds,
            clockToleranceSeconds,
            replayProtection,
            enabled,
            authorityId: authority.id,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
          };
          if (jwksUri !== undefined) provider.jwksUri = jwksUri;
          if (jwks !== undefined) provider.jwks = jwks as { keys: PublicJwk[] };
          return publicOidcProvider(await tx.insert<OidcProvider>('oidcProviders', provider));
        },
      );
    },

    /**
     * Changes a provider (iam:oidc-providers:update on the provider, recent authentication, the creator's authority or
     * root). The issuer cannot change. Needs web identity enabled unless the update only disables the provider, which
     * stays possible as a kill switch: a disabled provider admits no exchanges, and the sessions issued through it so
     * far end for good (re-enabling it does not bring them back). Cached keys are dropped. Disabling, or changing the
     * keys (`jwks`, `jwksUri`), algorithms, audiences, `maxTokenLifetimeSeconds` or `clockToleranceSeconds`, ends the
     * sessions issued through the provider so far: its `sessionsRevokedBefore` watermark moves forward and their rows
     * are deleted. An update that changes nothing is INVALID_INPUT.
     */
    update: async (
      credential: CredentialInput,
      input: OidcProviderUpdateInput,
    ): Promise<PublicOidcProvider> => {
      const given = input as unknown as Record<string, unknown>;
      const changed = updatableFields.filter((field) => given[field] !== undefined);
      const onlyDisables =
        changed.length === 1 && changed[0] === 'enabled' && input.enabled === false;
      if (!settings.enabled && !onlyDisables) throw featureDisabled();
      if (given.issuer !== undefined) invalid('The issuer of a provider cannot change');
      const providerId = text(input.providerId, 'providerId');
      const updated = await operation(
        credential,
        input.tenantId,
        'iam:oidc-providers:update',
        providerId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const provider = await ctx.scoped<OidcProvider>(
            tx,
            'oidcProviders',
            providerId,
            input.tenantId,
          );
          await ctx.canEditGrantResource(tx, principal, provider);
          const next: OidcProvider = { ...provider };
          if (input.name !== undefined) next.name = text(input.name, 'name', 128);
          if (input.audiences !== undefined) next.audiences = webIdentityAudiences(input.audiences);
          if (input.jwksUri === null) delete next.jwksUri;
          else if (input.jwksUri !== undefined) next.jwksUri = jwksUriValue(input.jwksUri);
          if (input.jwks === null) delete next.jwks;
          else if (input.jwks !== undefined)
            next.jwks = webIdentityKeys(input.jwks) as { keys: PublicJwk[] };
          if (next.jwksUri !== undefined && next.jwks !== undefined)
            invalid('Give jwks or jwksUri, not both');
          if (input.algorithms !== undefined)
            next.algorithms = webIdentityAlgorithms(input.algorithms) as WebIdentityAlgorithm[];
          if (input.maxTokenLifetimeSeconds !== undefined)
            next.maxTokenLifetimeSeconds = lifetimeValue(input.maxTokenLifetimeSeconds);
          if (input.clockToleranceSeconds !== undefined)
            next.clockToleranceSeconds = toleranceValue(input.clockToleranceSeconds);
          if (input.replayProtection !== undefined)
            next.replayProtection = replayProtectionValue(input.replayProtection);
          if (input.enabled !== undefined) next.enabled = enabledValue(input.enabled);
          if (JSON.stringify(next) === JSON.stringify(provider))
            invalid('The update changes nothing');
          const now = ctx.now();
          // Sessions verified under the old keys or claim rules would outlive them, so they end: the watermark
          // covers concurrent issuance, and the matching rows are deleted. Disabling is a kill switch and ends them
          // the same way (also with the feature off), so re-enabling the provider cannot bring them back.
          const endsSessions =
            (provider.enabled === true && next.enabled !== true) ||
            verificationFields.some(
              (field) =>
                JSON.stringify(provider[field] ?? null) !== JSON.stringify(next[field] ?? null),
            );
          if (endsSessions)
            next.sessionsRevokedBefore = nextWatermark(
              provider.sessionsRevokedBefore,
              undefined,
              now,
            );
          next.updatedAt = now;
          const stored = await tx.put<OidcProvider>('oidcProviders', next);
          if (endsSessions)
            await deleteProviderSessions(tx, stored, next.sessionsRevokedBefore as number);
          return publicOidcProvider(stored);
        },
      );
      forget(updated.id);
      return updated;
    },

    /**
     * Deletes a provider (iam:oidc-providers:delete, recent authentication, the creator's authority or root). Refused
     * with CONFLICT while unrevoked trusts reference it; revoking those trusts has already ended their sessions.
     */
    delete: async (
      credential: CredentialInput,
      input: { tenantId: string; providerId: string },
    ): Promise<{ deleted: true }> => {
      const providerId = text(input.providerId, 'providerId');
      const result = await operation(
        credential,
        input.tenantId,
        'iam:oidc-providers:delete',
        providerId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const provider = await ctx.scoped<OidcProvider>(
            tx,
            'oidcProviders',
            providerId,
            input.tenantId,
          );
          await ctx.canEditGrantResource(tx, principal, provider);
          const trusts = await tx.find<Trust>('trusts', { tenantId: input.tenantId, providerId });
          if (trusts.some((trust) => trust.providerId === provider.id && trust.revoked !== true))
            throw new IamError('CONFLICT', 'Revoke the trusts that use this provider first', 409);
          await tx.delete('oidcProviders', provider.id);
          return { deleted: true as const };
        },
      );
      forget(providerId);
      return result;
    },

    /** The tenant's OIDC providers (iam:oidc-providers:read on the tenant). */
    list: (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<PublicOidcProvider[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:oidc-providers:read',
        input.tenantId,
        async ({ tx }) =>
          (await tx.find<OidcProvider>('oidcProviders', { tenantId: input.tenantId }))
            .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
            .map(publicOidcProvider),
      ),

    /** One provider (iam:oidc-providers:read on the provider). */
    get: (
      credential: CredentialInput,
      input: { tenantId: string; providerId: string },
    ): Promise<PublicOidcProvider> =>
      operation(
        credential,
        input.tenantId,
        'iam:oidc-providers:read',
        input.providerId,
        async ({ tx }) =>
          publicOidcProvider(
            await ctx.scoped<OidcProvider>(tx, 'oidcProviders', input.providerId, input.tenantId),
          ),
      ),

    /**
     * Revokes the web-identity sessions issued through this provider before `before` (default: every session so far):
     * moves the provider's `sessionsRevokedBefore` watermark forward and deletes the matching rows of every trust that
     * uses it. Requires iam:roles:revoke-sessions on the provider and recent authentication; it only removes access,
     * so it is delegable and works while the feature is off. Audited as `role:sessions-revoked`.
     */
    revokeSessions: (
      credential: CredentialInput,
      input: OidcProviderRevokeSessionsInput,
    ): Promise<{ providerId: string; sessionsRevokedBefore: number; revoked: number }> =>
      operation(
        credential,
        input.tenantId,
        'iam:roles:revoke-sessions',
        input.providerId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const provider = await ctx.scoped<OidcProvider>(
            tx,
            'oidcProviders',
            input.providerId,
            input.tenantId,
          );
          const sessionsRevokedBefore = nextWatermark(
            provider.sessionsRevokedBefore,
            input.before,
            ctx.now(),
          );
          // updatedAt stays: it versions the provider's key settings, which have not changed.
          await tx.put<OidcProvider>('oidcProviders', { ...provider, sessionsRevokedBefore });
          const revoked = await deleteProviderSessions(tx, provider, sessionsRevokedBefore);
          await ctx.events.audit(
            tx,
            principal,
            'role:sessions-revoked',
            input.tenantId,
            provider.id,
            'allow',
            false,
            { sessionsRevokedBefore, revoked },
          );
          return { providerId: provider.id, sessionsRevokedBefore, revoked };
        },
      ),
  };
}
