import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { tagKeyPattern } from '../context-keys.js';
import type {
  IdentityLink,
  OidcProvider,
  PublicTrust,
  Role,
  SourceIdentityMode,
  Trust,
  TrustConditions,
} from '../models.js';
import { OperationDenied } from '../operations.js';
import { nextWatermark } from '../session-kinds.js';
import { allowedTagKeysValue, deleteTemporarySessions } from '../temporary-credentials.js';
import { all, hash, id, publicIdentity } from '../utils.js';
import { text } from '../validation.js';
import { webIdentityClaimName, webIdentityConditions } from '../web-identity.js';
import { evaluateWebIdentity, type WebIdentityEvaluation } from '../web-identity-exchange.js';

/**
 * `trust.create` input: an identity trust (a named source identity, possibly in another tenant; root only) or a
 * web-identity trust (tokens of an OIDC provider, backed by a service account of the tenant; tenant-managed).
 */
export type TrustCreateInput = IdentityTrustCreateInput | WebIdentityTrustCreateInput;

/**
 * `trust.create` for a web-identity trust (AssumeRoleWithWebIdentity). Requires `sts.webIdentity.enabled`,
 * iam:trust:create on the role, iam:identities:update on the service account and recent authentication, and records
 * the creator's grant authority, which bounds every session under the trust. Identity-trust fields (`sourceTenantId`, `sourceIdentityId`, `requireMfa`,
 * `externalId`, `allowedTagKeys`, `sourceIdentityMode`) are INVALID_INPUT.
 */
export interface WebIdentityTrustCreateInput {
  /** The tenant of the role, the provider and the service account. */
  tenantId: string;
  kind: 'web-identity';
  /** The OIDC provider whose tokens the trust admits (in the same tenant). */
  providerId: string;
  /** The active service account sessions act as (stored as `sourceIdentityId`). */
  serviceAccountId: string;
  roleId: string;
  /**
   * Claim conditions: a policy statement's `conditions` block over `token.<claim>` keys (at most 20 entries). It must
   * pin `token.sub` with StringEquals, or StringLike with any wildcard only after two complete segments such as
   * `repo:acme/*` (else WEAK_TRUST_CONDITIONS).
   */
  conditions: TrustConditions;
  /** Session tag key to flattened claim name (`token.<claim>`), at most 10. */
  tagClaims?: Record<string, string>;
  /** The flattened claim that becomes the session's source identity; a token without a valid one is refused. */
  sourceIdentityClaim?: string;
  /** Longest role session, 60 up to `sts.maxRoleSessionSeconds` (default 3600). */
  maxSessionSeconds?: number;
  /** Upper bound on what role sessions may do (default: everything the role grants). */
  ceiling?: PolicyDocument;
  /** Pass the service account's attributes into role sessions (default true). */
  passSourceAttributes?: boolean;
  /** At most 512 characters. */
  description?: string;
}

/** `trust.create` for an identity trust (platform-controlled: root only, recent authentication). */
export interface IdentityTrustCreateInput {
  /** The target tenant: the tenant of the role. */
  tenantId: string;
  /** 'identity' (default). */
  kind?: 'identity';
  sourceTenantId: string;
  sourceIdentityId: string;
  roleId: string;
  /** The source session must be MFA-verified (default true). */
  requireMfa?: boolean;
  /** A shared secret the caller must present on `roles.assume`; only its SHA-256 is stored. */
  externalId?: string;
  /** Upper bound on what role sessions may do (default: everything the role grants). */
  ceiling?: PolicyDocument;
  /** Longest role session, 60 up to `sts.maxRoleSessionSeconds` (default 3600). */
  maxSessionSeconds?: number;
  /** Pass the source identity's attributes into role sessions (default: only for same-tenant trusts). */
  passSourceAttributes?: boolean;
  /** Session tag keys callers may set (at most 50), or exactly ['*']; default none. */
  allowedTagKeys?: string[];
  /** Whether callers may or must state a source identity; default 'forbidden'. */
  sourceIdentityMode?: SourceIdentityMode;
  /** At most 512 characters. */
  description?: string;
}

/**
 * `trust.update` input. `null` clears a field back to its default. Web-only fields (`conditions`, `tagClaims`,
 * `sourceIdentityClaim`) on an identity trust, or identity-only fields (`requireMfa`, `allowedTagKeys`,
 * `sourceIdentityMode`) on a web-identity trust, are INVALID_INPUT.
 */
export interface TrustUpdateInput {
  tenantId: string;
  trustId: string;
  requireMfa?: boolean;
  ceiling?: PolicyDocument | null;
  maxSessionSeconds?: number | null;
  passSourceAttributes?: boolean;
  allowedTagKeys?: string[] | null;
  sourceIdentityMode?: SourceIdentityMode;
  description?: string | null;
  conditions?: TrustConditions;
  tagClaims?: Record<string, string> | null;
  sourceIdentityClaim?: string | null;
}

/** `trust.revokeSessions` / `roles.revokeSessions` input: `before` defaults to now + 1 (everything issued so far). */
export interface TrustRevokeSessionsInput {
  tenantId: string;
  trustId: string;
  /** Epoch milliseconds, no later than now + 1. */
  before?: number;
}

const sourceIdentityModes: readonly SourceIdentityMode[] = ['forbidden', 'optional', 'required'];
const identityOnlyFields = ['requireMfa', 'allowedTagKeys', 'sourceIdentityMode'] as const;
const webOnlyFields = ['conditions', 'tagClaims', 'sourceIdentityClaim'] as const;
/** Fields `trust.create` accepts only for identity trusts, and only for web-identity trusts. */
const identityCreateFields = [
  'sourceTenantId',
  'sourceIdentityId',
  'requireMfa',
  'externalId',
  'allowedTagKeys',
  'sourceIdentityMode',
] as const;
const webCreateFields = [
  'providerId',
  'serviceAccountId',
  'conditions',
  'tagClaims',
  'sourceIdentityClaim',
] as const;
const maxTagClaims = 10;
/** The duration cap of a trust without `maxSessionSeconds`. */
const defaultMaxSessionSeconds = 3600;

function invalid(message: string): never {
  throw new IamError('INVALID_INPUT', message);
}
const webIdentityDisabled = () =>
  new IamError('FEATURE_DISABLED', 'Web identity federation is not enabled', 403);

/**
 * A trust as the API returns it: an allowlist projection that never carries the external ID hash, reports whether an
 * external ID is required, and reads legacy records (no kind) as identity trusts.
 */
export function publicTrust(trust: Trust): PublicTrust {
  const result: PublicTrust = {
    id: trust.id,
    tenantId: trust.tenantId,
    kind: trust.kind === 'web-identity' ? 'web-identity' : 'identity',
    sourceTenantId: trust.sourceTenantId,
    sourceIdentityId: trust.sourceIdentityId,
    roleId: trust.roleId,
    requireMfa: trust.requireMfa,
    requiresExternalId: typeof trust.externalIdHash === 'string',
    revoked: trust.revoked,
  };
  if (trust.ceiling !== undefined) result.ceiling = structuredClone(trust.ceiling);
  if (trust.maxSessionSeconds !== undefined) result.maxSessionSeconds = trust.maxSessionSeconds;
  if (trust.passSourceAttributes !== undefined)
    result.passSourceAttributes = trust.passSourceAttributes;
  // A malformed stored value (not a list) is left out rather than failing the whole projection.
  if (Array.isArray(trust.allowedTagKeys)) result.allowedTagKeys = [...trust.allowedTagKeys];
  if (trust.sourceIdentityMode !== undefined) result.sourceIdentityMode = trust.sourceIdentityMode;
  if (trust.sessionsRevokedBefore !== undefined)
    result.sessionsRevokedBefore = trust.sessionsRevokedBefore;
  if (trust.providerId !== undefined) result.providerId = trust.providerId;
  if (trust.conditions !== undefined) result.conditions = structuredClone(trust.conditions);
  if (trust.tagClaims !== undefined) result.tagClaims = { ...trust.tagClaims };
  if (trust.sourceIdentityClaim !== undefined)
    result.sourceIdentityClaim = trust.sourceIdentityClaim;
  if (trust.authorityId !== undefined) result.authorityId = trust.authorityId;
  if (trust.description !== undefined) result.description = trust.description;
  if (trust.createdAt !== undefined) result.createdAt = trust.createdAt;
  if (trust.createdBy !== undefined) result.createdBy = trust.createdBy;
  if (trust.updatedAt !== undefined) result.updatedAt = trust.updatedAt;
  return result;
}

/** Longest role session a trust issues: 60 up to the deployment's `sts.maxRoleSessionSeconds`. */
function maxSessionSecondsValue(ctx: ServerContext, value: unknown): number {
  const ceiling = ctx.config.sts.maxRoleSessionSeconds;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 60 || value > ceiling)
    invalid(`maxSessionSeconds must be an integer from 60 to ${ceiling}`);
  return value;
}

function booleanValue(value: unknown, name: string): boolean {
  if (typeof value !== 'boolean') invalid(`${name} must be a boolean`);
  return value;
}

function sourceIdentityModeValue(value: unknown): SourceIdentityMode {
  if (!sourceIdentityModes.includes(value as SourceIdentityMode))
    invalid("sourceIdentityMode must be 'forbidden', 'optional' or 'required'");
  return value as SourceIdentityMode;
}

/**
 * A web-identity trust's claim-to-tag mapping: at most 10 entries, each a session tag key (unique case-insensitively)
 * mapped to a flattened claim name (`token.<claim>`).
 */
export function webTrustTagClaims(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    invalid('tagClaims must map session tag keys to token.<claim> names');
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > maxTagClaims)
    invalid(`tagClaims may contain at most ${maxTagClaims} entries`);
  const seen = new Set<string>();
  const mapping: Record<string, string> = {};
  for (const [key, claim] of entries) {
    if (!tagKeyPattern.test(key))
      invalid(
        'Tag keys must start with a letter and use at most 64 letters, digits or underscores',
      );
    const folded = key.toLowerCase();
    if (seen.has(folded)) invalid(`Tag key ${key} is repeated (tag keys are case-insensitive)`);
    seen.add(folded);
    mapping[key] = webIdentityClaimName(claim);
  }
  return mapping;
}

/** JSON with object keys sorted, so equal values compare equal whatever their key order. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) =>
    item && typeof item === 'object' && !Array.isArray(item)
      ? Object.fromEntries(
          Object.entries(item as Record<string, unknown>).sort(([a], [b]) =>
            a < b ? -1 : a > b ? 1 : 0,
          ),
        )
      : item,
  );
}

/** Tag key lists compare as sets. A stored value that is not a list (malformed) reads as no keys. */
function sameTagKeys(a: readonly string[] | undefined, b: readonly string[] | undefined): boolean {
  const keys = (value: unknown): string[] => (Array.isArray(value) ? [...value].sort() : []);
  return canonical(keys(a)) === canonical(keys(b));
}

/**
 * Who may manage a trust: identity trusts (a named source identity, possibly in another tenant) stay
 * platform-controlled and need a root principal; web-identity trusts are tenant-managed and editable by their
 * creator's authority (`canEditGrantResource`). Refusals are audited denials.
 */
async function assertTrustManager(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  trust: Trust,
): Promise<void> {
  if (trust.kind === 'web-identity') {
    await ctx.canEditGrantResource(tx, principal, trust);
    return;
  }
  if (!(await ctx.rootPrincipal(tx, principal)))
    throw new OperationDenied('Only a root administrator can manage identity trusts');
}

/**
 * A web-identity trust hands its workloads the service account it names, so creating or changing one needs authority
 * over that account: iam:identities:update on it, the permission `serviceAccounts.update` and `setStatus` manage
 * service accounts with. Otherwise a trust administrator could act as any service account of the tenant. The refusal
 * is an audited denial (ACCESS_DENIED).
 */
async function assertServiceAccountControl(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
  accountId: string,
): Promise<void> {
  const decision = await ctx.decisions.decide(
    tx,
    principal,
    { tenantId, action: 'iam:identities:update', resource: { type: 'iam', id: accountId } },
    true,
  );
  if (!decision.allowed)
    throw new OperationDenied(
      'Binding a service account to a web-identity trust requires iam:identities:update on it',
    );
}

export function createTrustApi(ctx: ServerContext) {
  const { auth, catalog } = ctx;
  const { operation } = ctx.operations;

  /**
   * `trust.create` for web-identity trusts: tenant-managed (iam:trust:create on the role, not root-only), recent
   * authentication, the feature gate first. The role must not be protected, the provider must belong to the tenant,
   * and the service account must be active and unexpired, with the caller holding iam:identities:update on it
   * (ACCESS_DENIED otherwise). The trust records the creator's grant authority, which
   * bounds its sessions (`credentialAuthorityId`) and is the only authority that may edit it besides root.
   */
  async function createWebTrust(
    credential: CredentialInput,
    input: WebIdentityTrustCreateInput,
  ): Promise<PublicTrust> {
    if (!ctx.config.sts.webIdentity.enabled) throw webIdentityDisabled();
    const given = input as unknown as Record<string, unknown>;
    for (const field of identityCreateFields)
      if (given[field] !== undefined) invalid(`${field} applies only to identity trusts`);
    const providerId = text(input.providerId, 'providerId');
    const serviceAccountId = text(input.serviceAccountId, 'serviceAccountId');
    const conditions = webIdentityConditions(input.conditions);
    const tagClaims =
      input.tagClaims === undefined ? undefined : webTrustTagClaims(input.tagClaims);
    const sourceIdentityClaim =
      input.sourceIdentityClaim === undefined
        ? undefined
        : webIdentityClaimName(input.sourceIdentityClaim);
    const maxSessionSeconds =
      input.maxSessionSeconds === undefined
        ? undefined
        : maxSessionSecondsValue(ctx, input.maxSessionSeconds);
    const passSourceAttributes =
      input.passSourceAttributes === undefined
        ? true
        : booleanValue(input.passSourceAttributes, 'passSourceAttributes');
    const description =
      input.description === undefined ? undefined : text(input.description, 'description', 512);
    return operation(
      credential,
      input.tenantId,
      'iam:trust:create',
      input.roleId,
      async ({ tx, principal }) => {
        auth.requireRecent(principal);
        const role = await ctx.scoped<Role>(tx, 'roles', input.roleId, input.tenantId);
        if (role.protected)
          throw new IamError('PROTECTED_RESOURCE', 'Cannot assume protected owner roles');
        await ctx.scoped<OidcProvider>(tx, 'oidcProviders', providerId, input.tenantId);
        const account = await ctx.scoped<Identity>(
          tx,
          'identities',
          serviceAccountId,
          input.tenantId,
        );
        if (
          account.kind !== 'service' ||
          account.status !== 'active' ||
          ctx.identityExpired(account)
        )
          throw new IamError(
            'INVALID_IDENTITY',
            'Web-identity trusts require an active service account',
          );
        await assertServiceAccountControl(ctx, tx, principal, input.tenantId, account.id);
        if (input.ceiling) await catalog.validate(tx, input.tenantId, input.ceiling);
        const authority = await ctx.grantingAuthority(tx, principal, input.tenantId);
        const now = ctx.now();
        const trust: Trust = {
          id: id(),
          tenantId: input.tenantId,
          kind: 'web-identity',
          sourceTenantId: input.tenantId,
          sourceIdentityId: account.id,
          roleId: role.id,
          requireMfa: false,
          ceiling: input.ceiling ?? all,
          revoked: false,
          passSourceAttributes,
          providerId,
          conditions,
          authorityId: authority.id,
          createdAt: now,
          createdBy: principal.identity.id,
          updatedAt: now,
        };
        if (tagClaims !== undefined) trust.tagClaims = tagClaims;
        if (sourceIdentityClaim !== undefined) trust.sourceIdentityClaim = sourceIdentityClaim;
        if (maxSessionSeconds !== undefined) trust.maxSessionSeconds = maxSessionSeconds;
        if (description !== undefined) trust.description = description;
        return publicTrust(await tx.insert<Trust>('trusts', trust));
      },
    );
  }

  return {
    /**
     * Creates a trust. Identity trusts are platform-controlled: they establish exact source-identity to target-role
     * trust for temporary role assumption (root only, recent authentication). Defaults: MFA required, no ceiling
     * beyond the role, a 3600 s session cap, no session tags, source identity forbidden, and source attributes passed
     * only for same-tenant trusts. Web-identity trusts (`kind: 'web-identity'`) admit the tokens of an OIDC provider
     * that satisfy their claim conditions; see WebIdentityTrustCreateInput.
     */
    create: async (credential: CredentialInput, input: TrustCreateInput): Promise<PublicTrust> => {
      if (input.kind === 'web-identity') return createWebTrust(credential, input);
      const kind: unknown = input.kind;
      if (kind !== undefined && kind !== 'identity')
        invalid("kind must be 'identity' or 'web-identity'");
      const given = input as unknown as Record<string, unknown>;
      for (const field of webCreateFields)
        if (given[field] !== undefined) invalid(`${field} applies only to web-identity trusts`);
      if (input.requireMfa !== undefined) booleanValue(input.requireMfa, 'requireMfa');
      if (input.externalId !== undefined && typeof input.externalId !== 'string')
        invalid('externalId must be a string');
      const maxSessionSeconds =
        input.maxSessionSeconds === undefined
          ? undefined
          : maxSessionSecondsValue(ctx, input.maxSessionSeconds);
      const passSourceAttributes =
        input.passSourceAttributes === undefined
          ? input.sourceTenantId === input.tenantId
          : booleanValue(input.passSourceAttributes, 'passSourceAttributes');
      const allowedTagKeys =
        input.allowedTagKeys === undefined ? [] : allowedTagKeysValue(input.allowedTagKeys);
      const sourceIdentityMode =
        input.sourceIdentityMode === undefined
          ? 'forbidden'
          : sourceIdentityModeValue(input.sourceIdentityMode);
      const description =
        input.description === undefined ? undefined : text(input.description, 'description', 512);
      return operation(
        credential,
        input.tenantId,
        'iam:trust:create',
        input.roleId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const role = await ctx.scoped<Role>(tx, 'roles', input.roleId, input.tenantId);
          if (role.protected)
            throw new IamError('PROTECTED_RESOURCE', 'Cannot assume protected owner roles');
          await ctx.scoped(tx, 'identities', input.sourceIdentityId, input.sourceTenantId);
          if (input.ceiling) await catalog.validate(tx, input.tenantId, input.ceiling);
          const now = ctx.now();
          const trust: Trust = {
            id: id(),
            tenantId: input.tenantId,
            kind: 'identity',
            sourceTenantId: input.sourceTenantId,
            sourceIdentityId: input.sourceIdentityId,
            roleId: input.roleId,
            requireMfa: input.requireMfa ?? true,
            ceiling: input.ceiling ?? all,
            revoked: false,
            passSourceAttributes,
            allowedTagKeys,
            sourceIdentityMode,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
          };
          if (input.externalId) trust.externalIdHash = hash(input.externalId);
          if (maxSessionSeconds !== undefined) trust.maxSessionSeconds = maxSessionSeconds;
          if (description !== undefined) trust.description = description;
          return publicTrust(await tx.insert<Trust>('trusts', trust));
        },
        true,
      );
    },
    /**
     * Changes a trust's knobs (recent authentication; identity trusts need a root principal, web-identity trusts
     * their creator's authority and iam:identities:update on their service account). Tightening what a trust admits (tag keys, source identity mode, claim conditions or
     * mappings, or a lower session cap) also revokes the sessions issued under the old rules, through the trust's
     * `sessionsRevokedBefore` watermark. A revoked trust is CONFLICT; an update that changes nothing is INVALID_INPUT.
     */
    update: (credential: CredentialInput, input: TrustUpdateInput): Promise<PublicTrust> =>
      operation(
        credential,
        input.tenantId,
        'iam:trust:update',
        input.trustId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const trust = await ctx.scoped<Trust>(tx, 'trusts', input.trustId, input.tenantId);
          const web = trust.kind === 'web-identity';
          if (web && !ctx.config.sts.webIdentity.enabled)
            throw new IamError('FEATURE_DISABLED', 'Web identity federation is not enabled', 403);
          await assertTrustManager(ctx, tx, principal, trust);
          if (trust.revoked) throw new IamError('CONFLICT', 'The trust is revoked', 409);
          // Changing what a web-identity trust admits changes who acts as its service account.
          if (web)
            await assertServiceAccountControl(
              ctx,
              tx,
              principal,
              input.tenantId,
              trust.sourceIdentityId,
            );
          const given = input as unknown as Record<string, unknown>;
          for (const field of web ? identityOnlyFields : webOnlyFields)
            if (given[field] !== undefined)
              invalid(`${field} applies only to ${web ? 'identity' : 'web-identity'} trusts`);
          const next: Trust = { ...trust };
          if (input.requireMfa !== undefined)
            next.requireMfa = booleanValue(input.requireMfa, 'requireMfa');
          if (input.ceiling === null) next.ceiling = all;
          else if (input.ceiling !== undefined) {
            await catalog.validate(tx, input.tenantId, input.ceiling);
            next.ceiling = input.ceiling;
          }
          if (input.maxSessionSeconds === null) delete next.maxSessionSeconds;
          else if (input.maxSessionSeconds !== undefined)
            next.maxSessionSeconds = maxSessionSecondsValue(ctx, input.maxSessionSeconds);
          if (input.passSourceAttributes !== undefined)
            next.passSourceAttributes = booleanValue(
              input.passSourceAttributes,
              'passSourceAttributes',
            );
          if (input.allowedTagKeys === null) next.allowedTagKeys = [];
          else if (input.allowedTagKeys !== undefined)
            next.allowedTagKeys = allowedTagKeysValue(input.allowedTagKeys);
          if (input.sourceIdentityMode !== undefined)
            next.sourceIdentityMode = sourceIdentityModeValue(input.sourceIdentityMode);
          if (input.description === null) delete next.description;
          else if (input.description !== undefined)
            next.description = text(input.description, 'description', 512);
          if (input.conditions !== undefined)
            next.conditions = webIdentityConditions(input.conditions);
          if (input.tagClaims === null) delete next.tagClaims;
          else if (input.tagClaims !== undefined)
            next.tagClaims = webTrustTagClaims(input.tagClaims);
          if (input.sourceIdentityClaim === null) delete next.sourceIdentityClaim;
          else if (input.sourceIdentityClaim !== undefined)
            next.sourceIdentityClaim = webIdentityClaimName(input.sourceIdentityClaim);
          if (canonical(next) === canonical(trust)) invalid('The update changes nothing');
          // Sessions issued under looser rules would keep what the trust no longer admits, so they end.
          const tightened =
            !sameTagKeys(trust.allowedTagKeys, next.allowedTagKeys) ||
            (trust.sourceIdentityMode ?? 'forbidden') !==
              (next.sourceIdentityMode ?? 'forbidden') ||
            canonical(trust.conditions ?? null) !== canonical(next.conditions ?? null) ||
            canonical(trust.tagClaims ?? null) !== canonical(next.tagClaims ?? null) ||
            (trust.sourceIdentityClaim ?? null) !== (next.sourceIdentityClaim ?? null) ||
            (next.maxSessionSeconds ?? defaultMaxSessionSeconds) <
              (trust.maxSessionSeconds ?? defaultMaxSessionSeconds);
          const now = ctx.now();
          if (tightened)
            next.sessionsRevokedBefore = nextWatermark(trust.sessionsRevokedBefore, undefined, now);
          next.updatedAt = now;
          return publicTrust(await tx.put<Trust>('trusts', next));
        },
      ),
    /**
     * Permanently revokes a trust and deletes its live role sessions (recent authentication; identity trusts need a
     * root principal, web-identity trusts their creator's authority). Revoking only removes access, so it works for
     * web-identity trusts while `sts.webIdentity.enabled` is off (their provider can then be deleted).
     */
    revoke: (
      credential: CredentialInput,
      input: { tenantId: string; trustId: string },
    ): Promise<PublicTrust> =>
      operation(
        credential,
        input.tenantId,
        'iam:trust:revoke',
        input.trustId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const trust = await ctx.scoped<Trust>(tx, 'trusts', input.trustId, input.tenantId);
          await assertTrustManager(ctx, tx, principal, trust);
          await deleteTemporarySessions(tx, {
            tenantId: trust.tenantId,
            roleId: trust.roleId,
            trustId: trust.id,
            createdBefore: Number.POSITIVE_INFINITY,
          });
          return publicTrust(
            await tx.put<Trust>('trusts', { ...trust, revoked: true, updatedAt: ctx.now() }),
          );
        },
      ),
    /**
     * Revokes the trust's role sessions issued before `before` (default: every session so far): moves the trust's
     * `sessionsRevokedBefore` watermark forward and deletes the matching rows. Delegated like
     * `roles.revokeSessions` (iam:roles:revoke-sessions on the trust's role, recent authentication), so a target
     * tenant's administrators can end sessions under platform-controlled trusts. Audited as `role:sessions-revoked`.
     */
    revokeSessions: async (
      credential: CredentialInput,
      input: TrustRevokeSessionsInput,
    ): Promise<{ trustId: string; sessionsRevokedBefore: number; revoked: number }> => {
      // The action targets the trust's role, so the trust is pre-read with ctx.scoped, as roles.assume does (after
      // the credential is verified, so anonymous callers cannot probe trust ids): a missing or foreign trust is
      // NOT_FOUND (spec F2).
      await ctx.principals.authenticate(credential);
      const trustId = text(input.trustId, 'trustId');
      const requested = await ctx.scoped<Trust>(ctx.store, 'trusts', trustId, input.tenantId);
      const resourceId = requested.roleId;
      return operation(
        credential,
        input.tenantId,
        'iam:roles:revoke-sessions',
        resourceId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const trust = await ctx.scoped<Trust>(tx, 'trusts', trustId, input.tenantId);
          // Authorized for another resource than this trust's role (it changed since the pre-read).
          if (trust.roleId !== resourceId)
            throw new IamError('NOT_FOUND', 'Resource not found', 404);
          const sessionsRevokedBefore = nextWatermark(
            trust.sessionsRevokedBefore,
            input.before,
            ctx.now(),
          );
          await tx.put<Trust>('trusts', { ...trust, sessionsRevokedBefore });
          const revoked = await deleteTemporarySessions(tx, {
            tenantId: trust.tenantId,
            roleId: trust.roleId,
            trustId: trust.id,
            createdBefore: sessionsRevokedBefore,
          });
          await ctx.events.audit(
            tx,
            principal,
            'role:sessions-revoked',
            input.tenantId,
            trust.id,
            'allow',
            false,
            { sessionsRevokedBefore, revoked },
          );
          return { trustId: trust.id, sessionsRevokedBefore, revoked };
        },
      );
    },
    /** Trust relationships targeting this tenant's roles, as PublicTrust (external ID hashes are never returned). */
    list: (
      credential: CredentialInput,
      input: { tenantId: string; includeRevoked?: boolean },
    ): Promise<PublicTrust[]> =>
      operation(credential, input.tenantId, 'iam:trust:read', input.tenantId, async ({ tx }) =>
        (await tx.find<Trust>('trusts', { tenantId: input.tenantId }))
          .filter((trust) => input.includeRevoked === true || !trust.revoked)
          .map(publicTrust),
      ),
    /**
     * Dry run of AssumeRoleWithWebIdentity for administrators (iam:trust:read on the trust, web identity enabled):
     * verifies a token against the trust's provider, evaluates the claim conditions (listing each unmet entry) and
     * the claim mappings, and reports why the exchange would refuse it, stored-state causes included (a revoked trust,
     * a disabled provider, the role, the service account, a revoked authority). Nothing is issued and no replay record is
     * written, so the token stays redeemable. Web-identity trusts only (INVALID_INPUT otherwise).
     */
    evaluateWebIdentity: async (
      credential: CredentialInput,
      input: { tenantId: string; trustId: string; webIdentityToken: string },
    ): Promise<WebIdentityEvaluation> => {
      if (!ctx.config.sts.webIdentity.enabled) throw webIdentityDisabled();
      const trustId = text(input.trustId, 'trustId');
      // The same size bound as the public exchange, before anything is parsed or verified.
      const token: unknown = input.webIdentityToken;
      if (typeof token !== 'string' || token.length > 8192)
        invalid('webIdentityToken must be a compact JWT of at most 8192 characters');
      const wellFormed = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(token);
      // Authorized on the trust before it is read, so the answer reveals nothing to callers without the permission.
      const { trust, provider } = await operation(
        credential,
        input.tenantId,
        'iam:trust:read',
        trustId,
        async ({ tx }) => {
          const trust = await ctx.scoped<Trust>(tx, 'trusts', trustId, input.tenantId);
          if (trust.kind !== 'web-identity' || typeof trust.providerId !== 'string')
            invalid('Only web-identity trusts evaluate web identity tokens');
          const provider = await ctx.scoped<OidcProvider>(
            tx,
            'oidcProviders',
            trust.providerId,
            input.tenantId,
          );
          return { trust, provider };
        },
      );
      // A value that is not a compact JWS never reaches the verifier.
      if (!wellFormed) return { verified: false, reason: 'malformed' };
      // Outside the transaction: verification may fetch the provider's keys.
      return evaluateWebIdentity(ctx, { trust, provider, token });
    },
  };
}

export interface LinkedAccount {
  id: string;
  identityId: string;
  email?: string;
  name: string;
  status: Identity['status'];
  tenantId: string;
  tenantName: string;
  tenantSlug?: string;
  tenantStatus: Tenant['status'];
}

export function createLinksApi(ctx: ServerContext) {
  const { store, auth } = ctx;
  return {
    /** Linked accounts of the current identity, for account-switcher UIs. Switching still requires a target credential. */
    list: async (credential: CredentialInput): Promise<LinkedAccount[]> => {
      const authenticated = await ctx.principals.authenticate(credential);
      return store.transaction(async (tx) => {
        const current = await ctx.principals.currentPrincipal(tx, authenticated);
        const links = [
          ...(await tx.find<IdentityLink>('identityLinks', {
            leftId: current.identity.id,
            revoked: false,
          })),
          ...(await tx.find<IdentityLink>('identityLinks', {
            rightId: current.identity.id,
            revoked: false,
          })),
        ];
        const result: LinkedAccount[] = [];
        for (const link of links) {
          const other = await tx.get<Identity>(
            'identities',
            link.leftId === current.identity.id ? link.rightId : link.leftId,
          );
          const realm = other ? await tx.get<Tenant>('tenants', other.tenantId) : undefined;
          if (!other || !realm) continue;
          result.push({
            id: link.id,
            identityId: other.id,
            email: other.email,
            name: other.name,
            status: other.status,
            tenantId: realm.id,
            tenantName: realm.name,
            tenantSlug: realm.slug,
            tenantStatus: realm.status,
          });
        }
        return result;
      });
    },
    create: (credential: CredentialInput, input: { targetCredential: CredentialInput }) =>
      ctx.flows.linkIdentities(credential, input.targetCredential),
    switch: (
      credential: CredentialInput,
      input: { linkId: string; targetCredential: CredentialInput },
    ) => ctx.flows.switchIdentity(credential, input),
    revoke: async (credential: CredentialInput, input: { linkId: string }) => {
      const authenticated = await ctx.principals.authenticate(credential);
      auth.requireRecent(authenticated);
      return store.transaction(async (tx) => {
        await ctx.principals.currentPrincipal(tx, authenticated);
        const link = await tx.get<IdentityLink>('identityLinks', input.linkId);
        if (!link || ![link.leftId, link.rightId].includes(authenticated.identity.id))
          throw new IamError('NOT_FOUND', 'Link not found', 404);
        await tx.put('identityLinks', { ...link, revoked: true });
        await ctx.events.audit(
          tx,
          authenticated,
          'identity:unlink',
          authenticated.identity.tenantId,
          link.id,
          'allow',
        );
        return { revoked: true };
      });
    },
  };
}

export function createRootApi(ctx: ServerContext) {
  const { auth } = ctx;
  const { operation } = ctx.operations;
  return {
    /** Grants or removes the protected root capability; only root administrators may call it. */
    setAdministrator: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; enabled: boolean },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:root:grant',
        input.identityId,
        async ({ tx, principal, tenant: realm }) => {
          auth.requireRecent(principal);
          if (realm.parentId !== null || typeof input.enabled !== 'boolean')
            throw new IamError('INVALID_INPUT', 'Root administrator must belong to root');
          const identity = await ctx.scoped<Identity>(tx, 'identities', input.identityId, realm.id);
          if (identity.kind !== 'user')
            throw new IamError('INVALID_INPUT', 'Root administrators must be users');
          if (!input.enabled) await ctx.protectLastOwner(tx, identity);
          await ctx.revokeAll(tx, identity.id);
          return publicIdentity(
            await tx.put('identities', { ...identity, rootAdmin: input.enabled }),
          );
        },
        true,
      ),
    listAdministrators: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:read',
        input.tenantId,
        async ({ tx, tenant: realm }) => {
          if (realm.parentId !== null)
            throw new IamError('INVALID_INPUT', 'Root administrators belong to the root tenant');
          return (
            await tx.find<Identity>('identities', { tenantId: realm.id, rootAdmin: true })
          ).map(publicIdentity);
        },
        true,
      ),
  };
}
