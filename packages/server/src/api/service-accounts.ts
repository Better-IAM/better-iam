import {
  IamError,
  matchPattern,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type PolicyDocument,
  type Session,
} from '@better-iam/core';
import { newCredentialToken } from '@better-iam/auth';
import { agentStanding, machineIdentity } from '../agents.js';
import { attributeValues } from '../catalog.js';
import type { ServerContext } from '../context.js';
import { endContainment } from '../threats.js';
import { hash, id, publicIdentity } from '../utils.js';
import { integer, strings, text } from '../validation.js';
import { deleteIdentity } from './identities.js';
import { afterIdentityChange } from './package-automation.js';

export function createServiceAccountsApi(ctx: ServerContext) {
  const { auth } = ctx;
  const { operation } = ctx.operations;
  return {
    /** `expiresAt` schedules deactivation: the account's keys stop working at that time and the worker disables it. */
    create: (
      credential: CredentialInput,
      input: { tenantId: string; name: string; description?: string; expiresAt?: number },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:create',
        input.tenantId,
        async ({ tx, principal, tenant }) => {
          await ctx.grantingAuthority(tx, principal, input.tenantId);
          await ctx.enforceLimit(
            tx,
            tenant,
            'serviceAccounts',
            async () =>
              (
                await tx.find<Identity>('identities', { tenantId: input.tenantId, kind: 'service' })
              ).filter((item) => item.status !== 'deleted').length,
          );
          const account: Identity = {
            id: id(),
            tenantId: input.tenantId,
            kind: 'service',
            name: text(input.name, 'name'),
            status: 'active',
            emailVerified: false,
            owner: false,
            rootAdmin: false,
            createdAt: Date.now(),
          };
          if (input.description !== undefined)
            account.description = text(input.description, 'description', 512);
          if (input.expiresAt !== undefined) account.expiresAt = ctx.bindingExpiry(input.expiresAt);
          return tx.insert<Identity>('identities', account);
        },
      ).then((account) => afterIdentityChange(ctx, input.tenantId, [account.id], account)),
    list: (credential: CredentialInput, input: { tenantId: string; includeDeleted?: boolean }) =>
      operation(credential, input.tenantId, 'iam:identities:read', input.tenantId, async ({ tx }) =>
        (await tx.find<Identity>('identities', { tenantId: input.tenantId, kind: 'service' }))
          .filter((account) => input.includeDeleted === true || account.status !== 'deleted')
          .map(publicIdentity),
      ),
    get: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:read',
        input.identityId,
        async ({ tx }) =>
          publicIdentity(await ctx.serviceAccount(tx, input.identityId, input.tenantId)),
      ),
    update: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        identityId: string;
        name?: string;
        description?: string;
        attributes?: Record<string, Json>;
        /** Schedules (epoch milliseconds) or clears (null) the account's deactivation. */
        expiresAt?: number | null;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:update',
        input.identityId,
        async ({ tx }) => {
          const account = await ctx.serviceAccount(tx, input.identityId, input.tenantId);
          if (account.status === 'deleted')
            throw new IamError('NOT_FOUND', 'Service account has been deleted', 404);
          if (
            input.name === undefined &&
            input.description === undefined &&
            input.attributes === undefined &&
            input.expiresAt === undefined
          )
            throw new IamError('INVALID_INPUT', 'Nothing to update');
          const next: Identity = { ...account };
          if (input.name !== undefined) next.name = text(input.name, 'name');
          if (input.description !== undefined)
            next.description = text(input.description, 'description', 512);
          if (input.attributes !== undefined)
            next.attributes = attributeValues(ctx.catalog.identityAttributes, input.attributes);
          if (input.expiresAt === null) delete next.expiresAt;
          else if (input.expiresAt !== undefined)
            next.expiresAt = ctx.bindingExpiry(input.expiresAt);
          return publicIdentity(await tx.put('identities', next));
        },
      ).then((updated) => afterIdentityChange(ctx, input.tenantId, [updated.id], updated)),
    /** Disabling a service account revokes every API key and assumed-role session it holds until it is enabled again. */
    setStatus: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; status: 'active' | 'disabled' },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:update',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          if (!['active', 'disabled'].includes(input.status))
            throw new IamError('INVALID_INPUT', 'Invalid status');
          const account = await ctx.serviceAccount(tx, input.identityId, input.tenantId);
          if (account.status === 'deleted')
            throw new IamError('NOT_FOUND', 'Service account has been deleted', 404);
          if (input.status === 'active' && ctx.identityExpired(account))
            throw new IamError(
              'INVALID_TRANSITION',
              'Extend or clear expiresAt before re-enabling an expired service account',
              409,
            );
          const updated = await tx.put('identities', { ...account, status: input.status });
          // The status is now this call's: a threats containment is over (released here, or held by this disable).
          await endContainment(tx, account.id, ctx.now());
          if (input.status === 'disabled') await ctx.revokeAll(tx, account.id);
          return publicIdentity(updated);
        },
      ),
    delete: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:identities:delete',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const account = await ctx.serviceAccount(tx, input.identityId, input.tenantId);
          const result = await deleteIdentity(ctx, tx, principal, account);
          await ctx.events.audit(
            tx,
            principal,
            'identity:delete',
            input.tenantId,
            account.id,
            'allow',
            false,
            { kind: 'service' },
          );
          return result;
        },
      ),
  };
}

/** An API key as administrators see it: label, lifetime, and usage, never token material. */
export interface CredentialSummary {
  id: string;
  identityId: string;
  name?: string;
  description?: string;
  createdAt: number;
  expiresAt: number;
  /** When the key last authenticated a request (recorded at most once a minute); absent until first use. */
  lastUsedAt?: number;
  expired: boolean;
  policy?: PolicyDocument;
  /** The action allowlist the key was issued with (`credentials.create({ scopes })`), when its policy is exactly that. */
  scopes?: string[];
  credentialAuthorityId?: string;
}

const scopesSid = 'KeyScopes';
/** A scopes list compiles to a session policy allowing exactly those actions on every resource. */
export function scopesPolicy(scopes: string[]): PolicyDocument {
  return {
    version: 1,
    statements: [{ sid: scopesSid, effect: 'allow', actions: scopes, resources: ['*'] }],
  };
}
/** The scopes list behind a session policy, when the policy is exactly the compiled form. */
function policyScopes(policy: PolicyDocument | undefined): string[] | undefined {
  const statement = policy?.statements[0];
  return policy?.statements.length === 1 &&
    statement?.sid === scopesSid &&
    statement.effect === 'allow' &&
    statement.resources.length === 1 &&
    statement.resources[0] === '*' &&
    !statement.conditions
    ? [...statement.actions]
    : undefined;
}

const wildcard = /[*?]|\$\{/;
/** Whether every action `inner` names is also named by `outer`; a wildcard scope needs an equal or broader prefix. */
function scopeCovers(outer: string, inner: string): boolean {
  if (outer === inner) return true;
  if (!wildcard.test(inner)) return matchPattern(outer, inner);
  const prefix = outer.slice(0, -1);
  return outer.endsWith('*') && !wildcard.test(prefix) && inner.startsWith(prefix);
}
/**
 * Whether a key policy stays within a caller key's own: the same document, or scopes that each fall within one of the
 * caller's scopes. Anything else (a broader or an unrelated custom policy, or none) does not.
 */
function withinKeyPolicy(outer: PolicyDocument, inner: PolicyDocument | undefined): boolean {
  if (!inner) return false;
  if (JSON.stringify(outer) === JSON.stringify(inner)) return true;
  const outerScopes = policyScopes(outer);
  const innerScopes = policyScopes(inner);
  return Boolean(
    outerScopes &&
      innerScopes &&
      innerScopes.every((scope) => outerScopes.some((allowed) => scopeCovers(allowed, scope))),
  );
}

export function credentialSummary(session: Session, now: number): CredentialSummary {
  const summary: CredentialSummary = {
    id: session.id,
    identityId: session.identityId,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    expired: session.expiresAt <= now,
    policy: session.policy,
    credentialAuthorityId: session.credentialAuthorityId as string | undefined,
  };
  if (session.name !== undefined) summary.name = session.name;
  if (session.description !== undefined) summary.description = session.description;
  if (session.lastSeenAt > session.createdAt) summary.lastUsedAt = session.lastSeenAt;
  const scopes = policyScopes(session.policy);
  if (scopes) summary.scopes = scopes;
  return summary;
}

export function createCredentialsApi(ctx: ServerContext) {
  const { auth, catalog } = ctx;
  const { operation } = ctx.operations;
  /** A key's expiry may be extended or shortened, but only into the future and at most a year out. */
  const keyExpiry = (value: unknown, now: number): number => {
    const expiresAt = integer(value, 'expiresAt', 0, Number.MAX_SAFE_INTEGER);
    if (expiresAt <= now) throw new IamError('INVALID_INPUT', 'expiresAt must be in the future');
    if (expiresAt > now + 86400_000 * 365)
      throw new IamError('INVALID_INPUT', 'expiresAt must be within one year');
    return expiresAt;
  };
  async function apiKey(tx: IamStore, credentialId: string, tenantId: string): Promise<Session> {
    const session = await ctx.scoped<Session>(tx, 'sessions', credentialId, tenantId);
    if (session.kind !== 'api-key')
      throw new IamError('INVALID_CREDENTIAL', 'Not an API key credential');
    return session;
  }
  return {
    /**
     * API keys of the tenant, or of one service account, with their labels and last use. `unusedForMs` keeps only
     * keys that have not authenticated a request in that long (including keys never used since creation), for
     * hygiene reviews. Token hashes are never returned.
     */
    list: (
      credential: CredentialInput,
      input: { tenantId: string; identityId?: string; unusedForMs?: number },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:credentials:read',
        input.identityId ?? input.tenantId,
        async ({ tx }) => {
          const filter: Record<string, unknown> = { tenantId: input.tenantId, kind: 'api-key' };
          if (input.identityId !== undefined)
            filter.identityId = text(input.identityId, 'identityId');
          const now = ctx.now();
          const unusedSince =
            input.unusedForMs !== undefined
              ? now - integer(input.unusedForMs, 'unusedForMs', 0, 10 * 365 * 86400_000)
              : undefined;
          return (await tx.find<Session>('sessions', filter))
            .map((session) => credentialSummary(session, now))
            .filter(
              (summary) =>
                unusedSince === undefined ||
                (summary.lastUsedAt ?? summary.createdAt) <= unusedSince,
            )
            .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? -1 : 1));
        },
      ),
    get: (credential: CredentialInput, input: { tenantId: string; credentialId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:credentials:read',
        input.credentialId,
        async ({ tx }) =>
          credentialSummary(await apiKey(tx, input.credentialId, input.tenantId), ctx.now()),
      ),
    /**
     * Issues an opaque API key for a service account, bounded by the issuer's grant authority and an optional
     * session policy. `name` and `description` label the key for reviews; the plaintext is returned once. An API key
     * with scopes (or a session policy) issues only keys within them; without scopes of their own, they inherit its.
     */
    create: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        identityId: string;
        expiresInSeconds?: number;
        policy?: PolicyDocument;
        /** Restricts the key to these actions (an allow over every resource); an alternative to `policy`. */
        scopes?: string[];
        name?: string;
        description?: string;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:credentials:create',
        input.identityId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const authority = await ctx.grantingAuthority(tx, principal, input.tenantId);
          const identity = await ctx.scoped<Identity>(
            tx,
            'identities',
            input.identityId,
            input.tenantId,
          );
          if (
            !machineIdentity(identity) ||
            identity.status !== 'active' ||
            ctx.identityExpired(identity)
          )
            throw new IamError('INVALID_IDENTITY', 'API keys require an active service account');
          // An agent gets keys only while its sponsor is an active person (agents.ts).
          if (identity.kind === 'agent' && (await agentStanding(ctx, tx, identity)) !== 'ok')
            throw new IamError('INVALID_IDENTITY', 'API keys require an agent in good standing');
          if (input.scopes !== undefined && input.policy !== undefined)
            throw new IamError('INVALID_INPUT', 'Provide either scopes or a session policy');
          if (input.scopes !== undefined) {
            const scopes = [...new Set(strings(input.scopes, 'scopes'))];
            if (!scopes.length)
              throw new IamError('INVALID_INPUT', 'scopes must name at least one action');
            input = { ...input, policy: scopesPolicy(scopes) };
          }
          // A key never mints a broader key: a caller key with scopes or a session policy passes them on (a new key
          // without its own gets the caller's), and a new key's own scopes must fall within the caller's.
          const callerPolicy = principal.session.policy;
          if (callerPolicy) {
            if (input.policy === undefined) input = { ...input, policy: callerPolicy };
            else if (!withinKeyPolicy(callerPolicy, input.policy))
              throw new IamError(
                'ACCESS_DENIED',
                'A key can only issue keys within its own scopes or policy',
                403,
              );
          }
          if (input.policy) await catalog.validate(tx, input.tenantId, input.policy);
          // Typed and checksummed (`biam_key_…`) so secret scanners recognise leaked keys.
          const raw = newCredentialToken('key');
          // The injected clock, so creation and expiry agree with every other time check.
          const now = ctx.now();
          const duration = integer(
            input.expiresInSeconds ?? 86400 * 90,
            'expiresInSeconds',
            60,
            86400 * 365,
          );
          const record: Session = {
            id: id(),
            tenantId: input.tenantId,
            identityId: identity.id,
            kind: 'api-key',
            tokenHash: hash(raw),
            uniqueKey: hash(raw),
            createdAt: now,
            lastSeenAt: now,
            authenticatedAt: now,
            expiresAt: now + duration * 1000,
            mfa: false,
            policy: input.policy,
            credentialAuthorityId: authority.id,
          };
          if (input.name !== undefined) record.name = text(input.name, 'name', 128);
          if (input.description !== undefined)
            record.description = text(input.description, 'description', 512);
          const session = await tx.insert<Session>('sessions', record);
          return {
            token: raw,
            credentialId: session.id,
            expiresAt: session.expiresAt,
            name: session.name,
          };
        },
      ),
    /** Relabels a key or moves its expiry (future, at most a year out); the token itself never changes. */
    update: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        credentialId: string;
        name?: string | null;
        description?: string | null;
        expiresAt?: number;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:credentials:create',
        input.credentialId,
        async ({ tx, principal }) => {
          const session = await apiKey(tx, input.credentialId, input.tenantId);
          if (
            input.name === undefined &&
            input.description === undefined &&
            input.expiresAt === undefined
          )
            throw new IamError('INVALID_INPUT', 'Nothing to update');
          if (input.expiresAt !== undefined) {
            auth.requireRecent(principal);
            await ctx.grantingAuthority(
              tx,
              principal,
              input.tenantId,
              typeof session.credentialAuthorityId === 'string'
                ? session.credentialAuthorityId
                : undefined,
            );
          }
          const next: Session = { ...session };
          if (input.name === null) delete next.name;
          else if (input.name !== undefined) next.name = text(input.name, 'name', 128);
          if (input.description === null) delete next.description;
          else if (input.description !== undefined)
            next.description = text(input.description, 'description', 512);
          if (input.expiresAt !== undefined) next.expiresAt = keyExpiry(input.expiresAt, ctx.now());
          return credentialSummary(await tx.put('sessions', next), ctx.now());
        },
      ),
    /** Deletes an API key at once. Other sessions (user, role) are refused: they end through their own flows. */
    revoke: (credential: CredentialInput, input: { tenantId: string; credentialId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:credentials:revoke',
        input.credentialId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          await apiKey(tx, input.credentialId, input.tenantId);
          await tx.delete('sessions', input.credentialId);
          return { revoked: true };
        },
      ),
    /** Replaces the key material atomically; the old key stops working in the same transaction. */
    rotate: (credential: CredentialInput, input: { tenantId: string; credentialId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:credentials:create',
        input.credentialId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const old = await ctx.scoped<Session>(tx, 'sessions', input.credentialId, input.tenantId);
          if (old.kind !== 'api-key')
            throw new IamError('INVALID_CREDENTIAL', 'Only API keys can rotate');
          // Rotating hands over the new token, so a key may only rotate keys within its own scopes (as `create`).
          if (principal.session.policy && !withinKeyPolicy(principal.session.policy, old.policy))
            throw new IamError(
              'ACCESS_DENIED',
              'A key can only rotate keys within its own scopes or policy',
              403,
            );
          const authority = await ctx.grantingAuthority(
            tx,
            principal,
            input.tenantId,
            typeof old.credentialAuthorityId === 'string' ? old.credentialAuthorityId : undefined,
          );
          const raw = newCredentialToken('key');
          await tx.delete('sessions', old.id);
          const now = ctx.now();
          // The replacement keeps the label, policy, and expiry; its usage history and
          // authentication time (principal.authTime is an API key's creation time) start over.
          const replacement: Session = {
            ...old,
            id: id(),
            tokenHash: hash(raw),
            uniqueKey: hash(raw),
            createdAt: now,
            lastSeenAt: now,
            authenticatedAt: now,
            credentialAuthorityId: authority.id,
          };
          await tx.insert('sessions', replacement);
          return {
            token: raw,
            credentialId: replacement.id,
            expiresAt: replacement.expiresAt,
            name: replacement.name,
          };
        },
      ),
  };
}
